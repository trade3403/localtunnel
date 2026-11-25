"""Real Windows SCM tunnel under LocalService; disposable, loopback only."""
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
import e2e

def run(*args, check=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors="replace", timeout=40)
    if check and p.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed: {p.returncode}: {p.stdout}")
    return p

def sc(*args, check=True):
    return run(str(Path(os.environ["SystemRoot"]) / "System32" / "sc.exe"),
               *args, check=check)

def wait_state(name, state, seconds=25):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        p = sc("query", name)
        if re.search(r"STATE\s*:\s*" + str(state) + r"\b", p.stdout):
            return
        time.sleep(.25)
    raise RuntimeError(f"service did not reach SCM state {state}")

def main(executable, evidence):
    engine = Path(os.environ["LOCALTUNNEL_TEST_ENGINE"]).resolve()
    name = "LocalTunnelPreview-" + uuid.uuid4().hex
    root = Path(os.environ["ProgramData"]) / name
    report = {"scope": "real SCM LocalService same-host encrypted HTTP; no public E2E",
              "registered": False, "sealed_profile": False, "invalid_profile_rejected": False,
              "overwrite_rejected": False, "forwarded": False,
              "stopped": False, "runtime_cleaned": False, "deleted": False}
    created = False
    relay = None
    fixture = None
    root_created = False
    try:
        root.mkdir()
        root_created = True
        # Strip inherited broad access before copying any files.
        run("icacls.exe", str(root), "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
        exe = root / "localtunnel-desktop.exe"
        shutil.copyfile(executable, exe)
        (root / "engine").mkdir()
        shutil.copyfile(engine, root / "engine" / "rathole.exe")
        (root / "runtime").mkdir()
        binary = f'"{exe}" --service-tunnel {name}'
        sc("create", name, "binPath=", binary, "start=", "demand", "obj=", r"NT AUTHORITY\LocalService")
        created = True
        sc("sidtype", name, "unrestricted")
        # Per-service SID, rather than every process running as LocalService.
        service = "NT SERVICE\\" + name
        run("icacls.exe", str(root), "/grant:r", service + ":(OI)(CI)RX")
        run("icacls.exe", str(root / "runtime"), "/grant:r", service + ":(OI)(CI)M")
        report["registered"] = True
        body = secrets.token_hex(32).encode()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory(prefix="localtunnel-scm-relay-") as work:
            try:
                keys = subprocess.check_output([str(engine), "--genkey"], text=True, timeout=15)
                private = re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
                public = re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
                token = secrets.token_hex(32)
                # Reserve distinct ports together to avoid duplicate allocation.
                with socket.socket() as a, socket.socket() as b:
                    a.bind(("127.0.0.1", 0))
                    b.bind(("127.0.0.1", 0))
                    relay_port, mapped = a.getsockname()[1], b.getsockname()[1]
                config = Path(work) / "server.toml"
                config.write_text(f"""[server]
bind_addr = "127.0.0.1:{relay_port}"
heartbeat_interval = 5

[server.transport]
type = "noise"

[server.transport.noise]
pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "{private}"

[server.services.web]
type = "tcp"
token = "{token}"
bind_addr = "127.0.0.1:{mapped}"
""", encoding="utf-8")
                profile = json.dumps({"engine": "", "remote": f"127.0.0.1:{relay_port}",
                                      "serverKey": public,
                                      "mappings": [{"name": "web", "localPort": fixture.server_port,
                                                    "token": token}]}).encode()
                # Exercise the shipped Rust provisioning entry, not a test-only
                # implementation. All sensitive input is inherited stdin.
                command = [str(exe), "--service-seal-profile", name]
                def provision(data):
                    return subprocess.run(command, input=data, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, timeout=20).returncode
                bad = json.loads(profile)
                bad["engine"] = str(engine)
                if provision(json.dumps(bad).encode()) == 0 or (root / "service-profile.bin").exists():
                    raise RuntimeError("invalid service profile accepted")
                report["invalid_profile_rejected"] = True
                if provision(profile) != 0:
                    raise RuntimeError("Rust service credential provisioning failed")
                encrypted = (root / "service-profile.bin").read_bytes()
                if token.encode() in encrypted:
                    raise RuntimeError("plaintext token in sealed profile")
                report["sealed_profile"] = True
                if provision(profile) == 0 or (root / "service-profile.bin").read_bytes() != encrypted:
                    raise RuntimeError("existing service credential overwritten")
                report["overwrite_rejected"] = True
                relay = subprocess.Popen([str(engine), str(config)], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                sc("start", name)
                wait_state(name, 4)
                url = f"http://127.0.0.1:{mapped}/"
                e2e.wait_for(url, body, [relay], seconds=35)
                report["forwarded"] = True
                sc("stop", name)
                wait_state(name, 1)
                report["stopped"] = True
                if any((root / "runtime").iterdir()):
                    raise RuntimeError("service runtime files survived stop")
                report["runtime_cleaned"] = True
                deadline = time.monotonic() + 8
                while e2e.get(url) == body and time.monotonic() < deadline:
                    time.sleep(.25)
                if e2e.get(url) == body:
                    raise RuntimeError("tunnel survived service stop")
            finally:
                if relay is not None:
                    e2e.terminate(relay)
                    relay = None
        sc("delete", name)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = sc("query", name, check=False)
            if result.returncode == 1060 or "1060" in result.stdout:
                created = False
                report["deleted"] = True
                break
            time.sleep(.25)
        if not report["deleted"]:
            raise RuntimeError("service remains after deletion")
    finally:
        if created:
            sc("stop", name, check=False)
            try:
                wait_state(name, 1, 15)
            except Exception:
                pass
            sc("delete", name, check=False)
        if fixture:
            fixture.shutdown()
            fixture.server_close()
        if root_created:
            shutil.rmtree(root)
        Path(evidence).write_text(json.dumps(report, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
