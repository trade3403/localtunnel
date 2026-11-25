"""Real Windows SCM tunnel under LocalService; disposable, loopback only."""
import ctypes
from ctypes import wintypes
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

class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

def seal(data):
    # Machine-scoped DPAPI permits a separately ACL-authorized service to
    # decrypt. This is NOT user-scoped protection. Do not store real secrets
    # in this test; its profile contains only randomly generated CI tokens.
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [
        ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptProtectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    raw = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    try:
        if not crypt.CryptProtectData(ctypes.byref(source), None, None, None, None,
                                     0x1 | 0x4, ctypes.byref(output)):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.memset(raw, 0, len(data))
        if output.pbData:
            kernel.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))

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
              "registered": False, "sealed_profile": False, "forwarded": False,
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
                encrypted = seal(profile)
                if token.encode() in encrypted:
                    raise RuntimeError("plaintext token in sealed profile")
                (root / "service-profile.bin").write_bytes(encrypted)
                report["sealed_profile"] = True
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
