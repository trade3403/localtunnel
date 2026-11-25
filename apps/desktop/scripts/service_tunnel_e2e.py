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

def service_pid(name):
    result = sc("queryex", name)
    match = re.search(r"PID\s*:\s*(\d+)", result.stdout)
    if not match or int(match.group(1)) <= 0:
        raise RuntimeError("missing SCM host PID")
    return int(match.group(1))

def engine_child(parent, root):
    # Only inspect the exact SCM host's own child process; no global
    # name-based process termination. Require its image in this runtime.
    command = (f"Get-CimInstance Win32_Process -Filter 'ParentProcessId={parent}' | "
               "Where-Object {$_.Name -eq 'rathole.exe'} | "
               "Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress")
    result = run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
    if not result.stdout.strip():
        return None
    child = json.loads(result.stdout)
    if not isinstance(child, dict) or not child.get("ExecutablePath"):
        raise RuntimeError("unexpected service engine process list")
    image = Path(child["ExecutablePath"])
    if (image.name.lower() != "rathole.exe" or
            image.parent.parent != root / "runtime" or
            not image.parent.name.startswith("localtunnel-client-")):
        raise RuntimeError("unexpected engine image location")
    return int(child["ProcessId"]), image.parent

def main(executable, evidence):
    engine = Path(os.environ["LOCALTUNNEL_TEST_ENGINE"]).resolve()
    name = "LocalTunnelPreview-" + uuid.uuid4().hex
    root = Path(os.environ["ProgramData"]) / name
    report = {"scope": "real SCM LocalService same-host encrypted HTTP; no public E2E",
              "registered": False, "unsafe_registration_rejected": False,
              "duplicate_registration_rejected": False, "running_unregister_rejected": False,
              "sealed_profile": False, "invalid_profile_rejected": False,
              "overwrite_rejected": False, "unsafe_acl_rejected": False,
              "unsafe_profile_acl_rejected": False, "autostart_unsafe_rejected": False,
              "autostart_enabled": False, "autostart_disabled": False, "forwarded": False,
              "stopped": False, "runtime_cleaned": False, "deleted": False,
              "engine_recovered": False, "old_runtime_cleaned": False,
              "host_crash_restart": False, "host_crash_runtime_cleaned": False,
              "unknown_runtime_preserved": False, "unsafe_recovery_rejected": False,
              "automatic_host_recovered": False, "normal_stop_no_recovery": False,
              "recovery_disabled": False}
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
        run("icacls.exe", str(root), "/setowner", "*S-1-5-32-544", "/T")
        def control(action, check=True):
            return run(str(exe), "--service-control", name, action, check=check)
        run("icacls.exe", str(root), "/grant:r", "*S-1-1-0:RX")
        if control("register", check=False).returncode == 0:
            created = True
            raise RuntimeError("unsafe service registration accepted")
        report["unsafe_registration_rejected"] = True
        run("icacls.exe", str(root), "/remove:g", "*S-1-1-0")
        control("register")
        created = True
        if control("register", check=False).returncode == 0:
            raise RuntimeError("duplicate service registration accepted")
        report["duplicate_registration_rejected"] = True
        # Per-service SID, rather than every process running as LocalService.
        service = "NT SERVICE\\" + name
        run("icacls.exe", str(root), "/grant:r", service + ":(OI)(CI)RX")
        run("icacls.exe", str(root / "runtime"), "/grant:r", service + ":(OI)(CI)M")
        run("icacls.exe", str(root), "/setowner", "*S-1-5-32-544", "/T")
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
                # A valid profile must still be refused before writing if
                # any unrelated account has read access to the deployment.
                run("icacls.exe", str(root), "/grant:r", "*S-1-1-0:RX")
                if provision(profile) == 0 or (root / "service-profile.bin").exists():
                    raise RuntimeError("unsafe deployment ACL accepted")
                report["unsafe_acl_rejected"] = True
                run("icacls.exe", str(root), "/remove:g", "*S-1-1-0")
                bad = json.loads(profile)
                bad["engine"] = str(engine)
                if provision(json.dumps(bad).encode()) == 0 or (root / "service-profile.bin").exists():
                    raise RuntimeError("invalid service profile accepted")
                report["invalid_profile_rejected"] = True
                if provision(profile) != 0:
                    raise RuntimeError("Rust service credential provisioning failed")
                run("icacls.exe", str(root / "service-profile.bin"), "/setowner", "*S-1-5-32-544")
                encrypted = (root / "service-profile.bin").read_bytes()
                if token.encode() in encrypted:
                    raise RuntimeError("plaintext token in sealed profile")
                report["sealed_profile"] = True
                if provision(profile) == 0 or (root / "service-profile.bin").read_bytes() != encrypted:
                    raise RuntimeError("existing service credential overwritten")
                report["overwrite_rejected"] = True
                relay = subprocess.Popen([str(engine), str(config)], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Machine DPAPI is not sufficient by itself. Even read
                # access to ciphertext by another principal must block SCM start.
                run("icacls.exe", str(root / "service-profile.bin"), "/grant:r", "*S-1-1-0:RX")
                if control("autostart-on", check=False).returncode == 0:
                    raise RuntimeError("unsafe service autostart accepted")
                report["autostart_unsafe_rejected"] = True
                if control("recovery-on", check=False).returncode == 0:
                    raise RuntimeError("unsafe service recovery accepted")
                report["unsafe_recovery_rejected"] = True
                sc("start", name, check=False)
                wait_state(name, 1)
                if any((root / "runtime").iterdir()):
                    raise RuntimeError("unsafe profile started an engine")
                report["unsafe_profile_acl_rejected"] = True
                run("icacls.exe", str(root / "service-profile.bin"), "/remove:g", "*S-1-1-0")
                control("check")
                if not re.search(r"START_TYPE\s*:\s*3\b", sc("qc", name).stdout):
                    raise RuntimeError("service did not default to manual")
                control("autostart-on")
                if not re.search(r"START_TYPE\s*:\s*2\b", sc("qc", name).stdout):
                    raise RuntimeError("SCM auto start not configured")
                report["autostart_enabled"] = True
                control("autostart-off")
                if not re.search(r"START_TYPE\s*:\s*3\b", sc("qc", name).stdout):
                    raise RuntimeError("SCM manual start not restored")
                report["autostart_disabled"] = True
                control("start")
                wait_state(name, 4)
                url = f"http://127.0.0.1:{mapped}/"
                e2e.wait_for(url, body, [relay], seconds=35)
                report["forwarded"] = True
                host_pid = service_pid(name)
                old_child = engine_child(host_pid, root)
                if old_child is None:
                    raise RuntimeError("service engine child missing")
                old_pid, old_dir = old_child
                # Fault injection targets only the child just verified above.
                run("taskkill.exe", "/PID", str(old_pid), "/F")
                deadline = time.monotonic() + 20
                new_child = None
                while time.monotonic() < deadline:
                    candidate = engine_child(host_pid, root)
                    if candidate and candidate[0] != old_pid:
                        new_child = candidate
                        break
                    time.sleep(.25)
                if new_child is None or service_pid(name) != host_pid:
                    raise RuntimeError("engine not recovered under original SCM host")
                if old_dir.exists():
                    raise RuntimeError("old runtime directory survived engine exit")
                report["old_runtime_cleaned"] = True
                e2e.wait_for(url, body, [relay], seconds=35)
                report["engine_recovered"] = True
                # End only the SCM host identified above. Job-object close
                # must terminate its assigned engine, leaving the crash data.
                if service_pid(name) != host_pid:
                    raise RuntimeError("SCM host changed before crash injection")
                run("taskkill.exe", "/PID", str(host_pid), "/F")
                wait_state(name, 1)
                crashed_dir = new_child[1]
                if not (crashed_dir / "client.toml").is_file():
                    raise RuntimeError("host crash did not leave the expected fixture")
                # Wait until the original engine image is no longer in use.
                deadline = time.monotonic() + 10
                while engine_child(host_pid, root) is not None:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("engine survived host crash")
                    time.sleep(.25)
                # Unknown data must not be removed or overwritten.
                unknown = crashed_dir / "unknown.txt"
                unknown.write_bytes(b"preserve this fixture")
                sc("start", name, check=False)
                wait_state(name, 1)
                if unknown.read_bytes() != b"preserve this fixture" or not (crashed_dir / "client.toml").is_file():
                    raise RuntimeError("unknown runtime caused destructive cleanup")
                report["unknown_runtime_preserved"] = True
                unknown.unlink()
                control("start")
                wait_state(name, 4)
                if crashed_dir.exists():
                    raise RuntimeError("stale runtime survived host restart")
                report["host_crash_runtime_cleaned"] = True
                e2e.wait_for(url, body, [relay], seconds=35)
                report["host_crash_restart"] = True
                # Recovery is explicitly enabled only after the manual-crash
                # tests. This is a disposable test service with a unique name.
                control("recovery-on")
                previous_host = service_pid(name)
                previous_child = engine_child(previous_host, root)
                if previous_child is None:
                    raise RuntimeError("engine missing before automatic recovery")
                started_at = time.monotonic()
                run("taskkill.exe", "/PID", str(previous_host), "/F")
                deadline = time.monotonic() + 35
                recovered_host = None
                while time.monotonic() < deadline:
                    result = sc("queryex", name)
                    pid = re.search(r"PID\s*:\s*(\d+)", result.stdout)
                    if (re.search(r"STATE\s*:\s*4\b", result.stdout) and pid
                            and int(pid.group(1)) not in (0, previous_host)):
                        recovered_host = int(pid.group(1))
                        break
                    time.sleep(.25)
                if recovered_host is None:
                    raise RuntimeError("SCM failed automatic host recovery")
                if previous_child[1].exists():
                    raise RuntimeError("automatic recovery left old runtime")
                e2e.wait_for(url, body, [relay], seconds=35)
                report["automatic_host_recovered"] = True
                report["automatic_host_recovery_seconds"] = round(time.monotonic() - started_at, 3)
                if control("unregister", check=False).returncode == 0:
                    raise RuntimeError("running service unregistered")
                report["running_unregister_rejected"] = True
                e2e.wait_for(url, body, [relay], seconds=10)
                control("stop")
                wait_state(name, 1)
                control("stop")  # idempotent once SCM confirms stopped
                report["stopped"] = True
                report["idempotent_stop"] = True
                if any((root / "runtime").iterdir()):
                    raise RuntimeError("service runtime files survived stop")
                report["runtime_cleaned"] = True
                deadline = time.monotonic() + 8
                while e2e.get(url) == body and time.monotonic() < deadline:
                    time.sleep(.25)
                if e2e.get(url) == body:
                    raise RuntimeError("tunnel survived service stop")
                # Observe longer than the longest configured restart delay.
                until = time.monotonic() + 14
                while time.monotonic() < until:
                    result = sc("query", name)
                    if not re.search(r"STATE\s*:\s*1\b", result.stdout):
                        raise RuntimeError("normal stop unexpectedly triggered SCM recovery")
                    time.sleep(.5)
                report["normal_stop_no_recovery"] = True
                control("recovery-off")
                report["recovery_disabled"] = True
            finally:
                if relay is not None:
                    e2e.terminate(relay)
                    relay = None
        control("unregister")
        if not (root / "service-profile.bin").is_file():
            raise RuntimeError("unregister unexpectedly deleted credentials")
        report["unregister_preserved_profile"] = True
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
            # Disable startup before emergency cleanup, including a queued retry.
            control("recovery-off", check=False)
            sc("config", name, "start=", "disabled", check=False)
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
