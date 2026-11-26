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
              "recovery_disabled": False, "readonly_scm_status": False, "service_traffic_measured": False,
              "recovered_traffic_measured": False, "history_checkpoint": False,
              "history_after_host_recovery": False, "history_after_stop": False,
              "history_preserved_unregister": False, "unsafe_history_rejected": False, "desktop_service_controls": False, "one_click_provision": False, "profile_update": False, "desktop_unregister": False,
              "mixed_service_forwarded": False, "mixed_service_recovered": False,
              "mixed_service_measured_traffic": False, "mixed_service_stopped": False}
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
        (root / "history").mkdir()
        run("icacls.exe", str(root), "/setowner", "*S-1-5-32-544", "/T")
        def control(action, check=True):
            return run(str(exe), "--service-control", name, action, check=check)
        def manage(action, check=True, target=name):
            # Same function as GUI IPC, from the ordinary desktop executable.
            return run(str(executable), "--service-manage", target, action, check=check)
        def snapshot():
            # Query using original desktop EXE, not the privileged service copy.
            return json.loads(run(str(executable), "--service-status", name).stdout)
        def wait_traffic(host, engine_pid, minimum_up):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                record = snapshot().get("traffic")
                if (record and record["hostPid"] == host and record["enginePid"] == engine_pid
                        and record["uploadBytes"] >= minimum_up and record["downloadBytes"] > 0):
                    return record
                time.sleep(.3)
            raise RuntimeError("real service traffic sample unavailable")
        def wait_history(minimum_up, minimum_down):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                record = snapshot().get("history")
                if (record and record["uploadBytes"] >= minimum_up
                        and record["downloadBytes"] >= minimum_down):
                    return record
                time.sleep(.3)
            raise RuntimeError("saved service history unavailable")
        if run(str(executable), "--service-status", "Spooler", check=False).returncode == 0:
            raise RuntimeError("status accepted unrelated system service")
        run("icacls.exe", str(root), "/grant:r", "*S-1-1-0:RX")
        if control("register", check=False).returncode == 0:
            created = True
            raise RuntimeError("unsafe service registration accepted")
        report["unsafe_registration_rejected"] = True
        run("icacls.exe", str(root), "/remove:g", "*S-1-1-0")
        control("register")
        created = True
        initial = snapshot()
        if initial["state"] != "stopped" or initial["startup"] != "manual" or initial["hostPid"] is not None:
            raise RuntimeError("incorrect initial read-only SCM snapshot")
        if control("register", check=False).returncode == 0:
            raise RuntimeError("duplicate service registration accepted")
        if manage("unregister", check=False).returncode == 0:
            raise RuntimeError("desktop management allowed unregister")
        if manage("check", check=False, target="Spooler").returncode == 0:
            raise RuntimeError("desktop management accepted unrelated service")
        report["duplicate_registration_rejected"] = True
        # Per-service SID, rather than every process running as LocalService.
        service = "NT SERVICE\\" + name
        run("icacls.exe", str(root), "/grant:r", service + ":(OI)(CI)RX")
        run("icacls.exe", str(root / "runtime"), "/grant:r", service + ":(OI)(CI)M")
        run("icacls.exe", str(root / "history"), "/grant:r", service + ":(OI)(CI)M")
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
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.bind(("127.0.0.1", 0))
                    udp_mapped = probe.getsockname()[1]
                    if udp_mapped in (relay_port, mapped):
                        raise RuntimeError("unexpected UDP mapping port collision")
                udp_token = secrets.token_hex(32)
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

[server.services.datagram]
type = "udp"
token = "{udp_token}"
bind_addr = "127.0.0.1:{udp_mapped}"
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
                run("icacls.exe", str(root / "history"), "/grant:r", "*S-1-1-0:RX")
                if manage("start", check=False).returncode == 0:
                    raise RuntimeError("unsafe service history directory accepted")
                wait_state(name, 1)
                report["unsafe_history_rejected"] = True
                run("icacls.exe", str(root / "history"), "/remove:g", "*S-1-1-0")
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
                manage("check")
                if not re.search(r"START_TYPE\s*:\s*3\b", sc("qc", name).stdout):
                    raise RuntimeError("service did not default to manual")
                manage("autostart-on")
                if not re.search(r"START_TYPE\s*:\s*2\b", sc("qc", name).stdout):
                    raise RuntimeError("SCM auto start not configured")
                report["autostart_enabled"] = True
                if snapshot()["startup"] != "automatic":
                    raise RuntimeError("SCM snapshot did not reflect automatic startup")
                manage("autostart-off")
                if not re.search(r"START_TYPE\s*:\s*3\b", sc("qc", name).stdout):
                    raise RuntimeError("SCM manual start not restored")
                report["autostart_disabled"] = True
                manage("start")
                wait_state(name, 4)
                url = f"http://127.0.0.1:{mapped}/"
                e2e.wait_for(url, body, [relay], seconds=35)
                report["forwarded"] = True
                host_pid = service_pid(name)
                running_snapshot = snapshot()
                if (running_snapshot["state"] != "running" or running_snapshot["hostPid"] != host_pid
                        or running_snapshot["startup"] != "manual"):
                    raise RuntimeError("read-only SCM running snapshot mismatch")
                old_child = engine_child(host_pid, root)
                if old_child is None:
                    raise RuntimeError("service engine child missing")
                old_pid, old_dir = old_child
                first_traffic = wait_traffic(host_pid, old_pid, len(body))
                initial_history = wait_history(first_traffic["uploadBytes"], first_traffic["downloadBytes"])
                report["history_checkpoint"] = True
                report["service_traffic_measured"] = True
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
                manage("recovery-on")
                if snapshot()["recovery"] != "enabled":
                    raise RuntimeError("desktop recovery enable not verified")
                previous_host = service_pid(name)
                previous_child = engine_child(previous_host, root)
                if previous_child is None:
                    raise RuntimeError("engine missing before automatic recovery")
                previous_traffic = wait_traffic(previous_host, previous_child[0], len(body))
                before_crash = wait_history(initial_history["uploadBytes"] + previous_traffic["uploadBytes"],
                                             initial_history["downloadBytes"] + previous_traffic["downloadBytes"])
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
                if snapshot()["hostPid"] != recovered_host:
                    raise RuntimeError("read-only SCM snapshot retained old host PID")
                recovered_child = engine_child(recovered_host, root)
                if recovered_child is None:
                    raise RuntimeError("recovered engine absent")
                recovered_traffic = wait_traffic(recovered_host, recovered_child[0], len(body))
                after_crash = wait_history(before_crash["uploadBytes"] + recovered_traffic["uploadBytes"],
                                            before_crash["downloadBytes"] + recovered_traffic["downloadBytes"])
                report["history_after_host_recovery"] = True
                report["recovered_traffic_measured"] = True
                report["automatic_host_recovered"] = True
                report["automatic_host_recovery_seconds"] = round(time.monotonic() - started_at, 3)
                if control("unregister", check=False).returncode == 0:
                    raise RuntimeError("running service unregistered")
                report["running_unregister_rejected"] = True
                e2e.wait_for(url, body, [relay], seconds=10)
                manage("stop")
                wait_state(name, 1)
                manage("stop")  # idempotent once SCM confirms stopped
                report["stopped"] = True
                report["idempotent_stop"] = True
                stopped_snapshot = snapshot()
                if (stopped_snapshot["state"] != "stopped" or stopped_snapshot["hostPid"] is not None
                        or stopped_snapshot["traffic"] is not None):
                    raise RuntimeError("read-only SCM snapshot retained stopped PID")
                report["readonly_scm_status"] = True
                final_history = stopped_snapshot.get("history")
                if (not final_history or final_history["uploadBytes"] < after_crash["uploadBytes"]
                        or final_history["downloadBytes"] < after_crash["downloadBytes"]):
                    raise RuntimeError("history lost at service stop")
                report["history_after_stop"] = True
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
                manage("recovery-off")
                if snapshot()["recovery"] != "disabled":
                    raise RuntimeError("desktop recovery disable not verified")
                report["recovery_disabled"] = True
                report["desktop_service_controls"] = True
                # Exercise provisioning from the ordinary executable with
                # the same fixed sibling engine layout as the installed app.
                with tempfile.TemporaryDirectory(prefix="localtunnel-provision-source-") as source:
                    source = Path(source)
                    source_exe = source / "localtunnel-desktop.exe"
                    shutil.copyfile(executable, source_exe)
                    (source / "engine").mkdir()
                    shutil.copyfile(engine, source / "engine" / "rathole.exe")
                    result = subprocess.run([str(source_exe), "--service-provision"], input=profile,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
                    if result.returncode:
                        raise RuntimeError("one-click provisioning failed: " + result.stderr.decode(errors="replace"))
                    fresh = result.stdout.decode().strip()
                    if not re.fullmatch(r"LocalTunnelPreview-[0-9a-f]{32}", fresh) or fresh == name:
                        raise RuntimeError("invalid new service name")
                    fresh_root = Path(os.environ["ProgramData"]) / fresh
                    fresh_exe = fresh_root / "localtunnel-desktop.exe"
                    def fresh_control(action, check=True):
                        return run(str(fresh_exe), "--service-control", fresh, action, check=check)
                    try:
                        state = json.loads(run(str(source_exe), "--service-status", fresh).stdout)
                        if state["state"] != "stopped" or state["startup"] != "manual":
                            raise RuntimeError("provisioning started or enabled new service")
                        if token.encode() in (fresh_root / "service-profile.bin").read_bytes():
                            raise RuntimeError("provisioning wrote plaintext credentials")
                        def update(data, confirmation=fresh):
                            return subprocess.run([str(source_exe), "--service-update", fresh, confirmation],
                                                  input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
                        saved_profile = fresh_root / "service-profile.bin"
                        before = saved_profile.read_bytes()
                        run(str(source_exe), "--service-manage", fresh, "start")
                        e2e.wait_for(url, body, [relay], seconds=35)
                        if update(profile).returncode == 0 or saved_profile.read_bytes() != before:
                            raise RuntimeError("running service profile replaced")
                        if run(str(source_exe), "--service-unregister", fresh, fresh, check=False).returncode == 0:
                            raise RuntimeError("running service unregistered by desktop")
                        run(str(source_exe), "--service-manage", fresh, "stop")
                        wait_state(fresh, 1)
                        history_file = fresh_root / "history" / "traffic-history.json"
                        if not history_file.is_file():
                            raise RuntimeError("one-click service did not persist traffic")
                        report["one_click_provision"] = True
                        before_history = json.loads(history_file.read_text(encoding="utf-8"))
                        invalid = json.loads(profile)
                        invalid["mappings"][0]["localPort"] = 0
                        if update(json.dumps(invalid).encode()).returncode == 0 or saved_profile.read_bytes() != before:
                            raise RuntimeError("invalid profile update changed saved credentials")
                        if update(profile, "wrong").returncode == 0 or saved_profile.read_bytes() != before:
                            raise RuntimeError("incorrect confirmation accepted")
                        alternate = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                        changed_body = secrets.token_hex(40).encode()
                        # Handler closes over body, so use a distinct fixture handler.
                        class AlternateHandler(http.server.BaseHTTPRequestHandler):
                            def do_GET(self):
                                self.send_response(200)
                                self.send_header("Content-Length", str(len(changed_body)))
                                self.end_headers()
                                self.wfile.write(changed_body)
                            def log_message(self, *args):
                                pass
                        alternate.RequestHandlerClass = AlternateHandler
                        threading.Thread(target=alternate.serve_forever, daemon=True).start()
                        try:
                            changed = json.loads(profile)
                            changed["mappings"][0]["localPort"] = alternate.server_port
                            result = update(json.dumps(changed).encode())
                            if result.returncode:
                                raise RuntimeError("profile update failed: " + result.stderr.decode(errors="replace"))
                            if saved_profile.read_bytes() == before or token.encode() in saved_profile.read_bytes():
                                raise RuntimeError("updated profile not encrypted/replaced")
                            state = json.loads(run(str(source_exe), "--service-status", fresh).stdout)
                            if state["state"] != "stopped" or state["startup"] != "disabled":
                                raise RuntimeError("updated service did not remain disabled")
                            if run(str(source_exe), "--service-manage", fresh, "start", check=False).returncode == 0:
                                raise RuntimeError("disabled service started")
                            run(str(source_exe), "--service-manage", fresh, "autostart-off")
                            run(str(source_exe), "--service-manage", fresh, "start")
                            e2e.wait_for(url, changed_body, [relay], seconds=35)
                            run(str(source_exe), "--service-manage", fresh, "stop")
                            wait_state(fresh, 1)
                            report["profile_update"] = True
                        finally:
                            alternate.shutdown()
                            alternate.server_close()
                        after_history = json.loads(history_file.read_text(encoding="utf-8"))
                        if after_history["uploadBytes"] < before_history["uploadBytes"] + len(changed_body):
                            raise RuntimeError("profile update lost saved traffic")
                        # Update the real SCM service to mixed TCP/UDP after the
                        # existing measured TCP lifecycle. Preserve historical data.
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_fixture:
                            udp_fixture.bind(("127.0.0.1", 0))
                            udp_fixture.settimeout(.2)
                            stop_echo = threading.Event()
                            def echo_udp():
                                while not stop_echo.is_set():
                                    try:
                                        data, peer = udp_fixture.recvfrom(2048)
                                        udp_fixture.sendto(b"U" + data, peer)
                                    except socket.timeout:
                                        continue
                            echo_thread = threading.Thread(target=echo_udp, daemon=True)
                            echo_thread.start()
                            def udp_roundtrip():
                                payload = secrets.token_bytes(128)
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                                    sock.settimeout(.5)
                                    sock.connect(("127.0.0.1", udp_mapped))
                                    try:
                                        sock.send(payload)
                                        return sock.recv(2048) == b"U" + payload
                                    except (socket.timeout, ConnectionResetError):
                                        return False
                            def wait_mixed():
                                e2e.wait_for(url, body, [relay], seconds=35)
                                deadline = time.monotonic() + 35
                                while time.monotonic() < deadline:
                                    if udp_roundtrip():
                                        return
                                    time.sleep(.2)
                                raise RuntimeError("real SCM UDP echo unavailable")
                            try:
                                mixed = json.loads(profile)
                                mixed["mappings"].append({"protocol": "udp", "name": "datagram",
                                    "localPort": udp_fixture.getsockname()[1], "token": udp_token})
                                result = update(json.dumps(mixed).encode())
                                if result.returncode:
                                    raise RuntimeError("mixed SCM profile update rejected")
                                ciphertext = saved_profile.read_bytes()
                                if token.encode() in ciphertext or udp_token.encode() in ciphertext:
                                    raise RuntimeError("mixed profile plaintext credential")
                                state = json.loads(run(str(source_exe), "--service-status", fresh).stdout)
                                assert state["state"] == "stopped" and state["startup"] == "disabled"
                                run(str(source_exe), "--service-manage", fresh, "autostart-off")
                                run(str(source_exe), "--service-manage", fresh, "start")
                                wait_mixed()
                                report["mixed_service_forwarded"] = True
                                host = service_pid(fresh)
                                old_child = engine_child(host, fresh_root)
                                assert old_child is not None
                                run("taskkill.exe", "/PID", str(old_child[0]), "/F")
                                deadline = time.monotonic() + 35
                                while time.monotonic() < deadline:
                                    child = engine_child(host, fresh_root)
                                    if child is not None and child[0] != old_child[0] and not old_child[1].exists():
                                        break
                                    time.sleep(.25)
                                else:
                                    raise RuntimeError("mixed SCM child did not recover")
                                assert service_pid(fresh) == host
                                wait_mixed()
                                report["mixed_service_recovered"] = True
                                # Observe a real UDP-only increment after the mixed engine recovers.
                                # No HTTP request is issued between the two snapshots.
                                def sample():
                                    deadline = time.monotonic() + 15
                                    while time.monotonic() < deadline:
                                        snap = json.loads(run(str(source_exe), "--service-status", fresh).stdout)
                                        record = snap["traffic"]
                                        if (snap["state"] == "running" and record is not None
                                                and record["enginePid"] == child[0]
                                                and record["uploadBytes"] >= 129 and record["downloadBytes"] >= 128):
                                            return record
                                        time.sleep(.25)
                                    raise RuntimeError("mixed service traffic sample unavailable")
                                initial = sample()
                                assert udp_roundtrip()
                                deadline = time.monotonic() + 15
                                while time.monotonic() < deadline:
                                    final = sample()
                                    if (final["uploadBytes"] == initial["uploadBytes"] + 129
                                            and final["downloadBytes"] == initial["downloadBytes"] + 128):
                                        break
                                    time.sleep(.25)
                                else:
                                    raise RuntimeError("UDP-only service traffic delta is not exact")
                                assert (child[1] / "traffic.json").is_file()
                                report["mixed_service_udp_upload_delta"] = final["uploadBytes"] - initial["uploadBytes"]
                                report["mixed_service_udp_download_delta"] = final["downloadBytes"] - initial["downloadBytes"]
                                report["mixed_service_measured_traffic"] = True
                                run(str(source_exe), "--service-manage", fresh, "stop")
                                wait_state(fresh, 1)
                                assert not any((fresh_root / "runtime").iterdir())
                                assert not udp_roundtrip() and e2e.get(url) != body
                                mixed_history = json.loads(history_file.read_text(encoding="utf-8"))
                                assert mixed_history["uploadBytes"] >= after_history["uploadBytes"] + final["uploadBytes"]
                                assert mixed_history["downloadBytes"] >= after_history["downloadBytes"] + final["downloadBytes"]
                                after_history = mixed_history
                                report["mixed_service_stopped"] = True
                            finally:
                                stop_echo.set()
                                echo_thread.join(timeout=2)
                        if run(str(source_exe), "--service-unregister", fresh, "wrong", check=False).returncode == 0:
                            raise RuntimeError("incorrect unregister confirmation accepted")
                        run(str(source_exe), "--service-unregister", fresh, fresh)
                        if not saved_profile.is_file() or json.loads(history_file.read_text(encoding="utf-8")) != after_history:
                            raise RuntimeError("unregister deleted protected data")
                        deadline = time.monotonic() + 25
                        while time.monotonic() < deadline:
                            if sc("query", fresh, check=False).returncode == 1060:
                                break
                            time.sleep(.25)
                        else:
                            raise RuntimeError("desktop unregister did not remove SCM registration")
                        report["desktop_unregister"] = True
                    finally:
                        fresh_control("recovery-off", check=False)
                        fresh_control("stop", check=False)
                        fresh_control("unregister", check=False)
                        # Only remove the newly created disposable CI fixture.
                        shutil.rmtree(fresh_root)
            finally:
                if relay is not None:
                    e2e.terminate(relay)
                    relay = None
        control("unregister")
        if not (root / "service-profile.bin").is_file():
            raise RuntimeError("unregister unexpectedly deleted credentials")
        report["unregister_preserved_profile"] = True
        if json.loads((root / "history" / "traffic-history.json").read_text(encoding="utf-8")) != final_history:
            raise RuntimeError("unregister modified saved history")
        report["history_preserved_unregister"] = True
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
        if run(str(executable), "--service-status", name, check=False).returncode == 0:
            raise RuntimeError("deleted service reported available")
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
