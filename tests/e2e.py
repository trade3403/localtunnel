"""Real local TCP/HTTP forwarding through two Rathole processes; not public E2E."""
import base64
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "test-results"
RESULTS.mkdir(exist_ok=True)
WINDOWS = os.name == "nt"
EXE = ".exe" if WINDOWS else ""
CLI = ROOT / "target" / "release" / ("localtunnel" + EXE)
ENGINE_VERSION = "v0.5.0"

def engine(directory):
    from pinned_engine import acquire
    binary, report = acquire(directory)
    (RESULTS / "engine.json").write_text(json.dumps(report, indent=2))
    return binary

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def terminate(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=8)

def get(url):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=1) as r:
            return r.read()
    except (OSError, http.client.HTTPException):
        return None

def wait_for(url, body, processes, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("tunnel process exited prematurely")
        if get(url) == body:
            return
        time.sleep(.4)
    raise RuntimeError("expected fixture response did not traverse tunnel")

def main():
    result = {"scope": "single-host real encrypted tunnel", "public_e2e": "BLOCKED: no public relay/domain", "passed": []}
    processes, handles, redactions = [], [], []
    fixture = None
    fixture2 = None
    try:
        with tempfile.TemporaryDirectory(prefix="localtunnel-") as tmp:
            d = Path(tmp)
            binary = engine(d)
            keys = subprocess.check_output([str(binary), "--genkey"], text=True, timeout=15)
            private = re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
            public = re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
            token, bad = secrets.token_hex(32), secrets.token_hex(32)
            redactions.extend([private, public, token, bad])
            body = ("localtunnel-" + secrets.token_hex(24)).encode()
            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"
                def do_GET(self):
                    if self.path == "/ws":
                        ws_key = self.headers.get("Sec-WebSocket-Key")
                        if not ws_key or self.headers.get("Upgrade", "").lower() != "websocket":
                            self.send_error(400)
                            return
                        accept = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                        self.send_response(101)
                        self.send_header("Upgrade", "websocket")
                        self.send_header("Connection", "Upgrade")
                        self.send_header("Sec-WebSocket-Accept", accept)
                        self.end_headers()
                        self.connection.settimeout(5)
                        header = self.rfile.read(2)
                        if len(header) != 2 or header[0] != 0x81 or not header[1] & 0x80 or (header[1] & 127) > 125:
                            self.close_connection = True
                            return
                        size = header[1] & 127
                        mask = self.rfile.read(4)
                        payload = self.rfile.read(size)
                        if len(mask) == 4 and len(payload) == size:
                            self.wfile.write(bytes([0x81, size]) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
                            self.wfile.flush()
                        self.close_connection = True
                        return
                    if self.path == "/headers":
                        data = "|".join(self.headers.get(h, "") for h in ("X-Forwarded-For", "X-Forwarded-Proto", "Forwarded")).encode()
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                def log_message(self, *args):
                    pass
            fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=fixture.serve_forever, daemon=True).start()
            a, b = port(), port()
            while b == a:
                b = port()
            url = f"http://127.0.0.1:{b}/"
            env = {**os.environ, "LOCALTUNNEL_TOKEN": token, "LOCALTUNNEL_SERVER_PRIVATE_KEY": private, "LOCALTUNNEL_SERVER_PUBLIC_KEY": public}
            server, client, wrong = [d / (s + ".toml") for s in ("server", "client", "wrong")]
            def config(args, custom_env):
                subprocess.run([str(CLI), *map(str, args)], env=custom_env, check=True, timeout=15)
            config(["server-config", server, f"127.0.0.1:{a}", "web", b], env)
            args = ["client-config", client, f"127.0.0.1:{a}", "web", f"127.0.0.1:{fixture.server_port}"]
            config(args, env)
            args[1] = wrong
            config(args, {**env, "LOCALTUNNEL_TOKEN": bad})
            result["passed"].append("Rust config generation")
            def launch(path, label):
                log = (RESULTS / (label + ".log")).open("wb")
                handles.append(log)
                p = subprocess.Popen([str(binary), str(path)], stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "RUST_LOG": "warn"})
                processes.append(p)
                return p
            try:
                relay = launch(server, "relay")
                invalid = launch(wrong, "invalid-agent")
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if relay.poll() is not None:
                        raise RuntimeError("relay failed during unauthorized test")
                    if get(url) == body:
                        raise RuntimeError("wrong token exposed fixture")
                    time.sleep(.3)
                terminate(invalid)
                result["passed"].append("wrong token cannot forward")
                agent = launch(client, "agent")
                wait_for(url, body, [relay, agent])
                result["passed"].append("HTTP body through encrypted reverse tunnel")
                for _ in range(8):
                    if get(url) != body:
                        raise RuntimeError("repeated request failed")
                result["passed"].append("repeated HTTP requests")
                terminate(relay)
                if get(url) == body:
                    raise RuntimeError("stopped relay still forwards")
                relay = launch(server, "relay-restarted")
                wait_for(url, body, [relay, agent], seconds=60)
                result["passed"].append("agent reconnects after relay restart")
                terminate(agent)
                terminate(relay)
                body2 = ("localtunnel-api-" + secrets.token_hex(24)).encode()
                class ApiHandler(Handler):
                    def do_GET(self):
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body2)))
                        self.end_headers()
                        self.wfile.write(body2)
                fixture2 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
                threading.Thread(target=fixture2.serve_forever, daemon=True).start()
                c = port()
                while c in (a, b):
                    c = port()
                url2 = f"http://127.0.0.1:{c}/"
                token2 = secrets.token_hex(32)
                redactions.append(token2)
                multi_env = {**env, "LOCALTUNNEL_TOKEN_1": token, "LOCALTUNNEL_TOKEN_2": token2}
                multi_server, multi_client = d / "multi-server.toml", d / "multi-client.toml"
                config(["server-multi", multi_server, f"127.0.0.1:{a}", "web", b, "api", c], multi_env)
                config(["client-multi", multi_client, f"127.0.0.1:{a}", "web", f"127.0.0.1:{fixture.server_port}", "api", f"127.0.0.1:{fixture2.server_port}"], multi_env)
                relay = launch(multi_server, "multi-relay")
                agent = launch(multi_client, "multi-agent")
                wait_for(url, body, [relay, agent])
                wait_for(url2, body2, [relay, agent])
                result["passed"].append("two isolated mappings with different local services")
                pairs = [(url, body), (url2, body2)] * 16
                def verify(pair):
                    return get(pair[0]) == pair[1]
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    if not all(pool.map(verify, pairs)):
                        raise RuntimeError("concurrent mappings returned incorrect data")
                result["passed"].append("32 concurrent/interleaved HTTP requests across two mappings")
                if os.environ.get("LOCALTUNNEL_UDP_E2E") == "1":
                    from udp_e2e import exercise as udp_exercise
                    udp_exercise(d,binary,CLI.resolve(),private,public,RESULTS,port,terminate)
                    from mixed_e2e import exercise as mixed_exercise
                    mixed_exercise(d,binary,CLI.resolve(),private,public,RESULTS,port,terminate,get,body,fixture.server_port)
                if os.environ.get("LOCALTUNNEL_NATIVE_AGENT_PROCESS_E2E") == "1":
                    from unix_agent_process_e2e import exercise
                    exercise(d,binary,CLI.resolve(),body,fixture.server_port,private,public,RESULTS,port,wait_for,get,terminate)
                if os.environ.get("LOCALTUNNEL_GATEWAY_E2E") == "1":
                    from gateway_e2e import check_gateway
                    check_gateway(d, CLI, (b, c), (body, body2), port, result["passed"], RESULTS)
            finally:
                for p in reversed(processes):
                    terminate(p)
                for h in handles:
                    h.close()
    finally:
        if fixture2:
            fixture2.shutdown()
            fixture2.server_close()
        if fixture:
            fixture.shutdown()
            fixture.server_close()
        for log in RESULTS.glob("*.log"):
            content = log.read_text(errors="replace")
            for secret in redactions:
                content = content.replace(secret, "[REDACTED]")
            log.write_text(content)
        (RESULTS / "report.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
