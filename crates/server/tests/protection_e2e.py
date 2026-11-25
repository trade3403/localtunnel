"""Real loopback API admission, timeout and recovery; no external target."""
from contextlib import closing
import http.client
import json
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time

exe = str(Path(sys.argv[1]).resolve())
evidence = Path(sys.argv[2])
report = {}

def request(port, path="/healthz", headers=None, method="GET", body=None):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as conn:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())

def launch(root):
    p = subprocess.Popen([exe, str(root), "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            assert selector.select(20), "startup timeout"
        line = p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:")
        return p, int(line.rsplit(":", 1)[1])
    except BaseException:
        stop(p)
        raise

def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)

def slow(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        # Hyper sends 100 Continue when the admitted handler starts polling
        # the body. A successful TCP send alone does not prove admission.
        s.settimeout(3)
        s.sendall(b"POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
        interim = bytearray()
        while not interim.endswith(b"\r\n\r\n"):
            chunk = s.recv(1)
            if not chunk or len(interim) >= 1024:
                raise AssertionError("connection closed or oversized response before admission")
            interim.extend(chunk)
        assert interim.split(b"\r\n", 1)[0] == b"HTTP/1.1 100 Continue", (
            "expected admitted body read, received " + repr(interim.split(b"\r\n", 1)[0]))
        s.sendall(b"{")
        s.settimeout(18)
        return s
    except BaseException:
        s.close()
        raise

def security(response):
    h = {k.lower(): v for k,v in response[2].items()}
    assert h["cache-control"] == "no-store"
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    return h

try:
    with tempfile.TemporaryDirectory() as d:
        p, port = launch(d)
        sockets = []
        try:
            healthy = request(port)
            assert healthy[:2] == (200, b"ok")
            security(healthy)
            security(request(port, "/api/v1/mappings"))
            assert request(port, "/healthz?" + "a"*2048)[0] == 414
            assert request(port, headers={"X-Test": "a"*17000})[0] == 431
            assert request(port, "/api/v1/auth/login", {"Content-Type":"application/json"}, "POST", b"x"*4097)[0] == 413
            assert request(port, "/readyz")[:2] == (200, b"ready")
            report["real_request_bounds_and_response_headers"] = True
            for headers in (
                {"Host": "external.example.test"},
                {"Host": "127.0.0.1.example.test"},
                {"Host": "localhost:65536"},
                {"Origin": "https://external.example.test"},
                {"Origin": "null"},
                {"Origin": "http://127.0.0.1:1432"},
                {"Sec-Fetch-Site": "cross-site"},
                {"Sec-Fetch-Site": "same-site"},
            ):
                denied = request(port, headers=headers)
                assert denied[:2] == (403,b"invalid local request origin")
                assert security(denied)
                assert not any(k.lower().startswith("access-control-allow") for k in denied[2])
            allowed = request(port,headers={"Host":"127.0.0.1:1430","Origin":"http://127.0.0.1:1430","Sec-Fetch-Site":"same-origin"})
            assert allowed[:2] == (200,b"ok")
            # Duplicate Origin is never accepted, even if both are allowed.
            with closing(http.client.HTTPConnection("127.0.0.1",port,timeout=5)) as conn:
                conn.putrequest("GET","/healthz")
                conn.putheader("Origin","http://127.0.0.1:1430")
                conn.putheader("Origin","http://127.0.0.1:1430")
                conn.endheaders()
                r=conn.getresponse()
                assert r.status==403 and r.read()==b"invalid local request origin"
            report["real_local_host_origin_and_fetch_site_guard"] = True

            # All bodies deliberately incomplete, so they hold application
            # permits rather than executing authentication or mutating SQL.
            started = time.monotonic()
            for _ in range(32):
                sockets.append(slow(port))
            assert time.monotonic()-started < 6, "admitting all 32 requests took too long"
            result = request(port, "/readyz")
            assert result[:2] == (503, b"request concurrency exceeded"), (
                "32 confirmed body readers did not exhaust permits: " + repr(result[:2]))
            assert security(result)["retry-after"] == "1"
            report["real_concurrent_requests_rejected_without_queue"] = True
            # Read every original response; none may have been silently
            # refused, parsed as invalid JSON or released prematurely.
            for index, s in enumerate(sockets):
                with http.client.HTTPResponse(s) as response:
                    response.begin()
                    assert response.status == 503, f"unexpected slow response {index}: {response.status}"
                    assert response.read() == b"request deadline exceeded"
                    assert response.getheader("Retry-After") == "1"
                if index == 0:
                    assert 9 <= time.monotonic()-started < 20, "unexpected deadline"
                s.close()
            sockets = []
            deadline = time.monotonic()+5
            while time.monotonic()<deadline:
                if request(port, "/readyz")[:2] == (200,b"ready"):
                    break
                time.sleep(.1)
            else:
                raise AssertionError("admission capacity did not recover")
            report["real_partial_body_deadline_and_capacity_recovery"] = True

            # Single persistent local connection, bounded request count.
            # The application budget must reject burst traffic, not merely
            # report a configured number. Auth-specific budgets are separate.
            limited = False
            with closing(http.client.HTTPConnection("127.0.0.1",port,timeout=5)) as conn:
                end = time.monotonic()+10
                for _ in range(3000):
                    conn.request("GET","/healthz")
                    r = conn.getresponse()
                    body = r.read()
                    if r.status == 429:
                        assert body == b"request rate exceeded"
                        assert r.getheader("Retry-After") == "1"
                        limited = True
                        break
                    assert r.status == 200 and body == b"ok"
                    if time.monotonic() >= end:
                        break
            assert limited, "actual burst never reached admission limit"
            time.sleep(1.1)
            assert request(port, "/readyz")[:2] == (200,b"ready")
            report["real_global_rate_limit_and_refill"] = True
        finally:
            for s in sockets:
                s.close()
            stop(p)
finally:
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2), encoding="utf-8")
