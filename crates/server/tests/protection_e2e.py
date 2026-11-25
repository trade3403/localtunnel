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
        s.settimeout(18)
        s.sendall(b"POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
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

            # All bodies deliberately incomplete, so they hold application
            # permits rather than executing authentication or mutating SQL.
            started = time.monotonic()
            for _ in range(32):
                sockets.append(slow(port))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = request(port, "/readyz")
                if result[:2] == (503, b"request concurrency exceeded"):
                    assert security(result)["retry-after"] == "1"
                    break
                time.sleep(.05)
            else:
                raise AssertionError("32 admitted partial bodies did not exhaust permits")
            report["real_concurrent_requests_rejected_without_queue"] = True
            with http.client.HTTPResponse(sockets[0]) as response:
                response.begin()
                assert response.status == 503
                assert response.read() == b"request deadline exceeded"
            assert 9 <= time.monotonic()-started < 20, "unexpected deadline"
            for s in sockets:
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
