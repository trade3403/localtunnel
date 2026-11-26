"""Actual local HTTP/1 sockets, header deadline, connection cap and recovery."""
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

def health(port):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=2)) as conn:
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        return response.status, response.read()

def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    sock.settimeout(9)
    return sock

def partial(port):
    sock = connect(port)
    try:
        sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
        return sock
    except BaseException:
        sock.close()
        raise

def disconnected(sock):
    # Hyper may close silently or send 408; never accept a normal response.
    data = b""
    try:
        while len(data) < 32768:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        else:
            raise AssertionError("unexpected large response")
    except (ConnectionResetError, BrokenPipeError):
        pass
    assert not data or data.startswith(b"HTTP/1.1 408 "), "unexpected response before disconnect"

def recover(port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if health(port) == (200, b"ok"):
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise AssertionError("connection capacity did not recover")

try:
    with tempfile.TemporaryDirectory() as d:
        p, port = launch(d)
        sockets = []
        try:
            assert health(port) == (200,b"ok")
            # The header deadline is absolute, not a timer reset by a byte.
            started = time.monotonic()
            sock = partial(port)
            sockets.append(sock)
            time.sleep(3)
            sock.sendall(b"X-Partial: x")
            disconnected(sock)
            elapsed = time.monotonic()-started
            assert 4 <= elapsed < 8, "header deadline did not bound trickle"
            sock.close()
            sockets.clear()
            recover(port)
            report["real_incomplete_header_absolute_deadline"] = True

            # Idle keep-alive after a real response must release its slot.
            sock = connect(port)
            sockets.append(sock)
            sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            with http.client.HTTPResponse(sock) as response:
                response.begin()
                assert response.status == 200 and response.read() == b"ok"
            started = time.monotonic()
            disconnected(sock)
            assert time.monotonic()-started < 8, "idle keepalive not released"
            sock.close()
            sockets.clear()
            recover(port)
            report["real_keepalive_idle_connection_released"] = True

            # Fill connection slots without consuming application permits.
            started = time.monotonic()
            for _ in range(64):
                sockets.append(partial(port))
            time.sleep(.2)
            assert time.monotonic()-started < 3, "connection fixture too slow"
            with closing(connect(port)) as extra:
                try:
                    extra.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                except (ConnectionResetError, BrokenPipeError):
                    pass
                extra.settimeout(1)
                disconnected(extra)
            # An admitted connection still serves actual HTTP, proving that
            # rejection was not a service crash or blanket refusal.
            sockets[-1].sendall(b"Connection: close\r\n\r\n")
            with http.client.HTTPResponse(sockets[-1]) as response:
                response.begin()
                assert response.status == 200 and response.read() == b"ok"
            report["real_connection_cap_and_admitted_request"] = True
            for sock in sockets:
                sock.close()
            sockets.clear()
            recover(port)
            assert p.poll() is None
            report["real_transport_capacity_recovery"] = True

            # Keep a single actual HTTP/1 socket active, so neither the
            # five-second header/idle deadline nor the request deadline
            # can explain its closure. Never reconnect inside this fixture.
            # Run at the unchanged production-preview 120 second lifetime.
            time.sleep(.5)
            proc_fd = Path("/proc") / str(p.pid) / "fd"
            fd_baseline = len(list(proc_fd.iterdir()))
            started = time.monotonic()
            with closing(connect(port)) as long_conn:
                long_conn.settimeout(3)
                successes = 0
                last_ok = 0.0
                ended = None
                while time.monotonic() - started < 130:
                    try:
                        long_conn.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        with http.client.HTTPResponse(long_conn) as response:
                            response.begin()
                            assert response.status == 200 and response.read() == b"ok"
                            assert not response.will_close, "unexpected HTTP connection-close response"
                    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
                        ended = time.monotonic() - started
                        break
                    successes += 1
                    last_ok = time.monotonic() - started
                    # Independent fresh connection must continue to serve.
                    if successes % 10 == 0:
                        assert health(port) == (200, b"ok")
                    time.sleep(1)
                assert ended is not None, "active connection outlived its lifetime"
                report["connection_lifetime_measurements"] = {
                    "successful_requests_on_same_socket": successes,
                    "last_success_seconds": round(last_ok, 3),
                    "disconnect_seconds": round(ended, 3),
                    "fd_before": fd_baseline,
                }
                assert successes >= 100 and last_ok >= 115, "connection closed before expected lifetime"
                assert 118 <= ended <= 125, "active connection lifetime outside tolerance"
                assert ended - last_ok < 5, "closure not distinguishable from idle deadline"
            report["real_active_connection_total_lifetime"] = True
            recover(port)
            # A new persistent socket is independently usable, and the
            # expired socket's task/descriptor no longer consumes resources.
            with closing(connect(port)) as fresh:
                for _ in range(3):
                    fresh.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    with http.client.HTTPResponse(fresh) as response:
                        response.begin()
                        assert response.status == 200 and response.read() == b"ok"
                        assert not response.will_close
            time.sleep(.5)
            fd_after = len(list(proc_fd.iterdir()))
            report["connection_lifetime_measurements"]["fd_after"] = fd_after
            assert fd_after <= fd_baseline + 2, "connection descriptor growth after expiry"
            assert p.poll() is None
            report["real_connection_lifetime_same_process_recovery"] = True
        finally:
            for sock in sockets:
                sock.close()
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
