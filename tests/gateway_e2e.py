"""Linux-only gateway tests against actual encrypted relay ports."""
import base64
import hashlib
import http.client
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time

def check_gateway(directory, cli, ports, expected, port_factory, passed, results):
    names = ("web.example.test", "api.example.test")
    http_port = port_factory()
    tls_port = port_factory()
    while tls_port == http_port:
        tls_port = port_factory()
    cert, key = directory / "cert.pem", directory / "cert.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=web.example.test", "-addext", "subjectAltName=DNS:web.example.test,DNS:api.example.test",
        "-keyout", str(key), "-out", str(cert)], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.create_default_context(cafile=str(cert))
    pairs = [names[0], str(ports[0]), names[1], str(ports[1])]
    processes = []
    handles = []
    def start(mode, port, args):
        prefix = directory / mode
        prefix.mkdir()
        config = prefix / "nginx.conf"
        subprocess.run([str(cli), "gateway-" + mode, str(config), f"127.0.0.1:{port}", *args, *pairs], check=True, timeout=15)
        command = ["nginx", "-p", str(prefix) + "/", "-c", str(config)]
        subprocess.run([*command, "-t"], check=True, timeout=15)
        log = (results / (mode + "-nginx.log")).open("wb")
        # Keep private CI temporary config/certificates out of artifacts.
        handles.append(log)
        process = subprocess.Popen([*command, "-g", "daemon off;"], stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("nginx terminated")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.5):
                    return
            except OSError:
                time.sleep(.2)
        raise RuntimeError("gateway failed to listen")

    def request(port, host, tls=False, sni=None, path="/", headers=None, trust=None):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            if tls:
                sock = (trust or context).wrap_socket(sock, server_hostname=sni or host)
            extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n".encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            return response.status, response.read()
        finally:
            sock.close()

    try:
        start("http", http_port, [])
        start("https", tls_port, [str(cert), str(key)])
        for n, body in zip(names, expected):
            assert request(http_port, n) == (200, body), "HTTP domain routing"
            assert request(tls_port, n, True) == (200, body), "verified HTTPS domain routing"
        passed.append("HTTP and trusted test HTTPS Host routing through two encrypted tunnels")
        assert request(http_port, "unknown.example.test")[0] == 421
        assert request(tls_port, names[1], True, sni=names[0])[0] == 421
        try:
            request(tls_port, "unknown.example.test", True)
        except (ssl.SSLError, ConnectionError):
            pass
        else:
            raise RuntimeError("unknown SNI was accepted")
        passed.append("unknown Host, unknown TLS SNI and mismatched SNI/Host rejected")
        status, headers = request(http_port, names[0], path="/headers", headers={
            "X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "fake",
            "Forwarded": "for=203.0.113.9"})
        assert status == 200 and headers == b"127.0.0.1|http|", headers
        passed.append("spoofed forwarding headers overwritten")
        # A real WebSocket upgrade followed by masked client text frame and echo.
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=names[0]) as conn:
                ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
                conn.sendall((f"GET /ws HTTP/1.1\r\nHost: {names[0]}\r\nUpgrade: websocket\r\n"
                    f"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {ws_key}\r\n\r\n").encode())
                reader = conn.makefile("rb")
                with reader:
                    assert b" 101 " in reader.readline()
                    accept = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                    headers = {}
                    while True:
                        line = reader.readline()
                        if line == b"\r\n":
                            break
                        if not line:
                            raise RuntimeError("incomplete upgrade")
                        k, v = line.split(b":", 1)
                        headers[k.lower()] = v.strip()
                    assert headers[b"sec-websocket-accept"] == accept
                    payload = b"localtunnel-ws"
                    mask = secrets.token_bytes(4)
                    conn.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
                    assert reader.read(2) == bytes([0x81, len(payload)])
                    assert reader.read(len(payload)) == payload
        passed.append("verified TLS WebSocket upgrade and bidirectional text frame")
        # Certificate preflight rejects short validity, wrong hostname, wrong key.
        def cert_check(certificate, private_key, days, hosts, success):
            run = subprocess.run([str(cli), "cert-check", str(certificate), str(private_key), str(cert), str(days), *hosts],
                                 capture_output=True, timeout=15)
            assert (run.returncode == 0) == success, run.stderr.decode(errors="replace")
        cert_check(cert, key, 0, list(names), True)
        cert_check(cert, key, 2, list(names), False)
        cert_check(cert, key, 0, ["wrong.example.test"], False)
        other_key = directory / "wrong.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(other_key)], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert_check(cert, other_key, 0, list(names), False)
        passed.append("certificate trust, hostname, expiration and private key preflight")
        # Dynamic routes over the running relay: keep the same master and listener.
        managed_port = port_factory()
        while managed_port in (http_port, tls_port, *ports):
            managed_port = port_factory()
        managed = directory / "managed"
        managed.mkdir(mode=0o700)
        endpoint = f"127.0.0.1:{managed_port}"
        def manage(action, routes, success=True):
            run = subprocess.run([str(cli), "gateway-" + action, str(managed), endpoint, *routes],
                                 capture_output=True, timeout=35)
            assert (run.returncode == 0) == success, run.stderr.decode(errors="replace")
        manage("init", pairs[:2])
        log = (results / "managed-nginx.log").open("wb")
        handles.append(log)
        master = subprocess.Popen(["nginx", "-p", str(managed)+"/", "-c", str(managed/"nginx.conf"),
                                  "-g", "daemon off;"], stdout=log, stderr=subprocess.STDOUT)
        processes.append(master)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if master.poll() is not None:
                raise RuntimeError("managed gateway terminated")
            try:
                if request(managed_port, names[0]) == (200, expected[0]):
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise RuntimeError("managed gateway did not start")
        assert request(managed_port, names[1])[0] == 421
        original_pid = (managed/"nginx.pid").read_text()
        manage("apply", pairs)
        assert request(managed_port, names[1]) == (200, expected[1])
        assert request(managed_port, names[0]) == (200, expected[0])
        before = (managed/"nginx.conf").read_bytes()
        manage("apply", [*pairs, names[0], str(ports[1])], success=False)
        assert (managed/"nginx.conf").read_bytes() == before
        assert request(managed_port, names[1]) == (200, expected[1])
        manage("apply", pairs[2:])
        assert request(managed_port, names[0])[0] == 421
        assert request(managed_port, names[1]) == (200, expected[1])
        manage("apply", [])
        assert request(managed_port, names[1])[0] == 421
        assert (managed/"nginx.pid").read_text() == original_pid and master.poll() is None
        passed.append("live gateway add/remove/disable-all routes with same master and invalid update rejected")
        # Managed HTTPS: use versioned certificate files so rollback can retain old material.
        live_tls = port_factory()
        probe = port_factory()
        used = {http_port, tls_port, managed_port, *ports}
        while live_tls in used:
            live_tls = port_factory()
        while probe in used or probe == live_tls:
            probe = port_factory()
        tls_dir = directory / "managed-tls"
        tls_dir.mkdir(mode=0o700)
        new_cert, new_key = directory / "rotated.pem", directory / "rotated.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=web.example.test", "-addext", "subjectAltName=DNS:web.example.test,DNS:api.example.test",
            "-keyout", str(new_key), "-out", str(new_cert)], check=True, timeout=30,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        new_context = ssl.create_default_context(cafile=str(new_cert))
        def manage_tls(action, certificate, private_key, trust_file, routes, success=True):
            run = subprocess.run([str(cli), "gateway-tls-" + action, str(tls_dir),
                f"127.0.0.1:{live_tls}", f"127.0.0.1:{probe}", str(certificate), str(private_key),
                str(trust_file), "0", *routes], capture_output=True, timeout=45)
            assert (run.returncode == 0) == success, run.stderr.decode(errors="replace")
        manage_tls("init", cert, key, cert, pairs[:2])
        log = (results / "managed-tls-nginx.log").open("wb")
        handles.append(log)
        tls_master = subprocess.Popen(["nginx", "-p", str(tls_dir)+"/", "-c", str(tls_dir/"nginx.conf"),
                                     "-g", "daemon off;"], stdout=log, stderr=subprocess.STDOUT)
        processes.append(tls_master)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if tls_master.poll() is not None:
                raise RuntimeError("managed TLS gateway exited")
            try:
                if request(live_tls, names[0], True) == (200, expected[0]):
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise RuntimeError("managed HTTPS gateway did not start")
        original_tls_pid = (tls_dir/"nginx.pid").read_text()
        manage_tls("apply", new_cert, new_key, new_cert, pairs)
        for name, body in zip(names, expected):
            assert request(live_tls, name, True, trust=new_context) == (200, body)
        try:
            request(live_tls, names[0], True)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise RuntimeError("old trust unexpectedly accepted rotated certificate")
        before_tls = (tls_dir/"nginx.conf").read_bytes()
        manage_tls("apply", new_cert, key, new_cert, pairs, success=False)
        assert (tls_dir/"nginx.conf").read_bytes() == before_tls
        assert request(live_tls, names[0], True, trust=new_context) == (200, expected[0])
        manage_tls("apply", new_cert, new_key, new_cert, pairs[2:])
        try:
            request(live_tls, names[0], True, trust=new_context)
        except (ssl.SSLError, ConnectionError):
            pass
        else:
            raise RuntimeError("deleted TLS domain still accepted")
        assert request(live_tls, names[1], True, trust=new_context) == (200, expected[1])
        assert (tls_dir/"nginx.pid").read_text() == original_tls_pid and tls_master.poll() is None
        passed.append("live HTTPS route changes and certificate rotation with verified trust and same master")
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=8)
        for handle in handles:
            handle.close()
