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

def check_gateway(directory, cli, ports, expected, port_factory, passed):
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
        log = (directory.parent / (mode + "-nginx.log")).open("wb")
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

    def request(port, host, tls=False, sni=None, path="/", headers=None):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            if tls:
                sock = context.wrap_socket(sock, server_hostname=sni or host)
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
