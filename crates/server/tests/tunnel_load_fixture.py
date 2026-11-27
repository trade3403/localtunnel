"""Bounded loopback throughput fixture for the real Noise gateway tests."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import http.client
import math
import secrets
import socket
import ssl
import time

PAYLOAD_BYTES = 256 * 1024
WORKERS = 4
ROUNDS = 4
PATH = "/__localtunnel_fixture_echo"

class EchoFixture:
    # Fixture only; never included in the product or exposed outside loopback.
    def do_POST(self):
        self.connection.settimeout(10)
        if self.path != PATH or self.headers.get("Content-Length") != str(PAYLOAD_BYTES):
            self.send_error(400)
            return
        payload = self.rfile.read(PAYLOAD_BYTES)
        if len(payload) != PAYLOAD_BYTES:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Fixture-SHA256", hashlib.sha256(payload).hexdigest())
        self.end_headers()
        self.wfile.write(payload)

def transfer(port, hostname, processes, ca=None, *, workers=WORKERS, rounds=ROUNDS):
    # Each transaction uses a different non-compressible random payload and
    # an independent socket. No retries, fake success, or external endpoints.
    ctx = ssl.create_default_context(cafile=str(ca)) if ca is not None else None

    def one(_):
        payload = secrets.token_bytes(PAYLOAD_BYTES)
        digest = hashlib.sha256(payload).hexdigest()
        headers = (
            f"POST {PATH} HTTP/1.1\r\nHost: {hostname}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            if ctx is not None:
                conn = ctx.wrap_socket(raw, server_hostname=hostname)
            else:
                conn = raw
            with closing(conn):
                conn.sendall(headers + payload)
                with http.client.HTTPResponse(conn) as response:
                    response.begin()
                    assert response.status == 200, f"unexpected gateway status {response.status}"
                    assert response.getheader("Content-Length") == str(PAYLOAD_BYTES)
                    assert response.getheader("X-Fixture-SHA256") == digest
                    echoed = response.read(PAYLOAD_BYTES + 1)
                    assert echoed == payload, "tunnel payload corrupted or truncated"
        return (time.monotonic() - started) * 1000

    latencies = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in range(rounds):
            assert all(p.poll() is None for p in processes), "gateway or tunnel exited"
            latencies.extend(pool.map(one, range(workers)))
    elapsed = time.monotonic() - started
    assert all(p.poll() is None for p in processes)
    assert len(latencies) == workers * rounds and 0 < elapsed <= 60
    verified_bytes = len(latencies) * PAYLOAD_BYTES
    ordered = sorted(latencies)
    return {
        "transactions": len(latencies), "workers": workers,
        "bytes_uploaded": verified_bytes, "bytes_downloaded": verified_bytes,
        "elapsed_seconds": round(elapsed, 6),
        "combined_application_goodput_mbps": round(verified_bytes * 2 * 8 / elapsed / 1_000_000, 3),
        "transaction_latency_ms": {
            "p50": round(ordered[math.ceil(len(ordered) * .5) - 1], 3),
            "p95": round(ordered[math.ceil(len(ordered) * .95) - 1], 3),
            "max": round(max(ordered), 3),
        },
    }


def quota_rejects_transfer(port, hostname, ca=None):
    """A real oversized echo must not complete. Caller verifies the ledger
    and owned process cleanup separately; a generic request failure alone
    is not evidence of quota enforcement."""
    payload = secrets.token_bytes(PAYLOAD_BYTES)
    headers = (
        f"POST {PATH} HTTP/1.1\r\nHost: {hostname}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    ctx = ssl.create_default_context(cafile=str(ca)) if ca is not None else None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
            conn = ctx.wrap_socket(raw, server_hostname=hostname) if ctx else raw
            with closing(conn):
                conn.sendall(headers + payload)
                with http.client.HTTPResponse(conn) as response:
                    response.begin()
                    if response.status != 200:
                        return response.status
                    echoed = response.read(PAYLOAD_BYTES + 1)
                    assert len(echoed) < len(payload), "full echo exceeded monthly quota"
                    assert echoed == payload[:len(echoed)], "corrupt partial response"
                    return 200
    except (OSError, http.client.HTTPException):
        return None
