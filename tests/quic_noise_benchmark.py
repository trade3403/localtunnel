"""Paired single-runner application benchmark of pinned Noise and experimental QUIC.

Both paths use the same framed TCP echo fixture, pre-generated binary payloads,
and identical sequential/concurrent batches. QUIC is initiated inside the relay;
Noise uses its actual loopback ingress socket. Not a transport-only benchmark.
"""
import asyncio
import os
from pathlib import Path
import re
import secrets
import socket
import statistics
import subprocess
import time

from quic_experiment import frame, send

CLI = Path(__file__).resolve().parents[1] / "target/release/localtunnel"


def two_ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        return first.getsockname()[1], second.getsockname()[1]


async def compare(root, binary, engine_report, local, reverse, observed):
    control, mapped = two_ports()
    keys = subprocess.check_output([str(binary), "--genkey"], text=True, timeout=10)
    private = re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
    public = re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)", keys).group(1)
    env = dict(os.environ, LOCALTUNNEL_TOKEN=secrets.token_hex(32),
               LOCALTUNNEL_SERVER_PRIVATE_KEY=private,
               LOCALTUNNEL_SERVER_PUBLIC_KEY=public)
    server, client = root / "benchmark-server.toml", root / "benchmark-client.toml"
    for args in [
        ["server-config", str(server), f"127.0.0.1:{control}", "bench", str(mapped)],
        ["client-config", str(client), f"127.0.0.1:{control}", "bench", f"127.0.0.1:{local}"],
    ]:
        subprocess.run([str(CLI), *args], env=env, check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in (server, client):
        path.chmod(0o600)
        assert 'type = "noise"' in path.read_text()
    processes = []

    async def noise(data):
        async with asyncio.timeout(10):
            reader, writer = await asyncio.open_connection("127.0.0.1", mapped)
            try:
                send(writer, data)
                await writer.drain()
                assert await frame(reader) == data, "Noise echo integrity mismatch"
            finally:
                writer.close()
                await writer.wait_closed()

    def alive():
        assert len(processes) == 2 and all(p.poll() is None for p in processes), "Noise engine exited"

    async def measure(fn, seq, batches):
        latencies = []
        for payload in seq:
            t = time.perf_counter()
            await fn(payload)
            latencies.append((time.perf_counter() - t) * 1000)
        start = time.perf_counter()
        for batch in batches:
            await asyncio.gather(*(fn(data) for data in batch))
        elapsed = time.perf_counter() - start
        total = sum(len(data) for batch in batches for data in batch)
        ordered = sorted(latencies)
        return {"sequential_count": len(seq),
                "latency_median_ms": round(statistics.median(ordered), 6),
                "latency_p95_ms": round(ordered[(95*len(ordered)+99)//100-1], 6),
                "latency_max_ms": round(max(ordered), 6),
                "concurrent_count": sum(map(len, batches)),
                "bytes_each_direction": total,
                "elapsed_seconds": round(elapsed, 6),
                "combined_application_goodput_mbps": round(2*total*8/elapsed/1e6, 6)}

    try:
        for path in (server, client):
            processes.append(subprocess.Popen([str(binary), str(path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # Warm both paths, preserving the existing QUIC connection during Noise
        # startup. A failed warmup does not count as a measured transaction.
        deadline = time.monotonic() + 25
        while True:
            alive()
            await reverse(secrets.token_bytes(32))
            try:
                async with asyncio.timeout(1):
                    await noise(secrets.token_bytes(32))
                break
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                if time.monotonic() >= deadline:
                    raise AssertionError("Noise benchmark warmup failed")
                await asyncio.sleep(.2)
        rounds = []
        for index in range(4):
            # Generate once, outside timed regions; reuse exact bytes for both.
            seq = [secrets.token_bytes(1024) for _ in range(16)]
            batches = [[secrets.token_bytes(64*1024) for _ in range(8)] for _ in range(2)]
            order = ("noise_tcp", "quic") if index % 2 == 0 else ("quic", "noise_tcp")
            row = {"order": list(order)}
            for label in order:
                alive()
                before = len(observed)
                fn = noise if label == "noise_tcp" else reverse
                row[label] = await measure(fn, seq, batches)
                assert len(observed) - before == 32, "fixture transaction count mismatch"
                assert row[label]["bytes_each_direction"] == 1048576
            rounds.append(row)
        alive()
        return {"scope": "same-host paired application benchmark, not wire-only or WAN",
                "engine": engine_report,
                "noise_path": "TCP ingress -> pinned Rathole Noise/TCP -> local TCP echo",
                "quic_path": "relay-initiated QUIC stream -> local TCP echo; no external TCP ingress",
                "latency_payload_bytes": 1024, "parallel_payload_bytes": 65536,
                "parallel_streams": 8, "rounds": rounds,
                "verified_transactions_per_protocol": 128,
                "median_of_rounds": {
                    label: {
                        key: round(statistics.median(row[label][key] for row in rounds), 6)
                        for key in ("latency_median_ms", "latency_p95_ms",
                                    "combined_application_goodput_mbps")
                    } for label in ("noise_tcp", "quic")
                },
                "passed": ["both real encrypted paths warmed",
                           "four alternating paired rounds with identical payloads",
                           "all 256 measured transactions verified at shared fixture"]}
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:
                    await asyncio.to_thread(p.wait, 5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    await asyncio.to_thread(p.wait, 5)
