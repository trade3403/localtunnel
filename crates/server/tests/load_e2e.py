"""Bounded real loopback management workload on Linux CI, not a production SLA."""
from concurrent.futures import ThreadPoolExecutor
import json
import http.client
from contextlib import closing
import math
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

exe = str(Path(sys.argv[1]).resolve())
evidence = Path(sys.argv[2])
report = {}
password = secrets.token_hex(24)
ROUNDS = 100
INTERVAL = 0.2
WORKERS = 8

def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)

def launch(root):
    p = subprocess.Popen([exe, str(root), "0"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            assert selector.select(20), "startup timeout"
        line = p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:"), "non-loopback listener"
        return p, "http://" + line.split()[1]
    except BaseException:
        stop(p)
        raise

def request(base, path, token=None, data=None, expected=200):
    headers = {"Connection": "close"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, headers=headers,
        data=None if data is None else json.dumps(data).encode())
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            code, body, cache = response.status, response.read(65537), response.headers.get("Cache-Control")
    except urllib.error.HTTPError as error:
        with error:
            code, body, cache = error.code, error.read(65537), error.headers.get("Cache-Control")
    elapsed = (time.monotonic() - start) * 1000
    assert code == expected, f"unexpected HTTP status {code}, expected {expected}"
    assert cache == "no-store" and len(body) <= 65536
    value = json.loads(body) if body.startswith((b"{", b"[")) else body
    return elapsed, value

def resources(pid):
    proc = Path("/proc") / str(pid)
    rss = next(int(line.split()[1]) for line in (proc / "status").read_text().splitlines()
               if line.startswith("VmRSS:"))
    return {"rss_kib": rss, "fd_count": len(list((proc / "fd").iterdir()))}

def percentile(values, fraction):
    return round(sorted(values)[math.ceil(len(values) * fraction) - 1], 3)

try:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        result = subprocess.run([exe, "--init-admin", str(root)],
            input=json.dumps({"username": "operator", "password": password}).encode(),
            capture_output=True, timeout=20)
        assert result.returncode == 0, "fixture administrator initialization failed"
        p, base = launch(root)
        try:
            _, login = request(base, "/api/v1/auth/login", data={"username": "operator", "password": password})
            admin = login["access_token"]
            _, pairing = request(base, "/api/v1/devices/pairing-code", admin, {})
            _, device = request(base, "/api/v1/devices/enroll",
                data={"pairing_code": pairing["pairing_code"], "name": "load fixture"}, expected=201)
            did, token = device["id"], device["device_token"]
            prefix = "/api/v1/devices/" + did
            operations = [
                ("health", "/healthz", None, None),
                ("ready", "/readyz", None, None),
                ("admin", "/api/v1/auth/me", admin, None),
                ("inventory", "/api/v1/devices", admin, None),
                ("identity", prefix + "/identity", token, None),
                ("config", prefix + "/config", token, None),
                ("status", prefix + "/status", admin, None),
                ("heartbeat", prefix + "/status", token, {"reported_revision": 1, "reported_state": "running"}),
            ]

            def execute(operation):
                name, path, credential, data = operation
                elapsed, value = request(base, path, credential, data)
                if name == "health":
                    assert value == b"ok"
                elif name == "ready":
                    assert value == b"ready"
                elif name == "admin":
                    assert value["username"] == "operator"
                elif name == "inventory":
                    assert len(value) == 1 and value[0]["id"] == did
                elif name == "identity":
                    assert value["id"] == did and value["enabled"] is True
                elif name == "config":
                    assert value["device_id"] == did and value["revision"] == 1 and value["mappings"] == []
                elif name == "status":
                    assert value["device_id"] == did and value["enabled"] is True
                elif name == "heartbeat":
                    assert value["heartbeat_interval_seconds"] == 30 and value["last_seen_at"] > 0
                return name, elapsed

            latencies = {op[0]: [] for op in operations}
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                # Warm up SQLite pool and allocator before measuring baseline.
                for _ in range(5):
                    list(pool.map(execute, operations))
                time.sleep(1)
                baseline = resources(p.pid)
                samples = [baseline]
                start = time.monotonic()
                for index in range(ROUNDS):
                    for name, elapsed in pool.map(execute, operations):
                        latencies[name].append(elapsed)
                    if index % 10 == 9:
                        samples.append(resources(p.pid))
                    # Fixed bounded workload; no accumulating queue and no
                    # automatic retry or catch-up burst when a round is slow.
                    delay = INTERVAL - (time.monotonic() - (start + index * INTERVAL))
                    if delay > 0:
                        time.sleep(delay)
                    else:
                        # Avoid a catch-up burst by shifting the schedule.
                        time.sleep(INTERVAL)
                duration = time.monotonic() - start
            values = [v for group in latencies.values() for v in group]
            report["measurements"] = {
                "requests": len(values), "elapsed_seconds": round(duration, 3),
                "completed_requests_per_second": round(len(values) / duration, 3),
                "http_status_200": len(values), "concurrent_workers": WORKERS,
                "latency_ms": {"p50": percentile(values, .5), "p95": percentile(values, .95),
                               "p99": percentile(values, .99), "max": round(max(values), 3)},
                "per_operation_p95_ms": {k: percentile(v, .95) for k, v in latencies.items()},
                "baseline": baseline, "sampled_max": {key: max(s[key] for s in samples) for key in baseline},
            }
            assert len(values) == ROUNDS * WORKERS and all(len(v) == ROUNDS for v in latencies.values())
            assert 19 <= duration <= 45, "bounded workload duration exceeded"
            report["real_sustained_mixed_management_workload"] = True
            time.sleep(1)
            settled = resources(p.pid)
            report["measurements"]["settled"] = settled
            assert settled["fd_count"] <= baseline["fd_count"] + 8, "descriptor growth after settling"
            assert settled["rss_kib"] <= baseline["rss_kib"] + 65536, "resident memory growth after settling"
            report["real_load_process_resources_sampled_and_recovered"] = True
            _, status = request(base, prefix + "/status", admin)
            assert status["management_online"] is True and status["configuration_current"] is True
            assert request(base, "/readyz")[1] == b"ready"
            request(base, prefix + "/config", expected=401)
            report["real_post_load_heartbeat_readiness_and_auth"] = True

            # A second bounded workload exceeds the process-wide 120/s
            # budget, on the same private test server, with no external target.
            # Eight persistent HTTP/1 connections, each at most 25 requests/s,
            # 250 requests each. No catch-up, no retries, no queued backlog.
            time.sleep(2.1)
            overload_baseline = resources(p.pid)
            port = int(base.rsplit(":", 1)[1])
            blocks = 5
            per_block = 50

            def overload_worker(_):
                counts = []
                latency = []
                with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as conn:
                    for block in range(blocks):
                        tally = {"200": 0, "429": 0}
                        for _ in range(per_block):
                            started = time.monotonic()
                            conn.request("GET", "/healthz")
                            with conn.getresponse() as response:
                                body = response.read(1024)
                                assert response.getheader("Cache-Control") == "no-store"
                                assert response.getheader("X-Content-Type-Options") == "nosniff"
                                assert response.getheader("X-Frame-Options") == "DENY"
                                assert response.getheader("Referrer-Policy") == "no-referrer"
                                if response.status == 200:
                                    assert body == b"ok"
                                else:
                                    assert response.status == 429, f"unexpected overload status {response.status}"
                                    assert body == b"request rate exceeded"
                                    assert response.getheader("Retry-After") == "1"
                                tally[str(response.status)] += 1
                            elapsed = time.monotonic() - started
                            latency.append(elapsed * 1000)
                            time.sleep(max(0, 0.04 - elapsed))
                        counts.append(tally)
                return counts, latency

            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                results = list(pool.map(overload_worker, range(WORKERS)))
            overload_duration = time.monotonic() - started
            counts = [{code: sum(result[0][i][code] for result in results)
                       for code in ("200", "429")} for i in range(blocks)]
            accepted = sum(item["200"] for item in counts)
            limited = sum(item["429"] for item in counts)
            times = [value for result in results for value in result[1]]
            report["overload_measurements"] = {
                "requests": accepted + limited,
                "accepted": accepted, "rate_limited": limited,
                "elapsed_seconds": round(overload_duration, 3),
                "attempted_requests_per_second": round((accepted + limited) / overload_duration, 3),
                "accepted_requests_per_second": round(accepted / overload_duration, 3),
                "request_blocks": counts,
                "latency_ms": {"p50": percentile(times, .5), "p95": percentile(times, .95),
                               "p99": percentile(times, .99), "max": round(max(times), 3)},
                "baseline": overload_baseline,
            }
            assert accepted + limited == WORKERS * blocks * per_block
            assert 9 <= overload_duration <= 20, "overload workload did not complete within its bounded interval"
            assert accepted > 0 and limited > 0, "both successful and rejected responses required"
            assert all(item["200"] > 0 and item["429"] > 0 for item in counts[-2:]), "sustained admission and rejection not observed"
            # The initial full bucket plus refill bounds successful requests,
            # even with scheduling overhead. No threshold is changed here.
            assert accepted <= 240 + math.ceil(120 * overload_duration)
            assert p.poll() is None, "management process exited under load"
            report["real_sustained_rate_overload_bounded_and_rejected"] = True

            # Refill the original process, verify real authenticated read/write,
            # no credential bypass, and no residual descriptor/resource growth.
            time.sleep(2.1)
            assert request(base, "/healthz")[1] == b"ok"
            assert request(base, "/readyz")[1] == b"ready"
            assert request(base, "/api/v1/auth/me", admin)[1]["username"] == "operator"
            _, receipt = request(base, prefix + "/status", token,
                                 {"reported_revision": 1, "reported_state": "idle"})
            assert receipt["last_seen_at"] > 0
            _, state = request(base, prefix + "/status", admin)
            assert state["management_online"] is True and state["configuration_current"] is True
            assert state["reported_state"] == "idle"
            request(base, prefix + "/config", expected=401)
            recovered = resources(p.pid)
            report["overload_measurements"]["recovered"] = recovered
            assert recovered["fd_count"] <= overload_baseline["fd_count"] + 8
            assert recovered["rss_kib"] <= overload_baseline["rss_kib"] + 65536
            assert p.poll() is None
            report["real_overload_recovery_without_restart_and_authenticated_write"] = True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2), encoding="utf-8")
