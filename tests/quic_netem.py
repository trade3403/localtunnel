"""Linux-only, isolated kernel netem evidence for real paired tunnel workloads.

The disposable namespace contains only loopback. Impairment applies to ALL
loopback legs, including the local TCP fixture and the Noise ingress socket.
Never change the runner's default network namespace or use production endpoints.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

from pinned_engine import LOCK, VERSION, native_target, verified_bytes

ROOT = Path(__file__).resolve().parents[1]
NS_SCRIPT = r"""
set -euo pipefail
ip link set lo up
# Namespace must have exactly one interface and no default route.
test "$(ip -o link show | wc -l)" -eq 1
test -z "$(ip route show default)"
test "$(readlink /proc/self/ns/net)" != "$1"
tc qdisc add dev lo root netem limit 10000 delay 10ms loss "$2"
tc qdisc show dev lo > "$6"
# Root is used only for network setup/statistics; run repository tests as runner.
runuser -u "$3" -- "$4" "$5/tests/quic_experiment.py" "$7" --compare "$8"
tc -s -j qdisc show dev lo > "$9"
"""


def run(results):
    results.mkdir(parents=True, exist_ok=True)
    report = {"scope": "real kernel netem on all loopback legs in disposable Linux network namespaces",
              "passed": [], "profiles": []}
    try:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise RuntimeError("requires unprivileged Linux runner and sudo")
        user = subprocess.check_output(["id", "-un"], text=True).strip()
        outer_ns = os.readlink("/proc/self/ns/net")
        target = native_target()
        assert target == "x86_64-unknown-linux-gnu"
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        assert lock["version"] == VERSION
        url = f"https://github.com/rathole-org/rathole/releases/download/{VERSION}/rathole-{target}.zip"
        with tempfile.TemporaryDirectory(prefix="lt-netem-") as temp:
            work = Path(temp)
            archive = work / "engine.zip"
            # Download outside namespace; verify both archive and binary before
            # caching, then re-verify on every offline acquire inside namespace.
            with urllib.request.urlopen(url, timeout=90) as response:
                data = response.read(20*1024*1024+1)
            verified_bytes(data, target, lock["targets"][target])
            archive.write_bytes(data)
            archive.chmod(0o600)
            for label, loss in [("delay", "0%"), ("delay-loss", "1%")]:
                evidence = results / f"quic-netem-{label}.json"
                config = results / f"quic-netem-{label}-qdisc.txt"
                stats = results / f"quic-netem-{label}-stats.json"
                # Exclusive files owned by runner; root only writes qdisc outputs.
                for file in (evidence, config, stats):
                    with file.open("x"):
                        pass
                subprocess.run(["sudo", "-n", "unshare", "--net", "--pid", "--fork",
                                "--kill-child", "--", "bash", "-c", NS_SCRIPT, "netem",
                                outer_ns, loss, user, sys.executable, str(ROOT),
                                str(config), str(evidence), str(archive), str(stats)],
                               cwd=ROOT, check=True, timeout=145)
                assert os.readlink("/proc/self/ns/net") == outer_ns
                text = config.read_text()
                assert "netem" in text and re.search(r"delay\\s+10(?:\\.0+)?ms", text)
                if loss == "1%":
                    assert re.search(r"loss\\s+1(?:\\.0+)?%", text)
                qdiscs = json.loads(stats.read_text())
                netem, = [q for q in qdiscs if q["kind"] == "netem"]
                packets, drops = netem["packets"], netem["drops"]
                assert packets > 0
                assert drops > 0 if loss == "1%" else drops == 0
                actual = json.loads(evidence.read_text())
                assert len(actual["passed"]) == 6
                cmp = actual["comparison"]
                assert len(cmp["rounds"]) == 4 and len(cmp["passed"]) == 3
                assert cmp["verified_transactions_per_protocol"] == 128
                assert cmp["engine"]["pinned_archive_and_binary_verified"] is True
                report["profiles"].append({"profile": label, "configured_one_way_delay_ms_per_loopback_leg": 10,
                    "configured_random_loss_percent": 1 if loss == "1%" else 0,
                    "kernel_packets": packets, "kernel_drops": drops,
                    "median_of_rounds": cmp["median_of_rounds"],
                    "verified_transactions_per_protocol": 128,
                    "quic_fresh_registration_after_restart": True,
                    "report": evidence.name, "qdisc_stats": stats.name})
                report["passed"].append(label + " actual netem and verified traffic")
        assert len(report["passed"]) == 2
    finally:
        (results / "quic-netem-summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
