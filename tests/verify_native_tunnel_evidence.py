"""Require the actual seven core E2E results and the pinned native engine."""
import json
from pathlib import Path
import sys

root=Path(sys.argv[1])
target=sys.argv[2]
report=json.loads((root/"report.json").read_text(encoding="utf-8"))
engine=json.loads((root/"engine.json").read_text(encoding="utf-8"))
lock=json.loads(Path(__file__).with_name("rathole-assets.lock.json").read_text(encoding="utf-8"))
pin=lock["targets"][target]
assert report["scope"]=="single-host real encrypted tunnel"
assert report["public_e2e"].startswith("BLOCKED")
assert report["passed"]==[
    "Rust config generation",
    "wrong token cannot forward",
    "HTTP body through encrypted reverse tunnel",
    "repeated HTTP requests",
    "agent reconnects after relay restart",
    "two isolated mappings with different local services",
    "32 concurrent/interleaved HTTP requests across two mappings",
]
assert engine["version"]==lock["version"] and engine["target"]==target
assert engine["pinned_archive_and_binary_verified"] is True
assert engine["archive_sha256"]==pin["archive_sha256"]
assert engine["binary_sha256"]==pin["binary_sha256"]
print("Verified seven actual native tunnel assertions and locked engine digests")
