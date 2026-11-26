"""Collect candidate archive digests; never execute or extract unpinned upstream bytes."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import urllib.request
import zipfile

target=sys.argv[1]
output=Path(sys.argv[2])
sizes={"x86_64-unknown-linux-gnu":1275184,
       "aarch64-unknown-linux-musl":1025661,
       "x86_64-apple-darwin":1724482}
report={"version":"v0.5.0","target":target,"engine_executed":False}
if target=="aarch64-apple-darwin":
    report["status"]="blocked_no_native_upstream_release_asset"
else:
    assert target in sizes
    url="https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-"+target+".zip"
    with urllib.request.urlopen(url,timeout=90) as response:
        archive=response.read(20*1024*1024+1)
    assert len(archive)==sizes[target], "upstream candidate size differs from observed release metadata"
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        members=[m for m in zipped.infolist() if PurePosixPath(m.filename).name=="rathole"]
        assert len(members)==1
        member=members[0]
        assert not member.is_dir() and 0<member.file_size<=64*1024*1024
        assert not stat.S_ISLNK(member.external_attr>>16)
        with zipped.open(member) as stream:
            binary=stream.read(64*1024*1024+1)
        assert len(binary)==member.file_size
    if target.endswith("linux-gnu") or target.endswith("linux-musl"):
        assert binary[:6]==b"\x7fELF\x02\x01"
        assert int.from_bytes(binary[18:20],"little")== (183 if target.startswith("aarch64") else 62)
    else:
        assert binary[:4]==b"\xcf\xfa\xed\xfe"
        assert int.from_bytes(binary[4:8],"little")==0x01000007
    report.update(status="candidate_digest_observed_not_trusted",source=url,
                  archive_bytes=len(archive),archive_sha256=hashlib.sha256(archive).hexdigest(),
                  binary_bytes=len(binary),binary_sha256=hashlib.sha256(binary).hexdigest())
output.parent.mkdir(parents=True,exist_ok=True)
output.write_text(json.dumps(report,indent=2),encoding="utf-8")
print(json.dumps(report))
