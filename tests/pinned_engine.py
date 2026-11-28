"""Pinned upstream Rathole release assets for disposable real E2E only.

Digests fix the previously observed bytes; they are not publisher signatures.
Never execute or write an engine until archive and extracted bytes both match.
"""
import hashlib
import io
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
import platform
import stat
import urllib.request
import zipfile

LOCK = Path(__file__).with_name("rathole-assets.lock.json")
VERSION = "v0.5.0"
TARGETS = {
    ("Windows","amd64"):"x86_64-pc-windows-msvc",
    ("Windows","x86_64"):"x86_64-pc-windows-msvc",
    ("Linux","x86_64"):"x86_64-unknown-linux-gnu",
    ("Linux","aarch64"):"aarch64-unknown-linux-musl",
    ("Darwin","x86_64"):"x86_64-apple-darwin",
    ("Darwin","arm64"):"aarch64-apple-darwin",
}

def native_target():
    target=TARGETS.get((platform.system(),platform.machine().lower()))
    if target is None:
        raise RuntimeError("no pinned native Rathole release for this platform")
    return target

def checked_digest(data, expected, label):
    digest=hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise RuntimeError("unexpected pinned engine "+label+" SHA-256")
    return digest

def verified_bytes(archive,target,pin):
    if len(archive)!=pin["archive_bytes"] or len(archive)>20*1024*1024:
        raise RuntimeError("unexpected pinned engine archive size")
    archive_digest=checked_digest(archive,pin["archive_sha256"],"archive")
    name="rathole.exe" if target.endswith("windows-msvc") else "rathole"
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        members=[m for m in zipped.infolist() if PurePosixPath(m.filename).name==name]
        if len(members)!=1:
            raise RuntimeError("expected exactly one engine archive member")
        member=members[0]
        if member.is_dir() or stat.S_ISLNK(member.external_attr>>16) or not 0<member.file_size<=64*1024*1024:
            raise RuntimeError("invalid engine member")
        with zipped.open(member) as stream:
            binary=stream.read(64*1024*1024+1)
        if len(binary)!=member.file_size or len(binary)!=pin.get("binary_bytes",member.file_size):
            raise RuntimeError("unexpected pinned engine binary size")
    binary_digest=checked_digest(binary,pin["binary_sha256"],"binary")
    if "linux" in target:
        machine=183 if target.startswith("aarch64") else 62
        if binary[:6]!=b"\x7fELF\x02\x01" or int.from_bytes(binary[18:20],"little")!=machine:
            raise RuntimeError("wrong native ELF engine architecture")
    elif target.endswith("apple-darwin"):
        if binary[:4]!=b"\xcf\xfa\xed\xfe" or int.from_bytes(binary[4:8],"little")!=0x01000007:
            raise RuntimeError("wrong native Mach-O engine architecture")
    return name,binary,archive_digest,binary_digest

def acquire(directory, archive_path=None, *, cache_dir=None):
    lock=json.loads(LOCK.read_text(encoding="utf-8"))
    if lock["version"]!=VERSION:
        raise RuntimeError("unexpected engine lock version")
    target=native_target()
    if target in lock.get("source_targets",{}):
        if archive_path is not None:
            raise ValueError("offline archive is not supported for source-built target")
        from native_source_engine import build
        return build(directory,VERSION,lock["source_targets"][target])
    pin=lock["targets"][target]
    url=f"https://github.com/rathole-org/rathole/releases/download/{VERSION}/rathole-{target}.zip"
    # Job-local cache only; never trust cached content or use a different pin.
    # An explicit offline archive always takes precedence.
    cache=None
    if archive_path is None and cache_dir is not None:
        cache_dir=Path(cache_dir)
        cache_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        cache=cache_dir/f"{VERSION}-{target}-{pin['archive_sha256']}.zip"
    source=Path(archive_path) if archive_path is not None else cache
    reused=False
    if source is not None:
        try:
            with source.open("rb") as response:
                archive=response.read(20*1024*1024+1)
            reused=True
        except FileNotFoundError:
            if archive_path is not None:
                raise
    if not reused:
        with urllib.request.urlopen(url,timeout=90) as response:
            archive=response.read(20*1024*1024+1)
    # Verify both digests, sizes and architecture on every use, including hits.
    # A damaged cache fails closed rather than silently accepting other bytes.
    name,binary,archive_digest,binary_digest=verified_bytes(archive,target,pin)
    if cache is not None and not reused:
        pending=None
        try:
            with tempfile.NamedTemporaryFile(dir=cache_dir,prefix=".archive-",delete=False) as stream:
                pending=Path(stream.name)
                stream.write(archive)
            os.replace(pending,cache)
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)
    path=directory/name
    with path.open("xb") as stream:
        stream.write(binary)
    path.chmod(0o700)
    return path,{"version":VERSION,"target":target,"source":url,
                 "archive_sha256":archive_digest,"binary_sha256":binary_digest,
                 "archive_bytes":len(archive),"binary_bytes":len(binary),
                 "pinned_archive_and_binary_verified":True}
