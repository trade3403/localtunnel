#!/usr/bin/env python3
"""Install an unsigned LocalTunnel preview into a NEW owner-only directory.

Obtain this installer and expected archive SHA256 via a trusted channel.
No sudo, service activation, credentials, shell commands or archive extract().
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import tarfile

LIMIT=64*1024*1024
NAMES={"localtunnel-agent":0o700,"rathole":0o700,"manifest.json":0o600,
       "README.txt":0o600,"rathole-LICENSE.txt":0o600,"rathole-NOTICE.txt":0o600}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def target():
    return {"Linux":"linux","Darwin":"macos"}[platform.system()]+"-"+{
        "x86_64":"x64","aarch64":"arm64","arm64":"arm64"}[platform.machine().lower()]

def trusted_parent(path):
    if not path.is_absolute() or ".." in path.parts or path.resolve(strict=True)!=path:
        raise ValueError("use a canonical absolute installation parent")
    uid=os.geteuid()
    for p in reversed([path,*path.parents]):
        m=p.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0,uid):
            raise ValueError("untrusted installation ancestor")
        if m.st_mode&0o022 and not (m.st_uid==0 and m.st_mode&stat.S_ISVTX):
            raise ValueError("writable installation ancestor")
    m=path.lstat()
    if m.st_uid!=uid or m.st_mode&0o022:
        raise ValueError("installation parent must be owned and not group/world writable")

def load(archive,expected):
    if not re.fullmatch("[0-9a-f]{64}",expected):
        raise ValueError("expected archive SHA256 is required")
    with archive.open("rb") as f:
        raw=f.read(LIMIT+1)
    if not 0<len(raw)<=LIMIT or sha(raw)!=expected:
        raise ValueError("archive SHA256 or size mismatch")
    payload={}
    total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tar:
        for member in tar:
            if member.name not in NAMES or member.name in payload or not member.isfile():
                raise ValueError("unexpected, duplicate, linked or special archive member")
            ceiling=LIMIT if NAMES[member.name]==0o700 else 65536
            total+=member.size
            if not 0<member.size<=ceiling or total>LIMIT:
                raise ValueError("archive payload size exceeded")
            stream=tar.extractfile(member)
            if stream is None:
                raise ValueError("missing archive member")
            with stream:
                data=stream.read(member.size+1)
            if len(data)!=member.size:
                raise ValueError("truncated archive member")
            payload[member.name]=data
    if set(payload)!=set(NAMES):
        raise ValueError("incomplete package")
    manifest=json.loads(payload["manifest.json"])
    if manifest.get("schema")!=1 or manifest.get("target")!=target():
        raise ValueError("package platform mismatch")
    files=manifest.get("files")
    if not isinstance(files,dict) or set(files)!=set(NAMES)-{"manifest.json"}:
        raise ValueError("unexpected manifest")
    for name,digest in files.items():
        if sha(payload[name])!=digest:
            raise ValueError("package member digest mismatch")
    return payload

def install(archive,expected,dest):
    payload=load(archive,expected)
    if not dest.is_absolute() or dest.name in ("",".","..") or ".." in dest.parts:
        raise ValueError("use a new absolute installation directory")
    trusted_parent(dest.parent)
    os.mkdir(dest,0o700)
    created=[]
    try:
        dest.chmod(0o700)
        for name,data in payload.items():
            path=dest/name
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,NAMES[name])
            created.append(path)
            with os.fdopen(fd,"wb") as f:
                os.fchmod(f.fileno(),NAMES[name])
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            m=path.lstat()
            if m.st_nlink!=1 or m.st_uid!=os.geteuid() or stat.S_IMODE(m.st_mode)!=NAMES[name]:
                raise ValueError("installed member metadata mismatch")
    except BaseException:
        for path in reversed(created):
            path.unlink()
        dest.rmdir()
        raise

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive",type=Path)
    parser.add_argument("sha256")
    parser.add_argument("destination",type=Path)
    a=parser.parse_args()
    try:
        install(a.archive,a.sha256,a.destination)
    except (OSError,ValueError,KeyError,TypeError,tarfile.TarError) as e:
        parser.exit(1,"install refused: "+str(e)+"\n")
    print("Private LocalTunnel preview installed; no service enabled.")
