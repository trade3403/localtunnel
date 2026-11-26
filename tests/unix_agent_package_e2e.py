"""Package the exact native CLI and verified engine, install from that package."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

def sha(data):
    return hashlib.sha256(data).hexdigest()

def exercise(project,d,cli,engine,results):
    installer=project/"packaging"/"unix"/"install.py"
    sys.path.insert(0,str(installer.parent))
    try:
        from install import NAMES,target
    finally:
        sys.path.pop(0)
    platform_target=target()
    evidence=json.loads((results/"engine.json").read_text(encoding="utf-8"))
    engine_bytes=engine.read_bytes()
    assert sha(engine_bytes)==evidence["binary_sha256"]
    cli_bytes=cli.read_bytes()
    license_bytes=(project/"apps/desktop/src-tauri/third-party/rathole-LICENSE.txt").read_bytes()
    notice=("Rathole v0.5.0; separate Apache-2.0 executable.\n"
            "Authors: Yujia Qiao and Rathole contributors.\n"
            "Upstream: https://github.com/rathole-org/rathole/tree/v0.5.0\n"
            "See rathole-LICENSE.txt. Engine provenance:\n"+
            json.dumps(evidence,indent=2)+"\n").encode()
    instructions=(project/"packaging/unix/README.txt").read_bytes()
    files={"localtunnel-agent":cli_bytes,"rathole":engine_bytes,
           "README.txt":instructions,"rathole-LICENSE.txt":license_bytes,
           "rathole-NOTICE.txt":notice}
    files["manifest.json"]=json.dumps({"schema":1,"target":platform_target,
        "preview":True,"files":{name:sha(data) for name,data in files.items()}},
        indent=2).encode()
    dist=project/"native-dist"
    dist.mkdir(exist_ok=True)
    archive=dist/("localtunnel-agent-"+platform_target+".tar.gz")
    def create(path,items):
        with tarfile.open(path,"x:gz") as tar:
            for name,data in items:
                member=tarfile.TarInfo(name)
                member.size=len(data)
                member.mode=NAMES.get(name,0o600)
                member.mtime=0
                tar.addfile(member,io.BytesIO(data))
    create(archive,files.items())
    expected=sha(archive.read_bytes())
    def install(path,digest,dest,ok=True):
        p=subprocess.run([sys.executable,str(installer),str(path),digest,str(dest)],
                         capture_output=True,text=True,timeout=30)
        assert (p.returncode==0)==ok, "native package installation outcome differs: "+p.stderr[-300:]
    dest=d/"installed-agent"
    report={}
    install(archive,"0"*64,dest,False)
    assert not dest.exists()
    malicious=d/"invalid-package.tar.gz"
    create(malicious,[*files.items(),("../escape",b"not permitted")])
    install(malicious,sha(malicious.read_bytes()),dest,False)
    assert not dest.exists() and not (d/"escape").exists()
    report["real_package_bad_digest_and_path_traversal_denied"]=True
    wrong=dict(files)
    wrong["rathole"]=engine_bytes[:-1]+bytes([engine_bytes[-1]^1])
    invalid=d/"wrong-member.tar.gz"
    create(invalid,wrong.items())
    install(invalid,sha(invalid.read_bytes()),dest,False)
    assert not dest.exists()
    report["real_package_bad_member_digest_denied"]=True
    install(archive,expected,dest)
    assert dest.stat().st_mode&0o777==0o700
    assert {p.name for p in dest.iterdir()}==set(NAMES)
    for name,data in files.items():
        p=dest/name
        assert p.read_bytes()==data and p.stat().st_nlink==1
        assert p.stat().st_mode&0o777==NAMES[name]
    install(archive,expected,dest,False)
    assert (dest/"localtunnel-agent").read_bytes()==cli_bytes
    report["real_package_private_install_and_no_overwrite"]=True
    report["archive_sha256"]=expected
    report["archive_bytes"]=archive.stat().st_size
    report["target"]=platform_target
    report["agent_cli_sha256"]=sha(cli_bytes)
    report["engine_sha256"]=sha(engine_bytes)
    (results/"unix-package.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    with (dist/"install.py").open("xb") as out:
        out.write(installer.read_bytes())
    return dest/"localtunnel-agent",dest/"rathole"
