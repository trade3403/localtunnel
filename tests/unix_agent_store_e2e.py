"""Native owner-only storage E2E. Uses actual CLI and real filesystem operations."""
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile

exe=Path(sys.argv[1]).resolve(strict=True)
out=Path(sys.argv[2])
token=secrets.token_hex(32)
key="A"*43+"="
credentials=(token+"\n"+key+"\n").encode()
# An intentionally wrong legacy environment token must never be imported.
env=dict(os.environ,LOCALTUNNEL_TOKEN="unexpected-environment-token",
         LOCALTUNNEL_SERVER_PUBLIC_KEY="unexpected-environment-key")
report={}

def run(*args, data=b"", ok=True):
    p=subprocess.run([str(exe),*map(str,args)],input=data,env=env,
                     capture_output=True,timeout=10)
    assert (p.returncode==0)==ok, "unexpected agent store command result"
    assert token.encode() not in p.stdout+p.stderr
    assert b"unexpected-environment-token" not in p.stdout+p.stderr
    return p.stdout

try:
    with tempfile.TemporaryDirectory(prefix="lt-store-") as tmp:
        parent=Path(tmp).resolve()
        parent.chmod(0o700)
        root=parent/"store"
        previous=os.umask(0o022)
        try:
            run("agent-store-init",root)
            assert stat.S_IMODE(root.stat().st_mode)==0o700
            assert root.stat().st_uid==os.geteuid()
            run("agent-store-init",root,ok=False)
            args=("agent-config-create",root,"127.0.0.1:2333","web","127.0.0.1:8080")
            file=root/"client.toml"
            run(*args,ok=False)
            run(*args,data=b"x"*257,ok=False)
            run(*args,data=credentials+b"extra\n",ok=False)
            run("agent-config-create",root,"127.0.0.1:2333","web","0.0.0.0:8080",data=credentials,ok=False)
            assert not file.exists()
            run(*args,data=credentials)
            original=file.read_bytes()
            assert token.encode() in original and b"unexpected-environment-token" not in original
            assert stat.S_IMODE(file.stat().st_mode)==0o600 and file.stat().st_uid==os.geteuid()
            assert run("agent-config-check",root)==b"private agent configuration verified\n"
            run(*args,data=credentials,ok=False)
            assert file.read_bytes()==original
            report["real_unix_private_store_stdin_and_no_overwrite"]=True
            root.chmod(0o755)
            run("agent-config-check",root,ok=False)
            root.chmod(0o700)
            parent.chmod(0o777)
            run("agent-config-check",root,ok=False)
            run("agent-store-init",parent/"unsafe",ok=False)
            parent.chmod(0o700)
            file.chmod(0o644)
            run("agent-config-check",root,ok=False)
            file.chmod(0o600)
            report["real_unix_unsafe_permissions_and_ancestors_denied"]=True
            alias=parent/"alias"
            alias.symlink_to(root,target_is_directory=True)
            run("agent-config-check",alias,ok=False)
            run("agent-store-init",alias/"nested",ok=False)
            assert not (root/"nested").exists()
            link=parent/"hardlink"
            os.link(file,link)
            run("agent-config-check",root,ok=False)
            link.unlink()
            moved=parent/"original"
            file.rename(moved)
            file.symlink_to(moved)
            run("agent-config-check",root,ok=False)
            run(*args,data=credentials,ok=False)
            assert moved.read_bytes()==original
            file.unlink()
            os.mkfifo(file,0o600)
            run("agent-config-check",root,ok=False)
            run(*args,data=credentials,ok=False)
            assert stat.S_ISFIFO(file.stat().st_mode)
            file.unlink()
            file.mkdir(mode=0o700)
            run("agent-config-check",root,ok=False)
            file.rmdir()
            moved.rename(file)
            report["real_unix_symlink_hardlink_fifo_directory_denied"]=True
            file.write_bytes(b"x"*4097)
            run("agent-config-check",root,ok=False)
            file.write_bytes(original+b"\n[unexpected]\n")
            run("agent-config-check",root,ok=False)
            file.write_bytes(original.replace(b"127.0.0.1:8080",b"0.0.0.0:8080"))
            run("agent-config-check",root,ok=False)
            file.write_bytes(original)
            run("agent-config-check",root)
            assert file.read_bytes()==original
            report["real_unix_corruption_and_invalid_target_denied_recovery"]=True
        finally:
            os.umask(previous)
finally:
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==4 and all(v is True for v in report.values())
