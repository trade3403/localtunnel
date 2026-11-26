"""Actual foreground exec/lock/termination test using the already verified engine."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

def exercise(d, binary, cli, body, local_port, private, public, results, port, wait_for, get, terminate):
    d=d.resolve()
    binary=binary.resolve()
    token=secrets.token_hex(32)
    source=binary.read_bytes()
    digest=hashlib.sha256(source).hexdigest()
    # Separate native target dir; the original CLI and tests remain unchanged.
    build_dir=d/"agent-build"
    project=Path(__file__).resolve().parents[1]
    env=dict(os.environ,LOCALTUNNEL_AGENT_ENGINE_SHA256=digest,CARGO_TARGET_DIR=str(build_dir))
    subprocess.run(["cargo","build","--release","--locked"],cwd=project,env=env,check=True,timeout=120)
    agent_cli=build_dir/"release"/"localtunnel"
    root=d/"agent-store"
    def command(*args,data=b"",success=True,exe=agent_cli):
        p=subprocess.run([str(exe),*map(str,args)],input=data,capture_output=True,timeout=10)
        assert (p.returncode==0)==success, "unexpected agent CLI result"
        assert token.encode() not in p.stdout+p.stderr
        return p
    command("agent-store-init",root)
    a,b=port(),port()
    while b in (a,local_port) or a==local_port:
        a,b=port(),port()
    url=f"http://127.0.0.1:{b}/"
    command("agent-config-create",root,f"127.0.0.1:{a}","web",f"127.0.0.1:{local_port}",
            data=(token+"\n"+public+"\n").encode())
    # The normal unpinned CLI must fail closed.
    command("agent-engine-install",root,binary,success=False,exe=cli)
    altered=d/"altered-engine"
    altered.write_bytes(source[:-1]+bytes([source[-1]^1]))
    altered.chmod(0o700)
    command("agent-engine-install",root,altered,success=False)
    installed=root/"rathole"
    assert not installed.exists()
    command("agent-engine-install",root,binary)
    assert installed.read_bytes()==source and installed.stat().st_mode&0o777==0o700
    command("agent-engine-install",root,binary,success=False)
    report={"real_unix_engine_install_build_pin_and_tamper_denial":True}
    relay_config=d/"agent-relay.toml"
    subprocess.run([str(cli),"server-config",str(relay_config),f"127.0.0.1:{a}","web",str(b)],
                   env=dict(os.environ,LOCALTUNNEL_TOKEN=token,LOCALTUNNEL_SERVER_PRIVATE_KEY=private),
                   check=True,capture_output=True,timeout=10)
    relay=subprocess.Popen([str(binary),str(relay_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    active=None
    def start():
        p=subprocess.Popen([str(agent_cli),"agent-run",str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            wait_for(url,body,[relay,p])
            # A real process identity check, not an inferred wrapper PID.
            line=subprocess.check_output(["/bin/ps","-p",str(p.pid),"-o","command="],text=True,timeout=5).strip()
            assert line.startswith(str(installed)+" "), "foreground PID is not the engine"
            return p
        except BaseException:
            terminate(p)
            raise
    def unavailable():
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if get(url)!=body:
                return
            time.sleep(.2)
        raise AssertionError("stopped engine still forwarded payload")
    try:
        active=start()
        command("agent-run",root,success=False)
        assert get(url)==body and active.poll() is None
        report["real_unix_foreground_exec_and_duplicate_lock"]=True
        active.terminate()
        assert active.wait(timeout=10) in (0,-signal.SIGTERM)
        unavailable()
        active=start()
        active.kill()
        assert active.wait(timeout=10)==-signal.SIGKILL
        unavailable()
        report["real_unix_term_kill_and_kernel_lock_release"]=True
        installed.write_bytes(altered.read_bytes())
        command("agent-run",root,success=False)
        installed.write_bytes(source)
        config=root/"client.toml"
        config.chmod(0o644)
        command("agent-run",root,success=False)
        config.chmod(0o600)
        active=start()
        assert get(url)==body
        active.terminate()
        assert active.wait(timeout=10) in (0,-signal.SIGTERM)
        unavailable()
        assert config.is_file() and installed.is_file()
        report["real_unix_tamper_permission_denial_and_restart"]=True
        assert len(report)==4 and all(v is True for v in report.values())
        report["engine_sha256"]=digest
        report["agent_cli_sha256"]=hashlib.sha256(agent_cli.read_bytes()).hexdigest()
        if os.environ.get("LOCALTUNNEL_NATIVE_AGENT_SERVICE_E2E")=="1":
            from unix_agent_service_e2e import exercise as service_exercise
            service_exercise(root,agent_cli,url,body,relay,token,results,get)
        # Ship only the verified CLI in the existing CI artifact, never config.
        dist=project/"native-dist"
        dist.mkdir(exist_ok=True)
        packaged=dist/"localtunnel-agent"
        with packaged.open("xb") as out:
            out.write(agent_cli.read_bytes())
        packaged.chmod(0o700)
        assert hashlib.sha256(packaged.read_bytes()).hexdigest()==report["agent_cli_sha256"]
    finally:
        if active is not None:
            terminate(active)
        terminate(relay)
        (results/"unix-process.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
