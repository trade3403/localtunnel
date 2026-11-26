"""Real systemd user service or launchd user job, on disposable CI only."""
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import signal
import subprocess
import time

def exercise(root, cli, url, body, relay, token, results, get):
    service_id=secrets.token_hex(16)
    label="localtunnel-agent-"+service_id
    linux=platform.system()=="Linux"
    env=dict(os.environ)
    if linux:
        env.update(XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
                   DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")
    report={}
    def call(*args,ok=True,timeout=20):
        p=subprocess.run(list(map(str,args)),env=env,capture_output=True,text=True,timeout=timeout)
        assert token not in p.stdout+p.stderr
        if ok and p.returncode!=0:
            raise RuntimeError("native service command failed: "+str(args[0])+" "+str(args[1:3])+" "+p.stderr[-500:])
        return p
    call(cli,"agent-service-generate",root,service_id)
    definition=root/(label+(".service" if linux else ".plist"))
    original=definition.read_bytes()
    assert token.encode() not in original
    assert definition.stat().st_mode&0o777==0o600
    assert call(cli,"agent-service-generate",root,service_id,ok=False).returncode!=0
    assert call(cli,"agent-service-generate",root,"bad\nid",ok=False).returncode!=0
    assert definition.read_bytes()==original
    report["real_native_service_definition_and_no_overwrite"]=True
    installed=root/"rathole"
    def identity(pid):
        p=call("/bin/ps","-p",str(pid),"-o","command=",ok=False)
        return p.returncode==0 and p.stdout.strip().startswith(str(installed)+" ")
    if linux:
        manager="/usr/bin/systemctl"
        call(manager,"--user","show-environment")
        assert b"User=" not in original and b"Restart=on-failure" in original
        unit=label+".service"
        unitdir=Path.home()/".config/systemd/user"
        unitdir.mkdir(parents=True,exist_ok=True)
        unitpath=unitdir/unit
        with unitpath.open("xb") as f:
            f.write(original)
        unitpath.chmod(0o600)
        def ctl(*args,ok=True):
            return call(manager,"--user",*args,ok=ok)
        def pid():
            text=ctl("show",unit,"--property=MainPID","--value",ok=False).stdout.strip()
            return int(text) if text.isdigit() else 0
        def start():
            ctl("daemon-reload")
            ctl("enable",unit)
            assert ctl("is-enabled",unit).stdout.strip()=="enabled"
            ctl("start",unit)
        def stop():
            ctl("stop",unit)
            ctl("disable",unit)
            assert ctl("is-enabled",unit,ok=False).returncode!=0
        def cleanup():
            ctl("stop",unit,ok=False)
            ctl("disable",unit,ok=False)
            unitpath.unlink(missing_ok=True)
            ctl("daemon-reload")
        manager_kind="systemd-user"
    else:
        manager="/bin/launchctl"
        parsed=plistlib.loads(original)
        assert parsed["Label"]==label and parsed["ProgramArguments"]==[str(cli),"agent-run",str(root)]
        assert parsed["KeepAlive"]=={"SuccessfulExit":False}
        call("/usr/bin/plutil","-lint",definition)
        # Use the runner's existing GUI domain when present, otherwise user domain.
        gui=f"gui/{os.getuid()}"
        domain=gui if call(manager,"print",gui,ok=False).returncode==0 else f"user/{os.getuid()}"
        call(manager,"print",domain)
        target=f"{domain}/{label}"
        def pid():
            p=call(manager,"print",target,ok=False)
            m=re.search(r"(?m)^\s*pid = (\d+)\s*$",p.stdout)
            return int(m.group(1)) if p.returncode==0 and m else 0
        def start():
            call(manager,"bootstrap",domain,definition)
        def stop():
            call(manager,"bootout",target)
            assert call(manager,"print",target,ok=False).returncode!=0
        def cleanup():
            call(manager,"bootout",target,ok=False)
            assert call(manager,"print",target,ok=False).returncode!=0
        manager_kind="launchd-"+domain.split("/")[0]
    def online(previous=0):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            assert relay.poll() is None
            p=pid()
            if p>0 and p!=previous and identity(p) and get(url)==body:
                return p
            time.sleep(.4)
        raise AssertionError("native service did not forward real fixture")
    try:
        start()
        first=online()
        report["real_native_service_start_and_forward"]=True
        assert identity(first)
        os.kill(first,signal.SIGKILL)
        second=online(first)
        assert not identity(first) and identity(second)
        report["real_native_service_failure_restart_and_forward"]=True
        stop()
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if not identity(second) and not pid() and get(url)!=body:
                break
            time.sleep(.3)
        else:
            raise AssertionError("native service failed to stop")
        report["real_native_service_stop_and_disable_or_unload"]=True
    finally:
        cleanup()
        report["manager"]=manager_kind
        (results/"unix-service.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    assert len(report)==5 and all(v is True for k,v in report.items() if k!="manager")
