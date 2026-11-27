"""Independent Linux relay control processes; no shared database or fake server."""
import json
import os
import secrets
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

exe=Path(sys.argv[1]).resolve()
relay=exe.with_name("localtunnel-relay")
evidence=Path(sys.argv[2])
report={}
children=[]
secrets_used=[]

def stop(p):
    if p.poll() is None:
        p.terminate()
    try: return p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate(timeout=5)

def wait_for(predicate,seconds=25):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.25)
    raise AssertionError("relay condition did not converge")

try:
    with tempfile.TemporaryDirectory() as tmp:
        base=Path(tmp)
        root=base/"center"
        root.mkdir(mode=0o700)
        def command(action,*args,data=None):
            p=subprocess.run([str(exe),action,str(root),*map(str,args)],input=None if data is None else json.dumps(data),text=True,capture_output=True,timeout=20)
            assert p.returncode==0,"trusted command failed"
            return p.stdout.strip()
        command("--init-admin",data={"username":"owner","password":secrets.token_hex(24)})
        def server(port=0):
            p=subprocess.Popen([str(exe),str(root),str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(p)
            with selectors.DefaultSelector() as sel:
                sel.register(p.stdout,selectors.EVENT_READ)
                assert sel.select(20),"center startup timeout"
            line=p.stdout.readline().strip()
            assert line.startswith("LISTENING 127.0.0.1:")
            return p,int(line.rsplit(":",1)[1])
        center,port=server()
        def health(token):
            req=urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/relay/heartbeat",headers={"Authorization":"Bearer "+token})
            with urllib.request.urlopen(req,timeout=4) as response:
                assert response.status==200
                return json.load(response)
        def start(directory,node,generation,capacity):
            p=subprocess.Popen([str(relay),str(directory),str(port),node,str(generation),str(capacity)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(p)
            return p
        entries=[]
        for i in range(3):
            node=command("--add-node",f"relay {i}")
            token=command("--relay-issue",node)
            secrets_used.append(token)
            directory=base/f"node-{i}"
            directory.mkdir(mode=0o700)
            file=directory/"relay.token"
            file.write_text(token+"\n")
            file.chmod(0o600)
            p=start(directory,node,1,10+i)
            entries.append((directory,node,token,p))
        def all_fresh():
            return all(p.poll() is None and (h:=health(token))["fresh"] and h["node_id"]==node and h["capacity"]==10+i for i,(_,node,token,p) in enumerate(entries))
        wait_for(all_fresh)
        assert all(sorted(x.name for x in d.iterdir())==["relay.token"] for d,_,_,_ in entries)
        report["real_three_independent_relay_control_processes"]=True
        # Center outage is not a new authorization. Existing control clients
        # reconnect only with their original identity once the center returns.
        old=[health(t)["received_at"] for _,_,t,_ in entries]
        stop(center)
        time.sleep(5)
        assert all(p.poll() is None for _,_,_,p in entries)
        center,rebound=server(port)
        assert rebound==port
        wait_for(lambda:all_fresh() and all(health(t)["received_at"]>stamp for (_,_,t,_),stamp in zip(entries,old)))
        report["real_relay_control_center_restart_recovery"]=True
        directory,node,token,p=entries[0]
        stop(p)
        wait_for(lambda:not health(token)["fresh"],25)
        assert all(health(t)["fresh"] for _,_,t,_ in entries[1:])
        new=start(directory,node,1,10)
        entries[0]=(directory,node,token,new)
        wait_for(all_fresh)
        report["real_relay_process_loss_and_health_recovery"]=True
        directory,node,token,p=entries[1]
        rotated=command("--relay-rotate",node,1)
        secrets_used.append(rotated)
        wait_for(lambda:p.poll() is not None,15)
        assert p.returncode!=0
        assert health(rotated)["fresh"] is False
        (directory/"relay.token").write_text(rotated+"\n")
        wrong=start(directory,entries[0][1],2,11)
        wait_for(lambda:wrong.poll() is not None,10)
        assert wrong.returncode!=0
        assert health(rotated)["received_at"] is None
        (directory/"relay.token").chmod(0o644)
        invalid=start(directory,node,2,11)
        wait_for(lambda:invalid.poll() is not None,10)
        assert invalid.returncode!=0
        (directory/"relay.token").chmod(0o600)
        fresh=start(directory,node,2,11)
        wait_for(lambda:health(rotated)["fresh"])
        command("--relay-revoke",node,2)
        wait_for(lambda:fresh.poll() is not None,15)
        assert fresh.returncode!=0
        report["real_relay_process_credential_rotation_private_file_and_revocation"]=True
finally:
    for p in reversed(children):
        out,err=stop(p)
        assert not any(token in ((out or "")+(err or "")) for token in secrets_used),"relay credential logged"
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==4 and all(report.values())
