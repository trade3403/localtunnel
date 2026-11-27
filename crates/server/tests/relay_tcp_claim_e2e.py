"""Real one-shot TCP claim, exact binding, race and restore."""
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
exe=str(Path(sys.argv[1]).resolve())
evidence=Path(sys.argv[2])
report={}
password=secrets.token_hex(24)
def cmd(root,*args,data=None):
    p=subprocess.run([exe,args[0],str(root),*map(str,args[1:])],input=None if data is None else json.dumps(data),text=True,capture_output=True,timeout=30)
    assert p.returncode==0,"operator command failed"
    return p.stdout.strip()
def stop(p):
    p.terminate()
    try:p.communicate(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=5)
def launch(root):
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout,selectors.EVENT_READ)
            assert sel.select(20)
        line=p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:")
        return p,"http://"+line.split()[1]
    except BaseException:
        stop(p);raise
def call(base,path,status,token=None,method="GET",data=None):
    headers={}
    if token:headers["Authorization"]="Bearer "+token
    if data is not None:headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            code,raw=r.status,r.read()
            assert "no-store" in r.headers.get("Cache-Control","")
    except urllib.error.HTTPError as e:code,raw=e.code,e.read()
    assert code in (status if isinstance(status,tuple) else (status,)),f"{method} {path}: unexpected {code}"
    return (code,json.loads(raw) if code in (200,201) else None)
def login(base,name):
    return call(base,"auth/login",200,method="POST",data={"username":name,"password":password})[1]["access_token"]
def device(base,token):
    code=call(base,"devices/pairing-code",200,token,"POST")[1]["pairing_code"]
    return call(base,"devices/enroll",201,method="POST",data={"pairing_code":code,"name":"fixture"})[1]["id"]
try:
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)/"live";root.mkdir(mode=0o700)
        cmd(root,"--init-admin",data={"username":"owner","password":password})
        cmd(root,"--commercial-create-account",data={"username":"other","password":password,"plan_id":"legacy-v1","expires_at":None})
        nodes=[cmd(root,"--add-node","TCP relay "+str(i)) for i in range(2)]
        tokens=[cmd(root,"--relay-issue",n) for n in nodes]
        for n in nodes:cmd(root,"--set-node-policy",n,1,8,"east","active")
        p,base=launch(root)
        try:
            owner=login(base,"owner");other=login(base,"other");did=device(base,owner)
            def beat(i):
                call(base,"relay/heartbeat",204,tokens[i],"POST",{"protocol_version":1,"generation":1,"capacity":8})
            def grant(i,port):
                beat(i)
                a=call(base,"allocations",201,owner,"POST",dict(request_key=secrets.token_hex(16),device_id=did,protocol="tcp",local_port=8080,bind_port=port,node_id=nodes[i]))[1]
                g=call(base,"allocations/"+a["id"]+"/grant",201,owner,"POST",{"expected_generation":1,"expected_mapping_revision":1})[1]
                return g
            def intent(g,port,status=201,token=owner):
                return call(base,"allocations/"+g["allocation_id"]+"/tcp-intent",status,token,"POST",{"grant_id":g["id"],"expected_generation":g["generation"],"relay_port":port})[1]
            def payload(g,port):
                return dict({k:g[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")},protocol_version=1,grant_id=g["id"],relay_port=port,nonce=secrets.token_hex(16))
            def claim(q,status=200,token=tokens[0]):
                return call(base,"relay/tcp-claim",status,token,"POST",q)
            g=grant(0,20000);q=payload(g,31000)
            claim(q,401)
            intent(g,31000,409,other)
            intent(g,31000,401,tokens[0])
            record=intent(g,31000)
            assert record["bind_port"]==20000 and record["claimed_at"] is None
            intent(g,31000,409)
            claim(q,401,tokens[1]);claim(q,401,owner)
            claim(dict(q,relay_port=31001),401);claim(dict(q,mapping_revision=2),401)
            claim(dict(q,generation=3),401);claim(dict(q,protocol_version=2),400)
            with ThreadPoolExecutor(max_workers=2) as workers:
                results=list(workers.map(lambda _:claim(q,(200,401)),range(2)))
            assert sorted(code for code,_ in results)==[200,401]
            answer=next(row for code,row in results if code==200)
            assert answer["scope"]=="tcp_loopback_start_claim" and answer["nonce"]==q["nonce"]
            permit=answer["permit"]
            assert all(permit[k]==q[k] for k in ("grant_id","allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation","relay_port"))
            assert permit["bind_port"]==20000 and permit["expires_at"]==g["expires_at"] and permit["claimed_at"]<=permit["server_time"]
            claim(q,401)
            report["real_tcp_explicit_intent_exact_claim_and_one_shot_race"]=True
            second=grant(0,20001)
            intent(second,31000,409)
            intent(second,31001)
            q2=payload(second,31001)
            third=grant(1,20000)
            intent(third,31000)
            cmd(root,"--set-node-policy",nodes[0],2,8,"east","maintenance")
            claim(q2,401)
            cmd(root,"--set-node-policy",nodes[0],3,8,"east","active")
            beat(0);claim(q2,401)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_tcp_intents").fetchone()==(3,)
                assert db.execute("SELECT count(*) FROM relay_tcp_intents WHERE claimed_at IS NOT NULL").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='tcp.claimed'").fetchone()==(1,)
            backup=Path(tmp)/"backup";restored=Path(tmp)/"restored"
            assert subprocess.run([exe,"--backup-db",str(root),str(backup)],capture_output=True,timeout=40).returncode==0
        finally:stop(p)
        assert subprocess.run([exe,"--restore-db",str(backup),str(restored)],capture_output=True,timeout=40).returncode==0
        p,base=launch(restored)
        try:
            claim(q,401);claim(payload(third,31000),401,tokens[1])
            with sqlite3.connect(restored/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_tcp_intents").fetchone()==(3,)
                assert db.execute("SELECT count(*) FROM relay_tcp_intents WHERE claimed_at IS NOT NULL").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM relay_grants WHERE revoked_at IS NOT NULL").fetchone()==(3,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_tcp_claim_port_policy_and_restore_isolation"]=True
        finally:stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==2 and all(report.values())
