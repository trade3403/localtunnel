"""Real bounded grant ledger, generation, expiry and restore."""
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
        nodes=[cmd(root,"--add-node","grant relay "+str(i)) for i in range(2)]
        tokens=[cmd(root,"--relay-issue",n) for n in nodes]
        for n in nodes:cmd(root,"--set-node-policy",n,1,8,"east","active")
        p,base=launch(root)
        try:
            owner=login(base,"owner");other=login(base,"other");did=device(base,owner)
            def beat(i,token=None,generation=1):
                call(base,"relay/heartbeat",204,token or tokens[i],"POST",{"protocol_version":1,"generation":generation,"capacity":8})
            beat(0);beat(1)
            def reserve(port,protocol="tcp"):
                beat(0)
                return call(base,"allocations",201,owner,"POST",dict(request_key=secrets.token_hex(16),device_id=did,protocol=protocol,local_port=8080,bind_port=port,node_id=nodes[0]))[1]
            a=reserve(20000)
            b=reserve(20001,"udp")
            route="allocations/"+a["id"]
            issue_spec={"expected_generation":1,"expected_mapping_revision":1}
            def issue(status=201,token=owner,allocation=a,data=issue_spec):
                return call(base,"allocations/"+allocation["id"]+"/grant",status,token,"POST",data)
            def cancel(status=409,gen=2):
                call(base,route+"/cancel",status,owner,"POST",{"expected_generation":gen})
            issue(409,other)
            issue(401,tokens[0])
            issue(409,data=dict(issue_spec,expected_mapping_revision=2))
            issue(409,allocation=b,data=dict(issue_spec,expected_mapping_revision=2))
            cmd(root,"--set-node-policy",nodes[0],2,8,"east","draining")
            beat(0)
            issue(409)
            cmd(root,"--set-node-policy",nodes[0],3,8,"east","active")
            beat(0)
            with ThreadPoolExecutor(max_workers=2) as workers:
                result=list(workers.map(lambda _:issue((201,409)),range(2)))
            assert sorted(code for code,_ in result)==[201,409]
            grant=next(row for code,row in result if code==201)
            assert grant["allocation_id"]==a["id"] and grant["mapping_id"]==a["mapping_id"] and grant["node_id"]==nodes[0]
            assert grant["generation"]==2 and grant["node_generation"]==1 and grant["expires_at"]-grant["issued_at"]==15
            assert call(base,route,200,owner)[1]["generation"]==2
            assert call(base,route+"/grant",200,owner)[1]==grant
            call(base,route+"/grant",404,other)
            cancel(gen=1);cancel()
            fence_spec={"expected_generation":2,"grant_id":grant["id"]}
            def fence(status=201,token=owner,data=fence_spec):
                return call(base,route+"/fence",status,token,"POST",data)
            fence(409);fence(404,other);fence(401,tokens[0])
            call(base,route+"/fence",404,owner)
            fence(400,data=dict(fence_spec,expected_generation=3))
            payload={k:grant[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")}
            payload.update(protocol_version=1,nonce=secrets.token_hex(16))
            def fetch(status=200,token=tokens[0],data=payload):
                return call(base,"relay/grant",status,token,"POST",data)[1]
            response=fetch()
            assert grant["issued_at"]<=response["server_time"]<grant["expires_at"]
            assert {k:v for k,v in response.items() if k!="server_time"}=={"protocol_version":1,"nonce":payload["nonce"],"scope":"authorization_preview_only","grant":grant}
            fetch(401,tokens[1]);fetch(401,owner)
            fetch(401,data=dict(payload,mapping_revision=2))
            fetch(401,data=dict(payload,generation=3))
            fetch(400,data=dict(payload,protocol_version=2))
            fetch(422,data=dict(payload,extra=True))
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_grants").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='grant.preview_issued'").fetchone()==(1,)
            report["real_grant_exact_binding_atomic_generation_and_owner_isolation"]=True
            # Real time expiry with heartbeat kept current, no synthetic
            # timestamp edit or arbitrary fixed delay used to assert expiry.
            end=time.monotonic()+22
            while True:
                beat(0)
                status,_=call(base,"relay/grant",(200,401),tokens[0],"POST",payload)
                if status==401:break
                assert time.monotonic()<end,"grant did not expire"
                time.sleep(.25)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT unixepoch()>=expires_at FROM relay_grants WHERE id=?",(grant["id"],)).fetchone()==(1,)
            cancel()
            issue(409)
            while time.time()<grant["expires_at"]+2:time.sleep(.1)
            with ThreadPoolExecutor(max_workers=2) as workers:
                results=list(workers.map(lambda _:fence((200,201)),range(2)))
            assert sorted(code for code,_ in results)==[200,201]
            row=results[0][1]
            assert results[1][1]==row and row["resources_released"] is False and row["executable"] is False
            assert row["fence"]["old_generation"]==2 and row["fence"]["new_generation"]==3
            assert call(base,route,200,owner)[1]["generation"]==3
            assert call(base,route+"/fence",200,owner)[1]==row
            fence(409,data=dict(fence_spec,grant_id=secrets.token_hex(16)))
            call(base,route+"/fence",404,other)
            cancel(gen=3)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='allocation.expiry_fenced'").fetchone()==(1,)
                for sql in ("DELETE FROM relay_allocation_fences","UPDATE relay_allocation_fences SET fenced_at=fenced_at+1","UPDATE relay_allocations SET generation=2 WHERE id IN (SELECT allocation_id FROM relay_allocation_fences)"):
                    try:db.execute(sql);raise AssertionError("mutable fence")
                    except sqlite3.IntegrityError:db.rollback()
            report["real_expired_allocation_fence_atomic_idempotent_and_retained"]=True
            beat(0)
            c=reserve(20002)
            current=issue(allocation=c)[1]
            current_payload={k:current[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")}
            current_payload.update(protocol_version=1,nonce=secrets.token_hex(16))
            fetch(data=current_payload)
            cmd(root,"--set-node-policy",nodes[0],4,8,"east","maintenance")
            fetch(401,data=current_payload)
            cmd(root,"--set-node-policy",nodes[0],5,8,"east","active")
            beat(0)
            fetch(401,data=current_payload)
            rotated=cmd(root,"--relay-rotate",nodes[0],1)
            beat(0,rotated,2)
            fetch(401,rotated,dict(current_payload,node_generation=2))
            fetch(401,data=current_payload)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_allocations WHERE state='reserved'").fetchone()==(3,)
                assert db.execute("SELECT count(*) FROM relay_grants").fetchone()==(2,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_grant_policy_generation_expiry_and_no_release"]=True
            backup=Path(tmp)/"backup";restored=Path(tmp)/"restored"
            assert subprocess.run([exe,"--backup-db",str(root),str(backup)],capture_output=True,timeout=40).returncode==0
        finally:stop(p)
        assert subprocess.run([exe,"--restore-db",str(backup),str(restored)],capture_output=True,timeout=40).returncode==0
        p,base=launch(restored)
        try:
            fresh=login(base,"owner")
            restored_grant=call(base,route+"/grant",200,fresh)[1]
            assert restored_grant["id"]==grant["id"] and restored_grant["revoked_at"] is not None
            call(base,route+"/cancel",409,fresh,"POST",{"expected_generation":3})
            assert call(base,route+"/fence",200,fresh)[1]==row
            assert call(base,route,200,fresh)[1]["generation"]==3
            call(base,"relay/grant",401,rotated,"POST",current_payload)
            with sqlite3.connect(restored/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_grants WHERE revoked_at IS NOT NULL").fetchone()==(2,)
                assert db.execute("SELECT count(*) FROM relay_allocations WHERE state='reserved'").fetchone()==(3,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_grant_restore_revoked_and_retained"]=True
        finally:stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==4 and all(report.values())
