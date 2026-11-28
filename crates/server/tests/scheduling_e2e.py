"""Real server HTTP, concurrent SQLite admission, reservation and recovery."""
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
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
        nodes=[cmd(root,"--add-node","relay "+str(i)) for i in range(3)]
        tokens=[cmd(root,"--relay-issue",n) for n in nodes]
        for n,area in zip(nodes,["east","west","east"]):
            cmd(root,"--set-node-policy",n,1,1,area,"active")
        p,base=launch(root)
        try:
            owner=login(base,"owner");other=login(base,"other")
            did=device(base,owner);foreign=device(base,other)
            def beat(i,c=99):
                call(base,"relay/heartbeat",204,tokens[i],"POST",{"protocol_version":1,"generation":1,"capacity":c})
            beat(0);beat(1);beat(2,0)
            def spec(port,**extra):
                return dict(request_key=secrets.token_hex(16),device_id=did,protocol="tcp",local_port=8080,bind_port=port,**extra)
            def allocate(s,status=201,token=owner):
                return call(base,"allocations",status,token,"POST",s)
            a=spec(20000,region="east")
            with ThreadPoolExecutor(max_workers=2) as workers:
                result=list(workers.map(lambda _:allocate(a,(200,201)),range(2)))
            assert sorted(code for code,_ in result)==[200,201]
            one=result[0][1]
            assert one==result[1][1] and one["node_id"]==nodes[0] and one["state"]=="reserved" and one["generation"]==1
            allocate(dict(a,local_port=8081),409)
            allocate(spec(20001,region="east"),409)
            beat(2,1)
            competing=[spec(20001+i,region="east") for i in range(2)]
            with ThreadPoolExecutor(max_workers=2) as workers:
                result=list(workers.map(lambda s:allocate(s,(201,409)),competing))
            assert sorted(code for code,_ in result)==[201,409]
            three=next(row for code,row in result if code==201)
            assert three["node_id"]==nodes[2]
            report["real_atomic_capacity_and_idempotent_reservation"]=True
            beat(1)
            two=allocate(spec(20000,node_id=nodes[1],region="west"))[1]
            assert two["node_id"]==nodes[1] and two["bind_port"]==one["bind_port"]
            allocate(spec(20000,node_id=nodes[1]),409)
            allocate(spec(20002,node_id=nodes[1],region="east"),409)
            path="allocations/"+two["id"]
            def cancel(row,status=200,token=owner,gen=1):
                return call(base,"allocations/"+row["id"]+"/cancel",status,token,"POST",{"expected_generation":gen})[1]
            cmd(root,"--set-node-policy",nodes[1],2,3,"west","draining")
            beat(1)
            allocate(spec(20003,region="west"),409)
            assert call(base,path,200,owner)[1]==two
            cmd(root,"--set-node-policy",nodes[1],3,3,"west","active")
            beat(1)
            allocate(spec(20000,node_id=nodes[1]),409)
            # Future heartbeat and stale generation are never eligible.
            with sqlite3.connect(root/"control.sqlite3") as db:
                db.execute("UPDATE relay_heartbeat SET received_at=unixepoch()+60 WHERE node_id=?",(nodes[1],))
            allocate(spec(20003,region="west"),409)
            beat(1)
            report["real_region_port_and_drain_isolation"]=True
            allocate(spec(20004,region="west"),401,tokens[0])
            allocate(dict(spec(20004,region="west"),device_id=foreign),409)
            call(base,path,404,other)
            cancel(two,404,other)
            cancel(two,409,gen=2)
            mapping="mappings/"+two["mapping_id"]
            call(base,mapping+"/tcp-start",409,owner,"POST",{"expected_revision":1})
            call(base,mapping,409,owner,"PATCH",{"expected_revision":1,"local_port":8081})
            call(base,mapping+"?expected_revision=1",409,owner,"DELETE")
            call(base,"mappings",409,owner,"POST",{"device_id":did,"node_id":nodes[1],"protocol":"tcp","local_port":8080,"bind_port":20004})
            cancelled=cancel(two)
            assert cancelled["state"]=="cancelled" and cancel(two)==cancelled
            call(base,mapping,404,owner)
            beat(1)
            replacement=allocate(spec(20000,region="west"))[1]
            assert replacement["id"]!=two["id"]
            old=cancel(one)
            assert allocate(a,200)[1]==old
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
                assert db.execute("SELECT count(*) FROM relay_allocations WHERE state='reserved'").fetchone()==(2,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='allocation.reserved'").fetchone()==(4,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='allocation.cancelled'").fetchone()==(2,)
            report["real_allocation_owner_boundary_and_cancel"]=True
            call(base,"allocations",401)
            call(base,"allocations",401,tokens[0])
            call(base,"allocations?after=invalid",400,owner)
            listing=call(base,"allocations",200,owner)[1]
            assert listing["scope"]=="owner_allocation_observations_only" and listing["executable"] is False and listing["next_after"] is None
            rows=listing["allocations"]
            assert [r["id"] for r in rows]==sorted([one["id"],two["id"],three["id"],replacement["id"]])
            byid={r["id"]:r for r in rows}
            assert byid[replacement["id"]]["authorization_state"]=="not_issued" and byid[replacement["id"]]["cancellable"] is True
            assert byid[two["id"]]["authorization_state"]=="cancelled" and byid[two["id"]]["cancellable"] is False
            assert all("request_digest" not in r and "request_key" not in r and "owner_id" not in r for r in rows)
            assert call(base,"allocations",200,other)[1]["allocations"]==[]
            assert call(base,"allocations?after="+rows[0]["id"],200,owner)[1]["allocations"]==rows[1:]
            report["real_owner_allocation_overview_and_history"]=True
            backup=Path(tmp)/"backup";restored=Path(tmp)/"restored"
            assert subprocess.run([exe,"--backup-db",str(root),str(backup)],capture_output=True,timeout=40).returncode==0
        finally:stop(p)
        assert subprocess.run([exe,"--restore-db",str(backup),str(restored)],capture_output=True,timeout=40).returncode==0
        p,base=launch(restored)
        try:
            fresh=login(base,"owner")
            assert call(base,"allocations/"+replacement["id"],200,fresh)[1]==replacement
            assert call(base,"allocations/"+one["id"],200,fresh)[1]==old
            call(base,"relay/identity",401,tokens[1])
            with sqlite3.connect(restored/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_allocations WHERE state='reserved'").fetchone()==(2,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_allocation_restore_retains_reservation"]=True
        finally:stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==5 and all(report.values())
