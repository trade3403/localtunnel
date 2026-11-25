"""Actual CLI + HTTP device registration, ownership and revocation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

exe=str(Path(sys.argv[1]).resolve())
evidence=Path(sys.argv[2])
report={}
password=secrets.token_hex(24)

def call(base,path,method="GET",token=None,data=None):
    headers={}
    if token is not None:
        headers["Authorization"]="Bearer "+token
    if data is not None:
        headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,r.read(),r.headers
    except urllib.error.HTTPError as e:
        return e.code,e.read(),e.headers

def expect(r,status):
    assert r[0]==status, f"expected {status}, got {r[0]}"
    if status in (200,201):
        assert r[2].get("Cache-Control")=="no-store"
        return json.loads(r[1])

def login(base,name):
    return expect(call(base,"auth/login","POST",data={"username":name,"password":password}),200)["access_token"]

def issue(base,admin):
    payload=expect(call(base,"devices/pairing-code","POST",admin),200)
    assert payload["expires_in"]==600
    code=payload["pairing_code"]
    assert code.startswith("ltpair_") and len(bytes.fromhex(code[7:]))==32
    return code

def enroll(base,code,name="fixture device"):
    return call(base,"devices/enroll","POST",data={"pairing_code":code,"name":name})

def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)

def launch(root):
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with selectors.DefaultSelector() as s:
            s.register(p.stdout,selectors.EVENT_READ)
            assert s.select(20),"startup timed out"
        line=p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:"),"not loopback"
        return p,"http://"+line.split()[1]
    except BaseException:
        stop(p)
        raise

try:
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        db_path=root/"control.sqlite3"
        result=subprocess.run([exe,"--init-admin",str(root)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20)
        assert result.returncode==0
        with sqlite3.connect(db_path) as db:
            owner,phc=db.execute("SELECT id,password_hash FROM users").fetchone()
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('other','otheradmin',?,'admin')",(phc,))
            db.execute("INSERT INTO nodes(id,name) VALUES ('n1','fixture')")
            db.execute("INSERT INTO nodes(id,name,enabled) VALUES ('n2','disabled',0)")
            db.execute("INSERT INTO domains(id,owner_id,hostname) VALUES ('h1',?,'one.example.test')",(owner,))
            db.execute("INSERT INTO domains(id,owner_id,hostname) VALUES ('h2','other','two.example.test')")
        p,base=launch(root)
        try:
            admin=login(base,"operator")
            other=login(base,"otheradmin")
            a=expect(enroll(base,issue(base,admin),"device a"),201)
            b=expect(enroll(base,issue(base,other),"device b"),201)
            aid,token=a["id"],a["device_token"]
            bid=b["id"]
            spec={"device_id":aid,"node_id":"n1","protocol":"tcp","local_port":8080,"bind_port":20001}
            def create(specification,credential=admin):
                return call(base,"mappings","POST",credential,specification)
            def snapshot():
                return expect(call(base,"devices/"+aid+"/config",token=token),200)
            expect(call(base,"mappings"),401)
            expect(create(spec,token),401)
            expect(create(spec,other),409)
            expect(create(dict(spec,device_id=bid)),409)
            expect(create(dict(spec,node_id="n2")),409)
            expect(create(dict(spec,bind_port=443)),400)
            expect(create(dict(spec,local_port=0)),400)
            expect(create(dict(spec,protocol="https")),400)
            expect(create(dict(spec,protocol="tcp",domain_id="h1")),400)
            expect(create(dict(spec,protocol="https",domain_id="h2")),409)
            expect(create(dict(spec,enabled=True)),422)
            assert snapshot()["revision"]==1
            m=expect(create(spec),201)
            mid=m["id"]
            assert len(bytes.fromhex(mid))==16
            assert m==dict(spec,id=mid,domain_id=None,local_host="127.0.0.1",enabled=False,revision=1)
            path="mappings/"+mid
            assert expect(call(base,path,token=admin),200)==m
            assert expect(call(base,"mappings",token=admin),200)==[m]
            assert expect(call(base,"mappings?after="+mid,token=admin),200)==[]
            assert expect(call(base,"mappings",token=other),200)==[]
            expect(call(base,path,token=other),404)
            expect(call(base,path,"PATCH",other,{"expected_revision":1,"local_port":9000}),404)
            expect(call(base,path+"?expected_revision=1","DELETE",other),404)
            expect(create(spec),409)
            expect(create(dict(spec,device_id=bid),other),409)
            assert snapshot()["revision"]==2
            web=expect(create(dict(spec,protocol="https",domain_id="h1",bind_port=20002)),201)
            expect(create(dict(spec,protocol="http",domain_id="h1",bind_port=20003)),409)
            assert snapshot()["revision"]==3
            assert len(snapshot()["mappings"])==2
            report["create_read_scope_and_conflicts"]=True
            expect(call(base,path,"PATCH",admin,{"expected_revision":1,"enabled":True}),409)
            expect(call(base,path,"PATCH",admin,{"expected_revision":1,"bind_port":20002}),409)
            assert snapshot()["revision"]==3
            updated=expect(call(base,path,"PATCH",admin,{"expected_revision":1,"local_port":9090,"bind_port":20003}),200)
            assert updated==dict(m,local_port=9090,bind_port=20003,revision=2)
            expect(call(base,path,"PATCH",admin,{"expected_revision":1,"local_port":9091}),409)
            expect(call(base,path+"?expected_revision=1","DELETE",admin),409)
            assert snapshot()["revision"]==4
            # Explicit database fixture for legacy enabled row, not activation API.
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE mappings SET enabled=1,revision=revision+1 WHERE id=?",(mid,))
            expect(call(base,path+"?expected_revision=3","DELETE",admin),409)
            expect(call(base,path,"PATCH",admin,{"expected_revision":3,"local_port":9091}),409)
            disabled=expect(call(base,path,"PATCH",admin,{"expected_revision":3,"enabled":False}),200)
            assert disabled["enabled"] is False and disabled["revision"]==4
            assert snapshot()["revision"]==6
            report["optimistic_update_and_activation_gate"]=True
        finally:
            stop(p)
        p,base=launch(root)
        try:
            assert expect(call(base,path,token=admin),200)==disabled
            expect(call(base,path+"?expected_revision=4","DELETE",admin),204)
            expect(call(base,path,token=admin),404)
            assert snapshot()["revision"]==7 and len(snapshot()["mappings"])==1
            # Fill the device with disabled fixtures to exercise the atomic
            # count limit without making dozens of unrelated HTTP requests.
            with sqlite3.connect(db_path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                db.executemany("INSERT INTO mappings(id,owner_id,device_id,node_id,protocol,local_port,bind_port) VALUES (?,?,?,'n1','tcp',8080,?)",
                    [(f"{i:032x}",owner,aid,21000+i) for i in range(63)])
            before=snapshot()
            assert len(before["mappings"])==64
            expect(create(dict(spec,bind_port=25000)),409)
            assert snapshot()==before
            report["restart_delete_and_mapping_limit"]=True
            # Audit the real committed operations, not attempted requests.
            expect(call(base,"audit"),401)
            expect(call(base,"audit",token=token),401)
            expect(call(base,"audit?before=0",token=admin),400)
            a_log=expect(call(base,"audit",token=admin),200)
            assert a_log["scope"]=="committed_owner_state_changes"
            mine=[e for e in a_log["events"] if e["resource_id"]==mid]
            assert [(e["event"],e["revision"]) for e in mine]==[
                ("mapping.deleted",4),("mapping.updated",4),("mapping.updated",3),("mapping.updated",2),("mapping.created",1)]
            other_log=expect(call(base,"audit",token=other),200)
            assert not any(e["resource_id"] in (mid,aid,web["id"]) for e in other_log["events"])
            assert all(set(e)=={"seq","event","resource_id","revision","request_id","state","occurred_at"} for e in a_log["events"])
            assert token not in json.dumps(a_log) and admin not in json.dumps(a_log)
            # Controlled SQLite fixtures only for cursor boundary/retention.
            with sqlite3.connect(db_path) as db:
                db.executemany("INSERT INTO management_audit(owner_id,event,resource_id,occurred_at) VALUES (?,'fixture.old','fixture',unixepoch()-8000000)",[(owner,)]*110)
            first=expect(call(base,"audit",token=admin),200)
            second=expect(call(base,"audit?before="+str(first["next_before"]),token=admin),200)
            assert len(first["events"])==100 and second["events"]
            assert min(e["seq"] for e in first["events"])>max(e["seq"] for e in second["events"])
            assert subprocess.run([exe,"--prune-history",str(root)],capture_output=True,timeout=20).returncode==0
            remaining=expect(call(base,"audit",token=admin),200)
            assert not any(e["event"]=="fixture.old" for e in remaining["events"])
            assert any(e["resource_id"]==mid and e["event"]=="mapping.deleted" for e in remaining["events"])
            report["real_committed_audit_owner_cursor_and_local_retention"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
