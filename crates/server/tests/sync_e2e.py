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
        p,base=launch(root)
        try:
            admin=login(base,"operator")
            other=login(base,"otheradmin")
            a=expect(enroll(base,issue(base,admin),"device a"),201)
            b=expect(enroll(base,issue(base,other),"device b"),201)
            aid,token=a["id"],a["device_token"]
            bid,other_token=b["id"],b["device_token"]
            config="devices/"+aid+"/config"
            status="devices/"+aid+"/status"
            def fetch():
                return expect(call(base,config,token=token),200)
            def view():
                return expect(call(base,status,token=admin),200)
            def heartbeat(rev,state="running",credential=token):
                return call(base,status,"POST",credential,{"reported_revision":rev,"reported_state":state})
            assert fetch()=={"device_id":aid,"revision":1,"scope":"desired_metadata_only","mappings":[]}
            initial=view()
            assert initial["management_online"] is False and initial["last_seen_at"] is None
            expect(call(base,config),401)
            expect(call(base,config,token=admin),401)
            expect(call(base,config,token=other_token),401)
            expect(call(base,status,token=other),404)
            expect(call(base,status,token=token),401)
            expect(heartbeat(1,credential=admin),401)
            expect(heartbeat(1,credential=other_token),401)
            expect(heartbeat(-1),400)
            expect(heartbeat(1,"invented"),400)
            expect(heartbeat(2),409)
            assert view()["last_seen_at"] is None
            with sqlite3.connect(db_path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                sql="INSERT INTO mappings(id,owner_id,device_id,node_id,protocol,local_port,bind_port) VALUES (?,?,?,'n1','tcp',8080,?)"
                db.execute(sql,("m1",owner,aid,20001))
                db.execute(sql,("m2","other",bid,20002))
            cfg=fetch()
            assert cfg["revision"]==2 and len(cfg["mappings"])==1
            assert cfg["mappings"][0]=={"id":"m1","node_id":"n1","domain_id":None,"protocol":"tcp","local_host":"127.0.0.1","local_port":8080,"bind_port":20001,"enabled":False,"revision":1}
            assert token not in json.dumps(cfg)
            report["snapshot_revision_and_scope"]=True
            receipt=expect(heartbeat(1),200)
            assert receipt["heartbeat_interval_seconds"]==30
            observed=view()
            assert observed["last_seen_at"]==receipt["last_seen_at"]
            assert observed["management_online"] is True and observed["configuration_current"] is False
            assert observed["reported_state"]=="running" and observed["reported_revision"]==1
            expect(heartbeat(2),200)
            assert view()["configuration_current"] is True
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE mappings SET local_port=8081,revision=revision+1 WHERE id='m1'")
            assert fetch()["revision"]==3 and fetch()["mappings"][0]["local_port"]==8081
            assert view()["configuration_current"] is False
            expect(heartbeat(4),409)
            assert view()["reported_revision"]==2
            expect(heartbeat(3,"error"),200)
            assert view()["configuration_current"] is True and view()["reported_state"]=="error"
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE device_status SET last_seen_at=unixepoch()-91 WHERE device_id=?",(aid,))
            assert view()["management_online"] is False and view()["configuration_current"] is False
            expect(heartbeat(3),200)
            assert view()["management_online"] is True
            report["real_heartbeat_staleness_and_revision"]=True
            with sqlite3.connect(db_path) as db:
                db.execute("DELETE FROM mappings WHERE id='m1'")
            assert fetch()["revision"]==4 and fetch()["mappings"]==[]
            expect(heartbeat(4,"idle"),200)
        finally:
            stop(p)
        p,base=launch(root)
        try:
            assert fetch()["revision"]==4 and view()["reported_revision"]==4
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=0 WHERE id=?",(owner,))
            expect(call(base,config,token=token),401)
            expect(heartbeat(4),401)
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=1 WHERE id=?",(owner,))
            admin=login(base,"operator")
            assert view()["last_seen_at"] is None and view()["management_online"] is False
            expect(heartbeat(4),200)
            expect(call(base,"devices/"+aid+"/revoke","POST",admin),204)
            expect(call(base,config,token=token),401)
            expect(heartbeat(4),401)
            disabled=view()
            assert disabled["enabled"] is False and disabled["last_seen_at"] is None and disabled["management_online"] is False
            report["restart_owner_and_device_revocation"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
