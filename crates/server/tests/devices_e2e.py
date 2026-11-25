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
        p,base=launch(root)
        try:
            admin=login(base,"operator")
            other=login(base,"otheradmin")
            expect(call(base,"devices"),401)
            expect(call(base,"devices/pairing-code","POST"),401)
            expect(enroll(base,"ltpair_"+"0"*64),401)
            old=issue(base,admin)
            code=issue(base,admin)
            assert old!=code
            expect(enroll(base,old),401)
            with sqlite3.connect(db_path) as db:
                stored=db.execute("SELECT code_digest FROM device_pairings WHERE owner_id=?",(owner,)).fetchone()[0]
                assert stored==hashlib.sha256(code.encode()).digest()
            assert code.encode() not in db_path.read_bytes()
            expect(enroll(base,code,"   "),400)
            with ThreadPoolExecutor(max_workers=2) as workers:
                outcomes=list(workers.map(lambda _:enroll(base,code),range(2)))
            assert sorted(r[0] for r in outcomes)==[201,401]
            registered=expect(next(r for r in outcomes if r[0]==201),201)
            device_id,token=registered["id"],registered["device_token"]
            assert len(bytes.fromhex(device_id))==16
            assert token.startswith("ltdev_") and len(bytes.fromhex(token[6:]))==32
            expect(enroll(base,code),401)
            with sqlite3.connect(db_path) as db:
                row=db.execute("SELECT owner_id,credential_digest FROM devices WHERE id=?",(device_id,)).fetchone()
                assert row==(owner,hashlib.sha256(token.encode()).digest())
                assert db.execute("SELECT count(*) FROM device_pairings WHERE owner_id=?",(owner,)).fetchone()==(0,)
            assert token.encode() not in db_path.read_bytes()
            report["atomic_single_use_and_digest"]=True
            identity="devices/"+device_id+"/identity"
            revoke="devices/"+device_id+"/revoke"
            expect(call(base,identity),401)
            expect(call(base,identity,token=admin),401)
            expect(call(base,"auth/me",token=token),401)
            expect(call(base,"devices/pairing-code","POST",token),401)
            expect(call(base,"devices/"+"0"*32+"/identity",token=token),401)
            item=expect(call(base,identity,token=token),200)
            assert item=={"id":device_id,"name":"fixture device","enabled":True,"revision":1}
            assert expect(call(base,"devices",token=admin),200)==[item]
            assert expect(call(base,"devices?after="+device_id,token=admin),200)==[]
            assert expect(call(base,"devices",token=other),200)==[]
            expect(call(base,revoke,"POST",other),404)
            expect(call(base,identity,token=token),200)
            report["device_scope_and_admin_ownership"]=True
            expired=issue(base,admin)
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE device_pairings SET expires_at=unixepoch()-1 WHERE owner_id=?",(owner,))
            expect(enroll(base,expired),401)
            pending=issue(base,admin)
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=0 WHERE id=?",(owner,))
            expect(enroll(base,pending),401)
            expect(call(base,identity,token=token),401)
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=1 WHERE id=?",(owner,))
            expect(enroll(base,pending),401)
            admin=login(base,"operator")
            expect(call(base,identity,token=token),200)
            report["expiry_and_owner_state"]=True
        finally:
            stop(p)
        p,base=launch(root)
        try:
            expect(call(base,identity,token=token),200)
            expect(call(base,revoke,"POST",admin),204)
            expect(call(base,identity,token=token),401)
            expect(call(base,revoke,"POST",admin),404)
            items=expect(call(base,"devices",token=admin),200)
            assert items==[{"id":device_id,"name":"fixture device","enabled":False,"revision":2}]
            with sqlite3.connect(db_path) as db:
                stored=db.execute("SELECT credential_digest FROM devices WHERE id=?",(device_id,)).fetchone()[0]
                assert stored!=hashlib.sha256(token.encode()).digest()
            report["restart_and_revocation"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
