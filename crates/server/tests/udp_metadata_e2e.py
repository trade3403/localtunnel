"""Real SQLx upgrade of a pre-0011 database, then authenticated UDP CRUD."""
import hashlib
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
migrations=Path(__file__).resolve().parents[1]/"migrations"
report={}
password=secrets.token_hex(24)
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
            assert s.select(20),"startup timeout"
        line=p.stdout.readline().strip()
        if not line.startswith("LISTENING 127.0.0.1:"):
            raise AssertionError("legacy database upgrade startup failed")
        return p,"http://"+line.split()[1]
    except BaseException:
        stop(p)
        raise
def call(base,path,status,method="GET",token=None,data=None):
    headers={}
    if token is not None:
        headers["Authorization"]="Bearer "+token
    if data is not None:
        headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            code,raw=r.status,r.read()
    except urllib.error.HTTPError as e:
        code,raw=e.code,e.read()
    assert code==status,f"{method} {path}: expected {status}, got {code}"
    if code in (200,201):
        return json.loads(raw)
def rows(db,table):
    return db.execute("SELECT * FROM "+table+" ORDER BY 1").fetchall()
try:
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)/"legacy"
        root.mkdir(mode=0o700)
        fresh=Path(temp)/"fresh"
        fresh.mkdir(mode=0o700)
        assert subprocess.run([exe,"--init-admin",str(fresh)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20).returncode==0
        with sqlite3.connect(fresh/"control.sqlite3") as db:
            owner,phc=db.execute("SELECT id,password_hash FROM users").fetchone()
        db_path=root/"control.sqlite3"
        with sqlite3.connect(db_path) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("CREATE TABLE _sqlx_migrations(version BIGINT PRIMARY KEY,description TEXT NOT NULL,installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,success BOOLEAN NOT NULL,checksum BLOB NOT NULL,execution_time BIGINT NOT NULL)")
            for path in sorted(migrations.glob("*.sql")):
                number,description=path.stem.split("_",1)
                if int(number)>10:
                    continue
                raw=path.read_bytes()
                db.executescript(raw.decode())
                db.execute("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES (?,?,1,?,0)",
                    (int(number),description.replace("_"," "),hashlib.sha384(raw).digest()))
            aid="a"*32
            mid="b"*32
            hid="c"*32
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES (?,?,?,'admin')",(owner,"operator",phc))
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('other','otheradmin',?,'admin')",(phc,))
            db.execute("INSERT INTO devices(id,owner_id,name,credential_digest) VALUES (?,?,?,?)",(aid,owner,"legacy device",secrets.token_bytes(32)))
            db.execute("INSERT INTO nodes(id,name) VALUES ('n1','legacy node')")
            db.execute("INSERT INTO domains(id,owner_id,hostname) VALUES ('h1',?,'legacy.example.test')",(owner,))
            db.execute("INSERT INTO mappings(id,owner_id,device_id,node_id,protocol,local_port,bind_port) VALUES (?,?,?,'n1','tcp',8080,20001)",(mid,owner,aid))
            db.execute("INSERT INTO mappings(id,owner_id,device_id,node_id,domain_id,protocol,local_port,bind_port) VALUES (?,?,?,'n1','h1','http',8081,20002)",(hid,owner,aid))
            db.execute("INSERT INTO runtime_requests VALUES (?, 'legacy-request',1,'stopped',10,11)",(hid,))
            db.execute("INSERT INTO mapping_traffic VALUES ('legacy-request',?,1,5,100,200,12,'sampled')",(hid,))
            tables=["mappings","runtime_requests","mapping_traffic","management_audit","devices"]
            baseline={t:rows(db,t) for t in tables}
            assert not db.execute("PRAGMA foreign_key_check").fetchall()
        p,base=launch(root)
        try:
            with sqlite3.connect(db_path) as db:
                assert {t:rows(db,t) for t in tables}==baseline
                assert not db.execute("PRAGMA foreign_key_check").fetchall()
                assert db.execute("SELECT success FROM _sqlx_migrations WHERE version=11").fetchone()==(1,)
                assert db.execute("PRAGMA integrity_check").fetchone()==("ok",)
            report["actual_sqlx_upgrade_preserves_rows_revisions_audit_and_foreign_keys"]=True
            admin=call(base,"auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            other=call(base,"auth/login",200,"POST",data={"username":"otheradmin","password":password})["access_token"]
            pairing=call(base,"devices/pairing-code",200,"POST",admin)["pairing_code"]
            device=call(base,"devices/enroll",201,"POST",data={"pairing_code":pairing,"name":"UDP device"})
            did,token=device["id"],device["device_token"]
            spec={"device_id":did,"node_id":"n1","protocol":"udp","local_port":5353,"bind_port":20003}
            call(base,"mappings",400,"POST",admin,dict(spec,domain_id="h1"))
            call(base,"mappings",409,"POST",admin,dict(spec,bind_port=20001))
            call(base,"mappings",409,"POST",other,spec)
            udp=call(base,"mappings",201,"POST",admin,spec)
            path="mappings/"+udp["id"]
            assert udp["enabled"] is False and udp["domain_id"] is None and udp["protocol"]=="udp"
            desired=call(base,"devices/"+did+"/config",200,token=token)
            assert desired["scope"]=="desired_metadata_only" and len(desired["mappings"])==1
            assert desired["mappings"][0]["protocol"]=="udp" and desired["mappings"][0]["enabled"] is False
            call(base,path,404,token=other)
            call(base,path+"/start",409,"POST",admin,{"expected_revision":1})
            call(base,path,409,"PATCH",admin,{"expected_revision":1,"enabled":True})
            report["real_udp_draft_owner_port_domain_and_activation_gate"]=True
            updated=call(base,path,200,"PATCH",admin,{"expected_revision":1,"local_port":5354})
            assert updated["revision"]==2 and updated["protocol"]=="udp"
            assert call(base,"devices/"+did+"/config",200,token=token)["revision"]==desired["revision"]+1
            call(base,path+"?expected_revision=1",409,"DELETE",admin)
            call(base,path+"?expected_revision=2",204,"DELETE",admin)
            assert call(base,"devices/"+did+"/config",200,token=token)["mappings"]==[]
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT event,revision FROM management_audit WHERE resource_id=? ORDER BY seq",(udp["id"],)).fetchall()==[("mapping.created",1),("mapping.updated",2),("mapping.deleted",2)]
                assert not db.execute("PRAGMA foreign_key_check").fetchall()
                assert rows(db,"runtime_requests")==baseline["runtime_requests"]
                assert rows(db,"mapping_traffic")==baseline["mapping_traffic"]
            report["real_udp_device_revision_edit_delete_and_audit"]=True
        finally:
            stop(p)
        p,base=launch(root)
        try:
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT count(*) FROM _sqlx_migrations WHERE version=11").fetchone()==(1,)
                assert not db.execute("PRAGMA foreign_key_check").fetchall()
                assert rows(db,"mappings")==baseline["mappings"]
            report["real_migrated_database_restart_preserves_legacy_mappings"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==4 and all(v is True for v in report.values())
