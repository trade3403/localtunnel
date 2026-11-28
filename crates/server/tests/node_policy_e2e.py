"""Actual pre-0020 migration, operator CLI, relay HTTP and isolated restore."""
import concurrent.futures
import hashlib
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
migrations=Path(__file__).resolve().parents[1]/"migrations"
report={}
password=secrets.token_hex(24)
def command(root,*args,data=None,ok=True):
    p=subprocess.run([exe,args[0],str(root),*map(str,args[1:])],input=None if data is None else json.dumps(data),text=True,capture_output=True,timeout=30)
    assert (p.returncode==0)==ok,"operator result mismatch"
    if not ok: assert not p.stdout.strip()
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
            assert sel.select(20),"startup timeout"
        line=p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:")
        return p,"http://"+line.split()[1]
    except BaseException:
        stop(p);raise
def call(base,path,status,token=None,method="GET",data=None):
    headers={}
    if token:headers["Authorization"]="Bearer "+token
    if data is not None:headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,headers=headers,method=method,data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            assert r.status==status
            assert "no-store" in r.headers.get("Cache-Control","")
            raw=r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        assert e.code==status,f"{method} {path}: unexpected status {e.code}"
def reject(db,sql):
    try:db.execute(sql)
    except sqlite3.IntegrityError:return
    raise AssertionError("constraint did not reject invalid policy")
def health(root,node):
    return json.loads(command(root,"--node-health",node))
try:
    with tempfile.TemporaryDirectory() as tmp:
        parent=Path(tmp)
        root=parent/"live"
        root.mkdir(mode=0o700)
        dbpath=root/"control.sqlite3"
        a="a"*32
        b="b"*32
        token="ltrelay_"+secrets.token_hex(32)
        # Obtain the exact SQLx bookkeeping DDL from a genuine current database.
        # Restore validates sqlite_schema text, not just equivalent column types.
        reference=parent/"reference"
        reference.mkdir(mode=0o700)
        command(reference,"--add-node","schema reference")
        with sqlite3.connect(reference/"control.sqlite3") as db:
            migration_ddl=db.execute("SELECT sql FROM sqlite_schema WHERE type='table' AND name='_sqlx_migrations'").fetchone()[0]
        # Execute the exact prior migrations with genuine SQLx bookkeeping.
        with sqlite3.connect(dbpath) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute(migration_ddl)
            for path in sorted(migrations.glob("*.sql")):
                number,description=path.stem.split("_",1)
                if int(number)>19:continue
                raw=path.read_bytes()
                db.executescript(raw.decode())
                db.execute("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES (?,?,1,?,0)",(int(number),description.replace("_"," "),hashlib.sha384(raw).digest()))
            db.execute("INSERT INTO nodes(id,name) VALUES (?, 'legacy relay A'), (?, 'legacy relay B')",(a,b))
            db.execute("INSERT INTO relay_identities(node_id,token_digest,generation) VALUES (?,?,1)",(a,hashlib.sha256(bytes.fromhex(token[8:])).digest()))
            db.execute("INSERT INTO relay_identity_audit(node_id,generation,event) VALUES (?,1,'issued')",(a,))
            db.execute("INSERT INTO relay_heartbeat VALUES (?,1,unixepoch(),1,99)",(a,))
        dbpath.chmod(0o600)
        p,base=launch(root)
        try:
            with sqlite3.connect(dbpath) as db:
                db.execute("PRAGMA foreign_keys=ON")
                assert db.execute("SELECT id,name,approved_capacity,region,policy_mode,policy_revision FROM nodes ORDER BY id").fetchall()==[(a,"legacy relay A",0,"unassigned","active",1),(b,"legacy relay B",0,"unassigned","active",1)]
                assert db.execute("SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version").fetchall()==[(int(f.stem.split("_",1)[0]),1,hashlib.sha384(f.read_bytes()).digest()) for f in sorted(migrations.glob("*.sql"))]
                for sql in ("UPDATE nodes SET approved_capacity=-1","UPDATE nodes SET approved_capacity=65537","UPDATE nodes SET region='Invalid!'","UPDATE nodes SET region=''","UPDATE nodes SET policy_mode='other'","UPDATE nodes SET policy_revision=0","INSERT INTO node_policy_audit(node_id,revision,approved_capacity,region,mode) VALUES ('absent',2,1,'us','active')"):
                    reject(db,sql)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_node_policy_upgrade_and_constraints"]=True
            command(root,"--init-admin",data={"username":"owner","password":password})
            owner=call(base,"auth/login",200,method="POST",data={"username":"owner","password":password})["access_token"]
            policy="relay/policy"
            call(base,policy,401)
            call(base,policy,401,owner)
            call(base,"nodes",401,token)
            assert set(call(base,"nodes",200,owner)[0])=={"id","name","enabled"}
            assert health(root,b)["health"]=="unregistered"
            def beat(t,g,c,status=204,**extra):
                call(base,"relay/heartbeat",status,t,"POST",dict(protocol_version=1,generation=g,capacity=c,**extra))
            beat(token,1,99)
            h=call(base,policy+"?node_id="+b,200,token)
            assert h["node_id"]==a and h["approved_capacity"]==0 and h["reported_capacity"]==99 and h["health"]=="online" and h["candidate_capacity"]==0
            call(base,policy,405,token,"POST",{"approved_capacity":65536})
            beat(token,1,99,422,approved_capacity=65536)
            for cap,region,mode in ((-1,"us","active"),(65537,"us","active"),(1,"US","active"),(1,"us","bad")):
                command(root,"--set-node-policy",a,1,cap,region,mode,ok=False)
            command(root,"--set-node-policy","absent",1,1,"us","active",ok=False)
            command(root,"--set-node-policy",a,1,7,"us-east","active")
            assert health(root,a)["policy_revision"]==2
            command(root,"--set-node-policy",a,1,99,"us","active",ok=False)
            def race(_):
                return subprocess.run([exe,"--set-node-policy",str(root),a,"2","7","us-east","active"],capture_output=True,timeout=30)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                results=list(workers.map(race,range(2)))
            assert sum(p.returncode==0 for p in results)==1
            assert all(not p.stdout.strip() for p in results)
            with sqlite3.connect(dbpath) as db:
                assert db.execute("SELECT revision,approved_capacity,region,mode FROM node_policy_audit WHERE node_id=? ORDER BY revision",(a,)).fetchall()==[(2,7,"us-east","active"),(3,7,"us-east","active")]
            report["real_operator_policy_revision_audit_and_isolation"]=True
            beat(token,1,99)
            assert health(root,a)["candidate_capacity"]==7
            call(base,"nodes/overview",401)
            call(base,"nodes/overview",401,token)
            call(base,"nodes/overview",405,owner,"POST",{})
            overview=call(base,"nodes/overview",200,owner)
            assert len(overview)==2 and overview[0]["id"]==a and overview[1]["id"]==b
            assert overview[0]["health"]=="online" and overview[0]["candidate_capacity"]==7 and overview[0]["reported_capacity"]==99
            assert overview[1]["health"]=="unregistered" and overview[1]["reported_capacity"] is None
            assert all(x["owner_mappings"]==0 and x["owner_reserved_allocations"]==0 for x in overview)
            assert set(overview[0])=={"id","name","enabled","region","policy_mode","policy_revision","approved_capacity","reported_capacity","received_at","health","candidate_capacity","owner_mappings","owner_reserved_allocations"}
            assert call(base,"nodes/overview?after="+a,200,owner)==overview[1:]
            call(base,"nodes/overview?after="+"x"*65,400,owner)
            beat(token,1,3)
            assert call(base,policy,200,token)["candidate_capacity"]==3
            command(root,"--set-node-policy",a,3,7,"us-east","draining")
            beat(token,1,99)
            h=health(root,a)
            assert h["health"]=="online" and h["candidate_capacity"]==0 and h["policy_mode"]=="draining"
            o=call(base,"nodes/overview",200,owner)[0]
            assert o["health"]=="online" and o["candidate_capacity"]==0 and o["policy_mode"]=="draining"
            command(root,"--set-node-policy",a,4,7,"us-east","maintenance")
            assert health(root,a)["candidate_capacity"]==0
            command(root,"--set-node-policy",a,5,7,"us-east","active")
            beat(token,1,99)
            assert health(root,a)["candidate_capacity"]==7
            deadline=time.monotonic()+22
            while call(base,policy,200,token)["health"]=="online":
                assert time.monotonic()<deadline,"health did not expire"
                time.sleep(.25)
            h=health(root,a)
            assert h["health"]=="offline" and h["candidate_capacity"]==0
            o=call(base,"nodes/overview",200,owner)[0]
            assert o["health"]=="offline" and o["candidate_capacity"]==0
            report["real_owner_node_overview_health_and_cursor"]=True
            beat(token,1,99)
            with sqlite3.connect(dbpath) as db:
                db.execute("UPDATE relay_heartbeat SET received_at=unixepoch()+60 WHERE node_id=?",(a,))
            assert health(root,a)["health"]=="offline" and health(root,a)["candidate_capacity"]==0
            rotated=command(root,"--relay-rotate",a,1)
            call(base,policy,401,token)
            h=call(base,policy,200,rotated)
            assert h["health"]=="awaiting_heartbeat" and h["reported_capacity"] is None and h["candidate_capacity"]==0
            beat(rotated,2,9)
            assert health(root,a)["candidate_capacity"]==7
            command(root,"--relay-revoke",a,2)
            assert health(root,a)["health"]=="revoked"
            fresh=command(root,"--relay-rotate",a,3)
            beat(fresh,4,8)
            command(root,"--set-node-enabled",a,"false")
            assert health(root,a)["health"]=="disabled" and health(root,a)["candidate_capacity"]==0
            call(base,policy,401,fresh)
            command(root,"--set-node-enabled",a,"true")
            assert health(root,a)["health"]=="revoked"
            fresh=command(root,"--relay-rotate",a,5)
            beat(fresh,6,8)
            report["real_node_health_capacity_and_generation"]=True
            backup=parent/"backup"
            restored=parent/"restored"
            # Snapshot contains an active credential; restore must revoke it.
            assert subprocess.run([exe,"--backup-db",str(root),str(backup)],capture_output=True,timeout=40).returncode==0
        finally:
            stop(p)
        assert subprocess.run([exe,"--restore-db",str(backup),str(restored)],capture_output=True,timeout=40).returncode==0
        p,base=launch(restored)
        try:
            call(base,policy,401,fresh)
            h=health(restored,a)
            assert h["health"]=="revoked" and h["candidate_capacity"]==0 and h["approved_capacity"]==7 and h["region"]=="us-east" and h["policy_revision"]==6
            with sqlite3.connect(restored/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_heartbeat").fetchone()==(0,)
                assert db.execute("SELECT generation,event FROM relay_identity_audit WHERE node_id=? ORDER BY seq DESC LIMIT 1",(a,)).fetchone()==(7,"revoked")
                assert db.execute("SELECT count(*) FROM node_policy_audit").fetchone()==(5,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_node_policy_restore_revokes_snapshot_credentials"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==5 and all(report.values())
