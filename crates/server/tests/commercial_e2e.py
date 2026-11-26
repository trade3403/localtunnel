"""Real pre-0012 SQLx upgrade and owner-scoped commercial inventory."""
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
    try: p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)

def launch(root):
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout,selectors.EVENT_READ)
            assert sel.select(20),"startup timeout"
        line=p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:"),"legacy migration failed"
        return p,"http://"+line.split()[1]
    except BaseException:
        stop(p)
        raise

def call(base,path,status,method="GET",token=None,data=None):
    headers={}
    if token is not None: headers["Authorization"]="Bearer "+token
    if data is not None: headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+path,method=method,headers=headers,data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            code,raw=response.status,response.read()
            assert "no-store" in response.headers.get("Cache-Control","") or path=="/readyz"
    except urllib.error.HTTPError as e:
        code,raw=e.code,e.read()
    assert code==status,f"{method} {path}: expected {status}, got {code}"
    return json.loads(raw) if code in (200,201) and path!="/readyz" else None

def rows(db,t):
    return db.execute("SELECT * FROM "+t+" ORDER BY 1").fetchall()

try:
    with tempfile.TemporaryDirectory() as tmp:
        fresh=Path(tmp)/"fresh"
        root=Path(tmp)/"legacy"
        fresh.mkdir(mode=0o700)
        root.mkdir(mode=0o700)
        assert subprocess.run([exe,"--init-admin",str(fresh)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20).returncode==0
        with sqlite3.connect(fresh/"control.sqlite3") as db:
            owner,phc=db.execute("SELECT id,password_hash FROM users").fetchone()
            assert db.execute("SELECT count(*) FROM tenants WHERE owner_id=?",(owner,)).fetchone()==(1,)
            assert db.execute("SELECT plan_id FROM tenant_entitlements").fetchone()==("legacy-v1",)
        db_path=root/"control.sqlite3"
        other="b"*32
        with sqlite3.connect(db_path) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("CREATE TABLE _sqlx_migrations(version BIGINT PRIMARY KEY,description TEXT NOT NULL,installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,success BOOLEAN NOT NULL,checksum BLOB NOT NULL,execution_time BIGINT NOT NULL)")
            for path in sorted(migrations.glob("*.sql")):
                number,description=path.stem.split("_",1)
                if int(number)>11: continue
                raw=path.read_bytes()
                db.executescript(raw.decode())
                db.execute("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES (?,?,1,?,0)",(int(number),description.replace("_"," "),hashlib.sha384(raw).digest()))
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES (?, 'operator',?,'admin')",(owner,phc))
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES (?, 'otheradmin',?,'admin')",(other,phc))
            db.execute("INSERT INTO nodes(id,name) VALUES ('node1','fixture')")
            db.execute("INSERT INTO devices(id,owner_id,name,credential_digest) VALUES (?,?,?,?)",("c"*32,owner,"legacy",secrets.token_bytes(32)))
            db.execute("INSERT INTO mappings(id,owner_id,device_id,node_id,protocol,local_port,bind_port) VALUES (?,?,?,'node1','udp',5353,20001)",("d"*32,owner,"c"*32))
            tables=["users","devices","nodes","domains","mappings","runtime_requests","mapping_traffic","management_audit"]
            baseline={t:rows(db,t) for t in tables}
        p,base=launch(root)
        try:
            with sqlite3.connect(db_path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                assert {t:rows(db,t) for t in tables}==baseline
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
                assert db.execute("PRAGMA integrity_check").fetchone()==("ok",)
                assert db.execute("SELECT success FROM _sqlx_migrations WHERE version=12").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM tenants").fetchone()==(2,)
                assert db.execute("SELECT count(*) FROM tenant_entitlements WHERE plan_id='legacy-v1'").fetchone()==(2,)
            report["real_legacy_upgrade_preserves_existing_owner_data"]=True
            report["fresh_bootstrap_and_legacy_tenant_assignment"]=True
            route="/api/v1/commercial/entitlement"
            call(base,route,401)
            admin=call(base,"/api/v1/auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            second=call(base,"/api/v1/auth/login",200,"POST",data={"username":"otheradmin","password":password})["access_token"]
            a=call(base,route,200,token=admin)
            b=call(base,route,200,token=second)
            assert a["scope"]=="owner_inventory_only" and a["commercial_enforcement"] is False
            a,b=a["entitlement"],b["entitlement"]
            assert a["tenant_id"]!=b["tenant_id"] and a["plan_id"]==b["plan_id"]=="legacy-v1"
            assert (a["active_devices"],a["retained_devices"],a["mappings"])==(1,1,1)
            assert (b["active_devices"],b["retained_devices"],b["mappings"])==(0,0,0)
            assert a["max_bandwidth_bps"] is None and a["max_monthly_bytes"] is None
            assert not ({"password_hash","credential_digest","owner_id"} & a.keys())
            call(base,route,405,"POST",admin,{"plan_id":"legacy-v1"})
            report["real_authenticated_owner_inventory_isolation"]=True
            # Fixture-only policy changes: no public mutation endpoint yet.
            with sqlite3.connect(db_path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("UPDATE tenant_entitlements SET expires_at=unixepoch()-1,revision=revision+1 WHERE tenant_id=?",(a["tenant_id"],))
                db.execute("UPDATE tenant_entitlements SET state='suspended',revision=revision+1 WHERE tenant_id=?",(b["tenant_id"],))
                db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('future-user','futureuser',?,'user')",(phc,))
                assert db.execute("SELECT count(*) FROM tenants WHERE owner_id='future-user'").fetchone()==(1,)
                try:
                    db.execute("INSERT INTO commercial_plans VALUES ('bad','bad',1,'bad',65,256,1,NULL,NULL,NULL)")
                except sqlite3.IntegrityError: pass
                else: raise AssertionError("invalid plan accepted")
            assert call(base,route,200,token=admin)["entitlement"]["effective_state"]=="expired"
            assert call(base,route,200,token=second)["entitlement"]["effective_state"]=="suspended"
            call(base,"/api/v1/auth/logout",204,"POST",admin)
            call(base,route,401,token=admin)
            report["real_policy_state_and_revoked_session_observation"]=True
        finally: stop(p)
        p,base=launch(root)
        try:
            admin=call(base,"/api/v1/auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            value=call(base,route,200,token=admin)["entitlement"]
            assert value["tenant_id"]==a["tenant_id"] and value["revision"]==2 and value["effective_state"]=="expired"
            with sqlite3.connect(db_path) as db:
                db.execute("DROP TABLE tenant_entitlements")
            call(base,"/readyz",503)
            report["real_restart_persistence_and_commercial_readiness"]=True
        finally: stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==5 and all(value is True for value in report.values())
