"""Real pre-0012 SQLx upgrade and owner-scoped commercial inventory."""
from concurrent.futures import ThreadPoolExecutor
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
    if isinstance(status,tuple):
        assert code in status,f"{method} {path}: expected {status}, got {code}"
        return code,json.loads(raw) if code==201 else None
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

    # Separate live service and real operator commands. Never expose the
    # operator's write authority through a tenant's HTTP session.
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        db_path=root/"control.sqlite3"
        assert subprocess.run([exe,"--init-admin",str(root)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20).returncode==0
        customer_password=secrets.token_hex(24)
        def command(action,data):
            result=subprocess.run([exe,action,str(root)],input=json.dumps(data).encode(),capture_output=True,timeout=20)
            assert customer_password.encode() not in result.stdout+result.stderr,"credential leaked in command output"
            return result
        def success(action,data):
            result=command(action,data)
            assert result.returncode==0,"operator action failed"
            value=result.stdout.decode().strip()
            assert len(value)==32 and all(ch in "0123456789abcdef" for ch in value)
            return value
        def reject(action,data):
            result=command(action,data)
            assert result.returncode!=0 and not result.stdout.strip(),"invalid operator action committed"
        plan={"code":"starter","version":1,"name":"Starter fixture","max_active_devices":2,"max_retained_devices":4,
              "max_mappings":3,"max_bandwidth_bps":1000000,"max_monthly_bytes":100000000,"max_concurrent_connections":5}
        pid=success("--commercial-create-plan",plan)
        reject("--commercial-create-plan",plan)
        reject("--commercial-create-plan",{**plan,"version":2,"max_retained_devices":1})
        reject("--commercial-create-plan",{**plan,"version":2,"max_monthly_bytes":0})
        next_pid=success("--commercial-create-plan",{**plan,"version":2,"max_mappings":5})
        with sqlite3.connect(db_path) as db:
            try: db.execute("UPDATE commercial_plans SET max_mappings=99 WHERE id=?",(pid,))
            except sqlite3.IntegrityError: pass
            else: raise AssertionError("published policy mutated")
            try: db.execute("DELETE FROM commercial_plans WHERE id=?",(pid,))
            except sqlite3.IntegrityError: pass
            else: raise AssertionError("published plan deleted")
            assert db.execute("SELECT max_mappings FROM commercial_plans WHERE id=?",(pid,)).fetchone()==(3,)
        report["real_operator_versioned_immutable_plan_creation"]=True
        account={"username":"customer01","password":customer_password,"plan_id":pid,"expires_at":None}
        reject("--commercial-create-account",{**account,"plan_id":"f"*32})
        reject("--commercial-create-account",{**account,"role":"admin"})
        reject("--commercial-create-account",{**account,"password":"short"})
        tenant=success("--commercial-create-account",account)
        reject("--commercial-create-account",{**account,"username":"CUSTOMER01"})
        with sqlite3.connect(db_path) as db:
            assert db.execute("SELECT count(*) FROM users").fetchone()==(2,)
            phc=db.execute("SELECT password_hash FROM users WHERE username='customer01'").fetchone()[0]
            assert phc.startswith("$argon2id$") and customer_password not in phc
            assert db.execute("SELECT plan_id,revision FROM tenant_entitlements WHERE tenant_id=?",(tenant,)).fetchone()==(pid,1)
        report["real_operator_atomic_account_and_plan_assignment"]=True
        p,base=launch(root)
        try:
            admin=call(base,"/api/v1/auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            customer=call(base,"/api/v1/auth/login",200,"POST",data={"username":"customer01","password":customer_password})["access_token"]
            route="/api/v1/commercial/entitlement"
            own=call(base,route,200,token=customer)["entitlement"]
            assert own["tenant_id"]==tenant and own["plan_id"]==pid and own["max_mappings"]==3
            assert call(base,route,200,token=admin)["entitlement"]["tenant_id"]!=tenant
            call(base,route,405,"POST",customer,{"plan_id":next_pid})
            call(base,route,405,"PATCH",customer,{"plan_id":next_pid})
            report["real_created_account_login_and_no_http_policy_mutation"]=True
            # A tenant session is never a global commercial operator.
            # Attempt explicit foreign selectors and every common mutation
            # verb; compare persisted policy and audit rows before/after.
            foreign=call(base,route,200,token=admin)["entitlement"]
            with sqlite3.connect(db_path) as db:
                snapshot={t:rows(db,t) for t in ("commercial_plans","tenant_entitlements","commercial_operator_audit","management_audit")}
            for token,expected,other_id in ((customer,own,foreign["tenant_id"]),(admin,foreign,tenant)):
                for query in ("?tenant_id="+other_id,"?owner_id="+other_id,"?plan_id="+next_pid):
                    assert call(base,route+query,200,token=token)["entitlement"]==expected
                for verb in ("POST","PUT","PATCH","DELETE"):
                    call(base,route,405,verb,token,{"tenant_id":other_id,"plan_id":next_pid,"state":"active","expected_revision":1})
                for resource in ("plans","accounts","tenants","assign","operator-audit"):
                    call(base,"/api/v1/commercial/"+resource,404,token=token)
                    call(base,"/api/v1/commercial/"+resource,404,"POST",token,{"tenant_id":other_id,"plan_id":next_pid})
            with sqlite3.connect(db_path) as db:
                assert {t:rows(db,t) for t in snapshot}==snapshot
            report["real_commercial_foreign_selectors_and_operator_http_boundary"]=True
            spec={"tenant_id":tenant,"plan_id":next_pid,"expected_revision":1,"state":"active","expires_at":1}
            reject("--commercial-assign",{**spec,"expected_revision":2})
            reject("--commercial-assign",{**spec,"plan_id":"f"*32})
            assert success("--commercial-assign",spec)==tenant
            expired=call(base,route,200,token=customer)["entitlement"]
            assert expired["revision"]==2 and expired["plan_id"]==next_pid and expired["effective_state"]=="expired"
            reject("--commercial-assign",spec)
            renewal={**spec,"expected_revision":2,"expires_at":None}
            with ThreadPoolExecutor(max_workers=2) as executor:
                results=list(executor.map(lambda value:command("--commercial-assign",value),[renewal,{**renewal,"state":"suspended"}]))
            assert sum(result.returncode==0 for result in results)==1,"concurrent revision check failed"
            current=call(base,route,200,token=customer)["entitlement"]
            assert current["revision"]==3 and current["state"] in ("active","suspended") and current["expires_at"] is None
            assert success("--commercial-assign",{**renewal,"expected_revision":3})==tenant
            assert call(base,route,200,token=customer)["entitlement"]["effective_state"]=="active"
            report["real_assignment_optimistic_concurrency_expiry_and_renewal"]=True
            with sqlite3.connect(db_path) as db:
                audit=db.execute("SELECT event,tenant_id,plan_id,revision,state,expires_at FROM commercial_operator_audit ORDER BY seq").fetchall()
                assert len(audit)==6
                assert audit[:3]==[("plan.created",None,pid,1,None,None),("plan.created",None,next_pid,2,None,None),("account.created",tenant,pid,1,"active",None)]
                assert [row[3] for row in audit[3:]]==[2,3,4]
                assert all(row[0]=="entitlement.assigned" and row[1]==tenant and row[2]==next_pid for row in audit[3:])
                assert customer_password not in repr(audit)
            owner_audit=call(base,"/api/v1/audit",200,token=customer)["events"]
            assert sorted(e["revision"] for e in owner_audit if e["event"]=="commercial.entitlement_assigned")==[2,3,4]
            assert any(e["event"]=="commercial.account_created" for e in owner_audit)
            assert not any(e["event"].startswith("commercial.") for e in call(base,"/api/v1/audit",200,token=admin)["events"])
            report["real_committed_operator_audit_and_owner_isolation"]=True
            # Use real operator assignment and HTTP writes on the same live DB.
            def assign_policy(revision,state="active",expires_at=None):
                assert success("--commercial-assign",{"tenant_id":tenant,"plan_id":pid,"expected_revision":revision,"state":state,"expires_at":expires_at})==tenant
            assign_policy(4)
            view=call(base,route,200,token=customer)
            assert view["commercial_enforcement"] is False
            assert set(view["enforced_admission"])=={"active_devices","retained_devices","mappings","active_entitlement_for_creation"}
            def issue(token):
                return call(base,"/api/v1/devices/pairing-code",200,"POST",token)["pairing_code"]
            def enroll(code,status=201):
                return call(base,"/api/v1/devices/enroll",status,"POST",data={"pairing_code":code,"name":"quota fixture"})
            def revoke(device):
                call(base,"/api/v1/devices/"+device["id"]+"/revoke",204,"POST",customer)
            d1=enroll(issue(customer))
            d2=enroll(issue(customer))
            pending=issue(customer)
            enroll(pending,409)
            revoke(d1)
            d3=enroll(pending)
            own=call(base,route,200,token=customer)["entitlement"]
            assert (own["active_devices"],own["retained_devices"])==(2,3)
            report["real_dynamic_active_device_quota_and_pairing_retry"]=True
            # Create a node via the existing trusted CLI, not a mocked API.
            node=subprocess.run([exe,"--add-node",str(root),"quota relay"],capture_output=True,timeout=20)
            assert node.returncode==0
            node_id=node.stdout.decode().strip()
            def spec(device,port):
                return {"device_id":device["id"],"node_id":node_id,"protocol":"udp","local_port":5353,"bind_port":port}
            def create_mapping(data,status=201,token=customer):
                return call(base,"/api/v1/mappings",status,"POST",token,data)
            def remove_mapping(item):
                call(base,"/api/v1/mappings/"+item["id"]+"?expected_revision="+str(item["revision"]),204,"DELETE",customer)
            requests=[spec(d2 if i%2==0 else d3,20010+i) for i in range(4)]
            with ThreadPoolExecutor(max_workers=4) as executor:
                results=list(executor.map(lambda data:create_mapping(data,(201,409)),requests))
            assert sorted(code for code,_ in results)==[201,201,201,409]
            items=[item for code,item in results if code==201]
            failed=requests[next(i for i,(code,_) in enumerate(results) if code==409)]
            assert call(base,route,200,token=customer)["entitlement"]["mappings"]==3
            # Other owner's inventory is not charged to this tenant.
            other_device=enroll(issue(admin))
            other_mapping=create_mapping(spec(other_device,20020),201,admin)
            assert other_mapping["device_id"]==other_device["id"]
            create_mapping(spec(other_device,20021),409)
            remove_mapping(items.pop())
            items.append(create_mapping(failed))
            assert call(base,route,200,token=customer)["entitlement"]["mappings"]==3
            report["real_concurrent_tenant_mapping_quota_and_owner_isolation"]=True
            # Free capacity before testing policy state, so the rejection
            # cannot be attributed to a full quota or occupied relay port.
            for item in items: remove_mapping(item)
            revoke(d2)
            pending=issue(customer)
            assign_policy(5,expires_at=1)
            enroll(pending,409)
            create_mapping(spec(d3,20030),409)
            assert call(base,route,200,token=customer)["entitlement"]["effective_state"]=="expired"
            assign_policy(6,state="suspended")
            enroll(pending,409)
            create_mapping(spec(d3,20030),409)
            assert call(base,route,200,token=customer)["entitlement"]["effective_state"]=="suspended"
            assign_policy(7)
            d4=enroll(pending)
            restored=create_mapping(spec(d3,20030))
            assert restored["enabled"] is False
            report["real_expiry_suspension_and_renewal_admission"]=True
            # Revoked rows still count toward the retained quota. Two
            # simultaneous retries must fail without consuming the code.
            revoke(d4)
            final_code=issue(customer)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results=list(executor.map(lambda _:enroll(final_code,(201,409)),range(2)))
            assert [code for code,_ in results]==[409,409]
            with sqlite3.connect(db_path) as db:
                owner=db.execute("SELECT owner_id FROM tenants WHERE id=?",(tenant,)).fetchone()[0]
                assert db.execute("SELECT count(*),sum(enabled) FROM devices WHERE owner_id=?",(owner,)).fetchone()==(4,1)
                assert db.execute("SELECT code_digest FROM device_pairings WHERE owner_id=?",(owner,)).fetchone()==(hashlib.sha256(final_code.encode()).digest(),)
            # Keep cleanup reachable even with an expired entitlement.
            assign_policy(8,expires_at=1)
            remove_mapping(restored)
            revoke(d3)
            own=call(base,route,200,token=customer)["entitlement"]
            assert (own["active_devices"],own["retained_devices"],own["mappings"])==(0,4,0)
            report["real_retained_quota_concurrency_and_expired_cleanup"]=True
        finally: stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==15 and all(value is True for value in report.values())
