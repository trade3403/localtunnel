"""Real multi-node conservative quota reservations."""
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
        plan=cmd(root,"--commercial-create-plan",data={"code":"distributed-preview","version":1,"name":"Distributed preview",
            "max_active_devices":4,"max_retained_devices":8,"max_mappings":16,"max_bandwidth_bps":1048576,
            "max_monthly_bytes":100000,"max_concurrent_connections":4})
        for name in ("budget","other"):
            cmd(root,"--commercial-create-account",data={"username":name,"password":password,"plan_id":plan,"expires_at":None})
        nodes=[cmd(root,"--add-node","budget relay "+str(i)) for i in range(2)]
        tokens=[cmd(root,"--relay-issue",n) for n in nodes]
        for n in nodes:cmd(root,"--set-node-policy",n,1,8,"east","active")
        p,base=launch(root)
        try:
            owner=login(base,"budget");other=login(base,"other")
            did=device(base,owner);oid=device(base,other)
            ent=call(base,"commercial/entitlement",200,owner)[1]["entitlement"]
            def beat():
                for token in tokens:
                    call(base,"relay/heartbeat",204,token,"POST",{"protocol_version":1,"generation":1,"capacity":8})
            def alloc(i,port,kind="tcp",token=owner,dev=did):
                beat()
                return call(base,"allocations",201,token,"POST",dict(request_key=secrets.token_hex(16),device_id=dev,
                    protocol=kind,local_port=8080,bind_port=port,node_id=nodes[i]))[1]
            a,b=alloc(0,20000),alloc(1,20001,"udp")
            spec=dict(expected_generation=1,expected_mapping_revision=1,expected_entitlement_revision=ent["revision"],
                rate_bytes_per_second=131072,monthly_bytes=60000,connection_slots=3)
            def reserve(item,status=201,token=owner,data=spec):
                return call(base,"allocations/"+item["id"]+"/budget-preview",status,token,"POST",data)
            reserve(a,409,other);reserve(a,401,tokens[0])
            reserve(a,409,data=dict(spec,expected_entitlement_revision=ent["revision"]+1))
            reserve(a,400,data=dict(spec,connection_slots=0))
            with ThreadPoolExecutor(max_workers=2) as workers:
                result=list(workers.map(lambda item:reserve(item,(201,409)),(a,b)))
            assert sorted(code for code,_ in result)==[201,409]
            winner,loser=(a,b) if result[0][0]==201 else (b,a)
            row=next(r for code,r in result if code==201)
            assert row["scope"]=="reservation_preview_only" and row["executable"] is False
            assert row["budget"]["node_id"]==winner["node_id"]
            reserve(winner,409)
            call(base,"allocations/"+winner["id"]+"/budget-preview",200,owner)
            call(base,"allocations/"+winner["id"]+"/budget-preview",404,other)
            # Test each independent cap; the winning reservation consumes all bandwidth.
            reserve(loser,409,data=dict(spec,rate_bytes_per_second=65536,monthly_bytes=1,connection_slots=1))
            call(base,"allocations/"+winner["id"]+"/grant",409,owner,"POST",{"expected_generation":1,"expected_mapping_revision":1})
            call(base,"allocations/"+winner["id"]+"/cancel",409,owner,"POST",{"expected_generation":1})
            independent=alloc(1,20002,token=other,dev=oid)
            other_ent=call(base,"commercial/entitlement",200,other)[1]["entitlement"]
            reserve(independent,201,other,dict(spec,expected_entitlement_revision=other_ent["revision"],rate_bytes_per_second=65536,monthly_bytes=40000,connection_slots=2))
            report["real_cross_node_budget_atomic_race_and_owner_isolation"]=True
            # The independent tenant has room for one rate slice but not an
            # excessive monthly or connection reservation.
            second=alloc(0,20003,token=other,dev=oid)
            small=dict(spec,expected_entitlement_revision=other_ent["revision"],rate_bytes_per_second=65536,monthly_bytes=60000,connection_slots=2)
            reserve(second,409,other,dict(small,monthly_bytes=60001))
            reserve(second,409,other,dict(small,connection_slots=3))
            reserve(second,201,other,small)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert sorted(db.execute("SELECT sum(rate_bytes_per_second),sum(monthly_bytes),sum(connection_slots) FROM relay_budget_previews GROUP BY tenant_id").fetchall())==[(131072,60000,3),(131072,100000,4)]
                assert db.execute("SELECT count(*) FROM relay_grants").fetchone()==(0,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='budget.preview_reserved'").fetchone()==(3,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
                for sql in ("DELETE FROM relay_budget_previews","UPDATE relay_budget_previews SET monthly_bytes=1"):
                    try:db.execute(sql);raise AssertionError("mutable budget")
                    except sqlite3.IntegrityError:db.rollback()
            report["real_cross_node_budget_independent_caps_and_immutable_non_executable_ledger"]=True
            # Two separate finite TCP allocations on different nodes can
            # observe only their own reserved slices; no old grant can run.
            beat()
            def issue(item,token=other,status=201):
                return call(base,"allocations/"+item["id"]+"/budget-grant",status,token,"POST",dict(
                    expected_generation=1,expected_mapping_revision=1,expected_entitlement_revision=other_ent["revision"]))
            issue(independent,owner,409)
            with ThreadPoolExecutor(max_workers=2) as workers:
                answers=list(workers.map(lambda _:issue(independent,status=(201,409)),range(2)))
            assert sorted(code for code,_ in answers)==[201,409]
            g=next(r["grant"] for code,r in answers if code==201)
            h=issue(second)[1]["grant"]
            assert g["rate_bytes_per_second"]==h["rate_bytes_per_second"]==65536 and g["monthly_bytes"]==40000 and h["monthly_bytes"]==60000
            def observe(g,status=200,token=None,**changes):
                payload={k:g[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")}
                payload.update(protocol_version=1,grant_id=g["id"],nonce=secrets.token_hex(16));payload.update(changes)
                return call(base,"relay/budget-grant",status,token or tokens[nodes.index(g["node_id"])],"POST",payload)[1]
            r=observe(g)
            assert r["scope"]=="budget_authorization_preview_only" and r["executable"] is False and r["grant"]["connection_slots"]==2
            observe(h)
            observe(g,401,tokens[0]);observe(g,401,other);observe(g,401,mapping_revision=2)
            call(base,"allocations/"+independent["id"]+"/grant",409,other,"POST",{"expected_generation":1,"expected_mapping_revision":1})
            payload={k:g[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")}
            payload.update(protocol_version=1,grant_id=g["id"],relay_port=31000,nonce=secrets.token_hex(16))
            call(base,"relay/tcp-claim",401,tokens[1],"POST",payload)
            def intent(g,status=201,token=other,port=31000,guarded=False):
                return call(base,"allocations/"+g["allocation_id"]+("/budget-run-intent" if guarded else "/budget-intent"),status,token,"POST",
                            dict(grant_id=g["id"],expected_generation=2,relay_port=port))[1]
            def claim(g,status=200,token=None,port=31000,guarded=False):
                payload={k:g[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")}
                payload.update(protocol_version=1,grant_id=g["id"],relay_port=port,nonce=secrets.token_hex(16))
                code,row=call(base,"relay/budget-run-claim" if guarded else "relay/budget-claim",status,token or tokens[nodes.index(g["node_id"])],"POST",payload)
                if row:
                    assert row["nonce"]==payload["nonce"] and row["scope"]==("budget_guarded_claim_preview_only" if guarded else "budget_claim_preview_only") and row["executable"] is False
                    assert row["grant"]["id"]==g["id"] and row["intent"]["relay_port"]==port and row["intent"]["claimed_at"] is not None
                return code
            claim(g,401)
            intent(g,409,owner)
            assert intent(g)["executable"] is False
            intent(g,409)
            intent(g,409,guarded=True)
            intent(h,409,owner,guarded=True)
            r=intent(h,guarded=True)
            assert r["scope"]=="budget_guarded_intent_preview_only" and r["executable"] is False
            intent(h,409)
            claim(g,401,guarded=True);claim(h,401)
            claim(g,401,tokens[0]);claim(g,401,port=31001)
            with ThreadPoolExecutor(max_workers=2) as workers:
                assert sorted(workers.map(lambda _:claim(g,(200,401)),range(2)))==[200,401]
            claim(g,401)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_budget_intents WHERE claimed_at IS NOT NULL").fetchone()==(1,)
                for sql in ("UPDATE relay_budget_intents SET claimed_at=NULL WHERE claimed_at IS NOT NULL","DELETE FROM relay_budget_intents"):
                    try:db.execute(sql);raise AssertionError("mutable intent")
                    except sqlite3.IntegrityError:db.rollback()
            report["real_finite_budget_one_shot_claim_and_replay_rejection"]=True
            cmd(root,"--set-node-policy",nodes[1],2,8,"east","maintenance")
            observe(g,401);observe(h)
            claim(g,401);claim(h,401)
            claim(h,401,tokens[1],guarded=True)
            claim(h,guarded=True);claim(h,401,guarded=True)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_budget_grants").fetchone()==(2,)
                assert sorted(db.execute("SELECT intent_mode,claimed_at IS NOT NULL FROM relay_budget_intents").fetchall())==[("guarded_tcp",1),("observe",1)]
                # Direct SQL cannot promote a recorded observation either.
                try:db.execute("UPDATE relay_budget_intents SET intent_mode='guarded_tcp' WHERE intent_mode='observe'");raise AssertionError("mutable mode")
                except sqlite3.IntegrityError:db.rollback()
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='budget.run_claim_preview'").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM relay_grants").fetchone()==(0,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_finite_budget_grant_exact_node_slice_and_legacy_isolation"]=True
            report["real_guarded_intent_explicit_opt_in_and_claim_mode_isolation"]=True
            # No finite slice is refunded or port released by expiry fencing.
            deadline=time.monotonic()+20
            while time.time()<g["expires_at"]+2:
                assert time.monotonic()<deadline
                time.sleep(.1)
            route="allocations/"+g["allocation_id"]
            data=dict(expected_generation=2,grant_id=g["id"])
            call(base,route+"/fence",404,owner,"POST",data)
            row=call(base,route+"/fence",201,other,"POST",data)[1]
            assert row["fence"]["grant_kind"]=="finite" and row["fence"]["new_generation"]==3
            assert row["resources_released"] is False and row["executable"] is False
            assert call(base,route+"/fence",200,other,"POST",data)[1]==row
            call(base,route+"/cancel",409,other,"POST",dict(expected_generation=3))
            observe(g,401);claim(g,401)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_budget_previews").fetchone()==(3,)
                assert db.execute("SELECT count(*) FROM relay_budget_intents").fetchone()==(2,)
                assert db.execute("SELECT generation,state FROM relay_allocations WHERE id=?",(g["allocation_id"],)).fetchone()==(3,"reserved")
            report["real_finite_expiry_fence_retains_budget_and_ports"]=True
        finally:stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==6 and all(report.values())
