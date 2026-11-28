"""Real CLI, HTTP, SQLite node identity lifecycle; no fake API."""
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
report={}
password=secrets.token_hex(24)
route="/api/v1/relay/identity"

try:
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        def command(action,*args,data=None,ok=True):
            result=subprocess.run([exe,action,str(root),*map(str,args)],input=None if data is None else json.dumps(data),text=True,capture_output=True,timeout=20)
            assert (result.returncode==0)==ok,"operator result mismatch"
            if not ok: assert not result.stdout.strip(),"failed operator command disclosed output"
            return result.stdout.strip()
        command("--init-admin",data={"username":"owner","password":password})
        a=command("--add-node","relay A")
        b=command("--add-node","relay B")
        db_path=root/"control.sqlite3"
        with sqlite3.connect(db_path) as db:
            assert db.execute("SELECT count(*) FROM relay_identities").fetchone()==(0,)
        p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(p.stdout,selectors.EVENT_READ)
                assert sel.select(20),"startup timeout"
            line=p.stdout.readline().strip()
            assert line.startswith("LISTENING 127.0.0.1:")
            base="http://"+line.split()[1]
            def call(path,status,token=None,method="GET",data=None):
                headers={}
                if token is not None: headers["Authorization"]="Bearer "+token
                if data is not None: headers["Content-Type"]="application/json"
                req=urllib.request.Request(base+path,headers=headers,method=method,data=None if data is None else json.dumps(data).encode())
                try:
                    with urllib.request.urlopen(req,timeout=10) as response:
                        assert response.status==status,"unexpected success status"
                        assert "no-store" in response.headers.get("Cache-Control","")
                        raw=response.read()
                        return json.loads(raw) if raw else None
                except urllib.error.HTTPError as error:
                    assert error.code==status,f"{method} {path}: unexpected status {error.code}"
            owner=call("/api/v1/auth/login",200,method="POST",data={"username":"owner","password":password})["access_token"]
            call(route,401)
            call(route,401,owner)
            call(route,401,"ltrelay_"+secrets.token_hex(32))
            command("--relay-issue","absent",ok=False)
            first=command("--relay-issue",a)
            second=command("--relay-issue",b)
            assert first.startswith("ltrelay_") and len(first)==72 and first!=second
            command("--relay-issue",a,ok=False)
            assert call(route,200,first)=={"node_id":a,"generation":1}
            assert call(route+"?node_id="+b,200,first)=={"node_id":a,"generation":1}
            assert call(route,200,second)=={"node_id":b,"generation":1}
            for path in ("/api/v1/nodes","/api/v1/commercial/entitlement","/api/v1/audit","/api/v1/mappings"):
                call(path,401,first)
            call(route,405,first,"POST",{"node_id":b})
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT token_digest FROM relay_identities WHERE node_id=?",(a,)).fetchone()==(hashlib.sha256(bytes.fromhex(first[8:])).digest(),)
                assert db.execute("SELECT count(*) FROM relay_identity_audit").fetchone()==(2,)
            report["real_independent_relay_identity_and_tenant_boundary"]=True
            command("--relay-rotate",a,0,ok=False)
            command("--relay-rotate",a,2,ok=False)
            def rotate(_):
                return subprocess.run([exe,"--relay-rotate",str(root),a,"1"],capture_output=True,text=True,timeout=20)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                results=list(workers.map(rotate,range(2)))
            assert sum(x.returncode==0 for x in results)==1
            assert all(not x.stdout.strip() for x in results if x.returncode!=0)
            rotated=next(x.stdout.strip() for x in results if x.returncode==0)
            call(route,401,first)
            assert call(route,200,rotated)=={"node_id":a,"generation":2}
            command("--relay-revoke",a,2)
            call(route,401,rotated)
            command("--relay-revoke",a,3,ok=False)
            third=command("--relay-rotate",a,3)
            assert call(route,200,third)=={"node_id":a,"generation":4}
            assert call(route,200,second)=={"node_id":b,"generation":1}
            report["real_relay_generation_rotation_and_revocation"]=True
            command("--set-node-enabled",a,"false")
            call(route,401,third)
            command("--relay-rotate",a,5,ok=False)
            command("--set-node-enabled",a,"true")
            call(route,401,third)
            fresh=command("--relay-rotate",a,5)
            assert call(route,200,fresh)=={"node_id":a,"generation":6}
            with sqlite3.connect(db_path) as db:
                audit=db.execute("SELECT generation,event FROM relay_identity_audit WHERE node_id=? ORDER BY seq",(a,)).fetchall()
                assert audit==[(1,"issued"),(2,"rotated"),(3,"revoked"),(4,"rotated"),(5,"disabled"),(6,"rotated")]
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_relay_disable_no_resurrection_and_audit"]=True
            heartbeat="/api/v1/relay/heartbeat"
            def beat(token,generation,capacity,status=204,**extra):
                call(heartbeat,status,token,"POST",{"protocol_version":1,"generation":generation,"capacity":capacity,**extra})
            assert call(heartbeat,200,fresh)=={"node_id":a,"generation":6,"received_at":None,"capacity":None,"fresh":False}
            call(heartbeat,401,owner)
            beat(owner,6,1,401)
            beat(third,4,1,401)
            beat(fresh,5,1,401)
            beat(fresh,6,65537,400)
            beat(fresh,6,1,422,node_id=b)
            before=int(time.time())
            beat(fresh,6,17)
            beat(second,1,4)
            health=call(heartbeat,200,fresh)
            assert health["node_id"]==a and health["generation"]==6 and health["capacity"]==17 and health["fresh"] is True
            assert before<=health["received_at"]<=int(time.time())
            assert call(heartbeat,200,second)["capacity"]==4
            # Wait for actual server clock expiry, not a modified database time.
            deadline=time.monotonic()+22
            while call(heartbeat,200,fresh)["fresh"]:
                assert time.monotonic()<deadline,"heartbeat freshness did not expire"
                time.sleep(.25)
            beat(fresh,6,18)
            assert call(heartbeat,200,fresh)["fresh"] is True
            final=command("--relay-rotate",a,6)
            assert call(heartbeat,200,final)=={"node_id":a,"generation":7,"received_at":None,"capacity":None,"fresh":False}
            beat(fresh,6,99,401)
            beat(final,7,8)
            assert call(heartbeat,200,final)["capacity"]==8
            command("--relay-revoke",a,7)
            call(heartbeat,401,final)
            beat(final,7,100,401)
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT generation,capacity FROM relay_heartbeat WHERE node_id=?",(a,)).fetchone()==(7,8)
            report["real_relay_heartbeat_freshness_generation_and_isolation"]=True
        finally:
            p.terminate()
            try:p.communicate(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=5)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==4 and all(report.values())
