"""Actual CLI + HTTP device registration, ownership and revocation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
import re
import socket
import time
import os
import socketserver
import struct
import threading
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
    if status in (200,201,202):
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
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,LOCALTUNNEL_DNS_RESOLVER=resolver))
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


# Real DNS-over-TCP fixture with bounded message framing. No verification
# bypass or injected success in the product. Only this disposable resolver
# is configured by the test operator.
records={}
queries=[]
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        def read(n):
            b=b""
            while len(b)<n:
                part=self.request.recv(n-len(b))
                if not part:
                    raise EOFError()
                b+=part
            return b
        self.request.settimeout(4)
        raw=read(struct.unpack("!H",read(2))[0])
        pos=12
        labels=[]
        while raw[pos]:
            n=raw[pos]
            pos+=1
            labels.append(raw[pos:pos+n].decode("ascii"))
            pos+=n
        pos+=1
        assert raw[pos:pos+4]==b"\x00\x10\x00\x01"
        qname=".".join(labels)+"."
        queries.append(qname)
        value=records.get(qname)
        question=raw[12:pos+4]
        answer=b""
        if value is not None:
            txt=value.encode("ascii")
            data=bytes([len(txt)])+txt
            answer=b"\xc0\x0c"+struct.pack("!HHIH",16,1,30,len(data))+data
        response=raw[:2]+struct.pack("!HHHHH",0x8180,1,int(bool(answer)),0,0)+question+answer
        self.request.sendall(struct.pack("!H",len(response))+response)


# Reuse pinned upstream download helper from the existing core E2E.
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tests"))
import e2e as core_test
core=core_test.CLI.resolve()

def request(port,hostname):
    try:
        conn=http.client.HTTPConnection("127.0.0.1",port,timeout=2)
        try:
            conn.request("GET","/",headers={"Host":hostname,"Connection":"close"})
            r=conn.getresponse()
            return r.status,r.read()
        finally:
            conn.close()
    except (OSError,http.client.HTTPException):
        return None

def await_body(port,hostname,expected,processes):
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        assert all(p.poll() is None for p in processes),"preview process exited"
        if request(port,hostname)==expected:
            return
        time.sleep(.25)
    raise AssertionError("preview traffic did not converge")

try:
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),Handler) as dns,tempfile.TemporaryDirectory() as directory:
        dns.daemon_threads=True
        worker=threading.Thread(target=dns.serve_forever,daemon=True)
        worker.start()
        processes=[]
        fixture=None
        try:
            resolver="127.0.0.1:"+str(dns.server_address[1])
            root=Path(directory)
            db_path=root/"control.sqlite3"
            body=secrets.token_hex(24).encode()
            probe_requests=[]
            class Web(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    probe_requests.append(self.headers.get("Host"))
                    self.send_response(200)
                    self.send_header("Content-Length",str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                def log_message(self,*args):
                    pass
            fixture=http.server.ThreadingHTTPServer(("127.0.0.1",0),Web)
            threading.Thread(target=fixture.serve_forever,daemon=True).start()
            engine=core_test.engine(root)
            keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
            private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
            public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
            env=dict(os.environ,LOCALTUNNEL_CORE_CLI=str(core),LOCALTUNNEL_SERVER_PRIVATE_KEY=private,LOCALTUNNEL_SERVER_PUBLIC_KEY=public,LOCALTUNNEL_ENGINE=str(engine))
            def operator(*args):
                return subprocess.run([exe,args[0],str(root),*map(str,args[1:])],env=env,capture_output=True,timeout=40)
            assert subprocess.run([exe,"--init-admin",str(root)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20).returncode==0
            node=operator("--add-node","preview relay")
            assert node.returncode==0
            nid=node.stdout.decode().strip()
            p,base=launch(root)
            try:
                admin=login(base,"operator")
                device=expect(enroll(base,issue(base,admin)),201)
                domain=expect(call(base,"domains","POST",admin,{"hostname":"preview.example.test"}),201)
                # Reserve a relay port from the allowed internal range.
                for bp in range(24000,25000):
                    with socket.socket() as s:
                        try:
                            s.bind(("127.0.0.1",bp))
                            break
                        except OSError:
                            continue
                else:
                    raise AssertionError("no free internal port")
                mapping=expect(call(base,"mappings","POST",admin,{"device_id":device["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"http","local_port":fixture.server_port,"bind_port":bp}),201)
                mid=mapping["id"]
                rp=core_test.port()
                gp=core_test.port()
                while gp in (rp,bp,fixture.server_port) or rp in (bp,fixture.server_port):
                    rp,gp=core_test.port(),core_test.port()
                assert operator("--export-preview",mid,1,rp,"unverified").returncode!=0
                assert not (root/"unverified").exists()
                records[domain["txt_name"]+"."]=domain["txt_value"]
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
            finally:
                stop(p)
            # Operator preview deliberately runs with management API stopped.
            assert operator("--export-preview",mid,2,rp,"stale").returncode!=0
            assert operator("--export-preview",mid,1,rp,"../escape").returncode!=0
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE domains SET verified_at=unixepoch()-301 WHERE id=?",(domain["id"],))
            assert operator("--export-preview",mid,1,rp,"expired").returncode!=0
            # Obtain a new actual TXT observation, not an injected success.
            p,base=launch(root)
            try:
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
            finally:
                stop(p)
            assert operator("--export-preview",mid,1,rp,"bundle").returncode==0
            bundle=root/"bundle"
            assert bundle.stat().st_mode&0o077==0
            for name in ("server.toml","client.toml","manifest.json"):
                assert (bundle/name).stat().st_mode&0o077==0
            assert private not in (bundle/"client.toml").read_text()
            assert json.loads((bundle/"manifest.json").read_text())["revision"]==1
            original=(bundle/"server.toml").read_bytes()
            assert operator("--export-preview",mid,1,rp,"bundle").returncode!=0
            assert (bundle/"server.toml").read_bytes()==original
            report["eligible_revision_private_bundle"]=True
            for name in ("server.toml","client.toml"):
                processes.append(subprocess.Popen([str(engine),str(bundle/name)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            await_body(bp,"preview.example.test",(200,body),processes)
            report["actual_noise_tunnel_from_managed_draft"]=True
            prefix=root/"gateway"
            prefix.mkdir(mode=0o700)
            assert operator("--preview-gateway","clear",0,"gateway",gp,"init").returncode==0
            processes.append(subprocess.Popen(["/usr/sbin/nginx","-p",str(prefix)+"/","-c",str(prefix/"nginx.conf"),"-g","daemon off;"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                r=request(gp,"preview.example.test")
                if r is not None and r[0]==421:
                    break
                time.sleep(.2)
            else:
                raise AssertionError("empty gateway unavailable")
            expected=root/"expected_body"
            expected.write_bytes(b"intentionally wrong expected body")
            expected.chmod(0o600)
            initial=(prefix/"nginx.conf").read_bytes()
            prior=len(probe_requests)
            # Candidate really becomes live before the HTTP body check fails.
            assert operator("--preview-gateway",mid,1,"gateway",gp,"apply-checked","expected_body").returncode!=0
            assert "preview.example.test" in probe_requests[prior:], "candidate was not actually probed"
            assert (prefix/"nginx.conf").read_bytes()==initial
            assert request(gp,"preview.example.test")[0]==421
            assert not (prefix/"nginx.previous.conf").exists()
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT outcome FROM preview_attempts WHERE mapping_id=? AND operation='apply-checked'",(mid,)).fetchall()==[("failed_or_unknown",)]
            report["real_post_reload_business_probe_failure_and_rollback"]=True
            expected.write_bytes(body)
            assert operator("--preview-gateway",mid,1,"gateway",gp,"apply-checked","expected_body").returncode==0
            await_body(gp,"preview.example.test",(200,body),processes)
            assert request(gp,"wrong.example.test")[0]==421
            old=(prefix/"nginx.conf").read_bytes()
            # Real failed apply due to existing recovery evidence. It must
            # preserve the prior live revision, not fake a reload rollback.
            backup=prefix/"nginx.previous.conf"
            backup.write_bytes(old)
            assert operator("--preview-gateway","clear",0,"gateway",gp,"apply").returncode!=0
            assert (prefix/"nginx.conf").read_bytes()==old
            assert backup.read_bytes()==old
            await_body(gp,"preview.example.test",(200,body),processes)
            backup.unlink()
            report["actual_gateway_apply_and_failed_apply_preserves_live_route"]=True
            p,base=launch(root)
            try:
                expect(call(base,"devices/"+device["id"]+"/revoke","POST",admin),204)
            finally:
                stop(p)
            assert operator("--preview-gateway",mid,1,"gateway",gp,"apply-checked","expected_body").returncode!=0
            # Explicit cleanup remains possible after revocation.
            assert operator("--preview-gateway","clear",0,"gateway",gp,"apply").returncode==0
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                r=request(gp,"preview.example.test")
                if r is not None and r[0]==421:
                    break
                time.sleep(.2)
            else:
                raise AssertionError("cleared gateway still exposed route")
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT enabled,revision FROM mappings WHERE id=?",(mid,)).fetchone()==(0,1)
                rows=db.execute("SELECT operation,outcome,count(*) FROM preview_attempts GROUP BY operation,outcome ORDER BY operation,outcome").fetchall()
                assert rows==[("apply","failed_or_unknown",1),("apply","succeeded",1),("apply-checked","failed_or_unknown",1),("apply-checked","succeeded",1),("init","succeeded",1)]
                assert db.execute("SELECT count(*) FROM preview_attempts WHERE finished_at IS NULL").fetchone()==(0,)
            report["actual_route_removal_no_false_activation"]=True
            report["persistent_attempt_outcomes_and_revoked_apply_denied"]=True
            # Release the earlier manually owned processes before the
            # foreground supervisor starts its own independent tunnel pair.
            for proc in processes[:2]:
                stop(proc)
            processes=processes[2:]
            p,base=launch(root)
            supervisor=None
            try:
                expect(call(base,"mappings/"+mid+"?expected_revision=1","DELETE",admin),204)
                device2=expect(enroll(base,issue(base,admin)),201)
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                mapping2=expect(call(base,"mappings","POST",admin,{"device_id":device2["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"http","local_port":fixture.server_port,"bind_port":bp}),201)
                mid2=mapping2["id"]
                supervisor=subprocess.Popen([exe,"--supervise-preview",str(root),mid2,"1",str(rp),"supervised_bundle","gateway",str(gp),"expected_body"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                await_body(gp,"preview.example.test",(200,body),[*processes,supervisor])
                assert request(bp,"preview.example.test")== (200,body)
                assert (root/"supervisor-gateway.lock").exists()
                competing=operator("--supervise-preview",mid2,1,rp,"competing_bundle","gateway",gp,"expected_body")
                assert competing.returncode!=0 and not (root/"competing_bundle").exists()
                expect(call(base,"devices/"+device2["id"]+"/revoke","POST",admin),204)
                assert supervisor.wait(timeout=40)==0,"supervisor did not cleanly stop revoked tunnel"
                assert request(gp,"preview.example.test")[0]==421
                assert request(bp,"preview.example.test") is None
                assert not (root/"supervisor-gateway.lock").exists()
                with sqlite3.connect(db_path) as db:
                    assert db.execute("SELECT outcome FROM preview_attempts WHERE mapping_id=? AND operation='apply-checked'",(mid2,)).fetchall()==[("succeeded",)]
                    assert db.execute("SELECT enabled FROM devices WHERE id=?",(device2["id"],)).fetchone()==(0,)
                    assert db.execute("SELECT enabled FROM mappings WHERE id=?",(mid2,)).fetchone()==(0,)
                report["actual_supervised_tunnel_revocation_and_gateway_clear"]=True
                # Start/stop via API, with a fixed one-shot local worker.
                expect(call(base,"mappings/"+mid2+"?expected_revision=1","DELETE",admin),204)
                device3=expect(enroll(base,issue(base,admin)),201)
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                mapping3=expect(call(base,"mappings","POST",admin,{"device_id":device3["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"http","local_port":fixture.server_port,"bind_port":bp}),201)
                mid3=mapping3["id"]
                runtime_path="mappings/"+mid3
                with sqlite3.connect(db_path) as db:
                    phc=db.execute("SELECT password_hash FROM users WHERE username='operator'").fetchone()[0]
                    db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('other','otheradmin',?,'admin')",(phc,))
                other=login(base,"otheradmin")
                expect(call(base,runtime_path+"/runtime"),401)
                expect(call(base,runtime_path+"/runtime",token=other),404)
                expect(call(base,runtime_path+"/start","POST",other,{"expected_revision":1}),404)
                expect(call(base,runtime_path+"/start","POST",device3["device_token"],{"expected_revision":1}),401)
                expect(call(base,runtime_path+"/start","POST",admin,{"expected_revision":2}),409)
                expect(call(base,runtime_path+"/start","POST",admin,{"expected_revision":1,"command":"forbidden"}),422)
                assert expect(call(base,runtime_path+"/runtime",token=admin),200)["request"] is None
                queued=expect(call(base,runtime_path+"/start","POST",admin,{"expected_revision":1}),202)
                # No worker: request does not start any actual process.
                assert queued["state"]=="queued" and request(gp,"preview.example.test")[0]==421
                expect(call(base,runtime_path+"/start","POST",admin,{"expected_revision":1}),409)
                expect(call(base,runtime_path+"?expected_revision=1","DELETE",admin),409)
                expect(call(base,runtime_path,"PATCH",admin,{"expected_revision":1,"local_port":12345}),409)
                cancelled=expect(call(base,runtime_path+"/stop","POST",admin,{"request_id":queued["request_id"]}),202)
                assert cancelled["state"]=="stopped"
                queued=expect(call(base,runtime_path+"/start","POST",admin,{"expected_revision":1}),202)
                assert queued["request_id"]!=cancelled["request_id"]
                expect(call(base,runtime_path+"/stop","POST",admin,{"request_id":cancelled["request_id"]}),409)
                supervisor=subprocess.Popen([exe,"--runtime-worker",str(root),mid3,"1",str(rp),"runtime_bundle","gateway",str(gp),"expected_body"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                await_body(gp,"preview.example.test",(200,body),[*processes,supervisor])
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    state=expect(call(base,runtime_path+"/runtime",token=admin),200)
                    if state["request"]["state"]=="running" and state["worker_recent"]:
                        break
                    time.sleep(.2)
                else:
                    raise AssertionError("worker did not report running")
                expect(call(base,runtime_path+"/stop","POST",other,{"request_id":queued["request_id"]}),404)
                stopped=expect(call(base,runtime_path+"/stop","POST",admin,{"request_id":queued["request_id"]}),202)
                assert stopped["state"]=="stopping"
                assert supervisor.wait(timeout=40)==0
                final=expect(call(base,runtime_path+"/runtime",token=admin),200)
                assert final["request"]["state"]=="stopped" and not final["worker_recent"]
                assert request(gp,"preview.example.test")[0]==421 and request(bp,"preview.example.test") is None
                expect(call(base,runtime_path+"?expected_revision=1","DELETE",admin),204)
                report["api_start_stop_scoped_request_real_worker"]=True
            finally:
                # Test failure cleanup: revoke before waiting so that the
                # supervisor gets the opportunity to stop its own children.
                if supervisor is not None and supervisor.poll() is None:
                    try:
                        call(base,"devices/"+(device3 if "device3" in locals() else device2)["id"]+"/revoke","POST",admin)
                        supervisor.wait(timeout=40)
                    except (OSError,subprocess.TimeoutExpired):
                        stop(supervisor)
                stop(p)
        finally:
            for proc in reversed(processes):
                stop(proc)
            if fixture:
                fixture.shutdown()
                fixture.server_close()
            dns.shutdown()
            worker.join(timeout=5)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
