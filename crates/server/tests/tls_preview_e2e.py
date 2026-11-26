"""Actual CLI + HTTP device registration, ownership and revocation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
from tunnel_load_fixture import EchoFixture, transfer
import re
import socket
import ssl
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


def tls_request(port,host,ca,sni=None):
    ctx=ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(("127.0.0.1",port),timeout=3) as raw:
        with ctx.wrap_socket(raw,server_hostname=sni or host) as conn:
            conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            r=http.client.HTTPResponse(conn)
            r.begin()
            return r.status,r.read()

def rejects(port,host,ca):
    try:
        tls_request(port,host,ca)
    except (ssl.SSLError,ConnectionError):
        return
    raise AssertionError("unexpected TLS handshake")

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
            hostname="secure.example.test"
            probe_requests=[]
            class Web(EchoFixture, http.server.BaseHTTPRequestHandler):
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
            node=operator("--add-node","TLS relay")
            assert node.returncode==0
            nid=node.stdout.decode().strip()
            def cert(name,host):
                d=root/name
                d.mkdir(mode=0o700)
                subprocess.run(["/usr/bin/openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","3","-subj","/CN="+host,"-addext","subjectAltName=DNS:"+host,"-keyout",str(d/"key.pem"),"-out",str(d/"chain.pem")],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                (d/"ca.pem").write_bytes((d/"chain.pem").read_bytes())
                for path in d.iterdir():
                    path.chmod(0o600)
                return d/"ca.pem"
            ca=cert("cert_v1",hostname)
            ca2=cert("cert_v2",hostname)
            wrongca=cert("wrong_cert","wrong.example.test")
            p,base=launch(root)
            try:
                admin=login(base,"operator")
                device=expect(enroll(base,issue(base,admin)),201)
                domain=expect(call(base,"domains","POST",admin,{"hostname":hostname}),201)
                for bp in range(25000,26000):
                    with socket.socket() as s:
                        try:
                            s.bind(("127.0.0.1",bp))
                            break
                        except OSError:
                            continue
                else:
                    raise AssertionError("no free internal port")
                mapping=expect(call(base,"mappings","POST",admin,{"device_id":device["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"https","local_port":fixture.server_port,"bind_port":bp}),201)
                mid=mapping["id"]
                ports={bp,fixture.server_port}
                def unique_port():
                    while True:
                        candidate=core_test.port()
                        if candidate not in ports:
                            ports.add(candidate)
                            return candidate
                rp,gp,probe=unique_port(),unique_port(),unique_port()
                assert operator("--export-preview",mid,1,rp,"unverified").returncode!=0
                records[domain["txt_name"]+"."]=domain["txt_value"]
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
            finally:
                stop(p)
            assert operator("--export-preview",mid,1,rp,"tls_bundle").returncode==0
            bundle=root/"tls_bundle"
            assert json.loads((bundle/"manifest.json").read_text())["protocol"]=="https"
            for name in ("server.toml","client.toml"):
                processes.append(subprocess.Popen([str(engine),str(bundle/name)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            await_body(bp,hostname,(200,body),processes)
            prefix=root/"tls_gateway"
            prefix.mkdir(mode=0o700)
            expected=root/"expected_body"
            expected.write_bytes(body)
            expected.chmod(0o600)
            def apply(id,rev,certdir,mode,*rest):
                return operator("--preview-tls-gateway",id,rev,"tls_gateway",gp,probe,certdir,mode,*rest)
            assert apply("clear",0,"cert_v1","init").returncode==0
            processes.append(subprocess.Popen(["/usr/sbin/nginx","-p",str(prefix)+"/","-c",str(prefix/"nginx.conf"),"-g","daemon off;"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                r=request(probe,"localtunnel-probe.invalid")
                if r is not None and r[0]==421:
                    break
                time.sleep(.2)
            else:
                raise AssertionError("empty TLS gateway unavailable")
            rejects(gp,hostname,ca)
            # HTTPS draft may not be published through the HTTP apply path.
            assert operator("--preview-gateway",mid,1,"tls_gateway",gp,"apply-checked","expected_body").returncode!=0
            empty=(prefix/"nginx.conf").read_bytes()
            assert apply(mid,1,"wrong_cert","apply-checked","expected_body").returncode!=0
            assert (prefix/"nginx.conf").read_bytes()==empty
            rejects(gp,hostname,ca)
            assert apply(mid,1,"cert_v1","apply-checked","expected_body").returncode==0
            assert tls_request(gp,hostname,ca)==(200,body)
            rejects(gp,hostname,wrongca)
            rejects(gp,"wrong.example.test",ca)
            assert tls_request(gp,"wrong.example.test",ca,sni=hostname)[0]==421
            report["real_tls_certificate_and_noise_http_body"]=True
            report["https_tunnel_measurements"]=transfer(gp,hostname,processes,ca)
            assert tls_request(gp,hostname,ca)==(200,body)
            rejects(gp,hostname,wrongca)
            report["real_https_noise_concurrent_bidirectional_payload_integrity"]=True
            old=(prefix/"nginx.conf").read_bytes()
            expected.write_bytes(b"wrong expected response")
            prior=len(probe_requests)
            assert apply(mid,1,"cert_v2","apply-checked","expected_body").returncode!=0
            assert hostname in probe_requests[prior:]
            assert (prefix/"nginx.conf").read_bytes()==old
            assert tls_request(gp,hostname,ca)==(200,body)
            rejects(gp,hostname,ca2)
            expected.write_bytes(body)
            assert apply(mid,1,"cert_v2","apply-checked","expected_body").returncode==0
            assert tls_request(gp,hostname,ca2)==(200,body)
            rejects(gp,hostname,ca)
            report["tls_business_failure_restores_previous_certificate_and_route"]=True
            p,base=launch(root)
            try:
                expect(call(base,"devices/"+device["id"]+"/revoke","POST",admin),204)
            finally:
                stop(p)
            assert apply(mid,1,"cert_v2","apply-checked","expected_body").returncode!=0
            assert apply("clear",0,"cert_v2","apply").returncode==0
            rejects(gp,hostname,ca2)
            assert request(probe,"localtunnel-probe.invalid")[0]==421
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT enabled,revision FROM mappings WHERE id=?",(mid,)).fetchone()==(0,1)
                rows=db.execute("SELECT operation,outcome,count(*) FROM preview_attempts WHERE transport='https' GROUP BY operation,outcome ORDER BY operation,outcome").fetchall()
                assert rows==[("apply","succeeded",1),("apply-checked","failed_or_unknown",2),("apply-checked","succeeded",2),("init","succeeded",1)]
            report["revoked_apply_denied_and_explicit_tls_clear"]=True
            # Release manually owned children before starting the supervisor.
            for proc in processes[:2]:
                stop(proc)
            processes=processes[2:]
            p,base=launch(root)
            supervisor=None
            try:
                expect(call(base,"mappings/"+mid+"?expected_revision=1","DELETE",admin),204)
                device2=expect(enroll(base,issue(base,admin)),201)
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                mapping2=expect(call(base,"mappings","POST",admin,{"device_id":device2["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"https","local_port":fixture.server_port,"bind_port":bp}),201)
                mid2=mapping2["id"]
                assert operator("--supervise-preview",mid2,1,rp,"wrong_transport","tls_gateway",gp,"expected_body").returncode!=0
                assert operator("--supervise-tls-preview",mid2,1,rp,"bad_port","tls_gateway",gp,"expected_body",rp,"cert_v2").returncode!=0
                assert not (root/"wrong_transport").exists() and not (root/"bad_port").exists()
                supervisor=subprocess.Popen([exe,"--supervise-tls-preview",str(root),mid2,"1",str(rp),"supervised_tls","tls_gateway",str(gp),"expected_body",str(probe),"cert_v2"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    assert supervisor.poll() is None,"TLS supervisor exited during startup"
                    try:
                        if tls_request(gp,hostname,ca2)==(200,body):
                            break
                    except (OSError,http.client.HTTPException):
                        pass
                    time.sleep(.25)
                else:
                    raise AssertionError("supervised HTTPS did not converge")
                rejects(gp,hostname,ca)
                assert request(bp,hostname)==(200,body)
                assert (root/"supervisor-tls_gateway.lock").exists()
                assert operator("--supervise-tls-preview",mid2,1,rp,"competing_tls","tls_gateway",gp,"expected_body",probe,"cert_v2").returncode!=0
                assert not (root/"competing_tls").exists()
                expect(call(base,"devices/"+device2["id"]+"/revoke","POST",admin),204)
                assert supervisor.wait(timeout=40)==0,"TLS supervisor failed cleanup"
                rejects(gp,hostname,ca2)
                assert request(probe,"localtunnel-probe.invalid")[0]==421
                assert request(bp,hostname) is None
                assert not (root/"supervisor-tls_gateway.lock").exists()
                assert all(proc.poll() is None for proc in processes),"gateway must remain running"
                with sqlite3.connect(db_path) as db:
                    assert db.execute("SELECT outcome,transport FROM preview_attempts WHERE mapping_id=? AND operation='apply-checked'",(mid2,)).fetchall()==[("succeeded","https")]
                    assert db.execute("SELECT enabled FROM devices WHERE id=?",(device2["id"],)).fetchone()==(0,)
                    assert db.execute("SELECT enabled FROM mappings WHERE id=?",(mid2,)).fetchone()==(0,)
                report["real_supervised_https_revocation_and_handshake_denial"]=True
                expect(call(base,"mappings/"+mid2+"?expected_revision=1","DELETE",admin),204)
                device3=expect(enroll(base,issue(base,admin)),201)
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                mapping3=expect(call(base,"mappings","POST",admin,{"device_id":device3["id"],"node_id":nid,"domain_id":domain["id"],"protocol":"https","local_port":fixture.server_port,"bind_port":bp}),201)
                mid3=mapping3["id"]
                path="mappings/"+mid3
                queued=expect(call(base,path+"/start","POST",admin,{"expected_revision":1}),202)
                assert queued["state"]=="queued"
                rejects(gp,hostname,ca2)
                supervisor=subprocess.Popen([exe,"--runtime-tls-worker",str(root),mid3,"1",str(rp),"runtime_tls","tls_gateway",str(gp),"expected_body",str(probe),"cert_v2"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    assert supervisor.poll() is None,"TLS runtime worker exited"
                    try:
                        state=expect(call(base,path+"/runtime",token=admin),200)
                        if state["request"]["state"]=="running" and state["worker_recent"] and tls_request(gp,hostname,ca2)==(200,body):
                            break
                    except (OSError,http.client.HTTPException):
                        pass
                    time.sleep(.25)
                else:
                    raise AssertionError("TLS worker never published actual traffic")
                stopped=expect(call(base,path+"/stop","POST",admin,{"request_id":queued["request_id"]}),202)
                assert stopped["state"]=="stopping"
                assert supervisor.wait(timeout=40)==0
                state=expect(call(base,path+"/runtime",token=admin),200)
                assert state["request"]["state"]=="stopped" and not state["worker_recent"]
                rejects(gp,hostname,ca2)
                assert request(bp,hostname) is None
                assert request(probe,"localtunnel-probe.invalid")[0]==421
                report["real_https_runtime_api_start_stop"]=True
                # Exercise the shared recovery mechanism with actual HTTPS,
                # a verified certificate and two owned encrypted tunnel children.
                import signal
                def resident(bundle):
                    return subprocess.Popen([exe,"--runtime-tls-resident",str(root),mid3,"1",str(rp),bundle,"tls_gateway",str(gp),"expected_body",str(probe),"cert_v2"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                def state():
                    return expect(call(base,path+"/runtime",token=admin),200)["request"]
                def wait_state(phase,rid):
                    end=time.monotonic()+40
                    while time.monotonic()<end:
                        current=state()
                        if current and current["state"]==phase and current["request_id"]==rid:
                            return current
                        time.sleep(.2)
                    raise AssertionError("TLS resident state did not converge: "+phase)
                lock=root/"worker-tls_gateway.lock"
                sup_lock=root/"supervisor-tls_gateway.lock"
                def ready():
                    end=time.monotonic()+10
                    while time.monotonic()<end:
                        assert supervisor.poll() is None,"TLS resident exited before readiness"
                        if lock.exists():
                            return
                        time.sleep(.1)
                    raise AssertionError("TLS resident lock missing")
                def start_run():
                    rid=expect(call(base,path+"/start","POST",admin,{"expected_revision":1}),202)["request_id"]
                    end=time.monotonic()+45
                    while time.monotonic()<end:
                        assert supervisor.poll() is None,"TLS resident exited during start"
                        current=state()
                        try:
                            if current["request_id"]==rid and current["state"]=="running" and tls_request(gp,hostname,ca2)==(200,body):
                                return rid
                        except (OSError,http.client.HTTPException):
                            pass
                        time.sleep(.25)
                    raise AssertionError("TLS resident traffic did not converge")
                def closed_port(port):
                    with socket.socket() as sock:
                        sock.settimeout(.5)
                        return sock.connect_ex(("127.0.0.1",port))==__import__("errno").ECONNREFUSED
                def closed_tunnel():
                    end=time.monotonic()+15
                    while time.monotonic()<end:
                        if closed_port(rp) and closed_port(bp):
                            return
                        time.sleep(.2)
                    raise AssertionError("TLS relay or mapping listener remained reachable")
                def empty_gateway():
                    rejects(gp,hostname,ca2)
                    assert request(probe,"localtunnel-probe.invalid")[0]==421
                    assert all(proc.poll() is None for proc in processes),"dedicated Nginx exited"
                def recovery_record(rid):
                    record=root/("recovery-tls_gateway-"+rid+".json")
                    assert record.stat().st_mode&0o077==0
                    saved=json.loads(record.read_text())
                    assert saved=={"mapping_id":mid3,"revision":1,"request_id":rid,"prefix":"tls_gateway","relay":rp,"bind":bp,"listen":gp,"probe":probe,"cert_dir":"cert_v2"}
                    return record
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                supervisor=resident("tls_resident")
                ready()
                assert operator("--runtime-tls-resident",mid3,1,rp,"competing_resident","tls_gateway",gp,"expected_body",probe,"cert_v2").returncode!=0
                for _ in range(2):
                    rid=start_run()
                    recovery_record(rid)
                    assert (root/("tls_resident-"+rid)/"client.toml").is_file()
                    expect(call(base,path+"/stop","POST",admin,{"request_id":rid}),202)
                    wait_state("stopped",rid)
                    closed_tunnel()
                    empty_gateway()
                    assert not (root/("tls_resident-"+rid)).exists()
                    assert supervisor.poll() is None
                report["real_https_resident_multiple_start_stop"]=True
                # Fail one direct engine child only after identifying the exact
                # test executable and private per-request configuration.
                rid=start_run()
                recovery_record(rid)
                failed_bundle=root/("tls_resident-"+rid)
                assert operator("--recover-runtime","tls_gateway",rid).returncode!=0
                assert tls_request(gp,hostname,ca2)==(200,body)
                children=set()
                for task in (Path("/proc")/str(supervisor.pid)/"task").iterdir():
                    try:
                        candidates=(task/"children").read_text().split()
                    except FileNotFoundError:
                        continue
                    for child in candidates:
                        try:
                            proc=Path("/proc")/child
                            if (proc/"exe").resolve()==engine.resolve() and str(failed_bundle).encode() in (proc/"cmdline").read_bytes():
                                children.add(int(child))
                        except FileNotFoundError:
                            pass
                assert len(children)==2,"expected two owned TLS tunnel children"
                os.kill(min(children),signal.SIGKILL)
                assert supervisor.wait(timeout=40)!=0
                wait_state("failed_or_unknown",rid)
                closed_tunnel()
                empty_gateway()
                assert failed_bundle.is_dir()
                expect(call(base,path+"/start","POST",admin,{"expected_revision":1}),409)
                expect(call(base,path+"?expected_revision=1","DELETE",admin),409)
                assert operator("--recover-runtime","tls_gateway","0"*32).returncode!=0
                # Recovery must not clear SQL while a listener is still live.
                with socket.socket() as occupied:
                    occupied.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    occupied.bind(("127.0.0.1",rp))
                    occupied.listen(1)
                    assert operator("--recover-runtime","tls_gateway",rid).returncode!=0
                    assert state()["state"]=="failed_or_unknown"
                assert operator("--recover-runtime","tls_gateway",rid).returncode==0
                wait_state("stopped",rid)
                empty_gateway()
                assert failed_bundle.is_dir()
                report["real_https_child_failure_recovery_rejects_live_listener"]=True
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                supervisor=resident("tls_crash")
                ready()
                rid=start_run()
                recovery_record(rid)
                assert operator("--recover-runtime","tls_gateway",rid).returncode!=0
                assert tls_request(gp,hostname,ca2)==(200,body)
                # No graceful handler: parent-death protection must stop
                # both owned engines, while Nginx stays independently alive.
                supervisor.kill()
                assert supervisor.wait(timeout=10)!=0
                closed_tunnel()
                assert lock.exists() and sup_lock.exists()
                expect(call(base,path+"/start","POST",admin,{"expected_revision":1}),409)
                assert operator("--recover-runtime","tls_gateway",rid).returncode==0
                wait_state("stopped",rid)
                empty_gateway()
                assert not lock.exists() and not sup_lock.exists()
                assert (root/("tls_crash-"+rid)).is_dir()
                assert operator("--recover-runtime","tls_gateway",rid).returncode!=0
                report["real_https_supervisor_sigkill_parent_death_and_recovery"]=True
                # Prove a new request can really serve HTTPS after explicit
                # recovery; no automatic reuse of failed bundle or request.
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                supervisor=resident("tls_recovered")
                ready()
                fresh=start_run()
                assert fresh!=rid
                assert tls_request(gp,hostname,ca2)==(200,body)
                rejects(gp,hostname,ca)
                marker=root/"worker-tls_gateway.stop"
                marker.touch(mode=0o600)
                assert supervisor.wait(timeout=40)==0
                wait_state("stopped",fresh)
                closed_tunnel()
                empty_gateway()
                assert not lock.exists() and not sup_lock.exists()
                assert not (root/("tls_recovered-"+fresh)).exists()
                marker.unlink()
                report["real_https_restart_after_recovery_and_local_stop"]=True

                # Boundary inventory fixtures are sparse local files only.
                # Actual admission, TLS traffic, stop and recovery use the
                # existing real API, supervisor, Noise and Nginx.
                mib=1024*1024
                def logs():
                    return {p.name:p.stat().st_size for p in prefix.iterdir()
                            if re.fullmatch(r"traffic-[0-9]+-[0-9]+\.log",p.name)}
                baseline=logs()
                assert 0<len(baseline)<31 and 0<sum(baseline.values())<mib
                def fillers(count,size):
                    paths=[]
                    for i in range(count):
                        p=prefix/("traffic-0-"+str(10000+i)+".log")
                        with p.open("xb") as out:
                            out.truncate(size)
                        paths.append(p)
                    return paths
                def rejected_start(bundle):
                    global supervisor
                    expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                    supervisor=resident(bundle)
                    ready()
                    before=logs()
                    failed=expect(call(base,path+"/start","POST",admin,{"expected_revision":1}),202)["request_id"]
                    assert supervisor.wait(timeout=40)!=0
                    wait_state("failed_or_unknown",failed)
                    recovery_record(failed)
                    assert not (root/(bundle+"-"+failed)).exists()
                    closed_tunnel()
                    empty_gateway()
                    assert logs()==before,"admission changed retained log generations"
                    assert operator("--recover-runtime","tls_gateway",failed).returncode==0
                    wait_state("stopped",failed)
                    return failed

                # Exactly 32 existing logs is within the runtime cap, but
                # cannot reserve a new generation. No tunnel may start.
                fill=fillers(32-len(baseline),0)
                assert len(logs())==32
                rejected_start("tls_count_quota")
                for fixture_log in fill:fixture_log.unlink()
                assert logs()==baseline
                report["real_https_log_count_reservation_rejected"]=True

                # Seven individually valid 4MiB files plus the actual
                # existing logs exceed the 28MiB startup reservation only.
                fill=fillers(7,4*mib)
                assert 28*mib<sum(logs().values())<32*mib
                assert len(logs())<32
                rejected_start("tls_size_quota")
                for fixture_log in fill:fixture_log.unlink()
                assert logs()==baseline
                report["real_https_log_byte_reservation_rejected"]=True

                # Admit a real generation just below the reserved budget;
                # then grow several retained fixtures without exceeding the
                # per-file cap. Only aggregate quota is violated.
                fill=fillers(6,4*mib)
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                supervisor=resident("tls_total_quota")
                ready()
                rid=start_run()
                first=logs()
                new=set(first)-set(baseline)-{p.name for p in fill}
                assert len(new)==1
                first_name=new.pop()
                assert first[first_name]>0
                assert all(first[k]==v for k,v in baseline.items())
                added=[]
                for i in range(3):
                    fixture_log=prefix/("traffic-0-"+str(20000+i)+".log")
                    with fixture_log.open("xb") as out:
                        out.truncate(4*mib)
                    added.append(fixture_log)
                exceeded=logs()
                assert sum(exceeded.values())>32*mib and max(exceeded.values())<=4*mib
                assert len(exceeded)<=32
                assert supervisor.wait(timeout=40)!=0
                wait_state("failed_or_unknown",rid)
                closed_tunnel()
                empty_gateway()
                assert (root/("tls_total_quota-"+rid)).is_dir()
                assert set(exceeded)<=set(logs())
                assert operator("--recover-runtime","tls_gateway",rid).returncode==0
                wait_state("stopped",rid)
                for fixture_log in fill+added:fixture_log.unlink()
                report["real_https_aggregate_log_quota_stops_and_recovers"]=True

                # Re-admission after removing only test-created fixtures
                # must produce a new numeric log, not reuse old generation.
                retained=logs()
                expect(call(base,"domains/verify","POST",admin,{"domain_id":domain["id"]}),200)
                supervisor=resident("tls_quota_recovered")
                ready()
                next_id=start_run()
                assert next_id!=rid
                current=logs()
                generated=set(current)-set(retained)
                assert len(generated)==1 and first_name not in generated
                assert current[next(iter(generated))]>0
                assert all(current[k]==v for k,v in retained.items())
                marker.touch(mode=0o600)
                assert supervisor.wait(timeout=40)==0
                wait_state("stopped",next_id)
                closed_tunnel()
                empty_gateway()
                marker.unlink()
                assert (root/("tls_total_quota-"+rid)).is_dir()
                report["real_https_log_generation_isolation_after_quota_recovery"]=True
            finally:
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
