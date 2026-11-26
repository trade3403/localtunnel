"""Real authorized management UDP draft -> guarded Noise echo preview on Linux."""
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tests"))
import e2e as core_test

exe=str(Path(sys.argv[1]).resolve())
evidence=Path(sys.argv[2])
report={}
def call(base,path,status,method="GET",token=None,data=None):
    headers={}
    if token is not None:
        headers["Authorization"]="Bearer "+token
    if data is not None:
        headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            code,raw=r.status,r.read()
    except urllib.error.HTTPError as e:
        code,raw=e.code,e.read()
    assert code==status, f"{method} {path}: expected {status}, got {code}"
    if code in (200,201,202):
        return json.loads(raw)
def line(p,prefix,seconds):
    with selectors.DefaultSelector() as s:
        s.register(p.stdout,selectors.EVENT_READ)
        assert s.select(seconds), "preview readiness timed out"
    assert p.stdout.readline().strip().startswith(prefix), "unexpected preview readiness"
def free(kind,lo,hi,exclude):
    for _ in range(200):
        p=lo+secrets.randbelow(hi-lo+1)
        if p in exclude:
            continue
        with socket.socket(socket.AF_INET,kind) as s:
            try:
                s.bind(("127.0.0.1",p))
                return p
            except OSError:
                continue
    raise AssertionError("no free preview port")
try:
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        password=secrets.token_hex(24)
        assert subprocess.run([exe,"--init-admin",str(root)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20).returncode==0
        node=subprocess.check_output([exe,"--add-node",str(root),"UDP preview node"],text=True,timeout=20).strip()
        engine=core_test.engine(root)
        keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
        private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        env=dict(os.environ,LOCALTUNNEL_CORE_CLI=str(core_test.CLI.resolve()),LOCALTUNNEL_ENGINE=str(engine),LOCALTUNNEL_SERVER_PRIVATE_KEY=private,LOCALTUNNEL_SERVER_PUBLIC_KEY=public)
        fixture=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        fixture.bind(("127.0.0.1",0))
        fixture.settimeout(.2)
        local=fixture.getsockname()[1]
        stopped=threading.Event()
        seen=[]
        def echo():
            while not stopped.is_set():
                try:
                    data,addr=fixture.recvfrom(65535)
                    seen.append(data)
                    fixture.sendto(data,addr)
                except socket.timeout:
                    continue
                except OSError:
                    return
        thread=threading.Thread(target=echo,daemon=True)
        thread.start()
        management=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        children=[]
        try:
            with selectors.DefaultSelector() as s:
                s.register(management.stdout,selectors.EVENT_READ)
                assert s.select(20)
            address=management.stdout.readline().strip()
            assert address.startswith("LISTENING 127.0.0.1:")
            base="http://"+address.split()[1]
            admin=call(base,"auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            pairing=call(base,"devices/pairing-code",200,"POST",admin)["pairing_code"]
            device=call(base,"devices/enroll",201,"POST",data={"pairing_code":pairing,"name":"UDP echo preview"})
            ingress=free(socket.SOCK_DGRAM,20000,29999,[local])
            relay=free(socket.SOCK_STREAM,30000,60000,[local,ingress])
            internal=free(socket.SOCK_DGRAM,30000,60000,[local,ingress,relay])
            m=call(base,"mappings",201,"POST",admin,{"device_id":device["id"],"node_id":node,"protocol":"udp","local_port":local,"bind_port":ingress})
            mid=m["id"]
            def command(revision,bundle):
                return [exe,"--supervise-udp-preview",str(root),mid,str(revision),str(relay),str(internal),bundle]
            def launch(bundle):
                p=subprocess.Popen(command(m["revision"],bundle),env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                children.append(p)
                line(p,"UDP_PREVIEW_READY",45)
                return p
            def rejected(args):
                p=subprocess.run(args,env=env,capture_output=True,timeout=10)
                assert p.returncode!=0 and b"UDP_PREVIEW_READY" not in p.stdout
            def exchange():
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.settimeout(1)
                    data=secrets.token_bytes(128)
                    try:
                        s.sendto(data,("127.0.0.1",ingress))
                        reply,addr=s.recvfrom(65535)
                        return reply==data and addr==("127.0.0.1",ingress)
                    except (socket.timeout,ConnectionRefusedError,ConnectionResetError):
                        return False
            def closed():
                assert not exchange()
                for kind,p in [(socket.SOCK_DGRAM,ingress),(socket.SOCK_DGRAM,internal),(socket.SOCK_STREAM,relay)]:
                    with socket.socket(socket.AF_INET,kind) as s:
                        if kind==socket.SOCK_STREAM:
                            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                        s.bind(("127.0.0.1",p))
            rejected(command(m["revision"]+1,"stale"))
            assert not (root/"stale").exists()
            # SO_REUSEADDR permits TIME_WAIT reuse, never an existing listener.
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as occupied:
                occupied.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                occupied.bind(("127.0.0.1",relay))
                occupied.listen(1)
                rejected(command(m["revision"],"occupied"))
                assert not (root/"occupied").exists()
                with socket.create_connection(("127.0.0.1",relay),timeout=2) as client:
                    conn,_=occupied.accept()
                    with conn:
                        client.sendall(b"owned")
                        assert conn.recv(5)==b"owned"
            report["real_udp_preflight_rejects_live_tcp_listener"]=True
            p=launch("udp_first")
            assert exchange()
            rejected(command(m["revision"],"duplicate"))
            assert not (root/"duplicate").exists()
            manifest=json.loads((root/"udp_first"/"manifest.json").read_text())
            assert manifest["mapping_id"]==mid and manifest["ingress_port"]==ingress and manifest["internal_port"]==internal
            for filename in ("server.toml","client.toml","manifest.json"):
                assert (root/"udp_first"/filename).stat().st_mode&0o777==0o600
            assert "type = \"udp\"" in (root/"udp_first"/"server.toml").read_text()
            assert call(base,"mappings/"+mid+"/runtime",200,token=admin)["request"] is None
            call(base,"mappings/"+mid+"/start",409,"POST",admin,{"expected_revision":m["revision"]})
            report["real_udp_draft_to_guarded_noise_preview_and_duplicate_denial"]=True
            (root/"udp-stop-udp_first").touch(mode=0o600)
            assert p.wait(timeout=10)==0
            closed()
            report["real_udp_preview_explicit_stop_closes_owned_children"]=True
            # A separately authorized API route queues an operator-fixed worker;
            # no public listener, executable path or limits accepted in JSON.
            route="mappings/"+mid
            call(base,route+"/udp-start",409,"POST",admin,{"expected_revision":m["revision"]+1})
            queued=call(base,route+"/udp-start",202,"POST",admin,{"expected_revision":m["revision"]})
            assert queued["state"]=="queued"
            call(base,route+"/udp-start",409,"POST",admin,{"expected_revision":m["revision"]})
            assert call(base,route+"/stop",202,"POST",admin,{"request_id":queued["request_id"]})["state"]=="stopped"
            queued=call(base,route+"/udp-start",202,"POST",admin,{"expected_revision":m["revision"]})
            rid=queued["request_id"]
            worker=[exe,"--runtime-udp-worker",str(root),mid,str(m["revision"]),str(relay),str(internal),"udp_api","4096","1200"]
            p=subprocess.Popen(worker,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            children.append(p)
            line(p,"UDP_PREVIEW_READY",45)
            state=call(base,route+"/runtime",200,token=admin)
            assert state["request"]["request_id"]==rid and state["request"]["state"]=="running" and state["worker_recent"]
            manifest=json.loads((root/"udp_api"/"manifest.json").read_text())
            assert manifest["request_id"]==rid and manifest["byte_rate"]==4096 and manifest["burst_bytes"]==1200
            assert exchange()
            # Send four large but otherwise valid datagrams below the old
            # per-source packet burst. At least one must be byte-limited.
            prefix=secrets.token_bytes(16)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                sender.bind(("127.0.0.1",0))
                start=time.monotonic()
                for n in range(4):
                    sender.sendto(prefix+bytes([n])+secrets.token_bytes(983),("127.0.0.1",ingress))
                time.sleep(.3)
                actual=sum(v.startswith(prefix) and len(v)==1000 for v in seen)
                elapsed=time.monotonic()-start
                assert 0<actual<4 and actual*1000<=1200+4096*elapsed
            assert exchange()
            report["real_udp_api_worker_claim_and_byte_limit"]=True
            call(base,route+"/stop",409,"POST",admin,{"request_id":secrets.token_hex(16)})
            assert call(base,route+"/stop",202,"POST",admin,{"request_id":rid})["state"]=="stopping"
            assert p.wait(timeout=10)==0
            closed()
            state=call(base,route+"/runtime",200,token=admin)
            assert state["request"]["state"]=="stopped" and not state["worker_recent"]
            report["real_udp_api_stop_reaps_children_and_closes_ports"]=True
            # One resident process handles independent requests with new credentials.
            resident=[exe,"--runtime-udp-resident",str(root),mid,str(m["revision"]),str(relay),str(internal),"udp_res","4096","1200"]
            p=subprocess.Popen(resident,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(p)
            def request_start():
                queued=call(base,route+"/udp-start",202,"POST",admin,{"expected_revision":m["revision"]})
                rid=queued["request_id"]
                deadline=time.monotonic()+40
                while time.monotonic()<deadline:
                    if p.poll() is not None:
                        # Product resident emits only a static reason; do not
                        # dump child configuration, credentials or paths.
                        diagnostic=p.stderr.read(1024)
                        raise AssertionError("resident exited: "+diagnostic.strip())
                    s=call(base,route+"/runtime",200,token=admin)
                    if s["request"]["state"]=="running" and s["request"]["request_id"]==rid:
                        assert s["worker_recent"] and exchange()
                        return rid
                    time.sleep(.25)
                raise AssertionError("resident did not start")
            def request_stop(rid):
                call(base,route+"/stop",202,"POST",admin,{"request_id":rid})
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    s=call(base,route+"/runtime",200,token=admin)
                    if s["request"]["state"]=="stopped":
                        assert p.poll() is None
                        closed()
                        return
                    time.sleep(.25)
                raise AssertionError("resident did not stop")
            first=request_start()
            request_stop(first)
            second=request_start()
            assert first!=second
            first_dir=root/("udp_res-"+first)
            second_dir=root/("udp_res-"+second)
            assert first_dir.is_dir() and second_dir.is_dir()
            assert (first_dir/"client.toml").read_bytes()!=(second_dir/"client.toml").read_bytes()
            report["real_udp_resident_two_independent_requests"]=True
            # Local emergency stop during active forwarding reaps children.
            (root/("udp-worker-"+mid+".stop")).touch(mode=0o600)
            assert p.wait(timeout=15)==0
            closed()
            assert call(base,route+"/runtime",200,token=admin)["request"]["state"]=="stopped"
            report["real_udp_resident_local_stop_reaps_children"]=True
            (root/("udp-worker-"+mid+".stop")).unlink()
            p=launch("udp_second")
            assert exchange()
            call(base,"devices/"+device["id"]+"/revoke",204,"POST",admin)
            assert p.wait(timeout=10)!=0
            closed()
            rejected(command(m["revision"],"revoked"))
            assert not (root/"revoked").exists()
            report["real_udp_preview_revocation_closes_ingress_and_denies_restart"]=True
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
            core_test.terminate(management)
            stopped.set()
            thread.join(timeout=2)
            fixture.close()
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==8 and all(v is True for v in report.values())
