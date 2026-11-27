"""Real TLS gateway, three actual relay binaries and negative trust checks."""
import json
import os
from pathlib import Path
import secrets
import selectors
import sqlite3
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import http.server
import threading
import re

exe=Path(sys.argv[1]).resolve()
relay=exe.with_name("localtunnel-relay")
evidence=Path(sys.argv[2])
template=Path(__file__).resolve().parents[3]/"deploy/relay-control-nginx.conf.example"
report={}
children=[]
tokens=[]
def stop(p):
    if p.poll() is None:p.terminate()
    try:return p.communicate(timeout=5)
    except subprocess.TimeoutExpired:p.kill();return p.communicate(timeout=5)
def wait(predicate,seconds=20):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.2)
    raise AssertionError("TLS condition did not converge")
def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0));return s.getsockname()[1]
def openssl(*args):
    subprocess.run(["openssl",*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
try:
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        center=root/"center";center.mkdir(mode=0o700)
        def cmd(*args,data=None):
            p=subprocess.run([str(exe),args[0],str(center),*map(str,args[1:])],input=None if data is None else json.dumps(data),text=True,capture_output=True,timeout=25)
            assert p.returncode==0,"operator command failed"
            return p.stdout.strip()
        password=secrets.token_hex(24)
        cmd("--init-admin",data={"username":"owner","password":password})
        nodes=[cmd("--add-node","TLS relay "+str(i)) for i in range(3)]
        tokens.extend(cmd("--relay-issue",n) for n in nodes)
        p=subprocess.Popen([str(exe),str(center),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(p)
        with selectors.DefaultSelector() as s:
            s.register(p.stdout,selectors.EVENT_READ);assert s.select(20)
        address=p.stdout.readline().strip()
        assert address.startswith("LISTENING 127.0.0.1:")
        cp=int(address.rsplit(":",1)[1])
        ca=root/"ca.pem";cak=root/"ca.key";cert=root/"leaf.pem";key=root/"leaf.key";csr=root/"leaf.csr";ext=root/"extensions"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=LocalTunnel test CA","-keyout",cak,"-out",ca,"-addext","basicConstraints=critical,CA:TRUE")
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=localhost","-keyout",key,"-out",csr)
        ext.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")
        openssl("x509","-req","-in",csr,"-CA",ca,"-CAkey",cak,"-CAcreateserial","-days","2","-extfile",ext,"-out",cert)
        wrongca=root/"wrong.pem"
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=Other test CA","-keyout",root/"wrong.key","-out",wrongca)
        tp=port()
        conf=template.read_text()
        for name,value in {"LISTEN":f"127.0.0.1:{tp}","HOST":"localhost","CERT":cert,"KEY":key,"CENTER_PORT":cp}.items():
            conf=conf.replace("@"+name+"@",str(value))
        config=root/"nginx.conf"
        config.write_text("pid "+str(root/"nginx.pid")+";\nerror_log "+str(root/"nginx-error.log")+" crit;\nevents {}\nhttp {\nclient_body_temp_path "+str(root/"body")+";\nproxy_temp_path "+str(root/"proxy")+";\nfastcgi_temp_path "+str(root/"fastcgi")+";\nuwsgi_temp_path "+str(root/"uwsgi")+";\nscgi_temp_path "+str(root/"scgi")+";\n"+conf+"\n}\n")
        subprocess.run(["nginx","-t","-p",str(root)+"/","-c",str(config)],check=True,capture_output=True,timeout=10)
        proxy=subprocess.Popen(["nginx","-p",str(root)+"/","-c",str(config),"-g","daemon off;"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(proxy)
        ctx=ssl.create_default_context(cafile=str(ca))
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
        def request(path,token=None):
            req=urllib.request.Request(f"https://localhost:{tp}"+path,headers={} if token is None else {"Authorization":"Bearer "+token})
            try:
                with opener.open(req,timeout=2) as r:return r.status,json.loads(r.read())
            except urllib.error.HTTPError as e:return e.code,None
        def ready():
            assert proxy.poll() is None
            try:return request("/api/v1/relay/identity")[0]==401
            except OSError:return False
        wait(ready)
        def directory(name,token,anchor=ca):
            d=root/name;d.mkdir(mode=0o700)
            (d/"relay.token").write_text(token+"\n")
            (d/"relay.token").chmod(0o600)
            (d/"center-ca.pem").write_bytes(anchor.read_bytes())
            (d/"center-ca.pem").chmod(0o600)
            return d
        def start(d,i,host="localhost",target=tp):
            env=dict(os.environ,https_proxy="http://127.0.0.1:1",HTTPS_PROXY="http://127.0.0.1:1",ALL_PROXY="http://127.0.0.1:1",NO_PROXY="")
            p=subprocess.Popen([str(relay),"--tls",str(d),host,str(target),nodes[i],"1",str(i+5)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(p);return p
        dirs=[directory("relay-"+str(i),t) for i,t in enumerate(tokens)]
        live=[start(d,i) for i,d in enumerate(dirs)]
        def fresh():
            for i,p in enumerate(live):
                assert p.poll() is None,"valid TLS relay exited"
                code,h=request("/api/v1/relay/heartbeat",tokens[i])
                if code!=200 or not h["fresh"] or h["node_id"]!=nodes[i] or h["capacity"]!=i+5:return False
            return True
        wait(fresh)
        for path in ("/api/v1/nodes","/api/v1/auth/login","/api/v1/allocations","/readyz","/"):
            assert request(path,tokens[0])[0]==404
        report["real_tls_three_relay_processes_and_restricted_ingress"]=True
        # Real versioned control response; rejected mutations cannot alter
        # another node's heartbeat, including a valid token of equal generation.
        def control(token,payload,status):
            req=urllib.request.Request(f"https://localhost:{tp}/api/v1/relay/control",method="POST",
                headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},data=json.dumps(payload).encode())
            try:
                with opener.open(req,timeout=4) as r:
                    assert r.status==status and r.headers.get("Cache-Control")=="no-store"
                    return json.load(r)
            except urllib.error.HTTPError as e:assert e.code==status
        stop(live[2])
        nonce=secrets.token_hex(16)
        payload={"protocol_version":1,"node_id":nodes[2],"generation":1,"capacity":7,"nonce":nonce}
        def stored():
            with sqlite3.connect(center/"control.sqlite3") as db:
                return db.execute("SELECT generation,capacity,received_at FROM relay_heartbeat WHERE node_id=?",(nodes[2],)).fetchone()
        before=stored()
        control(tokens[2],dict(payload,protocol_version=2),400)
        control(tokens[2],dict(payload,generation=2),401)
        control(tokens[2],dict(payload,nonce="bad"),400)
        control(tokens[2],dict(payload,extra=True),422)
        control(tokens[0],payload,401)
        assert stored()==before
        cmd("--set-node-policy",nodes[2],1,9,"east","draining")
        snapshot=control(tokens[2],payload,200)
        assert snapshot["protocol_version"]==1 and snapshot["nonce"]==nonce and snapshot["scope"]=="control_only"
        assert snapshot["policy"]=={"node_id":nodes[2],"generation":1,"policy_revision":2,"approved_capacity":9,"region":"east","policy_mode":"draining","received_at":stored()[2]}
        assert stored()[:2]==(1,7)
        assert request("/api/v1/relay/control",tokens[2])[0]==405
        live[2]=start(dirs[2],2)
        wait(fresh)
        report["real_versioned_control_atomic_policy_and_rejected_mutations"]=True
        def fails(p):
            wait(lambda:p.poll() is not None,12)
            assert p.returncode!=0
        fails(start(directory("wrong-ca",tokens[0],wrongca),0))
        fails(start(dirs[0],0,host="127.0.0.1"))
        unsafe=directory("unsafe-ca",tokens[0])
        (unsafe/"center-ca.pem").chmod(0o644)
        fails(start(unsafe,0))
        report["real_tls_untrusted_ca_hostname_and_private_ca_rejected"]=True
        hits=[]
        class Capture(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(True);self.send_response(200);self.end_headers()
            def log_message(self,*args):pass
        capture=http.server.ThreadingHTTPServer(("127.0.0.1",0),Capture)
        thread=threading.Thread(target=capture.serve_forever,daemon=True);thread.start()
        class Redirect(Capture):
            def do_GET(self):
                self.send_response(302);self.send_header("Location",f"http://127.0.0.1:{capture.server_port}/capture");self.send_header("Content-Length","0");self.end_headers()
        redirect=http.server.ThreadingHTTPServer(("127.0.0.1",0),Redirect)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
        redirect.socket=tls.wrap_socket(redirect.socket,server_side=True)
        redthread=threading.Thread(target=redirect.serve_forever,daemon=True);redthread.start()
        try:
            fails(start(dirs[0],0,target=redirect.server_port))
            fails(start(dirs[0],0,target=capture.server_port))
            assert hits==[]
            assert fresh()
            report["real_tls_redirect_no_plaintext_or_proxy_fallback"]=True
        finally:
            redirect.shutdown();redirect.server_close();redthread.join(timeout=3)
            capture.shutdown();capture.server_close();thread.join(timeout=3)
        # Observe live revision update without restarting the node. The
        # fixed diagnostic contains only revision and enumerated policy mode.
        cmd("--set-node-policy",nodes[0],1,8,"west","maintenance")
        observed=[]
        def read_policy():
            for line in live[0].stdout:
                observed.append(line.strip())
                if "relay policy synchronized revision=2 mode=maintenance"==line.strip():return
        reader=threading.Thread(target=read_policy,daemon=True);reader.start()
        reader.join(timeout=15)
        assert "relay policy synchronized revision=2 mode=maintenance" in observed
        assert not any(t in line for t in tokens for line in observed)
        assert live[0].poll() is None
        report["real_relay_process_live_policy_revision_sync"]=True
        # Authorize an actual TLS node to verify only a fixed grant preview.
        # The owner API stays on loopback; the node gets exact opaque IDs.
        def admin(path,data,token=None,status=200):
            headers={"Content-Type":"application/json"}
            if token:headers["Authorization"]="Bearer "+token
            req=urllib.request.Request(f"http://127.0.0.1:{cp}/api/v1/"+path,headers=headers,
                method="POST",data=None if data is None else json.dumps(data).encode())
            with urllib.request.urlopen(req,timeout=4) as r:
                assert r.status==status
                return json.load(r)
        owner=admin("auth/login",{"username":"owner","password":password})["access_token"]
        tokens.append(owner)
        code=admin("devices/pairing-code",None,owner)["pairing_code"]
        device=admin("devices/enroll",{"pairing_code":code,"name":"TLS grant fixture"},status=201)["id"]
        cmd("--set-node-policy",nodes[1],1,8,"east","active")
        alloc=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[1],
            "protocol":"tcp","local_port":8080,"bind_port":20000},owner,201)
        grant=admin("allocations/"+alloc["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
        def verify(i=1,grant_id=grant["id"],generation=grant["generation"],mapping=grant["mapping_id"]):
            return subprocess.Popen([str(relay),"--verify-grant",str(dirs[i]),"localhost",str(tp),nodes[i],"1",str(i+5),
                alloc["id"],mapping,str(grant["mapping_revision"]),str(generation),grant_id],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        good=verify();children.append(good)
        with selectors.DefaultSelector() as sel:
            sel.register(good.stdout,selectors.EVENT_READ);assert sel.select(8)
        assert good.stdout.readline().strip()=="relay grant preview verified"
        for bad in (verify(grant_id=secrets.token_hex(16)),verify(mapping=secrets.token_hex(16)),verify(i=0),verify(generation=3)):
            children.append(bad);fails(bad)
            assert "relay grant preview verified" not in bad.stdout.read()
        report["real_tls_node_exact_grant_validation"]=True
        out,err=good.communicate(timeout=20)
        assert good.returncode==0 and out.strip()=="relay grant preview expired"
        assert not any(t in (out+err) for t in tokens)
        # Wait on the actual database UTC deadline, not the earlier
        # conservative node observation deadline.
        def expired():
            with sqlite3.connect(center/"control.sqlite3") as db:
                return db.execute("SELECT unixepoch()>=expires_at FROM relay_grants WHERE id=?",(grant["id"],)).fetchone()==(1,)
        wait(expired,5)
        stale=verify();children.append(stale);fails(stale)
        assert "relay grant preview verified" not in stale.stdout.read()
        with sqlite3.connect(center/"control.sqlite3") as db:
            assert db.execute("SELECT count(*) FROM relay_grants").fetchone()==(1,)
            assert db.execute("SELECT generation,state FROM relay_allocations WHERE id=?",(alloc["id"],)).fetchone()==(2,"reserved")
        report["real_tls_node_conservative_expiry_and_restart_rejection"]=True
        # Real TCP data path on an independently launched relay engine.
        # Reuse the repository's checksum-pinned Rathole acquisition helper.
        sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tests"))
        import e2e as core_test
        engine=core_test.engine(root)
        keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
        private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        service_token=secrets.token_hex(32)
        tokens.extend([private,service_token])
        for name,value in (("noise.private",private),("tcp.token",service_token)):
            path=dirs[1]/name
            path.write_text(value+"\n");path.chmod(0o600)
        def free_range(lo,hi):
            for _ in range(200):
                n=lo+secrets.randbelow(hi-lo+1)
                with socket.socket() as s:
                    try:s.bind(("127.0.0.1",n))
                    except OSError:continue
                    return n
            raise AssertionError("port unavailable")
        relay_port=free_range(30000,59999)
        bind_port=free_range(20001,29999)
        class Echo(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body=self.path.encode()
                self.send_response(200);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        target=http.server.ThreadingHTTPServer(("127.0.0.1",0),Echo)
        worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
        try:
            a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[1],
                "protocol":"tcp","local_port":target.server_port,"bind_port":bind_port},owner,201)
            config=root/"agent.toml"
            subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{relay_port}",
                "m_"+a["mapping_id"],f"127.0.0.1:{target.server_port}"],
                env=dict(os.environ,LOCALTUNNEL_TOKEN=service_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public),
                check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
            def tcp():
                p=subprocess.Popen([str(relay),"--tcp-preview",str(dirs[1]),"localhost",str(tp),nodes[1],"1","6",
                    a["id"],a["mapping_id"],"1",str(g["generation"]),g["id"],str(relay_port),str(bind_port),str(engine)],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                children.append(p);return p
            denied=tcp();fails(denied)
            assert "relay TCP engine started" not in denied.stdout.read()
            admin("allocations/"+a["id"]+"/tcp-intent",{"grant_id":g["id"],"expected_generation":g["generation"],"relay_port":relay_port},owner,201)
            running=tcp()
            with selectors.DefaultSelector() as sel:
                sel.register(running.stdout,selectors.EVENT_READ);assert sel.select(5)
            assert running.stdout.readline().strip()=="relay TCP engine started"
            agent=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                env=dict(os.environ,RUST_LOG="warn"))
            children.append(agent)
            body="/"+secrets.token_hex(24)
            def transfer():
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{bind_port}"+body,timeout=.5) as r:return r.read()==body.encode()
                except OSError:return False
            wait(transfer,9)
            assert running.poll() is None and agent.poll() is None
            replay=tcp();fails(replay)
            assert "relay TCP engine started" not in replay.stdout.read()
            report["real_independent_noise_tcp_transfer_and_one_shot_start"]=True
            out,err=running.communicate(timeout=20)
            assert running.returncode==0 and out.strip()=="relay TCP engine expired and stopped"
            assert not any(t in out+err for t in tokens)
            for port in (bind_port,relay_port):
                with socket.socket() as s:
                    s.settimeout(.5);assert s.connect_ex(("127.0.0.1",port))!=0
            assert not transfer()
            assert not (dirs[1]/("tcp-"+g["id"]+".toml")).exists()
            with sqlite3.connect(center/"control.sqlite3") as db:
                assert db.execute("SELECT claimed_at IS NOT NULL FROM relay_tcp_intents WHERE grant_id=?",(g["id"],)).fetchone()==(1,)
            report["real_independent_tcp_engine_expiry_closes_ports"]=True
        finally:
            target.shutdown();target.server_close();worker.join(timeout=3)
        # UDP uses a separate grant/intent/claim and independent service token.
        udp_token=secrets.token_hex(32)
        tokens.append(udp_token)
        path=dirs[1]/"udp.token";path.write_text(udp_token+"\n");path.chmod(0o600)
        udp_relay=free_range(30000,59999)
        while udp_relay==relay_port:udp_relay=free_range(30000,59999)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target_udp:
            target_udp.bind(("127.0.0.1",0));target_udp.settimeout(.2)
            done=threading.Event()
            def echo_udp():
                while not done.is_set():
                    try:
                        body,peer=target_udp.recvfrom(4096)
                        target_udp.sendto(body,peer)
                    except socket.timeout:pass
            worker=threading.Thread(target=echo_udp,daemon=True);worker.start()
            try:
                while True:
                    udp_bind=free_range(20001,29999)
                    if udp_bind==bind_port:continue
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        try:probe.bind(("127.0.0.1",udp_bind))
                        except OSError:continue
                    break
                a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[1],
                    "protocol":"udp","local_port":target_udp.getsockname()[1],"bind_port":udp_bind},owner,201)
                config=root/"udp-agent.toml"
                subprocess.run([str(core_test.CLI),"client-udp-config",str(config),f"127.0.0.1:{udp_relay}",
                    "m_"+a["mapping_id"],f"127.0.0.1:{target_udp.getsockname()[1]}"],
                    env=dict(os.environ,LOCALTUNNEL_TOKEN=udp_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public),
                    check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
                def intent_for(kind,port,status):
                    data={"grant_id":g["id"],"expected_generation":g["generation"],"relay_port":port}
                    try:admin("allocations/"+a["id"]+"/"+kind+"-intent",data,owner,status)
                    except urllib.error.HTTPError as ex:assert ex.code==status
                intent_for("tcp",udp_relay,409)
                intent_for("udp",relay_port,409)
                intent_for("udp",udp_relay,201)
                def start_udp(kind="udp"):
                    p=subprocess.Popen([str(relay),"--"+kind+"-preview",str(dirs[1]),"localhost",str(tp),nodes[1],"1","6",
                        a["id"],a["mapping_id"],"1",str(g["generation"]),g["id"],str(udp_relay),str(udp_bind),str(engine)],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    children.append(p);return p
                wrong=start_udp("tcp");fails(wrong)
                assert "relay TCP engine started" not in wrong.stdout.read()
                running=start_udp()
                with selectors.DefaultSelector() as sel:
                    sel.register(running.stdout,selectors.EVENT_READ);assert sel.select(5)
                assert running.stdout.readline().strip()=="relay UDP engine started"
                agent=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=dict(os.environ,RUST_LOG="warn"))
                children.append(agent)
                def udp_transfer():
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                        client.settimeout(.4)
                        body=secrets.token_bytes(48)
                        try:
                            client.sendto(body,("127.0.0.1",udp_bind))
                            return client.recvfrom(4096)[0]==body
                        except OSError:return False
                wait(udp_transfer,9)
                assert running.poll() is None and agent.poll() is None
                replay=start_udp();fails(replay)
                assert "relay UDP engine started" not in replay.stdout.read()
                report["real_independent_udp_datagrams_protocol_and_port_isolation"]=True
                out,err=running.communicate(timeout=20)
                assert running.returncode==0 and out.strip()=="relay UDP engine expired and stopped"
                assert not any(t in out+err for t in tokens)
                assert not udp_transfer()
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                    probe.bind(("127.0.0.1",udp_bind))
                with socket.socket() as probe:
                    probe.settimeout(.5);assert probe.connect_ex(("127.0.0.1",udp_relay))!=0
                assert not (dirs[1]/("udp-"+g["id"]+".toml")).exists()
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT claimed_at IS NOT NULL FROM relay_udp_intents WHERE grant_id=?",(g["id"],)).fetchone()==(1,)
                    assert db.execute("SELECT count(*) FROM relay_tcp_intents WHERE grant_id=?",(g["id"],)).fetchone()==(0,)
                report["real_independent_udp_expiry_closes_transport_and_datagram_port"]=True
            finally:
                done.set();worker.join(timeout=3)
        cmd("--relay-revoke",nodes[1],1)
        fails(live[1])
        assert request("/api/v1/relay/identity",tokens[1])[0]==401
        assert request("/api/v1/relay/heartbeat",tokens[0])[1]["fresh"]
        report["real_tls_relay_revocation_and_no_credential_diagnostics"]=True
finally:
    for p in reversed(children):
        out,err=stop(p)
        assert not any(t in ((out or "")+(err or "")) for t in tokens),"credential leaked"
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==12 and all(report.values())
