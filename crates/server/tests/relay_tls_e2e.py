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
import http.client
import hashlib
import threading
import socketserver
import struct
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

try:
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),Handler) as dns,tempfile.TemporaryDirectory() as tmp:
        dns.daemon_threads=True
        dns_thread=threading.Thread(target=dns.serve_forever,daemon=True);dns_thread.start()
        resolver="127.0.0.1:"+str(dns.server_address[1])
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
        p=subprocess.Popen([str(exe),str(center),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,LOCALTUNNEL_DNS_RESOLVER=resolver))
        children.append(p)
        center_process=p
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
        def start(d,i,host="localhost",target=tp,capacity=None):
            env=dict(os.environ,https_proxy="http://127.0.0.1:1",HTTPS_PROXY="http://127.0.0.1:1",ALL_PROXY="http://127.0.0.1:1",NO_PROXY="")
            p=subprocess.Popen([str(relay),"--tls",str(d),host,str(target),nodes[i],"1",str(i+5 if capacity is None else capacity)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
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
            do_POST=do_GET
            def log_message(self,*args):pass
        capture=http.server.ThreadingHTTPServer(("127.0.0.1",0),Capture)
        thread=threading.Thread(target=capture.serve_forever,daemon=True);thread.start()
        class Redirect(Capture):
            def do_GET(self):
                self.send_response(302);self.send_header("Location",f"http://127.0.0.1:{capture.server_port}/capture");self.send_header("Content-Length","0");self.end_headers()
            do_POST=do_GET
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
        # HTTP data path: real DNS proof, verified TLS claim, independent
        # gateway and Noise agent. Unknown hosts never reach the target.
        http_token=secrets.token_hex(32);tokens.append(http_token)
        path=dirs[1]/"http.token";path.write_text(http_token+"\n");path.chmod(0o600)
        web=admin("domains",{"hostname":"relay-web.example.test"},owner,201)
        records[web["txt_name"]+"."]=web["txt_value"]
        proof=admin("domains/verify",{"domain_id":web["id"]},owner)
        assert proof["verified_at"] is not None
        web_relay=free_range(30000,59999)
        while web_relay in (relay_port,udp_relay):web_relay=free_range(30000,59999)
        web_bind=free_range(20001,29999)
        while web_bind in (bind_port,udp_bind):web_bind=free_range(20001,29999)
        gateway_port=free_range(60000,64999)
        hits=[]
        class WebTarget(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                body=json.dumps({"path":self.path,"host":self.headers.get("Host"),"xff":self.headers.get("X-Forwarded-For"),
                    "proto":self.headers.get("X-Forwarded-Proto"),"forwarded":self.headers.get("Forwarded")}).encode()
                self.send_response(200);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        target=http.server.ThreadingHTTPServer(("127.0.0.1",0),WebTarget)
        worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
        try:
            a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[1],
                "protocol":"http","domain_id":web["id"],"local_port":target.server_port,"bind_port":web_bind},owner,201)
            config=root/"http-agent.toml"
            subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{web_relay}","m_"+a["mapping_id"],
                f"127.0.0.1:{target.server_port}"],env=dict(os.environ,LOCALTUNNEL_TOKEN=http_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public),
                check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
            admin("allocations/"+a["id"]+"/http-intent",{"grant_id":g["id"],"expected_generation":g["generation"],
                "relay_port":web_relay,"gateway_port":gateway_port},owner,201)
            def start_web(host=web["hostname"]):
                p=subprocess.Popen([str(relay),"--http-preview",str(dirs[1]),"localhost",str(tp),nodes[1],"1","6",
                    a["id"],a["mapping_id"],"1",str(g["generation"]),g["id"],str(web_relay),str(web_bind),str(engine),
                    str(gateway_port),host],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                children.append(p);return p
            wrong=start_web("other.example.test");fails(wrong)
            assert "relay HTTP engine started" not in wrong.stdout.read()
            running=start_web()
            with selectors.DefaultSelector() as sel:
                sel.register(running.stdout,selectors.EVENT_READ);assert sel.select(5)
            assert running.stdout.readline().strip()=="relay HTTP engine started"
            agent=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,RUST_LOG="warn"))
            children.append(agent)
            body="/"+secrets.token_hex(24)
            def web_request(host):
                req=urllib.request.Request(f"http://127.0.0.1:{gateway_port}"+body,headers={"Host":host,"X-Forwarded-For":"203.0.113.9","Forwarded":"for=203.0.113.9"})
                try:
                    with urllib.request.urlopen(req,timeout=.5) as r:return r.status,json.load(r)
                except urllib.error.HTTPError as ex:return ex.code,None
                except OSError:return None,None
            def transfer_web():
                return web_request(web["hostname"])==(200,{"path":body,"host":web["hostname"],"xff":"127.0.0.1","proto":"http","forwarded":None})
            wait(transfer_web,9)
            before=len(hits)
            assert web_request("other.example.test")[0]==421 and len(hits)==before
            replay=start_web();fails(replay)
            assert "relay HTTP engine started" not in replay.stdout.read()
            assert running.poll() is None and agent.poll() is None
            report["real_independent_http_dns_host_routing_and_header_isolation"]=True
            out,err=running.communicate(timeout=20)
            assert running.returncode==0 and out.strip()=="relay HTTP engine expired and stopped"
            assert not any(t in out+err for t in tokens)
            for n in (web_relay,web_bind,gateway_port):
                with socket.socket() as check:
                    check.settimeout(.5);assert check.connect_ex(("127.0.0.1",n))!=0
            assert not (dirs[1]/("http-"+g["id"]+".toml")).exists()
            assert not (dirs[1]/("http-"+g["id"]+".gateway")).exists()
            with sqlite3.connect(center/"control.sqlite3") as db:
                assert db.execute("SELECT claimed_at IS NOT NULL FROM relay_http_intents WHERE grant_id=?",(g["id"],)).fetchone()==(1,)
            report["real_independent_http_expiry_closes_gateway_and_noise_engine"]=True
        finally:
            target.shutdown();target.server_close();worker.join(timeout=3)
        # Independent HTTPS with a real leaf signed by a separate trusted
        # fixture CA, exact SAN/fingerprint and encrypted client traffic.
        host="relay-secure.example.test"
        secure=admin("domains",{"hostname":host},owner,201)
        records[secure["txt_name"]+"."]=secure["txt_value"]
        assert admin("domains/verify",{"domain_id":secure["id"]},owner)["verified_at"] is not None
        tls_token=secrets.token_hex(32);tokens.append(tls_token)
        path=dirs[1]/"https.token";path.write_text(tls_token+"\n");path.chmod(0o600)
        tls_cert=root/"web-leaf.pem";tls_key=root/"web-leaf.key";tls_csr=root/"web-leaf.csr"
        tls_ext=root/"web-ext"
        tls_ext.write_text("subjectAltName=DNS:"+host+"\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+host,"-keyout",tls_key,"-out",tls_csr)
        openssl("x509","-req","-in",tls_csr,"-CA",ca,"-CAkey",cak,"-CAcreateserial","-days","2","-extfile",tls_ext,"-out",tls_cert)
        alternate=root/"web-other.pem"
        openssl("x509","-req","-in",tls_csr,"-CA",ca,"-CAkey",cak,"-CAcreateserial","-days","2","-extfile",tls_ext,"-out",alternate)
        fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert(tls_cert.read_text())).hexdigest()
        assert fp!=hashlib.sha256(ssl.PEM_cert_to_DER_cert(alternate.read_text())).hexdigest()
        def provision(name,source):
            path=dirs[1]/name;path.write_bytes(source.read_bytes());path.chmod(0o600)
        provision("web-ca.pem",ca);provision("leaf.pem",tls_cert);provision("leaf.key",tls_key)
        tls_relay=free_range(30000,59999)
        while tls_relay in (relay_port,udp_relay,web_relay):tls_relay=free_range(30000,59999)
        tls_bind=free_range(20001,29999)
        while tls_bind in (bind_port,udp_bind,web_bind):tls_bind=free_range(20001,29999)
        tls_gateway=free_range(60000,64999)
        while tls_gateway==gateway_port:tls_gateway=free_range(60000,64999)
        target=http.server.ThreadingHTTPServer(("127.0.0.1",0),WebTarget)
        worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
        try:
            a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[1],
                "protocol":"https","domain_id":secure["id"],"local_port":target.server_port,"bind_port":tls_bind},owner,201)
            config=root/"https-agent.toml"
            subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{tls_relay}","m_"+a["mapping_id"],
                f"127.0.0.1:{target.server_port}"],env=dict(os.environ,LOCALTUNNEL_TOKEN=tls_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public),
                check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
            admin("allocations/"+a["id"]+"/https-intent",{"grant_id":g["id"],"expected_generation":g["generation"],
                "relay_port":tls_relay,"gateway_port":tls_gateway,"certificate_sha256":fp},owner,201)
            def start_secure():
                p=subprocess.Popen([str(relay),"--https-preview",str(dirs[1]),"localhost",str(tp),nodes[1],"1","6",
                    a["id"],a["mapping_id"],"1",str(g["generation"]),g["id"],str(tls_relay),str(tls_bind),str(engine),
                    str(tls_gateway),host],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                children.append(p);return p
            # Wrong private key, wrong SAN, untrusted CA and a different
            # correctly signed leaf cannot consume the authorized claim.
            for name,wrong,correct in [("leaf.key",key,tls_key),("leaf.pem",cert,tls_cert),
                    ("web-ca.pem",wrongca,ca),("leaf.pem",alternate,tls_cert)]:
                provision(name,wrong)
                bad=start_secure();fails(bad)
                assert "relay HTTPS engine started" not in bad.stdout.read()
                provision(name,correct)
            with sqlite3.connect(center/"control.sqlite3") as db:
                assert db.execute("SELECT claimed_at FROM relay_https_intents WHERE grant_id=?",(g["id"],)).fetchone()==(None,)
            running=start_secure()
            with selectors.DefaultSelector() as sel:
                sel.register(running.stdout,selectors.EVENT_READ);assert sel.select(5)
            assert running.stdout.readline().strip()=="relay HTTPS engine started"
            agent=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,RUST_LOG="warn"))
            children.append(agent)
            secure_ctx=ssl.create_default_context(cafile=str(ca))
            body="/"+secrets.token_hex(24)
            def https_request(sni=host,header=host,context=secure_ctx):
                try:
                    with socket.create_connection(("127.0.0.1",tls_gateway),timeout=.7) as raw:
                        with context.wrap_socket(raw,server_hostname=sni) as tls:
                            assert hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==fp
                            tls.sendall(("GET "+body+" HTTP/1.1\r\nHost: "+header+"\r\nX-Forwarded-For: 203.0.113.9\r\nForwarded: for=203.0.113.9\r\nConnection: close\r\n\r\n").encode())
                            with http.client.HTTPResponse(tls) as response:
                                response.begin()
                                return response.status,json.loads(response.read()) if response.status==200 else None
                except (OSError,http.client.HTTPException):return None,None
            def transfer_secure():
                return https_request()==(200,{"path":body,"host":host,"xff":"127.0.0.1","proto":"https","forwarded":None})
            wait(transfer_secure,8)
            before=len(hits)
            no_hostname=ssl.create_default_context(cafile=str(ca));no_hostname.check_hostname=False
            assert https_request("wrong.example.test",host,no_hostname)==(None,None)
            assert https_request(None,host,no_hostname)==(None,None)
            assert https_request(host,"wrong.example.test")[0]==421
            assert https_request(context=ssl.create_default_context(cafile=str(wrongca)))==(None,None)
            assert len(hits)==before
            replay=start_secure();fails(replay)
            assert running.poll() is None
            report["real_independent_https_certificate_key_fingerprint_and_sni_isolation"]=True
            out,err=running.communicate(timeout=20)
            assert running.returncode==0 and out.strip()=="relay HTTPS engine expired and stopped"
            assert not any(t in out+err for t in tokens)
            for n in (tls_relay,tls_bind,tls_gateway):
                with socket.socket() as check:
                    check.settimeout(.5);assert check.connect_ex(("127.0.0.1",n))!=0
            assert not (dirs[1]/("https-"+g["id"]+".toml")).exists()
            assert not (dirs[1]/("https-"+g["id"]+".gateway")).exists()
            with sqlite3.connect(center/"control.sqlite3") as db:
                assert db.execute("SELECT certificate_sha256,claimed_at IS NOT NULL FROM relay_https_intents WHERE grant_id=?",(g["id"],)).fetchone()==(fp,1)
            report["real_independent_https_expiry_closes_tls_gateway_and_noise_engine"]=True
        finally:
            target.shutdown();target.server_close();worker.join(timeout=3)
        # A real, already established TCP connection continues only within
        # its bounded lease after the actual center process is stopped.
        # Use a separate node and independently generated data credentials.
        cmd("--set-node-policy",nodes[0],2,8,"west","active")
        control(tokens[0],{"protocol_version":1,"node_id":nodes[0],"generation":1,"capacity":5,"nonce":secrets.token_hex(16)},200)
        keys0=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
        private0=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys0).group(1)
        public0=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys0).group(1)
        offline_token=secrets.token_hex(32);tokens.extend([private0,offline_token])
        for name,value in (("noise.private",private0),("tcp.token",offline_token)):
            path=dirs[0]/name;path.write_text(value+"\n");path.chmod(0o600)
        used={relay_port,udp_relay,web_relay,tls_relay,bind_port,udp_bind,web_bind,tls_bind,20000}
        low,high=map(int,Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        def offline_port(lo,hi):
            candidates=[n for n in range(lo,hi+1) if n not in used and not low<=n<=high]
            while candidates:
                n=candidates.pop(secrets.randbelow(len(candidates)))
                with socket.socket() as probe:
                    try:probe.bind(("127.0.0.1",n))
                    except OSError:continue
                used.add(n);return n
            raise AssertionError("offline fixture port unavailable")
        class Stream(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(25)
                try:
                    while True:
                        data=self.request.recv(4096)
                        if not data:return
                        self.request.sendall(data)
                except OSError:return
        with socketserver.ThreadingTCPServer(("127.0.0.1",0),Stream) as target:
            target.daemon_threads=True
            worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
            try:
                def prepare():
                    rp,bp=offline_port(30000,59999),offline_port(20001,29999)
                    a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":device,"node_id":nodes[0],
                        "protocol":"tcp","local_port":target.server_address[1],"bind_port":bp},owner,201)
                    config=root/("offline-"+a["id"]+".toml")
                    subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{rp}",
                        "m_"+a["mapping_id"],f"127.0.0.1:{target.server_address[1]}"],
                        env=dict(os.environ,LOCALTUNNEL_TOKEN=offline_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public0),
                        check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    return a,rp,bp,config
                pending,active=prepare(),prepare()
                def authorize(item):
                    a,rp,bp,_=item
                    g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
                    admin("allocations/"+a["id"]+"/tcp-intent",{"grant_id":g["id"],"expected_generation":2,"relay_port":rp},owner,201)
                    return g
                pending_grant=authorize(pending)
                active_grant=authorize(active)
                def start_offline(item,g):
                    a,rp,bp,_=item
                    child=subprocess.Popen([str(relay),"--tcp-preview",str(dirs[0]),"localhost",str(tp),nodes[0],"1","5",
                        a["id"],a["mapping_id"],"1",str(g["generation"]),g["id"],str(rp),str(bp),str(engine)],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    children.append(child);return child
                running=start_offline(active,active_grant)
                with selectors.DefaultSelector() as sel:
                    sel.register(running.stdout,selectors.EVENT_READ);assert sel.select(5)
                assert running.stdout.readline().strip()=="relay TCP engine started"
                agent=subprocess.Popen([str(engine),str(active[3])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=dict(os.environ,RUST_LOG="warn"))
                children.append(agent)
                def exchange_stream(conn):
                    body=secrets.token_bytes(256)
                    conn.sendall(body)
                    received=bytearray()
                    while len(received)<len(body):
                        chunk=conn.recv(len(body)-len(received))
                        assert chunk,"established stream closed early"
                        received.extend(chunk)
                    assert received==body
                def connect_stream():
                    try:
                        conn=socket.create_connection(("127.0.0.1",active[2]),timeout=.5)
                        try:exchange_stream(conn)
                        except (OSError,AssertionError):conn.close();return None
                        return conn
                    except OSError:return None
                holder=[]
                def connected():
                    conn=connect_stream()
                    if conn is None:return False
                    holder.append(conn);return True
                wait(connected,6)
                with holder[0] as conn:
                    # Stop the actual management process, leave TLS ingress
                    # and separate relay/agent running. Prove control is down.
                    stop(center_process)
                    assert center_process.poll() is not None
                    with socket.socket() as check:
                        check.settimeout(.5);assert check.connect_ex(("127.0.0.1",cp))!=0
                    assert request("/api/v1/relay/identity",tokens[0])[0] in (502,503,504)
                    exchange_stream(conn)
                    with sqlite3.connect(center/"control.sqlite3") as db:
                        assert db.execute("SELECT expires_at>unixepoch() FROM relay_grants WHERE id=?",(pending_grant["id"],)).fetchone()==(1,)
                    denied=start_offline(pending,pending_grant);fails(denied)
                    assert "relay TCP engine started" not in denied.stdout.read()
                    for n in pending[1:3]:
                        with socket.socket() as check:
                            check.settimeout(.5);assert check.connect_ex(("127.0.0.1",n))!=0
                    exchange_stream(conn)
                    assert running.poll() is None
                    report["real_center_process_loss_preserves_existing_tcp_stream_and_denies_new_claim"]=True
                    out,err=running.communicate(timeout=20)
                    assert running.returncode==0 and out.strip()=="relay TCP engine expired and stopped"
                    conn.settimeout(2)
                    try:
                        conn.sendall(secrets.token_bytes(64))
                        assert conn.recv(1)==b"","expired connection forwarded data"
                    except (ConnectionResetError,BrokenPipeError,ConnectionAbortedError):pass
                for n in active[1:3]:
                    with socket.socket() as check:
                        check.settimeout(.5);assert check.connect_ex(("127.0.0.1",n))!=0
                assert not (dirs[0]/("tcp-"+active_grant["id"]+".toml")).exists()
                report["real_offline_expiry_closes_established_tcp_stream_and_ports"]=True
                # Restore the same center/database/port. Do not rewrite grants
                # or heartbeat times. Wait for real server time and control.
                center_process=subprocess.Popen([str(exe),str(center),str(cp)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=dict(os.environ,LOCALTUNNEL_DNS_RESOLVER=resolver))
                children.append(center_process)
                with selectors.DefaultSelector() as sel:
                    sel.register(center_process.stdout,selectors.EVENT_READ);assert sel.select(20)
                assert center_process.stdout.readline().strip()==f"LISTENING 127.0.0.1:{cp}"
                wait(lambda:request("/api/v1/relay/identity",tokens[0])[0]==200)
                def both_expired():
                    with sqlite3.connect(center/"control.sqlite3") as db:
                        return db.execute("SELECT count(*) FROM relay_grants WHERE id IN (?,?) AND expires_at<=unixepoch()",
                            (active_grant["id"],pending_grant["id"])).fetchone()==(2,)
                wait(both_expired,5)
                # Exact TLS API replay, independent of local port preflight.
                def reject_replay(item,g):
                    a,rp,bp,_=item
                    payload=dict(protocol_version=1,grant_id=g["id"],allocation_id=a["id"],mapping_id=a["mapping_id"],
                        mapping_revision=1,node_id=nodes[0],node_generation=1,generation=2,relay_port=rp,nonce=secrets.token_hex(16))
                    req=urllib.request.Request(f"https://localhost:{tp}/api/v1/relay/tcp-claim",method="POST",
                        headers={"Authorization":"Bearer "+tokens[0],"Content-Type":"application/json"},data=json.dumps(payload).encode())
                    try:
                        with opener.open(req,timeout=4):raise AssertionError("expired claim accepted")
                    except urllib.error.HTTPError as ex:assert ex.code==401
                control(tokens[0],{"protocol_version":1,"node_id":nodes[0],"generation":1,"capacity":5,"nonce":secrets.token_hex(16)},200)
                reject_replay(active,active_grant);reject_replay(pending,pending_grant)
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT claimed_at IS NOT NULL FROM relay_tcp_intents WHERE grant_id=?",(active_grant["id"],)).fetchone()==(1,)
                    assert db.execute("SELECT claimed_at FROM relay_tcp_intents WHERE grant_id=?",(pending_grant["id"],)).fetchone()==(None,)
                    assert db.execute("SELECT count(*) FROM relay_allocations WHERE id IN (?,?) AND state='reserved' AND generation=2",
                        (active[0]["id"],pending[0]["id"])).fetchone()==(2,)
                report["real_center_restart_rejects_expired_claims_and_retains_reservations"]=True
            finally:
                target.shutdown();worker.join(timeout=3)
        # Independent UDP and HTTPS supervisors on two different nodes.
        # Both must forward during actual control loss; killing one supervisor
        # must close its own gateway and engine without stopping the other.
        for i in (0,1):
            control(tokens[i],{"protocol_version":1,"node_id":nodes[i],"generation":1,
                "capacity":i+5,"nonce":secrets.token_hex(16)},200)
        multi_host="offline-secure.example.test"
        multi_domain=admin("domains",{"hostname":multi_host},owner,201)
        records[multi_domain["txt_name"]+"."]=multi_domain["txt_value"]
        assert admin("domains/verify",{"domain_id":multi_domain["id"]},owner)["verified_at"] is not None
        multi_leaf=root/"offline-leaf.pem";multi_key=root/"offline-leaf.key";multi_csr=root/"offline-leaf.csr"
        multi_ext=root/"offline-ext"
        multi_ext.write_text("subjectAltName=DNS:"+multi_host+"\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+multi_host,"-keyout",multi_key,"-out",multi_csr)
        openssl("x509","-req","-in",multi_csr,"-CA",ca,"-CAkey",cak,"-CAcreateserial","-days","2","-extfile",multi_ext,"-out",multi_leaf)
        multi_fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert(multi_leaf.read_text())).hexdigest()
        provision("leaf.pem",multi_leaf);provision("leaf.key",multi_key);provision("web-ca.pem",ca)
        multi_udp_token=secrets.token_hex(32);multi_web_token=secrets.token_hex(32)
        tokens.extend([multi_udp_token,multi_web_token])
        for path,value in ((dirs[0]/"udp.token",multi_udp_token),(dirs[1]/"https.token",multi_web_token)):
            path.write_text(value+"\n");path.chmod(0o600)
        multi_ur=offline_port(30000,59999);multi_ub=offline_port(20001,29999)
        multi_wr=offline_port(30000,59999);multi_wb=offline_port(20001,29999);multi_wg=offline_port(60000,64999)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp_target:
            udp_target.bind(("127.0.0.1",0));udp_target.settimeout(.2)
            # Confirm the actual UDP business port is free, separately from TCP.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1",multi_ub))
            done=threading.Event()
            def echo_multi_udp():
                while not done.is_set():
                    try:
                        data,peer=udp_target.recvfrom(4096)
                        udp_target.sendto(data,peer)
                    except socket.timeout:continue
                    except OSError:return
            udp_thread=threading.Thread(target=echo_multi_udp,daemon=True);udp_thread.start()
            target=http.server.ThreadingHTTPServer(("127.0.0.1",0),WebTarget)
            web_thread=threading.Thread(target=target.serve_forever,daemon=True);web_thread.start()
            try:
                def prepare_multi(i,kind,rp,bp,local,secret,pub,domain=None):
                    spec=dict(request_key=secrets.token_hex(16),device_id=device,node_id=nodes[i],
                        protocol=kind,local_port=local,bind_port=bp)
                    if domain:spec["domain_id"]=domain
                    a=admin("allocations",spec,owner,201)
                    config=root/("multi-"+a["id"]+".toml")
                    subprocess.run([str(core_test.CLI),"client-udp-config" if kind=="udp" else "client-config",
                        str(config),f"127.0.0.1:{rp}","m_"+a["mapping_id"],f"127.0.0.1:{local}"],
                        env=dict(os.environ,LOCALTUNNEL_TOKEN=secret,LOCALTUNNEL_SERVER_PUBLIC_KEY=pub),
                        check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    return a,config
                ua,uc=prepare_multi(0,"udp",multi_ur,multi_ub,udp_target.getsockname()[1],multi_udp_token,public0)
                wa,wc=prepare_multi(1,"https",multi_wr,multi_wb,target.server_port,multi_web_token,public,multi_domain["id"])
                def grant_multi(a,kind,rp,extra=None):
                    g=admin("allocations/"+a["id"]+"/grant",{"expected_generation":1,"expected_mapping_revision":1},owner,201)
                    intent=dict(grant_id=g["id"],expected_generation=2,relay_port=rp)
                    if extra:intent.update(extra)
                    admin("allocations/"+a["id"]+"/"+kind+"-intent",intent,owner,201)
                    return g
                def start_multi(i,kind,a,g,rp,bp,config,extra=()):
                    child=subprocess.Popen([str(relay),"--"+kind+"-preview",str(dirs[i]),"localhost",str(tp),
                        nodes[i],"1",str(i+5),a["id"],a["mapping_id"],"1","2",g["id"],str(rp),str(bp),str(engine),*extra],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    children.append(child)
                    with selectors.DefaultSelector() as sel:
                        sel.register(child.stdout,selectors.EVENT_READ);assert sel.select(5)
                    assert child.stdout.readline().strip()=="relay "+kind.upper()+" engine started"
                    client=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                        env=dict(os.environ,RUST_LOG="warn"))
                    children.append(client)
                    return child,client
                ug=grant_multi(ua,"udp",multi_ur)
                wg=grant_multi(wa,"https",multi_wr,dict(gateway_port=multi_wg,certificate_sha256=multi_fp))
                ur,ucp=start_multi(0,"udp",ua,ug,multi_ur,multi_ub,uc)
                wr,wcp=start_multi(1,"https",wa,wg,multi_wr,multi_wb,wc,(str(multi_wg),multi_host))
                secure_ctx=ssl.create_default_context(cafile=str(ca))
                def multi_web():
                    body="/"+secrets.token_hex(16)
                    try:
                        with socket.create_connection(("127.0.0.1",multi_wg),timeout=.5) as raw:
                            with secure_ctx.wrap_socket(raw,server_hostname=multi_host) as tls:
                                assert hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==multi_fp
                                tls.sendall(("GET "+body+" HTTP/1.1\r\nHost: "+multi_host+"\r\nConnection: close\r\n\r\n").encode())
                                with http.client.HTTPResponse(tls) as response:
                                    response.begin()
                                    if response.status!=200:return False
                                    return json.loads(response.read())=={"path":body,"host":multi_host,"xff":"127.0.0.1","proto":"https","forwarded":None}
                    except (OSError,http.client.HTTPException):return False
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(.5)
                    def multi_udp():
                        body=secrets.token_bytes(48)
                        try:
                            client.sendto(body,("127.0.0.1",multi_ub))
                            return client.recvfrom(4096)==(body,("127.0.0.1",multi_ub))
                        except OSError:return False
                    wait(lambda:multi_udp() and multi_web(),7)
                    assert all(p.poll() is None for p in (ur,wr,ucp,wcp))
                    stop(center_process)
                    assert center_process.poll() is not None
                    assert request("/api/v1/relay/identity",tokens[0])[0] in (502,503,504)
                    assert multi_udp() and multi_web()
                    report["real_two_independent_nodes_udp_https_forward_during_center_loss"]=True
                    # Verify exactly two test-owned direct child executables,
                    # not arbitrary PIDs or processes discovered by name.
                    def owned_children(p):
                        found=set()
                        for task in (Path("/proc")/str(p.pid)/"task").iterdir():
                            try:found.update(int(n) for n in (task/"children").read_text().split())
                            except FileNotFoundError:pass
                        return found
                    direct=owned_children(wr)
                    assert len(direct)==2
                    binaries={(Path("/proc")/str(pid)/"exe").resolve() for pid in direct}
                    assert binaries=={engine.resolve(),Path("/usr/sbin/nginx").resolve()}
                    wr.kill();assert wr.wait(timeout=3)!=0
                    def closed_web():
                        for port in (multi_wr,multi_wb,multi_wg):
                            with socket.socket() as probe:
                                probe.settimeout(.2)
                                if probe.connect_ex(("127.0.0.1",port))==0:return False
                        # Reparented zombies are already dead, so not live
                        # children. Check state rather than PID existence alone.
                        for pid in direct:
                            try:
                                stat=(Path("/proc")/str(pid)/"stat").read_text()
                                if stat.rsplit(")",1)[1].split()[0]!="Z":return False
                            except FileNotFoundError:pass
                        return True
                    wait(closed_web,3)
                    assert not multi_web()
                    assert ur.poll() is None and ucp.poll() is None and multi_udp()
                    # SIGKILL bypasses RAII cleanup: preserve crash evidence,
                    # never treat missing heartbeat as resource release.
                    assert (dirs[1]/("https-"+wg["id"]+".gateway")).is_dir()
                    assert (dirs[1]/("https-"+wg["id"]+".toml")).is_file()
                    report["real_https_supervisor_sigkill_closes_owned_gateway_and_engine_other_node_survives"]=True
                    out,err=ur.communicate(timeout=20)
                    assert ur.returncode==0 and out.strip()=="relay UDP engine expired and stopped"
                    assert not any(t in out+err for t in tokens)
                    assert not multi_udp()
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        probe.bind(("127.0.0.1",multi_ub))
                    with socket.socket() as probe:
                        probe.settimeout(.5);assert probe.connect_ex(("127.0.0.1",multi_ur))!=0
                    assert not (dirs[0]/("udp-"+ug["id"]+".toml")).exists()
                    with sqlite3.connect(center/"control.sqlite3") as db:
                        for table,g in (("relay_udp_intents",ug),("relay_https_intents",wg)):
                            assert db.execute("SELECT claimed_at IS NOT NULL FROM "+table+" WHERE grant_id=?",(g["id"],)).fetchone()==(1,)
                        assert db.execute("SELECT count(*) FROM relay_allocations WHERE id IN (?,?) AND state='reserved' AND generation=2",
                            (ua["id"],wa["id"])).fetchone()==(2,)
                    report["real_offline_udp_expiry_closes_datagram_port_and_retains_crash_reservation"]=True
                center_process=subprocess.Popen([str(exe),str(center),str(cp)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=dict(os.environ,LOCALTUNNEL_DNS_RESOLVER=resolver))
                children.append(center_process)
                with selectors.DefaultSelector() as sel:
                    sel.register(center_process.stdout,selectors.EVENT_READ);assert sel.select(20)
                assert center_process.stdout.readline().strip()==f"LISTENING 127.0.0.1:{cp}"
                wait(lambda:request("/api/v1/relay/identity",tokens[0])[0]==200)
                # Recheck exact consumed HTTPS claim via TLS after recovery,
                # not merely local retained configuration or port conflicts.
                control(tokens[1],{"protocol_version":1,"node_id":nodes[1],"generation":1,"capacity":6,"nonce":secrets.token_hex(16)},200)
                payload=dict(protocol_version=1,grant_id=wg["id"],allocation_id=wa["id"],mapping_id=wa["mapping_id"],
                    mapping_revision=1,node_id=nodes[1],node_generation=1,generation=2,relay_port=multi_wr,
                    gateway_port=multi_wg,hostname=multi_host,certificate_sha256=multi_fp,nonce=secrets.token_hex(16))
                req=urllib.request.Request(f"https://localhost:{tp}/api/v1/relay/https-claim",method="POST",
                    headers={"Authorization":"Bearer "+tokens[1],"Content-Type":"application/json"},data=json.dumps(payload).encode())
                try:
                    with opener.open(req,timeout=4):raise AssertionError("crashed HTTPS claim replay accepted")
                except urllib.error.HTTPError as ex:assert ex.code==401
                report["real_crashed_https_claim_rejected_after_center_recovery"]=True
            finally:
                target.shutdown();target.server_close();web_thread.join(timeout=3)
                done.set();udp_thread.join(timeout=3)
        # Real independent TLS budget verifier, without any business listener.
        finite=cmd("--commercial-create-plan",data={"code":"finite-relay","version":1,"name":"Finite relay",
            "max_active_devices":4,"max_retained_devices":8,"max_mappings":8,"max_bandwidth_bps":1048576,
            "max_monthly_bytes":100000,"max_concurrent_connections":4})
        cmd("--commercial-create-account",data={"username":"finite","password":password,"plan_id":finite,"expires_at":None})
        finite_owner=admin("auth/login",{"username":"finite","password":password})["access_token"];tokens.append(finite_owner)
        pairing=admin("devices/pairing-code",None,finite_owner)["pairing_code"]
        finite_device=admin("devices/enroll",{"pairing_code":pairing,"name":"budget fixture"},status=201)["id"]
        control(tokens[0],{"protocol_version":1,"node_id":nodes[0],"generation":1,"capacity":5,"nonce":secrets.token_hex(16)},200)
        bp=offline_port(20001,29999)
        a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":finite_device,"node_id":nodes[0],
            "protocol":"tcp","local_port":8080,"bind_port":bp},finite_owner,201)
        spec=dict(expected_generation=1,expected_mapping_revision=1,expected_entitlement_revision=1)
        admin("allocations/"+a["id"]+"/budget-preview",dict(spec,rate_bytes_per_second=65536,monthly_bytes=50000,connection_slots=2),finite_owner,201)
        g=admin("allocations/"+a["id"]+"/budget-grant",spec,finite_owner,201)["grant"]
        def verify_budget(rate="65536"):
            child=subprocess.Popen([str(relay),"--verify-budget",str(dirs[0]),"localhost",str(tp),nodes[0],"1","5",
                a["id"],a["mapping_id"],"1","2",g["id"],str(bp),rate,"50000","2"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(child);return child
        rp=offline_port(30000,59999)
        admin("allocations/"+a["id"]+"/budget-intent",dict(grant_id=g["id"],expected_generation=2,relay_port=rp),finite_owner,201)
        def claim_budget(directory=dirs[0],port=rp):
            child=subprocess.Popen([str(relay),"--claim-budget",str(directory),"localhost",str(tp),nodes[0],"1","5",
                a["id"],a["mapping_id"],"1","2",g["id"],str(bp),"65536","50000","2",str(port)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(child);return child
        marker=dirs[0]/("budget-consumed-"+g["id"])
        bad=verify_budget("65537");fails(bad)
        assert "relay budget preview verified" not in bad.stdout.read()
        good=verify_budget()
        with selectors.DefaultSelector() as sel:
            sel.register(good.stdout,selectors.EVENT_READ);assert sel.select(5)
        assert good.stdout.readline().strip()=="relay budget preview verified"
        # A foreign or partial marker must fail closed without consuming the
        # center claim. Only this test removes its own synthetic symlink.
        marker.symlink_to(dirs[0]/"relay.token")
        fails(claim_budget())
        assert marker.is_symlink()
        marker.unlink()
        with sqlite3.connect(center/"control.sqlite3") as db:
            assert db.execute("SELECT claimed_at FROM relay_budget_intents WHERE grant_id=?",(g["id"],)).fetchone()==(None,)
        claim=claim_budget()
        out_claim,err_claim=claim.communicate(timeout=8)
        assert claim.returncode==0 and out_claim.strip()=="relay budget claim consumed"
        assert marker.is_file() and not marker.is_symlink() and marker.stat().st_mode&0o777==0o600
        assert marker.read_bytes()==b"budget claim consumed; non-executable\n"
        fails(claim_budget())
        with sqlite3.connect(center/"control.sqlite3") as db:
            assert db.execute("SELECT claimed_at IS NOT NULL FROM relay_budget_intents WHERE grant_id=?",(g["id"],)).fetchone()==(1,)
        for port in (rp,bp):
            with socket.socket() as check:
                check.settimeout(.5);assert check.connect_ex(("127.0.0.1",port))!=0
        assert not any(t in out_claim+err_claim for t in tokens)
        report["real_tls_finite_budget_one_shot_durable_node_consumption_without_listener"]=True
        with socket.socket() as check:
            check.settimeout(.5);assert check.connect_ex(("127.0.0.1",bp))!=0
        out,err=good.communicate(timeout=20)
        assert good.returncode==0 and out.strip()=="relay budget preview expired"
        assert not any(t in out+err for t in tokens)
        wait(lambda:time.time()>=g["expires_at"],5)
        fails(verify_budget())
        fails(claim_budget())
        assert marker.is_file()
        report["real_tls_finite_budget_node_verification_and_expiry_without_listener"]=True
        # Fresh explicit opt-in: existing observation or guarded previews
        # cannot be promoted. Use the remaining reserved plan slice.
        with socketserver.ThreadingTCPServer(("127.0.0.1",0),Stream) as target:
            target.daemon_threads=True
            worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
            try:
                br,bf=offline_port(30000,59999),offline_port(20001,29999)
                control(tokens[0],{"protocol_version":1,"node_id":nodes[0],"generation":1,"capacity":5,"nonce":secrets.token_hex(16)},200)
                a2=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":finite_device,"node_id":nodes[0],
                    "protocol":"tcp","local_port":target.server_address[1],"bind_port":bf},finite_owner,201)
                admin("allocations/"+a2["id"]+"/budget-preview",dict(spec,rate_bytes_per_second=65536,monthly_bytes=4096,connection_slots=1),finite_owner,201)
                service_token=secrets.token_hex(32);tokens.append(service_token)
                secret=dirs[0]/"budget-tcp.token";secret.write_text(service_token+"\n");secret.chmod(0o600)
                config=root/"finite-client.toml"
                subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{br}","m_"+a2["mapping_id"],f"127.0.0.1:{target.server_address[1]}"],
                    env=dict(os.environ,LOCALTUNNEL_TOKEN=service_token,LOCALTUNNEL_SERVER_PUBLIC_KEY=public0),
                    check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                g2=admin("allocations/"+a2["id"]+"/budget-grant",spec,finite_owner,201)["grant"]
                admin("allocations/"+a2["id"]+"/budget-start-intent",dict(grant_id=g2["id"],expected_generation=2,relay_port=br),finite_owner,201)
                args=[str(relay),"--budget-tcp-preview",str(dirs[0]),"localhost",str(tp),nodes[0],"1","5",a2["id"],a2["mapping_id"],"1","2",g2["id"],str(bf),"65536","4096","1",str(br),str(engine)]
                def start_finite():
                    p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(p);return p
                finite_relay=start_finite()
                with selectors.DefaultSelector() as sel:
                    sel.register(finite_relay.stdout,selectors.EVENT_READ);assert sel.select(5)
                assert finite_relay.stdout.readline().strip()=="relay finite TCP engine started"
                agent=subprocess.Popen([str(engine),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,RUST_LOG="warn"));children.append(agent)
                connected=[]
                def connect_finite():
                    try:
                        c=socket.create_connection(("127.0.0.1",bf),timeout=.5)
                        try:
                            c.sendall(b"budget-echo");data=c.recv(11)
                            if data!=b"budget-echo":c.close();return False
                            connected.append(c);return True
                        except OSError:c.close();return False
                    except OSError:return False
                wait(connect_finite,6)
                with connected[0] as c:
                    c.settimeout(3)
                    c.sendall(b"x"*8192)
                    try:
                        while c.recv(4096):pass
                    except (ConnectionResetError,BrokenPipeError):pass
                out,err=finite_relay.communicate(timeout=5)
                assert finite_relay.returncode==0 and out.strip()=="relay finite TCP stopped reason=exhausted bytes=4096"
                stop(agent)
                fails(start_finite())
                for port in (br,bf):
                    with socket.socket() as check:
                        check.settimeout(.5);assert check.connect_ex(("127.0.0.1",port))!=0
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT execution_opt_in,claimed_at IS NOT NULL FROM relay_budget_intents WHERE grant_id=?",(g2["id"],)).fetchone()==(1,1)
                assert (dirs[0]/("budget-consumed-"+g2["id"])).is_file()
                report["real_tls_guarded_noise_tcp_budget_exhaustion_and_replay_rejection"]=True
                # Actual stopped finite engine: a node observation must be
                # fenced, exact-bound, authenticated and never release quota.
                route="allocations/"+a2["id"]
                cleanup_args=[str(relay),"--report-budget-cleanup",str(dirs[0]),"localhost",str(tp),nodes[0],"1","5",
                    a2["id"],a2["mapping_id"],"1","3",g2["id"],str(br),str(bf)]
                def report_cleanup():
                    proc=subprocess.Popen(cleanup_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    children.append(proc);return proc
                fails(report_cleanup())
                confirmation="offline_engine_and_guard_verified_stopped"
                def reclaim_cmd(grant_id=g2["id"],confirm=confirmation):
                    return subprocess.run([str(exe),"--recover-relay-budget",str(center),a2["id"],grant_id,confirm],
                        text=True,capture_output=True,timeout=15)
                assert reclaim_cmd().returncode!=0
                def retire_cmd(grant_id=g2["id"],confirm="offline_ports_and_engine_verified_stopped"):
                    return subprocess.run([str(exe),"--retire-relay-budget",str(center),a2["id"],grant_id,confirm],
                        text=True,capture_output=True,timeout=15)
                assert retire_cmd().returncode!=0
                wait(lambda:time.time()>=g2["expires_at"]+2,20)
                fence=admin(route+"/fence",dict(expected_generation=2,grant_id=g2["id"]),finite_owner,201)
                assert fence["fence"]["new_generation"]==3
                payload=dict(protocol_version=1,allocation_id=a2["id"],grant_id=g2["id"],node_id=nodes[0],
                    node_generation=1,fenced_generation=3,relay_port=br,bind_port=bf,nonce=secrets.token_hex(16))
                def submit_report(token,data,status):
                    req=urllib.request.Request(f"https://localhost:{tp}/api/v1/relay/budget-cleanup-report",method="POST",
                        headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},data=json.dumps(data).encode())
                    try:
                        with opener.open(req,timeout=4) as r:
                            assert r.status==status
                            return json.load(r)
                    except urllib.error.HTTPError as e:assert e.code==status
                submit_report(tokens[1],payload,401)
                submit_report(tokens[0],dict(payload,bind_port=bf+1 if bf<29999 else bf-1),401)
                with socket.socket() as occupied:
                    # Match the Linux Rust/Tokio listener's SO_REUSEADDR:
                    # prior accepted connections may still be in TIME_WAIT.
                    # Never set SO_REUSEPORT; an actual listening socket
                    # must still prevent the node's exclusive bind probe.
                    occupied.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    occupied.bind(("127.0.0.1",br));occupied.listen()
                    assert occupied.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1
                    fails(report_cleanup())
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT count(*) FROM relay_cleanup_reports").fetchone()==(0,)
                for _ in range(2):
                    proc=report_cleanup();out,err=proc.communicate(timeout=8)
                    assert proc.returncode==0 and out.strip()=="relay cleanup observation recorded; resources retained"
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT count(*) FROM relay_cleanup_reports").fetchone()==(1,)
                    assert db.execute("SELECT count(*) FROM management_audit WHERE event='allocation.cleanup_observed'").fetchone()==(1,)
                    assert db.execute("SELECT monthly_bytes FROM relay_budget_previews WHERE allocation_id=?",(a2["id"],)).fetchone()==(4096,)
                    for sql in ("DELETE FROM relay_cleanup_reports","UPDATE relay_cleanup_reports SET reported_at=reported_at+1"):
                        try:db.execute(sql);raise AssertionError("mutable cleanup report")
                        except sqlite3.IntegrityError:db.rollback()
                req=urllib.request.Request(f"http://127.0.0.1:{cp}/api/v1/"+route+"/cleanup-report",
                    headers={"Authorization":"Bearer "+finite_owner})
                with urllib.request.urlopen(req,timeout=4) as response:
                    row=json.load(response)
                    assert row["report"]["grant_id"]==g2["id"] and row["resources_released"] is False and row["executable"] is False
                assert submit_report(tokens[0],payload,200)["report"]==row["report"]
                report["real_tls_fenced_cleanup_observation_idempotent_no_release"]=True
                assert reclaim_cmd(confirm="unverified").returncode!=0
                assert reclaim_cmd(grant_id=secrets.token_hex(16)).returncode!=0
                # Node report is not an automatic refund.
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT count(*) FROM relay_budget_reclaims").fetchone()==(0,)
                recovered=reclaim_cmd()
                assert recovered.returncode==0
                again=reclaim_cmd()
                assert again.returncode==0 and json.loads(again.stdout)==json.loads(recovered.stdout)
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT count(*) FROM relay_budget_reclaims").fetchone()==(1,)
                    assert db.execute("SELECT count(*) FROM management_audit WHERE event='budget.capacity_reclaimed'").fetchone()==(1,)
                    assert db.execute("SELECT count(*) FROM relay_budget_active WHERE allocation_id=?",(a2["id"],)).fetchone()==(0,)
                    assert db.execute("SELECT monthly_bytes FROM relay_budget_previews WHERE allocation_id=?",(a2["id"],)).fetchone()==(4096,)
                    assert db.execute("SELECT generation,state FROM relay_allocations WHERE id=?",(a2["id"],)).fetchone()==(3,"reserved")
                    for sql in ("DELETE FROM relay_budget_reclaims","UPDATE relay_budget_reclaims SET reclaimed_at=reclaimed_at+1"):
                        try:db.execute(sql);raise AssertionError("mutable reclaim")
                        except sqlite3.IntegrityError:db.rollback()
                req=urllib.request.Request(f"http://127.0.0.1:{cp}/api/v1/"+route+"/budget-reclaim",headers={"Authorization":"Bearer "+finite_owner})
                with urllib.request.urlopen(req,timeout=4) as response:
                    row=json.load(response)
                    assert row["ports_released"] is False and row["monthly_refunded"] is False and row["reclaim"]==json.loads(recovered.stdout)
                assert retire_cmd(confirm="unverified").returncode!=0
                assert retire_cmd(grant_id=secrets.token_hex(16)).returncode!=0
                retired=retire_cmd()
                assert retired.returncode==0
                again=retire_cmd()
                assert again.returncode==0 and json.loads(again.stdout)==json.loads(retired.stdout)
                with sqlite3.connect(center/"control.sqlite3") as db:
                    assert db.execute("SELECT generation,state,live_mapping_id FROM relay_allocations WHERE id=?",(a2["id"],)).fetchone()==(4,"cancelled",None)
                    assert db.execute("SELECT count(*) FROM mappings WHERE id=?",(a2["mapping_id"],)).fetchone()==(0,)
                    assert db.execute("SELECT count(*) FROM relay_budget_intents WHERE grant_id=?",(g2["id"],)).fetchone()==(0,)
                    assert db.execute("SELECT relay_port,bind_port,new_generation FROM relay_budget_retirements WHERE allocation_id=?",(a2["id"],)).fetchone()==(br,bf,4)
                    assert db.execute("SELECT count(*) FROM management_audit WHERE event='allocation.budget_retired'").fetchone()==(1,)
                    assert db.execute("SELECT monthly_bytes FROM relay_budget_previews WHERE allocation_id=?",(a2["id"],)).fetchone()==(4096,)
                    for sql in ("DELETE FROM relay_budget_retirements","UPDATE relay_budget_retirements SET relay_port=31000","UPDATE relay_allocations SET generation=3 WHERE id IN (SELECT allocation_id FROM relay_budget_retirements)"):
                        try:db.execute(sql);raise AssertionError("mutable retirement")
                        except sqlite3.IntegrityError:db.rollback()
                    assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
                fails(start_finite())
                req=urllib.request.Request(f"http://127.0.0.1:{cp}/api/v1/"+route+"/budget-retirement",headers={"Authorization":"Bearer "+finite_owner})
                with urllib.request.urlopen(req,timeout=4) as response:
                    row=json.load(response)
                    assert row["ports_released"] is True and row["monthly_refunded"] is False and row["retirement"]==json.loads(retired.stdout)
            finally:
                target.shutdown();target.server_close();worker.join(timeout=3)
        # D: two independently supervised real Noise tunnels from one finite
        # tenant, with disjoint slices saturating every commercial cap.
        # Refresh node 0's advertised capacity for the additional fixture.
        stop(live[0]);live[0]=start(dirs[0],0,capacity=8)
        cmd("--set-node-policy",nodes[2],2,9,"east","active")
        for i,cap in ((0,8),(2,7)):
            control(tokens[i],dict(protocol_version=1,node_id=nodes[i],generation=1,capacity=cap,nonce=secrets.token_hex(16)),200)
        # The reclaimed rate/slot capacity can be reserved again on another
        # node, but the previous monthly slice must remain fully charged.
        new_a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":finite_device,"node_id":nodes[0],
            "protocol":"tcp","local_port":8080,"bind_port":bf},finite_owner,201)
        assert new_a["mapping_id"]!=a2["mapping_id"] and new_a["id"]!=a2["id"]
        try:
            admin("allocations/"+new_a["id"]+"/budget-preview",dict(spec,rate_bytes_per_second=65536,monthly_bytes=45905,connection_slots=2),finite_owner,201)
            raise AssertionError("reclaimed monthly slice refunded")
        except urllib.error.HTTPError as ex:assert ex.code==409
        admin("allocations/"+new_a["id"]+"/budget-preview",dict(spec,rate_bytes_per_second=65536,monthly_bytes=45904,connection_slots=2),finite_owner,201)
        with sqlite3.connect(center/"control.sqlite3") as db:
            assert db.execute("SELECT sum(rate_bytes_per_second),sum(connection_slots) FROM relay_budget_active WHERE allocation_id IN (?,?,?)",
                (a["id"],a2["id"],new_a["id"])).fetchone()==(131072,4)
            assert db.execute("SELECT sum(monthly_bytes) FROM relay_budget_previews WHERE allocation_id IN (?,?,?)",
                (a["id"],a2["id"],new_a["id"])).fetchone()==(100000,)
        report["real_operator_reclaims_rate_slots_without_monthly_refund"]=True
        control(tokens[0],dict(protocol_version=1,node_id=nodes[0],generation=1,capacity=8,nonce=secrets.token_hex(16)),200)
        new_g=admin("allocations/"+new_a["id"]+"/budget-grant",spec,finite_owner,201)["grant"]
        assert new_g["id"]!=g2["id"]
        new_intent=admin("allocations/"+new_a["id"]+"/budget-start-intent",dict(grant_id=new_g["id"],expected_generation=2,relay_port=br),finite_owner,201)
        assert new_intent["intent"]["relay_port"]==br and new_intent["intent"]["bind_port"]==bf
        report["real_terminal_finite_retirement_and_port_reuse"]=True
        cmd("--commercial-create-account",data={"username":"finite-dual","password":password,"plan_id":finite,"expires_at":None})
        dual_owner=admin("auth/login",{"username":"finite-dual","password":password})["access_token"];tokens.append(dual_owner)
        pairing=admin("devices/pairing-code",None,dual_owner)["pairing_code"]
        dual_device=admin("devices/enroll",{"pairing_code":pairing,"name":"dual budget fixture"},status=201)["id"]
        with socketserver.ThreadingTCPServer(("127.0.0.1",0),Stream) as target:
            target.daemon_threads=True
            worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start()
            try:
                items=[]
                for i,cap,monthly,slots in ((0,8,4096,1),(2,7,95904,3)):
                    rp,bp=offline_port(30000,59999),offline_port(20001,29999)
                    a=admin("allocations",{"request_key":secrets.token_hex(16),"device_id":dual_device,"node_id":nodes[i],
                        "protocol":"tcp","local_port":target.server_address[1],"bind_port":bp},dual_owner,201)
                    admin("allocations/"+a["id"]+"/budget-preview",dict(spec,rate_bytes_per_second=65536,
                        monthly_bytes=monthly,connection_slots=slots),dual_owner,201)
                    keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
                    private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
                    public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
                    secret=secrets.token_hex(32);tokens.extend([private,secret])
                    # Distinct node credentials and state directories.
                    d=directory("dual-finite-"+str(i),tokens[i])
                    for name,value in (("noise.private",private),("budget-tcp.token",secret)):
                        path=d/name;path.write_text(value+"\n");path.chmod(0o600)
                    config=root/("dual-finite-"+str(i)+".toml")
                    subprocess.run([str(core_test.CLI),"client-config",str(config),f"127.0.0.1:{rp}","m_"+a["mapping_id"],
                        f"127.0.0.1:{target.server_address[1]}"],env=dict(os.environ,LOCALTUNNEL_TOKEN=secret,LOCALTUNNEL_SERVER_PUBLIC_KEY=public),
                        check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    items.append(dict(i=i,cap=cap,a=a,rp=rp,bp=bp,monthly=monthly,slots=slots,d=d,config=config))
                for item in items:
                    i=item["i"];a=item["a"]
                    control(tokens[i],dict(protocol_version=1,node_id=nodes[i],generation=1,capacity=item["cap"],nonce=secrets.token_hex(16)),200)
                    g=admin("allocations/"+a["id"]+"/budget-grant",spec,dual_owner,201)["grant"]
                    admin("allocations/"+a["id"]+"/budget-start-intent",dict(grant_id=g["id"],expected_generation=2,relay_port=item["rp"]),dual_owner,201)
                    item["grant"]=g
                    item["args"]=[str(relay),"--budget-tcp-preview",str(item["d"]),"localhost",str(tp),nodes[i],"1",str(item["cap"]),
                        a["id"],a["mapping_id"],"1","2",g["id"],str(item["bp"]),"65536",str(item["monthly"]),str(item["slots"]),str(item["rp"]),str(engine)]
                def launch(item):
                    proc=subprocess.Popen(item["args"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(proc);return proc
                for item in items:item["proc"]=launch(item)
                for item in items:
                    proc=item["proc"]
                    with selectors.DefaultSelector() as sel:
                        sel.register(proc.stdout,selectors.EVENT_READ);assert sel.select(5)
                    assert proc.stdout.readline().strip()=="relay finite TCP engine started"
                    client=subprocess.Popen([str(engine),str(item["config"])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,RUST_LOG="warn"))
                    children.append(client);item["client"]=client
                def echo(conn,body):
                    conn.sendall(body)
                    received=bytearray()
                    while len(received)<len(body):
                        chunk=conn.recv(len(body)-len(received))
                        if not chunk:raise OSError("finite echo closed")
                        received.extend(chunk)
                    assert received==body
                def connect_item(item):
                    if item.get("conn") is not None:return True
                    try:
                        c=socket.create_connection(("127.0.0.1",item["bp"]),timeout=.5)
                        try:echo(c,b"dual-finite-echo")
                        except (OSError,AssertionError):c.close();return False
                        item["conn"]=c;return True
                    except OSError:return False
                try:
                    wait(lambda:all(connect_item(item) for item in items),6)
                    first,second=items
                    assert all(item["proc"].poll() is None for item in items)
                    with sqlite3.connect(center/"control.sqlite3") as db:
                        assert db.execute("SELECT sum(rate_bytes_per_second),sum(monthly_bytes),sum(connection_slots) FROM relay_budget_previews WHERE allocation_id IN (?,?)",
                            tuple(item["a"]["id"] for item in items)).fetchone()==(131072,100000,4)
                        assert db.execute("SELECT count(DISTINCT node_id),count(*) FROM relay_budget_intents WHERE grant_id IN (?,?) AND claimed_at IS NOT NULL AND execution_opt_in=1",
                            tuple(item["grant"]["id"] for item in items)).fetchone()==(2,2)
                    # Exhaust only the first node's slice. The second must
                    # still carry a real established encrypted stream.
                    c=first["conn"];c.settimeout(3);c.sendall(b"x"*8192)
                    try:
                        while c.recv(4096):pass
                    except (ConnectionResetError,BrokenPipeError):pass
                    out,err=first["proc"].communicate(timeout=5)
                    assert first["proc"].returncode==0 and out.strip()=="relay finite TCP stopped reason=exhausted bytes=4096"
                    assert second["proc"].poll() is None
                    echo(second["conn"],b"survives-other-node")
                    for n in (first["rp"],first["bp"]):
                        with socket.socket() as probe:
                            probe.settimeout(.5);assert probe.connect_ex(("127.0.0.1",n))!=0
                    fails(launch(first))
                    # The surviving stream must close at its own lease,
                    # not consume the other node's unused allocation.
                    out,err=second["proc"].communicate(timeout=20)
                    assert second["proc"].returncode==0
                    match=re.fullmatch(r"relay finite TCP stopped reason=expired bytes=(\d+)",out.strip())
                    assert match and 2*(len(b"dual-finite-echo")+len(b"survives-other-node"))<=int(match.group(1))<second["monthly"]
                    second["conn"].settimeout(2)
                    try:assert second["conn"].recv(1)==b""
                    except ConnectionResetError:pass
                    fails(launch(second))
                    for item in items:
                        stop(item["client"])
                        assert (item["d"]/("budget-consumed-"+item["grant"]["id"])).is_file()
                        for n in (item["rp"],item["bp"]):
                            with socket.socket() as probe:
                                probe.settimeout(.5);assert probe.connect_ex(("127.0.0.1",n))!=0
                    with sqlite3.connect(center/"control.sqlite3") as db:
                        assert db.execute("SELECT sum(monthly_bytes),sum(connection_slots) FROM relay_budget_previews WHERE allocation_id IN (?,?)",
                            tuple(item["a"]["id"] for item in items)).fetchone()==(100000,4)
                        assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
                    report["real_dual_node_guarded_tcp_budget_isolation_and_expiry"]=True
                finally:
                    for item in items:
                        if item.get("conn") is not None:item["conn"].close()
                        for key in ("proc","client"):
                            if item.get(key) is not None:stop(item[key])
            finally:
                target.shutdown();target.server_close();worker.join(timeout=3)
        dns.shutdown();dns_thread.join(timeout=3)
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
assert len(report)==30 and all(report.values())
