"""Real TLS gateway, three actual relay binaries and negative trust checks."""
import json
import os
from pathlib import Path
import secrets
import selectors
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
        cmd("--init-admin",data={"username":"owner","password":secrets.token_hex(24)})
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
assert len(report)==4 and all(report.values())
