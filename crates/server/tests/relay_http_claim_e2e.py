"""Real DNS proof and HTTP claim isolation."""
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import os
import socketserver
import struct
import threading
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
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,LOCALTUNNEL_DNS_RESOLVER=resolver))
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
        worker=threading.Thread(target=dns.serve_forever,daemon=True);worker.start()
        resolver="127.0.0.1:"+str(dns.server_address[1])
        root=Path(tmp)/"live";root.mkdir(mode=0o700)
        cmd(root,"--init-admin",data={"username":"owner","password":password})
        cmd(root,"--commercial-create-account",data={"username":"other","password":password,"plan_id":"legacy-v1","expires_at":None})
        nodes=[cmd(root,"--add-node","HTTP relay "+str(i)) for i in range(2)]
        tokens=[cmd(root,"--relay-issue",n) for n in nodes]
        for n in nodes:cmd(root,"--set-node-policy",n,1,8,"east","active")
        p,base=launch(root)
        try:
            owner=login(base,"owner");other=login(base,"other");did=device(base,owner)
            def beat():
                call(base,"relay/heartbeat",204,tokens[0],"POST",{"protocol_version":1,"generation":1,"capacity":8})
            def domain(host):
                return call(base,"domains",201,owner,"POST",{"hostname":host})[1]
            def verify(d):
                records[d["txt_name"]+"."]=d["txt_value"]
                result=call(base,"domains/verify",200,owner,"POST",{"domain_id":d["id"]})[1]
                assert result["verified_at"] is not None
            def allocation(port,kind,d=None):
                beat()
                spec=dict(request_key=secrets.token_hex(16),device_id=did,protocol=kind,local_port=8080,bind_port=port,node_id=nodes[0])
                if d:spec["domain_id"]=d["id"]
                return call(base,"allocations",201,owner,"POST",spec)[1]
            def grant(a,status=201):
                beat()
                return call(base,"allocations/"+a["id"]+"/grant",status,owner,"POST",{"expected_generation":1,"expected_mapping_revision":1})[1]
            def intent(g,relay_port,gateway_port,status=201,token=owner):
                return call(base,"allocations/"+g["allocation_id"]+"/http-intent",status,token,"POST",{"grant_id":g["id"],"expected_generation":g["generation"],"relay_port":relay_port,"gateway_port":gateway_port})[1]
            def payload(g,host,relay_port,gateway_port):
                return dict({k:g[k] for k in ("allocation_id","mapping_id","mapping_revision","node_id","node_generation","generation")},protocol_version=1,grant_id=g["id"],relay_port=relay_port,gateway_port=gateway_port,hostname=host,nonce=secrets.token_hex(16))
            def claim(q,status=200,token=tokens[0]):
                return call(base,"relay/http-claim",status,token,"POST",q)
            d=domain("web.example.test")
            a=allocation(20000,"http",d)
            grant(a,409)
            verify(d)
            g=grant(a);q=payload(g,d["hostname"],31000,61000)
            claim(q,401)
            intent(g,31000,61000,409,other)
            intent(g,31000,61000,401,tokens[0])
            call(base,"allocations/"+a["id"]+"/tcp-intent",409,owner,"POST",{"grant_id":g["id"],"expected_generation":2,"relay_port":31000})
            result=intent(g,31000,61000)
            assert result["hostname"]==d["hostname"] and result["bind_port"]==20000 and "proof_token" not in result
            claim(dict(q,hostname="other.example.test"),401)
            claim(dict(q,gateway_port=61001),401)
            claim(q,401,tokens[1]);claim(q,401,owner)
            with ThreadPoolExecutor(max_workers=2) as pool:
                answers=list(pool.map(lambda _:claim(q,(200,401)),range(2)))
            assert sorted(x[0] for x in answers)==[200,401]
            result=next(x[1] for x in answers if x[0]==200)
            assert result["scope"]=="http_loopback_start_claim" and result["nonce"]==q["nonce"]
            permit=result["permit"]
            assert permit["hostname"]==d["hostname"] and permit["gateway_port"]==61000 and permit["expires_at"]==g["expires_at"]
            assert "proof_token" not in permit
            claim(q,401)
            report["real_http_dns_proof_exact_claim_and_protocol_isolation"]=True
            tcp=allocation(20001,"tcp");tg=grant(tcp)
            call(base,"allocations/"+tcp["id"]+"/tcp-intent",409,owner,"POST",{"grant_id":tg["id"],"expected_generation":2,"relay_port":31000})
            call(base,"allocations/"+tcp["id"]+"/tcp-intent",201,owner,"POST",{"grant_id":tg["id"],"expected_generation":2,"relay_port":31001})
            d2=domain("second.example.test");verify(d2)
            a2=allocation(20002,"http",d2);g2=grant(a2)
            intent(g2,31001,61001,409)
            intent(g2,31002,61000,409)
            intent(g2,31002,61001)
            q2=payload(g2,d2["hostname"],31002,61001)
            new=call(base,"domains/"+d2["id"]+"/challenge",200,owner,"POST")[1]
            claim(q2,401)
            verify(new);beat();claim(q2,401)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_http_intents").fetchone()==(2,)
                assert db.execute("SELECT count(*) FROM relay_http_intents WHERE claimed_at IS NOT NULL").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='http.claimed'").fetchone()==(1,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            assert "_localtunnel."+d["hostname"]+"." in queries
            report["real_http_proof_rotation_and_shared_transport_port_denial"]=True
            # HTTPS requires its own exact leaf fingerprint and permit.
            d3=domain("secure.example.test")
            a3=allocation(20003,"https",d3)
            grant(a3,409);verify(d3)
            g3=grant(a3)
            fp=secrets.token_hex(32)
            def tls_intent(rp,gp,status=201,fingerprint=fp,token=owner):
                return call(base,"allocations/"+a3["id"]+"/https-intent",status,token,"POST",
                    {"grant_id":g3["id"],"expected_generation":2,"relay_port":rp,"gateway_port":gp,"certificate_sha256":fingerprint})[1]
            intent(g3,31003,61003,409)
            tls_intent(31000,61003,409)
            tls_intent(31003,61000,409)
            tls_intent(31003,61003,400,"z"*64)
            tls_intent(31003,61003,409,token=other)
            r=tls_intent(31003,61003)
            assert r["certificate_sha256"]==fp and r["hostname"]==d3["hostname"]
            q3=dict(payload(g3,d3["hostname"],31003,61003),certificate_sha256=fp)
            def tls_claim(q,status=200,token=tokens[0]):
                return call(base,"relay/https-claim",status,token,"POST",q)
            claim(payload(g3,d3["hostname"],31003,61003),401)
            tls_claim(dict(q3,certificate_sha256=secrets.token_hex(32)),401)
            tls_claim(dict(q3,hostname="wrong.example.test"),401)
            tls_claim(q3,401,tokens[1])
            with ThreadPoolExecutor(max_workers=2) as pool:
                answers=list(pool.map(lambda _:tls_claim(q3,(200,401)),range(2)))
            assert sorted(x[0] for x in answers)==[200,401]
            result=next(x[1] for x in answers if x[0]==200)
            assert result["scope"]=="https_loopback_start_claim" and result["nonce"]==q3["nonce"]
            assert result["permit"]["certificate_sha256"]==fp and result["permit"]["hostname"]==d3["hostname"]
            tls_claim(q3,401)
            # Reverse direction port conflicts, across all protocol ledgers.
            d4=domain("next.example.test");verify(d4)
            a4=allocation(20004,"http",d4);g4=grant(a4)
            intent(g4,31003,61004,409)
            intent(g4,31004,61003,409)
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM relay_https_intents WHERE claimed_at IS NOT NULL").fetchone()==(1,)
                assert db.execute("SELECT count(*) FROM management_audit WHERE event='https.claimed'").fetchone()==(1,)
                assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            report["real_https_certificate_fingerprint_exact_claim_and_port_isolation"]=True
        finally:
            stop(p);dns.shutdown();worker.join(timeout=3)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len(report)==3 and all(report.values())
