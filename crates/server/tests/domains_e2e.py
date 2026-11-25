"""Actual CLI + HTTP device registration, ownership and revocation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
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
    if status in (200,201):
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

try:
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),Handler) as dns, tempfile.TemporaryDirectory() as directory:
        dns.daemon_threads=True
        worker=threading.Thread(target=dns.serve_forever,daemon=True)
        worker.start()
        try:
            resolver="127.0.0.1:"+str(dns.server_address[1])
            root=Path(directory)
            db_path=root/"control.sqlite3"
            result=subprocess.run([exe,"--init-admin",str(root)],input=json.dumps({"username":"operator","password":password}).encode(),capture_output=True,timeout=20)
            assert result.returncode==0
            def operator(*args):
                return subprocess.run([exe,args[0],str(root),*args[1:]],capture_output=True,text=True,timeout=20)
            node=operator("--add-node","relay fixture")
            assert node.returncode==0
            nid=node.stdout.strip()
            assert len(bytes.fromhex(nid))==16
            assert operator("--add-node","relay fixture").returncode!=0
            with sqlite3.connect(db_path) as db:
                owner,phc=db.execute("SELECT id,password_hash FROM users").fetchone()
                db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('other','otheradmin',?,'admin')",(phc,))
            p,base=launch(root)
            try:
                admin=login(base,"operator")
                other=login(base,"otheradmin")
                expect(call(base,"nodes"),401)
                assert expect(call(base,"nodes",token=admin),200)==[{"id":nid,"name":"relay fixture","enabled":True}]
                expect(call(base,"nodes","POST",admin,{"name":"forbidden"}),405)
                assert operator("--set-node-enabled",nid,"false").returncode==0
                assert expect(call(base,"nodes",token=other),200)[0]["enabled"] is False
                assert operator("--set-node-enabled",nid,"true").returncode==0
                report["local_operator_node_inventory"]=True
                expect(call(base,"domains"),401)
                for invalid in ["*.example.test","127.0.0.1","a..test","a.test.","localtunnel-probe.invalid"]:
                    expect(call(base,"domains","POST",admin,{"hostname":invalid}),400)
                domain=expect(call(base,"domains","POST",admin,{"hostname":"Web.Example.Test"}),201)
                did=domain["id"]
                path="domains/"+did
                assert domain["hostname"]=="web.example.test" and domain["verified_at"] is None
                assert domain["txt_name"]=="_localtunnel.web.example.test"
                assert domain["txt_value"].startswith("localtunnel-verification=")
                expect(call(base,"domains","POST",other,{"hostname":"WEB.example.test"}),409)
                assert expect(call(base,"domains",token=other),200)==[]
                expect(call(base,path,token=other),404)
                expect(call(base,path+"/challenge","POST",other),404)
                def verify(credential=admin):
                    return call(base,"domains/verify","POST",credential,{"domain_id":did})
                expect(verify(other),404)
                expect(verify(),409)
                qname=domain["txt_name"]+"."
                assert queries[-1]==qname
                records[qname]=domain["txt_value"]+"-wrong"
                expect(verify(),409)
                assert expect(call(base,path,token=admin),200)["verified_at"] is None
                records[qname]=domain["txt_value"]
                verified=expect(verify(),200)
                assert isinstance(verified["verified_at"],int)
                rotated=expect(call(base,path+"/challenge","POST",admin),200)
                assert rotated["verified_at"] is None and rotated["txt_value"]!=domain["txt_value"]
                expect(verify(),409)
                records[qname]=rotated["txt_value"]
                verified=expect(verify(),200)
                report["real_dns_tcp_exact_txt_rotation"]=True
                a=expect(enroll(base,issue(base,admin)),201)
                spec={"device_id":a["id"],"node_id":nid,"domain_id":did,"protocol":"https","local_port":8080,"bind_port":20001}
                mapping=expect(call(base,"mappings","POST",admin,spec),201)
                assert mapping["enabled"] is False
                expect(call(base,path,"DELETE",admin),409)
                expect(call(base,"mappings/"+mapping["id"],"PATCH",admin,{"expected_revision":1,"enabled":True}),409)
                report["mapping_reference_and_activation_gate"]=True
            finally:
                stop(p)
            p,base=launch(root)
            try:
                assert expect(call(base,path,token=admin),200)==verified
                expect(call(base,"mappings/"+mapping["id"]+"?expected_revision=1","DELETE",admin),204)
                expect(call(base,path,"DELETE",other),404)
                expect(call(base,path,"DELETE",admin),204)
                expect(call(base,path,token=admin),404)
                report["restart_and_scoped_delete"]=True
            finally:
                stop(p)
        finally:
            dns.shutdown()
            worker.join(timeout=5)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
