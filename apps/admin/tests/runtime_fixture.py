"""Disposable real DNS + HTTP services for Chromium management E2E."""
import sys, json, socket, socketserver, struct, threading, http.server, secrets, re, subprocess
from pathlib import Path
root=Path(sys.argv[1])
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tests"))
import e2e as core_test

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



# Accept only the fixture challenge, read from a private file written by the
# browser test after the actual API creates its domain. No API interception.
class DynamicHandler(Handler):
    def handle(self):
        record=root/"dns_record.json"
        if record.is_file():
            value=json.loads(record.read_text())
            records[value["name"]+"."]=value["value"]
        super().handle()

body=secrets.token_hex(24).encode()
class Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):
        pass

with socketserver.ThreadingTCPServer(("127.0.0.1",0),DynamicHandler) as dns,http.server.ThreadingHTTPServer(("127.0.0.1",0),Web) as web:
    dns.daemon_threads=True
    threading.Thread(target=dns.serve_forever,daemon=True).start()
    threading.Thread(target=web.serve_forever,daemon=True).start()
    engine=core_test.engine(root)
    keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
    private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
    public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
    (root/"expected_body").write_bytes(body)
    (root/"expected_body").chmod(0o600)
    ports={web.server_port,dns.server_address[1],20000,1430}
    def unique_port():
        while True:
            p=core_test.port()
            if p not in ports:
                ports.add(p)
                return p
    # Browser test consumes this JSON through a private pipe; never log it.
    print(json.dumps({"dns":f"127.0.0.1:{dns.server_address[1]}","local":web.server_port,"relay":unique_port(),"gateway":unique_port(),"body":body.decode(),"engine":str(engine),"core":str(core_test.CLI.resolve()),"private":private,"public":public}),flush=True)
    sys.stdin.read()
