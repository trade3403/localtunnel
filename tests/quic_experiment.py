"""Isolated QUIC v1 reverse-stream experiment, not shipped or publicly listening."""
import asyncio
import datetime
import hmac
import importlib.metadata
import json
import secrets
import socket
import ssl
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
from aioquic.quic.packet import QuicProtocolVersion
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ALPN = "localtunnel-experiment/1"
HOST = "relay.localtunnel.test"
MAX = 256 * 1024
TOKEN = secrets.token_bytes(32)
OK = b"OK"
DENIED = b"DENIED"

def certificates(root):
    now = datetime.datetime.now(datetime.timezone.utc)
    def ca(name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-datetime.timedelta(minutes=5))
                .not_valid_after(now+datetime.timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
                .sign(key,hashes.SHA256()))
        return key,cert
    key,issuer=ca("LocalTunnel disposable experiment CA")
    _,wrong=ca("Untrusted disposable CA")
    leaf_key=ec.generate_private_key(ec.SECP256R1())
    leaf=(x509.CertificateBuilder()
          .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,HOST)]))
          .issuer_name(issuer.subject).public_key(leaf_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=5))
          .not_valid_after(now+datetime.timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]),critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
          .sign(key,hashes.SHA256()))
    for name,cert in [("ca.pem",issuer),("wrong.pem",wrong),("leaf.pem",leaf)]:
        (root/name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path=root/"leaf.key"
    with path.open("xb") as f:
        path.chmod(0o600)
        f.write(leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

async def frame(reader):
    size=struct.unpack("!I",await reader.readexactly(4))[0]
    if not 1<=size<=MAX:
        raise ValueError("experimental frame out of bounds")
    data=await reader.readexactly(size)
    if await reader.read(1)!=b"":
        raise ValueError("unexpected trailing data")
    return data

def send(writer,data):
    writer.write(struct.pack("!I",len(data))+data)
    writer.write_eof()

def cfg(client,root,hostname=HOST,ca="ca.pem",alpn=ALPN):
    config=QuicConfiguration(is_client=client,alpn_protocols=[alpn],
                             supported_versions=[QuicProtocolVersion.VERSION_1],
                             idle_timeout=10,max_data=4*1024*1024,max_stream_data=MAX+4)
    if client:
        config.verify_mode=ssl.CERT_REQUIRED
        config.server_name=hostname
        config.load_verify_locations(cafile=str(root/ca))
    else:
        config.load_cert_chain(str(root/"leaf.pem"),str(root/"leaf.key"))
    return config

async def exercise(root,report,comparison=None):
    registry={"active":None}
    tasks=set()
    observed=[]
    def schedule(coro):
        task=asyncio.create_task(coro)
        tasks.add(task)
        task.add_done_callback(tasks.discard)
    async def echo(reader,writer):
        try:
            async with asyncio.timeout(8):
                data=await frame(reader)
                observed.append(len(data))
                send(writer,data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    fixture=await asyncio.start_server(lambda r,w:schedule(echo(r,w)),"127.0.0.1",0)
    local=fixture.sockets[0].getsockname()[1]
    class Relay(QuicConnectionProtocol):
        def __init__(self,quic,stream_handler=None):
            super().__init__(quic,stream_handler=self.incoming)
            self.handshake=False
            self.registered=False
        def quic_event_received(self,event):
            if isinstance(event,HandshakeCompleted):
                self.handshake=event.alpn_protocol==ALPN and not event.early_data_accepted
            elif isinstance(event,ConnectionTerminated):
                if registry["active"] is self:
                    registry["active"]=None
            super().quic_event_received(event)
        def incoming(self,reader,writer):
            schedule(self.register(reader,writer))
        async def register(self,reader,writer):
            try:
                async with asyncio.timeout(5):
                    token=await reader.readexactly(32)
                    eof=await reader.read(1)==b""
                    if self.handshake and eof and not self.registered and registry["active"] is None and hmac.compare_digest(token,TOKEN):
                        self.registered=True
                        registry["active"]=self
                        writer.write(OK)
                    else:
                        writer.write(DENIED)
                    writer.write_eof()
            except (TimeoutError,ValueError,ConnectionError,asyncio.IncompleteReadError):
                self.close(error_code=1,reason_phrase="registration failed")
    agent_slots=asyncio.Semaphore(8)
    async def forward(reader,writer):
        # Only a fixed local TCP fixture, not arbitrary relay-controlled targets.
        async with agent_slots:
            async with asyncio.timeout(8):
                data=await frame(reader)
                lr,lw=await asyncio.open_connection("127.0.0.1",local)
                try:
                    send(lw,data)
                    await lw.drain()
                    reply=await frame(lr)
                    send(writer,reply)
                finally:
                    lw.close()
                    await lw.wait_closed()
    def inbound(reader,writer):
        schedule(forward(reader,writer))
    async def register(client,token):
        reader,writer=await client.create_stream()
        writer.write(token)
        writer.write_eof()
        return await asyncio.wait_for(reader.read(7),5)
    async def reverse(data):
        relay=registry["active"]
        if relay is None:
            raise PermissionError("no registered agent")
        reader,writer=await relay.create_stream()
        send(writer,data)
        assert await asyncio.wait_for(frame(reader),10)==data
    def reserved_port():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1",0))
            return s.getsockname()[1]
    port=reserved_port()
    server=await serve("127.0.0.1",port,configuration=cfg(False,root),create_protocol=Relay,retry=True)
    try:
        # Negative handshakes must fail before an application stream can open.
        for bad in [cfg(True,root,ca="wrong.pem"),cfg(True,root,hostname="wrong.localtunnel.test"),
                    cfg(True,root,alpn="wrong-protocol")]:
            accepted=False
            try:
                async with asyncio.timeout(12):
                    async with connect("127.0.0.1",port,configuration=bad):
                        accepted=True
            except ConnectionError:
                pass
            assert not accepted and registry["active"] is None
        report["passed"].append("real TLS rejects untrusted CA, wrong hostname and ALPN")
        async with connect("127.0.0.1",port,configuration=cfg(True,root),stream_handler=inbound) as client:
            assert await register(client,secrets.token_bytes(32))==DENIED
            assert registry["active"] is None and not observed
            try:
                await reverse(b"unauthorized")
            except PermissionError:
                pass
            else:
                raise AssertionError("unregistered agent received a reverse stream")
        report["passed"].append("wrong application token cannot register or reach local fixture")
        started=time.perf_counter()
        async with connect("127.0.0.1",port,configuration=cfg(True,root),stream_handler=inbound) as client:
            report["handshake_ms"]=round((time.perf_counter()-started)*1000,3)
            assert await register(client,TOKEN)==OK and registry["active"] is not None
            original=registry["active"]
            async with connect("127.0.0.1",port,configuration=cfg(True,root)) as other:
                assert await register(other,TOKEN)==DENIED and registry["active"] is original
            report["passed"].append("authenticated registration and duplicate takeover rejection")
            before=len(observed)
            for size in [1,64,1200,MAX]:
                await reverse(secrets.token_bytes(size))
            assert observed[before:]==[1,64,1200,MAX]
            report["passed"].append("relay-initiated QUIC streams traverse real local TCP echo")
            lat=[]
            for _ in range(16):
                t=time.perf_counter()
                await reverse(secrets.token_bytes(1024))
                lat.append((time.perf_counter()-t)*1000)
            start=time.perf_counter()
            for _ in range(2):
                await asyncio.gather(*(reverse(secrets.token_bytes(64*1024)) for _ in range(8)))
            elapsed=time.perf_counter()-start
            assert len(observed)-before==36
            report["baseline"]={"sequential_1024B_roundtrips":16,"median_ms":round(statistics.median(lat),3),
                "concurrent_streams":8,"concurrent_roundtrips":16,"payload_bytes_each_direction":16*64*1024,
                "elapsed_seconds":round(elapsed,6),
                "combined_application_goodput_mbps":round(2*16*64*1024*8/elapsed/1e6,3)}
            report["passed"].append("16 sequential and 16 concurrent binary reverse round trips")
            if comparison is not None:
                from quic_noise_benchmark import compare
                binary, engine_report = comparison
                report["comparison"] = await compare(root,binary,engine_report,local,reverse,observed)
                assert len(report["comparison"]["passed"]) == 3
        # Client close must remove the authenticated registration. No automatic
        # restart, migration or resumption is claimed in this experiment.
        for _ in range(50):
            if registry["active"] is None:
                break
            await asyncio.sleep(.1)
        assert registry["active"] is None
        server.close()
        await asyncio.sleep(.2)
        server=await serve("127.0.0.1",port,configuration=cfg(False,root),create_protocol=Relay,retry=True)
        async with connect("127.0.0.1",port,configuration=cfg(True,root),stream_handler=inbound) as client:
            assert await register(client,TOKEN)==OK
            await reverse(secrets.token_bytes(4096))
        report["passed"].append("fresh TLS and token registration after explicit relay restart")
    finally:
        server.close()
        fixture.close()
        await fixture.wait_closed()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks),return_exceptions=True)

async def main(report,comparison=None):
    async with asyncio.timeout(110):
        with tempfile.TemporaryDirectory(prefix="lt-quic-experiment-") as d:
            root=Path(d)
            certificates(root)
            await exercise(root,report,comparison)

if __name__=="__main__":
    out=Path(sys.argv[1])
    report={"scope":"single-host QUIC v1 reverse stream experiment; no production integration",
            "aioquic":importlib.metadata.version("aioquic"),"passed":[],
            "public_e2e":"BLOCKED: no public deployment"}
    try:
        assert report["aioquic"]=="1.9.2"
        if len(sys.argv)==3 and sys.argv[2]=="--compare":
            from pinned_engine import acquire
            with tempfile.TemporaryDirectory(prefix="lt-paired-engine-") as d:
                comparison=acquire(Path(d))
                asyncio.run(main(report,comparison))
            assert len(report["comparison"]["rounds"])==4
        elif len(sys.argv)==2:
            asyncio.run(main(report))
        else:
            raise SystemExit("usage: quic_experiment.py REPORT [--compare]")
        assert len(report["passed"])==6
    finally:
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2),encoding="utf-8")
