"""Real UDP data over pinned Rathole Noise/TCP; no QUIC or public networking."""
import concurrent.futures
import json
import os
import platform
import secrets
import socket
import subprocess
import threading
import time

def exercise(d,binary,cli,private,public,results,port,terminate):
    report={"scope":"single-host UDP service over Noise/TCP","platform":platform.system(),
            "public_e2e":"BLOCKED: no public relay/domain","passed":[]}
    token=secrets.token_hex(32)
    bad=secrets.token_hex(32)
    seen=[]
    stop=threading.Event()
    fixture=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    fixture.bind(("127.0.0.1",0))
    fixture.settimeout(.2)
    local=fixture.getsockname()[1]
    def echo():
        while not stop.is_set():
            try:
                data,addr=fixture.recvfrom(65535)
                seen.append(data)
                fixture.sendto(data,addr)
            except socket.timeout:
                continue
            except OSError:
                return
    worker=threading.Thread(target=echo,daemon=True)
    worker.start()
    processes=[]
    def launch(config):
        p=subprocess.Popen([str(binary),str(config)],stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(p)
        return p
    def configure(args,secret,ok=True):
        env=dict(os.environ,LOCALTUNNEL_TOKEN=secret,
                 LOCALTUNNEL_SERVER_PRIVATE_KEY=private,LOCALTUNNEL_SERVER_PUBLIC_KEY=public)
        p=subprocess.run([str(cli),*map(str,args)],env=env,capture_output=True,timeout=10)
        assert (p.returncode==0)==ok, "unexpected UDP CLI configuration result"
        for value in (token,bad,private,public):
            assert value.encode() not in p.stdout+p.stderr
    def exchange(sock,data,timeout=1):
        sock.settimeout(timeout)
        try:
            sock.sendto(data,("127.0.0.1",mapped))
            received,addr=sock.recvfrom(65535)
            assert addr==("127.0.0.1",mapped)
            return received
        except (socket.timeout,ConnectionResetError,ConnectionRefusedError):
            return None
    def probe(process_list,seconds=45):
        deadline=time.monotonic()+seconds
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            while time.monotonic()<deadline:
                assert all(p.poll() is None for p in process_list), "UDP engine exited"
                data=secrets.token_bytes(48)
                got=exchange(s,data,.5)
                if got==data:
                    return
                # No unrelated reply can be treated as success.
                assert got is None, "unexpected UDP reply"
                time.sleep(.2)
        raise AssertionError("real UDP tunnel did not forward")
    try:
        control=port()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1",0))
            mapped=reserve.getsockname()[1]
        while control in (local,mapped):
            control=port()
        server=d/"udp-server.toml"
        client=d/"udp-client.toml"
        wrong=d/"udp-wrong.toml"
        configure(["server-udp-config",server,f"127.0.0.1:{control}","udp_echo",mapped],token)
        configure(["client-udp-config",client,f"127.0.0.1:{control}","udp_echo",f"127.0.0.1:{local}"],token)
        configure(["client-udp-config",wrong,f"127.0.0.1:{control}","udp_echo",f"127.0.0.1:{local}"],bad)
        for path in (server,client,wrong):
            assert 'type = "udp"' in path.read_text() and 'type = "noise"' in path.read_text()
            if os.name!="nt":
                assert path.stat().st_mode&0o777==0o600
        original=client.read_bytes()
        configure(["client-udp-config",client,f"127.0.0.1:{control}","udp_echo",f"127.0.0.1:{local}"],token,False)
        assert client.read_bytes()==original
        invalid=d/"udp-invalid.toml"
        configure(["client-udp-config",invalid,f"127.0.0.1:{control}","udp_echo","0.0.0.0:8080"],token,False)
        assert not invalid.exists()
        report["passed"].append("actual UDP configuration with Noise, no overwrite, loopback target")
        relay=launch(server)
        agent=launch(wrong)
        marker=secrets.token_bytes(32)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            for _ in range(5):
                assert relay.poll() is None
                assert exchange(s,marker,.6) is None, "wrong token forwarded UDP"
        assert marker not in seen
        terminate(agent)
        report["passed"].append("wrong token cannot forward UDP to local fixture")
        agent=launch(client)
        probe([relay,agent])
        report["passed"].append("actual encrypted UDP round trip")
        sizes=(1,64,512,1200)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            for size in sizes:
                data=secrets.token_bytes(size)
                assert exchange(s,data,3)==data, "UDP datagram bytes or boundaries differ"
        report["passed"].append("four binary datagram sizes preserved")
        def client_worker(index):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1",0))
                for seq in range(8):
                    data=bytes([index,seq])+secrets.token_bytes(510)
                    assert exchange(s,data,5)==data, "UDP concurrent client isolation failed"
                return 8
        start=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            count=sum(pool.map(client_worker,range(8)))
        assert count==64
        report["passed"].append("64 binary replies isolated across eight UDP client sockets")
        report["concurrent_round_trips"]=count
        report["concurrent_elapsed_seconds"]=round(time.monotonic()-start,6)
        terminate(relay)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            assert exchange(s,secrets.token_bytes(48),1) is None
        relay=launch(server)
        probe([relay,agent],60)
        report["passed"].append("UDP forwarding resumes after relay restart")
        assert len(report["passed"])==6
    finally:
        for p in reversed(processes):
            terminate(p)
        stop.set()
        worker.join(timeout=2)
        fixture.close()
        (results/"udp.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
