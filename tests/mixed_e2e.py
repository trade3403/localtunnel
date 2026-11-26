"""One real relay and one agent, three mappings, independent TCP/UDP credentials."""
import concurrent.futures
import json
import os
import secrets
import socket
import subprocess
import threading
import time

def exercise(d,binary,cli,private,public,results,port,terminate,get,body,local_tcp):
    report={"scope":"single-host mixed TCP/UDP services over Noise/TCP","passed":[]}
    tokens=[secrets.token_hex(32) for _ in range(3)]
    stop=threading.Event()
    fixtures=[]
    workers=[]
    seen=[[],[]]
    processes=[]
    held=[]
    def udp_fixture(index):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1",0))
        sock.settimeout(.2)
        fixtures.append(sock)
        def echo():
            while not stop.is_set():
                try:
                    data,addr=sock.recvfrom(65535)
                    seen[index].append(data)
                    sock.sendto(bytes([index])+data,addr)
                except socket.timeout:
                    continue
                except OSError:
                    return
        t=threading.Thread(target=echo,daemon=True)
        t.start()
        workers.append(t)
        return sock.getsockname()[1]
    def launch(config):
        p=subprocess.Popen([str(binary),str(config)],stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(p)
        return p
    def config(args,keys,ok=True):
        env=dict(os.environ,LOCALTUNNEL_SERVER_PRIVATE_KEY=private,LOCALTUNNEL_SERVER_PUBLIC_KEY=public)
        env.update({f"LOCALTUNNEL_TOKEN_{i+1}":v for i,v in enumerate(keys)})
        p=subprocess.run([str(cli),*map(str,args)],env=env,capture_output=True,timeout=10)
        assert (p.returncode==0)==ok, "mixed CLI result differs"
        for secret in [private,public,*tokens,*keys]:
            assert secret.encode() not in p.stdout+p.stderr
    def request(sock,index,data,timeout=2):
        sock.settimeout(timeout)
        try:
            sock.sendto(data,("127.0.0.1",mapped[index]))
            value,addr=sock.recvfrom(65535)
            assert addr==("127.0.0.1",mapped[index])
            return value
        except (socket.timeout,ConnectionResetError,ConnectionRefusedError):
            return None
    def ready(relay,agent,indices,seconds=60):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            assert relay.poll() is None and agent.poll() is None
            if get(url)==body:
                ok=True
                for index in indices:
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                        data=secrets.token_bytes(48)
                        reply=request(sock,index,data,.5)
                        if reply!=bytes([index])+data:
                            assert reply is None
                            ok=False
                if ok:
                    return
            time.sleep(.2)
        raise AssertionError("mixed mapping readiness failed")
    try:
        local=[udp_fixture(0),udp_fixture(1)]
        # Reserve all three mapping ports and the control port simultaneously.
        for kind in [socket.SOCK_STREAM,socket.SOCK_STREAM,socket.SOCK_DGRAM,socket.SOCK_DGRAM]:
            while True:
                s=socket.socket(socket.AF_INET,kind)
                s.bind(("127.0.0.1",0))
                p=s.getsockname()[1]
                if p not in [local_tcp,*local,*[h.getsockname()[1] for h in held]]:
                    held.append(s)
                    break
                s.close()
        control,tcp,*mapped=[s.getsockname()[1] for s in held]
        for s in held:
            s.close()
        held.clear()
        url=f"http://127.0.0.1:{tcp}/"
        server=d/"mixed-server.toml"
        client=d/"mixed-client.toml"
        bad=d/"mixed-wrong.toml"
        server_args=["server-mixed",server,f"127.0.0.1:{control}","tcp","web",tcp,
                     "udp","echo_a",mapped[0],"udp","echo_b",mapped[1]]
        client_args=["client-mixed",client,f"127.0.0.1:{control}","tcp","web",f"127.0.0.1:{local_tcp}",
                     "udp","echo_a",f"127.0.0.1:{local[0]}","udp","echo_b",f"127.0.0.1:{local[1]}"]
        config(server_args,tokens)
        config(client_args,tokens)
        for p in (server,client):
            c=p.read_text()
            assert c.count('type = "tcp"')==1 and c.count('type = "udp"')==2
            assert 'type = "noise"' in c
        original=client.read_bytes()
        config(client_args,tokens,False)
        assert client.read_bytes()==original
        invalid=d/"mixed-invalid.toml"
        for index,value in [(7,"web"),(6,"quic"),(8,"0.0.0.0:8080")]:
            args=client_args.copy()
            args[1]=invalid
            args[index]=value
            config(args,tokens,False)
            assert not invalid.exists()
        args=server_args.copy()
        args[1]=invalid
        args[8]=tcp
        config(args,tokens,False)
        assert not invalid.exists()
        args=client_args.copy()
        args[1]=invalid
        config(args,[tokens[0],tokens[0],tokens[2]],False)
        assert not invalid.exists()
        report["passed"].append("mixed config and global collision/credential validation")
        # Wrong token for only echo_b; legitimate TCP and echo_a must stay usable.
        args=client_args.copy()
        args[1]=bad
        config(args,[tokens[0],tokens[1],secrets.token_hex(32)])
        relay=launch(server)
        agent=launch(bad)
        ready(relay,agent,[0])
        marker=secrets.token_bytes(40)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            for _ in range(4):
                assert request(sock,1,marker,.5) is None
        assert marker not in seen[1] and get(url)==body
        report["passed"].append("invalid UDP credential isolated from valid TCP and UDP")
        terminate(agent)
        agent=launch(client)
        ready(relay,agent,[0,1])
        report["passed"].append("one relay and agent forward all three independent mappings")
        def worker(index):
            if index<4:
                for _ in range(8):
                    assert get(url)==body
                return 8,0
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                for seq in range(8):
                    mapping=(index+seq)%2
                    data=bytes([index,seq])+secrets.token_bytes(510)
                    assert request(sock,mapping,data,5)==bytes([mapping])+data
                return 0,8
        start=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            counts=list(pool.map(worker,range(12)))
        report["tcp_round_trips"]=sum(c[0] for c in counts)
        report["udp_round_trips"]=sum(c[1] for c in counts)
        assert (report["tcp_round_trips"],report["udp_round_trips"])==(32,64)
        report["elapsed_seconds"]=round(time.monotonic()-start,6)
        report["passed"].append("32 TCP and 64 UDP concurrent round trips without cross-mapping replies")
        terminate(relay)
        assert get(url)!=body
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            for index in (0,1):
                assert request(sock,index,secrets.token_bytes(48),.6) is None
        relay=launch(server)
        ready(relay,agent,[0,1])
        report["passed"].append("all mixed mappings recover after relay restart")
        assert len(report["passed"])==5
        from udp_guard_e2e import exercise as guard_exercise
        guard_exercise(cli,mapped[0],seen[0],results,terminate)
    finally:
        for p in reversed(processes):
            terminate(p)
        stop.set()
        for t in workers:
            t.join(timeout=2)
        for s in fixtures+held:
            s.close()
        (results/"mixed.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
