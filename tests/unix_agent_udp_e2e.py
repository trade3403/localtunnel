"""Actual packaged Unix agent with owner-only UDP config, pinned engine and service."""
import json
import os
import secrets
import socket
import subprocess
import threading
import time

def exercise(d,binary,cli,private,public,results,port,terminate):
    report={}
    root=d/"udp-agent-store"
    token=secrets.token_hex(32)
    credentials=(token+"\n"+public+"\n").encode()
    def cmd(*args,data=b"",ok=True):
        p=subprocess.run([str(cli),*map(str,args)],input=data,capture_output=True,timeout=10)
        assert (p.returncode==0)==ok, "UDP agent command unexpected outcome"
        assert token.encode() not in p.stdout+p.stderr
        return p
    fixture=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    fixture.bind(("127.0.0.1",0))
    fixture.settimeout(.2)
    local=fixture.getsockname()[1]
    stop=threading.Event()
    def echo():
        while not stop.is_set():
            try:
                data,addr=fixture.recvfrom(65535)
                fixture.sendto(data,addr)
            except socket.timeout:
                continue
            except OSError:
                return
    worker=threading.Thread(target=echo,daemon=True)
    worker.start()
    relay=None
    agent=None
    probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1",0))
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1",0))
            mapped=reserve.getsockname()[1]
        control=port()
        while control in (local,mapped):
            control=port()
        probe.settimeout(.6)
        def get(_):
            nonce=secrets.token_bytes(48)
            try:
                probe.sendto(nonce,("127.0.0.1",mapped))
                reply,addr=probe.recvfrom(65535)
                if addr==("127.0.0.1",mapped) and reply==nonce:
                    return b"udp-verified"
            except (socket.timeout,ConnectionRefusedError,ConnectionResetError):
                pass
            return None
        cmd("agent-store-init",root)
        args=("agent-config-create-udp",root,f"127.0.0.1:{control}","udp_agent",f"127.0.0.1:{local}")
        cmd(*args,ok=False)
        cmd(*args,data=b"x"*257,ok=False)
        cmd(*args,data=credentials+b"extra\n",ok=False)
        cmd(*args[:-1],"0.0.0.0:1234",data=credentials,ok=False)
        cfg=root/"client.toml"
        assert not cfg.exists()
        cmd(*args,data=credentials)
        original=cfg.read_bytes()
        assert b'type = "udp"' in original and b'type = "noise"' in original
        assert cfg.stat().st_mode&0o777==0o600 and cfg.stat().st_nlink==1
        assert cfg.stat().st_uid==os.geteuid()
        cmd(*args,data=credentials,ok=False)
        cmd("agent-config-create",*args[1:],data=credentials,ok=False)
        assert cfg.read_bytes()==original
        cmd("agent-config-check",root)
        for altered in (original.replace(b'type = "udp"',b'type = "quic"'),
                        original.replace(f"127.0.0.1:{local}".encode(),f"0.0.0.0:{local}".encode()),
                        original+b"\n[unexpected]\n"):
            assert altered!=original
            cfg.write_bytes(altered)
            cmd("agent-config-check",root,ok=False)
        cfg.write_bytes(original)
        cfg.chmod(0o644)
        cmd("agent-config-check",root,ok=False)
        cfg.chmod(0o600)
        cmd("agent-config-check",root)
        report["real_udp_private_store_and_canonical_validation"]=True
        cmd("agent-engine-install",root,binary)
        installed=root/"rathole"
        assert installed.read_bytes()==binary.read_bytes()
        relay_cfg=d/"udp-agent-relay.toml"
        subprocess.run([str(cli),"server-udp-config",str(relay_cfg),f"127.0.0.1:{control}","udp_agent",str(mapped)],
                       env=dict(os.environ,LOCALTUNNEL_TOKEN=token,LOCALTUNNEL_SERVER_PRIVATE_KEY=private),
                       check=True,capture_output=True,timeout=10)
        relay=subprocess.Popen([str(binary),str(relay_cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        agent=subprocess.Popen([str(cli),"agent-run",str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            assert agent.poll() is None and relay.poll() is None
            if get(None)==b"udp-verified":
                break
            time.sleep(.2)
        else:
            raise AssertionError("UDP private foreground failed to forward")
        identity=subprocess.check_output(["/bin/ps","-p",str(agent.pid),"-o","command="],text=True,timeout=5).strip()
        assert identity.startswith(str(installed)+" ")
        cmd("agent-run",root,ok=False)
        assert get(None)==b"udp-verified"
        report["real_udp_pinned_foreground_exec_and_duplicate_denial"]=True
        agent.terminate()
        agent.wait(timeout=10)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if get(None) is None:
                break
        else:
            raise AssertionError("stopped UDP foreground still forwards")
        report["real_udp_foreground_stop"]=True
        if os.environ.get("LOCALTUNNEL_NATIVE_AGENT_SERVICE_E2E")=="1":
            from unix_agent_service_e2e import exercise as service_exercise
            service_exercise(root,cli,None,b"udp-verified",relay,token,results,get,
                             report_name="unix-udp-service.json")
            report["real_udp_system_service_start_restart_stop"]=True
        assert len(report)==(4 if os.environ.get("LOCALTUNNEL_NATIVE_AGENT_SERVICE_E2E")=="1" else 3)
        assert all(v is True for v in report.values())
    finally:
        if agent is not None:
            terminate(agent)
        if relay is not None:
            terminate(relay)
        stop.set()
        worker.join(timeout=2)
        fixture.close()
        probe.close()
        (results/"unix-udp-agent.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
