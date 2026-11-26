"""Actual loopback ingress guard in front of a live, pinned Noise UDP mapping."""
import json
import math
import secrets
import socket
import subprocess
import time

def exercise(cli,upstream,seen,results,terminate):
    report={"scope":"opt-in local UDP guard in front of real Noise/TCP mapping",
            "passed":[],"limits":{"sessions":32,"new_sources_per_65s":32,
            "idle_seconds":65,"max_payload_bytes":1200,"per_peer_packets_per_second":40,
            "global_packets_per_second":200}}
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1",0))
        listen=reserve.getsockname()[1]
    endpoint=f"127.0.0.1:{listen}"
    relay=f"127.0.0.1:{upstream}"
    for a,b in [("0.0.0.0:0",relay),(endpoint,"192.168.1.1:80"),(endpoint,endpoint)]:
        p=subprocess.run([str(cli),"udp-guard",a,b],capture_output=True,timeout=5)
        assert p.returncode!=0
    report["passed"].append("invalid and non-loopback guard endpoints denied")
    process=subprocess.Popen([str(cli),"udp-guard",endpoint,relay],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    sockets=[]
    def new():
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.bind(("127.0.0.1",0))
        sockets.append(s)
        return s
    def exchange(s,data,timeout=3):
        s.settimeout(timeout)
        try:
            s.sendto(data,("127.0.0.1",listen))
            reply,addr=s.recvfrom(65535)
            assert addr==("127.0.0.1",listen)
            return reply
        except (socket.timeout,ConnectionResetError,ConnectionRefusedError):
            return None
    try:
        first=new()
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            assert process.poll() is None
            marker=secrets.token_bytes(32)
            got=exchange(first,marker,.5)
            if got==b"\x00"+marker:
                break
            assert got is None
        else:
            raise AssertionError("guard did not forward actual UDP")
        valid=secrets.token_bytes(1199) # fixture adds a 1-byte identity
        assert exchange(first,valid)==b"\x00"+valid
        oversized=secrets.token_bytes(1201)
        assert exchange(first,oversized,.5) is None
        assert oversized not in seen
        report["passed"].append("actual binary forwarding and oversized datagram denial")
        for _ in range(31):
            s=new()
            data=secrets.token_bytes(32)
            assert exchange(s,data)==b"\x00"+data
        denied=new()
        marker=secrets.token_bytes(48)
        assert exchange(denied,marker,.5) is None
        assert marker not in seen
        data=secrets.token_bytes(32)
        assert exchange(first,data)==b"\x00"+data
        report["passed"].append("32 admitted sources and 33rd denied without breaking existing source")
        # Real overload: count actual packets reaching the pinned engine's local
        # fixture, not only guard output. All requests are distinct and tagged.
        prefix=secrets.token_bytes(16)
        time.sleep(.3)
        start=time.monotonic()
        for seq in range(256):
            first.sendto(prefix+seq.to_bytes(2,"big"),("127.0.0.1",listen))
        time.sleep(1.2)
        elapsed=time.monotonic()-start
        forwarded=sum(x.startswith(prefix) and len(x)==18 for x in seen)
        assert 0<forwarded<256
        assert forwarded<=math.ceil(8+40*elapsed)+1
        report["overload"]={"sent":256,"actual_fixture_received":forwarded,"observation_seconds":round(elapsed,6)}
        # A new request from an existing source should still work after the burst.
        # Use a different admitted socket so queued replies on first do not
        # masquerade as a new reply.
        data=secrets.token_bytes(32)
        assert exchange(sockets[1],data)==b"\x00"+data
        report["passed"].append("real overload drops excess traffic and preserves admitted peer")
        # Fixed real production idle interval: no clock mocking, no lower test limit.
        time.sleep(66)
        assert process.poll() is None
        data=secrets.token_bytes(32)
        assert exchange(denied,data,5)==b"\x00"+data
        report["passed"].append("real 65-second idle session expiry permits a previously denied source")
        assert len(report["passed"])==5
    finally:
        terminate(process)
        for s in sockets:
            s.close()
        (results/"udp-guard.json").write_text(json.dumps(report,indent=2),encoding="utf-8")

    # Run the new configured byte gate against the same live encrypted mapping.
    limited_exercise(cli,upstream,seen,results,terminate)


def limited_exercise(cli,upstream,seen,results,terminate):
    report={"scope":"real configured per-direction UDP byte gate, same-host Noise/TCP",
            "bytes_per_second_each_direction":1,"burst_bytes_each_direction":1200,"passed":[]}
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1",0))
        listen=reserve.getsockname()[1]
    args=[str(cli),"udp-guard-limited",f"127.0.0.1:{listen}",f"127.0.0.1:{upstream}"]
    for rate,burst in [("0","1200"),("240001","1200"),("1","1199"),("1","76801"),("-1","1200"),("x","1200")]:
        p=subprocess.run([*args,rate,burst],capture_output=True,timeout=5)
        assert p.returncode!=0
    report["passed"].append("invalid rate and burst rejected before binding")
    process=subprocess.Popen([*args,"1","1200"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def exchange(sock,data,timeout):
        sock.settimeout(timeout)
        try:
            sock.sendto(data,("127.0.0.1",listen))
            reply,addr=sock.recvfrom(65535)
            assert addr==("127.0.0.1",listen)
            return reply
        except (socket.timeout,ConnectionResetError,ConnectionRefusedError):
            return None
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as b:
            a.bind(("127.0.0.1",0))
            b.bind(("127.0.0.1",0))
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                assert process.poll() is None
                marker=secrets.token_bytes(16)
                got=exchange(a,marker,.5)
                if got==bytes([0])+marker:
                    break
                assert got is None
            else:
                raise AssertionError("limited guard startup failed")
            # 256 bytes admitted; 1024 is below the existing 1200-byte
            # packet limit but exceeds remaining mapping byte budget.
            first=secrets.token_bytes(256)
            assert exchange(a,first,3)==bytes([0])+first
            denied=secrets.token_bytes(1024)
            started=time.monotonic()
            assert exchange(b,denied,.6) is None
            assert denied not in seen
            # Another source cannot bypass the shared byte bucket, but a
            # smaller request within the remaining budget still works.
            small=secrets.token_bytes(32)
            assert exchange(b,small,3)==bytes([0])+small
            assert time.monotonic()-started<15
            assert first in seen and small in seen and denied not in seen
            report["verified_fixture_bytes"]=[256,32]
            report["denied_fixture_bytes"]=1024
            report["passed"].append("real shared byte budget rejects larger datagram while smaller traffic survives")
        assert len(report["passed"])==2
    finally:
        terminate(process)
        (results/"udp-guard-limited.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
