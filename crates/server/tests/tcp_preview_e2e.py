"""Real raw TCP management worker, Noise forwarding and commercial policy."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tests"))
import e2e as core_test

exe=str(Path(sys.argv[1]).resolve())
evidence=Path(sys.argv[2])
report={}
password=secrets.token_hex(24)

def call(base,path,status,method="GET",token=None,data=None):
    headers={}
    if token is not None:headers["Authorization"]="Bearer "+token
    if data is not None:headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            code,raw=r.status,r.read()
    except urllib.error.HTTPError as e:
        code,raw=e.code,e.read()
    assert code==status,f"{method} {path}: expected {status}, got {code}"
    if code in (200,201,202):return json.loads(raw)

def free(lo,hi,exclude,kind=socket.SOCK_STREAM):
    for _ in range(200):
        port=lo+secrets.randbelow(hi-lo+1)
        if port in exclude:continue
        with socket.socket(socket.AF_INET,kind) as s:
            try:s.bind(("127.0.0.1",port))
            except OSError:continue
            return port
    raise AssertionError("no free TCP preview port")

def line(p,prefix,seconds):
    with selectors.DefaultSelector() as s:
        s.register(p.stdout,selectors.EVENT_READ)
        assert s.select(seconds),"TCP readiness timed out"
    assert p.stdout.readline().strip().startswith(prefix),"TCP readiness failed"

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                data=self.request.recv(4096)
                if not data:return
                self.request.sendall(data)
        except OSError:return

try:
    with tempfile.TemporaryDirectory() as tmp,socketserver.ThreadingTCPServer(("127.0.0.1",0),Echo) as fixture:
        fixture.daemon_threads=True
        thread=threading.Thread(target=fixture.serve_forever,daemon=True)
        thread.start()
        root=Path(tmp)
        def command(action,data):
            result=subprocess.run([exe,action,str(root)],input=json.dumps(data).encode(),capture_output=True,timeout=20)
            assert result.returncode==0,"operator action failed"
            return result.stdout.decode().strip()
        command("--init-admin",{"username":"operator","password":password})
        node=subprocess.check_output([exe,"--add-node",str(root),"TCP fixture"],text=True,timeout=20).strip()
        plan=command("--commercial-create-plan",{"code":"tcp-fixture","version":1,"name":"TCP fixture","max_active_devices":4,
            "max_retained_devices":8,"max_mappings":8,"max_bandwidth_bps":1048576,"max_monthly_bytes":None,"max_concurrent_connections":None})
        command("--commercial-create-account",{"username":"other","password":password,"plan_id":"legacy-v1","expires_at":None})
        engine=core_test.engine(root)
        keys=subprocess.check_output([str(engine),"--genkey"],text=True,timeout=15)
        private=re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        public=re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)",keys).group(1)
        env=dict(os.environ,LOCALTUNNEL_CORE_CLI=str(core_test.CLI.resolve()),LOCALTUNNEL_ENGINE=str(engine),LOCALTUNNEL_SERVER_PRIVATE_KEY=private,LOCALTUNNEL_SERVER_PUBLIC_KEY=public)
        management=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        children=[]
        try:
            with selectors.DefaultSelector() as s:
                s.register(management.stdout,selectors.EVENT_READ)
                assert s.select(20)
            address=management.stdout.readline().strip()
            assert address.startswith("LISTENING 127.0.0.1:")
            base="http://"+address.split()[1]
            admin=call(base,"auth/login",200,"POST",data={"username":"operator","password":password})["access_token"]
            other=call(base,"auth/login",200,"POST",data={"username":"other","password":password})["access_token"]
            def policy(pid=plan,state="active"):
                e=call(base,"commercial/entitlement",200,token=admin)["entitlement"]
                command("--commercial-assign",{"tenant_id":e["tenant_id"],"plan_id":pid,"expected_revision":e["revision"],"state":state,"expires_at":None})
            policy()
            pair=call(base,"devices/pairing-code",200,"POST",admin)["pairing_code"]
            device=call(base,"devices/enroll",201,"POST",data={"pairing_code":pair,"name":"TCP fixture"})
            local=fixture.server_address[1]
            ingress=free(20000,29999,[local])
            relay=free(30000,60000,[local,ingress])
            m=call(base,"mappings",201,"POST",admin,{"device_id":device["id"],"node_id":node,"protocol":"tcp","local_port":local,"bind_port":ingress})
            mid=m["id"]
            route="mappings/"+mid
            spec={"expected_revision":m["revision"]}
            call(base,route+"/tcp-start",401,"POST",data=spec)
            call(base,route+"/tcp-start",404,"POST",other,spec)
            call(base,route+"/start",409,"POST",admin,spec)
            call(base,route+"/udp-start",409,"POST",admin,spec)
            call(base,route+"/tcp-start",409,"POST",admin,{"expected_revision":m["revision"]+1})
            call(base,route+"/tcp-start",422,"POST",admin,{**spec,"port":12345})
            q=call(base,route+"/tcp-start",202,"POST",admin,spec)
            assert q["state"]=="queued"
            call(base,route+"/tcp-start",409,"POST",admin,spec)
            assert call(base,route+"/stop",202,"POST",admin,{"request_id":q["request_id"]})["state"]=="stopped"
            report["real_tcp_scoped_queue_and_cancel"]=True
            def start(bundle):
                q=call(base,route+"/tcp-start",202,"POST",admin,spec)
                p=subprocess.Popen([exe,"--runtime-tcp-worker",str(root),mid,str(m["revision"]),str(relay),bundle,"240000"],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                children.append(p)
                line(p,"TCP_PREVIEW_READY",45)
                state=call(base,route+"/runtime",200,token=admin)
                assert state["worker_recent"] and state["request"]["state"]=="running" and state["request"]["request_id"]==q["request_id"]
                manifest=json.loads((root/bundle/"manifest.json").read_text())
                assert manifest["byte_rate"]==131072 and manifest["commercial_bandwidth_bps"]==1048576 and manifest["request_id"]==q["request_id"]
                return p,q["request_id"],manifest["tcp_limiter_port"]
            def exchange(n,port=ingress):
                data=secrets.token_bytes(n)
                with socket.create_connection(("127.0.0.1",port),timeout=10) as s:
                    s.sendall(data)
                    reply=bytearray()
                    while len(reply)<n:
                        chunk=s.recv(min(n-len(reply),65536))
                        assert chunk,"TCP stream truncated"
                        reply.extend(chunk)
                    assert reply==data
            def closed(p,rid,guard,bundle):
                assert p.wait(timeout=15)==0
                state=call(base,route+"/runtime",200,token=admin)
                assert state["request"]["request_id"]==rid and state["request"]["state"]=="stopped" and not state["worker_recent"]
                for port in (ingress,relay,guard):
                    with socket.socket() as s:
                        s.settimeout(.5)
                        assert s.connect_ex(("127.0.0.1",port))!=0
                assert not (root/bundle).exists()
            p,rid,guard=start("tcp_first")
            started=time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(exchange,[262144,262144]))
            elapsed=time.monotonic()-started
            assert 3.8<=elapsed<=30
            report["tcp_bandwidth_measurements"]={"bytes_each_direction":524288,"elapsed_seconds":elapsed}
            report["real_tcp_noise_shared_bidirectional_cap"]=True
            call(base,route+"/stop",404,"POST",other,{"request_id":rid})
            call(base,route+"/stop",409,"POST",admin,{"request_id":secrets.token_hex(16)})
            assert call(base,route+"/stop",202,"POST",admin,{"request_id":rid})["state"]=="stopping"
            closed(p,rid,guard,"tcp_first")
            report["real_tcp_stop_closes_listeners_and_bundle"]=True
            p,rid,guard=start("tcp_second")
            exchange(1024)
            policy(state="suspended")
            call(base,route+"/tcp-start",409,"POST",admin,spec)
            policy()
            closed(p,rid,guard,"tcp_second")
            report["real_tcp_suspend_and_rapid_renewal_stops_generation"]=True
            p,rid,guard=start("tcp_third")
            exchange(1024)
            policy("legacy-v1")
            closed(p,rid,guard,"tcp_third")
            report["real_tcp_plan_change_closes_old_budget"]=True
            # Distinct processes and mappings must share the same tenant
            # capacity, including reservations for a different protocol.
            policy()
            used=[local,ingress,relay]
            def alloc(lo,hi,kind=socket.SOCK_STREAM):
                value=free(lo,hi,used,kind)
                used.append(value)
                return value
            def new_mapping(token,device,protocol,target):
                port=alloc(20000,29999,socket.SOCK_DGRAM if protocol=="udp" else socket.SOCK_STREAM)
                item=call(base,"mappings",201,"POST",token,{"device_id":device["id"],"node_id":node,"protocol":protocol,"local_port":target,"bind_port":port})
                return item
            def inventory(token=admin):
                return call(base,"commercial/entitlement",200,token=token)["entitlement"]
            def spawn_tcp(item,bundle,token=admin):
                path="mappings/"+item["id"]
                q=call(base,path+"/tcp-start",202,"POST",token,{"expected_revision":item["revision"]})
                port=alloc(30000,60000)
                child=subprocess.Popen([exe,"--runtime-tcp-worker",str(root),item["id"],str(item["revision"]),str(port),bundle,"65536"],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                children.append(child)
                return child,q["request_id"],path,port,bundle
            def ready_tcp(run):
                child,rid,path,port,bundle=run
                line(child,"TCP_PREVIEW_READY",45)
                manifest=json.loads((root/bundle/"manifest.json").read_text())
                assert manifest["byte_rate"]==65536
                return manifest["tcp_limiter_port"]
            def stop_run(run,token=admin):
                child,rid,path,port,bundle=run
                call(base,path+"/stop",202,"POST",token,{"request_id":rid})
                assert child.wait(timeout=15)==0
                assert call(base,path+"/runtime",200,token=token)["request"]["state"]=="stopped"
                assert not (root/bundle).exists()
            a=new_mapping(admin,device,"tcp",local)
            b=new_mapping(admin,device,"tcp",local)
            run_a=spawn_tcp(a,"aggregate_a")
            run_b=spawn_tcp(b,"aggregate_b")
            ready_tcp(run_a)
            ready_tcp(run_b)
            assert inventory()["reserved_bytes_per_second"]==131072 and inventory()["bandwidth_reservations"]==2
            started=time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(exchange,262144,item["bind_port"]) for item in (a,b)]
                for f in futures:f.result()
            elapsed=time.monotonic()-started
            assert 3.8<=elapsed<=30
            report["tenant_tcp_measurements"]={"bytes_each_direction":524288,"elapsed_seconds":elapsed}
            report["real_tenant_two_tcp_workers_share_fixed_budget"]=True
            # Another owner may reserve the same amount independently.
            other_ent=inventory(other)
            command("--commercial-assign",{"tenant_id":other_ent["tenant_id"],"plan_id":plan,"expected_revision":other_ent["revision"],"state":"active","expires_at":None})
            pair=call(base,"devices/pairing-code",200,"POST",other)["pairing_code"]
            other_device=call(base,"devices/enroll",201,"POST",data={"pairing_code":pair,"name":"Other TCP"})
            other_map=new_mapping(other,other_device,"tcp",local)
            run_other=spawn_tcp(other_map,"aggregate_other",other)
            ready_tcp(run_other)
            exchange(1024,other_map["bind_port"])
            assert inventory(other)["reserved_bytes_per_second"]==65536
            assert inventory()["reserved_bytes_per_second"]==131072
            stop_run(run_other,other)
            assert inventory(other)["bandwidth_reservations"]==0
            report["real_tenant_bandwidth_owner_isolation"]=True
            # A UDP worker cannot acquire a third budget while TCP owns it.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1",alloc(30000,60000,socket.SOCK_DGRAM)))
                udp.settimeout(.2)
                udp_local=udp.getsockname()[1]
                stop_echo=threading.Event()
                def udp_echo():
                    while not stop_echo.is_set():
                        try:
                            data,peer=udp.recvfrom(65535)
                            udp.sendto(data,peer)
                        except socket.timeout:continue
                        except OSError:return
                echo_thread=threading.Thread(target=udp_echo,daemon=True)
                echo_thread.start()
                try:
                    def spawn_udp(item,bundle):
                        path="mappings/"+item["id"]
                        q=call(base,path+"/udp-start",202,"POST",admin,{"expected_revision":item["revision"]})
                        rp=alloc(30000,60000)
                        ip=alloc(30000,60000,socket.SOCK_DGRAM)
                        child=subprocess.Popen([exe,"--runtime-udp-worker",str(root),item["id"],str(item["revision"]),str(rp),str(ip),bundle,"65536","1200"],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                        children.append(child)
                        return child,q["request_id"],path,rp,ip
                    denied=new_mapping(admin,device,"udp",udp_local)
                    child,denied_rid,denied_path,rp,ip=spawn_udp(denied,"aggregate_denied")
                    assert child.wait(timeout=15)!=0
                    assert "UDP_PREVIEW_READY" not in child.stdout.read()
                    assert call(base,denied_path+"/runtime",200,token=admin)["request"]["state"]=="failed_or_unknown"
                    assert inventory()["reserved_bytes_per_second"]==131072
                    report["real_tenant_cross_protocol_over_budget_denied"]=True
                    stop_run(run_a)
                    assert inventory()["reserved_bytes_per_second"]==65536
                    allowed=new_mapping(admin,device,"udp",udp_local)
                    child,udp_rid,udp_path,rp,ip=spawn_udp(allowed,"aggregate_udp")
                    line(child,"UDP_PREVIEW_READY",45)
                    assert inventory()["reserved_bytes_per_second"]==131072
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        probe.settimeout(2)
                        data=secrets.token_bytes(128)
                        probe.sendto(data,("127.0.0.1",allowed["bind_port"]))
                        assert probe.recvfrom(65535)==(data,("127.0.0.1",allowed["bind_port"]))
                    exchange(1024,b["bind_port"])
                    call(base,udp_path+"/stop",202,"POST",admin,{"request_id":udp_rid})
                    assert child.wait(timeout=15)==0
                    assert inventory()["reserved_bytes_per_second"]==65536
                    stop_run(run_b)
                    assert inventory()["reserved_bytes_per_second"]==0 and inventory()["bandwidth_reservations"]==0
                    report["real_tenant_released_budget_reused_by_other_protocol"]=True
                finally:
                    stop_echo.set()
                    echo_thread.join(timeout=2)
            # A killed supervisor cannot prove cleanup; capacity must remain
            # reserved in SQLite even though its children receive PDEATHSIG.
            crashed=spawn_tcp(a,"aggregate_crash")
            ready_tcp(crashed)
            crashed[0].kill()
            crashed[0].wait(timeout=10)
            assert inventory()["reserved_bytes_per_second"]==65536
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT mapping_id,request_id,rate_bytes_per_second FROM bandwidth_reservations").fetchall()==[(a["id"],crashed[1],65536)]
            def reservations():
                return json.loads(subprocess.check_output([exe,"--commercial-list-bandwidth",str(root)],timeout=20))["reservations"]
            stale=reservations()
            assert len(stale)==1 and stale[0]["mapping_id"]==a["id"] and stale[0]["request_id"]==crashed[1]
            stale=stale[0]
            recovery={"reservation_id":stale["id"],"tenant_id":stale["tenant_id"],"mapping_id":stale["mapping_id"],"mapping_revision":stale["mapping_revision"],"request_id":stale["request_id"],"confirmation":"offline_all_tunnels_stopped"}
            def recover(data,success=False):
                result=subprocess.run([exe,"--commercial-recover-bandwidth",str(root)],input=json.dumps(data).encode(),capture_output=True,timeout=20)
                assert (result.returncode==0)==success
                if success: assert result.stdout.decode().strip()==stale["id"]
            survivor=spawn_tcp(b,"aggregate_survivor")
            ready_tcp(survivor)
            exchange(1024,b["bind_port"])
            assert inventory()["reserved_bytes_per_second"]==131072
            # Even a valid exact stale ID cannot be released while any
            # current supervised worker owns the shared global guard.
            recover(recovery)
            assert inventory()["reserved_bytes_per_second"]==131072
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM bandwidth_recovery_audit").fetchone()==(0,)
            exchange(1024,b["bind_port"])
            report["real_bandwidth_recovery_refuses_live_worker"]=True
            extra=new_mapping(admin,device,"tcp",local)
            denied_run=spawn_tcp(extra,"aggregate_crash_denied")
            assert denied_run[0].wait(timeout=15)!=0
            assert "TCP_PREVIEW_READY" not in denied_run[0].stdout.read()
            stop_run(survivor)
            assert inventory()["reserved_bytes_per_second"]==65536
            assert inventory()["bandwidth_reservations"]==1
            report["real_tenant_crash_reservation_fail_closed"]=True
            # Check the crashed worker's known sockets have closed before
            # the trusted operator makes the explicit offline assertion.
            guard_port=json.loads((root/"aggregate_crash"/"manifest.json").read_text())["tcp_limiter_port"]
            for port in (a["bind_port"],crashed[3],guard_port):
                end=time.monotonic()+10
                while time.monotonic()<end:
                    with socket.socket() as check:
                        check.settimeout(.5)
                        if check.connect_ex(("127.0.0.1",port))!=0:break
                    time.sleep(.1)
                else: raise AssertionError("crashed listener remained reachable")
            recover({**recovery,"confirmation":"not_checked"})
            recover({**recovery,"mapping_revision":recovery["mapping_revision"]+1})
            recover({**recovery,"tenant_id":secrets.token_hex(16)})
            assert len(reservations())==1
            recover(recovery,True)
            recover(recovery)
            assert inventory()["reserved_bytes_per_second"]==0 and reservations()==[]
            with sqlite3.connect(root/"control.sqlite3") as db:
                audit=db.execute("SELECT reservation_id,tenant_id,mapping_id,mapping_revision,request_id,rate_bytes_per_second,reserved_at,confirmation FROM bandwidth_recovery_audit").fetchall()
                assert audit==[(stale["id"],stale["tenant_id"],a["id"],a["revision"],crashed[1],65536,stale["created_at"],"offline_all_tunnels_stopped")]
            # The release must not misreport the crashed request as stopped.
            assert call(base,crashed[2]+"/runtime",200,token=admin)["request"]["state"]=="running"
            report["real_bandwidth_recovery_exact_binding_audit_and_no_adoption"]=True
            recovered_a=spawn_tcp(b,"aggregate_after_recovery_a")
            new=new_mapping(admin,device,"tcp",local)
            recovered_b=spawn_tcp(new,"aggregate_after_recovery_b")
            ready_tcp(recovered_a)
            ready_tcp(recovered_b)
            assert inventory()["reserved_bytes_per_second"]==131072
            exchange(1024,b["bind_port"])
            exchange(1024,new["bind_port"])
            stop_run(recovered_a)
            stop_run(recovered_b)
            assert reservations()==[]
            report["real_bandwidth_recovered_capacity_reused_by_real_workers"]=True
            # Real finite monthly plan. Both directions and both independent
            # TCP workers share one durable UTC-month debit row.
            cap=32768
            monthly=command("--commercial-create-plan",{"code":"tcp-fixture","version":2,"name":"Monthly fixture","max_active_devices":4,
                "max_retained_devices":8,"max_mappings":8,"max_bandwidth_bps":1048576,"max_monthly_bytes":cap,"max_concurrent_connections":None})
            policy(monthly)
            tenant=inventory()["tenant_id"]
            # Seed only a prior calendar month as a migration/history fixture.
            # The product uses its real UTC clock; no test clock override.
            with sqlite3.connect(root/"control.sqlite3") as db:
                previous=db.execute("SELECT strftime('%Y-%m','now','start of month','-1 month')").fetchone()[0]
                db.execute("INSERT INTO tenant_monthly_usage VALUES (?,?,?)",(tenant,previous,cap))
            assert inventory()["monthly_charged_bytes"]==0 and inventory()["month_utc"]!=previous
            # The now-metered UDP protocol may queue a managed request.
            # Rebind the earlier fixture's actual target port and prove the
            # UDP debit persists into the subsequent independent TCP runs.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1",udp_local))
                udp.settimeout(.2)
                stop_echo=threading.Event()
                echo_thread=threading.Thread(target=udp_echo,daemon=True)
                echo_thread.start()
                try:
                    child,udp_rid,udp_path,rp,ip=spawn_udp(allowed,"monthly_udp_shared")
                    line(child,"UDP_PREVIEW_READY",45)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        probe.settimeout(2)
                        data=secrets.token_bytes(128)
                        probe.sendto(data,("127.0.0.1",allowed["bind_port"]))
                        assert probe.recvfrom(65535)==(data,("127.0.0.1",allowed["bind_port"]))
                    call(base,udp_path+"/stop",202,"POST",admin,{"request_id":udp_rid})
                    assert child.wait(timeout=15)==0
                    udp_used=inventory()["monthly_charged_bytes"]
                    assert 320<=udp_used<cap
                finally:
                    stop_echo.set()
                    echo_thread.join(timeout=2)
            monthly_a=spawn_tcp(b,"monthly_a")
            monthly_b=spawn_tcp(new,"monthly_b")
            ready_tcp(monthly_a)
            ready_tcp(monthly_b)
            initial=inventory()["monthly_charged_bytes"]
            assert udp_used+128<=initial<cap
            exchange(1024,b["bind_port"])
            exchange(1024,new["bind_port"])
            used_bytes=inventory()["monthly_charged_bytes"]
            assert used_bytes>=initial+4096 and used_bytes<cap
            assert inventory(other)["monthly_charged_bytes"]==0
            report["real_monthly_shared_tcp_debits_and_previous_month_isolation"]=True
            report["real_monthly_udp_and_tcp_share_durable_tenant_budget"]=True
            def until_closed(port):
                data=secrets.token_bytes(65536)
                got=bytearray()
                with socket.create_connection(("127.0.0.1",port),timeout=10) as conn:
                    try:
                        conn.sendall(data)
                        while len(got)<len(data):
                            chunk=conn.recv(4096)
                            if not chunk:break
                            got.extend(chunk)
                    except (ConnectionResetError,BrokenPipeError):pass
                assert bytes(got)==data[:len(got)] and len(got)<len(data)
                return len(got)
            with ThreadPoolExecutor(max_workers=2) as pool:
                forwarded=list(pool.map(until_closed,[b["bind_port"],new["bind_port"]]))
            for run in (monthly_a,monthly_b):
                assert run[0].wait(timeout=20)==0
                assert call(base,run[2]+"/runtime",200,token=admin)["request"]["state"]=="stopped"
                assert not (root/run[4]).exists()
            consumed=inventory()["monthly_charged_bytes"]
            assert cap-4096<consumed<=cap and consumed>=used_bytes+sum(forwarded)
            assert inventory()["bandwidth_reservations"]==0
            report["real_monthly_over_budget_closes_real_tcp_without_overspend"]=True
            # Restart the actual management process and check the same
            # current-month debit row remains, with the prior month intact.
            core_test.terminate(management)
            management=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            with selectors.DefaultSelector() as sel:
                sel.register(management.stdout,selectors.EVENT_READ)
                assert sel.select(20)
            address=management.stdout.readline().strip()
            assert address.startswith("LISTENING 127.0.0.1:")
            base="http://"+address.split()[1]
            assert inventory()["monthly_charged_bytes"]==consumed
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT charged_bytes FROM tenant_monthly_usage WHERE tenant_id=? AND month_utc=?",(tenant,previous)).fetchone()==(cap,)
                assert db.execute("SELECT count(*) FROM tenant_monthly_usage WHERE tenant_id=?",(tenant,)).fetchone()==(2,)
            report["real_monthly_debits_survive_management_restart"]=True
            concurrent=command("--commercial-create-plan",{"code":"tcp-fixture","version":3,"name":"Connection fixture","max_active_devices":4,
                "max_retained_devices":8,"max_mappings":8,"max_bandwidth_bps":None,"max_monthly_bytes":None,"max_concurrent_connections":2})
            policy(concurrent)
            call(base,udp_path+"/udp-start",409,"POST",admin,{"expected_revision":allowed["revision"]})
            def wait_slots(expected,token=admin):
                until=time.monotonic()+8
                while time.monotonic()<until:
                    if inventory(token)["reserved_connection_slots"]==expected:return
                    time.sleep(.05)
                raise AssertionError("connection slot count mismatch")
            run_a=spawn_tcp(b,"connection_a")
            ready_tcp(run_a)
            wait_slots(0)
            run_b=spawn_tcp(new,"connection_b")
            ready_tcp(run_b)
            wait_slots(0)
            def held(port):
                conn=socket.create_connection(("127.0.0.1",port),timeout=3)
                try:
                    data=secrets.token_bytes(32)
                    conn.sendall(data)
                    received=bytearray()
                    while len(received)<len(data):
                        piece=conn.recv(len(data)-len(received))
                        assert piece
                        received.extend(piece)
                    assert received==data
                    return conn
                except BaseException:
                    conn.close()
                    raise
            def rejected_stream(port):
                with socket.create_connection(("127.0.0.1",port),timeout=3) as conn:
                    try:
                        conn.sendall(secrets.token_bytes(32))
                        assert conn.recv(32)==b"", "over-limit stream received data"
                    except (ConnectionResetError,BrokenPipeError):pass
            with held(b["bind_port"]) as first, held(new["bind_port"]) as second:
                wait_slots(2)
                rejected_stream(b["bind_port"])
                rejected_stream(new["bind_port"])
                wait_slots(2)
                assert all(run[0].poll() is None for run in (run_a,run_b))
                first.shutdown(socket.SHUT_RDWR)
                first.close()
                wait_slots(1)
                with held(new["bind_port"]) as reused:
                    wait_slots(2)
                    assert inventory(other)["reserved_connection_slots"]==0
                wait_slots(1)
            wait_slots(0)
            stop_run(run_a)
            stop_run(run_b)
            assert inventory()["reserved_connection_slots"]==0
            report["real_tenant_tcp_connection_slots_shared_denied_and_reused"]=True
            # Crash retains an actual open stream slot; offline recovery
            # removes the exact reservation and its child slots together.
            crashed_slots=spawn_tcp(b,"connection_crash")
            guard_port=ready_tcp(crashed_slots)
            wait_slots(0)
            with held(b["bind_port"]) as active:
                wait_slots(1)
                crashed_slots[0].kill()
                crashed_slots[0].wait(timeout=10)
            assert inventory()["reserved_connection_slots"]==1
            rows=reservations()
            assert len(rows)==1 and rows[0]["request_id"]==crashed_slots[1]
            entry=rows[0]
            for port in (b["bind_port"],crashed_slots[3],guard_port):
                end=time.monotonic()+10
                while time.monotonic()<end:
                    with socket.socket() as check:
                        check.settimeout(.5)
                        if check.connect_ex(("127.0.0.1",port))!=0:break
                    time.sleep(.1)
                else:raise AssertionError("crashed connection listener remained reachable")
            spec={"reservation_id":entry["id"],"tenant_id":entry["tenant_id"],"mapping_id":entry["mapping_id"],
                  "mapping_revision":entry["mapping_revision"],"request_id":entry["request_id"],"confirmation":"offline_all_tunnels_stopped"}
            assert command("--commercial-recover-bandwidth",spec)==entry["id"]
            assert inventory()["reserved_connection_slots"]==0 and reservations()==[]
            with sqlite3.connect(root/"control.sqlite3") as db:
                assert db.execute("SELECT count(*) FROM connection_slots").fetchone()==(0,)
            report["real_crashed_connection_slot_retained_until_audited_recovery"]=True
        finally:
            for p in reversed(children):
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=10)
            core_test.terminate(management)
            fixture.shutdown()
            thread.join(timeout=5)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
assert len([v for v in report.values() if v is True])==19
