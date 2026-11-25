"""Actual SQLite snapshot and isolated recovery, with real API credentials."""
from contextlib import closing
import hashlib
import json
import os
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

def command(*args,input=None):
    return subprocess.run([exe,*map(str,args)],input=input,capture_output=True,timeout=40)

def stop(proc):
    proc.terminate()
    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=5)

def launch(root):
    proc=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout,selectors.EVENT_READ)
            assert sel.select(20),"API startup timeout"
        line=proc.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:")
        return proc,"http://"+line.split()[1]
    except BaseException:
        stop(proc)
        raise

def call(base,path,method="GET",token=None,data=None,status=200):
    headers={}
    if token:headers["Authorization"]="Bearer "+token
    if data is not None:headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/"+path,method=method,headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            result=(r.status,r.read())
    except urllib.error.HTTPError as e:
        result=(e.code,e.read())
    assert result[0]==status, f"unexpected status for {path}: {result[0]}"
    return json.loads(result[1]) if status in (200,201,202) else None

def login(base):
    return call(base,"auth/login","POST",data={"username":"operator","password":password})["access_token"]

def issue(base,admin):
    return call(base,"devices/pairing-code","POST",admin)["pairing_code"]

def enroll(base,code,status=201):
    return call(base,"devices/enroll","POST",data={"pairing_code":code,"name":"snapshot fixture"},status=status)

try:
    with tempfile.TemporaryDirectory() as d:
        root=Path(d)
        live=root/"live"
        live.mkdir(mode=0o700)
        backup=root/"backup"
        restored=root/"restored"
        dbpath=live/"control.sqlite3"
        assert command("--init-admin",live,input=json.dumps({"username":"operator","password":password}).encode()).returncode==0
        node=command("--add-node",live,"snapshot node")
        assert node.returncode==0
        node_id=node.stdout.decode().strip()
        proc,base=launch(live)
        try:
            admin=login(base)
            device=enroll(base,issue(base,admin))
            did=device["id"]
            mapping=call(base,"mappings","POST",admin,{"device_id":did,"node_id":node_id,"protocol":"tcp","local_port":8080,"bind_port":20001},201)
            mid=mapping["id"]
            # Existing enabled inventory is deliberately seeded, because the
            # public draft API does not allow enabling a mapping directly.
            legacy=call(base,"mappings","POST",admin,{"device_id":did,"node_id":node_id,"protocol":"tcp","local_port":8081,"bind_port":20002},201)
            domain=call(base,"domains","POST",admin,{"hostname":"restore.example.invalid"},201)
            http=call(base,"mappings","POST",admin,{"device_id":did,"node_id":node_id,"domain_id":domain["id"],"protocol":"http","local_port":8082,"bind_port":20003},201)
            with closing(sqlite3.connect(dbpath)) as seed:
                seed.execute("UPDATE mappings SET enabled=1 WHERE id=?",(legacy["id"],))
                # Seed a formerly verified proof, not a live DNS claim.
                seed.execute("UPDATE domains SET verified_at=unixepoch() WHERE id=?",(domain["id"],))
                seed.commit()
            verified=call(base,"domains/"+domain["id"],token=admin)
            assert verified["verified_at"] is not None and verified["txt_value"]==domain["txt_value"]
            assert call(base,"mappings/"+legacy["id"],token=admin)["enabled"] is True
            queued=call(base,"mappings/"+http["id"]+"/start","POST",admin,{"expected_revision":http["revision"]},202)
            assert queued["state"]=="queued"
            pending=issue(base,admin)
            call(base,"devices/"+did+"/status","POST",device["device_token"],{"reported_revision":2,"reported_state":"running"})
            # Real live committed WAL content, plus an uncommitted row that
            # must not appear in the consistent backup.
            with closing(sqlite3.connect(dbpath)) as db:
                assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0]=="wal"
                db.execute("PRAGMA wal_autocheckpoint=0")
                db.execute("UPDATE devices SET name='committed WAL name' WHERE id=?",(did,))
                db.commit()
                assert Path(str(dbpath)+"-wal").stat().st_size>0
                db.execute("UPDATE devices SET name='uncommitted name' WHERE id=?",(did,))
                # A read-only snapshot may coexist with a WAL writer.
                assert command("--backup-db",live,backup).returncode==0
                db.rollback()
            snap=backup/"snapshot.sqlite3"
            assert backup.stat().st_mode&0o777==0o700 and snap.stat().st_mode&0o777==0o600
            assert sorted(p.name for p in backup.iterdir())==["snapshot.sqlite3"]
            with closing(sqlite3.connect("file:"+str(snap)+"?mode=ro",uri=True)) as db:
                assert db.execute("PRAGMA integrity_check").fetchone()==("ok",)
                assert db.execute("SELECT name FROM devices WHERE id=?",(did,)).fetchone()==("committed WAL name",)
                assert db.execute("SELECT count(*) FROM admin_sessions").fetchone()==(1,)
                assert db.execute("SELECT enabled FROM mappings WHERE id=?",(legacy["id"],)).fetchone()==(1,)
                assert db.execute("SELECT request_id,state FROM runtime_requests WHERE mapping_id=?",(http["id"],)).fetchone()==(queued["request_id"],"queued")
                assert db.execute("SELECT verified_at,verification_token FROM domains WHERE id=?",(domain["id"],)).fetchone()==(verified["verified_at"],domain["txt_value"].split("=",1)[1])
            before=hashlib.sha256(snap.read_bytes()).digest()
            assert command("--backup-db",live,backup).returncode!=0
            assert hashlib.sha256(snap.read_bytes()).digest()==before
            assert call(base,"auth/me",token=admin)["username"]=="operator"
            report["real_consistent_live_wal_snapshot_and_no_overwrite"]=True
            # Later revocation must not be undone by restoring the old snapshot.
            call(base,"devices/"+did+"/revoke","POST",admin,status=204)
            call(base,"auth/logout","POST",admin,status=204)
        finally:
            stop(proc)
        assert command("--restore-db",backup,restored).returncode==0
        assert hashlib.sha256(snap.read_bytes()).digest()==before
        recovered=restored/"control.sqlite3"
        assert recovered.stat().st_mode&0o777==0o600
        with closing(sqlite3.connect(recovered)) as db:
            assert db.execute("PRAGMA integrity_check").fetchone()==("ok",)
            assert db.execute("PRAGMA foreign_key_check").fetchall()==[]
            for table in ("admin_sessions","device_pairings","device_status","runtime_requests"):
                assert db.execute("SELECT count(*) FROM "+table).fetchone()==(0,)
            enabled,digest=db.execute("SELECT enabled,credential_digest FROM devices WHERE id=?",(did,)).fetchone()
            assert enabled==0 and digest!=hashlib.sha256(device["device_token"].encode()).digest()
            assert db.execute("SELECT count(*) FROM management_audit").fetchone()[0]>0
        proc,base=launch(restored)
        try:
            call(base,"auth/me",token=admin,status=401)
            call(base,"devices/"+did+"/identity",token=device["device_token"],status=401)
            enroll(base,pending,401)
            fresh=login(base)
            assert call(base,"mappings/"+mid,token=fresh)==mapping
            assert call(base,"devices",token=fresh)[0]["enabled"] is False
            fresh_device=enroll(base,issue(base,fresh))
            assert call(base,"devices/"+fresh_device["id"]+"/identity",token=fresh_device["device_token"])["enabled"]
            assert call(base,"mappings/"+mid+"/runtime",token=fresh)["request"] is None
            disabled=call(base,"mappings/"+legacy["id"],token=fresh)
            assert disabled==dict(legacy,enabled=False,revision=legacy["revision"]+1)
            assert call(base,"mappings/"+http["id"],token=fresh)==http
            state=call(base,"mappings/"+http["id"]+"/runtime",token=fresh)
            assert state["request"] is None and state["worker_recent"] is False
            cleared=call(base,"domains/"+domain["id"],token=fresh)
            assert cleared["hostname"]==domain["hostname"] and cleared["verified_at"] is None and cleared["txt_value"] is None
            call(base,"mappings/"+http["id"]+"/start","POST",fresh,{"expected_revision":http["revision"]},409)
            call(base,"mappings/"+http["id"]+"/stop","POST",fresh,{"request_id":queued["request_id"]},409)
            challenge=call(base,"domains/"+domain["id"]+"/challenge","POST",fresh)
            assert challenge["verified_at"] is None and challenge["txt_value"] and challenge["txt_value"]!=domain["txt_value"]
            call(base,"mappings/"+http["id"]+"/start","POST",fresh,{"expected_revision":http["revision"]},409)
            report["restored_runtime_and_domain_authority_cleared"]=True
            report["real_restored_login_mapping_and_stale_credentials_rejected"]=True
        finally:
            stop(proc)
        assert command("--restore-db",backup,restored).returncode!=0
        assert command("--restore-db",backup,live).returncode!=0
        empty=root/"empty"
        empty.mkdir(mode=0o700)
        assert command("--restore-db",backup,empty).returncode!=0 and not list(empty.iterdir())
        bad=root/"bad"
        bad.mkdir(mode=0o700)
        badsnap=bad/"snapshot.sqlite3"
        badsnap.write_bytes(b"corrupt")
        badsnap.chmod(0o600)
        missing=root/"missing"
        assert command("--restore-db",bad,missing).returncode!=0 and not missing.exists()
        badsnap.write_bytes(snap.read_bytes())
        with sqlite3.connect(badsnap) as db:
            db.execute("CREATE TABLE unexpected(x)")
        assert command("--restore-db",bad,missing).returncode!=0 and not missing.exists()
        badsnap.unlink()
        badsnap.symlink_to(snap)
        assert command("--restore-db",bad,missing).returncode!=0 and not missing.exists()
        assert not list(root.glob(".snapshot-*"))
        assert hashlib.sha256(snap.read_bytes()).digest()==before
        report["corrupt_schema_symlink_and_existing_destination_refused"]=True
        # Use private sparse fixture files: test logical-length admission,
        # not actual filesystem exhaustion or a hard allocation quota.
        bounded=root/"bounded"
        bounded.mkdir(mode=0o700)
        control=bounded/"control.sqlite3"
        control.write_bytes(snap.read_bytes())
        control.chmod(0o600)
        cap=256*1024*1024
        side=bounded/"control.sqlite3-wal"
        with side.open("wb") as f:
            f.truncate(cap)
        side.chmod(0o600)
        assert control.stat().st_size+side.stat().st_size>cap
        rejected=command("--backup-db",bounded,missing)
        assert rejected.returncode!=0 and b"source budget exceeded" in rejected.stderr
        assert not missing.exists() and side.stat().st_size==cap
        side.unlink()
        assert hashlib.sha256(control.read_bytes()).digest()==before
        # Positive control: same database succeeds without the over-budget sidecar.
        assert command("--backup-db",bounded,root/"bounded-ok").returncode==0
        oversized=root/"oversized"
        oversized.mkdir(mode=0o700)
        oversized_snap=oversized/"snapshot.sqlite3"
        with oversized_snap.open("wb") as f:
            f.truncate(cap+1)
        oversized_snap.chmod(0o600)
        rejected=command("--restore-db",oversized,missing)
        assert rejected.returncode!=0 and b"unsafe or oversized database file" in rejected.stderr
        assert not missing.exists() and oversized_snap.stat().st_size==cap+1
        oversized_snap.unlink()
        oversized_snap.write_bytes(snap.read_bytes())
        oversized_snap.chmod(0o600)
        side=oversized/"snapshot.sqlite3-wal"
        side.touch(mode=0o600)
        rejected=command("--restore-db",oversized,missing)
        assert rejected.returncode!=0 and b"destination or sidecar already exists" in rejected.stderr
        assert side.exists() and not missing.exists()
        side.unlink()
        assert command("--restore-db",oversized,root/"bounded-restored").returncode==0
        assert hashlib.sha256(oversized_snap.read_bytes()).digest()==before
        assert not list(root.glob(".snapshot-*"))
        report["snapshot_size_and_sidecar_admission_recovery"]=True
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
