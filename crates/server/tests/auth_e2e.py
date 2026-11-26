"""Real CLI/HTTP/SQLite administrator authentication."""
import hashlib
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

exe = str(Path(sys.argv[1]).resolve())
evidence = Path(sys.argv[2])
report = {}
password = secrets.token_hex(24)

def init(root,user,pw):
    return subprocess.run([exe,"--init-admin",str(root)],
        input=json.dumps({"username":user,"password":pw}).encode(),capture_output=True,timeout=20)

def call(base,path,method="GET",token=None,data=None):
    headers={}
    if token is not None:
        headers["Authorization"]="Bearer "+token
    if data is not None:
        headers["Content-Type"]="application/json"
    req=urllib.request.Request(base+"/api/v1/auth/"+path,method=method,headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,r.read(),r.headers
    except urllib.error.HTTPError as e:
        return e.code,e.read(),e.headers

def login(base,user="operator",pw=password):
    return call(base,"login","POST",data={"username":user,"password":pw})

def token_from(result):
    code,body,headers=result
    assert code==200 and headers.get("Cache-Control")=="no-store","login failed"
    data=json.loads(body)
    assert data["token_type"]=="Bearer" and data["expires_in"]==3600
    token=data["access_token"]
    assert len(bytes.fromhex(token))==32
    return token

def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)

def launch(root):
    p=subprocess.Popen([exe,str(root),"0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
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

try:
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        db_path=root/"control.sqlite3"
        assert init(root,"operator","short").returncode!=0
        first=init(root,"operator",password)
        assert first.returncode==0 and password.encode() not in first.stdout+first.stderr
        assert init(root,"second",password).returncode!=0
        with sqlite3.connect(db_path) as db:
            row=db.execute("SELECT id,password_hash,role FROM users").fetchall()
            assert len(row)==1 and row[0][2]=="admin"
            uid,phc,_=row[0]
            assert phc.startswith("$argon2id$v=19$m=19456,t=2,p=1$") and password not in phc
            db.execute("INSERT INTO users(id,username,password_hash,role) VALUES ('ordinary','ordinary',?,'user')",(phc,))
        assert password.encode() not in db_path.read_bytes()
        report["bootstrap_and_argon2id"]=True
        p,base=launch(root)
        try:
            assert call(base,"me")[0]==401
            assert call(base,"me",token="a"*64)[0]==401
            assert call(base,"logout","POST")[0]==401
            # Even valid credentials must not reach login from a disallowed
            # browser origin. Native bearer clients remain supported.
            req=urllib.request.Request(base+"/api/v1/auth/login",method="POST",
                headers={"Content-Type":"application/json","Origin":"https://external.example.test"},
                data=json.dumps({"username":"operator","password":password}).encode())
            try:
                with urllib.request.urlopen(req,timeout=10):
                    raise AssertionError("foreign origin login unexpectedly succeeded")
            except urllib.error.HTTPError as e:
                assert e.code==403 and e.read()==b"invalid local request origin"
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT count(*) FROM admin_sessions").fetchone()==(0,)
            report["foreign_origin_valid_login_no_session"]=True
            wrong=login(base,pw=secrets.token_hex(24))
            unknown=login(base,user="unknown")
            ordinary=login(base,user="ordinary")
            assert wrong[:2]==unknown[:2]==ordinary[:2] and wrong[0]==401
            token=token_from(login(base))
            code,body,headers=call(base,"me",token=token)
            assert code==200 and headers.get("Cache-Control")=="no-store"
            assert json.loads(body)=={"id":uid,"username":"operator","role":"admin"}
            with sqlite3.connect(db_path) as db:
                digest=db.execute("SELECT token_digest FROM admin_sessions WHERE user_id=?",(uid,)).fetchone()[0]
                assert digest==hashlib.sha256(bytes.fromhex(token)).digest()
            assert token.encode() not in db_path.read_bytes()
            report["login_and_authorization"]=True
            new=token_from(login(base))
            assert new!=token and call(base,"me",token=token)[0]==401
            assert call(base,"logout","POST",new)[0]==204
            assert call(base,"me",token=new)[0]==401
            expired=token_from(login(base))
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE admin_sessions SET expires_at=unixepoch()-1 WHERE user_id=?",(uid,))
            assert call(base,"me",token=expired)[0]==401
            disabled=token_from(login(base))
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=0 WHERE id=?",(uid,))
            assert call(base,"me",token=disabled)[0]==401
            assert login(base)[0]==401
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET enabled=1 WHERE id=?",(uid,))
            assert call(base,"me",token=disabled)[0]==401
            demoted=token_from(login(base))
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET role='user' WHERE id=?",(uid,))
                db.execute("UPDATE users SET role='admin' WHERE id=?",(uid,))
            assert call(base,"me",token=demoted)[0]==401
            persisted=token_from(login(base))
            report["rotation_logout_expiry_revocation"]=True
        finally:
            stop(p)
        p,base=launch(root)
        try:
            assert call(base,"me",token=persisted)[0]==200
            assert call(base,"logout","POST",persisted)[0]==204
            assert call(base,"me",token=persisted)[0]==401
            for _ in range(12):
                assert login(base,pw=secrets.token_hex(24))[0]==401
            assert login(base)[0]==429
            report["restart_and_bounded_login"]=True
        finally:
            stop(p)
        # A separately launched process has a fresh existing login budget.
        # Corrupt the PHC in this private fixture, never a production database.
        p,base=launch(root)
        try:
            for invalid in (phc.replace("m=19456","m=1048576"),
                            phc.replace("t=2","t=1000"),
                            phc.replace("p=1","p=64"),
                            phc.replace("argon2id","argon2i")):
                with sqlite3.connect(db_path) as db:
                    db.execute("UPDATE users SET password_hash=? WHERE id=?",(invalid,uid))
                assert login(base)[0]==401
                assert call(base,"me",token=persisted)[0]==401
            with sqlite3.connect(db_path) as db:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",(phc,uid))
            fresh=token_from(login(base))
            assert call(base,"me",token=fresh)[0]==200
            report["unsupported_stored_argon2_parameters_rejected"]=True
        finally:
            stop(p)
finally:
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2),encoding="utf-8")
