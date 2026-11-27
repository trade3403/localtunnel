"""Real process, HTTP and SQLite integration; Linux hosted runner only."""
import hashlib
import json
import os
from pathlib import Path
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


def launch(directory):
    p = subprocess.Popen([exe, str(directory), "0"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            assert selector.select(20), "server startup timeout"
        line = p.stdout.readline().strip()
        assert line.startswith("LISTENING 127.0.0.1:"), "server did not bind loopback"
        return p, "http://" + line.split()[1]
    except BaseException:
        stop(p)
        raise


def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=5)


def http(base, path, method="GET"):
    req = urllib.request.Request(base + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def reject(db, sql, args=()):
    try:
        db.execute(sql, args)
    except sqlite3.IntegrityError:
        return
    raise AssertionError("database constraint did not reject invalid row")


def assert_migrations(db):
    # Exact current migration inventory and contents, not a count alone.
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    expected = [(int(path.stem.split("_", 1)[0]), 1, hashlib.sha384(path.read_bytes()).digest())
                for path in sorted(migrations.glob("*.sql"))]
    assert [version for version, _, _ in expected] == list(range(1, 18))
    actual = db.execute("SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version").fetchall()
    assert actual == expected, "database migration inventory or checksum mismatch"


def rejected_start(directory):
    p = subprocess.run([exe, str(directory), "0"], capture_output=True, timeout=10)
    assert p.returncode == 1 and b"LISTENING" not in p.stdout


try:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        db_path = root / "control.sqlite3"
        p, base = launch(root)
        try:
            assert db_path.stat().st_mode & 0o777 == 0o600
            assert http(base, "/healthz") == (200, b"ok")
            assert http(base, "/readyz") == (200, b"ready")
            assert http(base, "/api/v1/mappings")[0] == 401
            assert http(base, "/healthz", "POST")[0] == 405
            report["real_loopback_http"] = True
            with sqlite3.connect(db_path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                assert db.execute("PRAGMA foreign_keys").fetchone() == (1,)
                assert_migrations(db)
                db.executemany("INSERT INTO users(id,username,password_hash,role) VALUES (?,?,?,?)",
                               [("u1","fixture1","fixture-hash-not-a-login","admin"),
                                ("u2","fixture2","fixture-hash-not-a-login","user")])
                db.execute("INSERT INTO devices(id,owner_id,name,credential_digest) VALUES ('d1','u1','fixture',zeroblob(32))")
                db.execute("INSERT INTO nodes(id,name) VALUES ('n1','fixture')")
                db.execute("INSERT INTO domains(id,owner_id,hostname) VALUES ('h1','u1','example.test')")
                reject(db, "INSERT INTO domains(id,owner_id,hostname) VALUES ('h2','u2','EXAMPLE.TEST')")
                insert = "INSERT INTO mappings(id,owner_id,device_id,node_id,domain_id,protocol,local_port,bind_port) VALUES (?,?,?,?,?,?,?,?)"
                db.execute(insert, ("m1","u1","d1","n1","h1","https",8080,20000))
                reject(db, insert, ("m2","u2","d1","n1",None,"tcp",8080,20001))
                reject(db, insert, ("m2","u1","d1","n1",None,"tcp",8080,20000))
                reject(db, insert, ("m2","u1","d1","n1",None,"tcp",0,20002))
                reject(db, insert, ("m2","u1","d1","n1",None,"http",8080,20002))
                reject(db, insert, ("m2","u1","d1","n1","h1","udp",8080,20002))
                reject(db, insert, ("m2","u1","d1","n1",None,"udp",8080,20000))
                assert db.execute("SELECT enabled FROM mappings").fetchone() == (0,)
                assert db.execute("PRAGMA foreign_key_check").fetchall() == []
                report["migration_and_constraints"] = True
        finally:
            stop(p)
        # Compatibility: old private-dir databases may have been created
        # with 0644. Tighten the exact owned regular file on startup.
        db_path.chmod(0o644)
        p, base = launch(root)
        try:
            assert db_path.stat().st_mode & 0o777 == 0o600
            assert http(base, "/readyz") == (200, b"ready")
            with sqlite3.connect(db_path) as db:
                assert db.execute("SELECT count(*) FROM mappings").fetchone() == (1,)
                assert_migrations(db)
                # Simulate lost table: readiness must fail, liveness still responds.
                db.execute("DROP TABLE mappings")
            assert http(base, "/readyz") == (503, b"not ready")
            assert http(base, "/healthz") == (200, b"ok")
            report["restart_persistence_and_readiness"] = True
        finally:
            stop(p)
        with tempfile.TemporaryDirectory() as insecure:
            os.chmod(insecure, 0o755)
            rejected_start(insecure)
            os.chmod(insecure, 0o700)
            (Path(insecure) / "control.sqlite3").symlink_to(db_path)
            rejected_start(insecure)
        report["unsafe_path_rejected"] = True
        # A hard link to the real DB must be rejected, without changing
        # the underlying file permissions or opening the linked database.
        with tempfile.TemporaryDirectory() as linked:
            os.link(db_path, Path(linked) / "control.sqlite3")
            rejected_start(linked)
            assert db_path.stat().st_nlink == 2
        assert db_path.stat().st_nlink == 1
        with tempfile.TemporaryDirectory() as sidecar:
            outside = Path(sidecar) / "outside"
            outside.write_bytes(b"do not touch")
            os.link(outside, Path(sidecar) / "control.sqlite3-wal")
            rejected_start(sidecar)
            assert outside.read_bytes() == b"do not touch"
        report["linux_private_sqlite_modes_and_hardlinks"] = True
finally:
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2), encoding="utf-8")
