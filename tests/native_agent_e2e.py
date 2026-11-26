"""Actual native CLI configuration and filesystem checks, not tunnel E2E."""
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import subprocess
import sys
import tempfile

exe = Path(sys.argv[1]).resolve(strict=True)
expected_os, expected_machine = sys.argv[2:4]
output = Path(sys.argv[4])
report = {}
token = secrets.token_hex(32)
key = "A" * 43 + "="  # syntactic fixture; never used for a real Noise handshake
env = dict(os.environ, LOCALTUNNEL_TOKEN=token, LOCALTUNNEL_SERVER_PUBLIC_KEY=key)

def run(*args, success=True):
    p = subprocess.run([str(exe), *map(str,args)], env=env, capture_output=True, timeout=10)
    assert (p.returncode == 0) == success, "unexpected native CLI exit status"
    assert token.encode() not in p.stdout and token.encode() not in p.stderr, "credential leaked to output"
    return p.stdout

try:
    actual_os = platform.system()
    actual_machine = platform.machine().lower()
    assert actual_os == expected_os and actual_machine == expected_machine, "wrong native runner architecture"
    rust = subprocess.check_output(["rustc","-vV"], text=True, timeout=10)
    host = next(line.split(": ",1)[1] for line in rust.splitlines() if line.startswith("host: "))
    hosts = {
        ("Linux","x86_64"):"x86_64-unknown-linux-gnu",
        ("Linux","aarch64"):"aarch64-unknown-linux-gnu",
        ("Darwin","x86_64"):"x86_64-apple-darwin",
        ("Darwin","arm64"):"aarch64-apple-darwin",
    }
    assert host == hosts[(expected_os,expected_machine)], "Rust compiler is not native"
    # Inspect actual native executable format; a translated binary is insufficient.
    with exe.open("rb") as stream:
        header=stream.read(64)
    if actual_os=="Linux":
        assert header[:6]==b"\x7fELF\x02\x01"
        assert int.from_bytes(header[18:20],"little")==({"x86_64":62,"aarch64":183}[actual_machine])
    else:
        assert header[:4]==b"\xcf\xfa\xed\xfe"
        assert int.from_bytes(header[4:8],"little")==({"x86_64":0x01000007,"arm64":0x0100000c}[actual_machine])
    assert run("--version").startswith(b"localtunnel ")
    report["native_binary_architecture_and_execution"]=True
    report["platform"]={"os":actual_os,"machine":actual_machine,"rust_host":host,
                        "rustc":rust.splitlines()[0],"binary_sha256":hashlib.sha256(exe.read_bytes()).hexdigest(),
                        "binary_bytes":exe.stat().st_size}
    with tempfile.TemporaryDirectory(prefix="localtunnel-native-") as tmp:
        root=Path(tmp)
        root.chmod(0o700)
        config=root/"client.toml"
        # Even an ordinary default umask cannot make generated credentials public.
        previous=os.umask(0o022)
        try:
            run("client-config",config,"127.0.0.1:2333","web","127.0.0.1:8080")
            assert stat.S_IMODE(config.stat().st_mode)==0o600
            original=config.read_bytes()
            assert b'type = "noise"' in original and token.encode() in original
            assert b'local_addr = "127.0.0.1:8080"' in original
            assert b'remote_public_key = "'+key.encode()+b'"' in original
            run("client-config",config,"127.0.0.1:2333","web","127.0.0.1:8081",success=False)
            assert config.read_bytes()==original
            alias=root/"alias.toml"
            alias.symlink_to(config)
            run("client-config",alias,"127.0.0.1:2333","web","127.0.0.1:8081",success=False)
            assert alias.is_symlink() and config.read_bytes()==original
            invalid=root/"invalid.toml"
            run("client-config",invalid,"127.0.0.1:2333","web","0.0.0.0:8080",success=False)
            assert not invalid.exists()
            run("client-config",invalid,"127.0.0.1:2333","../escape","127.0.0.1:8080",success=False)
            assert not invalid.exists()
        finally:
            os.umask(previous)
        report["native_private_config_and_no_overwrite"]=True
        report["native_invalid_target_and_mapping_rejected"]=True
finally:
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding="utf-8")
