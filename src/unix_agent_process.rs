//! Unix foreground agent. A successful exec replaces this process, so the
//! operator/service manager owns the exact engine PID. No detached child.
use crate::unix_agent_store::{checked_config, private_dir, trusted_path, uid};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, &'static str>;
const LIMIT: u64 = 64 * 1024 * 1024;
const ENGINE: &str = "rathole";
const LOCK: &str = ".agent.lock";
extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

fn pin() -> Result<&'static str> {
    let digest=option_env!("LOCALTUNNEL_AGENT_ENGINE_SHA256")
        .ok_or("agent engine digest not configured at build time")?;
    if digest.len()!=64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid build-time engine digest");
    }
    Ok(digest)
}

fn digest(data: &[u8]) -> Result<String> {
    // Only trusted OS-installed absolute tools, no shell or PATH lookup.
    // Clear environment (including Perl loader and locale overrides on macOS).
    #[cfg(target_os="macos")]
    let mut command=Command::new("/usr/bin/shasum");
    #[cfg(not(target_os="macos"))]
    let mut command=Command::new("/usr/bin/sha256sum");
    #[cfg(target_os="macos")]
    command.args(["-a","256"]);
    let mut child=command.env_clear().env("LC_ALL","C").stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
        .map_err(|_| "cannot start system SHA256 utility")?;
    let write_result=child.stdin.take().ok_or("SHA256 pipe unavailable")
        .and_then(|mut pipe| pipe.write_all(data).map_err(|_| "SHA256 input failed"));
    if write_result.is_err() {
        let _=child.kill();
        let _=child.wait();
        return Err("SHA256 input failed");
    }
    let output=child.wait_with_output().map_err(|_| "SHA256 utility failed")?;
    if !output.status.success() {
        return Err("SHA256 utility failed");
    }
    let line=std::str::from_utf8(&output.stdout).map_err(|_| "invalid SHA256 output")?;
    let hash=line.split_whitespace().next().ok_or("missing SHA256 output")?;
    if hash.len()!=64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid SHA256 output");
    }
    Ok(hash.to_owned())
}

fn engine_meta(m: &Metadata, installed: bool) -> Result<()> {
    if !m.is_file() || m.nlink()!=1 || !(1..=LIMIT).contains(&m.len())
        || (m.uid()!=uid() && m.uid()!=0) || m.mode()&0o022!=0
        || (installed && (m.uid()!=uid() || m.mode()&0o7777!=0o700)) {
        return Err("invalid agent engine file");
    }
    Ok(())
}

fn verified_engine(path: &Path, installed: bool) -> Result<Vec<u8>> {
    let expected=pin()?;
    if !path.is_absolute() {
        return Err("agent engine path must be absolute");
    }
    trusted_path(path.parent().ok_or("agent engine needs parent")?)?;
    let before=fs::symlink_metadata(path).map_err(|_| "agent engine unavailable")?;
    engine_meta(&before,installed)?;
    let file=File::open(path).map_err(|_| "cannot open agent engine")?;
    let after=file.metadata().map_err(|_| "agent engine metadata unavailable")?;
    engine_meta(&after,installed)?;
    if (before.dev(),before.ino())!=(after.dev(),after.ino()) {
        return Err("agent engine replaced while opening");
    }
    let mut data=Vec::new();
    file.take(LIMIT+1).read_to_end(&mut data).map_err(|_| "cannot read agent engine")?;
    if data.len() as u64!=after.len() || digest(&data)?!=expected {
        return Err("agent engine digest mismatch");
    }
    Ok(data)
}

pub fn install(root: &Path, source: &Path) -> Result<()> {
    private_dir(root)?;
    let data=verified_engine(source,false)?;
    let dest=root.join(ENGINE);
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o700)
        .open(&dest).map_err(|_| "cannot install new private engine")?;
    let result=(|| {
        file.write_all(&data).and_then(|_| file.sync_all())
            .map_err(|_| "cannot write private engine")?;
        engine_meta(&file.metadata().map_err(|_| "agent engine metadata unavailable")?,true)?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _=fs::remove_file(dest);
    }
    result
}

fn lock_meta(m: &Metadata) -> Result<()> {
    if !m.is_file() || m.uid()!=uid() || m.nlink()!=1 || m.mode()&0o7777!=0o600 || m.len()!=0 {
        return Err("invalid agent lock file");
    }
    Ok(())
}

fn lock(root: &Path) -> Result<File> {
    let path=root.join(LOCK);
    match fs::symlink_metadata(&path) {
        Ok(m)=>lock_meta(&m)?,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
        Err(_)=>return Err("agent lock unavailable"),
    }
    let file=OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .open(&path).map_err(|_| "cannot open agent lock")?;
    lock_meta(&file.metadata().map_err(|_| "agent lock metadata unavailable")?)?;
    // LOCK_EX | LOCK_NB: Linux and Darwin have the same values.
    if unsafe { flock(file.as_raw_fd(),2|4) }!=0 {
        return Err("agent store already running or lock unavailable");
    }
    // F_SETFD=2, clear FD_CLOEXEC. Keep this descriptor across exec.
    // Do not unlink the lock file; the kernel releases the lock on exit.
    if unsafe { fcntl(file.as_raw_fd(),2,0i32) } == -1 {
        return Err("cannot preserve agent lock across exec");
    }
    Ok(file)
}

pub fn run(root: &Path) -> Result<()> {
    private_dir(root)?;
    let config=checked_config(root)?;
    let engine=root.join(ENGINE);
    let _lock=lock(root)?;
    verified_engine(&engine,true)?;
    // Only the private, checked configuration is passed to the pinned engine.
    // Same-uid processes/root and the trusted OS utilities are in the TCB.
    // No credentials in argv/env; suppress upstream logs in this preview.
    let _err=Command::new(&engine).arg(&config).env_clear().env("RUST_LOG","off")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).exec();
    Err("cannot execute private agent engine")
}
