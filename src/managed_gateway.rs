//! Linux-only management of a dedicated, unprivileged HTTP gateway.
//! Never reload the system Nginx configuration.
#[cfg(target_os = "linux")]
mod linux {
    use crate::gateway::{gateway_config, Route};
    use std::{fs::{self, OpenOptions}, io::{Read, Write}, net::{SocketAddr, TcpStream}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}, process::Command, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

    const NGINX: &str = "/usr/sbin/nginx";
    const MARKER: &str = "# localtunnel-managed-http ";
    const HOST: &str = "localtunnel-probe.invalid";

    fn err(e: impl std::fmt::Display) -> String { e.to_string() }

    fn directory(prefix: &Path) -> Result<PathBuf, String> {
        let m = fs::symlink_metadata(prefix).map_err(err)?;
        if !prefix.is_absolute() || !m.is_dir() || m.file_type().is_symlink() || m.permissions().mode() & 0o022 != 0 {
            return Err("use an absolute dedicated directory, not a symlink or group/world-writable directory".into());
        }
        fs::canonicalize(prefix).map_err(err)
    }

    fn write_new(path: &Path, text: &str) -> Result<(), String> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(err)?;
        if let Err(e) = f.write_all(text.as_bytes()).and_then(|_| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(path);
            return Err(err(e));
        }
        Ok(())
    }

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }

    fn validate_bind(bind: SocketAddr) -> Result<(), String> {
        if bind.ip().to_string() != "127.0.0.1" || bind.port() < 1024 {
            return Err("managed preview requires IPv4 loopback and port >= 1024".into());
        }
        Ok(())
    }

    fn generate(bind: SocketAddr, routes: &[Route<'_>]) -> Result<(String, String), String> {
        validate_bind(bind)?;
        if routes.iter().any(|r| r.domain == HOST) {
            return Err("reserved probe hostname".into());
        }
        let revision = format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map_err(err)?.as_nanos());
        let config = gateway_config(bind, routes, None).map_err(err)?;
        let config = config.replacen("        return 421;", &format!("        add_header X-LocalTunnel-Revision {revision} always;\n        return 421;"), 1);
        Ok((format!("{MARKER}{bind} {revision}\n{config}"), revision))
    }

    fn nginx(prefix: &Path, config: &Path, args: &[&str]) -> Result<(), String> {
        let status = Command::new(NGINX).arg("-p").arg(prefix).arg("-c").arg(config).args(args).status().map_err(err)?;
        if status.success() { Ok(()) } else { Err(format!("Nginx command failed: {status}")) }
    }

    fn active_revision(bind: SocketAddr, revision: &str) -> bool {
        let result = (|| -> std::io::Result<bool> {
            let mut s = TcpStream::connect_timeout(&bind, Duration::from_millis(500))?;
            s.set_read_timeout(Some(Duration::from_millis(750)))?;
            s.set_write_timeout(Some(Duration::from_millis(500)))?;
            s.write_all(format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n").as_bytes())?;
            let mut data = Vec::new();
            s.take(8192).read_to_end(&mut data)?;
            let response = String::from_utf8_lossy(&data);
            let head = response.split("\r\n\r\n").next().unwrap_or("");
            Ok(head.starts_with("HTTP/1.1 421 ") && head.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| name.eq_ignore_ascii_case("x-localtunnel-revision") && value.trim() == revision)
            }))
        })();
        result.unwrap_or(false)
    }

    fn wait_active(bind: SocketAddr, revision: &str) -> bool {
        let end = Instant::now() + Duration::from_secs(8);
        while Instant::now() < end {
            if active_revision(bind, revision) { return true; }
            thread::sleep(Duration::from_millis(150));
        }
        false
    }

    pub fn init(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>]) -> Result<(), String> {
        let prefix = directory(prefix)?;
        if fs::read_dir(&prefix).map_err(err)?.next().is_some() {
            return Err("managed initialization requires an empty directory".into());
        }
        let (config, _) = generate(bind, routes)?;
        let active = prefix.join("nginx.conf");
        write_new(&active, &config)?;
        if let Err(e) = nginx(&prefix, &active, &["-t"]) {
            let _ = fs::remove_file(active);
            return Err(e);
        }
        Ok(())
    }

    pub fn apply(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>]) -> Result<(), String> {
        let prefix = directory(prefix)?;
        let (config, revision) = generate(bind, routes)?;
        let lock = prefix.join("localtunnel.lock");
        write_new(&lock, "")?;
        let _lock = Cleanup(lock);
        let active = prefix.join("nginx.conf");
        if !fs::symlink_metadata(&active).map_err(err)?.file_type().is_file() {
            return Err("managed nginx.conf must be a regular file".into());
        }
        let old = fs::read_to_string(&active).map_err(err)?;
        let header = old.lines().next().and_then(|s| s.strip_prefix(MARKER)).ok_or("not a LocalTunnel managed HTTP configuration")?;
        let (old_bind, old_revision) = header.split_once(' ').ok_or("invalid managed header")?;
        if old_bind != bind.to_string() || !active_revision(bind, old_revision) {
            return Err("listener change or previous revision not running; refusing update".into());
        }

        let candidate = prefix.join("nginx.candidate.conf");
        let backup = prefix.join("nginx.previous.conf");
        // A stale backup is intentional evidence of an interrupted operation.
        if backup.exists() { return Err("previous configuration backup exists; inspect before retry".into()); }
        write_new(&candidate, &config)?;
        let _candidate = Cleanup(candidate.clone());
        nginx(&prefix, &candidate, &["-t"])?;
        write_new(&backup, &old)?;
        if let Err(e) = fs::rename(&candidate, &active) {
            let _ = fs::remove_file(&backup);
            return Err(err(e));
        }
        if nginx(&prefix, &active, &["-s", "reload"]).is_ok() && wait_active(bind, &revision) {
            fs::remove_file(&backup).map_err(err)?;
            return Ok(());
        }
        // Preserve the old file and require a positive probe, not just a signal.
        fs::rename(&backup, &active).map_err(|e| format!("reload failed; manual recovery required: {e}"))?;
        if nginx(&prefix, &active, &["-s", "reload"]).is_ok() && wait_active(bind, old_revision) {
            Err("new revision failed; previous revision restored".into())
        } else {
            Err("new revision failed; old file restored but runtime rollback unverified".into())
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{apply, init};
