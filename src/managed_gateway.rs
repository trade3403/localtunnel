//! Linux-only management of a dedicated, unprivileged HTTP/HTTPS gateway.
//! Never reload the system Nginx configuration.
#[cfg(target_os = "linux")]
mod linux {
    use crate::gateway::{gateway_config, Certificate, Route};
    use std::{fs::{self, OpenOptions}, io::{Read, Write}, net::{SocketAddr, TcpStream}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}, process::Command, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

    const NGINX: &str = "/usr/sbin/nginx";
    const MARKER: &str = "# localtunnel-managed-http ";
    const HOST: &str = "localtunnel-probe.invalid";
    const TLS_MARKER: &str = "# localtunnel-managed-https ";
    const PROBE_PATH: &str = "/.localtunnel-revision";

    pub struct TlsSettings<'a> {
        pub probe: SocketAddr,
        pub chain: &'a str,
        pub key: &'a str,
        pub ca: &'a str,
        pub minimum_days: u32,
    }

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

    fn generate(bind: SocketAddr, routes: &[Route<'_>], tls: Option<&TlsSettings<'_>>, meter: bool) -> Result<(String, String), String> {
        validate_bind(bind)?;
        if routes.iter().any(|r| r.domain == HOST) {
            return Err("reserved probe hostname".into());
        }
        let revision = format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map_err(err)?.as_nanos());
        let mut config = if let Some(tls) = tls {
            validate_bind(tls.probe)?;
            if tls.probe == bind || routes.iter().any(|r| r.port == tls.probe.port()) {
                return Err("probe port conflicts with HTTPS listener or upstream".into());
            }
            let domains = routes.iter().map(|r| r.domain.to_owned()).collect::<Vec<_>>();
            // Empty TLS gateway rejects every handshake. It must remain
            // clearable even after proof/certificate expiry; nginx -t still
            // checks the certificate/key files and generated configuration.
            if !domains.is_empty() {
                crate::certificates::check(tls.chain, tls.key, tls.ca, tls.minimum_days, &domains)?;
            }
            gateway_config(bind, routes, Some(Certificate { chain: tls.chain, key: tls.key })).map_err(err)?
        } else {
            gateway_config(bind, routes, None).map_err(err)?
        };
        if meter {
            // Only checked single-route previews. Numeric counters only;
            // never log URLs, IP addresses, headers, cookies or bodies.
            config = config.replace("    access_log off;", "    access_log off;\n    log_format lt_traffic '$request_length $bytes_sent $status';");
            config = config.replace("        location / {", &format!("        location / {{\n            access_log traffic-{revision}.log lt_traffic;"));
        }
        if let Some(tls) = tls {
            // A dedicated loopback listener checks activation even if a certificate changes.
            // The reserved HTTPS path additionally proves a verified TLS handshake.
            config = config.replace("        location / {", &format!("        location = {PROBE_PATH} {{ return 200 \"{revision}\"; }}\n        location / {{"));
            config.truncate(config.len() - 2);
            config.push_str(&format!("    server {{\n        listen {} default_server;\n        server_name _;\n        add_header X-LocalTunnel-Revision {revision} always;\n        return 421;\n    }}\n}}\n", tls.probe));
            Ok((format!("{TLS_MARKER}{bind} {} {revision}\n{config}", tls.probe), revision))
        } else {
            config = config.replacen("        return 421;", &format!("        add_header X-LocalTunnel-Revision {revision} always;\n        return 421;"), 1);
            Ok((format!("{MARKER}{bind} {revision}\n{config}"), revision))
        }
    }

    fn verify_tls(bind: SocketAddr, route: &Route<'_>, tls: &TlsSettings<'_>, revision: &str) -> bool {
        let resolve = format!("{}:{}:127.0.0.1", route.domain, bind.port());
        let url = format!("https://{}:{}{PROBE_PATH}", route.domain, bind.port());
        let out = Command::new("/usr/bin/curl").args(["--disable", "--silent", "--show-error", "--fail", "--noproxy", "*", "--connect-timeout", "2", "--max-time", "3", "--max-filesize", "65536", "--cacert", tls.ca, "--resolve", &resolve, &url]).output();
        out.is_ok_and(|o| o.status.success() && o.stdout == revision.as_bytes())
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

    fn init_mode(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>], tls: Option<&TlsSettings<'_>>) -> Result<(), String> {
        let prefix = directory(prefix)?;
        if fs::read_dir(&prefix).map_err(err)?.next().is_some() {
            return Err("managed initialization requires an empty directory".into());
        }
        let (config, _) = generate(bind, routes, tls, false)?;
        let active = prefix.join("nginx.conf");
        write_new(&active, &config)?;
        if let Err(e) = nginx(&prefix, &active, &["-t"]) {
            let _ = fs::remove_file(active);
            return Err(e);
        }
        Ok(())
    }

    fn apply_mode(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>], tls: Option<&TlsSettings<'_>>, meter: bool, business_check: impl FnOnce() -> bool) -> Result<(), String> {
        let prefix = directory(prefix)?;
        let (config, revision) = generate(bind, routes, tls, meter)?;
        let lock = prefix.join("localtunnel.lock");
        write_new(&lock, "")?;
        let _lock = Cleanup(lock);
        let active = prefix.join("nginx.conf");
        if !fs::symlink_metadata(&active).map_err(err)?.file_type().is_file() {
            return Err("managed nginx.conf must be a regular file".into());
        }
        let old = fs::read_to_string(&active).map_err(err)?;
        let identity = if let Some(tls) = tls { format!("{TLS_MARKER}{bind} {} ", tls.probe) } else { format!("{MARKER}{bind} ") };
        let old_revision = old.lines().next().and_then(|s| s.strip_prefix(&identity)).ok_or("not a managed configuration for this listener and mode")?;
        let probe = tls.map_or(bind, |t| t.probe);
        if !active_revision(probe, old_revision) {
            return Err("previous revision not running; refusing update".into());
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
        if nginx(&prefix, &active, &["-s", "reload"]).is_ok() && wait_active(probe, &revision) && tls.is_none_or(|t| routes.iter().all(|r| verify_tls(bind, r, t, &revision))) && business_check() {
            fs::remove_file(&backup).map_err(err)?;
            return Ok(());
        }
        // Preserve the old file and require a positive probe, not just a signal.
        fs::rename(&backup, &active).map_err(|e| format!("reload failed; manual recovery required: {e}"))?;
        if nginx(&prefix, &active, &["-s", "reload"]).is_ok() && wait_active(probe, old_revision) {
            Err("new revision failed; previous revision restored".into())
        } else {
            Err("new revision failed; old file restored but runtime rollback unverified".into())
        }
    }

    pub fn init(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>]) -> Result<(), String> {
        init_mode(prefix, bind, routes, None)
    }
    pub fn apply(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>]) -> Result<(), String> {
        apply_mode(prefix, bind, routes, None, false, || true)
    }
    /// Operator-provided expected body is checked only after the candidate
    /// revision is observed. A mismatch uses the same real rollback path.
    pub fn apply_checked_http(prefix: &Path, bind: SocketAddr, route: Route<'_>, expected: &[u8]) -> Result<(), String> {
        if expected.is_empty() || expected.len() > 65536 {
            return Err("expected body must be 1-65536 bytes".into());
        }
        let host=route.domain;
        apply_mode(prefix, bind, &[route], None, true, || {
            // Fixed loopback destination, validated Host, no redirects,
            // disabled user curl configuration, bounded time and response.
            let url=format!("http://{bind}/");
            let header=format!("Host: {host}");
            let out=Command::new("/usr/bin/curl").args(["--disable","--silent","--fail","--noproxy","*","--connect-timeout","2","--max-time","4","--max-filesize","65536","--header",&header,"--write-out","%{http_code}",&url]).output();
            out.is_ok_and(|o| o.status.success() && o.stdout.len()==expected.len()+3 && o.stdout.ends_with(b"200") && &o.stdout[..expected.len()]==expected)
        })
    }
    pub fn apply_checked_tls(prefix: &Path, bind: SocketAddr, route: Route<'_>, tls: &TlsSettings<'_>, expected: &[u8]) -> Result<(), String> {
        if expected.is_empty() || expected.len() > 65536 {
            return Err("expected body must be 1-65536 bytes".into());
        }
        let host=route.domain;
        apply_mode(prefix, bind, &[route], Some(tls), true, || {
            let resolve=format!("{host}:{}:127.0.0.1",bind.port());
            let url=format!("https://{host}:{}/",bind.port());
            let out=Command::new("/usr/bin/curl").args(["--disable","--silent","--fail","--noproxy","*","--connect-timeout","2","--max-time","4","--max-filesize","65536","--cacert",tls.ca,"--resolve",&resolve,"--write-out","%{http_code}",&url]).output();
            out.is_ok_and(|o| o.status.success() && o.stdout.len()==expected.len()+3 && o.stdout.ends_with(b"200") && &o.stdout[..expected.len()]==expected)
        })
    }
    pub fn init_tls(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>], tls: &TlsSettings<'_>) -> Result<(), String> {
        init_mode(prefix, bind, routes, Some(tls))
    }
    pub fn apply_tls(prefix: &Path, bind: SocketAddr, routes: &[Route<'_>], tls: &TlsSettings<'_>) -> Result<(), String> {
        apply_mode(prefix, bind, routes, Some(tls), false, || true)
    }
}

#[cfg(target_os = "linux")]
pub use linux::{apply, init, apply_tls, init_tls, apply_checked_http, apply_checked_tls, TlsSettings};
