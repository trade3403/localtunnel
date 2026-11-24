//! Offline certificate preflight; does not issue certificates or change DNS.
#[cfg(target_os = "linux")]
mod linux {
    use crate::gateway::domain_valid;
    use std::{path::Path, process::{Command, Output}, time::Duration};

    const OPENSSL: &str = "/usr/bin/openssl";

    fn run(args: &[&str]) -> Result<Output, String> {
        let out = Command::new(OPENSSL).args(args).stdin(std::process::Stdio::null()).output().map_err(|e| format!("openssl unavailable: {e}"))?;
        if !out.status.success() {
            return Err(format!("certificate preflight failed ({})", args[0]));
        }
        Ok(out)
    }

    pub fn check(chain: &str, key: &str, ca: &str, minimum_days: u32, domains: &[String]) -> Result<(), String> {
        for path in [chain, key, ca] {
            if !Path::new(path).is_absolute() || !Path::new(path).is_file() {
                return Err("expected absolute regular certificate/key/CA file paths".into());
            }
        }
        if minimum_days > 365 || domains.is_empty() || domains.len() > 64 || domains.iter().any(|d| !domain_valid(d)) {
            return Err("invalid minimum days or DNS hostname list".into());
        }
        let seconds = Duration::from_secs(u64::from(minimum_days) * 86_400).as_secs().to_string();
        run(&["x509", "-in", chain, "-noout", "-checkend", &seconds])?;
        let cert_pub = run(&["x509", "-in", chain, "-pubkey", "-noout"])?;
        let key_pub = run(&["pkey", "-in", key, "-passin", "pass:", "-pubout"])?;
        if cert_pub.stdout != key_pub.stdout { return Err("certificate/private key mismatch".into()); }
        for domain in domains {
            run(&["verify", "-purpose", "sslserver", "-CAfile", ca, "-no-CApath", "-no-CAstore", "-untrusted", chain, "-verify_hostname", domain, chain])?;
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
pub use linux::check;
