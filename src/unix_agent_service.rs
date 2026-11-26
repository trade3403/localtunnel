//! Generate opt-in, unprivileged native service definitions. Never register,
//! start or enable services implicitly. The operator controls the OS manager.
use crate::unix_agent_store::{private_dir, trusted_path, uid};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

type Result<T> = std::result::Result<T, &'static str>;

fn safe_path(path: &Path) -> Result<&str> {
    let value=path.to_str().ok_or("service paths must be UTF-8")?;
    // Intentionally reject whitespace, '%' (systemd specifiers), '$',
    // XML markup and shell quoting rather than interpreting any of them.
    if !path.is_absolute() || value.len()>2048 || !value.bytes().all(|b|
        b.is_ascii_alphanumeric() || b"/._-".contains(&b)) {
        return Err("unsupported service path characters");
    }
    Ok(value)
}
fn label(id: &str) -> Result<String> {
    if id.len()!=32 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("service id must be 32 lowercase hexadecimal characters");
    }
    Ok(format!("localtunnel-agent-{id}"))
}

pub fn generate(root: &Path, id: &str) -> Result<()> {
    private_dir(root)?;
    let name=label(id)?;
    let root_text=safe_path(root)?;
    let exe=std::env::current_exe().map_err(|_| "agent executable unavailable")?;
    let exe_text=safe_path(&exe)?;
    trusted_path(exe.parent().ok_or("agent executable has no parent")?)?;
    let metadata=fs::symlink_metadata(&exe).map_err(|_| "agent executable unavailable")?;
    if !metadata.is_file() || metadata.nlink()!=1 || (metadata.uid()!=uid() && metadata.uid()!=0)
        || metadata.mode()&0o022!=0 || metadata.mode()&0o111==0 {
        return Err("untrusted agent executable");
    }
    crate::unix_agent_process::preflight(root)?;
    #[cfg(target_os="linux")]
    let (filename, contents)=(format!("{name}.service"),format!(
        "[Unit]\nDescription=LocalTunnel agent {id}\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=exec\nExecStart={exe_text} agent-run {root_text}\nRestart=on-failure\nRestartSec=2s\nTimeoutStopSec=10s\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\nStandardInput=null\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n"));
    #[cfg(target_os="macos")]
    let (filename, contents)=(format!("{name}.plist"),format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{name}</string>\n<key>ProgramArguments</key><array><string>{exe_text}</string><string>agent-run</string><string>{root_text}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>2</integer>\n<key>ExitTimeOut</key><integer>10</integer>\n</dict></plist>\n"));
    let path=root.join(filename);
    let mut file=OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(&path).map_err(|_| "cannot create new service definition")?;
    if file.write_all(contents.as_bytes()).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _=fs::remove_file(path);
        return Err("cannot write service definition");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_service_injection() {
        assert!(label("bad.service").is_err());
        assert!(label("0123456789abcdef0123456789abcdef").is_ok());
        for path in ["/tmp/a b","/tmp/a%h","/tmp/a\nb","/tmp/a&b","/tmp/$HOME","relative"] {
            assert!(safe_path(Path::new(path)).is_err());
        }
        assert!(safe_path(Path::new("/home/test/lt-01")).is_ok());
    }
}
