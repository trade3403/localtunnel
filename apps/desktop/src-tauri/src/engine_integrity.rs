//! Stage only the engine extracted from the pinned release archive at build time.
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

const MAX_ENGINE: u64 = 64 * 1024 * 1024;

pub fn stage(source: &Path, directory: &Path) -> Result<PathBuf, String> {
    let expected = option_env!("LOCALTUNNEL_ENGINE_SHA256")
        .ok_or("当前构建未配置可信引擎指纹，拒绝启动")?;
    stage_with_digest(source, directory, expected)
}

fn stage_with_digest(source: &Path, directory: &Path, expected: &str) -> Result<PathBuf, String> {
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("可信引擎指纹格式无效".into());
    }
    if !source.is_absolute() || !source.is_file() {
        return Err("引擎必须是本地绝对路径的普通文件".into());
    }
    let mut bytes = Vec::new();
    File::open(source).map_err(|_| "无法读取引擎文件")?
        .take(MAX_ENGINE + 1).read_to_end(&mut bytes).map_err(|_| "无法读取引擎文件")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ENGINE {
        return Err("引擎文件大小无效".into());
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err("Rathole 引擎 SHA-256 不匹配，拒绝启动".into());
    }

    // Execute a private staged copy of the exact verified bytes, not the
    // original user-selected path that may change after hashing.
    let target = directory.join(if cfg!(windows) { "rathole.exe" } else { "rathole" });
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options.open(&target).map_err(|_| "无法创建已验证引擎副本")?;
    file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|_| "无法写入已验证引擎副本")?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verified_bytes_staged_and_changed_source_rejected() {
        let source_dir = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("engine.exe");
        let bytes = b"fixture, not an executable";
        std::fs::write(&source, bytes).unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));
        let staged = stage_with_digest(&source, stage_dir.path(), &digest).unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), bytes);
        std::fs::write(&source, b"modified").unwrap();
        assert!(stage_with_digest(&source, stage_dir.path(), &digest).is_err());
        assert_eq!(std::fs::read(&staged).unwrap(), bytes);
        assert!(stage_with_digest(&source, stage_dir.path(), "invalid").is_err());
    }

    #[test]
    fn refuses_to_overwrite_staged_engine() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.exe");
        std::fs::write(&source, b"fixture").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"fixture"));
        stage_with_digest(&source, dir.path(), &digest).unwrap();
        assert!(stage_with_digest(&source, dir.path(), &digest).is_err());
    }
}
