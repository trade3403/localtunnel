//! Desktop user-local, session-independent byte totals. No credentials,
//! payloads, remote addresses, or mapping names. Not billing evidence.
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH}};

const RECORD: &str = "traffic-history.json";
const LOCK: &str = "traffic-history.lock";
const MAX_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Totals {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub saved_at_ms: u64,
}

fn regular_or_missing(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    return Err("unsafe history reparse point".into());
                }
            }
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("unsafe history file".into());
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("history file unavailable".into()),
    }
}

pub fn read(dir: &Path) -> Result<Option<Totals>, String> {
    let path = dir.join(RECORD);
    if !regular_or_missing(&path)? { return Ok(None); }
    let mut bytes = Vec::new();
    File::open(path).map_err(|_| "history open failed")?.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes).map_err(|_| "history read failed")?;
    if bytes.len() as u64 > MAX_BYTES { return Err("history too large".into()); }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| "invalid history; preserve file for inspection".into())
}

pub struct Store {
    dir: PathBuf,
    _lock: File,
    baseline: Totals,
    saved: Option<Totals>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|_| "history directory unavailable")?;
        let lock_path = dir.join(LOCK);
        regular_or_missing(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path).map_err(|_| "history lock unavailable")?;
        // A second desktop instance must not overwrite a first writer's
        // cumulative totals. OS releases the lock on process exit/crash.
        lock.try_lock().map_err(|_| "another desktop session is using traffic history")?;
        let saved = read(dir)?;
        Ok(Self { dir: dir.to_path_buf(), _lock: lock,
            baseline: saved.unwrap_or_default(), saved })
    }

    pub fn checkpoint(&mut self, up: u64, down: u64) -> Result<(), String> {
        // Always add session counters to the original baseline, never to
        // the previous checkpoint. Repeated checkpoints are idempotent.
        let upload_bytes = self.baseline.upload_bytes.saturating_add(up);
        let download_bytes = self.baseline.download_bytes.saturating_add(down);
        if self.saved.is_some_and(|old| old.upload_bytes == upload_bytes && old.download_bytes == download_bytes) {
            return Ok(());
        }
        let saved_at_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "invalid system time")?.as_millis()).map_err(|_| "invalid system time")?;
        let totals = Totals { upload_bytes, download_bytes, saved_at_ms };
        // Temp file is on the same volume, synced before replacement.
        // No truncate-in-place: a reader sees the previous or next record.
        regular_or_missing(&self.dir.join(RECORD))?;
        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir).map_err(|_| "history temp file unavailable")?;
        serde_json::to_writer(tmp.as_file_mut(), &totals).map_err(|_| "history encode failed")?;
        tmp.as_file_mut().flush().and_then(|_| tmp.as_file().sync_all())
            .map_err(|_| "history sync failed")?;
        tmp.persist(self.dir.join(RECORD)).map_err(|_| "history replacement failed")?;
        self.saved = Some(totals);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoints_are_idempotent_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = Store::open(dir.path()).unwrap();
        assert!(Store::open(dir.path()).is_err());
        first.checkpoint(100, 200).unwrap();
        first.checkpoint(100, 200).unwrap();
        first.checkpoint(120, 240).unwrap();
        drop(first);
        let mut second = Store::open(dir.path()).unwrap();
        second.checkpoint(30, 40).unwrap();
        drop(second);
        let saved = read(dir.path()).unwrap().unwrap();
        assert_eq!((saved.upload_bytes, saved.download_bytes), (150, 280));
    }

    #[test]
    fn corrupt_history_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(RECORD);
        fs::write(&path, b"not json").unwrap();
        assert!(Store::open(dir.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"not json");
    }
}
