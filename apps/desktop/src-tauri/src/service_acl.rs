//! Strict preview deployment ACL allowlist. Fail closed on unknown ACEs.
//! The trusted administrator must provision the directory before SCM start.
#![cfg(windows)]
use std::{ffi::c_void, os::windows::{ffi::OsStrExt, fs::MetadataExt}, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{GetAce, IsValidAcl, IsValidSid, LookupAccountNameW, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION},
    Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
};

const ADMIN: &str = "S-1-5-32-544";
const SYSTEM: &str = "S-1-5-18";
const RX: u32 = 0x0012_00a9;
const MODIFY: u32 = 0x0013_01bf;
const FULL: u32 = 0x001f_01ff;

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() { unsafe { LocalFree(self.0); } }
    }
}

fn sid_string(sid: PSID) -> Result<String, String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err("invalid security SID".into());
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err("SID conversion failed".into());
    }
    let _memory = Local(text.cast());
    let len = (0..184).find(|&i| unsafe { *text.add(i) } == 0)
        .ok_or("invalid SID string")?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .map_err(|_| "invalid SID string".into())
}

fn service_sid(name: &str) -> Result<String, String> {
    let account: Vec<u16> = format!("NT SERVICE\\{name}").encode_utf16().chain(Some(0)).collect();
    // Maximum binary SID size is 68 bytes; use aligned storage.
    let mut sid = [0u32; 17];
    let mut bytes = std::mem::size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut chars = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    if unsafe { LookupAccountNameW(ptr::null(), account.as_ptr(), sid.as_mut_ptr().cast(),
        &mut bytes, domain.as_mut_ptr(), &mut chars, &mut kind) } == 0 {
        return Err("service SID lookup failed".into());
    }
    let value = sid_string(sid.as_mut_ptr().cast())?;
    if !value.starts_with("S-1-5-80-") { return Err("not a service SID".into()); }
    Ok(value)
}

fn check_entry(path: &Path, directory: bool, service: &str, limit: u32, runtime: bool) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "deployment entry missing")?;
    if meta.file_attributes() & 0x400 != 0 || (directory && !meta.is_dir())
        || (!directory && !meta.is_file()) {
        return Err("unsafe deployment entry".into());
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let result = unsafe { GetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut owner,
        ptr::null_mut(), &mut acl, ptr::null_mut(), &mut descriptor) };
    let _memory = Local(descriptor.cast());
    if result != 0 || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err("missing or invalid deployment ACL".into());
    }
    let owner = sid_string(owner)?;
    if owner != ADMIN && owner != SYSTEM && !(runtime && (owner == "S-1-5-19" || owner == service)) {
        return Err("untrusted deployment owner".into());
    }
    let mut admin = 0;
    let mut system = 0;
    let mut service_mask = 0;
    for i in 0..unsafe { (*acl).AceCount } as u32 {
        let mut raw: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 || raw.is_null() {
            return Err("invalid deployment ACE".into());
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        // Only ordinary allow ACEs. Unknown/conditional/deny ACEs fail closed.
        if header.AceType != 0 || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
            return Err("unsupported deployment ACE".into());
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_string(ptr::addr_of!(ace.SidStart).cast_mut().cast())?;
        // Reject even inheritable-only grants to unrelated identities.
        let effective = if header.AceFlags & 0x08 != 0 { 0 } else { ace.Mask };
        if sid == ADMIN { admin |= effective; }
        else if sid == SYSTEM { system |= effective; }
        else if sid == service {
            if ace.Mask & !limit != 0 { return Err("service has excessive rights".into()); }
            service_mask |= effective;
        } else { return Err("unexpected deployment ACL principal".into()); }
    }
    if admin & FULL != FULL || system & FULL != FULL || service_mask & limit != limit {
        return Err("required deployment rights missing".into());
    }
    Ok(())
}

fn check(path: &Path, directory: bool, service: &str, limit: u32) -> Result<(), String> {
    check_entry(path, directory, service, limit, false)
}

// Only SCM-owned startup uses this cleanup. The root is validated first.
// No recursive deletion: inspect the complete candidate before unlinking
// only the two files created by Supervisor::start_in.
fn runtime_name(name: &str) -> bool {
    name.strip_prefix("localtunnel-client-").is_some_and(|suffix|
        suffix.len() == 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric()))
}

pub fn clear_stale_runtime(dir: &Path, name: &str) -> Result<(), String> {
    let service = service_sid(name)?;
    let root = dir.join("runtime");
    check(&root, true, &service, MODIFY)?;
    let mut entries = std::fs::read_dir(&root).map_err(|_| "runtime unavailable")?;
    let Some(entry) = entries.next() else { return Ok(()); };
    let entry = entry.map_err(|_| "runtime entry unavailable")?;
    if entries.next().is_some() { return Err("multiple stale runtime entries; manual inspection required".into()); }
    if !entry.file_name().to_str().is_some_and(runtime_name) {
        return Err("unknown runtime entry; manual inspection required".into());
    }
    let stale = entry.path();
    check_entry(&stale, true, &service, MODIFY, true)?;
    let mut engine = None;
    let mut config = None;
    for item in std::fs::read_dir(&stale).map_err(|_| "stale runtime unavailable")? {
        let item = item.map_err(|_| "stale entry unavailable")?;
        let path = item.path();
        check_entry(&path, false, &service, MODIFY, true)?;
        match item.file_name().to_str() {
            Some("rathole.exe") if engine.is_none() => engine = Some(path),
            Some("client.toml") if config.is_none() => config = Some(path),
            _ => return Err("unknown stale runtime file; manual inspection required".into()),
        }
    }
    // A surviving image or open file must block cleanup rather than
    // deleting live credentials. Never terminate arbitrary processes here.
    use std::os::windows::fs::OpenOptionsExt;
    for path in engine.iter().chain(config.iter()) {
        std::fs::OpenOptions::new().read(true).share_mode(0).open(path)
            .map_err(|_| "stale runtime file still in use")?;
    }
    if let Some(path) = engine { std::fs::remove_file(path).map_err(|_| "stale engine removal failed")?; }
    if let Some(path) = config { std::fs::remove_file(path).map_err(|_| "stale credential removal failed")?; }
    std::fs::remove_dir(stale).map_err(|_| "stale runtime directory not empty or unavailable")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_generated_runtime_names() {
        assert!(runtime_name("localtunnel-client-aB12Z9"));
        assert!(!runtime_name("localtunnel-client-"));
        assert!(!runtime_name("localtunnel-client-abcdefg"));
        assert!(!runtime_name("localtunnel-client-../abc"));
        assert!(!runtime_name("other-abcdef"));
    }
}

// Before SCM registration, no service SID may have rights yet. The
// deployment is administrator/SYSTEM owned and contains no saved profile.
pub fn validate_registration(dir: &Path) -> Result<(), String> {
    for (path, directory) in [
        (dir.to_path_buf(), true),
        (dir.join("localtunnel-desktop.exe"), false),
        (dir.join("engine"), true),
        (dir.join("engine").join("rathole.exe"), false),
        (dir.join("runtime"), true),
    ] {
        check(&path, directory, "", 0)?;
    }
    match std::fs::symlink_metadata(dir.join("service-profile.bin")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("registration requires an empty credential slot".into()),
    }
    if std::fs::read_dir(dir.join("runtime")).map_err(|_| "runtime unavailable")?.next().is_some() {
        return Err("registration requires empty runtime directory".into());
    }
    Ok(())
}

pub fn validate(dir: &Path, name: &str, profile: bool) -> Result<(), String> {
    let service = service_sid(name)?;
    check(dir, true, &service, RX)?;
    check(&dir.join("localtunnel-desktop.exe"), false, &service, RX)?;
    check(&dir.join("engine"), true, &service, RX)?;
    check(&dir.join("engine").join("rathole.exe"), false, &service, RX)?;
    check(&dir.join("runtime"), true, &service, MODIFY)?;
    if profile { check(&dir.join("service-profile.bin"), false, &service, RX)?; }
    Ok(())
}
