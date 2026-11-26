//! Explicit administrator-only provisioning of a fresh stopped SCM service.
//! No elevation, replacement, arbitrary executable, or recursive cleanup.
#![cfg(windows)]
use std::{ffi::OsString, fs, io::{self, Write}, os::windows::{ffi::{OsStrExt, OsStringExt}, fs::MetadataExt}, path::{Path, PathBuf}, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_ATTRIBUTES, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION},
    Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT},
    Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
    Storage::FileSystem::CreateDirectoryW,
    System::{Com::CoTaskMemFree, Services::{OpenSCManagerW, CloseServiceHandle, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE}},
    UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramData},
};

fn path_wide(path: &Path) -> Vec<u16> { path.as_os_str().encode_wide().chain(Some(0)).collect() }
fn last_error() -> String { io::Error::last_os_error().to_string() }

pub(crate) fn program_data() -> Result<PathBuf, String> {
    let mut raw = ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        if !raw.is_null() { unsafe { CoTaskMemFree(raw.cast()); } }
        return Err("Windows ProgramData unavailable".into());
    }
    // The API returns a COM-allocated, NUL-terminated string.
    let len = (0..32768).find(|&i| unsafe { *raw.add(i) == 0 });
    let path = len.map(|n| PathBuf::from(OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, n) })));
    unsafe { CoTaskMemFree(raw.cast()); }
    let path = path.ok_or("invalid ProgramData path")?;
    if !path.is_absolute() || std::env::var_os("ProgramData").map(PathBuf::from).as_ref() != Some(&path) {
        return Err("ProgramData environment does not match Windows known folder".into());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| "ProgramData ancestor unavailable")?;
        if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
            return Err("unsafe ProgramData ancestor".into());
        }
    }
    Ok(path)
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { LocalFree(self.0.cast()); } } }
}
fn descriptor(directory: bool, service: Option<(&str, bool)>) -> Result<Descriptor, String> {
    let flags = if directory { "OICI" } else { "" };
    let mut text = format!("O:BAG:BAD:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)");
    if let Some((sid, modify)) = service {
        // The SID originates only from LookupAccountNameW for the new service.
        let rights = if modify { "0x001301bf" } else { "0x001200a9" };
        text.push_str(&format!("(A;{flags};{rights};;;{sid})"));
    }
    let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut raw, ptr::null_mut()) } == 0 {
        return Err(last_error());
    }
    Ok(Descriptor(raw))
}

// The root is born protected, rather than creating a broadly writable
// directory and applying ACLs later. CreateDirectoryW never reuses a name.
fn create_root(path: &Path) -> Result<(), String> {
    let sd = descriptor(true, None)?;
    let attrs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0.cast(), bInheritHandle: 0 };
    if unsafe { CreateDirectoryW(path_wide(path).as_ptr(), &attrs) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

pub(crate) fn set_acl(path: &Path, directory: bool, service: Option<(&str, bool)>) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "provisioned entry missing")?;
    if meta.file_attributes() & 0x400 != 0 || (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        return Err("unsafe provisioned entry".into());
    }
    let sd = descriptor(directory, service)?;
    let mut owner: PSID = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0 || acl.is_null() || owner.is_null() {
        return Err("invalid provisioning descriptor".into());
    }
    let result = unsafe { SetNamedSecurityInfoW(path_wide(path).as_ptr(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        owner, ptr::null_mut(), acl, ptr::null_mut()) };
    if result != 0 { return Err(io::Error::from_raw_os_error(result as i32).to_string()); }
    Ok(())
}

fn require_scm_admin() -> Result<(), String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() { return Err("administrator SCM creation permission required".into()); }
    unsafe { CloseServiceHandle(manager); }
    Ok(())
}

pub fn provision(request: crate::StartRequest, resource_dir: &Path) -> Result<String, String> {
    // Validate all user configuration before creating a persistent object.
    if !request.engine.is_empty() { return Err("service requires bundled engine".into()); }
    crate::validate_service_protocols(&request)?;
    crate::build_config(&request)?;
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&request).map_err(|_| "profile serialization failed")?);
    if bytes.len() > 256 * 1024 { return Err("service profile too large".into()); }
    require_scm_admin()?;
    let source = std::env::current_exe().map_err(|_| "desktop executable unavailable")?;
    let engine = crate::bundled_engine(resource_dir)?;
    let base = program_data()?;
    let mut random = [0u8; 16];
    if unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), random.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) } < 0 {
        return Err("service name randomness unavailable".into());
    }
    let name = format!("LocalTunnelPreview-{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let dir = base.join(&name);
    create_root(&dir)?;
    let exe_path = dir.join("localtunnel-desktop.exe");
    let exe = exe_path.to_str().ok_or("invalid service executable path")?;
    let engine_dir = dir.join("engine");
    let runtime = dir.join("runtime");
    let history = dir.join("history");
    let mut registered = false;
    let result = (|| -> Result<(), String> {
        for path in [&engine_dir, &runtime, &history] {
            fs::create_dir(path).map_err(|_| "service subdirectory creation failed")?;
            set_acl(path, true, None)?;
        }
        // Only copy the running desktop executable, into the fresh ACL root.
        let mut input = fs::File::open(&source).map_err(|_| "desktop image unavailable")?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&exe_path)
            .map_err(|_| "service image creation failed")?;
        io::copy(&mut input, &mut output).and_then(|_| output.flush()).and_then(|_| output.sync_all())
            .map_err(|_| "service image copy failed")?;
        drop(output);
        set_acl(&exe_path, false, None)?;
        let engine_path = crate::engine_integrity::stage(&engine, &engine_dir)?;
        set_acl(&engine_path, false, None)?;
        crate::service_control::register(&name, &dir, exe)?;
        registered = true;
        let sid = crate::service_acl::service_sid(&name)?;
        // Children have protected DACLs; grant precise permissions individually.
        for path in [&runtime, &history] { set_acl(path, true, Some((&sid, true)))?; }
        set_acl(&engine_dir, true, Some((&sid, false)))?;
        set_acl(&engine_path, false, Some((&sid, false)))?;
        set_acl(&exe_path, false, Some((&sid, false)))?;
        set_acl(&dir, true, Some((&sid, false)))?;
        crate::service_acl::validate(&dir, &name, false)?;
        crate::service_acl::history_dir(&dir, &name)?;
        crate::credentials::seal_service(&dir, bytes.as_slice())?;
        set_acl(&dir.join("service-profile.bin"), false, Some((&sid, false)))?;
        crate::service_control::execute_existing(&name, "check", &dir, exe)?;
        Ok(())
    })();
    if let Err(error) = result {
        // Never recursively delete a privileged directory. If registration
        // succeeded, remove only this exact stopped registration. Preserve
        // the protected directory for administrator inspection.
        let rollback = if registered {
            match crate::service_control::execute_existing(&name, "unregister", &dir, exe) {
                Ok(()) => "registration rolled back",
                Err(_) => "registration rollback failed; inspect SCM",
            }
        } else { "registration not confirmed; inspect SCM" };
        return Err(format!("{name}: {error}; {rollback}; deployment directory preserved"));
    }
    Ok(name)
}
