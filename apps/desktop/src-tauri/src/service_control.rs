//! Explicit administrator controls for a staged preview service.
//! No implicit registration, autostart, file deletion, or privilege elevation.
#![cfg(windows)]
use std::{io, ptr, time::{Duration, Instant}, thread};
use windows_sys::Win32::System::Services::*;

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) { unsafe { CloseServiceHandle(self.0); } }
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

fn last_error() -> String { io::Error::last_os_error().to_string() }

fn open(name: &str, access: u32) -> Result<Handle, String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() { return Err(last_error()); }
    let manager = Handle(manager);
    let name = wide(name);
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if service.is_null() { return Err(last_error()); }
    Ok(Handle(service))
}

// SCM returns pointers inside its output buffer. Bound every read to that
// allocation, avoiding reliance on a terminating NUL beyond the buffer.
fn read_string(buffer: &[usize], text: *const u16) -> Result<String, String> {
    let begin = buffer.as_ptr() as usize;
    let end = begin + std::mem::size_of_val(buffer);
    let address = text as usize;
    if address < begin || address >= end || address % 2 != 0 {
        return Err("invalid SCM string pointer".into());
    }
    let words = unsafe { std::slice::from_raw_parts(text, (end-address)/2) };
    let len = words.iter().position(|&c| c == 0).ok_or("unterminated SCM string")?;
    String::from_utf16(&words[..len]).map_err(|_| "invalid SCM string".into())
}

fn config(service: &Handle, name: &str, exe: &str) -> Result<u32, String> {
    let mut needed = 0u32;
    unsafe { QueryServiceConfigW(service.0, ptr::null_mut(), 0, &mut needed); }
    if needed < std::mem::size_of::<QUERY_SERVICE_CONFIGW>() as u32 || needed > 65536 {
        return Err("invalid SCM configuration size".into());
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let raw = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service.0, raw, needed, &mut needed) } == 0 {
        return Err(last_error());
    }
    let cfg = unsafe { &*raw };
    let binary = read_string(&buffer, cfg.lpBinaryPathName)?;
    let account = read_string(&buffer, cfg.lpServiceStartName)?;
    let expected = format!("\"{exe}\" --service-tunnel {name}");
    if !binary.eq_ignore_ascii_case(&expected)
        || !account.eq_ignore_ascii_case("NT AUTHORITY\\LocalService")
        || cfg.dwServiceType != SERVICE_WIN32_OWN_PROCESS {
        return Err("unexpected service identity or executable".into());
    }
    Ok(cfg.dwStartType)
}

fn status(service: &Handle) -> Result<u32, String> {
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 { return Err(last_error()); }
    Ok(status.dwCurrentState)
}

fn transition_allowed(state: u32, target: u32, pending: u32) -> bool {
    // ControlService can return before our service loop publishes STOP_PENDING.
    // Its handler sets an atomic stop flag, then the worker performs cleanup.
    state == pending || (target == SERVICE_STOPPED && state == SERVICE_RUNNING)
}

fn wait(service: &Handle, target: u32, pending: u32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let state = status(service)?;
        if state == target { return Ok(()); }
        if !transition_allowed(state, target, pending) {
            return Err(format!("unexpected SCM state {state}, expected {target}"));
        }
        if Instant::now() >= deadline {
            return Err(format!("SCM transition timed out: state {state}, expected {target}"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn set_start_type(service: &Handle, mode: u32) -> Result<(), String> {
    let ok = unsafe { ChangeServiceConfigW(service.0, SERVICE_NO_CHANGE, mode,
        SERVICE_NO_CHANGE, ptr::null(), ptr::null(), ptr::null_mut(),
        ptr::null(), ptr::null(), ptr::null(), ptr::null()) };
    if ok == 0 { Err(last_error()) } else { Ok(()) }
}

const DELETE_RIGHT: u32 = 0x0001_0000;

fn register(name: &str, dir: &std::path::Path, exe: &str) -> Result<(), String> {
    crate::service_acl::validate_registration(dir)?;
    let scratch = tempfile::tempdir().map_err(|_| "engine check directory unavailable")?;
    crate::engine_integrity::stage(&crate::bundled_engine(dir)?, scratch.path())?;
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() { return Err(last_error()); }
    let manager = Handle(manager);
    let name_w = wide(name);
    let binary = wide(&format!("\"{exe}\" --service-tunnel {name}"));
    let account = wide("NT AUTHORITY\\LocalService");
    // CreateService refuses an existing service; never modify or replace it.
    let raw = unsafe { CreateServiceW(manager.0, name_w.as_ptr(), name_w.as_ptr(),
        SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | DELETE_RIGHT,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        binary.as_ptr(), ptr::null(), ptr::null_mut(), ptr::null(), account.as_ptr(), ptr::null()) };
    if raw.is_null() { return Err(last_error()); }
    let service = Handle(raw);
    let result = (|| {
        let sid = SERVICE_SID_INFO { dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED };
        if unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_SERVICE_SID_INFO,
            (&sid as *const SERVICE_SID_INFO).cast()) } == 0 {
            return Err(last_error());
        }
        if config(&service, name, exe)? != SERVICE_DEMAND_START {
            return Err("new service is not manual start".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        if unsafe { DeleteService(service.0) } == 0 {
            return Err(format!("{error}; registration rollback failed: {}", last_error()));
        }
        return Err(error);
    }
    // The administrator must now grant the per-service SID access and seal
    // the profile. Both control/start and the host independently validate ACLs.
    Ok(())
}

fn access(action: &str) -> Result<u32, String> {
    let common = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS;
    Ok(common | match action {
        "start" => SERVICE_START,
        "stop" => SERVICE_STOP,
        "autostart-on" | "autostart-off" => SERVICE_CHANGE_CONFIG,
        "check" => 0,
        "unregister" => SERVICE_CHANGE_CONFIG | DELETE_RIGHT,
        _ => return Err("unknown service action".into()),
    })
}

pub fn execute(name: &str, action: &str) -> Result<(), String> {
    let dir = crate::service_host::deployment_dir(name)?;
    let exe = dir.join("localtunnel-desktop.exe");
    let exe = exe.to_str().ok_or("invalid executable path")?;
    if action == "register" { return register(name, &dir, exe); }
    let rights = access(action)?;
    let service = open(name, rights)?;
    config(&service, name, exe)?;
    // Stop and disabling autostart must remain available even if the
    // profile or ACL was damaged. Never start/enable an unsafe deployment.
    if matches!(action, "start" | "autostart-on" | "check") {
        crate::service_acl::validate(&dir, name, true)?;
        crate::credentials::load_service(&dir)?;
        let scratch = tempfile::tempdir().map_err(|_| "engine check directory unavailable")?;
        crate::engine_integrity::stage(&crate::bundled_engine(&dir)?, scratch.path())?;
    }
    match action {
        "check" => Ok(()),
        "unregister" => {
            if status(&service)? != SERVICE_STOPPED {
                return Err("stop service before unregistering".into());
            }
            // Disable boot startup first. No recursive directory deletion here.
            set_start_type(&service, SERVICE_DISABLED)?;
            if status(&service)? != SERVICE_STOPPED {
                return Err("service started concurrently; stop before retry".into());
            }
            if unsafe { DeleteService(service.0) } == 0 { return Err(last_error()); }
            Ok(())
        }
        "start" => {
            let state = status(&service)?;
            if state == SERVICE_RUNNING { return Ok(()); }
            if state != SERVICE_START_PENDING {
                if state != SERVICE_STOPPED { return Err("service not stopped".into()); }
                if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 { return Err(last_error()); }
            }
            wait(&service, SERVICE_RUNNING, SERVICE_START_PENDING)
        }
        "stop" => {
            let state = status(&service)?;
            if state == SERVICE_STOPPED { return Ok(()); }
            if state != SERVICE_STOP_PENDING {
                if state != SERVICE_RUNNING { return Err("service not running".into()); }
                let mut out: SERVICE_STATUS = unsafe { std::mem::zeroed() };
                if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut out) } == 0 {
                    return Err(last_error());
                }
            }
            wait(&service, SERVICE_STOPPED, SERVICE_STOP_PENDING)
        }
        "autostart-on" | "autostart-off" => {
            let mode = if action == "autostart-on" { SERVICE_AUTO_START } else { SERVICE_DEMAND_START };
            set_start_type(&service, mode)?;
            if config(&service, name, exe)? != mode { return Err("startup mode verification failed".into()); }
            Ok(())
        }
        _ => Err("unknown service action".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_accepts_running_before_worker_reports_pending() {
        assert!(transition_allowed(SERVICE_RUNNING, SERVICE_STOPPED, SERVICE_STOP_PENDING));
        assert!(transition_allowed(SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING));
        assert!(!transition_allowed(SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING));
        assert!(!transition_allowed(SERVICE_STOPPED, SERVICE_RUNNING, SERVICE_START_PENDING));
        assert!(transition_allowed(SERVICE_START_PENDING, SERVICE_RUNNING, SERVICE_START_PENDING));
    }

    #[test]
    fn action_access_is_minimal_and_closed() {
        assert!(access("start").unwrap() & SERVICE_START != 0);
        assert_eq!(access("check").unwrap() & SERVICE_CHANGE_CONFIG, 0);
        assert_eq!(access("stop").unwrap() & SERVICE_START, 0);
        assert!(access("install").is_err());
        assert!(access("delete").is_err());
        assert_eq!(access("unregister").unwrap() & SERVICE_START, 0);
        assert_ne!(access("unregister").unwrap() & DELETE_RIGHT, 0);
    }
}
