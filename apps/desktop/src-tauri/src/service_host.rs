//! Explicit SCM preview host and optional provisioned tunnel mode.
//! Service mode uses a separate ACL-restricted, machine-DPAPI sealed profile.
#![cfg(windows)]
use std::{ffi::c_void, io, ptr, sync::atomic::{AtomicBool, Ordering}, thread, time::Duration};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

static STOP: AtomicBool = AtomicBool::new(false);
static TUNNEL: AtomicBool = AtomicBool::new(false);
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_GEN_FAILURE: u32 = 31;

// Three retries per SCM service lifetime; never reset the budget just
// because a new child starts. A persistent fault must not spin forever.
#[derive(Default)]
struct RecoveryBudget { used: usize }

impl RecoveryBudget {
    fn next_delay(&mut self) -> Option<Duration> {
        let seconds = [1, 2, 4].get(self.used).copied()?;
        self.used += 1;
        Some(Duration::from_secs(seconds))
    }
}

fn backoff(delay: Duration) -> bool {
    let deadline = std::time::Instant::now() + delay;
    while !STOP.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { return true; }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    false
}


pub fn valid_name(name: &str) -> bool {
    let prefix = "LocalTunnelPreview-";
    name.strip_prefix(prefix).is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn dispatch(name: &str, tunnel: bool) -> io::Result<()> {
    if !valid_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid preview service name"));
    }
    TUNNEL.store(tunnel, Ordering::Release);
    // The SCM owns the callback invocation; the name and table stay alive until
    // StartServiceCtrlDispatcherW returns after the service has stopped.
    let mut wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: wide.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: ptr::null_mut(), lpServiceProc: None },
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::Release);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn report(handle: SERVICE_STATUS_HANDLE, state: u32, exit: u32) -> bool {
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if pending { 1 } else { 0 },
        dwWaitHint: if pending { 5000 } else { 0 },
    };
    unsafe { SetServiceStatus(handle, &status) != 0 }
}

unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    if argc == 0 || argv.is_null() { return; }
    let name = unsafe { *argv };
    if name.is_null() { return; }
    STOP.store(false, Ordering::Release);
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name, Some(control), ptr::null()) };
    if handle.is_null() { return; }
    if !report(handle, SERVICE_START_PENDING, 0) {
        let _ = report(handle, SERVICE_STOPPED, ERROR_GEN_FAILURE);
        return;
    }
    let mut supervisor = crate::Supervisor::default();
    let tunnel = TUNNEL.load(Ordering::Acquire);
    if tunnel && (prepare_initial_runtime().is_err() || start_provisioned(&mut supervisor).is_err()) {
        let _ = report(handle, SERVICE_STOPPED, ERROR_GEN_FAILURE);
        return;
    }
    if !report(handle, SERVICE_RUNNING, 0) {
        let _ = supervisor.stop();
        let _ = report(handle, SERVICE_STOPPED, ERROR_GEN_FAILURE);
        return;
    }
    // SCM Running describes the host, including bounded engine recovery.
    // It is never evidence of an authenticated/connected tunnel.
    let mut failed = false;
    let mut recovery = RecoveryBudget::default();
    let mut next_sample = std::time::Instant::now();
    while !STOP.load(Ordering::Acquire) {
        if tunnel && !supervisor.status().is_ok_and(|status| status.state == "running") {
            // Fully dispose of the old child and its runtime files before
            // retrying. Do not launch a second child if cleanup fails.
            if supervisor.stop().is_err() { failed = true; break; }
            let mut recovered = false;
            while let Some(delay) = recovery.next_delay() {
                if !backoff(delay) || STOP.load(Ordering::Acquire) { break; }
                // Re-read protected credentials and repeat all ACL/digest checks.
                if start_provisioned(&mut supervisor).is_ok() {
                    recovered = true;
                    break;
                }
                if supervisor.stop().is_err() { break; }
            }
            if !recovered {
                failed = !STOP.load(Ordering::Acquire);
                break;
            }
        }
        if tunnel && std::time::Instant::now() >= next_sample {
            // Telemetry failure must not stop a functioning tunnel.
            let _ = supervisor.publish_service_traffic();
            next_sample = std::time::Instant::now() + Duration::from_secs(1);
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = report(handle, SERVICE_STOP_PENDING, 0);
    if supervisor.stop().is_err() { failed = true; }
    let _ = report(handle, SERVICE_STOPPED, if failed { ERROR_GEN_FAILURE } else { 0 });
}

pub fn deployment_dir(name: &str) -> Result<std::path::PathBuf, String> {
    if !valid_name(name) { return Err("invalid service name".into()); }
    let exe = std::env::current_exe().map_err(|_| "service executable unavailable")?;
    let dir = exe.parent().ok_or("service directory missing")?;
    // Only accept the explicit per-service deployment directory. Provisioning
    // must establish its ACL before starting SCM (no user-writable install).
    let expected = std::env::var_os("ProgramData").map(std::path::PathBuf::from)
        .ok_or("ProgramData missing")?.join(name);
    if dir != expected { return Err("unexpected service deployment directory".into()); }
    // Reject directory junctions/reparse points at the deployment root.
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(dir).map_err(|_| "service directory unavailable")?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err("unsafe deployment directory".into());
    }
    Ok(dir.to_path_buf())
}

pub fn seal_profile_from_stdin(name: &str) -> Result<(), String> {
    let dir = deployment_dir(name)?;
    crate::service_acl::validate(&dir, name, false)?;
    crate::credentials::seal_service(&dir, std::io::stdin().lock())
}

fn prepare_initial_runtime() -> Result<(), String> {
    let name = std::env::args().nth(2).ok_or("service name missing")?;
    let dir = deployment_dir(&name)?;
    crate::service_acl::validate(&dir, &name, true)?;
    // Verify sealed profile before modifying any stale files.
    crate::credentials::load_service(&dir)?;
    crate::service_acl::clear_stale_runtime(&dir, &name)
}

fn start_provisioned(supervisor: &mut crate::Supervisor) -> Result<(), String> {
    let name = std::env::args().nth(2).ok_or("service name missing")?;
    let dir = deployment_dir(&name)?;
    crate::service_acl::validate(&dir, &name, true)?;
    let runtime = dir.join("runtime");
    if !runtime.is_dir() { return Err("service runtime directory missing".into()); }
    // The TempDir from a reaped child should have been removed. Refuse to
    // run over unknown/orphan data; host-crash cleanup is a later operation.
    if std::fs::read_dir(&runtime).map_err(|_| "runtime unavailable")?.next().is_some() {
        return Err("runtime not empty; inspect stale service files".into());
    }
    let mut request = crate::credentials::load_service(&dir)?;
    request.engine = crate::bundled_engine(&dir)?.to_str().ok_or("invalid engine path")?.to_owned();
    let status = supervisor.start_in(request, Some(&runtime))?;
    if status.state != "running" { return Err("engine did not start".into()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_budget_is_bounded_for_entire_service_lifetime() {
        let mut budget = RecoveryBudget::default();
        assert_eq!(budget.next_delay(), Some(Duration::from_secs(1)));
        assert_eq!(budget.next_delay(), Some(Duration::from_secs(2)));
        assert_eq!(budget.next_delay(), Some(Duration::from_secs(4)));
        assert_eq!(budget.next_delay(), None);
        assert_eq!(budget.next_delay(), None);
    }

    #[test]
    fn only_explicit_preview_service_names() {
        assert!(valid_name("LocalTunnelPreview-0123456789abcdef0123456789abcdef"));
        assert!(!valid_name("LocalTunnel"));
        assert!(!valid_name("LocalTunnelPreview-"));
        assert!(!valid_name("LocalTunnelPreview-0123456789abcdef0123456789abcdeg"));
    }
    #[test]
    fn stop_control_sets_flag_without_blocking() {
        STOP.store(false, Ordering::Release);
        assert_eq!(unsafe { control(SERVICE_CONTROL_INTERROGATE, 0, ptr::null_mut(), ptr::null_mut()) }, 0);
        assert!(!STOP.load(Ordering::Acquire));
        assert_eq!(unsafe { control(SERVICE_CONTROL_STOP, 0, ptr::null_mut(), ptr::null_mut()) }, 0);
        assert!(STOP.load(Ordering::Acquire));
        assert_eq!(unsafe { control(0xFFFF, 0, ptr::null_mut(), ptr::null_mut()) }, ERROR_CALL_NOT_IMPLEMENTED);
    }
}
