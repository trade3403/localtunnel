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

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSnapshot {
    state: &'static str,
    startup: &'static str,
    host_pid: Option<u32>,
    win32_exit_code: u32,
    service_exit_code: u32,
    traffic: Option<crate::traffic::ServiceSample>,
    history: Option<crate::history::Totals>,
    recovery: &'static str,
}

fn state_label(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING => "starting",
        SERVICE_STOP_PENDING => "stopping",
        SERVICE_RUNNING => "running",
        SERVICE_PAUSED => "paused",
        SERVICE_PAUSE_PENDING | SERVICE_CONTINUE_PENDING => "transitioning",
        _ => "unknown",
    }
}

fn startup_label(mode: u32) -> &'static str {
    match mode {
        SERVICE_AUTO_START => "automatic",
        SERVICE_DEMAND_START => "manual",
        SERVICE_DISABLED => "disabled",
        _ => "unknown",
    }
}

// Unlike mutating commands, status can be queried from the ordinary
// desktop installation. Do not open profile files or require elevation.
pub fn snapshot(name: &str) -> Result<ServiceSnapshot, String> {
    if !crate::service_host::valid_name(name) { return Err("invalid preview service name".into()); }
    let dir = std::env::var_os("ProgramData").map(std::path::PathBuf::from)
        .ok_or("ProgramData unavailable")?.join(name);
    let exe = dir.join("localtunnel-desktop.exe");
    let service = open(name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    let mode = config(&service, name, exe.to_str().ok_or("invalid executable path")?)?;
    let mut data: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0;
    if unsafe { QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO,
        (&mut data as *mut SERVICE_STATUS_PROCESS).cast(),
        std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut needed) } == 0 {
        return Err(last_error());
    }
    let traffic = if data.dwCurrentState == SERVICE_RUNNING && data.dwProcessId != 0 {
        crate::service_acl::read_traffic(&dir, name, data.dwProcessId).ok()
    } else { None };
    Ok(ServiceSnapshot {
        state: state_label(data.dwCurrentState),
        startup: startup_label(mode),
        host_pid: (matches!(data.dwCurrentState, SERVICE_RUNNING | SERVICE_PAUSED)
            && data.dwProcessId != 0).then_some(data.dwProcessId),
        win32_exit_code: data.dwWin32ExitCode,
        service_exit_code: data.dwServiceSpecificExitCode,
        traffic,
        history: crate::service_acl::read_history(&dir, name).ok().flatten(),
        recovery: if verify_recovery(&service, &recovery_actions(true)).is_ok() {
            "enabled"
        } else if verify_recovery(&service, &recovery_actions(false)).is_ok() {
            "disabled"
        } else {
            // Includes default SCM policy, custom policy, or unavailable query.
            "unverified"
        },
    })
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
const RECOVERY_RESET_SECONDS: u32 = 86400;

fn recovery_actions(enabled: bool) -> Vec<SC_ACTION> {
    let mut actions = Vec::new();
    if enabled {
        for delay in [3000, 6000, 12000] {
            actions.push(SC_ACTION { Type: SC_ACTION_RESTART, Delay: delay });
        }
    }
    // SCM repeats the last action for later failures. End with NONE.
    actions.push(SC_ACTION { Type: SC_ACTION_NONE, Delay: 0 });
    actions
}

fn query_config2(service: &Handle, level: u32) -> Result<Vec<usize>, String> {
    let mut size = 0;
    unsafe { QueryServiceConfig2W(service.0, level, ptr::null_mut(), 0, &mut size); }
    if size == 0 || size > 65536 { return Err("invalid recovery configuration size".into()); }
    let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { QueryServiceConfig2W(service.0, level, data.as_mut_ptr().cast(), size, &mut size) } == 0 {
        return Err(last_error());
    }
    Ok(data)
}

fn verify_recovery(service: &Handle, expected: &[SC_ACTION]) -> Result<(), String> {
    let data = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let size = std::mem::size_of_val(data.as_slice());
    if size < std::mem::size_of::<SERVICE_FAILURE_ACTIONSW>() {
        return Err("invalid failure actions structure".into());
    }
    let info = unsafe { &*data.as_ptr().cast::<SERVICE_FAILURE_ACTIONSW>() };
    let start = data.as_ptr() as usize;
    let actions = info.lpsaActions as usize;
    let bytes = std::mem::size_of_val(expected);
    if info.dwResetPeriod != RECOVERY_RESET_SECONDS || info.cActions as usize != expected.len()
        || actions < start || actions % std::mem::align_of::<SC_ACTION>() != 0
        || actions.checked_add(bytes).is_none_or(|end| end > start + size) {
        return Err("unexpected failure action configuration".into());
    }
    let actual = unsafe { std::slice::from_raw_parts(info.lpsaActions, expected.len()) };
    if !actual.iter().zip(expected).all(|(a,b)| a.Type == b.Type && a.Delay == b.Delay) {
        return Err("failure actions readback mismatch".into());
    }
    let flag = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?;
    if std::mem::size_of_val(flag.as_slice()) < std::mem::size_of::<SERVICE_FAILURE_ACTIONS_FLAG>() {
        return Err("invalid failure actions flag".into());
    }
    let flag = unsafe { &*flag.as_ptr().cast::<SERVICE_FAILURE_ACTIONS_FLAG>() };
    if flag.fFailureActionsOnNonCrashFailures != 0 {
        return Err("non-crash recovery must remain disabled".into());
    }
    Ok(())
}

fn set_recovery(service: &Handle, enabled: bool) -> Result<(), String> {
    // Only unexpected process termination is eligible, not a normal stop
    // or the host deliberately reporting a bad configuration and stopping.
    let flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 0 };
    if unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        (&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast()) } == 0 {
        return Err(last_error());
    }
    let mut actions = recovery_actions(enabled);
    // Clear any old command or reboot message; never run external commands.
    let mut empty = [0u16];
    let info = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: RECOVERY_RESET_SECONDS,
        lpRebootMsg: empty.as_mut_ptr(),
        lpCommand: empty.as_mut_ptr(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    if unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS,
        (&info as *const SERVICE_FAILURE_ACTIONSW).cast()) } == 0 {
        return Err(last_error());
    }
    verify_recovery(service, &actions)
}


pub(crate) fn register(name: &str, dir: &std::path::Path, exe: &str) -> Result<(), String> {
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
        "autostart-on" | "autostart-off" | "recovery-off" => SERVICE_CHANGE_CONFIG,
        "recovery-on" => SERVICE_CHANGE_CONFIG | SERVICE_START,
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
    execute_existing(name, action, &dir, exe)
}

// Desktop actions are a closed allowlist. No registration, deletion,
// arbitrary file path, profile mutation, shell execution, or elevation.
fn desktop_action_allowed(action: &str) -> bool {
    matches!(action, "check" | "start" | "stop" | "autostart-on" |
        "autostart-off" | "recovery-on" | "recovery-off")
}

pub fn manage_existing(name: &str, action: &str) -> Result<(), String> {
    if !crate::service_host::valid_name(name) || !desktop_action_allowed(action) {
        return Err("invalid desktop service action or name".into());
    }
    let dir = std::env::var_os("ProgramData").map(std::path::PathBuf::from)
        .ok_or("ProgramData unavailable")?.join(name);
    let exe = dir.join("localtunnel-desktop.exe");
    execute_existing(name, action, &dir, exe.to_str().ok_or("invalid executable path")?)
}

fn confirmed_directory(name: &str, confirmation: &str) -> Result<std::path::PathBuf, String> {
    if !crate::service_host::valid_name(name) || name != confirmation {
        return Err("exact service name confirmation required".into());
    }
    Ok(crate::service_provision::program_data()?.join(name))
}

// Keep this separate from the ordinary action allowlist. A configuration
// replacement is deliberately not a live reload, and never starts a service.
pub fn update_profile(name: &str, confirmation: &str, request: crate::StartRequest) -> Result<(), String> {
    let dir = confirmed_directory(name, confirmation)?;
    if !request.engine.is_empty() { return Err("service requires bundled engine".into()); }
    let _validated = zeroize::Zeroizing::new(crate::build_config(&request)?);
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&request).map_err(|_| "profile encode failed")?);
    if encoded.len() > 256 * 1024 { return Err("service profile too large".into()); }
    let exe = dir.join("localtunnel-desktop.exe");
    let exe = exe.to_str().ok_or("invalid executable path")?;
    let service = open(name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG)?;
    config(&service, name, exe)?;
    if status(&service)? != SERVICE_STOPPED { return Err("stop service before changing configuration".into()); }
    crate::service_acl::validate(&dir, name, true)?;
    crate::service_acl::history_dir(&dir, name)?;
    crate::credentials::load_service(&dir)?;
    let scratch = tempfile::tempdir().map_err(|_| "engine check directory unavailable")?;
    crate::engine_integrity::stage(&crate::bundled_engine(&dir)?, scratch.path())?;
    // Disable first to block new SCM starts during replacement. Do not
    // restore automatic/manual mode implicitly, even on successful update.
    set_start_type(&service, SERVICE_DISABLED)?;
    if config(&service, name, exe)? != SERVICE_DISABLED || status(&service)? != SERVICE_STOPPED {
        return Err("service disabled but no longer stopped; inspect SCM".into());
    }
    if let Err(e) = crate::credentials::replace_service(&dir, name, &request) {
        return Err(format!("service left disabled; inspect saved configuration: {e}"));
    }
    if config(&service, name, exe)? != SERVICE_DISABLED || status(&service)? != SERVICE_STOPPED {
        return Err("configuration written; service state changed concurrently; inspect SCM".into());
    }
    Ok(())
}

pub fn unregister_confirmed(name: &str, confirmation: &str) -> Result<(), String> {
    let dir = confirmed_directory(name, confirmation)?;
    let exe = dir.join("localtunnel-desktop.exe");
    execute_existing(name, "unregister", &dir, exe.to_str().ok_or("invalid executable path")?)
}

pub(crate) fn execute_existing(name: &str, action: &str, dir: &std::path::Path, exe: &str) -> Result<(), String> {
    let rights = access(action)?;
    let service = open(name, rights)?;
    config(&service, name, exe)?;
    // Stop and disabling autostart must remain available even if the
    // profile or ACL was damaged. Never start/enable an unsafe deployment.
    if matches!(action, "start" | "autostart-on" | "recovery-on" | "check") {
        crate::service_acl::validate(&dir, name, true)?;
        // Validate the optional history location before start/autostart.
        crate::service_acl::history_dir(&dir, name)?;
        crate::credentials::load_service(&dir)?;
        let scratch = tempfile::tempdir().map_err(|_| "engine check directory unavailable")?;
        crate::engine_integrity::stage(&crate::bundled_engine(&dir)?, scratch.path())?;
    }
    match action {
        "check" => Ok(()),
        "recovery-on" | "recovery-off" => {
            // An already queued SCM restart may survive a policy edit.
            // Disable future recovery explicitly; unregister also disables start.
            set_recovery(&service, action == "recovery-on")
        }
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
    fn labels_do_not_claim_connectivity() {
        assert_eq!(state_label(SERVICE_RUNNING), "running");
        assert_eq!(state_label(SERVICE_STOPPED), "stopped");
        assert_eq!(state_label(SERVICE_START_PENDING), "starting");
        assert_eq!(state_label(u32::MAX), "unknown");
        assert_eq!(startup_label(SERVICE_DEMAND_START), "manual");
        assert_eq!(startup_label(SERVICE_AUTO_START), "automatic");
        assert_eq!(startup_label(SERVICE_DISABLED), "disabled");
        assert!(snapshot("Spooler").is_err());
    }

    #[test]
    fn recovery_policy_has_a_terminal_no_action() {
        let enabled = recovery_actions(true);
        assert_eq!(enabled.len(), 4);
        assert_eq!(enabled[0].Type, SC_ACTION_RESTART);
        assert_eq!(enabled[0].Delay, 3000);
        assert_eq!(enabled[1].Delay, 6000);
        assert_eq!(enabled[2].Delay, 12000);
        assert_eq!(enabled[3].Type, SC_ACTION_NONE);
        let disabled = recovery_actions(false);
        assert_eq!(disabled.len(), 1);
        assert_eq!(disabled[0].Type, SC_ACTION_NONE);
    }

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
        for action in ["check", "start", "stop", "autostart-on", "autostart-off", "recovery-on", "recovery-off"] {
            assert!(desktop_action_allowed(action));
        }
        for action in ["register", "unregister", "delete", "start; calc", ""] {
            assert!(!desktop_action_allowed(action));
        }
        assert!(manage_existing("Spooler", "stop").is_err());
        assert!(unregister_confirmed("Spooler", "Spooler").is_err());
        assert!(unregister_confirmed("LocalTunnelPreview-0123456789abcdef0123456789abcdef", "wrong").is_err());
        assert!(manage_existing("LocalTunnelPreview-0123456789abcdef0123456789abcdef", "unregister").is_err());
        assert!(access("start").unwrap() & SERVICE_START != 0);
        assert_eq!(access("check").unwrap() & SERVICE_CHANGE_CONFIG, 0);
        assert_eq!(access("stop").unwrap() & SERVICE_START, 0);
        assert!(access("install").is_err());
        assert!(access("delete").is_err());
        assert_eq!(access("unregister").unwrap() & SERVICE_START, 0);
        assert_ne!(access("unregister").unwrap() & DELETE_RIGHT, 0);
    }
}
