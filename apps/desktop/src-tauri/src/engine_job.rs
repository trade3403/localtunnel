//! Windows process lifetime guard. After assignment, closing the last job handle
//! also terminates the engine if the desktop process is killed unexpectedly.
#![cfg(windows)]
use std::{io, mem, os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle}, process::Child, ptr};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub struct EngineJob {
    _handle: OwnedHandle,
}

impl EngineJob {
    pub fn new() -> io::Result<Self> {
        // Unnamed, non-inheritable job: the engine cannot keep the handle alive.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() { return Err(io::Error::last_os_error()); }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(), JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 { return Err(io::Error::last_os_error()); }
        Ok(Self { _handle: handle })
    }

    pub fn assign(&self, child: &Child) -> io::Result<()> {
        let ok = unsafe { AssignProcessToJobObject(self._handle.as_raw_handle(), child.as_raw_handle()) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::{Command, Stdio}, thread, time::{Duration, Instant}};
    #[test]
    fn job_close_terminates_real_child() {
        let job = EngineJob::new().unwrap();
        let executable = std::env::var_os("SystemRoot").map(std::path::PathBuf::from)
            .unwrap().join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe");
        let mut child = Command::new(executable).args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        if let Err(e) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("job assignment failed: {e}");
        }
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() { return; }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("job close did not terminate child");
    }
}
