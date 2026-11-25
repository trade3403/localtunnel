//! Passive per-engine TCP observations. TCP alone is not Noise authentication
//! or an end-to-end public availability check. No DNS or active network probe.
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

pub struct Target {
    literal: Option<IpAddr>,
    port: u16,
    local_ports: Vec<u16>,
}

fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

impl Target {
    pub fn new(remote: &str, local_ports: Vec<u16>) -> Result<Self, String> {
        let literal = remote.parse::<SocketAddr>().ok();
        let port = remote.rsplit_once(':').and_then(|(_,p)| p.parse::<u16>().ok())
            .filter(|&p| p != 0).ok_or("invalid relay port")?;
        Ok(Self { literal: literal.map(|a| normalized(a.ip())), port, local_ports })
    }
    fn matches(&self, ip: IpAddr, port: u16) -> bool {
        let ip = normalized(ip);
        // Local targets are loopback. In ambiguous same-port loopback
        // cases exclude the connection rather than falsely call it relay.
        if port != self.port || (ip.is_loopback() && self.local_ports.contains(&port)) {
            return false;
        }
        self.literal.is_none_or(|expected| expected == ip)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub state: &'static str,
    pub established: Option<u32>,
    pub match_scope: &'static str,
}
impl Observation {
    pub fn inactive() -> Self {
        Self { state: "inactive", established: None, match_scope: "none" }
    }
    pub fn unknown() -> Self {
        Self { state: "unknown", established: None, match_scope: "none" }
    }
}

pub fn observe(pid: u32, target: &Target) -> Observation {
    #[cfg(windows)]
    {
        if let Ok(count) = windows::count(pid, target) {
            return Observation {
                state: if count > 0 { "established" } else { "not_observed" },
                established: Some(count),
                match_scope: if target.literal.is_some() { "ip_port" } else { "port_only" },
            };
        }
    }
    #[cfg(not(windows))]
    let _ = (pid, target);
    Observation::unknown()
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{mem, ptr, net::{Ipv4Addr, Ipv6Addr}};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID,
    };

    // Windows documents a DWORD count followed by DWORD-aligned row
    // structures. These two OWNER_PID row types contain only 32-bit
    // fields and byte arrays. Read through bounded, aligned storage.
    fn table<T: Copy>(family: u32) -> Result<Vec<T>, ()> {
        const MAX: u32 = 16 * 1024 * 1024;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        let mut size = 0u32;
        let code = unsafe { GetExtendedTcpTable(ptr::null_mut(), &mut size, 0,
            family, TCP_TABLE_OWNER_PID_ALL, 0) };
        if code != ERROR_INSUFFICIENT_BUFFER || size < 4 { return Err(()); }
        for _ in 0..3 {
            if size < 4 || size > MAX { return Err(()); }
            let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
            let capacity = size;
            let code = unsafe { GetExtendedTcpTable(buffer.as_mut_ptr().cast(), &mut size,
                0, family, TCP_TABLE_OWNER_PID_ALL, 0) };
            if code == ERROR_INSUFFICIENT_BUFFER { continue; }
            if code != 0 || size < 4 || size > capacity || mem::align_of::<T>() > 4 {
                return Err(());
            }
            let rows = buffer[0] as usize;
            let bytes = rows.checked_mul(mem::size_of::<T>()).and_then(|n| n.checked_add(4)).ok_or(())?;
            if bytes > size as usize { return Err(()); }
            let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().add(1).cast::<T>(), rows) };
            return Ok(data.to_vec());
        }
        Err(())
    }

    pub fn count(pid: u32, target: &Target) -> Result<u32, ()> {
        const ESTABLISHED: u32 = 5;
        let ipv4 = table::<MIB_TCPROW_OWNER_PID>(2)?; // AF_INET
        let ipv6 = table::<MIB_TCP6ROW_OWNER_PID>(23)?; // AF_INET6
        let v4 = ipv4.iter().filter(|r| r.dwOwningPid == pid && r.dwState == ESTABLISHED
            && target.matches(IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                u16::from_be(r.dwRemotePort as u16))).count();
        let v6 = ipv6.iter().filter(|r| r.dwOwningPid == pid && r.dwState == ESTABLISHED
            && target.matches(IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                u16::from_be(r.dwRemotePort as u16))).count();
        u32::try_from(v4 + v6).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_hostname_and_local_target_matching() {
        let literal = Target::new("192.0.2.1:2333", vec![8080]).unwrap();
        assert!(literal.matches("192.0.2.1".parse().unwrap(), 2333));
        assert!(!literal.matches("192.0.2.2".parse().unwrap(), 2333));
        assert!(!literal.matches("192.0.2.1".parse().unwrap(), 2334));
        let host = Target::new("relay.example.test:2333", vec![2333]).unwrap();
        assert!(host.matches("2001:db8::1".parse().unwrap(), 2333));
        assert!(!host.matches("127.0.0.1".parse().unwrap(), 2333));
        assert!(!host.matches("::ffff:127.0.0.1".parse().unwrap(), 2333));
        assert!(Target::new("bad:0", vec![]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn native_table_observes_real_owned_socket() {
        use std::net::{TcpListener,TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let target = Target::new(&addr.to_string(), vec![]).unwrap();
        let outbound = TcpStream::connect(addr).unwrap();
        let (inbound, _) = listener.accept().unwrap();
        assert_eq!(observe(std::process::id(), &target).established, Some(1));
        drop(outbound);
        drop(inbound);
        assert_eq!(observe(std::process::id(), &target).established, Some(0));
    }
}
