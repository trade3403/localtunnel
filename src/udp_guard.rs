//! Opt-in, loopback-only UDP ingress guard for a single mapped service.
//! Bounds its own sockets and admitted traffic, not all internal engine state.
//! Direct access to the relay's UDP port bypasses this guard.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_SESSIONS: usize = 32;
const IDLE: Duration = Duration::from_secs(65);
const MAX_PAYLOAD: usize = 1200;
const GLOBAL_RATE: f64 = 200.0;
const GLOBAL_BURST: f64 = 64.0;
const PEER_RATE: f64 = 40.0;
const PEER_BURST: f64 = 8.0;

struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}
impl Bucket {
    fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self { tokens: burst, rate, burst, last: now }
    }
    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64()*self.rate).min(self.burst);
        self.last = now;
        if self.tokens < 1.0 { false } else { self.tokens -= 1.0; true }
    }
}

struct Admission {
    recent: VecDeque<Instant>,
}
impl Admission {
    fn new() -> Self { Self { recent: VecDeque::new() } }
    fn prune(&mut self, now: Instant) {
        while self.recent.front().is_some_and(|t| now.saturating_duration_since(*t)>=IDLE) {
            self.recent.pop_front();
        }
    }
    fn allow(&mut self, now: Instant) -> bool {
        self.prune(now);
        if self.recent.len()>=MAX_SESSIONS { false }
        else { self.recent.push_back(now); true }
    }
}
struct Session {
    socket: UdpSocket,
    last_forwarded: Instant,
    inbound: Bucket,
    outbound: Bucket,
}
fn transient(e: &io::Error) -> bool {
    matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted|io::ErrorKind::ConnectionReset|io::ErrorKind::ConnectionRefused)
}
fn valid_endpoints(listen: SocketAddr, relay: SocketAddr) -> bool {
    let valid=|a: SocketAddr| a.ip()==std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) && a.port()!=0;
    valid(listen)&&valid(relay)&&listen!=relay
}

pub fn run(listen: SocketAddr, relay: SocketAddr) -> Result<(), &'static str> {
    if !valid_endpoints(listen,relay) {
        return Err("UDP guard requires distinct nonzero IPv4 127.0.0.1 endpoints");
    }
    let ingress=UdpSocket::bind(listen).map_err(|_| "UDP guard bind failed")?;
    ingress.set_nonblocking(true).map_err(|_| "UDP guard nonblocking setup failed")?;
    let now=Instant::now();
    let mut sessions: HashMap<SocketAddr,Session>=HashMap::new();
    let mut admission=Admission::new();
    let mut inbound=Bucket::new(GLOBAL_RATE,GLOBAL_BURST,now);
    let mut outbound=Bucket::new(GLOBAL_RATE,GLOBAL_BURST,now);
    // A full UDP-size buffer avoids silent truncation and platform-specific
    // WSAEMSGSIZE for oversize datagrams. No application-level pending queue.
    let mut buf=[0u8;65536];
    loop {
        let now=Instant::now();
        sessions.retain(|_,s| now.saturating_duration_since(s.last_forwarded)<IDLE);
        admission.prune(now);
        // Bound work each iteration so upstream responses cannot starve.
        for _ in 0..32 {
            let (n,peer)=match ingress.recv_from(&mut buf) {
                Ok(v)=>v,
                Err(e) if transient(&e)=>break,
                Err(_)=>return Err("UDP guard receive failed"),
            };
            if n==0 || n>MAX_PAYLOAD || !peer.ip().is_loopback() { continue; }
            let now=Instant::now();
            if !inbound.take(now) { continue; }
            if !sessions.contains_key(&peer) {
                if sessions.len()>=MAX_SESSIONS || !admission.allow(now) { continue; }
                let Ok(socket)=UdpSocket::bind("127.0.0.1:0") else { continue; };
                if socket.connect(relay).is_err() || socket.set_nonblocking(true).is_err() { continue; }
                sessions.insert(peer,Session {socket,last_forwarded:now,
                    inbound:Bucket::new(PEER_RATE,PEER_BURST,now),
                    outbound:Bucket::new(PEER_RATE,PEER_BURST,now)});
            }
            if let Some(s)=sessions.get_mut(&peer) {
                if s.inbound.take(now) && s.socket.send(&buf[..n]).ok()==Some(n) {
                    s.last_forwarded=now;
                }
            }
        }
        for (peer,s) in &mut sessions {
            for _ in 0..4 {
                let n=match s.socket.recv(&mut buf) {
                    Ok(n)=>n,
                    Err(_)=>break, // no state expansion or retry queue on error
                };
                let now=Instant::now();
                if n>0 && n<=MAX_PAYLOAD && outbound.take(now) && s.outbound.take(now) {
                    let _=ingress.send_to(&buf[..n],peer);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_rate_and_admission_bounds() {
        let now=Instant::now();
        let mut b=Bucket::new(40.0,8.0,now);
        for _ in 0..8 { assert!(b.take(now)); }
        assert!(!b.take(now));
        assert!(b.take(now+Duration::from_millis(25)));
        assert!(!b.take(now+Duration::from_millis(25)));
        let mut a=Admission::new();
        for _ in 0..32 { assert!(a.allow(now)); }
        assert!(!a.allow(now+Duration::from_secs(64)));
        assert!(a.allow(now+IDLE));
        assert_eq!(a.recent.len(),1);
    }
    #[test]
    fn loopback_distinct_endpoints_only() {
        let a="127.0.0.1:20001".parse().unwrap();
        let b="127.0.0.1:20002".parse().unwrap();
        assert!(valid_endpoints(a,b));
        for invalid in ["0.0.0.0:20002","192.168.1.2:20002","[::1]:20002","127.0.0.1:0","127.0.0.1:20001"] {
            assert!(!valid_endpoints(a,invalid.parse().unwrap()));
        }
    }
}
