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

/// Successful application-layer socket sends. These are not wire bytes,
/// acknowledgements or a count of packets lost by the operating system.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpStats {
    pub to_target_bytes: u64,
    pub to_target_packets: u64,
    pub to_source_bytes: u64,
    pub to_source_packets: u64,
    pub rejected_from_source: u64,
    pub rejected_from_target: u64,
}

fn count(bytes: &mut u64, packets: &mut u64, n: usize) {
    *bytes = bytes.saturating_add(n as u64);
    *packets = packets.saturating_add(1);
}
fn reject(packets: &mut u64) { *packets = packets.saturating_add(1); }

/// Reusable single-mapping, caller-driven UDP forwarder. The caller owns its
/// lifetime, polling cadence and failure handling. No hidden worker or queue.
/// The same fixed guard policy applies at relay ingress or a local agent target.
pub struct UdpForwarder {
    ingress: UdpSocket,
    target: SocketAddr,
    sessions: HashMap<SocketAddr, Session>,
    admission: Admission,
    inbound: Bucket,
    outbound: Bucket,
    buf: Box<[u8; 65536]>,
    stats: UdpStats,
}

impl UdpForwarder {
    /// Port zero is permitted only for programmatic ephemeral binding.
    /// The public guard CLI still requires a nonzero, explicit port.
    pub fn bind(listen: SocketAddr, target: SocketAddr) -> Result<Self, &'static str> {
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        if listen.ip() != loopback || target.ip() != loopback || target.port()==0 || listen==target {
            return Err("UDP forwarder requires distinct IPv4 loopback endpoints");
        }
        let ingress = UdpSocket::bind(listen).map_err(|_| "UDP guard bind failed")?;
        let assigned = ingress.local_addr().map_err(|_| "UDP guard address unavailable")?;
        if !valid_endpoints(assigned, target) { return Err("UDP guard port collision"); }
        ingress.set_nonblocking(true).map_err(|_| "UDP guard nonblocking setup failed")?;
        let now = Instant::now();
        Ok(Self { ingress, target, sessions: HashMap::new(), admission: Admission::new(),
            inbound: Bucket::new(GLOBAL_RATE,GLOBAL_BURST,now),
            outbound: Bucket::new(GLOBAL_RATE,GLOBAL_BURST,now),
            buf: Box::new([0u8;65536]), stats: UdpStats::default() })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> { self.ingress.local_addr() }
    pub fn stats(&self) -> UdpStats { self.stats }
    pub fn active_sources(&self) -> usize { self.sessions.len() }

    /// Bounded nonblocking work; no payload logging or pending application queue.
    pub fn poll(&mut self) -> Result<(), &'static str> {
        let now = Instant::now();
        self.sessions.retain(|_,s| now.saturating_duration_since(s.last_forwarded)<IDLE);
        self.admission.prune(now);
        for _ in 0..32 {
            let (n,peer)=match self.ingress.recv_from(&mut self.buf[..]) {
                Ok(v)=>v,
                Err(e) if transient(&e)=>break,
                Err(_)=>return Err("UDP guard receive failed"),
            };
            if n==0 || n>MAX_PAYLOAD || !peer.ip().is_loopback() {
                reject(&mut self.stats.rejected_from_source); continue;
            }
            let now=Instant::now();
            if !self.inbound.take(now) {
                reject(&mut self.stats.rejected_from_source); continue;
            }
            if !self.sessions.contains_key(&peer) {
                if self.sessions.len()>=MAX_SESSIONS || !self.admission.allow(now) {
                    reject(&mut self.stats.rejected_from_source); continue;
                }
                let Ok(socket)=UdpSocket::bind("127.0.0.1:0") else {
                    reject(&mut self.stats.rejected_from_source); continue;
                };
                if socket.connect(self.target).is_err() || socket.set_nonblocking(true).is_err() {
                    reject(&mut self.stats.rejected_from_source); continue;
                }
                self.sessions.insert(peer,Session {socket,last_forwarded:now,
                    inbound:Bucket::new(PEER_RATE,PEER_BURST,now),
                    outbound:Bucket::new(PEER_RATE,PEER_BURST,now)});
            }
            if let Some(s)=self.sessions.get_mut(&peer) {
                if s.inbound.take(now) && s.socket.send(&self.buf[..n]).ok()==Some(n) {
                    s.last_forwarded=now;
                    count(&mut self.stats.to_target_bytes,&mut self.stats.to_target_packets,n);
                } else { reject(&mut self.stats.rejected_from_source); }
            }
        }
        for (peer,s) in &mut self.sessions {
            for _ in 0..4 {
                let n=match s.socket.recv(&mut self.buf[..]) {
                    Ok(n)=>n,
                    Err(_)=>break, // no state expansion or retry queue on error
                };
                let now=Instant::now();
                if n>0 && n<=MAX_PAYLOAD && self.outbound.take(now) && s.outbound.take(now)
                    && self.ingress.send_to(&self.buf[..n],peer).ok()==Some(n) {
                    count(&mut self.stats.to_source_bytes,&mut self.stats.to_source_packets,n);
                } else { reject(&mut self.stats.rejected_from_target); }
            }
        }
        Ok(())
    }
}

pub fn run(listen: SocketAddr, relay: SocketAddr) -> Result<(), &'static str> {
    if !valid_endpoints(listen,relay) {
        return Err("UDP guard requires distinct nonzero IPv4 127.0.0.1 endpoints");
    }
    let mut forwarder = UdpForwarder::bind(listen,relay)?;
    loop {
        forwarder.poll()?;
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

    #[test]
    fn real_udp_forwarder_counts_only_successful_sends_and_isolates_sources() {
        let target=UdpSocket::bind("127.0.0.1:0").unwrap();
        target.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let mut f=UdpForwarder::bind("127.0.0.1:0".parse().unwrap(),target.local_addr().unwrap()).unwrap();
        let addr=f.local_addr().unwrap();
        let a=UdpSocket::bind("127.0.0.1:0").unwrap();
        let b=UdpSocket::bind("127.0.0.1:0").unwrap();
        for sock in [&a,&b] { sock.set_read_timeout(Some(Duration::from_millis(30))).unwrap(); }
        fn receive(f:&mut UdpForwarder,sock:&UdpSocket,buf:&mut [u8])->(usize,SocketAddr) {
            let until=Instant::now()+Duration::from_secs(3);
            loop {
                f.poll().unwrap();
                match sock.recv_from(buf) {
                    Ok(value)=>return value,
                    Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)=>{},
                    Err(e)=>panic!("unexpected UDP error: {e}"),
                }
                assert!(Instant::now()<until,"UDP receive timed out");
            }
        }
        let mut buf=[0u8;2048];
        a.send_to(&[1u8;17],addr).unwrap();
        let (n,pa)=receive(&mut f,&target,&mut buf);
        assert_eq!(&buf[..n],&[1u8;17]);
        b.send_to(&[2u8;31],addr).unwrap();
        let (n,pb)=receive(&mut f,&target,&mut buf);
        assert_eq!(&buf[..n],&[2u8;31]);
        assert_ne!(pa,pb);
        assert_eq!(f.active_sources(),2);
        // Reply in reverse order, with unequal payload lengths.
        target.send_to(&[4u8;43],pb).unwrap();
        target.send_to(&[3u8;23],pa).unwrap();
        let (n,_)=receive(&mut f,&a,&mut buf);
        assert_eq!(&buf[..n],&[3u8;23]);
        let (n,_)=receive(&mut f,&b,&mut buf);
        assert_eq!(&buf[..n],&[4u8;43]);
        assert_eq!(f.stats(),UdpStats {to_target_bytes:48,to_target_packets:2,
            to_source_bytes:66,to_source_packets:2,..UdpStats::default()});
        // Oversize ingress and response are explicitly rejected, not truncated.
        a.send_to(&[7u8;1201],addr).unwrap();
        target.send_to(&[8u8;1201],pa).unwrap();
        let until=Instant::now()+Duration::from_secs(3);
        while f.stats().rejected_from_source!=1 || f.stats().rejected_from_target!=1 {
            f.poll().unwrap();
            assert!(Instant::now()<until,"oversize rejection not observed");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(f.stats(),UdpStats {to_target_bytes:48,to_target_packets:2,
            to_source_bytes:66,to_source_packets:2,rejected_from_source:1,rejected_from_target:1});
        for sock in [&target,&a,&b] {
            assert!(matches!(sock.recv_from(&mut buf),Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)));
        }
        drop(f);
        // Released ingress can be rebound; no detached worker owns sockets.
        assert!(UdpSocket::bind(addr).is_ok());
    }

    #[test]
    fn counters_saturate_and_reject_invalid_forwarder_endpoints() {
        let mut bytes=u64::MAX-1;
        let mut packets=u64::MAX;
        count(&mut bytes,&mut packets,2);
        assert_eq!((bytes,packets),(u64::MAX,u64::MAX));
        reject(&mut packets);
        assert_eq!(packets,u64::MAX);
        assert!(UdpForwarder::bind("0.0.0.0:0".parse().unwrap(),"127.0.0.1:80".parse().unwrap()).is_err());
        assert!(UdpForwarder::bind("127.0.0.1:0".parse().unwrap(),"127.0.0.1:0".parse().unwrap()).is_err());
        assert!(UdpForwarder::bind("127.0.0.1:0".parse().unwrap(),"192.168.1.2:80".parse().unwrap()).is_err());
    }
}
