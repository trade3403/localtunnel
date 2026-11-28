//! Node-local finite TCP budget guard. No database or control-plane access.
//! A consumed grant must never be reused; the center retains the entire slice
//! on exit/crash until reconciliation. This module does not authorize startup.
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
const BURST: usize = 4096;
const MAX_LOCAL_CONNECTIONS: usize = 32;
const NANO: u128 = 1_000_000_000;

fn boot_now() -> io::Result<Duration> {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(io::Error::other("invalid boot clock"));
    }
    Ok(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
}
#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    pub(crate) monotonic: Instant,
    pub(crate) boot: Duration,
}
impl Deadline {
    fn alive(&self) -> io::Result<bool> {
        Ok(Instant::now() < self.monotonic && boot_now()? < self.boot)
    }
}
struct Bucket {
    rate: u128,
    credit: u128,
    last: Instant,
}
impl Bucket {
    fn new(rate: u32) -> Self {
        Self { rate: rate.into(), credit: BURST as u128 * NANO, last: Instant::now() }
    }
    fn available(&mut self) -> usize {
        let now = Instant::now();
        self.credit = self.credit.saturating_add(now.saturating_duration_since(self.last).as_nanos().saturating_mul(self.rate))
            .min(BURST as u128 * NANO);
        self.last = now;
        (self.credit / NANO) as usize
    }
    fn debit(&mut self, n: usize) {
        self.credit -= n as u128 * NANO;
    }
}
fn retry(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}
struct Direction {
    buf: [u8; BURST],
    start: usize,
    end: usize,
    eof: bool,
}
impl Direction {
    fn new() -> Self {
        Self { buf: [0; BURST], start: 0, end: 0, eof: false }
    }
    fn step(&mut self, from: &mut TcpStream, to: &mut TcpStream, bucket: &mut Bucket,
            left: &mut u64, deadline: Deadline) -> io::Result<()> {
        if self.eof || *left == 0 || !deadline.alive()? { return Ok(()); }
        if self.start == self.end {
            match from.read(&mut self.buf) {
                Ok(0) => { self.eof = true; to.shutdown(Shutdown::Write)?; return Ok(()); }
                Ok(n) => { self.start = 0; self.end = n; }
                Err(e) if retry(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        let n = bucket.available().min(self.end - self.start).min((*left).min(BURST as u64) as usize);
        if n == 0 || !deadline.alive()? { return Ok(()); }
        // A write is nonblocking and cannot exceed the remaining slice.
        // No other thread can write from this grant's accounting state.
        match to.write(&self.buf[self.start..self.start + n]) {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => {
                bucket.debit(written);
                *left -= written as u64;
                self.start += written;
                Ok(())
            }
            Err(e) if retry(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
struct Connection {
    source: TcpStream,
    target: TcpStream,
    up: Direction,
    down: Direction,
}
impl Connection {
    fn new(source: TcpStream, target: SocketAddr) -> io::Result<Self> {
        let target = TcpStream::connect_timeout(&target, Duration::from_millis(100))?;
        source.set_nonblocking(true)?;
        target.set_nonblocking(true)?;
        source.set_nodelay(true)?;
        target.set_nodelay(true)?;
        Ok(Self { source, target, up: Direction::new(), down: Direction::new() })
    }
    fn poll(&mut self, up: &mut Bucket, down: &mut Bucket, left: &mut u64, deadline: Deadline) -> bool {
        self.up.step(&mut self.source, &mut self.target, up, left, deadline).is_ok()
            && self.down.step(&mut self.target, &mut self.source, down, left, deadline).is_ok()
            && !(self.up.eof && self.down.eof)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End { Exhausted, Expired }
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) end: End,
    pub(crate) written: u64,
}
/// Owns the only guarded ingress listener and all admitted socket pairs.
/// Stops the entire guard at zero budget or deadline. The caller must stop
/// its upstream engine on any return; no startup authority is provided here.
/// A successful write is payload accounting, not a wire/delivery guarantee.
pub(crate) fn run(listener: TcpListener, target_port: u16, rate: u32, bytes: u64,
                  slots: u32, deadline: Deadline) -> io::Result<Outcome> {
    let local = listener.local_addr()?;
    if local.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) || local.port() == target_port
        || target_port == 0 || !(65536..=125_000_000).contains(&rate)
        || !(1..=9_000_000_000_000_000).contains(&bytes) || !(1..=65536).contains(&slots) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid finite guard configuration"));
    }
    listener.set_nonblocking(true)?;
    let target = SocketAddr::from(([127, 0, 0, 1], target_port));
    let cap = (slots as usize).min(MAX_LOCAL_CONNECTIONS);
    let mut connections = Vec::<Connection>::with_capacity(cap);
    let mut up = Bucket::new(rate);
    let mut down = Bucket::new(rate);
    let mut left = bytes;
    loop {
        if left == 0 { return Ok(Outcome { end: End::Exhausted, written: bytes }); }
        if !deadline.alive()? { return Ok(Outcome { end: End::Expired, written: bytes - left }); }
        match listener.accept() {
            Ok((source, peer)) => {
                if peer.ip().is_loopback() && connections.len() < cap && deadline.alive()? {
                    if let Ok(c) = Connection::new(source, target) {
                        if deadline.alive()? { connections.push(c); }
                    }
                }
            }
            Err(e) if retry(&e) => {},
            Err(e) => return Err(e),
        }
        let mut i = 0;
        while i < connections.len() && left != 0 && deadline.alive()? {
            if connections[i].poll(&mut up, &mut down, &mut left, deadline) { i += 1; }
            else { connections.swap_remove(i); }
        }
        if connections.len() > 1 { connections.rotate_left(1); }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    fn bind() -> TcpListener { TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap() }
    fn port(l: &TcpListener) -> u16 { l.local_addr().unwrap().port() }
    fn deadline(seconds: u64) -> Deadline {
        let d = Duration::from_secs(seconds);
        Deadline { monotonic: Instant::now() + d, boot: boot_now().unwrap() + d }
    }
    fn client(port: u16) -> TcpStream {
        let s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(6))).unwrap();
        s
    }
    #[test]
    fn real_shared_bidirectional_rate_and_exact_slice() {
        let backend = bind();
        let target = port(&backend);
        let ingress = bind();
        let front = port(&ingress);
        let fixture = thread::spawn(move || {
            let mut inputs = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = backend.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
                inputs.push(thread::spawn(move || {
                    let mut data = Vec::new();
                    s.read_to_end(&mut data).unwrap();
                    assert_eq!(data.len(), 32768);
                    (s, data)
                }));
            }
            let inputs: Vec<_> = inputs.into_iter().map(|t| t.join().unwrap()).collect();
            let received = Instant::now();
            for (mut s, data) in inputs { s.write_all(&data).unwrap(); s.shutdown(Shutdown::Write).unwrap(); }
            received
        });
        let start = Instant::now();
        let guard = thread::spawn(move || run(ingress, target, 65536, 131072, 2, deadline(8)).unwrap());
        let tasks: Vec<_> = [17, 39].into_iter().map(|value| thread::spawn(move || {
            let mut s = client(front);
            let data = vec![value; 32768];
            s.write_all(&data).unwrap();
            s.shutdown(Shutdown::Write).unwrap();
            let mut reply = vec![0; data.len()];
            s.read_exact(&mut reply).unwrap();
            assert_eq!(reply, data);
            Instant::now()
        })).collect();
        let done = tasks.into_iter().map(|t| t.join().unwrap()).max().unwrap();
        let received = fixture.join().unwrap();
        assert!(received.duration_since(start) >= Duration::from_millis(850));
        assert!(done.duration_since(received) >= Duration::from_millis(850));
        assert_eq!(guard.join().unwrap(), Outcome { end: End::Exhausted, written: 131072 });
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, front)).is_err());
    }
    #[test]
    fn real_slice_exhaustion_closes_all_sockets() {
        let backend = bind();
        let target = port(&backend);
        let ingress = bind();
        let front = port(&ingress);
        let fixture = thread::spawn(move || {
            let (mut s, _) = backend.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
            let mut data = Vec::new();
            s.read_to_end(&mut data).unwrap();
            data
        });
        let guard = thread::spawn(move || run(ingress, target, 65536, 4096, 1, deadline(5)).unwrap());
        let mut s = client(front);
        s.write_all(&vec![7; 8192]).unwrap();
        let _ = s.shutdown(Shutdown::Write);
        assert_eq!(guard.join().unwrap(), Outcome { end: End::Exhausted, written: 4096 });
        assert_eq!(fixture.join().unwrap(), vec![7; 4096]);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, front)).is_err());
    }
    #[test]
    fn real_slot_limit_and_dual_clock_expiry() {
        let backend = bind();
        let target = port(&backend);
        let ingress = bind();
        let front = port(&ingress);
        let (tx, rx) = mpsc::channel();
        let fixture = thread::spawn(move || {
            let (mut s, _) = backend.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
            let mut byte = [0; 1];
            s.read_exact(&mut byte).unwrap();
            tx.send(byte[0]).unwrap();
            assert_eq!(s.read(&mut byte).unwrap(), 0);
            backend.set_nonblocking(true).unwrap();
            assert!(backend.accept().is_err());
        });
        // Boot deadline intentionally earlier than the monotonic deadline.
        let d = Deadline { monotonic: Instant::now() + Duration::from_secs(8),
            boot: boot_now().unwrap() + Duration::from_secs(3) };
        let guard = thread::spawn(move || run(ingress, target, 65536, 10000, 1, d).unwrap());
        let mut first = client(front);
        first.write_all(&[13]).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 13);
        let mut second = client(front);
        let mut byte = [0; 1];
        match second.read(&mut byte) {
            Ok(0) => {},
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {},
            other => panic!("extra connection not rejected: {other:?}"),
        }
        assert_eq!(guard.join().unwrap(), Outcome { end: End::Expired, written: 1 });
        assert_eq!(first.read(&mut byte).unwrap(), 0);
        fixture.join().unwrap();
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, front)).is_err());
    }
}
