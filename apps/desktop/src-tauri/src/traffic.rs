//! Session-scoped application-byte metering for desktop-managed tunnels.
//! Only loopback endpoints; no payload logging or packet capture.
use serde::Serialize;
use std::{
    io, net::{SocketAddr, TcpListener as StdListener}, pin::Pin,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    task::{Context, Poll}, thread, time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Semaphore},
};

const MAX_CONNECTIONS: usize = 128;
#[derive(Default)]
struct Counters { up: AtomicU64, down: AtomicU64 }

struct Counted<'a> { stream: TcpStream, written: &'a AtomicU64 }
impl AsyncRead for Counted<'_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Counted<'_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let _ = self.written.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                |old| Some(old.saturating_add(*n as u64)));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn accept_loop(listener: TcpListener, target: SocketAddr, counts: Arc<Counters>, slots: Arc<Semaphore>) {
    loop {
        let (incoming, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else { drop(incoming); continue; };
        let counts = counts.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(local)) = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await else { return; };
            // Engine -> local application is download; local -> engine is upload.
            // Count successful writes, including partial writes before a close.
            let mut engine = Counted { stream: incoming, written: &counts.up };
            let mut local = Counted { stream: local, written: &counts.down };
            let _ = tokio::io::copy_bidirectional(&mut engine, &mut local).await;
        });
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub state: &'static str,
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub upload_bytes_per_second: Option<f64>,
    pub download_bytes_per_second: Option<f64>,
}
impl Snapshot {
    pub fn inactive() -> Self {
        Self { state: "inactive", upload_bytes: None, download_bytes: None,
            upload_bytes_per_second: None, download_bytes_per_second: None }
    }
}

pub struct Meter {
    ports: Vec<u16>,
    counts: Arc<Counters>,
    last: Option<(Instant, u64, u64)>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Meter {
    pub fn start(targets: &[u16], relay_port: u16) -> Result<Self, String> {
        if targets.is_empty() || targets.len() > 64 || targets.contains(&0) {
            return Err("invalid metered targets".into());
        }
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for &port in targets {
            let mut selected = None;
            // Keep rejected sockets alive until a suitable port is obtained,
            // avoiding a repeated allocation of the same excluded port.
            let mut rejected = Vec::new();
            for _ in 0..32 {
                let listener = StdListener::bind(("127.0.0.1", 0)).map_err(|_| "meter bind failed")?;
                let assigned = listener.local_addr().map_err(|_| "meter address unavailable")?.port();
                if targets.contains(&assigned) || assigned == relay_port {
                    rejected.push(listener); continue;
                }
                listener.set_nonblocking(true).map_err(|_| "meter nonblocking failed")?;
                selected = Some((assigned, listener));
                break;
            }
            let (assigned, listener) = selected.ok_or("no safe meter port")?;
            ports.push(assigned);
            listeners.push((listener, SocketAddr::from(([127,0,0,1], port))));
        }
        let counts = Arc::new(Counters::default());
        let task_counts = counts.clone();
        let (stop, stopped) = oneshot::channel();
        let (ready, startup) = std::sync::mpsc::sync_channel(1);
        let worker = thread::Builder::new().name("localtunnel-meter".into()).spawn(move || {
            let result = (|| -> io::Result<()> {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                rt.block_on(async move {
                    let mut bound = Vec::new();
                    for (listener, target) in listeners {
                        bound.push((TcpListener::from_std(listener)?, target));
                    }
                    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
                    for (listener, target) in bound {
                        tokio::spawn(accept_loop(listener, target, task_counts.clone(), slots.clone()));
                    }
                    let _ = ready.send(());
                    let _ = stopped.await;
                    Ok(())
                })
                // Runtime drop cancels listeners and all in-flight socket tasks.
            })();
            let _ = result;
        }).map_err(|_| "meter worker unavailable")?;
        let mut meter = Self { ports, counts, last: None, stop: Some(stop), worker: Some(worker) };
        if startup.recv_timeout(Duration::from_secs(3)).is_err() {
            return Err("meter startup failed".into());
        }
        // First rate is based on the actual elapsed interval since startup.
        meter.last = Some((Instant::now(), 0, 0));
        Ok(meter)
    }
    pub fn ports(&self) -> &[u16] { &self.ports }
    pub fn snapshot(&mut self) -> Snapshot {
        if self.worker.as_ref().is_none_or(|w| w.is_finished()) {
            return Snapshot { state: "unknown", ..Snapshot::inactive() };
        }
        let now = Instant::now();
        let up = self.counts.up.load(Ordering::Relaxed);
        let down = self.counts.down.load(Ordering::Relaxed);
        let rate = self.last.and_then(|(then, prev_up, prev_down)| {
            let elapsed = now.duration_since(then).as_secs_f64();
            (elapsed >= 0.1).then(|| ((up.saturating_sub(prev_up)) as f64 / elapsed,
                (down.saturating_sub(prev_down)) as f64 / elapsed))
        });
        if rate.is_some() || self.last.is_none() { self.last = Some((now, up, down)); }
        Snapshot { state: "measured", upload_bytes: Some(up), download_bytes: Some(down),
            upload_bytes_per_second: rate.map(|r| r.0), download_bytes_per_second: rate.map(|r| r.1) }
    }
}
impl Drop for Meter {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn counts_real_bytes_and_preserves_half_close() {
        let local = StdListener::bind("127.0.0.1:0").unwrap();
        let port = local.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut conn, _) = local.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut input = Vec::new();
            conn.read_to_end(&mut input).unwrap();
            assert_eq!(input, vec![7u8; 32768]);
            conn.write_all(&vec![9u8; 65536]).unwrap();
        });
        let mut meter = Meter::start(&[port], 2333).unwrap();
        let addr = SocketAddr::from(([127,0,0,1],meter.ports()[0]));
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        conn.write_all(&vec![7u8; 32768]).unwrap();
        conn.shutdown(std::net::Shutdown::Write).unwrap();
        let mut data = Vec::new();
        conn.read_to_end(&mut data).unwrap();
        assert_eq!(data, vec![9u8; 65536]);
        server.join().unwrap();
        thread::sleep(Duration::from_millis(120));
        let actual = meter.snapshot();
        assert_eq!(actual.download_bytes, Some(32768));
        assert_eq!(actual.upload_bytes, Some(65536));
        assert!(actual.upload_bytes_per_second.unwrap() > 0.0);
        drop(meter);
        assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err());
    }
}
