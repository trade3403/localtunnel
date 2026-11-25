//! Session-scoped application-byte metering for managed tunnels.
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

// The service publishes only numeric data, never credentials or payloads.
// A partial or stale JSON record is treated as unavailable by the reader.
#[cfg(windows)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceSample {
    pub host_pid: u32,
    pub engine_pid: u32,
    pub sampled_at_ms: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_bytes_per_second: Option<f64>,
    pub download_bytes_per_second: Option<f64>,
}

#[cfg(windows)]
fn now_ms() -> Option<u64> {
    u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_millis()).ok()
}

#[cfg(windows)]
impl ServiceSample {
    pub fn from_snapshot(snapshot: Snapshot, engine_pid: u32) -> Option<Self> {
        if snapshot.state != "measured" { return None; }
        Some(Self { host_pid: std::process::id(), engine_pid, sampled_at_ms: now_ms()?,
            upload_bytes: snapshot.upload_bytes?, download_bytes: snapshot.download_bytes?,
            upload_bytes_per_second: snapshot.upload_bytes_per_second,
            download_bytes_per_second: snapshot.download_bytes_per_second })
    }

    pub fn fresh_for(&self, host_pid: u32) -> bool {
        self.host_pid == host_pid && self.engine_pid != 0 &&
            now_ms().is_some_and(|now| now.checked_sub(self.sampled_at_ms).is_some_and(|age| age <= 5000)) &&
            [self.upload_bytes_per_second, self.download_bytes_per_second].into_iter().flatten()
                .all(|rate| rate.is_finite() && rate >= 0.0)
    }
}

struct HistoryWorker {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<(), String>>>,
    failed: Arc<std::sync::atomic::AtomicBool>,
}

impl HistoryWorker {
    fn start(mut store: crate::history::Store, counts: Arc<Counters>) -> Result<Self, String> {
        let (stop, rx) = std::sync::mpsc::channel();
        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_failed = failed.clone();
        let worker = thread::Builder::new().name("localtunnel-history".into()).spawn(move || {
            let mut save = || store.checkpoint(counts.up.load(Ordering::Relaxed), counts.down.load(Ordering::Relaxed));
            loop {
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        worker_failed.store(save().is_err(), Ordering::Relaxed);
                    }
                    _ => return save(),
                }
            }
        }).map_err(|_| "history worker unavailable")?;
        Ok(Self { stop: Some(stop), thread: Some(worker), failed })
    }
    fn finish(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(worker) = self.thread.take() {
            worker.join().map_err(|_| "history worker failed")??;
        }
        Ok(())
    }
}
impl Drop for HistoryWorker {
    fn drop(&mut self) { let _ = self.finish(); }
}

pub struct Meter {
    ports: Vec<u16>,
    counts: Arc<Counters>,
    last: Option<(Instant, u64, u64)>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
    history: Option<HistoryWorker>,
}
impl Meter {
    pub fn start(targets: &[u16], relay_port: u16) -> Result<Self, String> {
        Self::start_with_history(targets, relay_port, None)
    }
    pub fn start_with_history(targets: &[u16], relay_port: u16, history_dir: Option<&std::path::Path>) -> Result<Self, String> {
        let store = history_dir.map(crate::history::Store::open).transpose()?;
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
        let mut meter = Self { ports, counts, last: None, stop: Some(stop), worker: Some(worker), history: None };
        if startup.recv_timeout(Duration::from_secs(3)).is_err() {
            return Err("meter startup failed".into());
        }
        // First rate is based on the actual elapsed interval since startup.
        meter.last = Some((Instant::now(), 0, 0));
        if let Some(store) = store {
            meter.history = Some(HistoryWorker::start(store, meter.counts.clone())?);
        }
        Ok(meter)
    }
    pub fn ports(&self) -> &[u16] { &self.ports }
    pub fn history_failed(&self) -> bool {
        self.history.as_ref().is_some_and(|h| h.failed.load(Ordering::Relaxed))
    }
    pub fn finish(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        // Save only after all forwarding tasks have stopped writing bytes.
        if let Some(mut history) = self.history.take() { history.finish()?; }
        Ok(())
    }
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
        let _ = self.finish();
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
        let history = tempfile::tempdir().unwrap();
        let mut meter = Meter::start_with_history(&[port], 2333, Some(history.path())).unwrap();
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
        meter.finish().unwrap();
        drop(meter);
        let saved = crate::history::read(history.path()).unwrap().unwrap();
        assert_eq!((saved.upload_bytes, saved.download_bytes), (65536, 32768));
        let mut restarted = Meter::start_with_history(&[port], 2333, Some(history.path())).unwrap();
        restarted.finish().unwrap();
        assert_eq!(crate::history::read(history.path()).unwrap().unwrap(), saved);
        assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err());
    }
}
