//! HTTP/1-only transport admission for the private IPv4 loopback API.
//! Application deadlines remain independent of the header/connection timers.
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{rt::{TokioIo, TokioTimer}, service::TowerToHyperService};
use std::{io, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};

const MAX_CONNECTIONS: usize = 64;
const HEADER_DEADLINE: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(120);
const MAX_BUFFER: usize = 32 * 1024;

pub async fn serve(listener: TcpListener, app: Router) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(_) => {
                // Bound repeated accept failures without leaking peer data.
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() { continue; }
        // Accept then immediately close overflow: no per-connection tasks,
        // HTTP parsing, queue, or response allocation for rejected sockets.
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new())
                .header_read_timeout(HEADER_DEADLINE)
                .max_buf_size(MAX_BUFFER)
                .keep_alive(true);
            // Drop the socket and permit on every completion/error/timeout.
            // Hard lifetime includes response writes, even a slow reader.
            // It may interrupt an active request; clients must not assume
            // that a timed-out mutation was rolled back.
            let _ = tokio::time::timeout(
                CONNECTION_LIFETIME,
                builder.serve_connection(TokioIo::new(stream), service),
            ).await;
        });
    }
}
