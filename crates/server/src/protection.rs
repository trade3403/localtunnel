//! Bounded application-layer admission for the loopback control plane.
//! No client-controlled keys, unbounded queue, or forwarded-IP trust.
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{sync::{Arc, Mutex}, time::{Duration, Instant}};
use tokio::sync::Semaphore;

const MAX_ACTIVE: usize = 32;
const BURST: f64 = 240.0;
const PER_SECOND: f64 = 120.0;
const MAX_URI: usize = 2048;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY: u64 = 4096;
const DEADLINE: Duration = Duration::from_secs(12);

struct Bucket {
    at: Instant,
    tokens: f64,
}
impl Bucket {
    fn new(now: Instant) -> Self { Self { at: now, tokens: BURST } }
    fn admit(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * PER_SECOND).min(BURST);
        self.at = now;
        if self.tokens < 1.0 { return false; }
        self.tokens -= 1.0;
        true
    }
}
#[derive(Clone)]
pub struct Limits {
    bucket: Arc<Mutex<Bucket>>,
    active: Arc<Semaphore>,
}
impl Limits {
    pub fn new() -> Self {
        Self { bucket: Arc::new(Mutex::new(Bucket::new(Instant::now()))), active: Arc::new(Semaphore::new(MAX_ACTIVE)) }
    }
}

fn headers(response: &mut Response) {
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
}
fn reject(status: StatusCode, message: &'static str, retry: bool) -> Response {
    let mut r = (status, message).into_response();
    headers(&mut r);
    if retry { r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1")); }
    r
}

fn local_host(value: &str) -> bool {
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if host != "127.0.0.1" && !host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) &&
        p.parse::<u16>().is_ok_and(|n| n != 0))
}

// Native loopback clients do not send browser metadata. Browser requests
// must come through the fixed same-origin admin preview. Neither check
// replaces bearer authentication: native clients can forge these headers.
fn local_request(request: &Request) -> bool {
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return false;
    }
    let all = request.headers().get_all(header::HOST);
    let mut hosts = all.iter();
    if !hosts.next().and_then(|h| h.to_str().ok()).is_some_and(local_host) ||
        hosts.next().is_some() {
        return false;
    }
    let all = request.headers().get_all(header::ORIGIN);
    let mut origins = all.iter();
    if let Some(origin) = origins.next() {
        if origin.as_bytes() != b"http://127.0.0.1:1430" || origins.next().is_some() {
            return false;
        }
    }
    let all = request.headers().get_all("sec-fetch-site");
    let mut sites = all.iter();
    if let Some(site) = sites.next() {
        if !matches!(site.as_bytes(), b"same-origin" | b"none") || sites.next().is_some() {
            return false;
        }
    }
    true
}

pub async fn protect(State(limits): State<Limits>, request: Request, next: Next) -> Response {
    // This starts after Hyper has parsed the headers; it is not a transport
    // connection cap or a pre-header slowloris defense.
    let admitted = match limits.bucket.lock() {
        Ok(mut b) => b.admit(Instant::now()),
        Err(_) => return reject(StatusCode::SERVICE_UNAVAILABLE, "admission unavailable", true),
    };
    if !admitted { return reject(StatusCode::TOO_MANY_REQUESTS, "request rate exceeded", true); }
    if request.uri().path_and_query().map_or(0, |p| p.as_str().len()) > MAX_URI {
        return reject(StatusCode::URI_TOO_LONG, "request target too long", false);
    }
    let size = request.headers().iter().fold(0usize, |total, (name, value)| {
        total.saturating_add(name.as_str().len()).saturating_add(value.as_bytes().len()).saturating_add(4)
    });
    if size > MAX_HEADER_BYTES {
        return reject(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "request headers too large", false);
    }
    if !local_request(&request) {
        return reject(StatusCode::FORBIDDEN, "invalid local request origin", false);
    }
    if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
        match length.to_str().ok().and_then(|v| v.parse::<u64>().ok()) {
            Some(n) if n > MAX_BODY => return reject(StatusCode::PAYLOAD_TOO_LARGE, "request body too large", false),
            Some(_) => {},
            None => return reject(StatusCode::BAD_REQUEST, "invalid content length", false),
        }
    }
    // Never wait in a growing application queue. The permit is released on
    // completion, timeout or cancellation. Existing login CPU/DNS guards
    // still apply independently.
    let Ok(_permit) = limits.active.try_acquire() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE, "request concurrency exceeded", true);
    };
    match tokio::time::timeout(DEADLINE, next.run(request)).await {
        Ok(mut r) => { headers(&mut r); r }
        Err(_) => reject(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_host_exact_and_port_bounded() {
        for h in ["127.0.0.1", "127.0.0.1:1431", "localhost", "LOCALHOST:65535"] {
            assert!(local_host(h));
        }
        for h in ["localhost.example.test", "127.0.0.1.example.test", "127.0.0.2",
            "localhost:", "localhost:0", "localhost:65536", "localhost:+80",
            "127.0.0.1@evil.test", "evil.test", "[::1]:1431", "localhost."] {
            assert!(!local_host(h));
        }
    }
    #[test]
    fn bucket_has_bounded_burst_and_monotonic_refill() {
        let now = Instant::now();
        let mut b = Bucket::new(now);
        for _ in 0..240 { assert!(b.admit(now)); }
        assert!(!b.admit(now));
        let half = now + Duration::from_millis(500);
        for _ in 0..60 { assert!(b.admit(half)); }
        assert!(!b.admit(half));
        let later = half + Duration::from_secs(100);
        for _ in 0..240 { assert!(b.admit(later)); }
        assert!(!b.admit(later));
    }
}
