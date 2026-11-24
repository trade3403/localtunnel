//! Generates an isolated Nginx gateway for static, authorized domain mappings.
use std::{collections::HashSet, fmt::Write, net::{IpAddr, SocketAddr}};

pub struct Route<'a> {
    pub domain: &'a str,
    pub port: u16,
}

pub struct Certificate<'a> {
    pub chain: &'a str,
    pub key: &'a str,
}

pub(crate) fn domain_valid(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.parse::<IpAddr>().is_err()
        && domain.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63
                && !label.starts_with('-') && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && domain.rsplit('.').next().is_some_and(|label| label.bytes().any(|b| b.is_ascii_lowercase()))
}

fn path_valid(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 1024
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        && path.split('/').skip(1).all(|p| !p.is_empty() && p != "." && p != "..")
}

/// Full standalone configuration. It never edits or reloads existing Nginx.
/// All upstreams are restricted to relay ports on IPv4 loopback.
pub fn gateway_config(bind: SocketAddr, routes: &[Route<'_>], cert: Option<Certificate<'_>>) -> Result<String, &'static str> {
    if bind.port() == 0 || bind.ip().is_multicast() { return Err("invalid listener"); }
    if routes.len() > 64 { return Err("expected at most 64 routes"); }
    let mut domains = HashSet::new();
    for route in routes {
        if !domain_valid(route.domain) { return Err("expected lowercase DNS hostname, without wildcard"); }
        if !domains.insert(route.domain) { return Err("duplicate hostname"); }
        if route.port == 0 || route.port == bind.port() { return Err("invalid or conflicting upstream port"); }
    }
    if let Some(c) = &cert {
        if !path_valid(c.chain) || !path_valid(c.key) || c.chain == c.key { return Err("expected distinct safe absolute Linux certificate paths"); }
    }
    let tls = cert.is_some();
    let listener = format!("{bind}{}", if tls { " ssl" } else { "" });
    let mut out = String::from("worker_processes 1;\npid nginx.pid;\nerror_log stderr warn;\nevents { worker_connections 1024; }\nhttp {\n    access_log off;\n    client_body_temp_path client_body_temp;\n    proxy_temp_path proxy_temp;\n    fastcgi_temp_path fastcgi_temp;\n    uwsgi_temp_path uwsgi_temp;\n    scgi_temp_path scgi_temp;\n    server_tokens off;\n    client_max_body_size 16m;\n    client_header_timeout 15s;\n    client_body_timeout 30s;\n    map $http_upgrade $lt_connection { default upgrade; '' close; }\n");
    if let Some(c) = &cert {
        writeln!(out, "    ssl_certificate {};\n    ssl_certificate_key {};\n    ssl_protocols TLSv1.2 TLSv1.3;", c.chain, c.key).map_err(|_| "format error")?;
    }
    writeln!(out, "    server {{\n        listen {listener} default_server;\n        server_name _;").map_err(|_| "format error")?;
    if tls { out.push_str("        ssl_reject_handshake on;\n"); }
    out.push_str("        return 421;\n    }\n");
    for route in routes {
        writeln!(out, "    server {{\n        listen {listener};\n        server_name {};\n        if ($host != {}) {{ return 421; }}\n        if ($http_host = '') {{ return 421; }}", route.domain, route.domain).map_err(|_| "format error")?;
        if tls { out.push_str("        if ($ssl_server_name != $host) { return 421; }\n"); }
        writeln!(out, "        location / {{\n            proxy_pass http://127.0.0.1:{};\n            proxy_http_version 1.1;\n            proxy_set_header Host $host;\n            proxy_set_header X-Real-IP $remote_addr;\n            proxy_set_header X-Forwarded-For $remote_addr;\n            proxy_set_header X-Forwarded-Host $host;\n            proxy_set_header X-Forwarded-Proto $scheme;\n            proxy_set_header X-Forwarded-Port $server_port;\n            proxy_set_header Forwarded \"\";\n            proxy_set_header Upgrade $http_upgrade;\n            proxy_set_header Connection $lt_connection;\n            proxy_connect_timeout 5s;\n            proxy_read_timeout 60s;\n            proxy_send_timeout 60s;\n            proxy_buffering off;\n        }}\n    }}", route.port).map_err(|_| "format error")?;
    }
    out.push_str("}\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bind() -> SocketAddr { "127.0.0.1:18080".parse().unwrap() }

    #[test]
    fn routes_are_static_and_unknown_hosts_rejected() {
        let out = gateway_config(bind(), &[Route {domain:"web.example.test",port:20800},Route{domain:"api.example.test",port:20801}], None).unwrap();
        assert!(out.contains("default_server"));
        assert!(out.contains("return 421"));
        assert!(out.contains("proxy_pass http://127.0.0.1:20800;"));
        assert!(out.contains("proxy_pass http://127.0.0.1:20801;"));
        assert!(out.contains("proxy_set_header X-Forwarded-For $remote_addr;"));
        assert!(out.contains("proxy_set_header Forwarded \"\";"));
    }

    #[test]
    fn rejects_injection_and_bad_domains() {
        for domain in ["*.example.test", "api.test;\n", "API.example.test", "127.0.0.1", "a..test", "-a.test", "localhost", "a.test."] {
            assert!(gateway_config(bind(), &[Route {domain,port:20800}],None).is_err());
        }
        assert!(gateway_config(bind(), &[Route {domain:"api.test",port:18080}],None).is_err());
        assert!(gateway_config(bind(), &[Route {domain:"api.test",port:20800},Route{domain:"api.test",port:20801}],None).is_err());
    }

    #[test]
    fn tls_requires_safe_paths_and_rejects_sni_host_mismatch() {
        let routes = [Route{domain:"api.test",port:20800}];
        assert!(gateway_config(bind(), &routes, Some(Certificate{chain:"/tmp/cert;bad",key:"/tmp/key.pem"})).is_err());
        assert!(gateway_config(bind(), &routes, Some(Certificate{chain:"/tmp/../cert.pem",key:"/tmp/key.pem"})).is_err());
        let out = gateway_config(bind(), &routes, Some(Certificate{chain:"/tmp/cert.pem",key:"/tmp/key.pem"})).unwrap();
        assert!(out.contains("ssl_reject_handshake on;"));
        assert!(out.contains("if ($ssl_server_name != $host)"));
        assert!(out.contains("ssl_protocols TLSv1.2 TLSv1.3;"));
    }
}
