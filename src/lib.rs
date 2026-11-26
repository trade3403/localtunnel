pub mod managed_gateway;
pub mod certificates;
pub mod gateway;
pub mod udp_guard;
#[cfg(unix)]
pub mod unix_agent_store;
#[cfg(unix)]
pub mod unix_agent_process;
#[cfg(any(target_os="linux",target_os="macos"))]
pub mod unix_agent_service;
use std::net::SocketAddr;

const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("mapping name must be 1-64 ASCII letters, digits, underscores or hyphens");
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), &'static str> {
    if token.len() < 32 || token.len() > 128 || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("token must be 32-128 URL-safe ASCII characters; generate randomly");
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), &'static str> {
    if key.len() != 44 || !key.ends_with('=') || !key.as_bytes()[..43].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/') {
        return Err("expected a base64 X25519 key from rathole --genkey");
    }
    Ok(())
}

fn port_valid(port: u16) -> Result<(), &'static str> {
    if port == 0 { Err("port must not be zero") } else { Ok(()) }
}

fn remote_valid(remote: &str) -> Result<(), &'static str> {
    if let Ok(addr) = remote.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() || addr.ip().is_multicast() { return Err("invalid remote IP"); }
        return port_valid(addr.port());
    }
    let (host, port) = remote.rsplit_once(':').ok_or("remote address must be host:port")?;
    let port: u16 = port.parse().map_err(|_| "invalid remote port")?;
    port_valid(port)?;
    if host.len() > 253 || host.split('.').any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        return Err("invalid remote hostname");
    }
    Ok(())
}

pub struct ServerMapping<'a> {
    pub name: &'a str,
    pub port: u16,
    pub token: &'a str,
}

pub struct ClientMapping<'a> {
    pub name: &'a str,
    pub local: SocketAddr,
    pub token: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingProtocol { Tcp, Udp }

impl MappingProtocol {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err("mapping protocol must be tcp or udp"),
        }
    }

    fn name(self) -> &'static str {
        match self { Self::Tcp => "tcp", Self::Udp => "udp" }
    }
}

fn mapping_count(count: usize) -> Result<(), &'static str> {
    if (1..=64).contains(&count) { Ok(()) } else { Err("expected 1-64 mappings") }
}

pub fn server_configs(bind: SocketAddr, mappings: &[ServerMapping<'_>], key: &str) -> Result<String, &'static str> {
    let typed: Vec<_> = mappings.iter().map(|m| (MappingProtocol::Tcp, ServerMapping { name: m.name, port: m.port, token: m.token })).collect();
    server_mixed_configs(bind, &typed, key)
}

pub fn server_mixed_configs(bind: SocketAddr, mappings: &[(MappingProtocol, ServerMapping<'_>)], key: &str) -> Result<String, &'static str> {
    use std::collections::HashSet;
    use std::fmt::Write;
    validate_key(key)?;
    port_valid(bind.port())?;
    mapping_count(mappings.len())?;
    let mut names = HashSet::new();
    let mut ports = HashSet::new();
    let mut tokens = HashSet::new();
    let mut config = format!("[server]\nbind_addr = \"{bind}\"\nheartbeat_interval = 5\n\n[server.transport]\ntype = \"noise\"\n\n[server.transport.noise]\npattern = \"{PATTERN}\"\nlocal_private_key = \"{key}\"\n");
    for (protocol, m) in mappings {
        let kind = protocol.name();
        validate_name(m.name)?;
        validate_token(m.token)?;
        port_valid(m.port)?;
        if !names.insert(m.name) { return Err("duplicate mapping name"); }
        if bind.port() == m.port || !ports.insert(m.port) { return Err("duplicate or conflicting mapping port"); }
        if !tokens.insert(m.token) { return Err("each mapping must use an independent token"); }
        writeln!(config, "\n[server.services.{}]\ntype = \"{kind}\"\ntoken = \"{}\"\nbind_addr = \"127.0.0.1:{}\"", m.name, m.token, m.port).map_err(|_| "configuration formatting failed")?;
    }
    Ok(config)
}

pub fn client_configs(remote: &str, mappings: &[ClientMapping<'_>], key: &str) -> Result<String, &'static str> {
    let typed: Vec<_> = mappings.iter().map(|m| (MappingProtocol::Tcp, ClientMapping { name: m.name, local: m.local, token: m.token })).collect();
    client_mixed_configs(remote, &typed, key)
}

pub fn client_mixed_configs(remote: &str, mappings: &[(MappingProtocol, ClientMapping<'_>)], key: &str) -> Result<String, &'static str> {
    use std::collections::HashSet;
    use std::fmt::Write;
    validate_key(key)?;
    remote_valid(remote)?;
    mapping_count(mappings.len())?;
    let mut names = HashSet::new();
    let mut tokens = HashSet::new();
    let mut config = format!("[client]\nremote_addr = \"{remote}\"\nheartbeat_timeout = 15\nretry_interval = 1\n\n[client.transport]\ntype = \"noise\"\n\n[client.transport.noise]\npattern = \"{PATTERN}\"\nremote_public_key = \"{key}\"\n");
    for (protocol, m) in mappings {
        let kind = protocol.name();
        validate_name(m.name)?;
        validate_token(m.token)?;
        port_valid(m.local.port())?;
        if !m.local.ip().is_loopback() { return Err("local target must be loopback"); }
        if !names.insert(m.name) { return Err("duplicate mapping name"); }
        if !tokens.insert(m.token) { return Err("each mapping must use an independent token"); }
        writeln!(config, "\n[client.services.{}]\ntype = \"{kind}\"\ntoken = \"{}\"\nlocal_addr = \"{}\"", m.name, m.token, m.local).map_err(|_| "configuration formatting failed")?;
    }
    Ok(config)
}

pub fn server_config(bind: SocketAddr, name: &str, port: u16, token: &str, key: &str) -> Result<String, &'static str> {
    server_configs(bind, &[ServerMapping { name, port, token }], key)
}

pub fn client_config(remote: &str, name: &str, local: SocketAddr, token: &str, key: &str) -> Result<String, &'static str> {
    client_configs(remote, &[ClientMapping { name, local, token }], key)
}

/// Experimental UDP service over the existing Noise transport (not QUIC).
/// The relay UDP service and client destination remain loopback-only.
pub fn server_udp_config(bind: SocketAddr, name: &str, port: u16, token: &str, key: &str) -> Result<String, &'static str> {
    server_mixed_configs(bind, &[(MappingProtocol::Udp, ServerMapping { name, port, token })], key)
}

pub fn client_udp_config(remote: &str, name: &str, local: SocketAddr, token: &str, key: &str) -> Result<String, &'static str> {
    client_mixed_configs(remote, &[(MappingProtocol::Udp, ClientMapping { name, local, token })], key)
}

#[cfg(test)]
mod udp_tests {
    use super::*;
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn udp_explicit_and_tcp_unchanged() {
        let bind = "127.0.0.1:2333".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        let server = server_udp_config(bind, "udp-echo", 20800, TOKEN, KEY).unwrap();
        let client = client_udp_config("localhost:2333", "udp-echo", local, TOKEN, KEY).unwrap();
        assert_eq!(server, server_config(bind, "udp-echo", 20800, TOKEN, KEY).unwrap().replace("type = \"tcp\"", "type = \"udp\""));
        assert_eq!(client, client_config("localhost:2333", "udp-echo", local, TOKEN, KEY).unwrap().replace("type = \"tcp\"", "type = \"udp\""));
        assert!(server.contains("bind_addr = \"127.0.0.1:20800\""));
        assert!(client.contains("remote_public_key") && client.contains("type = \"noise\""));
    }

    #[test]
    fn udp_inherits_existing_security_validations() {
        let bind = "127.0.0.1:2333".parse().unwrap();
        assert!(server_udp_config(bind,"echo",0,TOKEN,KEY).is_err());
        assert!(server_udp_config(bind,"echo",2333,TOKEN,KEY).is_err());
        assert!(client_udp_config("localhost:2333","echo","0.0.0.0:8080".parse().unwrap(),TOKEN,KEY).is_err());
        assert!(client_udp_config("localhost:2333","echo","192.168.1.1:8080".parse().unwrap(),TOKEN,KEY).is_err());
        assert!(client_udp_config("localhost:2333","../bad","127.0.0.1:8080".parse().unwrap(),TOKEN,KEY).is_err());
        assert!(client_udp_config("localhost:2333","echo","127.0.0.1:8080".parse().unwrap(),"short",KEY).is_err());
        assert!(client_udp_config("localhost:2333","echo","127.0.0.1:8080".parse().unwrap(),TOKEN,"bad").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn server_mapping_is_loopback_only() {
        let config = server_config("0.0.0.0:2333".parse().unwrap(), "web", 20800, TOKEN, KEY).unwrap();
        assert!(config.contains("bind_addr = \"127.0.0.1:20800\""));
        assert!(config.contains("type = \"noise\""));
    }

    #[test]
    fn client_rejects_nonlocal_target_and_injection() {
        assert!(client_config("relay.example.com:2333", "web", "192.168.1.1:80".parse().unwrap(), TOKEN, KEY).is_err());
        assert!(client_config("relay.example.com:2333", "web]\n[evil", "127.0.0.1:80".parse().unwrap(), TOKEN, KEY).is_err());
        assert!(client_config("bad\"host:2333", "web", "127.0.0.1:80".parse().unwrap(), TOKEN, KEY).is_err());
    }

    #[test]
    fn rejects_weak_tokens_and_invalid_ports_or_keys() {
        let local = "127.0.0.1:8080".parse().unwrap();
        assert!(client_config("localhost:2333", "web", local, "short", KEY).is_err());
        assert!(client_config("localhost:0", "web", local, TOKEN, KEY).is_err());
        assert!(client_config("localhost:2333", "web", local, TOKEN, "bad").is_err());
        assert!(server_config("127.0.0.1:2333".parse().unwrap(), "web", 2333, TOKEN, KEY).is_err());
    }

    #[test]
    fn valid_client_uses_pinned_server_key() {
        let c = client_config("relay.example.com:2333", "web-1", "[::1]:8080".parse().unwrap(), TOKEN, KEY).unwrap();
        assert!(c.contains("remote_public_key"));
        assert!(c.contains("local_addr = \"[::1]:8080\""));
        assert!(!c.contains("local_private_key"));
    }
}

#[cfg(test)]
mod multi_tests {
    use super::*;
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn renders_independent_mappings() {
        let config = server_configs("127.0.0.1:2333".parse().unwrap(), &[
            ServerMapping { name: "web", port: 20800, token: A },
            ServerMapping { name: "api", port: 20801, token: B },
        ], KEY).unwrap();
        assert_eq!(config.matches("[server.transport]").count(), 1);
        assert!(config.contains("[server.services.web]"));
        assert!(config.contains("[server.services.api]"));
        assert!(config.contains("127.0.0.1:20801"));
        let client = client_configs("localhost:2333", &[
            ClientMapping { name: "web", local: "127.0.0.1:5173".parse().unwrap(), token: A },
            ClientMapping { name: "api", local: "127.0.0.1:8080".parse().unwrap(), token: B },
        ], KEY).unwrap();
        assert!(client.contains("[client.services.api]"));
        assert!(client.contains("127.0.0.1:5173"));
    }

    #[test]
    fn rejects_collisions_and_reused_credentials() {
        let bind = "127.0.0.1:2333".parse().unwrap();
        let first = || ServerMapping { name: "web", port: 20800, token: A };
        for second in [
            ServerMapping { name: "web", port: 20801, token: B },
            ServerMapping { name: "api", port: 20800, token: B },
            ServerMapping { name: "api", port: 20801, token: A },
            ServerMapping { name: "api", port: 2333, token: B },
        ] {
            assert!(server_configs(bind, &[first(), second], KEY).is_err());
        }
        assert!(server_configs(bind, &[], KEY).is_err());
    }
}

#[cfg(test)]
mod mixed_tests {
    use super::*;
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn mixed_protocols_and_global_collisions() {
        let bind = "127.0.0.1:2333".parse().unwrap();
        let first = || (MappingProtocol::Tcp, ServerMapping { name:"web", port:20800, token:A });
        let second = || (MappingProtocol::Udp, ServerMapping { name:"echo", port:20801, token:B });
        let c = server_mixed_configs(bind, &[first(),second()], KEY).unwrap();
        assert!(c.contains("[server.services.web]\ntype = \"tcp\""));
        assert!(c.contains("[server.services.echo]\ntype = \"udp\""));
        for m in [
            ServerMapping{name:"web",port:20801,token:B},
            ServerMapping{name:"echo",port:20800,token:B},
            ServerMapping{name:"echo",port:20801,token:A},
            ServerMapping{name:"echo",port:2333,token:B},
        ] {
            assert!(server_mixed_configs(bind,&[first(),(MappingProtocol::Udp,m)],KEY).is_err());
        }
        assert!(MappingProtocol::parse("quic").is_err());
        assert!(MappingProtocol::parse("UDP").is_err());
        let local="127.0.0.1:8080".parse().unwrap();
        let a=|| (MappingProtocol::Tcp,ClientMapping{name:"web",local,token:A});
        let b=|| (MappingProtocol::Udp,ClientMapping{name:"echo",local,token:B});
        let c=client_mixed_configs("localhost:2333",&[a(),b()],KEY).unwrap();
        assert!(c.contains("[client.services.web]\ntype = \"tcp\""));
        assert!(c.contains("[client.services.echo]\ntype = \"udp\""));
        assert!(client_mixed_configs("localhost:2333",&[a(),(MappingProtocol::Udp,ClientMapping{name:"echo",local,token:A})],KEY).is_err());
        assert!(client_mixed_configs("localhost:2333",&[a(),(MappingProtocol::Udp,ClientMapping{name:"web",local,token:B})],KEY).is_err());
        assert!(client_mixed_configs("localhost:2333",&[a(),(MappingProtocol::Udp,ClientMapping{name:"echo",local:"0.0.0.0:8080".parse().unwrap(),token:B})],KEY).is_err());
    }
}
