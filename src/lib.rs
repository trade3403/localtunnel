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

pub fn server_config(bind: SocketAddr, name: &str, port: u16, token: &str, key: &str) -> Result<String, &'static str> {
    validate_name(name)?;
    validate_token(token)?;
    validate_key(key)?;
    port_valid(bind.port())?;
    port_valid(port)?;
    if bind.port() == port { return Err("tunnel port and mapping port must differ"); }
    Ok(format!("[server]\nbind_addr = \"{bind}\"\nheartbeat_interval = 5\n\n[server.transport]\ntype = \"noise\"\n\n[server.transport.noise]\npattern = \"{PATTERN}\"\nlocal_private_key = \"{key}\"\n\n[server.services.{name}]\ntype = \"tcp\"\ntoken = \"{token}\"\nbind_addr = \"127.0.0.1:{port}\"\n"))
}

pub fn client_config(remote: &str, name: &str, local: SocketAddr, token: &str, key: &str) -> Result<String, &'static str> {
    validate_name(name)?;
    validate_token(token)?;
    validate_key(key)?;
    remote_valid(remote)?;
    port_valid(local.port())?;
    if !local.ip().is_loopback() { return Err("local target must be loopback in V0.1"); }
    Ok(format!("[client]\nremote_addr = \"{remote}\"\nheartbeat_timeout = 15\nretry_interval = 1\n\n[client.transport]\ntype = \"noise\"\n\n[client.transport.noise]\npattern = \"{PATTERN}\"\nremote_public_key = \"{key}\"\n\n[client.services.{name}]\ntype = \"tcp\"\ntoken = \"{token}\"\nlocal_addr = \"{local}\"\n"))
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
