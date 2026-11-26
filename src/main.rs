use localtunnel::gateway::{gateway_config, Certificate, Route};
use localtunnel::{client_config, server_config, client_configs, server_configs, ClientMapping, ServerMapping};
use std::{env, fs::OpenOptions, io::Write, path::Path, process::{Command, ExitCode}};

fn env_required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("set {name} in the environment"))
}

fn write_new(path: &Path, config: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("cannot create configuration: {e}"))?;
    if let Err(e) = file.write_all(config.as_bytes()).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("cannot write configuration: {e}"));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, output, bind, name, port] if command == "server-config" => {
            let config = server_config(bind.parse().map_err(|_| "invalid bind address")?, name, port.parse().map_err(|_| "invalid mapping port")?, &env_required("LOCALTUNNEL_TOKEN")?, &env_required("LOCALTUNNEL_SERVER_PRIVATE_KEY")?)?;
            write_new(Path::new(output), &config)?;
        }
        [command, output, remote, name, local] if command == "client-config" => {
            let config = client_config(remote, name, local.parse().map_err(|_| "invalid local address")?, &env_required("LOCALTUNNEL_TOKEN")?, &env_required("LOCALTUNNEL_SERVER_PUBLIC_KEY")?)?;
            write_new(Path::new(output), &config)?;
        }
        [command, output, bind, name, port] if command == "server-udp-config" => {
            let config = localtunnel::server_udp_config(bind.parse().map_err(|_| "invalid bind address")?, name, port.parse().map_err(|_| "invalid mapping port")?, &env_required("LOCALTUNNEL_TOKEN")?, &env_required("LOCALTUNNEL_SERVER_PRIVATE_KEY")?)?;
            write_new(Path::new(output), &config)?;
        }
        [command, output, remote, name, local] if command == "client-udp-config" => {
            let config = localtunnel::client_udp_config(remote, name, local.parse().map_err(|_| "invalid local address")?, &env_required("LOCALTUNNEL_TOKEN")?, &env_required("LOCALTUNNEL_SERVER_PUBLIC_KEY")?)?;
            write_new(Path::new(output), &config)?;
        }
        [command, listen, relay] if command == "udp-guard" => {
            localtunnel::udp_guard::run(listen.parse().map_err(|_| "invalid UDP guard listener")?,
                relay.parse().map_err(|_| "invalid UDP guard relay")?)?;
        }
        [command, listen, relay, rate, burst] if command == "udp-guard-limited" => {
            let limits = localtunnel::udp_guard::ByteLimits::new(
                rate.parse().map_err(|_| "invalid UDP byte rate")?,
                burst.parse().map_err(|_| "invalid UDP byte burst")?)?;
            localtunnel::udp_guard::run_with_limits(listen.parse().map_err(|_| "invalid UDP guard listener")?,
                relay.parse().map_err(|_| "invalid UDP guard relay")?,Some(limits))?;
        }
        [command, output, endpoint, rest @ ..] if command == "server-mixed" || command == "client-mixed" => {
            use localtunnel::{MappingProtocol, server_mixed_configs, client_mixed_configs};
            if rest.is_empty() || rest.len() % 3 != 0 || rest.len() > 192 {
                return Err("provide 1-64 protocol/name/address triples".into());
            }
            let tokens = (1..=rest.len() / 3).map(|n| env_required(&format!("LOCALTUNNEL_TOKEN_{n}"))).collect::<Result<Vec<_>, _>>()?;
            let config = if command == "server-mixed" {
                let mappings = rest.chunks_exact(3).zip(&tokens).map(|(triple, token)| {
                    Ok((MappingProtocol::parse(&triple[0])?, ServerMapping { name: &triple[1], port: triple[2].parse().map_err(|_| "invalid mapping port")?, token }))
                }).collect::<Result<Vec<_>, &str>>()?;
                server_mixed_configs(endpoint.parse().map_err(|_| "invalid bind address")?, &mappings, &env_required("LOCALTUNNEL_SERVER_PRIVATE_KEY")?)?
            } else {
                let mappings = rest.chunks_exact(3).zip(&tokens).map(|(triple, token)| {
                    Ok((MappingProtocol::parse(&triple[0])?, ClientMapping { name: &triple[1], local: triple[2].parse().map_err(|_| "invalid local address")?, token }))
                }).collect::<Result<Vec<_>, &str>>()?;
                client_mixed_configs(endpoint, &mappings, &env_required("LOCALTUNNEL_SERVER_PUBLIC_KEY")?)?
            };
            write_new(Path::new(output), &config)?;
        }
        [command, output, endpoint, rest @ ..] if command == "server-multi" || command == "client-multi" => {
            if rest.is_empty() || rest.len() % 2 != 0 || rest.len() > 128 {
                return Err("provide 1-64 name/address pairs".into());
            }
            let tokens = (1..=rest.len() / 2).map(|n| env_required(&format!("LOCALTUNNEL_TOKEN_{n}"))).collect::<Result<Vec<_>, _>>()?;
            let config = if command == "server-multi" {
                let mappings = rest.chunks_exact(2).zip(&tokens).map(|(pair, token)| {
                    Ok(ServerMapping { name: &pair[0], port: pair[1].parse().map_err(|_| "invalid mapping port")?, token })
                }).collect::<Result<Vec<_>, &str>>()?;
                server_configs(endpoint.parse().map_err(|_| "invalid bind address")?, &mappings, &env_required("LOCALTUNNEL_SERVER_PRIVATE_KEY")?)?
            } else {
                let mappings = rest.chunks_exact(2).zip(&tokens).map(|(pair, token)| {
                    Ok(ClientMapping { name: &pair[0], local: pair[1].parse().map_err(|_| "invalid local address")?, token })
                }).collect::<Result<Vec<_>, &str>>()?;
                client_configs(endpoint, &mappings, &env_required("LOCALTUNNEL_SERVER_PUBLIC_KEY")?)?
            };
            write_new(Path::new(output), &config)?;
        }
        [command, output, bind, rest @ ..] if command == "gateway-http" || command == "gateway-https" => {
            let (cert, pairs) = if command == "gateway-https" {
                match rest {
                    [chain, key, pairs @ ..] => (Some(Certificate { chain, key }), pairs),
                    _ => return Err("gateway-https requires certificate and key paths".into()),
                }
            } else { (None, rest) };
            if pairs.is_empty() || pairs.len() % 2 != 0 || pairs.len() > 128 {
                return Err("provide 1-64 domain/port pairs".into());
            }
            let routes = pairs.chunks_exact(2).map(|p| {
                Ok(Route { domain: &p[0], port: p[1].parse().map_err(|_| "invalid upstream port")? })
            }).collect::<Result<Vec<_>, &str>>()?;
            let config = gateway_config(bind.parse().map_err(|_| "invalid gateway listener")?, &routes, cert)?;
            write_new(Path::new(output), &config)?;
        }
        #[cfg(target_os = "linux")]
        [command, prefix, bind, pairs @ ..] if command == "gateway-init" || command == "gateway-apply" => {
            if pairs.len() % 2 != 0 || pairs.len() > 128 {
                return Err("provide 0-64 domain/port pairs".into());
            }
            let routes = pairs.chunks_exact(2).map(|p| {
                Ok(Route { domain: &p[0], port: p[1].parse().map_err(|_| "invalid upstream port")? })
            }).collect::<Result<Vec<_>, &str>>()?;
            let address = bind.parse().map_err(|_| "invalid gateway listener")?;
            if command == "gateway-init" {
                localtunnel::managed_gateway::init(Path::new(prefix), address, &routes)?;
            } else {
                localtunnel::managed_gateway::apply(Path::new(prefix), address, &routes)?;
            }
        }
        #[cfg(target_os = "linux")]
        [command, prefix, bind, domain, port, expected_file] if command == "gateway-apply-checked" => {
            use std::io::Read;
            let mut expected=Vec::new();
            let metadata=std::fs::symlink_metadata(expected_file).map_err(|_|"expected body file unavailable")?;
            if !metadata.file_type().is_file() || !(1..=65536).contains(&metadata.len()) {
                return Err("invalid expected body file".into());
            }
            std::fs::File::open(expected_file).map_err(|_|"expected body file unavailable")?
                .take(65537).read_to_end(&mut expected).map_err(|_|"expected body read failed")?;
            let route=Route{domain,port:port.parse().map_err(|_|"invalid upstream port")?};
            localtunnel::managed_gateway::apply_checked_http(Path::new(prefix),bind.parse().map_err(|_|"invalid gateway listener")?,route,&expected)?;
        }
        #[cfg(target_os = "linux")]
        [command, prefix, bind, probe, chain, key, ca, days, domain, port, expected_file] if command == "gateway-tls-apply-checked" => {
            use std::io::Read;
            let mut expected=Vec::new();
            let metadata=std::fs::symlink_metadata(expected_file).map_err(|_|"expected body file unavailable")?;
            if !metadata.file_type().is_file() || !(1..=65536).contains(&metadata.len()) {
                return Err("invalid expected body file".into());
            }
            std::fs::File::open(expected_file).map_err(|_|"expected body file unavailable")?
                .take(65537).read_to_end(&mut expected).map_err(|_|"expected body read failed")?;
            let tls=localtunnel::managed_gateway::TlsSettings {
                probe:probe.parse().map_err(|_|"invalid revision probe listener")?,chain,key,ca,
                minimum_days:days.parse().map_err(|_|"invalid minimum validity days")?,
            };
            let route=Route{domain,port:port.parse().map_err(|_|"invalid upstream port")?};
            localtunnel::managed_gateway::apply_checked_tls(Path::new(prefix),bind.parse().map_err(|_|"invalid gateway listener")?,route,&tls,&expected)?;
        }
        #[cfg(target_os = "linux")]
        [command, prefix, bind, probe, chain, key, ca, days, pairs @ ..]
            if command == "gateway-tls-init" || command == "gateway-tls-apply" => {
            if pairs.len() % 2 != 0 || pairs.len() > 128 {
                return Err("provide 0-64 domain/port pairs".into());
            }
            let routes = pairs.chunks_exact(2).map(|p| {
                Ok(Route { domain: &p[0], port: p[1].parse().map_err(|_| "invalid upstream port")? })
            }).collect::<Result<Vec<_>, &str>>()?;
            let address = bind.parse().map_err(|_| "invalid gateway listener")?;
            let tls = localtunnel::managed_gateway::TlsSettings {
                probe: probe.parse().map_err(|_| "invalid revision probe listener")?,
                chain, key, ca, minimum_days: days.parse().map_err(|_| "invalid minimum validity days")?,
            };
            if command == "gateway-tls-init" {
                localtunnel::managed_gateway::init_tls(Path::new(prefix), address, &routes, &tls)?;
            } else {
                localtunnel::managed_gateway::apply_tls(Path::new(prefix), address, &routes, &tls)?;
            }
        }
        #[cfg(target_os = "linux")]
        [command, chain, key, ca, days, domains @ ..] if command == "cert-check" => {
            let days = days.parse().map_err(|_| "invalid minimum validity days")?;
            localtunnel::certificates::check(chain, key, ca, days, domains)?;
            println!("certificate preflight passed");
        }
        #[cfg(unix)]
        [command, root] if command == "agent-store-init" => {
            localtunnel::unix_agent_store::init(Path::new(root))?;
        }
        #[cfg(unix)]
        [command, root, remote, name, local] if command == "agent-config-create" => {
            localtunnel::unix_agent_store::create(Path::new(root), remote, name,
                local.parse().map_err(|_| "invalid local address")?, std::io::stdin().lock())?;
        }
        #[cfg(unix)]
        [command, root, remote, name, local] if command == "agent-config-create-udp" => {
            localtunnel::unix_agent_store::create_udp(Path::new(root), remote, name,
                local.parse().map_err(|_| "invalid local address")?, std::io::stdin().lock())?;
        }
        #[cfg(unix)]
        [command, root] if command == "agent-config-check" => {
            localtunnel::unix_agent_store::checked_config(Path::new(root))?;
            println!("private agent configuration verified");
        }
        #[cfg(unix)]
        [command, root, source] if command == "agent-engine-install" => {
            localtunnel::unix_agent_process::install(Path::new(root), Path::new(source))?;
        }
        #[cfg(unix)]
        [command, root] if command == "agent-run" => {
            localtunnel::unix_agent_process::run(Path::new(root))?;
        }
        #[cfg(any(target_os="linux",target_os="macos"))]
        [command, root, id] if command == "agent-service-generate" => {
            localtunnel::unix_agent_service::generate(Path::new(root), id)?;
        }
        [command, config] if command == "run" => {
            let binary = env::var_os("LOCALTUNNEL_ENGINE").ok_or("set LOCALTUNNEL_ENGINE to the absolute path of the verified rathole executable")?;
            if !Path::new(&binary).is_absolute() { return Err("engine path must be absolute".into()); }
            let mut child = Command::new(binary);
            child.arg(config).env_remove("LOCALTUNNEL_TOKEN").env_remove("LOCALTUNNEL_SERVER_PRIVATE_KEY").env_remove("LOCALTUNNEL_SERVER_PUBLIC_KEY");
            for n in 1..=64 { child.env_remove(format!("LOCALTUNNEL_TOKEN_{n}")); }
            let status = child.status().map_err(|e| format!("engine launch failed: {e}"))?;
            if !status.success() { return Err(format!("engine exited: {status}")); }
        }
        [command] if command == "--version" => println!("localtunnel {}", env!("CARGO_PKG_VERSION")),
        _ => return Err("usage: localtunnel server-config <new-file> <bind-IP:port> <name> <mapping-port> | client-config <new-file> <server:port> <name> <loopback-IP:port> | server-udp-config <new-file> <bind-IP:port> <name> <mapping-port> | client-udp-config <new-file> <server:port> <name> <loopback-IP:port> | udp-guard <127.0.0.1:listen-port> <127.0.0.1:relay-port> | udp-guard-limited <127.0.0.1:listen-port> <127.0.0.1:relay-port> <bytes-per-second> <burst-bytes> | server-mixed <new-file> <bind-IP:port> <tcp|udp> <name> <port> [...] | client-mixed <new-file> <server:port> <tcp|udp> <name> <loopback-IP:port> [...] | server-multi <new-file> <bind-IP:port> <name> <mapping-port> [...] | client-multi <new-file> <server:port> <name> <loopback-IP:port> [...] | gateway-http <new-file> <bind-IP:port> <domain> <upstream-port> [...] | gateway-https <new-file> <bind-IP:port> <cert-path> <key-path> <domain> <upstream-port> [...] | gateway-init/gateway-apply <dedicated-prefix> <loopback-IP:port> [<domain> <relay-port> ...] (Linux) | gateway-apply-checked <prefix> <bind> <domain> <relay-port> <expected-body-file> (Linux) | gateway-tls-init/gateway-tls-apply <prefix> <bind> <probe> <chain> <key> <CA> <minimum-days> <domain> <relay-port> [...] (Linux) | gateway-tls-apply-checked <prefix> <bind> <probe> <chain> <key> <CA> <minimum-days> <domain> <relay-port> <expected-body-file> (Linux) | cert-check <chain> <key> <CA> <minimum-days> <domain> [...] (Linux) | agent-store-init <new-absolute-dir> | agent-config-create <dir> <server:port> <name> <loopback-IP:port> (Unix; stdin token and public key) | agent-config-create-udp <dir> <server:port> <name> <loopback-IP:port> (Unix; stdin token and public key) | agent-config-check <dir> (Unix) | agent-engine-install <dir> <absolute-engine> (Unix) | agent-run <dir> (Unix foreground) | agent-service-generate <dir> <32hex-id> (Linux/macOS user service) | run <config-file> | --version".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("localtunnel: {error}"); ExitCode::FAILURE }
    }
}
