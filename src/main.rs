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
        _ => return Err("usage: localtunnel server-config <new-file> <bind-IP:port> <name> <mapping-port> | client-config <new-file> <server:port> <name> <loopback-IP:port> | server-multi <new-file> <bind-IP:port> <name> <mapping-port> [...] | client-multi <new-file> <server:port> <name> <loopback-IP:port> [...] | run <config-file> | --version".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("localtunnel: {error}"); ExitCode::FAILURE }
    }
}
