#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use localtunnel::{client_configs, ClientMapping};
use serde::{Deserialize, Serialize};
use std::{io::Write, net::SocketAddr, path::Path, process::{Child, Command, Stdio}, sync::Mutex};
use tempfile::TempDir;
use tauri::Manager;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mapping {
    name: String,
    local_port: u16,
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartRequest {
    engine: String,
    remote: String,
    server_key: String,
    mappings: Vec<Mapping>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    state: &'static str,
    detail: String,
    mapping_count: usize,
}

struct Running {
    child: Child,
    _directory: TempDir,
    count: usize,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct Supervisor {
    running: Option<Running>,
    last_error: Option<String>,
}

impl Supervisor {
    fn status(&mut self) -> Result<Status, String> {
        if let Some(running) = &mut self.running {
            if let Some(code) = running.child.try_wait().map_err(|_| "无法读取引擎进程状态")? {
                self.last_error = Some(format!("引擎已退出：{code}"));
                self.running.take();
            } else {
                return Ok(Status { state: "running", detail: "隧道进程运行中；公网连通性尚未验证".into(), mapping_count: running.count });
            }
        }
        Ok(Status { state: if self.last_error.is_some() { "error" } else { "stopped" },
            detail: self.last_error.clone().unwrap_or_else(|| "隧道已停止".into()), mapping_count: 0 })
    }

    fn start(&mut self, request: StartRequest) -> Result<Status, String> {
        self.status()?;
        if self.running.is_some() { return Err("请先停止现有隧道".into()); }
        let engine = Path::new(&request.engine);
        if !engine.is_absolute() || !engine.is_file() {
            return Err("请选择已验证的 Rathole 可执行文件绝对路径".into());
        }
        #[cfg(windows)]
        if !engine.extension().is_some_and(|s| s.eq_ignore_ascii_case("exe")) {
            return Err("Windows 引擎必须为 EXE 文件".into());
        }
        let config = build_config(&request)?;
        let directory = tempfile::Builder::new().prefix("localtunnel-client-").tempdir()
            .map_err(|_| "无法创建临时配置目录")?;
        let config_path = directory.path().join("client.toml");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&config_path).map_err(|_| "无法创建临时配置")?;
        file.write_all(config.as_bytes()).and_then(|_| file.sync_all()).map_err(|_| "无法写入配置")?;
        drop(file);
        let mut command = Command::new(engine);
        command.arg(&config_path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        command.env_remove("LOCALTUNNEL_TOKEN").env_remove("LOCALTUNNEL_SERVER_PRIVATE_KEY").env_remove("LOCALTUNNEL_SERVER_PUBLIC_KEY");
        for i in 1..=64 { command.env_remove(format!("LOCALTUNNEL_TOKEN_{i}")); }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let child = command.spawn().map_err(|_| "无法启动 Rathole 引擎")?;
        self.running = Some(Running { child, _directory: directory, count: request.mappings.len() });
        self.last_error = None;
        self.status()
    }

    fn stop(&mut self) -> Result<Status, String> {
        if let Some(running) = &mut self.running {
            if running.child.try_wait().map_err(|_| "无法读取进程状态")?.is_none() {
                running.child.kill().map_err(|_| "无法停止隧道引擎")?;
            }
            running.child.wait().map_err(|_| "无法等待隧道退出")?;
        }
        self.running.take();
        self.last_error = None;
        self.status()
    }
}

fn build_config(request: &StartRequest) -> Result<String, String> {
    let mappings = request.mappings.iter().map(|m| ClientMapping {
        name: &m.name,
        local: SocketAddr::from(([127, 0, 0, 1], m.local_port)),
        token: &m.token,
    }).collect::<Vec<_>>();
    client_configs(&request.remote, &mappings, &request.server_key).map_err(str::to_owned)
}

#[tauri::command]
fn start_tunnel(request: StartRequest, supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.start(request)
}

#[tauri::command]
fn stop_tunnel(supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.stop()
}

#[tauri::command]
fn tunnel_status(supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.status()
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(Supervisor::default()))
        .invoke_handler(tauri::generate_handler![start_tunnel, stop_tunnel, tunnel_status])
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    let state = window.state::<Mutex<Supervisor>>();
                    let stopped = state.lock().ok().is_some_and(|mut supervisor| supervisor.stop().is_ok());
                    if !stopped { api.prevent_close(); }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("LocalTunnel desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> StartRequest {
        StartRequest { engine: String::new(), remote: "relay.example.test:2333".into(),
            server_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            mappings: vec![Mapping { name: "web".into(), local_port: 5173, token: "a".repeat(32) }] }
    }

    #[test]
    fn desktop_builds_core_encrypted_config() {
        let text = build_config(&request()).unwrap();
        assert!(text.contains("local_addr = \"127.0.0.1:5173\""));
        assert!(text.contains("remote_public_key"));
        assert!(text.contains("type = \"noise\""));
    }

    #[test]
    fn desktop_rejects_invalid_mapping() {
        let mut req = request();
        req.mappings[0].local_port = 0;
        assert!(build_config(&req).is_err());
        req.mappings[0].local_port = 8080;
        req.mappings[0].token = "short".into();
        assert!(build_config(&req).is_err());
    }

    #[test]
    #[ignore = "requires real Rathole executable; run explicitly in hosted CI"]
    fn real_engine_supervisor_lifecycle() {
        use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread, time::{Duration, Instant}};
        use localtunnel::server_config;
        let engine = std::env::var("LOCALTUNNEL_TEST_ENGINE").expect("test engine required");
        let output = Command::new(&engine).arg("--genkey").output().unwrap();
        assert!(output.status.success());
        let keys = String::from_utf8(output.stdout).unwrap();
        let private = keys.lines().find_map(|s| s.trim().strip_prefix("Private Key:").map(str::trim)).unwrap();
        let public = keys.lines().find_map(|s| s.trim().strip_prefix("Public Key:").map(str::trim)).unwrap();
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_port = local.local_addr().unwrap().port();
        local.set_nonblocking(true).unwrap();
        let relay_port = TcpListener::bind("127.0.0.1:0").unwrap();
        let mapped_port = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_port.local_addr().unwrap();
        let mapped_addr = mapped_port.local_addr().unwrap();
        let fixture = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if let Ok((mut connection, _)) = local.accept() {
                    connection.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut buffer = [0u8; 4];
                    if connection.read_exact(&mut buffer).is_ok() && &buffer == b"ping" {
                        connection.write_all(b"pong").unwrap();
                        return;
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
            panic!("fixture did not receive tunneled data");
        });
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("server.toml");
        // Ephemeral loopback-only CI token, never a production credential.
        let token = format!("{:032x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        std::fs::write(&config, server_config(relay_addr, "web", mapped_addr.port(), &token, private).unwrap()).unwrap();
        drop(relay_port);
        drop(mapped_port);
        let child = Command::new(&engine).arg(&config).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let _relay = Running { child, _directory: directory, count: 1 };
        let mut supervisor = Supervisor::default();
        assert_eq!(supervisor.start(StartRequest { engine, remote: relay_addr.to_string(), server_key: public.into(),
            mappings: vec![Mapping { name: "web".into(), local_port, token }] }).unwrap().state, "running");
        let until = Instant::now() + Duration::from_secs(25);
        let mut forwarded = false;
        while Instant::now() < until {
            if let Ok(mut stream) = TcpStream::connect_timeout(&mapped_addr, Duration::from_millis(500)) {
                stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut response = [0u8; 4];
                if stream.write_all(b"ping").is_ok() && stream.read_exact(&mut response).is_ok() && &response == b"pong" {
                    forwarded = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        assert!(forwarded, "desktop supervisor failed to forward real bytes");
        fixture.join().unwrap();
        assert_eq!(supervisor.stop().unwrap().state, "stopped");
        assert!(supervisor.running.is_none());
    }

    #[test]
    fn stopped_state_and_missing_engine() {
        let mut supervisor = Supervisor::default();
        assert_eq!(supervisor.status().unwrap().state, "stopped");
        assert!(supervisor.start(request()).is_err());
        assert_eq!(supervisor.stop().unwrap().state, "stopped");
    }
}
