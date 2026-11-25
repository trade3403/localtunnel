#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod profile;
mod credentials;
mod engine_integrity;
mod transport;
mod traffic;
mod history;
#[cfg(windows)]
mod engine_job;
#[cfg(windows)]
mod service_host;
#[cfg(windows)]
mod service_acl;
#[cfg(windows)]
mod service_control;

use localtunnel::{client_configs, ClientMapping};
use serde::{Deserialize, Serialize};
use std::{io::Write, net::SocketAddr, path::Path, process::{Child, Command, Stdio}, sync::Mutex};
use tempfile::TempDir;
use tauri::Manager;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Mapping {
    name: String,
    local_port: u16,
    token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[cfg(windows)]
    _job: engine_job::EngineJob,
    // Close telemetry before TempDir removes its files.
    #[cfg(windows)]
    telemetry: Option<std::fs::File>,
    _directory: TempDir,
    count: usize,
    relay_target: Option<transport::Target>,
    meter: Option<traffic::Meter>,
}

impl Running {
    fn spawn(command: &mut Command, directory: TempDir, count: usize) -> Result<Self, String> {
        #[cfg(windows)]
        let job = engine_job::EngineJob::new().map_err(|e| format!("无法创建引擎进程保护：{e}"))?;
        let mut child = command.spawn().map_err(|_| "无法启动 Rathole 引擎")?;
        #[cfg(windows)]
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("无法保护引擎进程，已拒绝启动：{error}"));
        }
        Ok(Self {
            child,
            #[cfg(windows)]
            _job: job,
            #[cfg(windows)]
            telemetry: None,
            _directory: directory,
            count,
            relay_target: None,
            meter: None,
        })
    }
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
        self.start_in(request, None)
    }

    fn start_in(&mut self, request: StartRequest, runtime_root: Option<&Path>) -> Result<Status, String> {
        self.start_in_with_history(request, runtime_root, None)
    }

    fn start_in_with_history(&mut self, request: StartRequest, runtime_root: Option<&Path>, history_dir: Option<&Path>) -> Result<Status, String> {
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
        // Validate original configuration before allocating any listeners.
        build_config(&request)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("localtunnel-client-");
        let directory = match runtime_root {
            Some(root) => builder.tempdir_in(root),
            None => builder.tempdir(),
        }.map_err(|_| "无法创建临时配置目录")?;
        let staged_engine = engine_integrity::stage(engine, directory.path())?;
        let relay_port = request.remote.rsplit_once(':').and_then(|(_,p)| p.parse::<u16>().ok())
            .ok_or("invalid relay port")?;
        let meter = traffic::Meter::start_with_history(&request.mappings.iter().map(|m| m.local_port).collect::<Vec<_>>(), relay_port, history_dir)?;
        let mappings = request.mappings.iter().zip(meter.ports()).map(|(m, &port)| ClientMapping {
            name: &m.name, local: SocketAddr::from(([127,0,0,1],port)), token: &m.token,
        }).collect::<Vec<_>>();
        let config = client_configs(&request.remote, &mappings, &request.server_key).map_err(str::to_owned)?;
        let target_ports = meter.ports().to_vec();
        #[cfg(windows)]
        let telemetry = if runtime_root.is_some() {
            Some(std::fs::OpenOptions::new().write(true).create_new(true)
                .open(directory.path().join("traffic.json")).map_err(|_| "service telemetry file unavailable")?)
        } else { None };
        let relay_target = transport::Target::new(&request.remote, target_ports)?;
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
        let mut command = Command::new(&staged_engine);
        command.current_dir(directory.path()).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        command.env_remove("LOCALTUNNEL_TOKEN").env_remove("LOCALTUNNEL_SERVER_PRIVATE_KEY").env_remove("LOCALTUNNEL_SERVER_PUBLIC_KEY");
        for i in 1..=64 { command.env_remove(format!("LOCALTUNNEL_TOKEN_{i}")); }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut running = Running::spawn(&mut command, directory, request.mappings.len())?;
        running.relay_target = Some(relay_target);
        running.meter = Some(meter);
        #[cfg(windows)]
        { running.telemetry = telemetry; }
        self.running = Some(running);
        self.last_error = None;
        self.status()
    }

    fn transport_status(&mut self) -> Result<transport::Observation, String> {
        if self.status()?.state != "running" {
            return Ok(transport::Observation::inactive());
        }
        let running = self.running.as_ref().ok_or("engine unavailable")?;
        let Some(target) = &running.relay_target else { return Ok(transport::Observation::unknown()); };
        Ok(transport::observe(running.child.id(), target))
    }

    fn traffic_status(&mut self) -> Result<traffic::Snapshot, String> {
        if self.status()?.state != "running" { return Ok(traffic::Snapshot::inactive()); }
        Ok(self.running.as_mut().and_then(|r| r.meter.as_mut())
            .map(|m| m.snapshot()).unwrap_or_else(traffic::Snapshot::inactive))
    }

    #[cfg(windows)]
    fn publish_service_traffic(&mut self) -> Result<(), String> {
        use std::io::{Seek, SeekFrom};
        let running = self.running.as_mut().ok_or("engine unavailable")?;
        let meter = running.meter.as_mut().ok_or("meter unavailable")?;
        let file = running.telemetry.as_mut().ok_or("telemetry unavailable")?;
        let sample = traffic::ServiceSample::from_snapshot(meter.snapshot(), running.child.id())
            .ok_or("sample unavailable")?;
        let bytes = serde_json::to_vec(&sample).map_err(|_| "sample serialization failed")?;
        // Fixed file and bounded record; no extra temp files to survive a
        // host crash. Reader rejects partial or stale records.
        file.seek(SeekFrom::Start(0)).and_then(|_| file.set_len(0))
            .and_then(|_| file.write_all(&bytes)).map_err(|_| "sample write failed".to_owned())
    }

    fn stop(&mut self) -> Result<Status, String> {
        if let Some(running) = &mut self.running {
            if running.child.try_wait().map_err(|_| "无法读取进程状态")?.is_none() {
                running.child.kill().map_err(|_| "无法停止隧道引擎")?;
            }
            running.child.wait().map_err(|_| "无法等待隧道退出")?;
        }
        let mut history_failure = false;
        if let Some(mut running) = self.running.take() {
            if let Some(mut meter) = running.meter.take() {
                history_failure = meter.finish().is_err();
            }
            // Report cleanup failures rather than silently discarding a plaintext config.
            let config_path = running._directory.path().join("client.toml");
            if let Err(error) = std::fs::remove_file(&config_path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.last_error = Some("引擎已停止，但临时凭据文件清理失败".into());
                    drop(running);
                    return Err(self.last_error.clone().unwrap());
                }
            }
            drop(running);
        }
        if history_failure {
            self.last_error = Some("隧道已停止，但历史流量保存失败".into());
            return Err(self.last_error.clone().unwrap());
        }
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

fn bundled_engine(resource_dir: &Path) -> Result<std::path::PathBuf, String> {
    let path = resource_dir.join("engine").join("rathole.exe");
    if !path.is_absolute() || !path.is_file() {
        return Err("内置 Rathole 引擎缺失，请重新安装客户端".into());
    }
    Ok(path)
}

#[tauri::command]
fn start_tunnel(app: tauri::AppHandle, mut request: StartRequest, supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    // Empty means the packaged resource, resolved by Rust, not a frontend path.
    if request.engine.is_empty() {
        let resource = app.path().resource_dir().map_err(|_| "无法定位应用资源目录")?;
        request.engine = bundled_engine(&resource)?.to_str().ok_or("引擎路径编码无效")?.to_owned();
    }
    let history_dir = app.path().app_config_dir().map_err(|_| "无法定位用户统计目录")?;
    supervisor.lock().map_err(|_| "进程状态不可用")?.start_in_with_history(request, None, Some(&history_dir))
}

#[tauri::command]
fn stop_tunnel(supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.stop()
}

#[tauri::command]
fn tunnel_status(supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<Status, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.status()
}

#[tauri::command]
async fn transport_status(app: tauri::AppHandle) -> Result<transport::Observation, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let supervisor = app.state::<Mutex<Supervisor>>();
        let result = supervisor.lock().map_err(|_| "进程状态不可用")?.transport_status();
        result
    }).await.map_err(|_| "TCP 状态读取失败")?
}

#[tauri::command]
fn traffic_status(supervisor: tauri::State<'_, Mutex<Supervisor>>) -> Result<traffic::Snapshot, String> {
    supervisor.lock().map_err(|_| "进程状态不可用")?.traffic_status()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryStatus {
    saved: Option<history::Totals>,
    write_failed: bool,
}

#[tauri::command]
async fn traffic_history(app: tauri::AppHandle) -> Result<HistoryStatus, String> {
    let dir = app.path().app_config_dir().map_err(|_| "无法定位用户统计目录")?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<Mutex<Supervisor>>();
        let write_failed = state.lock().map_err(|_| "进程状态不可用")?.running.as_ref()
            .and_then(|r| r.meter.as_ref()).is_some_and(|m| m.history_failed());
        Ok(HistoryStatus { saved: history::read(&dir)?, write_failed })
    }).await.map_err(|_| "历史流量读取失败")?
}

#[cfg(windows)]
#[tauri::command]
async fn manage_service(name: String, action: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        // Only one desktop mutation per process; Windows SCM remains
        // authoritative for cross-process state transitions.
        static ACTION: Mutex<()> = Mutex::new(());
        let _guard = ACTION.try_lock().map_err(|_| "another service action is running")?;
        service_control::manage_existing(&name, &action)
    }).await.map_err(|_| "service action failed")?
}

#[cfg(not(windows))]
#[tauri::command]
async fn manage_service(name: String, action: String) -> Result<(), String> {
    let _ = (name, action);
    Err("Windows SCM unavailable".into())
}

#[cfg(windows)]
#[tauri::command]
async fn service_status(name: String) -> Result<service_control::ServiceSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || service_control::snapshot(&name))
        .await.map_err(|_| "service query failed")?
}

#[cfg(not(windows))]
#[tauri::command]
async fn service_status(_name: String) -> Result<serde_json::Value, String> {
    Err("Windows SCM unavailable".into())
}

#[tauri::command]
fn save_profile(app: tauri::AppHandle, profile: profile::Profile) -> Result<(), String> {
    let path = app.path().app_config_dir().map_err(|_| "无法定位用户配置目录")?;
    profile::save(&path, &profile)
}

#[tauri::command]
fn load_profile(app: tauri::AppHandle) -> Result<Option<profile::Profile>, String> {
    let path = app.path().app_config_dir().map_err(|_| "无法定位用户配置目录")?;
    profile::load(&path)
}

#[tauri::command]
fn save_protected_profile(app: tauri::AppHandle, request: StartRequest) -> Result<(), String> {
    let path = app.path().app_config_dir().map_err(|_| "无法定位用户配置目录")?;
    credentials::save(&path, &request)
}

#[tauri::command]
fn load_protected_profile(app: tauri::AppHandle) -> Result<Option<StartRequest>, String> {
    let path = app.path().app_config_dir().map_err(|_| "无法定位用户配置目录")?;
    credentials::load(&path)
}

#[tauri::command]
fn forget_protected_profile(app: tauri::AppHandle) -> Result<(), String> {
    let path = app.path().app_config_dir().map_err(|_| "无法定位用户配置目录")?;
    credentials::forget(&path)
}

fn local_port_open(port: u16) -> Result<bool, String> {
    if port == 0 { return Err("端口必须在 1–65535".into()); }
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    Ok(std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok())
}

#[tauri::command]
async fn check_local_port(port: u16) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || local_port_open(port)).await
        .map_err(|_| "本地端口检测失败")?
}

fn main() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).is_some_and(|arg| arg == "--service-status") {
            let result = if args.len() == 3 {
                service_control::snapshot(&args[2]).and_then(|s|
                    serde_json::to_writer(std::io::stdout().lock(), &s).map_err(|_| "status output failed".into()))
            } else { Err("invalid service status arguments".into()) };
            if let Err(error) = &result {
                let _ = writeln!(std::io::stderr(), "service status failed: {error}");
            }
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        if args.get(1).is_some_and(|arg| arg == "--service-manage") {
            // Exercise the same allowlisted native function as the desktop IPC.
            let result = if args.len() == 4 {
                service_control::manage_existing(&args[2], &args[3])
            } else { Err("invalid desktop service arguments".into()) };
            if let Err(error) = &result {
                let _ = writeln!(std::io::stderr(), "desktop service action failed: {error}");
            }
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        if args.get(1).is_some_and(|arg| arg == "--service-control") {
            let result = if args.len() == 4 {
                service_control::execute(&args[2], &args[3])
            } else { Err("invalid service control arguments".into()) };
            if let Err(error) = &result {
                // Only static diagnostics and SCM errors; never print credentials.
                let _ = writeln!(std::io::stderr(), "service control failed: {error}");
            }
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
        if args.get(1).is_some_and(|arg| arg == "--service-seal-profile") {
            let ok = args.len() == 3 && service_host::seal_profile_from_stdin(&args[2]).is_ok();
            std::process::exit(if ok { 0 } else { 1 });
        }
        if args.get(1).is_some_and(|arg| arg == "--service-host" || arg == "--service-tunnel") {
            // Explicit SCM-only entry; ordinary desktop startup never registers a service.
            let ok = args.len() == 3 && service_host::dispatch(&args[2], args[1] == "--service-tunnel").is_ok();
            std::process::exit(if ok { 0 } else { 1 });
        }
    }
    use tauri::{menu::{Menu, MenuItem}, tray::TrayIconBuilder};
    tauri::Builder::default()
        .manage(Mutex::new(Supervisor::default()))
        .invoke_handler(tauri::generate_handler![start_tunnel, stop_tunnel, tunnel_status, transport_status, traffic_status, traffic_history, service_status, manage_service, save_profile, load_profile, save_protected_profile, load_protected_profile, forget_protected_profile, check_local_port])
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", "停止隧道", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出 LocalTunnel", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &stop, &quit])?;
            let icon = app.default_window_icon().cloned().ok_or("应用图标缺失")?;
            TrayIconBuilder::with_id("localtunnel")
                .icon(icon)
                .tooltip("LocalTunnel · 内网穿透")
                .menu(&menu)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "stop" | "quit" => {
                            let state = app.state::<Mutex<Supervisor>>();
                            let stopped = state.lock().ok().is_some_and(|mut supervisor| supervisor.stop().is_ok());
                            if stopped && event.id.as_ref() == "quit" {
                                app.exit(0);
                            } else if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        _ => {}
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    // Only hide if the tray exists; the explicit tray quit stops the engine.
                    if window.app_handle().tray_by_id("localtunnel").is_some() && window.hide().is_ok() {
                        api.prevent_close();
                    } else {
                        let state = window.state::<Mutex<Supervisor>>();
                        let stopped = state.lock().ok().is_some_and(|mut supervisor| supervisor.stop().is_ok());
                        if !stopped { api.prevent_close(); }
                    }
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

    // Match the same bounded Base64 token extraction as the verified Python E2E.
    fn generated_key<'a>(output: &'a str, label: &str) -> Option<&'a str> {
        let (_, tail) = output.split_once(label)?;
        let tail = tail.trim_start();
        let n = tail.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')).count();
        let key = &tail[..n];
        (key.len() == 44 && key.ends_with('=')).then_some(key)
    }

    #[test]
    fn key_parser_ignores_trailing_output_without_weakening_key_validation() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let output = format!("Private Key: {key} \x1b[0m\r\nPublic Key: {key} (keep safe)\r\n");
        assert_eq!(generated_key(&output, "Private Key:"), Some(key));
        assert_eq!(generated_key(&output, "Public Key:"), Some(key));
        assert!(generated_key("Private Key: invalid", "Private Key:").is_none());
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
        let private = generated_key(&keys, "Private Key:").expect("missing or malformed generated private key");
        let public = generated_key(&keys, "Public Key:").expect("missing or malformed generated public key");
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
        let mut relay_command = Command::new(&engine);
        relay_command.arg(&config).stdout(Stdio::null()).stderr(Stdio::null());
        let _relay = Running::spawn(&mut relay_command, directory, 1).unwrap();
        let mut supervisor = Supervisor::default();
        // Alter one byte of the real release executable and exercise the exact
        // supervisor launch guard, without ever executing the altered copy.
        let tampered_dir = tempfile::tempdir().unwrap();
        let tampered_path = tampered_dir.path().join("rathole.exe");
        let mut tampered_bytes = std::fs::read(&engine).unwrap();
        tampered_bytes[0] ^= 1;
        std::fs::write(&tampered_path, tampered_bytes).unwrap();
        let error = supervisor.start(StartRequest {
            engine: tampered_path.to_string_lossy().into_owned(),
            remote: relay_addr.to_string(), server_key: public.into(),
            mappings: vec![Mapping { name: "web".into(), local_port, token: token.clone() }],
        }).err().expect("modified engine must not launch");
        assert!(error.contains("SHA-256"));
        assert!(supervisor.running.is_none());
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
        let measured = supervisor.traffic_status().unwrap();
        assert_eq!(measured.state, "measured");
        assert!(measured.download_bytes.unwrap() >= 4);
        assert!(measured.upload_bytes.unwrap() >= 4);
        #[cfg(windows)]
        {
            let observed = supervisor.transport_status().unwrap();
            assert_eq!(observed.state, "established", "real engine relay TCP connection missing");
            assert!(observed.established.unwrap() > 0);
            assert_eq!(observed.match_scope, "ip_port");
        }
        let client_dir = supervisor.running.as_ref().unwrap()._directory.path().to_owned();
        assert!(client_dir.join("client.toml").is_file());
        assert_eq!(supervisor.stop().unwrap().state, "stopped");
        assert!(!client_dir.join("client.toml").exists(), "plaintext config survived stop");
        assert!(!client_dir.exists(), "temporary directory survived stop");
        assert!(supervisor.running.is_none());
        assert_eq!(supervisor.transport_status().unwrap().state, "inactive");
        assert_eq!(supervisor.traffic_status().unwrap().state, "inactive");
    }

    #[test]
    fn local_port_probe_uses_real_loopback_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(local_port_open(port).unwrap());
        drop(listener);
        assert!(!local_port_open(port).unwrap());
        assert!(local_port_open(0).is_err());
    }

    #[test]
    fn bundled_engine_resolves_only_expected_resource() {
        let dir = tempfile::tempdir().unwrap();
        assert!(bundled_engine(dir.path()).is_err());
        let engine_dir = dir.path().join("engine");
        std::fs::create_dir(&engine_dir).unwrap();
        let exe = engine_dir.join("rathole.exe");
        std::fs::write(&exe, b"test path only").unwrap();
        assert_eq!(bundled_engine(dir.path()).unwrap(), exe);
    }

    #[test]
    fn stopped_state_and_missing_engine() {
        let mut supervisor = Supervisor::default();
        assert_eq!(supervisor.status().unwrap().state, "stopped");
        assert!(supervisor.start(request()).is_err());
        assert_eq!(supervisor.stop().unwrap().state, "stopped");
    }
}
