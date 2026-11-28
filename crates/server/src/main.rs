mod auth;
mod devices;
mod commercial;
mod mappings;
mod nodes;
mod scheduling;
mod reconciliation;
mod failover;
mod grants;
mod relay_tcp;
mod relay_http;
mod relay_https;
mod relay_budget;
mod relay_budget_grant;
mod relay;
mod domains;
mod preview;
mod tcp_limit;
#[path = "../../../src/udp_guard.rs"]
#[allow(dead_code)]
mod udp_guard;
mod udp_monthly;
mod runtime;
mod traffic;
mod audit;
mod protection;
mod transport;
#[cfg(target_os = "linux")]
mod backup;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, SqlitePool};
use std::{error::Error, io::{self, Write}, net::Ipv4Addr, path::{Path, PathBuf}, time::Duration};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(pool): State<SqlitePool>) -> impl IntoResponse {
    // Real database query, not a cached startup flag.
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('users','devices','nodes','domains','mappings','admin_sessions','device_pairings','device_status','preview_attempts','runtime_requests','mapping_traffic','management_audit','commercial_plans','tenants','tenant_entitlements','commercial_operator_audit','bandwidth_reservations','bandwidth_recovery_audit','tenant_monthly_usage','connection_slots','relay_identities','relay_identity_audit','relay_heartbeat','node_policy_audit','relay_allocations','relay_grants','relay_tcp_intents','relay_udp_intents','relay_http_intents','relay_https_intents','relay_budget_previews','relay_budget_grants','relay_budget_intents','relay_allocation_fences','relay_cleanup_reports','relay_budget_reclaims','relay_budget_retirements','relay_failover_links','relay_failure_observations')"
    ).fetch_one(&pool).await;
    match count {
        Ok(39) => (StatusCode::OK, "ready"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
}

#[cfg(target_os = "linux")]
fn secure_sqlite_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    // The parent is private and trusted. Open without following links, then
    // inspect and tighten the exact descriptor rather than chmod a pathname.
    let file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe SQLite ownership or link count"));
    }
    if m.permissions().mode() & 0o7777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn data_path(dir: &Path) -> io::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "data directory must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "data directory must be private (0700)"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "data directory must belong to runtime user"));
        }
    }
    let dir = dir.canonicalize()?;
    let path = dir.join("control.sqlite3");
    // Reject non-regular files and symlinks including SQLite sidecars.
    for name in ["control.sqlite3", "control.sqlite3-wal", "control.sqlite3-shm", "control.sqlite3-journal"] {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe SQLite file"));
            }
            Ok(_) => {
                #[cfg(target_os = "linux")]
                secure_sqlite_file(&dir.join(name))?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let backup_db = args.first().is_some_and(|a| a=="--backup-db");
    let restore_db = args.first().is_some_and(|a| a=="--restore-db");
    if backup_db || restore_db {
        if args.len()!=3{return Err("usage: --backup-db <data-dir> <new-backup-dir> | --restore-db <backup-dir> <new-data-dir>".into())}
        #[cfg(target_os = "linux")]
        {
            if let Err(error) = backup::run(Path::new(&args[1]),Path::new(&args[2]),restore_db).await {
                // Trusted local maintenance CLI only: expose fixed admission
                // reasons, never raw SQL, paths, credentials or OS errors.
                match error.to_string().as_str() {
                    "source budget exceeded" => eprintln!("source budget exceeded"),
                    "unsafe or oversized database file" => eprintln!("unsafe or oversized database file"),
                    "destination or sidecar already exists" => eprintln!("destination or sidecar already exists"),
                    _ => {}
                }
                return Err(error);
            }
            println!("verified database snapshot published");
            return Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        return Err("database snapshot maintenance is Linux-only".into());
    }
    let scan_relay_failures=args.first().is_some_and(|a|a=="--scan-relay-failures");
    let watch_relay_failures=args.first().is_some_and(|a|a=="--watch-relay-failures");
    let relay_budget_retire=args.first().is_some_and(|a|a=="--retire-relay-budget");
    let relay_budget_recover=args.first().is_some_and(|a|a=="--recover-relay-budget");
    let bandwidth_list=args.first().is_some_and(|a|a=="--commercial-list-bandwidth");
    let bandwidth_recover=args.first().is_some_and(|a|a=="--commercial-recover-bandwidth");
    let commercial_action=args.first().and_then(|a|a.to_str()).filter(|a|matches!(*a,"--commercial-create-account"|"--commercial-create-plan"|"--commercial-assign"));
    let relay_action=args.first().and_then(|a|a.to_str()).filter(|a|matches!(*a,"--relay-issue"|"--relay-rotate"|"--relay-revoke"));
    let init = args.first().is_some_and(|a| a=="--init-admin");
    let add_node = args.first().is_some_and(|a| a=="--add-node");
    let node_health = args.first().is_some_and(|a| a=="--node-health");
    let set_policy = args.first().is_some_and(|a| a=="--set-node-policy");
    let set_node = args.first().is_some_and(|a| a=="--set-node-enabled");
    let export = args.first().is_some_and(|a| a=="--export-preview");
    let gateway = args.first().is_some_and(|a| a=="--preview-gateway");
    let supervise = args.first().is_some_and(|a| a=="--supervise-preview");
    let udp_supervise = args.first().is_some_and(|a| a=="--supervise-udp-preview");
    let tcp_worker = args.first().is_some_and(|a| a=="--runtime-tcp-worker");
    let udp_worker = args.first().is_some_and(|a| a=="--runtime-udp-worker");
    let udp_device_worker = args.first().is_some_and(|a| a=="--runtime-udp-device-worker");
    let udp_resident = args.first().is_some_and(|a| a=="--runtime-udp-resident");
    let tls_gateway = args.first().is_some_and(|a| a=="--preview-tls-gateway");
    let supervise_tls = args.first().is_some_and(|a| a=="--supervise-tls-preview");
    let worker = args.first().is_some_and(|a| a=="--runtime-worker");
    let tls_worker = args.first().is_some_and(|a| a=="--runtime-tls-worker");
    let resident = args.first().is_some_and(|a| a=="--runtime-resident");
    let tls_resident = args.first().is_some_and(|a| a=="--runtime-tls-resident");
    let recover = args.first().is_some_and(|a| a=="--recover-runtime");
    let prune_history = args.first().is_some_and(|a| a=="--prune-history");
    let prune_logs = args.first().is_some_and(|a| a=="--prune-gateway-logs");
    let expected = if relay_budget_recover || relay_budget_retire {5} else if node_health {3} else if set_policy {7} else if relay_action==Some("--relay-issue") {3} else if relay_action.is_some() {4} else if prune_logs {3} else if prune_history {2} else if recover {4} else if tcp_worker {7} else if udp_device_worker {8} else if udp_worker || udp_resident {9} else if udp_supervise {7} else if supervise_tls || tls_worker || tls_resident {11} else if worker || resident {9} else if tls_gateway {if args.get(8).is_some_and(|a|a=="apply-checked"){10}else{9}} else if supervise {9} else if export {6} else if gateway {if args.get(6).is_some_and(|a|a=="apply-checked"){8}else{7}} else if add_node {3} else if set_node {4} else {2};
    if args.len()!=expected {
        return Err("usage: localtunnel-server <data-dir> <port> | --init-admin <data-dir> | --commercial-create-account <data-dir> | --commercial-create-plan <data-dir> | --commercial-assign <data-dir> (each reads bounded JSON stdin) | --scan-relay-failures <data-dir> | --watch-relay-failures <data-dir> | --retire-relay-budget <data-dir> <allocation-id> <grant-id> <offline_ports_and_engine_verified_stopped> | --recover-relay-budget <data-dir> <allocation-id> <grant-id> <offline_engine_and_guard_verified_stopped> | --commercial-list-bandwidth <data-dir> | --commercial-recover-bandwidth <data-dir> (reads exact reservation JSON and offline confirmation) | --relay-issue <data-dir> <node-id> | --relay-rotate / --relay-revoke <data-dir> <node-id> <expected-generation> | --node-health <data-dir> <node-id> | --set-node-policy <data-dir> <node-id> <expected-revision> <approved-capacity> <region> <active|draining|maintenance> | --add-node <data-dir> <name> | --set-node-enabled <data-dir> <id> <true|false> | --export-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> | --preview-gateway <data-dir> <mapping-id|clear> <revision> <prefix-name> <listen-port> <init|apply|apply-checked> [private-expected-body-filename] | --supervise-udp-preview <data-dir> <mapping-id> <revision> <relay-port> <internal-udp-port> <bundle-name> | --runtime-tcp-worker <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> <bytes-per-second> | --runtime-udp-worker <data-dir> <mapping-id> <revision> <relay-port> <internal-udp-port> <bundle-name> <bytes-per-second> <burst-bytes> | --runtime-udp-device-worker <data-dir> <mapping-id> <revision> <relay-port> <internal-udp-port> <bytes-per-second> <burst-bytes> | --runtime-udp-resident (same arguments as --runtime-udp-worker; bundle base <=30 characters) | --supervise-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> <prefix-name> <listen-port> <expected-body-filename> | --preview-tls-gateway <data-dir> <mapping-id|clear> <revision> <prefix> <listen-port> <probe-port> <cert-dir> <init|apply|apply-checked> [expected-body-filename] | --supervise-tls-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> <prefix-name> <listen-port> <expected-body-filename> <probe-port> <cert-dir> | --runtime-worker / --runtime-tls-worker / --runtime-resident / --runtime-tls-resident (same arguments as corresponding supervise command; resident bundle base <=30 characters) | --recover-runtime <data-dir> <prefix> <request-id> | --prune-history <data-dir> | --prune-gateway-logs <data-dir> <prefix>".into());
    }
    let operator = scan_relay_failures || watch_relay_failures || relay_budget_retire || relay_budget_recover || node_health || set_policy || relay_action.is_some() || bandwidth_list || bandwidth_recover || commercial_action.is_some() || init || add_node || set_node || export || gateway || supervise || udp_supervise || tcp_worker || udp_worker || udp_device_worker || udp_resident || tls_gateway || supervise_tls || worker || tls_worker || resident || tls_resident || recover || prune_history || prune_logs;
    let database = data_path(Path::new(if operator { &args[1] } else { &args[0] }))?;
    let port: u16 = if operator { 0 } else { args[1].to_str().ok_or("invalid port")?.parse()? };
    let root=database.parent().ok_or("invalid data directory")?.to_path_buf();
    if prune_logs{
        let count=preview::prune_gateway_logs(&root,args[2].to_str().ok_or("invalid prefix")?)?;
        println!("removed {count} expired numeric gateway logs");
        return Ok(())
    }
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(SqliteConnectOptions::new()
            .filename(database)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(3)))
        .await.map_err(|e|{
            if tcp_worker{eprintln!("TCP worker database connection failed");}
            e
        })?;
    MIGRATOR.run(&pool).await.map_err(|e|{
        if tcp_worker{eprintln!("TCP worker database migration check failed");}
        e
    })?;
    // Hold the guard until this entire process finishes, including
    // cleanup and DB release. Exclusive recovery cannot race a new worker.
    let _bandwidth_guard=if bandwidth_recover{
        Some(preview::bandwidth_guard(&root,true)?)
    }else if supervise || supervise_tls || worker || tls_worker || resident || tls_resident || udp_supervise || udp_worker || udp_device_worker || udp_resident || tcp_worker || recover{
        Some(preview::bandwidth_guard(&root,false)?)
    }else{None};
    if scan_relay_failures{
        let result=reconciliation::scan_failures(&pool).await?;
        println!("{}",serde_json::to_string(&result)?);
        return Ok(())
    }
    if watch_relay_failures{
        // An opt-in independent controller. No HTTP listener, tenant token,
        // grant issuance or remote command execution.
        loop{
            match reconciliation::scan_failures(&pool).await{
                Ok(result)=>{
                    if result.observed>0||result.fenced>0{
                        println!("relay failure scan observed={} fenced={}",result.observed,result.fenced);
                        io::stdout().flush()?;
                    }
                },
                Err(_)=>eprintln!("relay failure scan unavailable; resources retained"),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    if relay_budget_retire{
        let id=args[2].to_str().ok_or("invalid allocation id")?;
        let grant=args[3].to_str().ok_or("invalid grant id")?;
        let confirmation=args[4].to_str().ok_or("invalid retirement confirmation")?;
        println!("{}",reconciliation::retire_budget(&pool,id,grant,confirmation).await?);
        return Ok(())
    }
    if relay_budget_recover{
        let id=args[2].to_str().ok_or("invalid allocation id")?;
        let grant=args[3].to_str().ok_or("invalid grant id")?;
        let confirmation=args[4].to_str().ok_or("invalid recovery confirmation")?;
        println!("{}",reconciliation::reclaim_budget(&pool,id,grant,confirmation).await?);
        return Ok(())
    }
    if bandwidth_list{
        println!("{}",commercial::list_bandwidth(&pool).await?);
        return Ok(());
    }
    if bandwidth_recover{
        println!("{}",commercial::recover_bandwidth(&pool).await?);
        return Ok(());
    }
    if let Some(action)=commercial_action{
        let id=commercial::operator(&pool,action).await?;
        println!("{id}");
        return Ok(())
    }
    if init {
        auth::init_admin(&pool).await.map_err(|_| "administrator initialization refused")?;
        return Ok(());
    }
    if let Some(action)=relay_action{
        let node=args[2].to_str().ok_or("invalid node id")?;
        let expected:i64=if action=="--relay-issue"{0}else{args[3].to_str().ok_or("invalid generation")?.parse().map_err(|_|"invalid generation")?};
        if action!="--relay-issue" && expected<=0{return Err("invalid generation".into())}
        let result=relay::change(&pool,node,expected,action=="--relay-revoke").await.map_err(|_|"relay credential change refused")?;
        if let Some(token)=result{println!("{token}");}
        return Ok(())
    }
    if node_health {
        let result=nodes::operator_health(&pool,args[2].to_str().ok_or("invalid node id")?).await.map_err(|_|"node health unavailable")?;
        println!("{result}");
        return Ok(())
    }
    if set_policy {
        let expected:i64=args[3].to_str().ok_or("invalid policy revision")?.parse().map_err(|_|"invalid policy revision")?;
        let capacity:i64=args[4].to_str().ok_or("invalid approved capacity")?.parse().map_err(|_|"invalid approved capacity")?;
        nodes::set_policy(&pool,args[2].to_str().ok_or("invalid node id")?,expected,capacity,args[5].to_str().ok_or("invalid region")?,args[6].to_str().ok_or("invalid policy mode")?).await.map_err(|_|"node policy change refused")?;
        return Ok(())
    }
    if add_node {
        let id=nodes::add(&pool,args[2].to_str().ok_or("invalid node name")?).await.map_err(|_|"node creation refused")?;
        println!("{id}");
        return Ok(());
    }
    if set_node {
        let enabled=args[3].to_str().ok_or("invalid node state")?.parse::<bool>()?;
        nodes::set_enabled(&pool,args[2].to_str().ok_or("invalid node id")?,enabled).await.map_err(|_|"node state change refused")?;
        return Ok(());
    }
    if prune_history{
        audit::prune(&pool).await?;
        return Ok(());
    }
    if recover{
        preview::recover(&pool,&root,args[2].to_str().ok_or("invalid prefix")?,args[3].to_str().ok_or("invalid request id")?).await?;
        return Ok(());
    }
    if tcp_worker {
        let arg=|i:usize|args[i].to_str().ok_or("invalid TCP worker argument");
        // tcp_worker returns only static, internally authored errors. Never
        // print SQLx errors, engine stderr, argument values or secret material.
        preview::tcp_worker(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?,arg(6)?.parse()?).await.map_err(|reason|{
            eprintln!("TCP worker stopped: {reason}");
            reason
        })?;
        return Ok(());
    }
    if udp_device_worker {
        let arg=|i:usize|args[i].to_str().ok_or("invalid UDP device worker argument");
        preview::udp_device_worker(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?.parse()?,arg(6)?.parse()?,arg(7)?.parse()?).await?;
        return Ok(());
    }
    if udp_resident {
        let arg=|i:usize|args[i].to_str().ok_or("invalid UDP resident argument");
        preview::udp_resident(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?.parse()?,arg(6)?,arg(7)?.parse()?,arg(8)?.parse()?).await.map_err(|reason|{
            // preview returns only static, non-secret diagnostics.
            eprintln!("UDP resident stopped: {reason}");
            reason
        })?;
        return Ok(());
    }
    if udp_worker {
        let arg=|i:usize|args[i].to_str().ok_or("invalid UDP worker argument");
        preview::udp_worker(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?.parse()?,arg(6)?,arg(7)?.parse()?,arg(8)?.parse()?).await?;
        return Ok(());
    }
    if udp_supervise {
        let arg=|i:usize|args[i].to_str().ok_or("invalid UDP preview argument");
        preview::supervise_udp(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?.parse()?,arg(6)?).await?;
        return Ok(());
    }
    if export || gateway || supervise || tls_gateway || supervise_tls || worker || tls_worker || resident || tls_resident {
        let arg=|i:usize|args[i].to_str().ok_or("invalid preview argument");
        if tls_gateway {
            preview::tls_gateway(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?,arg(5)?.parse()?,arg(6)?.parse()?,arg(7)?,arg(8)?,if args.len()==10{Some(arg(9)?)}else{None}).await?;
        } else if supervise || supervise_tls || worker || tls_worker || resident || tls_resident {
            let transport=if supervise_tls || tls_worker || tls_resident{
                preview::PreviewTransport::Https{probe:arg(9)?.parse()?,cert_dir:arg(10)?}
            }else{preview::PreviewTransport::Http};
            let id=arg(2)?;
            let revision=arg(3)?.parse()?;
            let relay=arg(4)?.parse()?;
            let bundle=arg(5)?;
            let prefix=arg(6)?;
            let listen=arg(7)?.parse()?;
            let expected_file=arg(8)?;
            if resident || tls_resident{
                preview::resident(&pool,&root,id,revision,relay,bundle,prefix,listen,expected_file,transport).await.map_err(|reason|{
                    eprintln!("Web resident stopped: {reason}");
                    reason
                })?;
            }else if worker || tls_worker{
                preview::worker(&pool,&root,id,revision,relay,bundle,prefix,listen,expected_file,transport).await.map_err(|reason|{
                    eprintln!("Web worker stopped: {reason}");
                    reason
                })?;
            }else{
                preview::supervise(&pool,&root,id,revision,relay,bundle,prefix,listen,expected_file,transport,None,None).await?;
            }
        } else if export {
            preview::export(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?.parse()?,arg(5)?).await?;
        } else {
            preview::gateway(&pool,&root,arg(2)?,arg(3)?.parse()?,arg(4)?,arg(5)?.parse()?,arg(6)?,if args.len()==8{Some(arg(7)?)}else{None}).await?;
        }
        return Ok(());
    }
    let auth = auth::AuthState::new(pool.clone()).map_err(|_| "authentication initialization failed")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .with_state(pool.clone())
        .merge(auth::routes(auth))
        .merge(devices::routes(pool.clone(),root.clone()))
        .merge(commercial::routes(pool.clone()))
        .merge(mappings::routes(pool.clone()))
        .merge(nodes::routes(pool.clone()))
        .merge(scheduling::routes(pool.clone()))
        .merge(reconciliation::routes(pool.clone()))
        .merge(failover::routes(pool.clone()))
        .merge(grants::routes(pool.clone()))
        .merge(relay_tcp::routes(pool.clone()))
        .merge(relay_http::routes(pool.clone()))
        .merge(relay_https::routes(pool.clone()))
        .merge(relay_budget::routes(pool.clone()))
        .merge(relay_budget_grant::routes(pool.clone()))
        .merge(relay::routes(pool.clone()))
        .merge(runtime::routes(pool.clone()))
        .merge(traffic::routes(pool.clone()))
        .merge(audit::routes(pool.clone()))
        .merge(domains::routes(pool).map_err(|_|"invalid DNS resolver configuration")?)
        .layer(axum::middleware::from_fn_with_state(protection::Limits::new(), protection::protect));
    // No configurable public bind or unauthenticated data API in this increment.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    println!("LISTENING {}", listener.local_addr()?);
    io::stdout().flush()?;
    transport::serve(listener, app).await?;
    Ok(())
}

fn main() {
    // Set the process mask before creating runtime threads or SQLite files.
    #[cfg(target_os = "linux")]
    unsafe { libc::umask(0o077); }
    entry();
}

#[tokio::main]
async fn entry() {
    if run().await.is_err() {
        // Do not print SQL, filesystem paths, or future credentials.
        eprintln!("LocalTunnel management server failed to initialize or serve");
        std::process::exit(1);
    }
}
