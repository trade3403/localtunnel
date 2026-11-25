mod auth;
mod devices;
mod mappings;
mod nodes;
mod domains;
mod preview;
mod runtime;
mod traffic;
mod audit;
mod protection;
mod transport;

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
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('users','devices','nodes','domains','mappings','admin_sessions','device_pairings','device_status','preview_attempts','runtime_requests','mapping_traffic','management_audit')"
    ).fetch_one(&pool).await;
    match count {
        Ok(12) => (StatusCode::OK, "ready"),
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
    let init = args.first().is_some_and(|a| a=="--init-admin");
    let add_node = args.first().is_some_and(|a| a=="--add-node");
    let set_node = args.first().is_some_and(|a| a=="--set-node-enabled");
    let export = args.first().is_some_and(|a| a=="--export-preview");
    let gateway = args.first().is_some_and(|a| a=="--preview-gateway");
    let supervise = args.first().is_some_and(|a| a=="--supervise-preview");
    let tls_gateway = args.first().is_some_and(|a| a=="--preview-tls-gateway");
    let supervise_tls = args.first().is_some_and(|a| a=="--supervise-tls-preview");
    let worker = args.first().is_some_and(|a| a=="--runtime-worker");
    let tls_worker = args.first().is_some_and(|a| a=="--runtime-tls-worker");
    let resident = args.first().is_some_and(|a| a=="--runtime-resident");
    let tls_resident = args.first().is_some_and(|a| a=="--runtime-tls-resident");
    let recover = args.first().is_some_and(|a| a=="--recover-runtime");
    let prune_history = args.first().is_some_and(|a| a=="--prune-history");
    let prune_logs = args.first().is_some_and(|a| a=="--prune-gateway-logs");
    let expected = if prune_logs {3} else if prune_history {2} else if recover {4} else if supervise_tls || tls_worker || tls_resident {11} else if worker || resident {9} else if tls_gateway {if args.get(8).is_some_and(|a|a=="apply-checked"){10}else{9}} else if supervise {9} else if export {6} else if gateway {if args.get(6).is_some_and(|a|a=="apply-checked"){8}else{7}} else if add_node {3} else if set_node {4} else {2};
    if args.len()!=expected {
        return Err("usage: localtunnel-server <data-dir> <port> | --init-admin <data-dir> | --add-node <data-dir> <name> | --set-node-enabled <data-dir> <id> <true|false> | --export-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> | --preview-gateway <data-dir> <mapping-id|clear> <revision> <prefix-name> <listen-port> <init|apply|apply-checked> [private-expected-body-filename] | --supervise-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> <prefix-name> <listen-port> <expected-body-filename> | --preview-tls-gateway <data-dir> <mapping-id|clear> <revision> <prefix> <listen-port> <probe-port> <cert-dir> <init|apply|apply-checked> [expected-body-filename] | --supervise-tls-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> <prefix-name> <listen-port> <expected-body-filename> <probe-port> <cert-dir> | --runtime-worker / --runtime-tls-worker / --runtime-resident / --runtime-tls-resident (same arguments as corresponding supervise command; resident bundle base <=30 characters) | --recover-runtime <data-dir> <prefix> <request-id> | --prune-history <data-dir> | --prune-gateway-logs <data-dir> <prefix>".into());
    }
    let operator = init || add_node || set_node || export || gateway || supervise || tls_gateway || supervise_tls || worker || tls_worker || resident || tls_resident || recover || prune_history || prune_logs;
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
        .await?;
    MIGRATOR.run(&pool).await?;
    if init {
        auth::init_admin(&pool).await.map_err(|_| "administrator initialization refused")?;
        return Ok(());
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
                preview::resident(&pool,&root,id,revision,relay,bundle,prefix,listen,expected_file,transport).await?;
            }else if worker || tls_worker{
                preview::worker(&pool,&root,id,revision,relay,bundle,prefix,listen,expected_file,transport).await?;
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
        .merge(devices::routes(pool.clone()))
        .merge(mappings::routes(pool.clone()))
        .merge(nodes::routes(pool.clone()))
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
