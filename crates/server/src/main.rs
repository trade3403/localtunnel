mod auth;
mod devices;
mod mappings;
mod nodes;
mod domains;
mod preview;

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
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('users','devices','nodes','domains','mappings','admin_sessions','device_pairings','device_status','preview_attempts')"
    ).fetch_one(&pool).await;
    match count {
        Ok(9) => (StatusCode::OK, "ready"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
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
    let dir = dir.canonicalize()?;
    let path = dir.join("control.sqlite3");
    // Reject non-regular files and symlinks including SQLite sidecars.
    for name in ["control.sqlite3", "control.sqlite3-wal", "control.sqlite3-shm", "control.sqlite3-journal"] {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe SQLite file"));
            }
            Ok(_) => {}
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
    let expected = if export {6} else if gateway {if args.get(6).is_some_and(|a|a=="apply-checked"){8}else{7}} else if add_node {3} else if set_node {4} else {2};
    if args.len()!=expected {
        return Err("usage: localtunnel-server <data-dir> <port> | --init-admin <data-dir> | --add-node <data-dir> <name> | --set-node-enabled <data-dir> <id> <true|false> | --export-preview <data-dir> <mapping-id> <revision> <relay-port> <bundle-name> | --preview-gateway <data-dir> <mapping-id|clear> <revision> <prefix-name> <listen-port> <init|apply|apply-checked> [private-expected-body-filename]".into());
    }
    let operator = init || add_node || set_node || export || gateway;
    let database = data_path(Path::new(if operator { &args[1] } else { &args[0] }))?;
    let port: u16 = if operator { 0 } else { args[1].to_str().ok_or("invalid port")?.parse()? };
    let root=database.parent().ok_or("invalid data directory")?.to_path_buf();
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
    if export || gateway {
        let arg=|i:usize|args[i].to_str().ok_or("invalid preview argument");
        if export {
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
        .merge(domains::routes(pool).map_err(|_|"invalid DNS resolver configuration")?);
    // No configurable public bind or unauthenticated data API in this increment.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    println!("LISTENING {}", listener.local_addr()?);
    io::stdout().flush()?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Do not print SQL, filesystem paths, or future credentials.
        eprintln!("LocalTunnel management server failed to initialize or serve");
        std::process::exit(1);
    }
}
