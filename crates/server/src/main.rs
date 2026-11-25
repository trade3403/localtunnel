mod auth;
mod devices;

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
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('users','devices','nodes','domains','mappings','admin_sessions','device_pairings')"
    ).fetch_one(&pool).await;
    match count {
        Ok(7) => (StatusCode::OK, "ready"),
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
    if args.len() != 2 {
        return Err("usage: localtunnel-server <private-data-directory> <port> | --init-admin <private-data-directory>".into());
    }
    let init = args[0] == "--init-admin";
    let database = data_path(Path::new(if init { &args[1] } else { &args[0] }))?;
    let port: u16 = if init { 0 } else { args[1].to_str().ok_or("invalid port")?.parse()? };
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
    let auth = auth::AuthState::new(pool.clone()).map_err(|_| "authentication initialization failed")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .with_state(pool.clone())
        .merge(auth::routes(auth))
        .merge(devices::routes(pool));
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
