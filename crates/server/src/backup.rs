//! Trusted local Linux snapshot and new-directory recovery. No HTTP surface.
use sqlx::{Connection,SqliteConnection,sqlite::SqliteConnectOptions};
use std::{ffi::CString,fs,io,path::{Path,PathBuf},os::unix::{ffi::OsStrExt,fs::{DirBuilderExt,MetadataExt,PermissionsExt}},time::Duration};

type Result<T>=std::result::Result<T,Box<dyn std::error::Error>>;
const MAX_BYTES:u64=256*1024*1024;
const SNAPSHOT:&str="snapshot.sqlite3";
const CONTROL:&str="control.sqlite3";

fn private_dir(path:&Path)->Result<PathBuf>{
    let m=fs::symlink_metadata(path)?;
    if !m.is_dir()||m.uid()!=unsafe{libc::geteuid()}||m.permissions().mode()&0o077!=0{
        return Err("expected owned private directory".into())
    }
    Ok(path.canonicalize()?)
}
fn absent(path:&Path)->Result<()>{
    match fs::symlink_metadata(path){
        Err(e) if e.kind()==io::ErrorKind::NotFound=>Ok(()),
        Err(e)=>Err(e.into()),
        Ok(_)=>Err("destination or sidecar already exists".into()),
    }
}
fn regular(path:&Path)->Result<u64>{
    let m=fs::symlink_metadata(path)?;
    if !m.is_file()||m.nlink()!=1||m.uid()!=unsafe{libc::geteuid()}||
        m.permissions().mode()&0o077!=0||m.len()>MAX_BYTES{
        return Err("unsafe or oversized database file".into())
    }
    Ok(m.len())
}
fn standalone(path:&Path)->Result<()>{
    if regular(path)?==0{return Err("empty snapshot".into())}
    for suffix in ["-wal","-shm","-journal"]{
        let mut side=path.as_os_str().to_os_string();side.push(suffix);
        absent(Path::new(&side))?;
    }
    Ok(())
}
async fn connect(path:&Path,read_only:bool)->Result<SqliteConnection>{
    Ok(SqliteConnection::connect_with(&SqliteConnectOptions::new()
        .filename(path).create_if_missing(false).read_only(read_only)
        .foreign_keys(true).busy_timeout(Duration::from_secs(3))).await?)
}
async fn validate(conn:&mut SqliteConnection)->Result<()>{
    let integrity=sqlx::query_scalar::<_,String>("PRAGMA integrity_check(1)").fetch_all(&mut *conn).await?;
    if integrity.as_slice()!=["ok"]{return Err("database integrity check failed".into())}
    if sqlx::query("SELECT 1 FROM pragma_foreign_key_check LIMIT 1").fetch_optional(&mut *conn).await?.is_some(){
        return Err("database foreign keys invalid".into())
    }
    let rows=sqlx::query_as::<_,(i64,bool,Vec<u8>)>("SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version").fetch_all(&mut *conn).await?;
    if rows.len()!=crate::MIGRATOR.iter().count(){return Err("unsupported migration inventory".into())}
    for ((version,success,checksum),expected) in rows.iter().zip(crate::MIGRATOR.iter()){
        if !*success||*version!=expected.version||checksum.as_slice()!=expected.checksum.as_ref(){
            return Err("unsupported migration checksum".into())
        }
    }
    // Also compare actual table/index/trigger definitions with a migrated
    // empty database. Migration bookkeeping alone does not prove the schema.
    let mut reference=SqliteConnection::connect("sqlite::memory:").await?;
    crate::MIGRATOR.run(&mut reference).await?;
    let sql="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name";
    let actual=sqlx::query_as::<_,(String,String,String,Option<String>)>(sql).fetch_all(&mut *conn).await?;
    let expected=sqlx::query_as::<_,(String,String,String,Option<String>)>(sql).fetch_all(&mut reference).await?;
    reference.close().await?;
    if actual!=expected{return Err("unexpected database schema".into())}
    Ok(())
}
struct Staging(PathBuf);
impl Drop for Staging{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn publish(stage:&Path,dest:&Path)->Result<()>{
    let from=CString::new(stage.as_os_str().as_bytes())?;
    let to=CString::new(dest.as_os_str().as_bytes())?;
    // Atomic directory publication without replacing even an empty directory.
    if unsafe{libc::renameat2(libc::AT_FDCWD,from.as_ptr(),libc::AT_FDCWD,to.as_ptr(),libc::RENAME_NOREPLACE)}!=0{
        return Err(io::Error::last_os_error().into())
    }
    Ok(())
}
pub async fn run(source:&Path,dest:&Path,restore:bool)->Result<()>{
    let source=private_dir(source)?;
    let name=dest.file_name().and_then(|v|v.to_str()).ok_or("invalid destination name")?;
    if name.is_empty()||name.len()>64||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'){
        return Err("invalid destination name".into())
    }
    let parent=private_dir(dest.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    let dest=parent.join(name);
    absent(&dest)?;
    if parent.starts_with(&source){return Err("destination must be outside source directory".into())}
    let input=if restore{
        let path=source.join(SNAPSHOT);
        standalone(&path)?;
        path
    }else{
        // Existing data_path enforces private owner and link checks; no
        // create-if-missing or migration of the source in this command.
        let path=crate::data_path(&source)?;
        let mut size=regular(&path)?;
        if size==0{return Err("empty source database".into())}
        for suffix in ["-wal","-journal","-shm"]{
            let side=source.join(format!("{CONTROL}{suffix}"));
            match fs::symlink_metadata(&side){
                Ok(_)=>size=size.checked_add(regular(&side)?).ok_or("source size overflow")?,
                Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
                Err(e)=>return Err(e.into()),
            }
        }
        if size>MAX_BYTES{return Err("source budget exceeded".into())}
        path
    };
    let stage=parent.join(format!(".snapshot-{}",hex::encode(crate::auth::random::<16>().map_err(|_|"random generation failed")?)));
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let stage=Staging(stage);
    let output=stage.0.join(if restore{CONTROL}else{SNAPSHOT});
    let mut src=connect(&input,true).await?;
    // SQLite performs a consistent snapshot, including committed WAL data;
    // never copy a live main file alone. Bound parameters, no SQL path interpolation.
    sqlx::query("VACUUM INTO ?").bind(output.to_str().ok_or("invalid snapshot path")?).execute(&mut src).await?;
    src.close().await?;
    standalone(&output)?;
    let mut copy=connect(&output,false).await?;
    validate(&mut copy).await?;
    if restore{
        // Prevent stale tokens, DNS authorization and runtime commands from
        // coming back after rollback. Keep owner/mapping/history records.
        let mut tx=copy.begin().await?;
        for statement in [
            "DELETE FROM admin_sessions",
            "DELETE FROM device_pairings",
            "DELETE FROM device_status",
            "DELETE FROM runtime_requests",
            "UPDATE mappings SET enabled=0,revision=revision+1 WHERE enabled=1",
            "UPDATE devices SET enabled=0,credential_digest=randomblob(32),revision=revision+1",
            "UPDATE domains SET verified_at=NULL,verification_token=NULL WHERE verified_at IS NOT NULL OR verification_token IS NOT NULL",
        ]{sqlx::query(statement).execute(&mut *tx).await?;}
        tx.commit().await?;
        validate(&mut copy).await?;
    }
    copy.close().await?;
    standalone(&output)?;
    fs::File::open(&output)?.sync_all()?;
    fs::File::open(&stage.0)?.sync_all()?;
    publish(&stage.0,&dest)?;
    // If parent sync fails publication may already have occurred; never
    // remove a published destination on an uncertain durability outcome.
    fs::File::open(&parent)?.sync_all()?;
    Ok(())
}
