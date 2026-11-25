//! Explicit, local operator-only preview. Never updates desired activation or
//! exposes private keys via HTTP. The operator owns all participating processes.
use crate::auth;
use sqlx::SqlitePool;
use std::{ffi::OsString,fs,path::{Path,PathBuf},process::{Command,Stdio}};

type Result<T> = std::result::Result<T,&'static str>;
#[derive(sqlx::FromRow)]
struct Mapping {id:String,revision:i64,local_port:i64,bind_port:i64,hostname:String}
async fn checked(pool:&SqlitePool,id:&str,revision:i64)->Result<Mapping>{
    if id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1{return Err("invalid mapping identity")}
    // Only HTTP, disabled draft, currently enabled owner/device/node and a
    // recent successful TXT observation. This is not continuous DNS proof.
    sqlx::query_as::<_,Mapping>("SELECT m.id,m.revision,m.local_port,m.bind_port,h.hostname FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN domains h ON h.id=m.domain_id AND h.owner_id=m.owner_id WHERE m.id=? AND m.revision=? AND m.enabled=0 AND m.protocol='http' AND m.local_host='127.0.0.1' AND m.local_port BETWEEN 1 AND 65535 AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch()")
        .bind(id).bind(revision).fetch_optional(pool).await.map_err(|_|"mapping read failed")?.ok_or("preview requires current eligible HTTP draft and recent TXT proof")
}
fn core()->Result<PathBuf>{
    let path=PathBuf::from(std::env::var_os("LOCALTUNNEL_CORE_CLI").ok_or("set trusted core CLI path")?);
    if !path.is_absolute()||!path.is_file(){return Err("invalid core CLI path")}
    path.canonicalize().map_err(|_|"invalid core CLI path")
}
fn safe_name(name:&str)->bool{
    !name.is_empty()&&name.len()<=64&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-')
}
fn private_dir(path:&Path)->Result<()>{
    let m=fs::symlink_metadata(path).map_err(|_|"directory unavailable")?;
    if !m.is_dir()||m.file_type().is_symlink(){return Err("not a private directory")}
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode()&0o077!=0{return Err("not a private directory")}
    }
    Ok(())
}
fn port(p:u16)->Result<String>{
    if p<1024{return Err("preview requires loopback high port")}
    Ok(format!("127.0.0.1:{p}"))
}
fn invoke(core:&Path,args:&[OsString],vars:&[(&str,&str)])->Result<()>{
    // No inherited management or unrelated credentials; suppress output
    // because the child may include sensitive configuration diagnostics.
    let status=Command::new(core).args(args).env_clear().env("PATH","/usr/bin:/bin")
        .envs(vars.iter().copied()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map_err(|_|"core invocation failed")?;
    if !status.success(){return Err("core command failed; inspect private preview directory")}
    Ok(())
}
fn key(name:&str)->Result<String>{std::env::var(name).map_err(|_|"missing operator key")}
#[cfg(unix)]
fn mkdir(path:&Path)->Result<()>{
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path).map_err(|_|"cannot create new private bundle")
}
#[cfg(not(unix))]
fn mkdir(_path:&Path)->Result<()>{Err("Linux preview only")}

pub async fn export(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,name:&str)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(name){return Err("invalid preview request")}
    let m=checked(pool,id,revision).await?;
    let relay=port(relay_port)?;
    if i64::from(relay_port)==m.bind_port{return Err("conflicting relay port")}
    let core=core()?;
    let private=key("LOCALTUNNEL_SERVER_PRIVATE_KEY")?;
    let public=key("LOCALTUNNEL_SERVER_PUBLIC_KEY")?;
    let token=hex::encode(auth::random::<32>().map_err(|_|"random generation failed")?);
    let dir=root.join(name);
    // create_new directory prevents overwrite and path traversal; failure
    // only removes this newly created directory, never an existing bundle.
    mkdir(&dir)?;
    let result=(||{
        let service=format!("m_{}",m.id);
        invoke(&core,&["server-config".into(),dir.join("server.toml").into_os_string(),relay.clone().into(),service.clone().into(),m.bind_port.to_string().into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PRIVATE_KEY",&private)])?;
        invoke(&core,&["client-config".into(),dir.join("client.toml").into_os_string(),relay.into(),service.into(),format!("127.0.0.1:{}",m.local_port).into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PUBLIC_KEY",&public)])?;
        // Non-secret snapshot descriptor; do not claim runtime application.
        use std::io::Write;
        let mut options=fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
        let mut file=options.open(dir.join("manifest.json")).map_err(|_|"manifest creation failed")?;
        let manifest=serde_json::json!({"mapping_id":m.id,"revision":m.revision,"hostname":m.hostname,"bind_port":m.bind_port,"scope":"operator_loopback_preview"});
        file.write_all(manifest.to_string().as_bytes()).and_then(|_|file.sync_all()).map_err(|_|"manifest write failed")?;
        Ok(())
    })();
    if result.is_err(){let _=fs::remove_dir_all(&dir);}
    result
}

pub async fn gateway(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,mode:&str,expected_file:Option<&str>)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(name)||!matches!(mode,"init"|"apply"|"apply-checked")||(mode=="apply-checked")!=expected_file.is_some(){return Err("invalid preview request")}
    let dir=root.join(name);
    private_dir(&dir)?;
    let mut args:Vec<OsString>=vec![format!("gateway-{mode}").into(),dir.into_os_string(),port(listen)?.into()];
    // Clearing a dedicated gateway remains possible after revoke or DNS expiry.
    if id=="clear"{
        if revision!=0||expected_file.is_some(){return Err("invalid clear revision")}
    }else{
        let m=checked(pool,id,revision).await?;
        if i64::from(listen)==m.bind_port{return Err("conflicting gateway port")}
        args.push(m.hostname.into());
        args.push(m.bind_port.to_string().into());
    }
    if let Some(file)=expected_file{
        if !safe_name(file){return Err("invalid expected body filename")}
        let path=root.join(file);
        let m=fs::symlink_metadata(&path).map_err(|_|"expected body unavailable")?;
        if !m.file_type().is_file()||!(1..=65536).contains(&m.len()){return Err("invalid expected body file")}
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            if m.permissions().mode()&0o077!=0{return Err("expected body must be private")}
        }
        args.push(path.into_os_string());
    }
    let cli=core()?;
    let attempt=hex::encode(auth::random::<16>().map_err(|_|"random generation failed")?);
    sqlx::query("INSERT INTO preview_attempts(id,mapping_id,mapping_revision,prefix_name,listen_port,operation) VALUES (?,?,?,?,?,?)")
        .bind(&attempt).bind(if id=="clear"{None}else{Some(id)}).bind(revision).bind(name).bind(i64::from(listen)).bind(mode)
        .execute(pool).await.map_err(|_|"cannot record pending preview operation")?;
    let result=invoke(&cli,&args,&[]);
    let outcome=if result.is_ok(){"succeeded"}else{"failed_or_unknown"};
    sqlx::query("UPDATE preview_attempts SET outcome=?,finished_at=unixepoch() WHERE id=? AND outcome='pending'")
        .bind(outcome).bind(attempt).execute(pool).await.map_err(|_|"preview outcome unknown; inspect runtime and pending record")?;
    result
}
