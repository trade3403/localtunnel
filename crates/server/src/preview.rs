//! Explicit, local operator-only preview. Never updates desired activation or
//! exposes private keys via HTTP. The operator owns all participating processes.
use crate::auth;
use sqlx::SqlitePool;
use std::{ffi::OsString,fs,path::{Path,PathBuf},process::{Child,Command,Stdio},time::{Duration,Instant}};

type Result<T> = std::result::Result<T,&'static str>;
#[derive(sqlx::FromRow)]
struct Mapping {id:String,revision:i64,local_port:i64,bind_port:i64,hostname:String,protocol:String}
async fn checked_protocol(pool:&SqlitePool,id:&str,revision:i64,protocol:&str)->Result<Mapping>{
    if id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1{return Err("invalid mapping identity")}
    // Only web protocols, disabled draft, currently enabled owner/device/node and a
    // recent successful TXT observation. This is not continuous DNS proof.
    sqlx::query_as::<_,Mapping>("SELECT m.id,m.revision,m.local_port,m.bind_port,h.hostname,m.protocol FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN domains h ON h.id=m.domain_id AND h.owner_id=m.owner_id WHERE m.id=? AND m.revision=? AND m.enabled=0 AND m.protocol IN ('http','https') AND (?='web' OR m.protocol=?) AND m.local_host='127.0.0.1' AND m.local_port BETWEEN 1 AND 65535 AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch()")
        .bind(id).bind(revision).bind(protocol).bind(protocol).fetch_optional(pool).await.map_err(|_|"mapping read failed")?.ok_or("preview requires current eligible web draft and recent TXT proof")
}
async fn checked(pool:&SqlitePool,id:&str,revision:i64)->Result<Mapping>{
    checked_protocol(pool,id,revision,"http").await
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
    let m=checked_protocol(pool,id,revision,"web").await?;
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
        let manifest=serde_json::json!({"mapping_id":m.id,"revision":m.revision,"hostname":m.hostname,"bind_port":m.bind_port,"protocol":m.protocol,"scope":"operator_loopback_preview"});
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
    record_attempt(pool,id,revision,name,listen,mode,"http",&args).await
}

async fn record_attempt(pool:&SqlitePool,id:&str,revision:i64,name:&str,listen:u16,mode:&str,transport:&str,args:&[OsString])->Result<()>{
    let cli=core()?;
    let attempt=hex::encode(auth::random::<16>().map_err(|_|"random generation failed")?);
    sqlx::query("INSERT INTO preview_attempts(id,mapping_id,mapping_revision,prefix_name,listen_port,operation,transport) VALUES (?,?,?,?,?,?,?)")
        .bind(&attempt).bind(if id=="clear"{None}else{Some(id)}).bind(revision).bind(name).bind(i64::from(listen)).bind(mode).bind(transport)
        .execute(pool).await.map_err(|_|"cannot record pending preview operation")?;
    let result=invoke(&cli,args,&[]);
    let outcome=if result.is_ok(){"succeeded"}else{"failed_or_unknown"};
    sqlx::query("UPDATE preview_attempts SET outcome=?,finished_at=unixepoch() WHERE id=? AND outcome='pending'")
        .bind(outcome).bind(attempt).execute(pool).await.map_err(|_|"preview outcome unknown; inspect runtime and pending record")?;
    result
}


// This foreground supervisor owns only children it actually spawned.
// No PID file, arbitrary PID kill, shell command or HTTP execution endpoint.
struct TunnelChildren(Vec<Child>);
impl TunnelChildren {
    fn start(&mut self,engine:&Path,config:&Path)->Result<()>{
        let child=Command::new(engine).arg(config).env_clear().env("PATH","/usr/bin:/bin")
            .env("RUST_LOG","warn").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().map_err(|_|"engine launch failed")?;
        self.0.push(child);
        Ok(())
    }
    fn healthy(&mut self)->bool{
        self.0.len()==2&&self.0.iter_mut().all(|p|matches!(p.try_wait(),Ok(None)))
    }
    fn stop(&mut self)->Result<()>{
        let mut ok=true;
        // Stop the relay first to close the ingress and then the agent.
        for child in &mut self.0{
            match child.try_wait(){
                Ok(Some(_))=>{},
                Ok(None)=>{
                    if child.kill().is_err() {
                        if !matches!(child.try_wait(),Ok(Some(_))){ok=false;continue}
                    }
                    if child.wait().is_err(){ok=false}
                },
                Err(_)=>{ok=false}
            }
        }
        if ok{Ok(())}else{Err("one or more tunnel children could not be confirmed stopped")}
    }
}
impl Drop for TunnelChildren {fn drop(&mut self){let _=self.stop();}}
struct PreviewLock(PathBuf);
impl Drop for PreviewLock {fn drop(&mut self){let _=fs::remove_file(&self.0);}}

fn read_expected(root:&Path,name:&str)->Result<Vec<u8>>{
    use std::io::Read;
    if !safe_name(name){return Err("invalid expected body filename")}
    let path=root.join(name);
    let m=fs::symlink_metadata(&path).map_err(|_|"expected body unavailable")?;
    if !m.file_type().is_file()||!(1..=65536).contains(&m.len()){return Err("invalid expected body file")}
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode()&0o077!=0{return Err("expected body must be private")}
    }
    let mut data=Vec::new();
    fs::File::open(path).map_err(|_|"expected body unavailable")?.take(65537)
        .read_to_end(&mut data).map_err(|_|"expected body read failed")?;
    if data.is_empty()||data.len()>65536{return Err("invalid expected body length")}
    Ok(data)
}
fn relay_probe(m:&Mapping,expected:&[u8])->bool{
    let url=format!("http://127.0.0.1:{}/",m.bind_port);
    let host=format!("Host: {}",m.hostname);
    let out=Command::new("/usr/bin/curl").env_clear().env("PATH","/usr/bin:/bin")
        .args(["--disable","--silent","--fail","--noproxy","*","--connect-timeout","1","--max-time","2","--max-filesize","65536","--header",&host,"--write-out","%{http_code}",&url])
        .stdin(Stdio::null()).output();
    out.is_ok_and(|o|o.status.success()&&o.stdout.len()==expected.len()+3&&o.stdout.ends_with(b"200")&&&o.stdout[..expected.len()]==expected)
}

/// Opt-in Linux foreground preview. The trusted operator must already have
/// started an exclusive, empty managed HTTP gateway; never use a shared prefix.
pub async fn supervise(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle:&str,prefix:&str,listen:u16,expected_file:&str)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle)||!safe_name(prefix)||bundle==prefix{return Err("invalid supervisor request")}
    let m=checked(pool,id,revision).await?;
    if relay_port==listen||i64::from(listen)==m.bind_port{return Err("conflicting preview port")}
    port(listen)?;
    private_dir(&root.join(prefix))?;
    let expected=read_expected(root,expected_file)?;
    let engine=PathBuf::from(std::env::var_os("LOCALTUNNEL_ENGINE").ok_or("set trusted engine path")?);
    if !engine.is_absolute()||!engine.is_file(){return Err("invalid engine path")}
    let engine=engine.canonicalize().map_err(|_|"invalid engine path")?;
    // Exclusive among supervised operations. Manual operator commands still
    // require external coordination; a stale lock is recovery evidence.
    let lock=root.join(format!("supervisor-{prefix}.lock"));
    let mut opts=fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
    opts.open(&lock).map_err(|_|"supervisor lock exists or unavailable")?;
    let _lock=PreviewLock(lock);
    // Reset the exclusive gateway to empty and verify the revision first.
    // This dedicated prefix must not serve other mappings.
    gateway(pool,root,"clear",0,prefix,listen,"apply",None).await?;
    export(pool,root,id,revision,relay_port,bundle).await?;
    let mut children=TunnelChildren(Vec::new());
    let result=async {
        children.start(&engine,&root.join(bundle).join("server.toml"))?;
        children.start(&engine,&root.join(bundle).join("client.toml"))?;
        let deadline=Instant::now()+Duration::from_secs(30);
        loop{
            checked(pool,id,revision).await?;
            if !children.healthy(){return Err("tunnel child exited")}
            if relay_probe(&m,&expected){break}
            if Instant::now()>=deadline{return Err("relay business probe timeout")}
            std::thread::sleep(Duration::from_millis(200));
        }
        gateway(pool,root,id,revision,prefix,listen,"apply-checked",Some(expected_file)).await?;
        // Authorization is re-read after apply and every 500ms. Database
        // errors also fail closed. DNS age is checked, not continuous DNS.
        loop{
            if checked(pool,id,revision).await.is_err(){return Ok(())}
            if !children.healthy(){return Err("tunnel child exited")}
            std::thread::sleep(Duration::from_millis(500));
        }
    }.await;
    // Stop owned tunnel processes even if the gateway clear fails.
    let stopped=children.stop();
    let cleared=gateway(pool,root,"clear",0,prefix,listen,"apply",None).await;
    stopped?;
    cleared?;
    result
}


/// TLS preview deliberately requires an immutable, private operator-owned
/// certificate directory. Empty configurations reject all TLS handshakes.
pub async fn tls_gateway(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,probe:u16,cert_dir:&str,mode:&str,expected_file:Option<&str>)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(name)||!safe_name(cert_dir)||name==cert_dir||listen==probe||
        !matches!((mode,id),("init","clear")|("apply","clear")|("apply-checked",_))||
        (mode=="apply-checked")!=expected_file.is_some(){return Err("invalid TLS preview request")}
    let dir=root.join(name);
    let certs=root.join(cert_dir);
    private_dir(&dir)?;
    private_dir(&certs)?;
    let mut args:Vec<OsString>=vec![format!("gateway-tls-{mode}").into(),dir.into_os_string(),port(listen)?.into(),port(probe)?.into()];
    for filename in ["chain.pem","key.pem","ca.pem"]{
        let path=certs.join(filename);
        let m=fs::symlink_metadata(&path).map_err(|_|"certificate file unavailable")?;
        if !m.file_type().is_file()||m.len()==0||m.len()>1048576{return Err("invalid certificate file")}
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            if m.permissions().mode()&0o077!=0{return Err("certificate files must be private")}
        }
        args.push(path.into_os_string());
    }
    // Fixed one-day validity margin for nonempty preview configurations.
    args.push("1".into());
    if id=="clear"{
        if revision!=0||expected_file.is_some(){return Err("invalid clear revision")}
    }else{
        let m=checked_protocol(pool,id,revision,"https").await?;
        if i64::from(listen)==m.bind_port||i64::from(probe)==m.bind_port{return Err("conflicting TLS gateway port")}
        args.push(m.hostname.into());
        args.push(m.bind_port.to_string().into());
    }
    if let Some(file)=expected_file{
        read_expected(root,file)?;
        args.push(root.join(file).into_os_string());
    }
    record_attempt(pool,id,revision,name,listen,mode,"https",&args).await
}
