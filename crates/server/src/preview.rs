//! Explicit, local operator-only preview. Never updates desired activation or
//! exposes private keys via HTTP. The operator owns all participating processes.
use crate::auth;
use sqlx::SqlitePool;
use std::{ffi::OsString,fs,path::{Path,PathBuf},process::{Child,Command,Stdio},time::{Duration,Instant}};

type Result<T> = std::result::Result<T,&'static str>;
#[derive(sqlx::FromRow)]
struct Mapping {id:String,revision:i64,local_port:i64,bind_port:i64,hostname:String,protocol:String,bandwidth_bps:Option<i64>}
async fn checked_protocol(pool:&SqlitePool,id:&str,revision:i64,protocol:&str)->Result<Mapping>{
    if id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1{return Err("invalid mapping identity")}
    // Only web protocols, disabled draft, currently enabled owner/device/node and a
    // recent successful TXT observation. This is not continuous DNS proof.
    sqlx::query_as::<_,Mapping>("SELECT m.id,m.revision,m.local_port,m.bind_port,h.hostname,m.protocol,(SELECT cp.max_bandwidth_bps FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id) AS bandwidth_bps FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN domains h ON h.id=m.domain_id AND h.owner_id=m.owner_id WHERE m.id=? AND m.revision=? AND m.enabled=0 AND m.protocol IN ('http','https') AND (?='web' OR m.protocol=?) AND m.local_host='127.0.0.1' AND m.local_port BETWEEN 1 AND 65535 AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch() AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()))")
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
    export_inner(pool,root,id,revision,relay_port,name,None,None).await
}
async fn export_inner(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,name:&str,limited_target:Option<u16>,expected_bps:Option<i64>)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(name){return Err("invalid preview request")}
    let m=checked_protocol(pool,id,revision,"web").await?;
    if m.bandwidth_bps!=expected_bps||m.bandwidth_bps.is_some()!=limited_target.is_some(){return Err("commercial web export requires supervised TCP limiter")}
    let local_port=limited_target.map(i64::from).unwrap_or(m.local_port);
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
        invoke(&core,&["client-config".into(),dir.join("client.toml").into_os_string(),relay.into(),service.into(),format!("127.0.0.1:{}",local_port).into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PUBLIC_KEY",&public)])?;
        // Non-secret snapshot descriptor; do not claim runtime application.
        use std::io::Write;
        let mut options=fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
        let mut file=options.open(dir.join("manifest.json")).map_err(|_|"manifest creation failed")?;
        let manifest=serde_json::json!({"mapping_id":m.id,"revision":m.revision,"hostname":m.hostname,"bind_port":m.bind_port,"protocol":m.protocol,"scope":"operator_loopback_preview","commercial_bandwidth_bps":expected_bps,"tcp_limiter_port":limited_target,"byte_rate":expected_bps.map(|bps|(bps/8).min(125000000)),"byte_limit_scope":"per_mapping_per_direction_tcp_stream"});
        file.write_all(manifest.to_string().as_bytes()).and_then(|_|file.sync_all()).map_err(|_|"manifest write failed")?;
        Ok(())
    })();
    if result.is_err(){let _=fs::remove_dir_all(&dir);}
    result
}

pub async fn gateway(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,mode:&str,expected_file:Option<&str>)->Result<()>{
    gateway_inner(pool,root,id,revision,name,listen,mode,expected_file,false).await
}
async fn gateway_inner(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,mode:&str,expected_file:Option<&str>,supervised:bool)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(name)||!matches!(mode,"init"|"apply"|"apply-checked")||(mode=="apply-checked")!=expected_file.is_some(){return Err("invalid preview request")}
    let dir=root.join(name);
    private_dir(&dir)?;
    let mut args:Vec<OsString>=vec![format!("gateway-{mode}").into(),dir.into_os_string(),port(listen)?.into()];
    // Clearing a dedicated gateway remains possible after revoke or DNS expiry.
    if id=="clear"{
        if revision!=0||expected_file.is_some(){return Err("invalid clear revision")}
    }else{
        let m=checked(pool,id,revision).await?;
        if m.bandwidth_bps.is_some()&&!supervised{return Err("commercial web gateway requires supervised TCP limiter")}
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
        let mut cmd=Command::new(engine);
        cmd.arg(config).env_clear().env("PATH","/usr/bin:/bin")
            .env("RUST_LOG","warn").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        protect_child(&mut cmd)?;
        let child=cmd.spawn().map_err(|_|"engine launch failed")?;
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
// Linux direct children must not outlive their owning supervisor, even if
// it receives SIGKILL. pre_exec only performs async-signal-safe syscalls.
// The parent PID recheck closes the fork-to-prctl race.
#[cfg(target_os="linux")]
fn protect_child(cmd:&mut Command)->Result<()>{
    use std::os::unix::process::CommandExt;
    let parent=std::process::id() as libc::pid_t;
    unsafe {
        cmd.pre_exec(move||{
            if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong)!=0{
                return Err(std::io::Error::last_os_error())
            }
            if libc::getppid()!=parent{libc::_exit(125)}
            Ok(())
        });
    }
    Ok(())
}
#[cfg(not(target_os="linux"))]
fn protect_child(_: &mut Command)->Result<()>{Err("Linux supervisor only")}

// Persistent inode, never unlink the guard file. Kernel releases flock on
// process death. A separate create_new marker retains crash evidence.
#[cfg(target_os="linux")]
fn guard(root:&Path,kind:&str,prefix:&str)->Result<fs::File>{
    use std::os::{fd::AsRawFd,unix::fs::{OpenOptionsExt,PermissionsExt}};
    if !safe_name(prefix){return Err("invalid guard prefix")}
    let file=fs::OpenOptions::new().read(true).write(true).create(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(root.join(format!("{kind}-{prefix}.guard"))).map_err(|_|"guard unavailable")?;
    let m=file.metadata().map_err(|_|"guard metadata unavailable")?;
    if !m.is_file()||m.permissions().mode()&0o077!=0{return Err("unsafe guard")}
    if unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{return Err("worker or supervisor still holds guard")}
    Ok(file)
}
#[cfg(not(target_os="linux"))]
fn guard(_: &Path,_:&str,_:&str)->Result<fs::File>{Err("Linux supervisor only")}
struct PreviewLock{path:PathBuf,_guard:fs::File}
impl Drop for PreviewLock {fn drop(&mut self){let _=fs::remove_file(&self.path);}}
fn acquire_lock(root:&Path,kind:&str,prefix:&str)->Result<PreviewLock>{
    let held=guard(root,kind,prefix)?;
    let path=root.join(format!("{kind}-{prefix}.lock"));
    let mut opts=fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
    opts.open(&path).map_err(|_|"lock exists or unavailable; inspect recovery evidence")?;
    Ok(PreviewLock{path,_guard:held})
}
fn acquire_worker_lock(root:&Path,prefix:&str)->Result<PreviewLock>{acquire_lock(root,"worker",prefix)}
fn stop_requested(path:Option<&Path>)->Result<bool>{
    let Some(path)=path else{return Ok(false)};
    // Any existing entry, including a symlink, is a fail-closed stop signal.
    match fs::symlink_metadata(path){
        Ok(_)=>Ok(true),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(false),
        Err(_)=>Err("cannot inspect local stop marker"),
    }
}

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

#[derive(Clone,Copy)]
pub enum PreviewTransport<'a> {
    Http,
    Https {probe:u16,cert_dir:&'a str},
}
impl PreviewTransport<'_>{
    fn protocol(self)->&'static str{
        match self{Self::Http=>"http",Self::Https{..}=>"https"}
    }
    async fn gateway(self,pool:&SqlitePool,root:&Path,id:&str,revision:i64,prefix:&str,listen:u16,mode:&str,expected_file:Option<&str>)->Result<()>{
        match self{
            Self::Http=>gateway_inner(pool,root,id,revision,prefix,listen,mode,expected_file,true).await,
            Self::Https{probe,cert_dir}=>tls_gateway_inner(pool,root,id,revision,prefix,listen,probe,cert_dir,mode,expected_file,true).await,
        }
    }
}

/// Opt-in Linux foreground preview. The trusted operator must already have
/// started an exclusive managed gateway of the selected transport.
pub async fn supervise(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle:&str,prefix:&str,listen:u16,expected_file:&str,transport:PreviewTransport<'_>,request:Option<&str>,stop_marker:Option<&Path>)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle)||!safe_name(prefix)||bundle==prefix{return Err("invalid supervisor request")}
    let m=checked_protocol(pool,id,revision,transport.protocol()).await?;
    if relay_port==listen||i64::from(listen)==m.bind_port{return Err("conflicting preview port")}
    port(listen)?;
    port(relay_port)?;
    if let PreviewTransport::Https{probe,cert_dir}=transport{
        port(probe)?;
        if probe==listen||probe==relay_port||i64::from(probe)==m.bind_port||!safe_name(cert_dir)||cert_dir==bundle||cert_dir==prefix{
            return Err("conflicting TLS preview parameters")
        }
        private_dir(&root.join(cert_dir))?;
    }
    private_dir(&root.join(prefix))?;
    let expected=read_expected(root,expected_file)?;
    let engine=PathBuf::from(std::env::var_os("LOCALTUNNEL_ENGINE").ok_or("set trusted engine path")?);
    if !engine.is_absolute()||!engine.is_file(){return Err("invalid engine path")}
    let engine=engine.canonicalize().map_err(|_|"invalid engine path")?;
    // Exclusive among supervised operations. Manual operator commands still
    // require external coordination; a stale lock is recovery evidence.
    let _lock=acquire_lock(root,"supervisor",prefix)?;
    if let Some(rid)=request{
        write_recovery(root,&Recovery{
            mapping_id:id.into(),revision,request_id:rid.into(),prefix:prefix.into(),
            relay:relay_port,bind:m.bind_port as u16,listen,
            probe:match transport{PreviewTransport::Http=>None,PreviewTransport::Https{probe,..}=>Some(probe)},
            cert_dir:match transport{PreviewTransport::Http=>None,PreviewTransport::Https{cert_dir,..}=>Some(cert_dir.into())},
        })?;
    }
    // Reset the exclusive gateway to empty and verify the revision first.
    // This dedicated prefix must not serve other mappings.
    transport.gateway(pool,root,"clear",0,prefix,listen,"apply",None).await?;
    // Preserve recovery metadata and the empty gateway even when a prior
    // run's retained log inventory prevents admitting a new generation.
    crate::traffic::check_log_budget(&root.join(prefix),true)?;
    // Bind the guard before generating the client configuration. The
    // encrypted tunnel can only reach the business fixture via this guard.
    // The guard lives in this supervisor, not an independently orphanable process.
    let mut limiter=match m.bandwidth_bps{
        None=>None,
        Some(bps)=>{
            if bps<524288{return Err("commercial TCP bandwidth below preview minimum")}
            let guard=crate::tcp_limit::Guard::start(m.local_port as u16,(bps/8).min(125000000) as u32)?;
            if [relay_port,listen,m.bind_port as u16].contains(&guard.port())||
                matches!(transport,PreviewTransport::Https{probe,..} if probe==guard.port()){
                return Err("TCP limiter port conflicts with preview")
            }
            Some(guard)
        },
    };
    export_inner(pool,root,id,revision,relay_port,bundle,limiter.as_ref().map(|g|g.port()),m.bandwidth_bps).await?;
    let mut children=TunnelChildren(Vec::new());
    let mut meter=None;
    let result=async {
        if stop_requested(stop_marker)?{return Ok(())}
        if let Some(rid)=request{
            if !crate::runtime::keep(pool,id,rid,"starting").await?{return Ok(())}
        }
        if checked_protocol(pool,id,revision,transport.protocol()).await?.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
        children.start(&engine,&root.join(bundle).join("server.toml"))?;
        children.start(&engine,&root.join(bundle).join("client.toml"))?;
        let deadline=Instant::now()+Duration::from_secs(30);
        loop{
            if stop_requested(stop_marker)?{return Ok(())}
            if let Some(rid)=request{
                if !crate::runtime::keep(pool,id,rid,"starting").await?{return Ok(())}
            }
            if checked_protocol(pool,id,revision,transport.protocol()).await?.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
            if limiter.as_ref().is_some_and(|g|!g.healthy()){return Err("TCP limiter exited")}
            if !children.healthy(){return Err("tunnel child exited")}
            if relay_probe(&m,&expected){break}
            if Instant::now()>=deadline{return Err("relay business probe timeout")}
            std::thread::sleep(Duration::from_millis(200));
        }
        if stop_requested(stop_marker)?{return Ok(())}
        if let Some(rid)=request{
            if !crate::runtime::keep(pool,id,rid,"starting").await?{return Ok(())}
        }
        if checked_protocol(pool,id,revision,transport.protocol()).await?.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
        transport.gateway(pool,root,id,revision,prefix,listen,"apply-checked",Some(expected_file)).await?;
        if request.is_some(){meter=Some(crate::traffic::Meter::new(&root.join(prefix)));}
        // Authorization is re-read after apply and every 500ms. Database
        // errors also fail closed. DNS age is checked, not continuous DNS.
        loop{
            if stop_requested(stop_marker)?{return Ok(())}
            match checked_protocol(pool,id,revision,transport.protocol()).await{
                Ok(current) if current.bandwidth_bps==m.bandwidth_bps=>{},
                _=>return Ok(()),
            }
            if limiter.as_ref().is_some_and(|g|!g.healthy()){return Err("TCP limiter exited")}
            if !children.healthy(){return Err("tunnel child exited")}
            // Sampled every supervisor iteration. This is a soft admission
            // threshold, not a filesystem-enforced hard byte quota.
            crate::traffic::check_log_budget(&root.join(prefix),false)?;
            if let Some(rid)=request{
                if !crate::runtime::keep(pool,id,rid,"running").await?{return Ok(())}
                if let Some(meter)=meter.as_mut(){meter.sample(pool,id,revision,rid,false).await;}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }.await;
    // Stop owned tunnel processes even if the gateway clear fails.
    let stopped=children.stop();
    let limited=match limiter.as_mut(){Some(g)=>g.stop(),None=>Ok(())};
    let cleared=transport.gateway(pool,root,"clear",0,prefix,listen,"apply",None).await;
    if let (Some(meter),Some(rid))=(meter.as_mut(),request){meter.sample(pool,id,revision,rid,true).await;}
    stopped?;
    limited?;
    cleared?;
    // Only resident-owned, freshly created bundle is removed after a known
    // clean result. Failed/unknown runs retain evidence for the operator.
    if stop_marker.is_some()&&result.is_ok(){
        fs::remove_dir_all(root.join(bundle)).map_err(|_|"private bundle cleanup failed")?;
    }
    result
}


/// TLS preview deliberately requires an immutable, private operator-owned
/// certificate directory. Empty configurations reject all TLS handshakes.
pub async fn tls_gateway(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,probe:u16,cert_dir:&str,mode:&str,expected_file:Option<&str>)->Result<()>{
    tls_gateway_inner(pool,root,id,revision,name,listen,probe,cert_dir,mode,expected_file,false).await
}
async fn tls_gateway_inner(pool:&SqlitePool,root:&Path,id:&str,revision:i64,name:&str,listen:u16,probe:u16,cert_dir:&str,mode:&str,expected_file:Option<&str>,supervised:bool)->Result<()>{
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
        if m.bandwidth_bps.is_some()&&!supervised{return Err("commercial TLS gateway requires supervised TCP limiter")}
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


/// One-shot opt-in worker for a fixed mapping and fixed local parameters.
/// Waits at most 60 seconds for a fresh request; then owns exactly one run.
/// No automatic retry of unknown outcomes or remote execution parameters.
pub async fn worker(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle:&str,prefix:&str,listen:u16,expected_file:&str,transport:PreviewTransport<'_>)->Result<()>{
    checked_protocol(pool,id,revision,transport.protocol()).await?;
    let _worker_lock=acquire_worker_lock(root,prefix)?;
    let deadline=Instant::now()+Duration::from_secs(60);
    let rid=loop{
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{break rid}
        if Instant::now()>=deadline{return Err("no fresh start request")}
        std::thread::sleep(Duration::from_millis(250));
    };
    let result=supervise(pool,root,id,revision,relay_port,bundle,prefix,listen,expected_file,transport,Some(&rid),None).await;
    crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
    result
}

/// Resident foreground worker for exactly one operator-fixed mapping/revision.
/// Never reclaims a previously claimed or unknown request. New start requests
/// have independent random credentials and an independent private bundle.
pub async fn resident(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle_base:&str,prefix:&str,listen:u16,expected_file:&str,transport:PreviewTransport<'_>)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle_base)||bundle_base.len()>30||!safe_name(prefix){
        return Err("invalid resident worker parameters")
    }
    checked_protocol(pool,id,revision,transport.protocol()).await?;
    let _worker_lock=acquire_worker_lock(root,prefix)?;
    let marker=root.join(format!("worker-{prefix}.stop"));
    loop{
        if stop_requested(Some(&marker))?{return Ok(())}
        // Idle authorization checks do not require fresh DNS; each start
        // still has a fresh proof gate. A revision change needs re-provisioning.
        let state=crate::runtime::resident_state(pool,id,revision,transport.protocol()).await?;
        match state.as_deref(){
            None|Some("stopped")|Some("queued")=>{},
            _=>return Err("claimed or unknown request requires local recovery"),
        }
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{
            let bundle=format!("{bundle_base}-{rid}");
            let result=supervise(pool,root,id,revision,relay_port,&bundle,prefix,listen,expected_file,transport,Some(&rid),Some(&marker)).await;
            crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
            result?;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}


// A non-secret, immutable record written before any runtime data-plane
// action. Keep it even after successful cleanup for local diagnostics.
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery{
    mapping_id:String,revision:i64,request_id:String,prefix:String,
    relay:u16,bind:u16,listen:u16,probe:Option<u16>,cert_dir:Option<String>,
}
fn recovery_path(root:&Path,prefix:&str,rid:&str)->Result<PathBuf>{
    if !safe_name(prefix)||rid.len()!=32||!rid.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("invalid recovery identity")
    }
    Ok(root.join(format!("recovery-{prefix}-{rid}.json")))
}
fn write_recovery(root:&Path,r:&Recovery)->Result<()>{
    use std::io::Write;
    let path=recovery_path(root,&r.prefix,&r.request_id)?;
    let mut opts=fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
    let mut file=opts.open(path).map_err(|_|"recovery record unavailable")?;
    let data=serde_json::to_vec(r).map_err(|_|"recovery record serialization failed")?;
    file.write_all(&data).and_then(|_|file.sync_all()).map_err(|_|"recovery record write failed")?;
    fs::File::open(root).and_then(|d|d.sync_all()).map_err(|_|"recovery directory sync failed")?;
    Ok(())
}
fn read_recovery(root:&Path,prefix:&str,rid:&str)->Result<Recovery>{
    use std::io::Read;
    let path=recovery_path(root,prefix,rid)?;
    let m=fs::symlink_metadata(&path).map_err(|_|"recovery record missing")?;
    if !m.file_type().is_file()||!(1..=4096).contains(&m.len()){return Err("invalid recovery record")}
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode()&0o077!=0{return Err("recovery record must be private")}
    }
    let mut data=Vec::new();
    fs::File::open(path).map_err(|_|"recovery record unavailable")?.take(4097).read_to_end(&mut data).map_err(|_|"recovery record read failed")?;
    if data.len()>4096{return Err("oversize recovery record")}
    let r:Recovery=serde_json::from_slice(&data).map_err(|_|"invalid recovery record")?;
    if r.prefix!=prefix||r.request_id!=rid{return Err("recovery identity mismatch")}
    Ok(r)
}
/// Explicit offline retention maintenance; never unlink a live log.
pub fn prune_gateway_logs(root:&Path,prefix:&str)->Result<usize>{
    if !cfg!(target_os="linux"){return Err("Linux gateway logs only")}
    let _worker=guard(root,"worker",prefix)?;
    let _supervisor=guard(root,"supervisor",prefix)?;
    let dir=root.join(prefix);
    private_dir(&dir)?;
    for kind in ["worker","supervisor"]{
        if stop_requested(Some(&root.join(format!("{kind}-{prefix}.lock"))))?{
            return Err("unresolved runtime marker")
        }
    }
    for name in ["nginx.pid","localtunnel.lock","nginx.previous.conf","nginx.candidate.conf"]{
        if stop_requested(Some(&dir.join(name)))?{return Err("gateway not offline or recovery pending")}
    }
    let config_path=dir.join("nginx.conf");
    let m=fs::symlink_metadata(&config_path).map_err(|_|"gateway config unavailable")?;
    if !m.is_file()||m.len()>65536{return Err("invalid gateway config")}
    let config=fs::read_to_string(config_path).map_err(|_|"gateway config unreadable")?;
    if config.contains("lt_traffic")||config.contains("proxy_pass "){return Err("gateway must be cleared before shutdown")}
    let first=config.lines().next().ok_or("gateway marker missing")?;
    let fields:Vec<_>=first.split_ascii_whitespace().collect();
    let count=match fields.as_slice(){
        ["#","localtunnel-managed-http",_,_]=>1,
        ["#","localtunnel-managed-https",_,_,_]=>2,
        _=>return Err("invalid gateway marker"),
    };
    for address in &fields[2..2+count]{
        let socket:std::net::SocketAddr=address.parse().map_err(|_|"invalid gateway listener")?;
        if socket.ip()!=std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)||socket.port()<1024||!refused(socket.port()){
            return Err("gateway listener still reachable or invalid")
        }
    }
    // The trusted operator must also ensure Nginx has fully exited and
    // no manual gateway commands are running. Never infer process ownership
    // from an arbitrary PID or delete a PID file.
    crate::traffic::prune_offline(&dir)
}

fn refused(p:u16)->bool{
    use std::net::{SocketAddr,Ipv4Addr,TcpStream};
    let addr=SocketAddr::from((Ipv4Addr::LOCALHOST,p));
    matches!(TcpStream::connect_timeout(&addr,Duration::from_secs(1)),Err(e) if e.kind()==std::io::ErrorKind::ConnectionRefused)
}
/// Trusted local recovery only, while the operator has exclusive control of
/// the dedicated prefix/ports and no manual gateway commands are running.
/// No arbitrary PID killing, no automatic restart, and no secret deletion.
pub async fn recover(pool:&SqlitePool,root:&Path,prefix:&str,rid:&str)->Result<()>{
    if !cfg!(target_os="linux"){return Err("Linux recovery only")}
    let _worker=guard(root,"worker",prefix)?;
    let _supervisor=guard(root,"supervisor",prefix)?;
    let r=read_recovery(root,prefix,rid)?;
    let protocol=match (&r.probe,&r.cert_dir){
        (None,None)=>"http",
        (Some(_),Some(_))=>"https",
        _=>return Err("invalid recovery transport"),
    };
    port(r.relay)?;port(r.bind)?;port(r.listen)?;
    if r.relay==r.bind||r.relay==r.listen||r.bind==r.listen{return Err("invalid recovery ports")}
    let transport=match (r.probe,r.cert_dir.as_deref()){
        (None,None)=>PreviewTransport::Http,
        (Some(probe),Some(cert_dir))=>{
            port(probe)?;
            if probe==r.relay||probe==r.bind||probe==r.listen||!safe_name(cert_dir)||cert_dir==prefix{return Err("invalid recovery TLS parameters")}
            PreviewTransport::Https{probe,cert_dir}
        },
        _=>return Err("invalid recovery transport"),
    };
    // Exact request and original mapping binding; never adopt a new request.
    let eligible=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM runtime_requests q JOIN mappings m ON m.id=q.mapping_id WHERE q.mapping_id=? AND q.request_id=? AND q.mapping_revision=? AND m.revision=? AND m.bind_port=? AND m.protocol=? AND m.enabled=0 AND q.state IN ('starting','running','stopping','failed_or_unknown')")
        .bind(&r.mapping_id).bind(rid).bind(r.revision).bind(r.revision).bind(i64::from(r.bind)).bind(protocol)
        .fetch_one(pool).await.map_err(|_|"recovery state read failed")?;
    if eligible!=1{return Err("request not recoverable")}
    if !refused(r.relay)||!refused(r.bind){return Err("relay or mapping listener still reachable")}
    // Core performs real Nginx revision verification; unresolved backups
    // deliberately block this operation. Preserve private bundles/history.
    transport.gateway(pool,root,"clear",0,prefix,r.listen,"apply",None).await?;
    if !refused(r.relay)||!refused(r.bind){return Err("listener became reachable during recovery")}
    for kind in ["worker","supervisor"]{
        let path=root.join(format!("{kind}-{prefix}.lock"));
        match fs::symlink_metadata(&path){
            Ok(m) if m.file_type().is_file()=>fs::remove_file(path).map_err(|_|"stale marker cleanup failed")?,
            Ok(_)=>return Err("unsafe stale marker"),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
            Err(_)=>return Err("stale marker unavailable"),
        }
    }
    let updated=sqlx::query("UPDATE runtime_requests SET state='stopped',updated_at=unixepoch() WHERE mapping_id=? AND request_id=? AND mapping_revision=? AND state IN ('starting','running','stopping','failed_or_unknown')")
        .bind(&r.mapping_id).bind(rid).bind(r.revision).execute(pool).await.map_err(|_|"recovery result unknown")?;
    if updated.rows_affected()!=1{return Err("recovery result unknown")}
    Ok(())
}

// Local operator preview only. Never claims the HTTP runtime request state,
// which is still reserved for the web gateway executor.
#[derive(sqlx::FromRow)]
struct UdpDraft { id:String, local_port:i64, bind_port:i64, device_id:String, device_revision:i64, bandwidth_bps:Option<i64> }

async fn checked_udp(pool:&SqlitePool,id:&str,revision:i64,rid:Option<&str>)->Result<UdpDraft>{
    if id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1{
        return Err("invalid UDP mapping identity")
    }
    sqlx::query_as::<_,UdpDraft>("SELECT m.id,m.local_port,m.bind_port,d.id AS device_id,d.revision AS device_revision,(SELECT cp.max_bandwidth_bps FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id) AS bandwidth_bps FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id WHERE m.id=? AND m.revision=? AND m.enabled=0 AND m.protocol='udp' AND m.domain_id IS NULL AND m.local_host='127.0.0.1' AND m.local_port BETWEEN 1 AND 65535 AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())) AND ((? IS NULL AND NOT EXISTS (SELECT 1 FROM runtime_requests r WHERE r.mapping_id=m.id AND r.state<>'stopped')) OR EXISTS (SELECT 1 FROM runtime_requests r WHERE r.mapping_id=m.id AND r.request_id=? AND r.mapping_revision=m.revision AND r.state IN ('starting','running','stopping')))")
        .bind(id).bind(revision).bind(rid).bind(rid).fetch_optional(pool).await.map_err(|_|"UDP draft read failed")?.ok_or("UDP preview requires current authorized draft")
}

/// One mapping, each direction separately, application payload only.
/// A commercial cap may tighten but never relax the operator's budget.
/// The preview needs at least 1024 B/s for its mandatory echo probes.
fn effective_udp_limits(operator:Option<(u32,u32)>,bps:Option<i64>)->Result<Option<(u32,u32)>>{
    match bps{
        None=>Ok(operator),
        Some(bps)=>{
            if bps<8192{return Err("commercial UDP bandwidth below preview minimum")}
            let rate=(bps/8).min(240000) as u32;
            let operator_rate=operator.map_or(240000,|v|v.0);
            Ok(Some((rate.min(operator_rate),1200)))
        }
    }
}

#[cfg(test)]
mod commercial_udp_tests{
    use super::effective_udp_limits;
    #[test]
    fn commercial_cap_tightens_operator_and_manual_udp(){
        assert_eq!(effective_udp_limits(None,None).unwrap(),None);
        assert_eq!(effective_udp_limits(Some((4096,2400)),None).unwrap(),Some((4096,2400)));
        assert_eq!(effective_udp_limits(None,Some(16385)).unwrap(),Some((2048,1200)));
        assert_eq!(effective_udp_limits(Some((4096,2400)),Some(16384)).unwrap(),Some((2048,1200)));
        assert_eq!(effective_udp_limits(Some((1024,1200)),Some(16384)).unwrap(),Some((1024,1200)));
        assert_eq!(effective_udp_limits(None,Some(i64::MAX)).unwrap(),Some((240000,1200)));
        assert!(effective_udp_limits(None,Some(8191)).is_err());
        assert!(effective_udp_limits(Some((4096,1200)),Some(1)).is_err());
    }
}

fn udp_echo_probe(socket:&std::net::UdpSocket)->bool{
    let Ok(nonce)=auth::random::<32>() else{return false};
    if socket.send(&nonce).ok()!=Some(nonce.len()){return false}
    let mut buffer=[0u8;1201];
    let deadline=Instant::now()+Duration::from_millis(500);
    while Instant::now()<deadline{
        let remaining=deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()||socket.set_read_timeout(Some(remaining)).is_err(){return false}
        match socket.recv(&mut buffer){
            Ok(n) if n==nonce.len()&&buffer[..n]==nonce=>return true,
            Ok(_)=>continue,
            Err(_)=>return false,
        }
    }
    false
}

/// Explicit one-shot local echo-service preview: the operator supplies trusted
/// binaries, keys, unused ports and an actual local UDP echo fixture.
/// No automatic registration, no public bind, no HTTP activation state.
pub async fn supervise_udp(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,internal_port:u16,bundle:&str)->Result<()>{
    supervise_udp_inner(pool,root,id,revision,relay_port,internal_port,bundle,None,None,None,false).await
}

/// The operator preselects the exact revision, ports and bounded byte budget.
/// API callers cannot choose executables, ports, credentials or limit values.
pub async fn udp_worker(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,internal_port:u16,bundle:&str,rate:u32,burst:u32)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle)||relay_port<30000||internal_port<30000||relay_port==internal_port
        || !(1024..=240000).contains(&rate)||!(1200..=76800).contains(&burst){
        return Err("invalid UDP worker parameters")
    }
    private_dir(root)?;
    let _worker_lock=acquire_lock(root,"udp-worker",id)?;
    let deadline=Instant::now()+Duration::from_secs(60);
    let rid=loop{
        match crate::runtime::resident_state(pool,id,revision,"udp").await?.as_deref(){
            None|Some("stopped")|Some("queued")=>{},
            _=>return Err("claimed or unknown UDP request requires local inspection"),
        }
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{break rid}
        if Instant::now()>=deadline{return Err("no fresh UDP start request")}
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let result=supervise_udp_inner(pool,root,id,revision,relay_port,internal_port,bundle,Some(&rid),Some((rate,burst)),None,false).await;
    crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
    result
}

/// Resident operator-fixed UDP worker. A distinct request gets a distinct
/// private configuration directory and random tunnel token. Never adopt an
/// unknown claimed request, even after a process restart.
pub async fn udp_resident(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,internal_port:u16,bundle_base:&str,rate:u32,burst:u32)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle_base)||bundle_base.len()>30||relay_port<30000||internal_port<30000||relay_port==internal_port
        || !(1024..=240000).contains(&rate)||!(1200..=76800).contains(&burst){
        return Err("invalid UDP resident parameters")
    }
    if id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1{
        return Err("invalid UDP mapping identity")
    }
    private_dir(root)?;
    let _worker_lock=acquire_lock(root,"udp-worker",id)?;
    let marker=root.join(format!("udp-worker-{id}.stop"));
    loop{
        if stop_requested(Some(&marker))?{return Ok(())}
        match crate::runtime::resident_state(pool,id,revision,"udp").await?.as_deref(){
            None|Some("stopped")|Some("queued")=>{},
            _=>return Err("claimed or unknown UDP request requires local inspection"),
        }
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{
            let bundle=format!("{bundle_base}-{rid}");
            let result=supervise_udp_inner(pool,root,id,revision,relay_port,internal_port,&bundle,Some(&rid),Some((rate,burst)),Some(&marker),false).await;
            crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
            result?;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn supervise_udp_inner(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,internal_port:u16,bundle:&str,rid:Option<&str>,limits:Option<(u32,u32)>,resident_stop:Option<&Path>,device_lease:bool)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle)||relay_port<30000||internal_port<30000||relay_port==internal_port{
        return Err("invalid UDP preview parameters")
    }
    private_dir(root)?;
    let m=checked_udp(pool,id,revision,rid).await?;
    let limits=effective_udp_limits(limits,m.bandwidth_bps)?;
    if device_lease!=bundle.starts_with("udp-device-"){return Err("reserved UDP device bundle name")}
    if [relay_port,internal_port,m.bind_port as u16].contains(&(m.local_port as u16)){
        return Err("conflicting UDP preview ports")
    }
    let core=core()?;
    let engine=PathBuf::from(std::env::var_os("LOCALTUNNEL_ENGINE").ok_or("set trusted engine path")?);
    if !engine.is_absolute()||!engine.is_file(){return Err("invalid engine path")}
    let engine=engine.canonicalize().map_err(|_|"invalid engine path")?;
    let private=key("LOCALTUNNEL_SERVER_PRIVATE_KEY")?;
    let public=key("LOCALTUNNEL_SERVER_PUBLIC_KEY")?;
    let token=hex::encode(auth::random::<32>().map_err(|_|"random generation failed")?);
    // Exclusive for this mapping even with different bundle names.
    // Crash leaves a marker requiring offline operator inspection.
    let _lock=acquire_lock(root,"udp-preview",id)?;
    let stop_marker=root.join(format!("udp-stop-{bundle}"));
    if stop_requested(Some(&stop_marker))?{return Err("UDP stop marker already exists")}
    let relay=port(relay_port)?;
    let internal=port(internal_port)?;
    let ingress=port(m.bind_port as u16)?;
    // Preflight only: trusted operator must exclusively control these ports.
    // Actual process binds and echo verification remain mandatory.
    {
        // Match the engine's reusable TCP listener semantics: a previous
        // clean session may leave TIME_WAIT sockets on this exact port.
        // SO_REUSEADDR (not SO_REUSEPORT) still rejects an active listener.
        let tcp=tokio::net::TcpSocket::new_v4().map_err(|_|"UDP relay preflight socket unavailable")?;
        tcp.set_reuseaddr(true).map_err(|_|"UDP relay preflight reuse setup failed")?;
        tcp.bind(std::net::SocketAddr::from(([127,0,0,1],relay_port))).map_err(|_|"UDP relay control port unavailable")?;
        let _tcp=tcp.listen(1).map_err(|_|"UDP relay control listener unavailable")?;
        let _inner=std::net::UdpSocket::bind(&internal).map_err(|_|"UDP internal port unavailable")?;
        let _outer=std::net::UdpSocket::bind(&ingress).map_err(|_|"UDP ingress port unavailable")?;
    }
    let dir=root.join(bundle);
    mkdir(&dir)?;
    let created=(||{
        let service=format!("m_{}",m.id);
        invoke(&core,&["server-udp-config".into(),dir.join("server.toml").into_os_string(),relay.clone().into(),service.clone().into(),internal_port.to_string().into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PRIVATE_KEY",&private)])?;
        invoke(&core,&["client-udp-config".into(),dir.join("client.toml").into_os_string(),relay.clone().into(),service.into(),format!("127.0.0.1:{}",m.local_port).into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PUBLIC_KEY",&public)])?;
        use std::io::Write;
        let mut opts=fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
        let mut file=opts.open(dir.join("manifest.json")).map_err(|_|"UDP manifest unavailable")?;
        let data=serde_json::json!({"mapping_id":id,"revision":revision,"protocol":"udp","scope":"operator_loopback_udp_echo_preview","ingress_port":m.bind_port,"internal_port":internal_port,"relay_port":relay_port,"request_id":rid,"byte_rate":limits.map(|v|v.0),"burst_bytes":limits.map(|v|v.1),"commercial_bandwidth_bps":m.bandwidth_bps,"byte_limit_scope":"per_mapping_per_direction_application_payload"});
        file.write_all(data.to_string().as_bytes()).and_then(|_|file.sync_all()).map_err(|_|"UDP manifest write failed")?;
        Ok(())
    })();
    if let Err(e)=created{
        let _=fs::remove_dir_all(&dir);
        return Err(e)
    }
    // The generated client file validates the public key and endpoint, but
    // this mode must never start a co-located agent from that file.
    if device_lease{fs::remove_file(dir.join("client.toml")).map_err(|_|"unused client config cleanup failed")?;}
    let mut tunnel=TunnelChildren(Vec::new());
    let mut entrance=TunnelChildren(Vec::new());
    let result=async{
        let current=checked_udp(pool,id,revision,rid).await?;
        if current.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
        if device_lease&&current.device_revision!=m.device_revision{return Err("device revision changed")}
        if let Some(rid)=rid{if !crate::runtime::keep(pool,id,rid,"starting").await?{return Ok(())}}
        tunnel.start(&engine,&dir.join("server.toml"))?;
        if !device_lease{tunnel.start(&engine,&dir.join("client.toml"))?;}
        let mut cmd=Command::new(&core);
        if let Some((rate,burst))=limits{
            cmd.args(["udp-guard-limited",&ingress,&internal,&rate.to_string(),&burst.to_string()]);
        }else{
            cmd.args(["udp-guard",&ingress,&internal]);
        }
        cmd.env_clear().env("PATH","/usr/bin:/bin")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        protect_child(&mut cmd)?;
        entrance.0.push(cmd.spawn().map_err(|_|"UDP guard launch failed")?);
        let probe=std::net::UdpSocket::bind("127.0.0.1:0").map_err(|_|"UDP probe bind failed")?;
        probe.connect(&ingress).map_err(|_|"UDP probe connect failed")?;
        let deadline=Instant::now()+Duration::from_secs(30);
        let lease_deadline=Instant::now()+Duration::from_secs(crate::devices::UDP_LEASE_SECONDS as u64);
        if device_lease{
            let rid=rid.ok_or("missing UDP device request")?;
            let now=sqlx::query_scalar::<_,i64>("SELECT unixepoch()").fetch_one(pool).await.map_err(|_|"lease clock unavailable")?;
            let lease=crate::devices::UdpLease{device_id:m.device_id.clone(),device_revision:m.device_revision,
                mapping_id:id.into(),mapping_revision:revision,request_id:rid.into(),relay_port,local_port:m.local_port as u16,
                token:token.clone(),server_key:public.clone(),expires_at:now+crate::devices::UDP_LEASE_SECONDS};
            use std::io::Write;
            let mut opts=fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
            let mut file=opts.open(dir.join("lease.pending")).map_err(|_|"lease creation failed")?;
            let bytes=serde_json::to_vec(&lease).map_err(|_|"lease serialization failed")?;
            file.write_all(&bytes).and_then(|_|file.sync_all()).map_err(|_|"lease write failed")?;
            fs::rename(dir.join("lease.pending"),dir.join("lease.json")).map_err(|_|"lease publication failed")?;
        }
        let mut ready=false;
        loop{
            if device_lease&&Instant::now()>=lease_deadline{return Ok(())}
            if stop_requested(Some(&stop_marker))?||stop_requested(resident_stop)?{return Ok(())}
            if let Some(rid)=rid{
                if !crate::runtime::keep(pool,id,rid,if ready{"running"}else{"starting"}).await?{return Ok(())}
            }
            let current=checked_udp(pool,id,revision,rid).await?;
            // No live reconfiguration or silent continuation on a changed
            // rate. Close the owned ingress and relay; require a fresh run.
            if current.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
            if device_lease&&current.device_revision!=m.device_revision{return Err("device revision changed")}
            let healthy=if device_lease{tunnel.0.len()==1&&matches!(tunnel.0[0].try_wait(),Ok(None))}else{tunnel.healthy()};
            if !healthy||!matches!(entrance.0[0].try_wait(),Ok(None)){
                return Err("UDP preview child exited")
            }
            if udp_echo_probe(&probe){
                if !ready{
                    if let Some(rid)=rid{if !crate::runtime::keep(pool,id,rid,"running").await?{return Ok(())}}
                    println!("UDP_PREVIEW_READY");
                    use std::io::Write;
                    std::io::stdout().flush().map_err(|_|"UDP preview output failed")?;
                    ready=true;
                }
            }else if ready||Instant::now()>=deadline{
                return Err("UDP echo probe failed")
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }.await;
    // Close admission before relay and agent. Do not remove retained secrets
    // or mark a preview stopped if owned children cannot be reaped.
    let entrance_stopped=entrance.stop();
    let tunnel_stopped=tunnel.stop();
    if device_lease{
        for name in ["lease.json","lease.pending"]{
            match fs::remove_file(dir.join(name)){Ok(())=>{},Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(_)=>return Err("UDP lease cleanup failed")}
        }
    }
    entrance_stopped?;
    tunnel_stopped?;
    if device_lease{
        fs::remove_file(dir.join("server.toml")).map_err(|_|"UDP relay configuration cleanup failed")?;
    }
    result
}


/// One-shot device-connected relay preview. The request selects a single
/// mapping; the operator fixes all ports and resource limits. No local agent
/// is spawned. A separate authenticated device must connect before ready.
pub async fn udp_device_worker(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,internal_port:u16,rate:u32,burst:u32)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(id)||id.len()!=32||revision<1||relay_port<30000||internal_port<30000||relay_port==internal_port
        || !(1024..=240000).contains(&rate)||!(1200..=76800).contains(&burst){return Err("invalid UDP device worker parameters")}
    private_dir(root)?;
    let _worker_lock=acquire_lock(root,"udp-worker",id)?;
    let deadline=Instant::now()+Duration::from_secs(60);
    let rid=loop{
        match crate::runtime::resident_state(pool,id,revision,"udp").await?.as_deref(){
            None|Some("stopped")|Some("queued")=>{},
            _=>return Err("claimed or unknown UDP request requires local inspection"),
        }
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{break rid}
        if Instant::now()>=deadline{return Err("no fresh UDP start request")}
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let bundle=format!("udp-device-{rid}");
    let result=supervise_udp_inner(pool,root,id,revision,relay_port,internal_port,&bundle,Some(&rid),Some((rate,burst)),None,true).await;
    crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
    result
}


// Independent raw TCP loopback echo preview. Never infer reachability from
// an open relay control socket: prove a nonce round trip through the guard.
#[derive(sqlx::FromRow)]
struct TcpDraft{local_port:i64,bind_port:i64,bandwidth_bps:Option<i64>}
async fn checked_tcp(pool:&SqlitePool,id:&str,revision:i64,rid:&str)->Result<TcpDraft>{
    sqlx::query_as::<_,TcpDraft>("SELECT m.local_port,m.bind_port,cp.max_bandwidth_bps AS bandwidth_bps FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN tenants t ON t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id JOIN runtime_requests r ON r.mapping_id=m.id WHERE m.id=? AND m.revision=? AND m.protocol='tcp' AND m.enabled=0 AND m.domain_id IS NULL AND m.local_host='127.0.0.1' AND m.local_port BETWEEN 1 AND 65535 AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()) AND r.request_id=? AND r.mapping_revision=m.revision AND r.state IN ('starting','running','stopping')")
        .bind(id).bind(revision).bind(rid).fetch_optional(pool).await.map_err(|_|"TCP draft read failed")?.ok_or("TCP draft authorization changed")
}
fn tcp_echo_probe(port:u16)->bool{
    use std::io::{Read,Write};
    let Ok(nonce)=auth::random::<32>() else{return false};
    let Ok(mut s)=std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127,0,0,1],port)),Duration::from_millis(500)) else{return false};
    if s.set_write_timeout(Some(Duration::from_millis(500))).is_err()||s.set_read_timeout(Some(Duration::from_millis(500))).is_err(){return false}
    if s.write_all(&nonce).is_err(){return false}
    // Bounded read count as well as timeout; a slowly trickling peer may
    // not hold the authorization loop indefinitely.
    let deadline=Instant::now()+Duration::from_millis(500);
    let mut buf=[0;32];
    let mut n=0;
    while n<buf.len(){
        let remaining=deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()||s.set_read_timeout(Some(remaining)).is_err(){return false}
        match s.read(&mut buf[n..]){Ok(k) if k>0=>n+=k,_=>return false}
    }
    buf==nonce
}
pub async fn tcp_worker(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle:&str,operator_rate:u32)->Result<()>{
    if !cfg!(target_os="linux")||!safe_name(bundle)||id.len()!=32||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||revision<1||relay_port<30000||!(65536..=125000000).contains(&operator_rate){return Err("invalid TCP worker parameters")}
    private_dir(root)?;
    let _lock=acquire_lock(root,"tcp-worker",id)?;
    let deadline=Instant::now()+Duration::from_secs(60);
    let rid=loop{
        match crate::runtime::resident_state(pool,id,revision,"tcp").await?.as_deref(){
            None|Some("stopped")|Some("queued")=>{},
            _=>return Err("claimed or unknown TCP request requires local inspection"),
        }
        if let Some(rid)=crate::runtime::claim(pool,id,revision).await?{break rid}
        if Instant::now()>=deadline{return Err("no fresh TCP start request")}
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let result=tcp_run(pool,root,id,revision,relay_port,bundle,operator_rate,&rid).await;
    crate::runtime::finish(pool,id,&rid,result.is_ok()).await?;
    result
}
async fn tcp_run(pool:&SqlitePool,root:&Path,id:&str,revision:i64,relay_port:u16,bundle:&str,operator_rate:u32,rid:&str)->Result<()>{
    let m=checked_tcp(pool,id,revision,rid).await?;
    let bind=m.bind_port as u16;
    let local=m.local_port as u16;
    if local==bind||local==relay_port{return Err("TCP worker port collision")}
    let rate=match m.bandwidth_bps{
        Some(bps) if bps<524288=>return Err("commercial TCP bandwidth below preview minimum"),
        Some(bps)=>operator_rate.min((bps/8).min(125000000) as u32),
        None=>operator_rate,
    };
    let core=core()?;
    let engine=PathBuf::from(std::env::var_os("LOCALTUNNEL_ENGINE").ok_or("set trusted engine path")?);
    if !engine.is_absolute()||!engine.is_file(){return Err("invalid engine path")}
    let engine=engine.canonicalize().map_err(|_|"invalid engine path")?;
    let private=key("LOCALTUNNEL_SERVER_PRIVATE_KEY")?;
    let public=key("LOCALTUNNEL_SERVER_PUBLIC_KEY")?;
    let token=hex::encode(auth::random::<32>().map_err(|_|"random generation failed")?);
    // Reject occupied listeners before creating any secret material.
    for p in [relay_port,bind]{
        let tcp=tokio::net::TcpSocket::new_v4().map_err(|_|"TCP preflight socket unavailable")?;
        tcp.set_reuseaddr(true).map_err(|_|"TCP preflight setup failed")?;
        tcp.bind(std::net::SocketAddr::from(([127,0,0,1],p))).map_err(|_|"TCP preview port unavailable")?;
        let _listener=tcp.listen(1).map_err(|_|"TCP preview listener unavailable")?;
    }
    let mut guard=crate::tcp_limit::Guard::start(local,rate)?;
    if [bind,relay_port,local].contains(&guard.port()){return Err("TCP limiter port collision")}
    let dir=root.join(bundle);
    mkdir(&dir)?;
    let created=(||{
        let service=format!("m_{id}");
        let relay=port(relay_port)?;
        invoke(&core,&["server-config".into(),dir.join("server.toml").into_os_string(),relay.clone().into(),service.clone().into(),bind.to_string().into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PRIVATE_KEY",&private)])?;
        invoke(&core,&["client-config".into(),dir.join("client.toml").into_os_string(),relay.into(),service.into(),format!("127.0.0.1:{}",guard.port()).into()],
            &[("LOCALTUNNEL_TOKEN",&token),("LOCALTUNNEL_SERVER_PUBLIC_KEY",&public)])?;
        use std::io::Write;
        let mut opts=fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
        let mut file=opts.open(dir.join("manifest.json")).map_err(|_|"TCP manifest unavailable")?;
        let manifest=serde_json::json!({"mapping_id":id,"revision":revision,"request_id":rid,"protocol":"tcp","scope":"operator_loopback_tcp_echo_preview","bind_port":bind,"relay_port":relay_port,"tcp_limiter_port":guard.port(),"byte_rate":rate,"commercial_bandwidth_bps":m.bandwidth_bps,"byte_limit_scope":"per_mapping_per_direction_tcp_stream"});
        file.write_all(manifest.to_string().as_bytes()).and_then(|_|file.sync_all()).map_err(|_|"TCP manifest write failed")?;
        Ok(())
    })();
    if let Err(e)=created{let _=fs::remove_dir_all(&dir);return Err(e)}
    let mut children=TunnelChildren(Vec::new());
    let result=async{
        if !crate::runtime::keep(pool,id,rid,"starting").await?{return Ok(())}
        if checked_tcp(pool,id,revision,rid).await?.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
        children.start(&engine,&dir.join("server.toml"))?;
        children.start(&engine,&dir.join("client.toml"))?;
        let deadline=Instant::now()+Duration::from_secs(30);
        let mut ready=false;
        loop{
            if !crate::runtime::keep(pool,id,rid,if ready{"running"}else{"starting"}).await?{return Ok(())}
            if checked_tcp(pool,id,revision,rid).await?.bandwidth_bps!=m.bandwidth_bps{return Ok(())}
            if !children.healthy()||!guard.healthy(){return Err("TCP worker child or guard exited")}
            if !ready{
                if tcp_echo_probe(bind){
                    if !crate::runtime::keep(pool,id,rid,"running").await?{return Ok(())}
                    println!("TCP_PREVIEW_READY");
                    use std::io::Write;
                    std::io::stdout().flush().map_err(|_|"TCP readiness output failed")?;
                    ready=true;
                }else if Instant::now()>=deadline{return Err("TCP echo readiness timeout")}
            }
            // After actual startup proof, monitor authorization and child
            // health, not arbitrary application protocol liveness.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }.await;
    let stopped=children.stop();
    let limited=guard.stop();
    stopped?;
    limited?;
    if result.is_ok(){
        fs::remove_dir_all(&dir).map_err(|_|"TCP bundle cleanup failed")?;
    }
    result
}
