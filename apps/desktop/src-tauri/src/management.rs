//! Explicit loopback-only management preview. No server-supplied executable
//! configuration, no automatic tunnel activation, no browser-held bearer.
use serde::{Deserialize,Serialize};
use std::{path::{Path,PathBuf},time::{Duration,Instant},sync::Mutex};
use zeroize::{Zeroize,Zeroizing};
use crate::credentials;
use tauri::Manager;
use sha2::{Digest,Sha256};
static ACTION:tokio::sync::Mutex<()>=tokio::sync::Mutex::const_new(());
const LIMIT:usize=256*1024;
const DENIED:&str="管理凭据无效或已吊销";
const PERIOD:Duration=Duration::from_secs(30);
// Network actions are serialized by ACTION. Snapshot readers never wait
// for the network, and no token is retained in the observable state.
#[derive(Default)]
struct AutoState{
    blocked:bool,
    next:Option<Instant>,
    observation:Option<SyncResult>,
    error:Option<String>,
}
static AUTO:Mutex<AutoState>=Mutex::new(AutoState{blocked:false,next:None,observation:None,error:None});
#[derive(Serialize)]
pub struct Snapshot{
    observation:Option<SyncResult>,
    error:Option<String>,
    blocked:bool,
}
pub fn snapshot()->Result<Snapshot,String>{
    let a=AUTO.lock().map_err(|_|"管理状态不可用")?;
    Ok(Snapshot{observation:a.observation.clone(),error:a.error.clone(),blocked:a.blocked})
}
fn reset_auto()->Result<(),String>{
    *AUTO.lock().map_err(|_|"管理状态不可用")?=AutoState::default();
    Ok(())
}
fn record(result:&Result<SyncResult,String>)->Result<(),String>{
    let mut a=AUTO.lock().map_err(|_|"管理状态不可用")?;
    a.next=Some(Instant::now()+PERIOD);
    match result{
        Ok(s)=>{a.observation=Some(s.clone());a.error=None;a.blocked=false;}
        Err(e)=>{a.observation=None;a.error=Some(e.clone());if e==DENIED{a.blocked=true;}}
    }
    Ok(())
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved{port:u16,id:String,device_token:String}
impl Drop for Saved{fn drop(&mut self){self.device_token.zeroize()}}
#[derive(Serialize)]
pub struct Public{port:u16,id:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolled{id:String,device_token:String}
impl Drop for Enrolled{fn drop(&mut self){self.device_token.zeroize()}}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity{id:String,name:String,enabled:bool,revision:i64}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata{id:String,node_id:String,domain_id:Option<String>,protocol:String,local_host:String,local_port:u16,bind_port:u16,enabled:bool,revision:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config{device_id:String,revision:i64,scope:String,mappings:Vec<Metadata>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt{last_seen_at:i64,heartbeat_interval_seconds:i64}
#[derive(Clone,Serialize)]
pub struct SyncResult{id:String,name:String,revision:i64,mappings:Vec<Metadata>,last_seen_at:i64,heartbeat_interval_seconds:i64}
fn hex(s:&str,len:usize)->bool{s.len()==len&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn valid_token(s:&str,prefix:&str)->bool{s.strip_prefix(prefix).is_some_and(|v|hex(v,64))}
fn validate_port(port:u16)->Result<(),String>{if port<1024{Err("请输入本机管理服务高位端口".into())}else{Ok(())}}
fn load(dir:&Path)->Result<Option<Saved>,String>{
    let Some(data)=credentials::load_management(dir)? else{return Ok(None)};
    let saved:Saved=serde_json::from_slice(&data).map_err(|_|"管理凭据格式无效")?;
    validate_port(saved.port)?;
    if !hex(&saved.id,32)||!valid_token(&saved.device_token,"ltdev_"){return Err("管理凭据格式无效".into())}
    Ok(Some(saved))
}
fn client()->Result<reqwest::Client,String>{
    reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(8))
        .build().map_err(|_|"本机管理连接初始化失败".into())
}
async fn json<T:serde::de::DeserializeOwned>(request:reqwest::RequestBuilder,expected:u16)->Result<T,String>{
    let mut response=request.send().await.map_err(|_|"本机管理服务不可达")?;
    if response.status().as_u16()!=expected{
        return Err(match response.status().as_u16(){401=>DENIED,409=>"管理状态冲突，请检查后台",429=>"管理请求过于频繁",_=>"管理服务拒绝请求"}.into())
    }
    if response.content_length().is_some_and(|n|n>LIMIT as u64){return Err("管理响应过大".into())}
    let mut bytes=Zeroizing::new(Vec::new());
    while let Some(chunk)=response.chunk().await.map_err(|_|"管理响应读取失败")?{
        if bytes.len()+chunk.len()>LIMIT{return Err("管理响应过大".into())}
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_|"管理响应格式无效".into())
}
pub async fn saved(dir:&Path)->Result<Option<Public>,String>{
    let _guard=ACTION.lock().await;
    Ok(load(dir)?.map(|s|Public{port:s.port,id:s.id.clone()}))
}
pub async fn enroll(dir:&Path,port:u16,name:String,pairing_code:String)->Result<Public,String>{
    let code=Zeroizing::new(pairing_code);
    let _guard=ACTION.lock().await;
    validate_port(port)?;
    if !valid_token(&code,"ltpair_")||name.trim().is_empty()||name.trim().len()>128||name.chars().any(char::is_control){
        return Err("配对码或设备名称无效".into())
    }
    if load(dir)?.is_some(){return Err("请先在后台吊销旧设备，再移除本地凭据".into())}
    let body=Zeroizing::new(serde_json::to_string(&serde_json::json!({"pairing_code":code.as_str(),"name":name.trim()})).map_err(|_|"配对请求无效")?);
    let c=client()?;
    let enrolled:Enrolled=json(c.post(format!("http://127.0.0.1:{port}/api/v1/devices/enroll"))
        .header("Content-Type","application/json").body(body.to_string()),201).await?;
    if !hex(&enrolled.id,32)||!valid_token(&enrolled.device_token,"ltdev_"){return Err("配对响应无效".into())}
    let s=Saved{port,id:enrolled.id.clone(),device_token:enrolled.device_token.clone()};
    let encoded=Zeroizing::new(serde_json::to_vec(&s).map_err(|_|"管理凭据格式无效")?);
    credentials::save_management(dir,&encoded).map_err(|_|"设备可能已登记，但本地凭据保存失败；请在后台吊销后重新配对")?;
    reset_auto()?;
    Ok(Public{port,id:s.id.clone()})
}
async fn sync_saved(s:&Saved)->Result<SyncResult,String>{
    let c=client()?;
    let base=format!("http://127.0.0.1:{}/api/v1/devices/{}",s.port,s.id);
    let identity:Identity=json(c.get(format!("{base}/identity")).bearer_auth(&s.device_token),200).await?;
    if identity.id!=s.id||!identity.enabled||identity.revision<1{return Err("设备身份不一致".into())}
    let config:Config=json(c.get(format!("{base}/config")).bearer_auth(&s.device_token),200).await?;
    if config.device_id!=s.id||config.scope!="desired_metadata_only"||config.revision<identity.revision||config.mappings.len()>64||
        config.mappings.iter().any(|m|!hex(&m.id,32)||!matches!(m.protocol.as_str(),"http"|"https"|"tcp"|"udp")||(matches!(m.protocol.as_str(),"tcp"|"udp")&&m.domain_id.is_some())||m.local_host!="127.0.0.1"||m.local_port==0||!(20000..=29999).contains(&m.bind_port)||m.revision<1){
        return Err("管理配置元数据无效".into())
    }
    // No managed data-plane has been applied. Report only receipt of the
    // desired metadata revision and idle managed state, not local manual tunnel.
    let body=serde_json::json!({"reported_revision":config.revision,"reported_state":"idle"}).to_string();
    let receipt:Receipt=json(c.post(format!("{base}/status")).bearer_auth(&s.device_token)
        .header("Content-Type","application/json").body(body),200).await?;
    if receipt.last_seen_at<1||receipt.heartbeat_interval_seconds!=30{return Err("管理心跳响应无效".into())}
    Ok(SyncResult{id:s.id.clone(),name:identity.name,revision:config.revision,mappings:config.mappings,last_seen_at:receipt.last_seen_at,heartbeat_interval_seconds:receipt.heartbeat_interval_seconds})
}
pub async fn sync(dir:&Path)->Result<SyncResult,String>{
    let _guard=ACTION.lock().await;
    if AUTO.lock().map_err(|_|"管理状态不可用")?.blocked{return Err(DENIED.into())}
    let result=match load(dir){
        Ok(Some(s))=>sync_saved(&s).await,
        Ok(None)=>Err("请先配对设备".into()),
        Err(e)=>Err(e),
    };
    record(&result)?;
    result
}
/// Explicit local draft import only. No server-provided relay endpoint,
/// key, executable, token or permission to activate a tunnel.
fn select_udp_draft(s:&SyncResult,id:&str,expected_revision:i64,mapping_revision:i64)->Result<crate::profile::ProfileMapping,String>{
    if !hex(id,32)||expected_revision<1||mapping_revision<1||s.revision!=expected_revision{
        return Err("管理配置版本已变化，请重新确认".into())
    }
    let mut rows=s.mappings.iter().filter(|m|m.id==id);
    let m=rows.next().ok_or("管理映射不存在")?;
    if rows.next().is_some()||m.revision!=mapping_revision||m.protocol!="udp"||m.enabled
        ||m.domain_id.is_some()||m.local_host!="127.0.0.1"||m.local_port==0{
        return Err("仅允许导入当前禁用 UDP 草稿".into())
    }
    Ok(crate::profile::ProfileMapping{protocol:"udp".into(),name:format!("m_{}",m.id),local_port:m.local_port})
}
pub async fn import_udp_draft(dir:&Path,id:&str,expected_revision:i64,mapping_revision:i64)->Result<crate::profile::ProfileMapping,String>{
    let _guard=ACTION.lock().await;
    if AUTO.lock().map_err(|_|"管理状态不可用")?.blocked{return Err(DENIED.into())}
    // Fresh identity, coherent metadata and successful authenticated
    // heartbeat are mandatory. Never import from cached UI state.
    let result=match load(dir){
        Ok(Some(s))=>sync_saved(&s).await,
        Ok(None)=>Err("请先配对设备".into()),
        Err(e)=>Err(e),
    };
    record(&result)?;
    select_udp_draft(&result?,id,expected_revision,mapping_revision)
}
pub async fn forget(dir:&Path,app:&tauri::AppHandle)->Result<(),String>{
    let _guard=ACTION.lock().await;
    {
        let state=app.state::<Mutex<crate::Supervisor>>();
        let mut supervisor=state.lock().map_err(|_|"进程状态不可用")?;
        if supervisor.managed_session().is_some(){supervisor.stop()?;}
        // Invalidate any pending start, including one captured before forget.
        supervisor.generation=supervisor.generation.wrapping_add(1);
    }
    credentials::forget_management(dir)?;
    reset_auto()
}
// Native task lives for the desktop process (including hidden tray window).
// One in-flight action at a time. A manual sync resets the same deadline;
// a rejected credential is not retried until explicit removal/re-enrollment
// or a new desktop process validates the saved credential again.
pub async fn automatic(dir:PathBuf){
    loop{
        tokio::time::sleep(Duration::from_secs(1)).await;
        let Ok(_guard)=ACTION.try_lock() else{continue};
        let due=match AUTO.lock(){
            Ok(a)=>!a.blocked&&a.next.is_none_or(|n|Instant::now()>=n),
            Err(_)=>return,
        };
        if !due{continue}
        match load(&dir){
            Ok(Some(s))=>{
                let result=sync_saved(&s).await;
                if record(&result).is_err(){return}
            },
            Ok(None)=>{
                if let Ok(mut a)=AUTO.lock(){a.observation=None;a.error=None;a.next=Some(Instant::now()+PERIOD);}else{return}
            },
            Err(e)=>{if record(&Err(e)).is_err(){return}}
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant{
    device_id:String,device_revision:i64,mapping_id:String,mapping_revision:i64,
    request_id:String,relay_port:u16,local_port:u16,token:String,server_key:String,expires_at:i64,
}
impl Drop for Grant{fn drop(&mut self){self.token.zeroize()}}
#[derive(Clone,PartialEq,Eq)]
struct Binding{
    device_id:String,device_revision:i64,mapping_id:String,mapping_revision:i64,
    request_id:String,relay_port:u16,local_port:u16,token_digest:[u8;32],server_key:String,expires_at:i64,
}
#[derive(Clone,PartialEq,Eq)]
pub(crate) struct LeaseSession{
    binding:Binding,
    management_port:u16,
    pub(crate) deadline:Instant,
}
fn unix_ms()->Result<i64,String>{
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .ok().and_then(|d|i64::try_from(d.as_millis()).ok()).ok_or("本机时钟无效".into())
}
fn validate_grant(g:&Grant,s:&Saved,id:&str,revision:i64,mapping_revision:i64,local_port:u16,
    started:Instant,started_ms:i64)->Result<LeaseSession,String>{
    if g.device_id!=s.id||g.device_revision!=revision||g.mapping_id!=id||g.mapping_revision!=mapping_revision||
        !hex(id,32)||!hex(&g.request_id,32)||revision<1||mapping_revision<1||
        local_port==0||g.local_port!=local_port||g.relay_port<30000||g.relay_port==local_port||
        !hex(&g.token,64)||g.server_key.len()!=44{
        return Err("UDP 授权配置不匹配".into())
    }
    let expires_ms=g.expires_at.checked_mul(1000).ok_or("UDP 授权时间无效")?;
    let remaining=expires_ms.checked_sub(started_ms).ok_or("UDP 授权时间无效")?;
    if !(1..=60_000).contains(&remaining){return Err("UDP 授权已过期或超出60秒上限".into())}
    let deadline=started+Duration::from_millis(remaining as u64);
    if Instant::now()>=deadline{return Err("UDP 授权已过期".into())}
    Ok(LeaseSession{management_port:s.port,deadline,binding:Binding{
        device_id:g.device_id.clone(),device_revision:revision,mapping_id:id.into(),mapping_revision,
        request_id:g.request_id.clone(),relay_port:g.relay_port,local_port,token_digest:Sha256::digest(g.token.as_bytes()).into(),
        server_key:g.server_key.clone(),expires_at:g.expires_at}})
}
async fn fetch_grant(s:&Saved,id:&str,revision:i64,mapping_revision:i64,local_port:u16)->Result<(Grant,LeaseSession),String>{
    let c=client()?;
    let started=Instant::now();
    let started_ms=unix_ms()?;
    let body=serde_json::json!({"mapping_id":id,"device_revision":revision,"mapping_revision":mapping_revision}).to_string();
    let grant:Grant=json(c.post(format!("http://127.0.0.1:{}/api/v1/devices/{}/udp-lease",s.port,s.id))
        .bearer_auth(&s.device_token).header("Content-Type","application/json").body(body),200).await?;
    let session=validate_grant(&grant,s,id,revision,mapping_revision,local_port,started,started_ms)?;
    Ok((grant,session))
}
fn request(g:&Grant,engine:String)->crate::StartRequest{
    crate::StartRequest{engine,remote:format!("127.0.0.1:{}",g.relay_port),server_key:g.server_key.clone(),
        mappings:vec![crate::Mapping{protocol:"udp".into(),name:format!("m_{}",g.mapping_id),local_port:g.local_port,token:g.token.clone()}]}
}
pub async fn start_udp(app:&tauri::AppHandle,dir:&Path,id:&str,revision:i64,mapping_revision:i64)->Result<crate::Status,String>{
    let _guard=ACTION.lock().await;
    if AUTO.lock().map_err(|_|"管理状态不可用")?.blocked{return Err(DENIED.into())}
    let generation={
        let state=app.state::<Mutex<crate::Supervisor>>();
        let mut supervisor=state.lock().map_err(|_|"进程状态不可用")?;
        if supervisor.status()?.state=="running"{return Err("请先停止现有隧道".into())}
        supervisor.generation
    };
    let s=load(dir)?.ok_or("请先配对设备")?;
    let result=sync_saved(&s).await;
    record(&result)?;
    let draft=select_udp_draft(&result?,id,revision,mapping_revision)?;
    let (grant,session)=match fetch_grant(&s,id,revision,mapping_revision,draft.local_port).await{
        Ok(value)=>value,
        Err(e)=>{if e==DENIED{record(&Err(e.clone()))?;}return Err(e)}
    };
    let resource=app.path().resource_dir().map_err(|_|"无法定位应用资源目录")?;
    let engine=crate::bundled_engine(&resource)?.to_str().ok_or("引擎路径编码无效")?.to_owned();
    let state=app.state::<Mutex<crate::Supervisor>>();
    let mut supervisor=state.lock().map_err(|_|"进程状态不可用")?;
    if supervisor.generation!=generation{return Err("隧道状态已变化，请重新确认".into())}
    supervisor.start_managed(request(&grant,engine),session,dir)
}
async fn verify_session(dir:&Path,session:&LeaseSession)->Result<(),String>{
    let s=load(dir)?.ok_or("管理凭据已移除")?;
    let b=&session.binding;
    if s.id!=b.device_id||s.port!=session.management_port{return Err("管理设备已变化".into())}
    let (_,current)=fetch_grant(&s,&b.mapping_id,b.device_revision,b.mapping_revision,b.local_port).await?;
    // Never extend the original deadline, even if the server sends a new grant.
    if current.binding!=*b{return Err("UDP 授权已变化".into())}
    Ok(())
}
pub async fn monitor(app:tauri::AppHandle,dir:PathBuf){
    loop{
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(_guard)=ACTION.try_lock() else{continue};
        let session={
            let state=app.state::<Mutex<crate::Supervisor>>();
            let Ok(supervisor)=state.lock() else{return};
            supervisor.managed_session().cloned()
        };
        let Some(session)=session else{continue};
        if verify_session(&dir,&session).await.is_err(){
            let state=app.state::<Mutex<crate::Supervisor>>();
            let Ok(mut supervisor)=state.lock() else{return};
            // A stale response must never stop a subsequent manual session.
            if supervisor.managed_session()==Some(&session){
                if supervisor.stop().is_ok(){supervisor.last_error=Some("UDP 管理授权失效，隧道已停止".into());}
            }
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn udp_import_rejects_stale_or_ineligible_metadata(){
        let id="a".repeat(32);
        let mut s=SyncResult{id:"b".repeat(32),name:"fixture".into(),revision:5,
            mappings:vec![Metadata{id:id.clone(),node_id:"node".into(),domain_id:None,
                protocol:"udp".into(),local_host:"127.0.0.1".into(),local_port:5353,
                bind_port:24001,enabled:false,revision:2}],last_seen_at:1,heartbeat_interval_seconds:30};
        let draft=select_udp_draft(&s,&id,5,2).unwrap();
        assert_eq!(draft.name,format!("m_{id}"));
        assert_eq!(draft.local_port,5353);
        assert_eq!(draft.protocol,"udp");
        assert!(select_udp_draft(&s,&id,4,2).is_err());
        assert!(select_udp_draft(&s,&id,5,1).is_err());
        assert!(select_udp_draft(&s,&"c".repeat(32),5,2).is_err());
        s.mappings[0].enabled=true;
        assert!(select_udp_draft(&s,&id,5,2).is_err());
        s.mappings[0].enabled=false;
        s.mappings[0].protocol="tcp".into();
        assert!(select_udp_draft(&s,&id,5,2).is_err());
        s.mappings[0].protocol="udp".into();
        s.mappings.push(s.mappings[0].clone());
        assert!(select_udp_draft(&s,&id,5,2).is_err());
    }

    #[test]
    fn grant_validation_rejects_scope_and_expiry() {
        let s=Saved{port:1431,id:"a".repeat(32),device_token:format!("ltdev_{}","b".repeat(64))};
        let id="c".repeat(32);
        let now=unix_ms().unwrap();
        let at=Instant::now();
        let mut g=Grant{device_id:s.id.clone(),device_revision:3,mapping_id:id.clone(),mapping_revision:2,
            request_id:"d".repeat(32),relay_port:31000,local_port:5353,token:"e".repeat(64),
            server_key:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),expires_at:now/1000+20};
        assert!(validate_grant(&g,&s,&id,3,2,5353,at,now).is_ok());
        assert!(validate_grant(&g,&s,&id,4,2,5353,at,now).is_err());
        assert!(validate_grant(&g,&s,&id,3,1,5353,at,now).is_err());
        assert!(validate_grant(&g,&s,&id,3,2,5354,at,now).is_err());
        g.expires_at=now/1000+61;
        assert!(validate_grant(&g,&s,&id,3,2,5353,at,now).is_err());
        g.expires_at=now/1000;
        assert!(validate_grant(&g,&s,&id,3,2,5353,at,now).is_err());
        g.expires_at=now/1000+20;
        g.relay_port=1234;
        assert!(validate_grant(&g,&s,&id,3,2,5353,at,now).is_err());
    }

    // The Linux worker/API has its own real management integration test.
    // This Windows test uses a bounded disposable HTTP response fixture,
    // actual DPAPI, actual HTTP request parsing and the pinned real engine.
    #[test]
    #[ignore = "requires real Rathole executable; run explicitly in hosted CI"]
    fn real_engine_supervisor_lifecycle_managed_udp() {
        use std::{io::{BufRead,BufReader,Read,Write},net::{TcpListener,UdpSocket},
            process::{Command,Stdio},thread};
        let engine=std::env::var("LOCALTUNNEL_TEST_ENGINE").expect("test engine required");
        let output=Command::new(&engine).arg("--genkey").output().unwrap();
        assert!(output.status.success());
        let keys=String::from_utf8(output.stdout).unwrap();
        fn key<'a>(keys:&'a str,label:&str)->&'a str {
            let tail=keys.split_once(label).unwrap().1.trim_start();
            let n=tail.bytes().take_while(|b|b.is_ascii_alphanumeric()||matches!(b,b'+'|b'/'|b'=')).count();
            assert_eq!(n,44);
            &tail[..n]
        }
        let private=key(&keys,"Private Key:");
        let public=key(&keys,"Public Key:").to_owned();
        let relay_socket=TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr=relay_socket.local_addr().unwrap();
        // High ephemeral Windows ports are required by the product contract.
        assert!(relay_addr.port()>=30000);
        let mapped=UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped_addr=mapped.local_addr().unwrap();
        let local=UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_port=local.local_addr().unwrap().port();
        assert_ne!(local_port,relay_addr.port());
        local.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let running=stop.clone();
        let echo=thread::spawn(move||{
            let until=Instant::now()+Duration::from_secs(60);
            let mut b=[0;2048];
            while !running.load(std::sync::atomic::Ordering::Relaxed)&&Instant::now()<until {
                if let Ok((n,peer))=local.recv_from(&mut b){local.send_to(&b[..n],peer).unwrap();}
            }
        });
        let root=tempfile::tempdir().unwrap();
        let relay_dir=tempfile::tempdir().unwrap();
        let device="a".repeat(32);
        let id="b".repeat(32);
        let rid="c".repeat(32);
        let token=format!("{:064x}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let server=localtunnel::server_udp_config(relay_addr,&format!("m_{id}"),mapped_addr.port(),&token,private).unwrap();
        let path=relay_dir.path().join("server.toml");
        std::fs::write(&path,server).unwrap();
        drop(relay_socket);
        drop(mapped);
        let mut command=Command::new(&engine);
        command.arg(&path).stdout(Stdio::null()).stderr(Stdio::null());
        let _relay=crate::Running::spawn(&mut command,relay_dir,1).unwrap();
        let http=TcpListener::bind("127.0.0.1:0").unwrap();
        http.set_nonblocking(true).unwrap();
        let s=Saved{port:http.local_addr().unwrap().port(),id:device.clone(),device_token:format!("ltdev_{}","d".repeat(64))};
        let saved=Zeroizing::new(serde_json::to_vec(&s).unwrap());
        credentials::save_management(root.path(),&saved).unwrap();
        let expected_path=format!("POST /api/v1/devices/{device}/udp-lease HTTP/1.1");
        let bearer=format!("Bearer {}",s.device_token);
        let mapping=id.clone();
        let expiry=unix_ms().unwrap()/1000+25;
        let body=serde_json::json!({"device_id":device,"device_revision":3,"mapping_id":id,"mapping_revision":2,
            "request_id":rid,"relay_port":relay_addr.port(),"local_port":local_port,"token":token,"server_key":public,"expires_at":expiry}).to_string();
        let fixture=thread::spawn(move||{
            for index in 0..3 {
                let until=Instant::now()+Duration::from_secs(10);
                let mut stream=loop{
                    match http.accept(){
                        Ok((stream,_))=>break stream,
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{},
                        Err(_)=>panic!("lease fixture accept error"),
                    }
                    assert!(Instant::now()<until,"lease fixture request missing");
                    thread::sleep(Duration::from_millis(10));
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut reader=BufReader::new(&mut stream);
                let mut line=String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.trim_end()==expected_path,"lease request path mismatch");
                let mut authorized=false;
                let mut len=0;
                for _ in 0..32{
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line=="\r\n"{break}
                    if let Some((name,value))=line.split_once(':'){
                        if name.eq_ignore_ascii_case("authorization"){authorized=value.trim()==bearer;}
                        if name.eq_ignore_ascii_case("content-length"){len=value.trim().parse::<usize>().unwrap();}
                    }
                }
                assert!(authorized&&len>0&&len<4096,"invalid fixture request");
                let mut data=vec![0;len];
                reader.read_exact(&mut data).unwrap();
                let json:serde_json::Value=serde_json::from_slice(&data).unwrap();
                assert!(json==serde_json::json!({"mapping_id":mapping,"device_revision":3,"mapping_revision":2}),"lease request scope mismatch");
                drop(reader);
                if index==2{
                    stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                }else{
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",body.len(),body).unwrap();
                }
            }
        });
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let saved=load(root.path()).unwrap().unwrap();
        let (grant,session)=rt.block_on(fetch_grant(&saved,&id,3,2,local_port)).unwrap();
        let mut supervisor=crate::Supervisor::default();
        assert_eq!(supervisor.start_managed(request(&grant,engine),session.clone(),root.path()).unwrap().state,"running");
        let config=supervisor.running.as_ref().unwrap()._directory.path().join("client.toml");
        assert!(config.is_file());
        assert!(rt.block_on(verify_session(root.path(),&session)).is_ok());
        let client=UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        let mut forwarded=false;
        let deadline=Instant::now()+Duration::from_secs(15);
        let mut buf=[0;128];
        while Instant::now()<deadline{
            client.send_to(b"managed-udp-fixture",mapped_addr).unwrap();
            if let Ok((n,peer))=client.recv_from(&mut buf){
                if peer==mapped_addr&&&buf[..n]==b"managed-udp-fixture"{forwarded=true;break}
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(forwarded,"managed UDP engine did not forward real bytes");
        assert!(rt.block_on(verify_session(root.path(),&session)).is_err(),"revoked fixture grant accepted");
        // Let the original monotonic deadline expire independently; the UI
        // is not involved and no synthetic clock or deadline modification.
        let until=session.deadline+Duration::from_secs(3);
        loop{
            if supervisor.status().unwrap().state!="running"{break}
            assert!(Instant::now()<until,"managed client outlived authorization");
            thread::sleep(Duration::from_millis(50));
        }
        assert!(Instant::now()>=session.deadline);
        assert!(supervisor.running.is_none()&&!config.exists());
        client.send_to(b"after-expiry",mapped_addr).unwrap();
        assert!(!matches!(client.recv_from(&mut buf),Ok((n,_)) if &buf[..n]==b"after-expiry"));
        fixture.join().unwrap();
        stop.store(true,std::sync::atomic::Ordering::Relaxed);
        echo.join().unwrap();
    }
    #[test]fn validates_credentials_and_port(){
        assert!(valid_token(&format!("ltpair_{}","a".repeat(64)),"ltpair_"));
        assert!(!valid_token(&format!("ltdev_{}","A".repeat(64)),"ltdev_"));
        assert!(validate_port(80).is_err());
    }
}
