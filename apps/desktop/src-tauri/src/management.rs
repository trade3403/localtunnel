//! Explicit loopback-only management preview. No server-supplied executable
//! configuration, no automatic tunnel activation, no browser-held bearer.
use serde::{Deserialize,Serialize};
use std::{path::{Path,PathBuf},time::{Duration,Instant},sync::Mutex};
use zeroize::{Zeroize,Zeroizing};
use crate::credentials;
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
async fn sync_saved(s:Saved)->Result<SyncResult,String>{
    let c=client()?;
    let base=format!("http://127.0.0.1:{}/api/v1/devices/{}",s.port,s.id);
    let identity:Identity=json(c.get(format!("{base}/identity")).bearer_auth(&s.device_token),200).await?;
    if identity.id!=s.id||!identity.enabled||identity.revision<1{return Err("设备身份不一致".into())}
    let config:Config=json(c.get(format!("{base}/config")).bearer_auth(&s.device_token),200).await?;
    if config.device_id!=s.id||config.scope!="desired_metadata_only"||config.revision<identity.revision||config.mappings.len()>64||
        config.mappings.iter().any(|m|!hex(&m.id,32)||!matches!(m.protocol.as_str(),"http"|"https"|"tcp")||m.local_host!="127.0.0.1"||m.local_port==0||!(20000..=29999).contains(&m.bind_port)||m.revision<1){
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
        Ok(Some(s))=>sync_saved(s).await,
        Ok(None)=>Err("请先配对设备".into()),
        Err(e)=>Err(e),
    };
    record(&result)?;
    result
}
pub async fn forget(dir:&Path)->Result<(),String>{
    let _guard=ACTION.lock().await;
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
                let result=sync_saved(s).await;
                if record(&result).is_err(){return}
            },
            Ok(None)=>{
                if let Ok(mut a)=AUTO.lock(){a.observation=None;a.error=None;a.next=Some(Instant::now()+PERIOD);}else{return}
            },
            Err(e)=>{if record(&Err(e)).is_err(){return}}
        }
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn validates_credentials_and_port(){
        assert!(valid_token(&format!("ltpair_{}","a".repeat(64)),"ltpair_"));
        assert!(!valid_token(&format!("ltdev_{}","A".repeat(64)),"ltdev_"));
        assert!(validate_port(80).is_err());
    }
}
