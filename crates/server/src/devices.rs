//! Device enrollment and control-plane authentication; no tunnel configuration applied yet.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,Query,State},http::{header,HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use sqlx::SqlitePool;
use std::{sync::{Arc,Mutex},time::{Duration,Instant}};

type Failure=(StatusCode,&'static str);
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid device or pairing credential");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"device service unavailable");
const MISSING:Failure=(StatusCode::NOT_FOUND,"device not found");
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid device input");
const LIMITED:Failure=(StatusCode::TOO_MANY_REQUESTS,"try again later");
const PAIR_TTL:i64=600;
const ACTIVE_DEVICE_LIMIT:i64=64;
const TOTAL_DEVICE_LIMIT:i64=256;
const QUOTA:Failure=(StatusCode::CONFLICT,"device quota reached");

#[derive(Clone)]
struct DeviceState {pool:SqlitePool,budget:Arc<Mutex<(Instant,u32)>>}
#[derive(Serialize)]
struct Pairing {pairing_code:String,expires_in:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {pairing_code:String,name:String}
#[derive(Serialize)]
struct Enrolled {id:String,device_token:String}
#[derive(Serialize)]
struct Device {id:String,name:String,enabled:bool,revision:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {after:Option<String>}

fn valid_id(id:&str)->bool{
    id.len()==32&&id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn digest(value:&str,prefix:&str)->Result<Vec<u8>,Failure>{
    let hex=value.strip_prefix(prefix).ok_or(DENIED)?;
    if hex.len()!=64||!hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(DENIED)}
    // Domain separation includes the credential type.
    Ok(Sha256::digest(value.as_bytes()).to_vec())
}
fn device_bearer(headers:&HeaderMap)->Result<Vec<u8>,Failure>{
    let all=headers.get_all(header::AUTHORIZATION);
    let mut values=all.iter();
    let raw=values.next().ok_or(DENIED)?.to_str().map_err(|_|DENIED)?;
    if values.next().is_some(){return Err(DENIED)}
    digest(raw.strip_prefix("Bearer ").ok_or(DENIED)?,"ltdev_")
}
fn generate(prefix:&str)->Result<String,Failure>{
    Ok(format!("{prefix}{}",hex::encode(auth::random::<32>()?)))
}
impl DeviceState{
    fn enroll_attempt(&self)->Result<(),Failure>{
        let mut b=self.budget.lock().map_err(|_|INTERNAL)?;
        if b.0.elapsed()>=Duration::from_secs(60){*b=(Instant::now(),0)}
        if b.1>=60{return Err(LIMITED)}
        b.1+=1;
        Ok(())
    }
}
pub fn routes(pool:SqlitePool)->Router{
    let state=DeviceState{pool,budget:Arc::new(Mutex::new((Instant::now(),0)))};
    Router::new()
        .route("/api/v1/devices/pairing-code",post(issue))
        .route("/api/v1/devices/enroll",post(enroll))
        .route("/api/v1/devices",get(list))
        .route("/api/v1/devices/{id}/identity",get(identity))
        .route("/api/v1/devices/{id}/config",get(config))
        .route("/api/v1/devices/{id}/status",get(status).post(heartbeat))
        .route("/api/v1/devices/{id}/revoke",post(revoke))
        .layer(DefaultBodyLimit::max(4096)).with_state(state)
}
async fn issue(State(s):State<DeviceState>,headers:HeaderMap)->Result<Response,Failure>{
    let admin_digest=auth::bearer(&headers)?;
    let code=generate("ltpair_")?;
    // One pending code per administrator; reissue rotates it. Authorization in same write.
    let r=sqlx::query("INSERT INTO device_pairings(owner_id,code_digest,expires_at) SELECT u.id,?,unixepoch()+? FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin' ON CONFLICT(owner_id) DO UPDATE SET code_digest=excluded.code_digest,expires_at=excluded.expires_at")
        .bind(digest(&code,"ltpair_")?).bind(PAIR_TTL).bind(admin_digest).execute(&s.pool).await.map_err(|_|INTERNAL)?;
    if r.rows_affected()!=1{return Err(DENIED)}
    Ok(auth::uncached(Json(Pairing{pairing_code:code,expires_in:PAIR_TTL})))
}
async fn enroll(State(s):State<DeviceState>,Json(c):Json<Enrollment>)->Result<Response,Failure>{
    s.enroll_attempt()?;
    let name=c.name.trim();
    if name.is_empty()||name.len()>128||name.chars().any(char::is_control){return Err(BAD)}
    let code_digest=digest(&c.pairing_code,"ltpair_")?;
    let id=hex::encode(auth::random::<16>()?);
    let token=generate("ltdev_")?;
    let mut tx=s.pool.begin().await.map_err(|_|INTERNAL)?;
    // First SQL statement is a write. Consume exactly once, then insert in
    // the same transaction; failure rolls consumption back.
    let owner=sqlx::query_scalar::<_,String>("DELETE FROM device_pairings WHERE code_digest=? AND expires_at>unixepoch() AND EXISTS (SELECT 1 FROM users WHERE id=device_pairings.owner_id AND role='admin' AND enabled=1) RETURNING owner_id")
        .bind(code_digest).fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    // The pairing DELETE acquired the SQLite write transaction. Check both
    // quotas in the INSERT, including retained revoked rows. Bounded indexed
    // lookups need not count the entire owner inventory.
    let inserted=sqlx::query("INSERT INTO devices(id,owner_id,name,credential_digest) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM devices WHERE owner_id=? AND enabled=1 LIMIT 1 OFFSET ?) AND NOT EXISTS (SELECT 1 FROM devices WHERE owner_id=? LIMIT 1 OFFSET ?)")
        .bind(&id).bind(&owner).bind(name).bind(digest(&token,"ltdev_")?)
        .bind(&owner).bind(ACTIVE_DEVICE_LIMIT-1)
        .bind(&owner).bind(TOTAL_DEVICE_LIMIT-1)
        .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if inserted.rows_affected()!=1{
        // Do not consume the pairing or emit a successful device audit on
        // quota failure. Retry after capacity is freed, before code expiry.
        tx.rollback().await.map_err(|_|INTERNAL)?;
        return Err(QUOTA)
    }
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(Enrolled{id,device_token:token}))))
}
async fn list(State(s):State<DeviceState>,headers:HeaderMap,Query(q):Query<ListQuery>)->Result<Response,Failure>{
    let owner=auth::identify(&s.pool,&auth::bearer(&headers)?).await?.id;
    let after=q.after.unwrap_or_default();
    if !after.is_empty()&&!valid_id(&after){return Err(BAD)}
    let rows=sqlx::query_as::<_,(String,String,bool,i64)>("SELECT id,name,enabled,revision FROM devices WHERE owner_id=? AND id>? ORDER BY id LIMIT 100")
        .bind(owner).bind(after).fetch_all(&s.pool).await.map_err(|_|INTERNAL)?;
    let items:Vec<_>=rows.into_iter().map(|(id,name,enabled,revision)|Device{id,name,enabled,revision}).collect();
    Ok(auth::uncached(Json(items)))
}
async fn identity(State(s):State<DeviceState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    if !valid_id(&id){return Err(DENIED)}
    let token=device_bearer(&headers)?;
    let (id,name,enabled,revision)=sqlx::query_as::<_,(String,String,bool,i64)>("SELECT d.id,d.name,d.enabled,d.revision FROM devices d JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.credential_digest=? AND d.enabled=1 AND u.enabled=1 AND u.role='admin'")
        .bind(id).bind(token).fetch_optional(&s.pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(Device{id,name,enabled,revision})))
}
async fn revoke(State(s):State<DeviceState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let admin_digest=auth::bearer(&headers)?;
    auth::identify(&s.pool,&admin_digest).await?;
    if !valid_id(&id){return Err(MISSING)}
    // Recheck session and ownership inside the write; rotate stored digest.
    let r=sqlx::query("UPDATE devices SET enabled=0,credential_digest=?,revision=revision+1 WHERE id=? AND enabled=1 AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin')")
        .bind(auth::random::<32>()?.to_vec()).bind(id).bind(admin_digest).execute(&s.pool).await.map_err(|_|INTERNAL)?;
    if r.rows_affected()!=1{return Err(MISSING)}
    Ok(auth::uncached(StatusCode::NO_CONTENT))
}

const HEARTBEAT_SECONDS:i64=30;
const ONLINE_SECONDS:i64=90;
const CONFLICT:Failure=(StatusCode::CONFLICT,"configuration revision mismatch");

#[derive(Serialize)]
struct DesiredMapping {
    id:String,node_id:String,domain_id:Option<String>,protocol:String,
    local_host:String,local_port:i64,bind_port:i64,enabled:bool,revision:i64,
}
#[derive(Serialize)]
struct DesiredConfig {
    device_id:String,revision:i64,scope:&'static str,mappings:Vec<DesiredMapping>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {reported_revision:i64,reported_state:String}
#[derive(Serialize)]
struct HeartbeatReceipt {last_seen_at:i64,heartbeat_interval_seconds:i64}
#[derive(Serialize)]
struct StatusView {
    device_id:String,enabled:bool,desired_revision:i64,last_seen_at:Option<i64>,
    reported_revision:Option<i64>,reported_state:Option<String>,management_online:bool,
    configuration_current:bool,
}
async fn config(State(s):State<DeviceState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    if !valid_id(&id){return Err(DENIED)}
    let token=device_bearer(&headers)?;
    // The revision and mapping rows must come from the same DB snapshot.
    let mut tx=s.pool.begin().await.map_err(|_|INTERNAL)?;
    let (owner,revision)=sqlx::query_as::<_,(String,i64)>("SELECT d.owner_id,d.revision FROM devices d JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.credential_digest=? AND d.enabled=1 AND u.enabled=1 AND u.role='admin'")
        .bind(&id).bind(token).fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    let rows=sqlx::query_as::<_,(String,String,Option<String>,String,String,i64,i64,bool,i64)>(
        "SELECT id,node_id,domain_id,protocol,local_host,local_port,bind_port,enabled,revision FROM mappings WHERE device_id=? AND owner_id=? ORDER BY id LIMIT 65")
        .bind(&id).bind(owner).fetch_all(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    // Never silently truncate a configuration.
    if rows.len()>64{return Err((StatusCode::CONFLICT,"too many mappings"))}
    let mappings=rows.into_iter().map(|(id,node_id,domain_id,protocol,local_host,local_port,bind_port,enabled,revision)|DesiredMapping{id,node_id,domain_id,protocol,local_host,local_port,bind_port,enabled,revision}).collect();
    Ok(auth::uncached(Json(DesiredConfig{device_id:id,revision,scope:"desired_metadata_only",mappings})))
}
async fn heartbeat(State(s):State<DeviceState>,Path(id):Path<String>,headers:HeaderMap,Json(h):Json<Heartbeat>)->Result<Response,Failure>{
    if !valid_id(&id){return Err(DENIED)}
    let token=device_bearer(&headers)?;
    if h.reported_revision<0||!matches!(h.reported_state.as_str(),"idle"|"starting"|"running"|"error"){return Err(BAD)}
    // Check the credential, owner, enabled state and desired revision in the
    // same write. A concurrent revocation cannot be bypassed by a stale read.
    let last=sqlx::query_scalar::<_,i64>("INSERT INTO device_status(device_id,last_seen_at,reported_revision,reported_state) SELECT d.id,unixepoch(),?,? FROM devices d JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.credential_digest=? AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND d.revision>=? ON CONFLICT(device_id) DO UPDATE SET last_seen_at=excluded.last_seen_at,reported_revision=excluded.reported_revision,reported_state=excluded.reported_state RETURNING last_seen_at")
        .bind(h.reported_revision).bind(h.reported_state).bind(&id).bind(&token).bind(h.reported_revision)
        .fetch_optional(&s.pool).await.map_err(|_|INTERNAL)?;
    let last_seen_at=match last{
        Some(t)=>t,
        None=>{
            let revision=sqlx::query_scalar::<_,i64>("SELECT d.revision FROM devices d JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.credential_digest=? AND d.enabled=1 AND u.enabled=1 AND u.role='admin'")
                .bind(&id).bind(token).fetch_optional(&s.pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
            let _=revision;
            return Err(CONFLICT);
        }
    };
    Ok(auth::uncached(Json(HeartbeatReceipt{last_seen_at,heartbeat_interval_seconds:HEARTBEAT_SECONDS})))
}
async fn status(State(s):State<DeviceState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let admin=auth::bearer(&headers)?;
    auth::identify(&s.pool,&admin).await?;
    if !valid_id(&id){return Err(MISSING)}
    let (id,enabled,revision,last,reported,state,online)=sqlx::query_as::<_,(String,bool,i64,Option<i64>,Option<i64>,Option<String>,bool)>(
        "SELECT d.id,d.enabled,d.revision,h.last_seen_at,h.reported_revision,h.reported_state,COALESCE(d.enabled=1 AND h.last_seen_at BETWEEN unixepoch()-? AND unixepoch(),0) FROM devices d JOIN users u ON u.id=d.owner_id JOIN admin_sessions a ON a.user_id=u.id LEFT JOIN device_status h ON h.device_id=d.id WHERE d.id=? AND a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin'")
        .bind(ONLINE_SECONDS).bind(id).bind(admin).fetch_optional(&s.pool).await.map_err(|_|INTERNAL)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(StatusView{device_id:id,enabled,desired_revision:revision,last_seen_at:last,reported_revision:reported,reported_state:state,management_online:online,configuration_current:online&&reported==Some(revision)})))
}
