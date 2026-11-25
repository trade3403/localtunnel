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
    sqlx::query("INSERT INTO devices(id,owner_id,name,credential_digest) VALUES (?,?,?,?)")
        .bind(&id).bind(owner).bind(name).bind(digest(&token,"ltdev_")?)
        .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
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
