use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Algorithm, Argon2, Params, Version};
use axum::{extract::{DefaultBodyLimit, State}, http::{header, HeaderMap, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
use rand_core::{OsRng,RngCore};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use sqlx::SqlitePool;
use std::{io::Read,sync::{Arc,Mutex},time::{Instant,Duration}};
use tokio::sync::Semaphore;

type Failure = (StatusCode,&'static str);
const DENIED: Failure = (StatusCode::UNAUTHORIZED,"invalid credentials or session");
const INTERNAL: Failure = (StatusCode::SERVICE_UNAVAILABLE,"authentication unavailable");
const LIMITED: Failure = (StatusCode::TOO_MANY_REQUESTS,"try again later");
const TTL: i64 = 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials { username:String,password:String }
#[derive(Clone)]
pub struct AuthState { pool:SqlitePool,dummy:Arc<String>,budget:Arc<Mutex<(Instant,u32)>>,workers:Arc<Semaphore> }
#[derive(Serialize)]
pub(crate) struct Identity { pub(crate) id:String,username:String,role:String }
#[derive(Serialize)]
struct Session { access_token:String,token_type:&'static str,expires_in:i64 }

pub(crate) fn random<const N:usize>() -> Result<[u8;N],Failure> {
    let mut bytes=[0;N];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_|INTERNAL)?;
    Ok(bytes)
}
fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id,Version::V0x13,Params::new(19456,2,1,Some(32)).expect("fixed parameters"))
}
fn hash(password:&str)->Result<String,Failure>{
    let salt=SaltString::encode_b64(&random::<16>()?).map_err(|_|INTERNAL)?;
    hasher().hash_password(password.as_bytes(),&salt).map(|h|h.to_string()).map_err(|_|INTERNAL)
}
fn verify(password:&str,encoded:&str)->bool{
    // PasswordVerifier uses the PHC's embedded parameters, not only the
    // constructor's defaults. Reject unsupported stored work factors before
    // any expensive verification. A future rehash policy must be explicit.
    if encoded.len()>256{return false}
    let Ok(h)=PasswordHash::new(encoded) else{return false};
    if h.algorithm.as_str()!="argon2id"||h.version!=Some(19)||
        h.params.iter().count()!=3||
        h.params.get_decimal("m")!=Some(19456)||
        h.params.get_decimal("t")!=Some(2)||
        h.params.get_decimal("p")!=Some(1)||
        h.salt.is_none()||h.hash.as_ref().map(|v|v.len())!=Some(32){
        return false
    }
    hasher().verify_password(password.as_bytes(),&h).is_ok()
}
fn valid(c:&Credentials)->bool{valid_parts(&c.username,&c.password)}
fn valid_parts(username:&str,password:&str)->bool{
    (3..=64).contains(&username.len()) && username.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-') && (12..=256).contains(&password.len())
}
// Trusted local operator path only; share the existing password policy.
pub(crate) fn operator_password_hash(username:&str,password:&str)->Result<String,&'static str>{
    if !valid_parts(username,password){return Err("invalid account credentials")}
    hash(password).map_err(|_|"password hashing unavailable")
}
pub async fn init_admin(pool:&SqlitePool)->Result<(),Failure>{
    let mut input=Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut input).map_err(|_|INTERNAL)?;
    if input.len()>4096 {return Err(DENIED)}
    let c:Credentials=serde_json::from_slice(&input).map_err(|_|DENIED)?;
    if !valid(&c){return Err(DENIED)}
    let result=sqlx::query("INSERT INTO users(id,username,password_hash,role) SELECT ?,?,?,'admin' WHERE NOT EXISTS (SELECT 1 FROM users)")
        .bind(hex::encode(random::<16>()?)).bind(c.username).bind(hash(&c.password)?).execute(pool).await.map_err(|_|INTERNAL)?;
    if result.rows_affected()!=1{return Err(DENIED)}
    Ok(())
}
impl AuthState{
    pub fn new(pool:SqlitePool)->Result<Self,Failure>{
        Ok(Self{pool,dummy:Arc::new(hash(&hex::encode(random::<32>()?))?),budget:Arc::new(Mutex::new((Instant::now(),0))),workers:Arc::new(Semaphore::new(2))})
    }
    fn attempt(&self)->Result<(),Failure>{
        let mut b=self.budget.lock().map_err(|_|INTERNAL)?;
        if b.0.elapsed()>=Duration::from_secs(60){*b=(Instant::now(),0)}
        if b.1>=12{return Err(LIMITED)}
        b.1+=1;
        Ok(())
    }
}
pub fn routes(state:AuthState)->Router{
    Router::new().route("/api/v1/auth/login",post(login)).route("/api/v1/auth/me",get(me)).route("/api/v1/auth/logout",post(logout))
        .layer(DefaultBodyLimit::max(4096)).with_state(state)
}
pub(crate) fn uncached(value:impl IntoResponse)->Response{
    let mut r=value.into_response();
    r.headers_mut().insert(header::CACHE_CONTROL,header::HeaderValue::from_static("no-store"));
    r
}
async fn login(State(state):State<AuthState>,Json(c):Json<Credentials>)->Result<Response,Failure>{
    state.attempt()?;
    if !valid(&c){return Err(DENIED)}
    let permit=state.workers.clone().try_acquire_owned().map_err(|_|LIMITED)?;
    let row=sqlx::query_as::<_,(String,String)>("SELECT id,password_hash FROM users WHERE username=? AND enabled=1 AND role='admin'")
        .bind(c.username).fetch_optional(&state.pool).await.map_err(|_|INTERNAL)?;
    let encoded=row.as_ref().map(|r|r.1.clone()).unwrap_or_else(||state.dummy.as_ref().clone());
    let password=c.password;
    // Retain the permit in the worker if the HTTP request is cancelled.
    let valid=tokio::task::spawn_blocking(move||{let _permit=permit;verify(&password,&encoded)}).await.map_err(|_|INTERNAL)?;
    let (id,password_hash)=row.filter(|_|valid).ok_or(DENIED)?;
    let token=random::<32>()?;
    let result=sqlx::query("INSERT INTO admin_sessions(user_id,token_digest,expires_at) SELECT id,?,unixepoch()+? FROM users WHERE id=? AND role='admin' AND enabled=1 AND password_hash=? ON CONFLICT(user_id) DO UPDATE SET token_digest=excluded.token_digest,expires_at=excluded.expires_at")
        .bind(Sha256::digest(token).to_vec()).bind(TTL).bind(id).bind(password_hash).execute(&state.pool).await.map_err(|_|INTERNAL)?;
    if result.rows_affected()!=1{return Err(DENIED)}
    Ok(uncached(Json(Session{access_token:hex::encode(token),token_type:"Bearer",expires_in:TTL})))
}
pub(crate) fn bearer(headers:&HeaderMap)->Result<Vec<u8>,Failure>{
    let all=headers.get_all(header::AUTHORIZATION);
    let mut values=all.iter();
    let raw=values.next().ok_or(DENIED)?.to_str().map_err(|_|DENIED)?;
    if values.next().is_some(){return Err(DENIED)}
    let token=raw.strip_prefix("Bearer ").ok_or(DENIED)?;
    if token.len()!=64||!token.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(DENIED)}
    Ok(Sha256::digest(hex::decode(token).map_err(|_|DENIED)?).to_vec())
}
pub(crate) async fn identify(pool:&SqlitePool,digest:&[u8])->Result<Identity,Failure>{
    let (id,username,role)=sqlx::query_as::<_,(String,String,String)>("SELECT u.id,u.username,u.role FROM admin_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_digest=? AND s.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin'")
        .bind(digest).fetch_optional(pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(Identity{id,username,role})
}
async fn me(State(state):State<AuthState>,headers:HeaderMap)->Result<Response,Failure>{
    Ok(uncached(Json(identify(&state.pool,&bearer(&headers)?).await?)))
}
async fn logout(State(state):State<AuthState>,headers:HeaderMap)->Result<Response,Failure>{
    let digest=bearer(&headers)?;
    identify(&state.pool,&digest).await?;
    sqlx::query("DELETE FROM admin_sessions WHERE token_digest=?").bind(digest).execute(&state.pool).await.map_err(|_|INTERNAL)?;
    Ok(uncached(StatusCode::NO_CONTENT))
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn salted_password_hash(){
        let a=hash("fixture-password").unwrap();
        let b=hash("fixture-password").unwrap();
        assert!(a.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_ne!(a,b);
        assert!(verify("fixture-password",&a));
        assert!(!verify("wrong-password",&a));
        assert!(!verify("fixture-password","malformed"));
        for invalid in [
            a.replace("m=19456","m=1048576"),
            a.replace("t=2","t=1000"),
            a.replace("p=1","p=64"),
            a.replace("argon2id","argon2i"),
            a.replace("v=19","v=16"),
            a.replace("m=19456","m=8"),
        ]{
            assert!(!verify("fixture-password",&invalid));
        }
    }
    #[test]
    fn strict_bearer(){
        let mut headers=HeaderMap::new();
        assert_eq!(bearer(&headers),Err(DENIED));
        headers.insert(header::AUTHORIZATION,format!("Bearer {}","ab".repeat(32)).parse().unwrap());
        assert_eq!(bearer(&headers).unwrap(),Sha256::digest([0xab;32]).to_vec());
        headers.append(header::AUTHORIZATION,"Bearer invalid".parse().unwrap());
        assert_eq!(bearer(&headers),Err(DENIED));
    }
}
