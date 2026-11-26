//! Scoped management requests; only a trusted local foreground worker can
//! claim and execute them. HTTP requests never specify executable parameters.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid runtime request");
const MISSING:Failure=(StatusCode::NOT_FOUND,"mapping not found");
const CONFLICT:Failure=(StatusCode::CONFLICT,"runtime request conflict or unavailable mapping");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"runtime service unavailable");
const FIELDS:&str="mapping_id,request_id,mapping_revision,state,requested_at,updated_at";
#[derive(Serialize,sqlx::FromRow)]
struct Request{mapping_id:String,request_id:String,mapping_revision:i64,state:String,requested_at:i64,updated_at:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start{expected_revision:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop{request_id:String}
fn id_valid(id:&str)->bool{id.len()==32&&id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub fn routes(pool:SqlitePool)->Router{
    Router::new()
        .route("/api/v1/mappings/{id}/runtime",get(status))
        .route("/api/v1/mappings/{id}/start",post(start))
        .route("/api/v1/mappings/{id}/udp-start",post(start_udp))
        .route("/api/v1/mappings/{id}/tcp-start",post(start_tcp))
        .route("/api/v1/mappings/{id}/stop",post(stop))
        .layer(DefaultBodyLimit::max(4096)).with_state(pool)
}
async fn owned(pool:&SqlitePool,id:&str,owner:&str)->Result<(),Failure>{
    if !id_valid(id){return Err(MISSING)}
    let n=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mappings WHERE id=? AND owner_id=?")
        .bind(id).bind(owner).fetch_one(pool).await.map_err(|_|INTERNAL)?;
    if n==0{Err(MISSING)}else{Ok(())}
}
async fn status(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    owned(&pool,&id,&owner).await?;
    let query=format!("SELECT {FIELDS} FROM runtime_requests WHERE mapping_id=? AND mapping_id IN (SELECT m.id FROM mappings m JOIN users u ON u.id=m.owner_id JOIN admin_sessions a ON a.user_id=u.id WHERE m.owner_id=? AND a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin')");
    let r=sqlx::query_as::<_,Request>(&query).bind(&id).bind(owner).bind(token).fetch_optional(&pool).await.map_err(|_|INTERNAL)?;
    let now=sqlx::query_scalar::<_,i64>("SELECT unixepoch()").fetch_one(&pool).await.map_err(|_|INTERNAL)?;
    let recent=r.as_ref().is_some_and(|v|matches!(v.state.as_str(),"starting"|"running"|"stopping")&&v.updated_at>=now-10&&v.updated_at<=now);
    Ok(auth::uncached(Json(serde_json::json!({"mapping_id":id,"request":r,"worker_recent":recent,"scope":"operator_loopback_preview"}))))
}
async fn start(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Start>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    owned(&pool,&id,&owner).await?;
    if c.expected_revision<1{return Err(BAD)}
    let rid=hex::encode(auth::random::<16>()?);
    // Expired unclaimed requests may be replaced; unknown or claimed ones
    // never restart automatically. Session and eligibility checked at write.
    let query=format!("INSERT INTO runtime_requests(mapping_id,request_id,mapping_revision,state,requested_at,updated_at) SELECT m.id,?,m.revision,'queued',unixepoch(),unixepoch() FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN domains h ON h.id=m.domain_id AND h.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN admin_sessions a ON a.user_id=u.id WHERE m.id=? AND m.owner_id=? AND m.revision=? AND m.enabled=0 AND m.protocol IN ('http','https') AND m.local_host='127.0.0.1' AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND n.enabled=1 AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch() AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch() AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())) ON CONFLICT(mapping_id) DO UPDATE SET request_id=excluded.request_id,mapping_revision=excluded.mapping_revision,state='queued',requested_at=excluded.requested_at,updated_at=excluded.updated_at WHERE runtime_requests.state='stopped' OR (runtime_requests.state='queued' AND runtime_requests.requested_at<unixepoch()-120) RETURNING {FIELDS}");
    let r=sqlx::query_as::<_,Request>(&query).bind(rid).bind(id).bind(owner).bind(c.expected_revision).bind(token)
        .fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    Ok(auth::uncached((StatusCode::ACCEPTED,Json(r))))
}
async fn start_udp(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Start>)->Result<Response,Failure>{
    start_stream_or_datagram(pool,id,headers,c,"udp").await
}
async fn start_tcp(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Start>)->Result<Response,Failure>{
    start_stream_or_datagram(pool,id,headers,c,"tcp").await
}
async fn start_stream_or_datagram(pool:SqlitePool,id:String,headers:HeaderMap,c:Start,protocol:&str)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    owned(&pool,&id,&owner).await?;
    if c.expected_revision<1{return Err(BAD)}
    let rid=hex::encode(auth::random::<16>()?);
    // Expired unclaimed requests may be replaced; unknown or claimed ones
    // never restart automatically. Session and eligibility checked at write.
    let query=format!("INSERT INTO runtime_requests(mapping_id,request_id,mapping_revision,state,requested_at,updated_at) SELECT m.id,?,m.revision,'queued',unixepoch(),unixepoch() FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN nodes n ON n.id=m.node_id JOIN users u ON u.id=m.owner_id JOIN admin_sessions a ON a.user_id=u.id WHERE m.id=? AND m.owner_id=? AND m.revision=? AND m.enabled=0 AND m.protocol=? AND m.domain_id IS NULL AND m.local_host='127.0.0.1' AND m.bind_port BETWEEN 20000 AND 29999 AND d.enabled=1 AND n.enabled=1 AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch() AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())) ON CONFLICT(mapping_id) DO UPDATE SET request_id=excluded.request_id,mapping_revision=excluded.mapping_revision,state='queued',requested_at=excluded.requested_at,updated_at=excluded.updated_at WHERE runtime_requests.state='stopped' OR (runtime_requests.state='queued' AND runtime_requests.requested_at<unixepoch()-120) RETURNING {FIELDS}");
    let r=sqlx::query_as::<_,Request>(&query).bind(rid).bind(id).bind(owner).bind(c.expected_revision).bind(protocol).bind(token)
        .fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    Ok(auth::uncached((StatusCode::ACCEPTED,Json(r))))
}
async fn stop(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Stop>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    owned(&pool,&id,&owner).await?;
    if !id_valid(&c.request_id){return Err(BAD)}
    let query=format!("UPDATE runtime_requests SET state=CASE WHEN state='queued' THEN 'stopped' WHEN state IN ('starting','running') THEN 'stopping' ELSE state END,updated_at=CASE WHEN state='queued' THEN unixepoch() ELSE updated_at END WHERE mapping_id=? AND request_id=? AND state IN ('queued','starting','running','stopping','stopped') AND mapping_id IN (SELECT m.id FROM mappings m JOIN users u ON u.id=m.owner_id JOIN admin_sessions a ON a.user_id=u.id WHERE m.owner_id=? AND a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin') RETURNING {FIELDS}");
    let r=sqlx::query_as::<_,Request>(&query).bind(id).bind(c.request_id).bind(owner).bind(token).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    Ok(auth::uncached((StatusCode::ACCEPTED,Json(r))))
}
pub async fn claim(pool:&SqlitePool,id:&str,revision:i64)->Result<Option<String>,&'static str>{
    sqlx::query_scalar("UPDATE runtime_requests SET state='starting',updated_at=unixepoch() WHERE mapping_id=? AND mapping_revision=? AND state='queued' AND requested_at BETWEEN unixepoch()-120 AND unixepoch() AND EXISTS(SELECT 1 FROM mappings m WHERE m.id=runtime_requests.mapping_id AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()))) RETURNING request_id")
        .bind(id).bind(revision).fetch_optional(pool).await.map_err(|_|"runtime claim failed")
}
pub async fn keep(pool:&SqlitePool,id:&str,rid:&str,phase:&str)->Result<bool,&'static str>{
    // Never overwrite a stop request, including one arriving during apply.
    let n=sqlx::query("UPDATE runtime_requests SET state=?,updated_at=unixepoch() WHERE mapping_id=? AND request_id=? AND state IN ('starting','running') AND EXISTS(SELECT 1 FROM mappings m WHERE m.id=runtime_requests.mapping_id AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())))")
        .bind(phase).bind(id).bind(rid).execute(pool).await.map_err(|_|"runtime heartbeat failed")?.rows_affected();
    Ok(n==1)
}
pub async fn finish(pool:&SqlitePool,id:&str,rid:&str,success:bool)->Result<(),&'static str>{
    let n=sqlx::query("UPDATE runtime_requests SET state=?,updated_at=unixepoch() WHERE mapping_id=? AND request_id=? AND state IN ('starting','running','stopping')")
        .bind(if success{"stopped"}else{"failed_or_unknown"}).bind(id).bind(rid).execute(pool).await.map_err(|_|"runtime outcome unknown")?.rows_affected();
    if n!=1{return Err("runtime outcome unknown")}
    Ok(())
}

/// A resident worker must never silently adopt a changed mapping or a
/// previously claimed request. DNS freshness is checked at every actual start.
pub async fn resident_state(pool:&SqlitePool,id:&str,revision:i64,protocol:&str)->Result<Option<String>,&'static str>{
    let row=sqlx::query_as::<_,(Option<String>,)>("SELECT r.state FROM mappings m JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=m.node_id LEFT JOIN runtime_requests r ON r.mapping_id=m.id WHERE m.id=? AND m.revision=? AND m.protocol=? AND m.enabled=0 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans cp ON cp.id=e.plan_id WHERE t.owner_id=m.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()))")
        .bind(id).bind(revision).bind(protocol).fetch_optional(pool).await.map_err(|_|"resident state unavailable")?.ok_or("resident mapping no longer eligible")?;
    Ok(row.0)
}
