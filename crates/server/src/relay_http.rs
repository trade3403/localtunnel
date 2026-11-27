//! Exact hostname HTTP startup authorization. No gateway process yet.
use crate::{auth,relay};
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::post,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid HTTP intent");
const CONFLICT:Failure=(StatusCode::CONFLICT,"HTTP intent unavailable");
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid relay credential or claim");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"HTTP intent unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent{grant_id:String,expected_generation:i64,relay_port:i64,gateway_port:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim{protocol_version:i64,grant_id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,relay_port:i64,gateway_port:i64,hostname:String,nonce:String}
#[derive(Serialize,sqlx::FromRow)]
struct Record{grant_id:String,node_id:String,relay_port:i64,bind_port:i64,gateway_port:i64,hostname:String,created_at:i64,claimed_at:Option<i64>}
#[derive(Serialize,sqlx::FromRow)]
struct Permit{grant_id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,policy_revision:i64,relay_port:i64,bind_port:i64,gateway_port:i64,hostname:String,issued_at:i64,expires_at:i64,server_time:i64,claimed_at:i64}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn ports(relay:i64,gateway:i64)->bool{(30000..=59999).contains(&relay)&&(60000..=64999).contains(&gateway)}
fn valid_host(s:&str)->bool{crate::domains::valid_host(s)}
const CURRENT:&str="FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id AND a.live_mapping_id=g.mapping_id AND a.generation=g.generation AND a.state='reserved'
 JOIN mappings m ON m.id=g.mapping_id AND m.revision=g.mapping_revision AND m.node_id=g.node_id AND m.owner_id=a.owner_id
 JOIN domains dom ON dom.id=m.domain_id AND dom.owner_id=m.owner_id
 JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id AND d.revision=g.device_revision
 JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=g.node_id AND n.policy_revision=g.policy_revision
 JOIN relay_identities r ON r.node_id=n.id AND r.generation=g.node_generation
 JOIN relay_heartbeat h ON h.node_id=r.node_id AND h.generation=r.generation
 JOIN tenants t ON t.owner_id=a.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id AND e.revision=g.entitlement_revision JOIN commercial_plans p ON p.id=e.plan_id
 WHERE g.revoked_at IS NULL AND g.issued_at<=unixepoch() AND g.expires_at>unixepoch()+2
 AND m.enabled=0 AND m.protocol='http' AND m.local_host='127.0.0.1' AND m.bind_port=a.bind_port
 AND dom.verification_token IS NOT NULL AND dom.verified_at BETWEEN unixepoch()-285 AND unixepoch()
 AND n.enabled=1 AND n.policy_mode='active' AND r.token_digest IS NOT NULL AND d.enabled=1 AND u.enabled=1 AND u.role='admin'
 AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
 AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<=min(n.approved_capacity,h.capacity)
 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>=g.expires_at)
 AND p.max_bandwidth_bps IS NULL AND p.max_monthly_bytes IS NULL AND p.max_concurrent_connections IS NULL
 AND (SELECT count(*) FROM mappings x WHERE x.owner_id=a.owner_id)<=p.max_mappings
 AND (SELECT count(*) FROM devices x WHERE x.owner_id=a.owner_id AND x.enabled=1)<=p.max_active_devices";
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/http-intent",post(intent))
        .route("/api/v1/relay/http-claim",post(claim)).layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
async fn intent(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Intent>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id)||!hex_id(&c.grant_id)||c.expected_generation<2||!ports(c.relay_port,c.gateway_port){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("INSERT INTO relay_http_intents(grant_id,node_id,relay_port,bind_port,gateway_port,domain_id,hostname,proof_token,verified_at,created_at)
      SELECT g.id,g.node_id,?,m.bind_port,?,dom.id,dom.hostname,dom.verification_token,dom.verified_at,unixepoch() {CURRENT}
      AND g.allocation_id=? AND g.id=? AND g.generation=? AND a.owner_id=?
      AND EXISTS(SELECT 1 FROM admin_sessions s WHERE s.user_id=a.owner_id AND s.token_digest=? AND s.expires_at>unixepoch())
      AND NOT EXISTS(SELECT 1 FROM relay_tcp_intents x WHERE x.node_id=g.node_id AND x.relay_port=?)
      AND NOT EXISTS(SELECT 1 FROM relay_udp_intents x WHERE x.node_id=g.node_id AND x.relay_port=?)
      ON CONFLICT DO NOTHING RETURNING grant_id,node_id,relay_port,bind_port,gateway_port,hostname,created_at,claimed_at");
    let row=sqlx::query_as::<_,Record>(&query).bind(c.relay_port).bind(c.gateway_port).bind(id).bind(c.grant_id).bind(c.expected_generation).bind(owner).bind(token).bind(c.relay_port).bind(c.relay_port)
        .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    if !valid_host(&row.hostname){return Err(CONFLICT)}
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
      SELECT a.owner_id,'http.intent',g.mapping_id,g.mapping_revision,g.id,'pending' FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id WHERE g.id=?")
        .bind(&row.grant_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(row))))
}
async fn claim(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Claim>)->Result<Response,Failure>{
    let credential=relay::digest(&headers)?;
    if c.protocol_version!=1||!hex_id(&c.grant_id)||!hex_id(&c.allocation_id)||!hex_id(&c.mapping_id)||!hex_id(&c.node_id)||!hex_id(&c.nonce)
      ||c.mapping_revision<1||c.node_generation<1||c.generation<2||!ports(c.relay_port,c.gateway_port)||!valid_host(&c.hostname){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("UPDATE relay_http_intents SET claimed_at=unixepoch() WHERE grant_id=? AND node_id=? AND relay_port=? AND gateway_port=? AND hostname=? AND claimed_at IS NULL
       AND EXISTS(SELECT 1 {CURRENT} AND g.id=relay_http_intents.grant_id AND g.node_id=relay_http_intents.node_id AND m.bind_port=relay_http_intents.bind_port
       AND dom.id=relay_http_intents.domain_id AND dom.hostname=relay_http_intents.hostname AND dom.verification_token=relay_http_intents.proof_token AND dom.verified_at=relay_http_intents.verified_at
       AND g.allocation_id=? AND g.mapping_id=? AND g.mapping_revision=? AND g.node_generation=? AND g.generation=? AND r.token_digest=?)");
    let changed=sqlx::query(&query).bind(&c.grant_id).bind(c.node_id).bind(c.relay_port).bind(c.gateway_port).bind(c.hostname).bind(c.allocation_id).bind(c.mapping_id).bind(c.mapping_revision).bind(c.node_generation).bind(c.generation).bind(credential)
       .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(DENIED)}
    let permit=sqlx::query_as::<_,Permit>("SELECT g.id AS grant_id,g.allocation_id,g.mapping_id,g.mapping_revision,g.node_id,g.node_generation,g.generation,g.policy_revision,
      i.relay_port,i.bind_port,i.gateway_port,i.hostname,g.issued_at,g.expires_at,unixepoch() AS server_time,i.claimed_at FROM relay_http_intents i JOIN relay_grants g ON g.id=i.grant_id WHERE i.grant_id=?")
       .bind(&c.grant_id).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
       SELECT a.owner_id,'http.claimed',g.mapping_id,g.mapping_revision,g.id,'claimed' FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id WHERE g.id=?")
       .bind(&c.grant_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached(Json(serde_json::json!({"protocol_version":1,"nonce":c.nonce,"scope":"http_loopback_start_claim","permit":permit}))))
}
