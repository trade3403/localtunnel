//! Initial bounded control-plane authorization preview; not an executable lease.
//! No renewal, reassignment, automatic reclamation or offline authority.
use crate::{auth,relay};
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid grant request");
const CONFLICT:Failure=(StatusCode::CONFLICT,"grant unavailable or reconciliation required");
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid relay credential");
const MISSING:Failure=(StatusCode::NOT_FOUND,"grant not found");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"grant service unavailable");
const FIELDS:&str="id,allocation_id,mapping_id,mapping_revision,node_id,node_generation,generation,policy_revision,device_revision,entitlement_revision,issued_at,expires_at,revoked_at";
#[derive(Serialize,sqlx::FromRow)]
struct Grant{id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,policy_revision:i64,device_revision:i64,entitlement_revision:i64,issued_at:i64,expires_at:i64,revoked_at:Option<i64>}
#[derive(sqlx::FromRow)]
struct Observation{#[sqlx(flatten)] grant:Grant,server_time:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue{expected_generation:i64,expected_mapping_revision:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetch{protocol_version:i64,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,nonce:String}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/grant",post(issue).get(detail))
        .route("/api/v1/relay/grant",post(fetch))
        .layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
async fn issue(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Issue>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    if c.expected_generation!=1||c.expected_mapping_revision<1{return Err(BAD)}
    let grant=hex::encode(auth::random::<16>()?);
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    // First statement is a write; authorize against current state, never a
    // previously returned reservation or policy snapshot. No finite metering
    // plan is eligible until the cross-node budget protocol is implemented.
    let query=format!("INSERT INTO relay_grants(id,allocation_id,mapping_id,mapping_revision,node_id,node_generation,generation,policy_revision,device_revision,entitlement_revision,issued_at,expires_at)
        SELECT ?,a.id,m.id,m.revision,n.id,r.generation,a.generation+1,n.policy_revision,d.revision,e.revision,unixepoch(),unixepoch()+15
        FROM relay_allocations a JOIN mappings m ON m.id=a.live_mapping_id AND m.owner_id=a.owner_id AND m.revision=a.mapping_revision AND m.node_id=a.node_id
        JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id
        JOIN users u ON u.id=a.owner_id JOIN admin_sessions s ON s.user_id=u.id
        JOIN nodes n ON n.id=a.node_id JOIN relay_identities r ON r.node_id=n.id AND r.generation=a.node_generation
        JOIN relay_heartbeat h ON h.node_id=r.node_id AND h.generation=r.generation
        JOIN tenants t ON t.owner_id=a.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id
        WHERE a.id=? AND a.owner_id=? AND a.generation=? AND a.mapping_revision=? AND a.state='reserved'
        AND m.enabled=0 AND ((m.protocol IN ('tcp','udp') AND m.domain_id IS NULL) OR (m.protocol IN ('http','https') AND EXISTS(SELECT 1 FROM domains dom WHERE dom.id=m.domain_id AND dom.owner_id=m.owner_id AND dom.verification_token IS NOT NULL AND dom.verified_at BETWEEN unixepoch()-285 AND unixepoch()))) AND m.local_host='127.0.0.1' AND m.bind_port=a.bind_port
        AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND s.token_digest=? AND s.expires_at>unixepoch()
        AND n.enabled=1 AND n.policy_mode='active' AND r.token_digest IS NOT NULL AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
        AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<=min(n.approved_capacity,h.capacity)
        AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>=unixepoch()+15)
        AND p.max_bandwidth_bps IS NULL AND p.max_monthly_bytes IS NULL AND p.max_concurrent_connections IS NULL
        AND (SELECT count(*) FROM mappings x WHERE x.owner_id=a.owner_id)<=p.max_mappings
        AND (SELECT count(*) FROM devices x WHERE x.owner_id=a.owner_id AND x.enabled=1)<=p.max_active_devices
        AND NOT EXISTS(SELECT 1 FROM relay_grants g WHERE g.allocation_id=a.id)
        AND NOT EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.tenant_id=t.id)
        RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Grant>(&query).bind(grant).bind(&id).bind(&owner).bind(c.expected_generation).bind(c.expected_mapping_revision).bind(token)
        .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    let changed=sqlx::query("UPDATE relay_allocations SET generation=? WHERE id=? AND generation=?")
        .bind(row.generation).bind(&id).bind(c.expected_generation).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(CONFLICT)}
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state) VALUES (?,'grant.preview_issued',?,?,?,'preview')")
        .bind(owner).bind(&row.mapping_id).bind(row.mapping_revision).bind(&row.id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(row))))
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let owner=auth::identify(&pool,&auth::bearer(&headers)?).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    let query=format!("SELECT {FIELDS} FROM relay_grants WHERE allocation_id=? AND EXISTS(SELECT 1 FROM relay_allocations a WHERE a.id=relay_grants.allocation_id AND a.owner_id=?)");
    let row=sqlx::query_as::<_,Grant>(&query).bind(id).bind(owner).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(row)))
}
async fn fetch(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Fetch>)->Result<Response,Failure>{
    let credential=relay::digest(&headers)?;
    if c.protocol_version!=1||!hex_id(&c.allocation_id)||!hex_id(&c.mapping_id)||!hex_id(&c.node_id)||!hex_id(&c.nonce)||c.mapping_revision<1||c.node_generation<1||c.generation<2{return Err(BAD)}
    // Exact identity plus current state in one read. No extension, no
    // reissuance. A stale observation never frees the port.
    let row=sqlx::query_as::<_,Observation>("SELECT g.*,unixepoch() AS server_time FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id AND a.live_mapping_id=g.mapping_id AND a.generation=g.generation AND a.state='reserved'
        JOIN mappings m ON m.id=g.mapping_id AND m.revision=g.mapping_revision AND m.node_id=g.node_id AND m.owner_id=a.owner_id AND m.enabled=0
        JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id AND d.revision=g.device_revision
        JOIN users u ON u.id=m.owner_id JOIN nodes n ON n.id=g.node_id AND n.policy_revision=g.policy_revision
        JOIN relay_identities r ON r.node_id=n.id AND r.generation=g.node_generation
        JOIN relay_heartbeat h ON h.node_id=r.node_id AND h.generation=r.generation
        JOIN tenants t ON t.owner_id=a.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id AND e.revision=g.entitlement_revision JOIN commercial_plans p ON p.id=e.plan_id
        WHERE g.allocation_id=? AND g.mapping_id=? AND g.mapping_revision=? AND g.node_id=? AND g.node_generation=? AND g.generation=?
        AND ((m.protocol IN ('tcp','udp') AND m.domain_id IS NULL) OR (m.protocol IN ('http','https') AND EXISTS(SELECT 1 FROM domains dom WHERE dom.id=m.domain_id AND dom.owner_id=m.owner_id AND dom.verification_token IS NOT NULL AND dom.verified_at BETWEEN unixepoch()-285 AND unixepoch())))
        AND r.token_digest=? AND g.revoked_at IS NULL AND g.issued_at<=unixepoch() AND g.expires_at>unixepoch()
        AND n.enabled=1 AND n.policy_mode='active' AND d.enabled=1 AND u.enabled=1 AND u.role='admin'
        AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
        AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<=min(n.approved_capacity,h.capacity)
        AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>=g.expires_at)
        AND p.max_bandwidth_bps IS NULL AND p.max_monthly_bytes IS NULL AND p.max_concurrent_connections IS NULL")
        .bind(c.allocation_id).bind(c.mapping_id).bind(c.mapping_revision).bind(c.node_id).bind(c.node_generation).bind(c.generation).bind(credential)
        .fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(serde_json::json!({"protocol_version":1,"nonce":c.nonce,"scope":"authorization_preview_only","server_time":row.server_time,"grant":row.grant}))))
}
