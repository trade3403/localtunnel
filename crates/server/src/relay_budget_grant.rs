//! Finite TCP budget authorization and separately opted-in guarded loopback execution.
use crate::{auth,relay};
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::post,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid budget grant");
const CONFLICT:Failure=(StatusCode::CONFLICT,"budget grant unavailable");
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid relay credential or budget grant");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"budget grant unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue{expected_generation:i64,expected_mapping_revision:i64,expected_entitlement_revision:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetch{protocol_version:i64,grant_id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,nonce:String}
#[derive(Serialize,sqlx::FromRow)]
struct Grant{id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,policy_revision:i64,entitlement_revision:i64,device_revision:i64,bind_port:i64,rate_bytes_per_second:i64,monthly_bytes:i64,connection_slots:i64,month_utc:String,issued_at:i64,expires_at:i64,server_time:i64}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
const CURRENT:&str="FROM relay_budget_previews b JOIN relay_allocations a ON a.id=b.allocation_id AND a.node_id=b.node_id AND a.node_generation=b.node_generation AND a.mapping_revision=b.mapping_revision AND a.state='reserved'
 JOIN mappings m ON m.id=a.live_mapping_id AND m.owner_id=a.owner_id AND m.node_id=b.node_id AND m.revision=b.mapping_revision AND m.bind_port=a.bind_port
 JOIN devices d ON d.id=m.device_id AND d.owner_id=a.owner_id
 JOIN users u ON u.id=a.owner_id JOIN tenants t ON t.id=b.tenant_id AND t.owner_id=a.owner_id
 JOIN tenant_entitlements e ON e.tenant_id=t.id AND e.revision=b.entitlement_revision JOIN commercial_plans p ON p.id=e.plan_id
 JOIN nodes n ON n.id=b.node_id AND n.policy_revision=b.policy_revision
 JOIN relay_identities r ON r.node_id=n.id AND r.generation=b.node_generation
 JOIN relay_heartbeat h ON h.node_id=r.node_id AND h.generation=r.generation";
const ELIGIBLE:&str="m.protocol='tcp' AND m.domain_id IS NULL AND m.enabled=0 AND m.local_host='127.0.0.1'
 AND d.enabled=1 AND u.enabled=1 AND u.role='admin' AND n.enabled=1 AND n.policy_mode='active' AND r.token_digest IS NOT NULL
 AND h.received_at BETWEEN unixepoch()-15 AND unixepoch() AND e.state='active'
 AND b.month_utc=strftime('%Y-%m','now')
 AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<=min(n.approved_capacity,h.capacity)
 AND (SELECT count(*) FROM mappings x WHERE x.owner_id=a.owner_id)<=p.max_mappings
 AND (SELECT count(*) FROM devices x WHERE x.owner_id=a.owner_id AND x.enabled=1)<=p.max_active_devices
 AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations x WHERE x.tenant_id=t.id)
 AND NOT EXISTS(SELECT 1 FROM relay_grants g JOIN relay_allocations z ON z.id=g.allocation_id WHERE z.owner_id=a.owner_id)
 AND p.max_bandwidth_bps IS NOT NULL AND p.max_monthly_bytes IS NOT NULL AND p.max_concurrent_connections IS NOT NULL
 AND (SELECT coalesce(sum(rate_bytes_per_second),0) FROM relay_budget_active x WHERE x.tenant_id=t.id)<=p.max_bandwidth_bps/8
 AND (SELECT coalesce(sum(connection_slots),0) FROM relay_budget_active x WHERE x.tenant_id=t.id)<=p.max_concurrent_connections
 AND (SELECT coalesce(sum(monthly_bytes),0) FROM relay_budget_previews x WHERE x.tenant_id=t.id AND x.month_utc=b.month_utc)<=p.max_monthly_bytes-coalesce((SELECT charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=b.month_utc),0)";
const FIELDS:&str="g.id,a.id AS allocation_id,m.id AS mapping_id,b.mapping_revision,b.node_id,b.node_generation,a.generation,b.policy_revision,b.entitlement_revision,g.device_revision,a.bind_port,b.rate_bytes_per_second,b.monthly_bytes,b.connection_slots,b.month_utc,g.issued_at,g.expires_at,unixepoch() AS server_time";
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/budget-grant",post(issue))
        .route("/api/v1/relay/budget-grant",post(fetch))
        .route("/api/v1/allocations/{id}/budget-intent",post(intent))
        .route("/api/v1/relay/budget-claim",post(claim))
        .route("/api/v1/allocations/{id}/budget-run-intent",post(run_intent))
        .route("/api/v1/relay/budget-run-claim",post(run_claim))
        .route("/api/v1/allocations/{id}/budget-start-intent",post(start_intent))
        .route("/api/v1/relay/budget-start-claim",post(start_claim)).layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
async fn issue(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Issue>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id)||c.expected_generation!=1||c.expected_mapping_revision<1||c.expected_entitlement_revision<1{return Err(BAD)}
    let gid=hex::encode(auth::random::<16>()?);
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("INSERT INTO relay_budget_grants(id,allocation_id,device_revision,issued_at,expires_at)
        SELECT ?,a.id,d.revision,unixepoch(),unixepoch()+15 {CURRENT}
        WHERE {ELIGIBLE} AND a.id=? AND a.owner_id=? AND a.generation=? AND b.mapping_revision=? AND b.entitlement_revision=?
        AND (e.expires_at IS NULL OR e.expires_at>=unixepoch()+15)
        AND b.month_utc=strftime('%Y-%m',unixepoch()+15,'unixepoch')
        AND EXISTS(SELECT 1 FROM admin_sessions s WHERE s.user_id=a.owner_id AND s.token_digest=? AND s.expires_at>unixepoch())
        AND NOT EXISTS(SELECT 1 FROM relay_budget_grants g WHERE g.allocation_id=a.id)");
    let changed=sqlx::query(&query).bind(&gid).bind(&id).bind(&owner).bind(c.expected_generation).bind(c.expected_mapping_revision).bind(c.expected_entitlement_revision).bind(token)
        .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(CONFLICT)}
    let changed=sqlx::query("UPDATE relay_allocations SET generation=2 WHERE id=? AND generation=1").bind(&id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(CONFLICT)}
    let query=format!("SELECT {FIELDS} {CURRENT} JOIN relay_budget_grants g ON g.allocation_id=a.id WHERE g.id=?");
    let row=sqlx::query_as::<_,Grant>(&query).bind(&gid).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state) VALUES (?,'budget.grant_preview_issued',?,?,?,'preview')")
        .bind(owner).bind(&row.mapping_id).bind(row.mapping_revision).bind(&gid).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(serde_json::json!({"scope":"budget_authorization_preview_only","executable":false,"grant":row})))))
}
async fn fetch(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Fetch>)->Result<Response,Failure>{
    let credential=relay::digest(&headers)?;
    if c.protocol_version!=1||!hex_id(&c.grant_id)||!hex_id(&c.allocation_id)||!hex_id(&c.mapping_id)||!hex_id(&c.node_id)||!hex_id(&c.nonce)||c.mapping_revision<1||c.node_generation<1||c.generation!=2{return Err(BAD)}
    let query=format!("SELECT {FIELDS} {CURRENT} JOIN relay_budget_grants g ON g.allocation_id=a.id
       WHERE {ELIGIBLE} AND g.id=? AND a.id=? AND m.id=? AND b.mapping_revision=? AND b.node_id=? AND b.node_generation=? AND a.generation=?
       AND d.revision=g.device_revision AND r.token_digest=? AND g.revoked_at IS NULL AND g.issued_at<=unixepoch() AND g.expires_at>unixepoch()
       AND (e.expires_at IS NULL OR e.expires_at>=g.expires_at)");
    let row=sqlx::query_as::<_,Grant>(&query).bind(c.grant_id).bind(c.allocation_id).bind(c.mapping_id).bind(c.mapping_revision).bind(c.node_id).bind(c.node_generation).bind(c.generation).bind(credential)
       .fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(serde_json::json!({"protocol_version":1,"nonce":c.nonce,"scope":"budget_authorization_preview_only","executable":false,"grant":row}))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent{grant_id:String,expected_generation:i64,relay_port:i64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim{protocol_version:i64,grant_id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,generation:i64,relay_port:i64,nonce:String}
#[derive(Serialize,sqlx::FromRow)]
struct IntentRecord{grant_id:String,node_id:String,relay_port:i64,bind_port:i64,created_at:i64,claimed_at:Option<i64>}
const CLAIM_ELIGIBLE:&str="a.generation=2 AND d.revision=g.device_revision AND g.revoked_at IS NULL
 AND g.issued_at<=unixepoch() AND g.expires_at>unixepoch()+2
 AND (e.expires_at IS NULL OR e.expires_at>=g.expires_at)";
async fn intent(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Intent>)->Result<Response,Failure>{
    intent_for(pool,id,headers,c,false,false).await
}
async fn run_intent(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Intent>)->Result<Response,Failure>{
    intent_for(pool,id,headers,c,true,false).await
}
async fn start_intent(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Intent>)->Result<Response,Failure>{
    intent_for(pool,id,headers,c,true,true).await
}
async fn intent_for(pool:SqlitePool,id:String,headers:HeaderMap,c:Intent,guarded:bool,execution:bool)->Result<Response,Failure>{
    let mode=if guarded{"guarded_tcp"}else{"observe"};
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id)||!hex_id(&c.grant_id)||c.expected_generation!=2||!(30000..=59999).contains(&c.relay_port){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("INSERT INTO relay_budget_intents(grant_id,node_id,relay_port,bind_port,created_at,intent_mode,execution_opt_in)
        SELECT g.id,b.node_id,?,a.bind_port,unixepoch(),?,? {CURRENT} JOIN relay_budget_grants g ON g.allocation_id=a.id
        WHERE {ELIGIBLE} AND {CLAIM_ELIGIBLE} AND a.id=? AND g.id=? AND a.owner_id=?
        AND EXISTS(SELECT 1 FROM admin_sessions s WHERE s.user_id=a.owner_id AND s.token_digest=? AND s.expires_at>unixepoch())
        AND NOT EXISTS(SELECT 1 FROM relay_tcp_intents x WHERE x.node_id=b.node_id AND x.relay_port=?)
        AND NOT EXISTS(SELECT 1 FROM relay_udp_intents x WHERE x.node_id=b.node_id AND x.relay_port=?)
        AND NOT EXISTS(SELECT 1 FROM relay_http_intents x WHERE x.node_id=b.node_id AND x.relay_port=?)
        AND NOT EXISTS(SELECT 1 FROM relay_https_intents x WHERE x.node_id=b.node_id AND x.relay_port=?)
        ON CONFLICT DO NOTHING RETURNING grant_id,node_id,relay_port,bind_port,created_at,claimed_at");
    let row=sqlx::query_as::<_,IntentRecord>(&query).bind(c.relay_port).bind(mode).bind(i64::from(execution)).bind(&id).bind(&c.grant_id).bind(&owner).bind(token)
        .bind(c.relay_port).bind(c.relay_port).bind(c.relay_port).bind(c.relay_port)
        .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
        SELECT a.owner_id,?,a.live_mapping_id,a.mapping_revision,g.id,'pending' FROM relay_budget_grants g JOIN relay_allocations a ON a.id=g.allocation_id WHERE g.id=?")
        .bind(if execution{"budget.start_intent"}else if guarded{"budget.run_intent"}else{"budget.intent"}).bind(&row.grant_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(serde_json::json!({"scope":if execution{"budget_guarded_start_intent"}else if guarded{"budget_guarded_intent_preview_only"}else{"budget_intent_preview_only"},"executable":false,"intent":row})))))
}
async fn claim(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Claim>)->Result<Response,Failure>{
    claim_for(pool,headers,c,false,false).await
}
async fn run_claim(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Claim>)->Result<Response,Failure>{
    claim_for(pool,headers,c,true,false).await
}
async fn start_claim(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Claim>)->Result<Response,Failure>{
    claim_for(pool,headers,c,true,true).await
}
async fn claim_for(pool:SqlitePool,headers:HeaderMap,c:Claim,guarded:bool,execution:bool)->Result<Response,Failure>{
    let mode=if guarded{"guarded_tcp"}else{"observe"};
    let credential=relay::digest(&headers)?;
    if c.protocol_version!=1||!hex_id(&c.grant_id)||!hex_id(&c.allocation_id)||!hex_id(&c.mapping_id)||!hex_id(&c.node_id)||!hex_id(&c.nonce)
        ||c.mapping_revision<1||c.node_generation<1||c.generation!=2||!(30000..=59999).contains(&c.relay_port){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("UPDATE relay_budget_intents SET claimed_at=unixepoch()
      WHERE grant_id=? AND node_id=? AND relay_port=? AND intent_mode=? AND execution_opt_in=? AND claimed_at IS NULL
      AND EXISTS(SELECT 1 {CURRENT} JOIN relay_budget_grants g ON g.allocation_id=a.id
        WHERE {ELIGIBLE} AND {CLAIM_ELIGIBLE} AND g.id=relay_budget_intents.grant_id
        AND b.node_id=relay_budget_intents.node_id AND a.bind_port=relay_budget_intents.bind_port
        AND a.id=? AND m.id=? AND b.mapping_revision=? AND b.node_generation=? AND r.token_digest=?)");
    let changed=sqlx::query(&query).bind(&c.grant_id).bind(&c.node_id).bind(c.relay_port).bind(mode).bind(i64::from(execution)).bind(&c.allocation_id).bind(&c.mapping_id)
        .bind(c.mapping_revision).bind(c.node_generation).bind(credential).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(DENIED)}
    let query=format!("SELECT {FIELDS} {CURRENT} JOIN relay_budget_grants g ON g.allocation_id=a.id WHERE g.id=?");
    let grant=sqlx::query_as::<_,Grant>(&query).bind(&c.grant_id).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    let row=sqlx::query_as::<_,IntentRecord>("SELECT grant_id,node_id,relay_port,bind_port,created_at,claimed_at FROM relay_budget_intents WHERE grant_id=?")
        .bind(&c.grant_id).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
        SELECT a.owner_id,?,a.live_mapping_id,a.mapping_revision,g.id,'claimed' FROM relay_budget_grants g JOIN relay_allocations a ON a.id=g.allocation_id WHERE g.id=?")
        .bind(if execution{"budget.start_claim"}else if guarded{"budget.run_claim_preview"}else{"budget.claimed"}).bind(&c.grant_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached(Json(serde_json::json!({"protocol_version":1,"nonce":c.nonce,"scope":if execution{"budget_guarded_tcp_start"}else if guarded{"budget_guarded_claim_preview_only"}else{"budget_claim_preview_only"},"executable":execution,"grant":grant,"intent":row}))))
}
