//! Owner-scoped commercial inventory plus trusted local operator mutations.
//! HTTP policy is read-only; resource admission is enforced separately.
use crate::auth;
use axum::{extract::State,http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::Serialize;
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"commercial inventory unavailable");
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid credentials or session");

#[derive(Serialize,sqlx::FromRow)]
struct Entitlement {
    tenant_id:String, plan_id:String, plan_code:String, plan_version:i64, plan_name:String,
    revision:i64, state:String, expires_at:Option<i64>, effective_state:String,
    max_active_devices:i64,max_retained_devices:i64,max_mappings:i64,
    max_bandwidth_bps:Option<i64>,max_monthly_bytes:Option<i64>,max_concurrent_connections:Option<i64>,
    active_devices:i64,retained_devices:i64,mappings:i64,
    bandwidth_reservations:i64, reserved_bytes_per_second:Option<i64>,
    month_utc:String, monthly_charged_bytes:i64,
    reserved_connection_slots:i64,
}
#[derive(Serialize)]
struct View {
    scope:&'static str,
    commercial_enforcement:bool,
    enforced_admission:[&'static str;4],
    enforced_runtime_entitlement:bool,
    udp_bandwidth_scope:&'static str,
    web_bandwidth_scope:&'static str,
    tcp_bandwidth_scope:&'static str,
    aggregate_bandwidth_scope:&'static str,
    monthly_quota_scope:&'static str,
    connection_quota_scope:&'static str,
    entitlement:Entitlement,
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/commercial/entitlement",get(current)).with_state(pool)
}
async fn current(State(pool):State<SqlitePool>,headers:HeaderMap)->Result<Response,Failure>{
    let digest=auth::bearer(&headers)?;
    // Identity, policy and real counts in one SQL snapshot. No caller-
    // supplied owner/tenant selector, no device credentials or hashes.
    let entitlement=sqlx::query_as::<_,Entitlement>(
        "SELECT t.id AS tenant_id,p.id AS plan_id,p.code AS plan_code,p.version AS plan_version,p.name AS plan_name,e.revision,e.state,e.expires_at,CASE WHEN e.state='suspended' THEN 'suspended' WHEN e.expires_at IS NOT NULL AND e.expires_at<=unixepoch() THEN 'expired' ELSE 'active' END AS effective_state,p.max_active_devices,p.max_retained_devices,p.max_mappings,p.max_bandwidth_bps,p.max_monthly_bytes,p.max_concurrent_connections,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id AND d.enabled=1) AS active_devices,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id) AS retained_devices,(SELECT count(*) FROM mappings m WHERE m.owner_id=u.id) AS mappings,(SELECT count(*) FROM bandwidth_reservations b WHERE b.tenant_id=t.id) AS bandwidth_reservations,CASE WHEN EXISTS(SELECT 1 FROM bandwidth_reservations b WHERE b.tenant_id=t.id AND b.rate_bytes_per_second IS NULL) THEN NULL ELSE (SELECT coalesce(sum(b.rate_bytes_per_second),0) FROM bandwidth_reservations b WHERE b.tenant_id=t.id) END AS reserved_bytes_per_second,strftime('%Y-%m','now') AS month_utc,coalesce((SELECT charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=strftime('%Y-%m','now')),0) AS monthly_charged_bytes,(SELECT count(*) FROM connection_slots s JOIN bandwidth_reservations b ON b.id=s.reservation_id WHERE b.tenant_id=t.id) AS reserved_connection_slots FROM users u JOIN admin_sessions a ON a.user_id=u.id JOIN tenants t ON t.owner_id=u.id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin'")
        .bind(digest).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(View{scope:"owner_inventory_only",commercial_enforcement:false,
        enforced_admission:["active_devices","retained_devices","mappings","active_entitlement_for_creation"],enforced_runtime_entitlement:true,udp_bandwidth_scope:"per_mapping_per_direction_guarded_payload_only",web_bandwidth_scope:"supervised_web_per_mapping_per_direction_tcp_stream",tcp_bandwidth_scope:"supervised_tcp_per_mapping_per_direction_stream",aggregate_bandwidth_scope:"same_database_fixed_reservations_per_direction_not_measured_usage",monthly_quota_scope:"finite_plan_managed_tcp_http_https_udp_precharged_both_directions",connection_quota_scope:"finite_plan_managed_tcp_http_https_backend_stream_and_udp_source_slots_including_unknown",entitlement})))
}


#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewPlan{
    code:String,version:i64,name:String,max_active_devices:i64,max_retained_devices:i64,max_mappings:i64,
    max_bandwidth_bps:Option<i64>,max_monthly_bytes:Option<i64>,max_concurrent_connections:Option<i64>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAccount{username:String,password:String,plan_id:String,expires_at:Option<i64>}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment{tenant_id:String,plan_id:String,expected_revision:i64,state:String,expires_at:Option<i64>}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn plan_id(s:&str)->bool{s=="legacy-v1"||hex_id(s)}
fn expiry(v:Option<i64>)->bool{v.is_none_or(|v|v>0)}
fn valid_plan(p:&NewPlan)->bool{
    (1..=32).contains(&p.code.len())&&p.code!="legacy"&&p.code.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-')
    &&(1..=i32::MAX as i64).contains(&p.version)&&!p.name.trim().is_empty()&&p.name.len()<=128&&!p.name.chars().any(char::is_control)
    &&(1..=64).contains(&p.max_active_devices)&&(p.max_active_devices..=256).contains(&p.max_retained_devices)
    &&(1..=4096).contains(&p.max_mappings)&&p.max_bandwidth_bps.is_none_or(|n|(1..=1_000_000_000_000).contains(&n))
    &&p.max_monthly_bytes.is_none_or(|n|(1..=9_000_000_000_000_000).contains(&n))
    &&p.max_concurrent_connections.is_none_or(|n|(1..=65536).contains(&n))
}
fn random_id()->Result<String,&'static str>{Ok(hex::encode(auth::random::<16>().map_err(|_|"commercial random source unavailable")?))}
fn decode<T:serde::de::DeserializeOwned>(bytes:&[u8])->Result<T,&'static str>{
    serde_json::from_slice(bytes).map_err(|_|"invalid commercial operator input")
}
/// Only the local operator CLI calls this. Credentials are accepted on
/// bounded stdin, never argv, output, HTTP or audit. All errors are static.
pub async fn operator(pool:&SqlitePool,action:&str)->Result<String,&'static str>{
    use std::io::Read;
    let mut bytes=Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes).map_err(|_|"commercial input unavailable")?;
    if bytes.len()>4096{return Err("commercial input too large")}
    match action{
        "--commercial-create-plan"=>create_plan(pool,decode(&bytes)?).await,
        "--commercial-create-account"=>create_account(pool,decode(&bytes)?).await,
        "--commercial-assign"=>assign(pool,decode(&bytes)?).await,
        _=>Err("unknown commercial action"),
    }
}
async fn create_plan(pool:&SqlitePool,p:NewPlan)->Result<String,&'static str>{
    if !valid_plan(&p){return Err("invalid plan policy")}
    let id=random_id()?;
    let mut tx=pool.begin().await.map_err(|_|"commercial transaction unavailable")?;
    sqlx::query("INSERT INTO commercial_plans(id,code,version,name,max_active_devices,max_retained_devices,max_mappings,max_bandwidth_bps,max_monthly_bytes,max_concurrent_connections) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(&id).bind(&p.code).bind(p.version).bind(&p.name).bind(p.max_active_devices).bind(p.max_retained_devices).bind(p.max_mappings)
        .bind(p.max_bandwidth_bps).bind(p.max_monthly_bytes).bind(p.max_concurrent_connections)
        .execute(&mut *tx).await.map_err(|_|"plan creation refused")?;
    sqlx::query("INSERT INTO commercial_operator_audit(event,plan_id,revision) VALUES ('plan.created',?,?)")
        .bind(&id).bind(p.version).execute(&mut *tx).await.map_err(|_|"commercial audit write failed")?;
    tx.commit().await.map_err(|_|"commercial commit outcome unknown")?;
    Ok(id)
}
async fn create_account(pool:&SqlitePool,c:NewAccount)->Result<String,&'static str>{
    if !plan_id(&c.plan_id)||!expiry(c.expires_at){return Err("invalid account policy")}
    let phc=auth::operator_password_hash(&c.username,&c.password)?;
    let id=random_id()?;
    let mut tx=pool.begin().await.map_err(|_|"commercial transaction unavailable")?;
    // 'admin' is the legacy owner-scoped role, not a global operator role.
    let inserted=sqlx::query("INSERT INTO users(id,username,password_hash,role) SELECT ?,?,?,'admin' WHERE EXISTS(SELECT 1 FROM commercial_plans WHERE id=?)")
        .bind(&id).bind(&c.username).bind(phc).bind(&c.plan_id).execute(&mut *tx).await.map_err(|_|"account creation refused")?;
    if inserted.rows_affected()!=1{return Err("account creation refused")}
    let tenant=sqlx::query_scalar::<_,String>("SELECT id FROM tenants WHERE owner_id=?")
        .bind(&id).fetch_one(&mut *tx).await.map_err(|_|"tenant creation unavailable")?;
    let changed=sqlx::query("UPDATE tenant_entitlements SET plan_id=?,expires_at=?,updated_at=unixepoch() WHERE tenant_id=? AND revision=1")
        .bind(&c.plan_id).bind(c.expires_at).bind(&tenant).execute(&mut *tx).await.map_err(|_|"account plan assignment refused")?;
    if changed.rows_affected()!=1{return Err("account plan assignment refused")}
    sqlx::query("INSERT INTO commercial_operator_audit(event,tenant_id,plan_id,revision,state,expires_at) VALUES ('account.created',?,?,1,'active',?)")
        .bind(&tenant).bind(&c.plan_id).bind(c.expires_at).execute(&mut *tx).await.map_err(|_|"commercial audit write failed")?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,state) VALUES (?,'commercial.account_created',?,1,'active')")
        .bind(&id).bind(&tenant).execute(&mut *tx).await.map_err(|_|"owner audit write failed")?;
    tx.commit().await.map_err(|_|"commercial commit outcome unknown")?;
    Ok(tenant)
}
async fn assign(pool:&SqlitePool,c:Assignment)->Result<String,&'static str>{
    if !hex_id(&c.tenant_id)||!plan_id(&c.plan_id)||c.expected_revision<1||c.expected_revision==i64::MAX
        ||!matches!(c.state.as_str(),"active"|"suspended")||!expiry(c.expires_at){return Err("invalid assignment")}
    let mut tx=pool.begin().await.map_err(|_|"commercial transaction unavailable")?;
    // Cancel unclaimed requests on any policy change. If the previous
    // entitlement was inactive or the new one is inactive, latch a stop
    // request even if an operator renews before the worker next polls.
    // Also stop managed UDP and web runs on a plan change, so a new guard budget
    // is always applied by a fresh worker generation.
    // The first SQL statement is a write; stale assignment rolls it back.
    sqlx::query("UPDATE runtime_requests SET state=CASE WHEN state='queued' THEN 'stopped' ELSE 'stopping' END,updated_at=CASE WHEN state='queued' THEN unixepoch() ELSE updated_at END WHERE mapping_id IN (SELECT m.id FROM mappings m JOIN tenants t ON t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id WHERE t.id=? AND e.revision=? AND (runtime_requests.state='queued' OR (runtime_requests.state IN ('starting','running') AND (e.state<>'active' OR (e.expires_at IS NOT NULL AND e.expires_at<=unixepoch()) OR ?<>'active' OR (? IS NOT NULL AND ?<=unixepoch()) OR (m.protocol IN ('udp','tcp','http','https') AND e.plan_id<>?)))))")
        .bind(&c.tenant_id).bind(c.expected_revision).bind(&c.state).bind(c.expires_at).bind(c.expires_at).bind(&c.plan_id)
        .execute(&mut *tx).await.map_err(|_|"commercial runtime stop request failed")?;
    let changed=sqlx::query("UPDATE tenant_entitlements SET plan_id=?,state=?,expires_at=?,revision=revision+1,updated_at=unixepoch() WHERE tenant_id=? AND revision=? AND EXISTS(SELECT 1 FROM commercial_plans WHERE id=?)")
        .bind(&c.plan_id).bind(&c.state).bind(c.expires_at).bind(&c.tenant_id).bind(c.expected_revision).bind(&c.plan_id)
        .execute(&mut *tx).await.map_err(|_|"assignment refused")?;
    if changed.rows_affected()!=1{return Err("assignment refused or stale revision")}
    let revision=c.expected_revision+1;
    sqlx::query("INSERT INTO commercial_operator_audit(event,tenant_id,plan_id,revision,state,expires_at) VALUES ('entitlement.assigned',?,?,?,?,?)")
        .bind(&c.tenant_id).bind(&c.plan_id).bind(revision).bind(&c.state).bind(c.expires_at)
        .execute(&mut *tx).await.map_err(|_|"commercial audit write failed")?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,state) SELECT owner_id,'commercial.entitlement_assigned',id,?,? FROM tenants WHERE id=?")
        .bind(revision).bind(&c.state).bind(&c.tenant_id).execute(&mut *tx).await.map_err(|_|"owner audit write failed")?;
    tx.commit().await.map_err(|_|"commercial commit outcome unknown")?;
    Ok(c.tenant_id)
}


/// Acquire the actual configured budget, before any owned engine or UDP
/// ingress starts. A NULL reservation marks an uncapped preview and blocks
/// finite admission until that preview has been confirmed stopped.
/// The INSERT is the atomic admission operation across independent workers.
pub async fn reserve_bandwidth(pool:&SqlitePool,mapping:&str,revision:i64,request:Option<&str>,bps:Option<i64>,rate:Option<u32>,monthly:Option<i64>,connections:Option<i64>)->Result<String,&'static str>{
    if bps.is_some()!=rate.is_some(){return Err("invalid bandwidth reservation")}
    let id=random_id()?;
    let rate=rate.map(i64::from);
    let changed=sqlx::query("INSERT INTO bandwidth_reservations(id,tenant_id,mapping_id,mapping_revision,request_id,rate_bytes_per_second,monthly_cap,connection_cap) SELECT ?,t.id,m.id,m.revision,?,?,?,? FROM mappings m JOIN tenants t ON t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id WHERE m.id=? AND m.revision=? AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()) AND p.max_bandwidth_bps IS ? AND p.max_monthly_bytes IS ? AND p.max_concurrent_connections IS ? AND (p.max_concurrent_connections IS NULL OR (m.protocol IN ('tcp','http','https','udp') AND ? IS NOT NULL AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations b WHERE b.tenant_id=t.id AND b.connection_cap IS NOT p.max_concurrent_connections))) AND (p.max_monthly_bytes IS NULL OR (m.protocol IN ('tcp','http','https','udp') AND ? IS NOT NULL AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations b WHERE b.tenant_id=t.id AND b.monthly_cap IS NOT p.max_monthly_bytes) AND coalesce((SELECT charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=strftime('%Y-%m','now')),0)<p.max_monthly_bytes)) AND (p.max_bandwidth_bps IS NULL OR (? BETWEEN 1 AND p.max_bandwidth_bps/8 AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations b WHERE b.tenant_id=t.id AND b.rate_bytes_per_second IS NULL) AND (SELECT coalesce(sum(b.rate_bytes_per_second),0) FROM bandwidth_reservations b WHERE b.tenant_id=t.id)<=p.max_bandwidth_bps/8-?))")
        .bind(&id).bind(request).bind(rate).bind(monthly).bind(connections).bind(mapping).bind(revision).bind(bps).bind(monthly).bind(connections).bind(request).bind(request).bind(rate).bind(rate)
        .execute(pool).await.map_err(|_|"bandwidth admission unavailable")?;
    if changed.rows_affected()!=1{return Err("tenant bandwidth budget unavailable or policy changed")}
    Ok(id)
}
/// Only the worker which reserved capacity may release its exact ID after
/// confirmed process/guard cleanup. No timer-based reaping or adoption.
pub async fn release_bandwidth(pool:&SqlitePool,id:Option<&str>)->Result<(),&'static str>{
    if let Some(id)=id{
        let n=sqlx::query("DELETE FROM bandwidth_reservations WHERE id=?").bind(id).execute(pool).await.map_err(|_|"bandwidth release unavailable")?.rows_affected();
        if n!=1{return Err("bandwidth release outcome unknown")}
    }
    Ok(())
}


#[derive(Serialize,sqlx::FromRow)]
struct Reservation{
    id:String,tenant_id:String,mapping_id:String,mapping_revision:i64,
    request_id:Option<String>,rate_bytes_per_second:Option<i64>,created_at:i64,
}
/// Trusted local inventory, no credential material. Bounded result; use
/// exact recovery ID rather than a broad "clear all" mutation.
pub async fn list_bandwidth(pool:&SqlitePool)->Result<String,&'static str>{
    let rows=sqlx::query_as::<_,Reservation>("SELECT id,tenant_id,mapping_id,mapping_revision,request_id,rate_bytes_per_second,created_at FROM bandwidth_reservations ORDER BY created_at,id LIMIT 1001")
        .fetch_all(pool).await.map_err(|_|"bandwidth inventory unavailable")?;
    let truncated=rows.len()>1000;
    serde_json::to_string(&serde_json::json!({"reservations":rows.into_iter().take(1000).collect::<Vec<_>>(),"truncated":truncated})).map_err(|_|"bandwidth inventory unavailable")
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverBandwidth{
    reservation_id:String,tenant_id:String,mapping_id:String,mapping_revision:i64,
    request_id:Option<String>,confirmation:String,
}
/// Caller MUST hold the exclusive global bandwidth guard. The explicit
/// offline assertion covers old binaries, external children and backups
/// which cannot be proved stopped by a file lock alone.
pub async fn recover_bandwidth(pool:&SqlitePool)->Result<String,&'static str>{
    use std::io::Read;
    let mut bytes=Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes).map_err(|_|"commercial input unavailable")?;
    if bytes.len()>4096{return Err("commercial input too large")}
    let c:RecoverBandwidth=decode(&bytes)?;
    if !hex_id(&c.reservation_id)||!hex_id(&c.tenant_id)||!hex_id(&c.mapping_id)||c.mapping_revision<1||
        c.request_id.as_ref().is_some_and(|id|!hex_id(id))||c.confirmation!="offline_all_tunnels_stopped"{
        return Err("invalid offline bandwidth recovery confirmation")
    }
    let mut tx=pool.begin().await.map_err(|_|"bandwidth recovery transaction unavailable")?;
    let n=sqlx::query("INSERT INTO bandwidth_recovery_audit(reservation_id,tenant_id,mapping_id,mapping_revision,request_id,rate_bytes_per_second,reserved_at,confirmation) SELECT id,tenant_id,mapping_id,mapping_revision,request_id,rate_bytes_per_second,created_at,'offline_all_tunnels_stopped' FROM bandwidth_reservations WHERE id=? AND tenant_id=? AND mapping_id=? AND mapping_revision=? AND request_id IS ?")
        .bind(&c.reservation_id).bind(&c.tenant_id).bind(&c.mapping_id).bind(c.mapping_revision).bind(&c.request_id)
        .execute(&mut *tx).await.map_err(|_|"bandwidth recovery refused")?.rows_affected();
    if n!=1{return Err("bandwidth reservation missing or binding changed")}
    let n=sqlx::query("DELETE FROM bandwidth_reservations WHERE id=?").bind(&c.reservation_id)
        .execute(&mut *tx).await.map_err(|_|"bandwidth recovery refused")?.rows_affected();
    if n!=1{return Err("bandwidth recovery outcome unknown")}
    tx.commit().await.map_err(|_|"bandwidth recovery outcome unknown")?;
    Ok(c.reservation_id)
}


/// One debit before each guarded stream write or datagram send. Both directions
/// consume the same durable tenant-month row. No refund/replay on failure.
/// The current wall-clock UTC month is selected inside the atomic statement.
pub async fn charge_monthly(pool:&SqlitePool,mapping:&str,revision:i64,rid:&str,cap:i64,n:usize)->Result<bool,&'static str>{
    if !(1..=4096).contains(&n)||!(1..=9_000_000_000_000_000).contains(&cap){return Err("invalid monthly debit")}
    let n=n as i64;
    let changed=sqlx::query("INSERT INTO tenant_monthly_usage(tenant_id,month_utc,charged_bytes) SELECT t.id,strftime('%Y-%m','now'),? FROM mappings m JOIN tenants t ON t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id JOIN runtime_requests r ON r.mapping_id=m.id JOIN users u ON u.id=m.owner_id JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN nodes node ON node.id=m.node_id WHERE m.id=? AND m.revision=? AND m.protocol IN ('tcp','http','https','udp') AND (m.protocol IN ('tcp','udp') OR EXISTS(SELECT 1 FROM domains h WHERE h.id=m.domain_id AND h.owner_id=m.owner_id AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch())) AND m.enabled=0 AND u.enabled=1 AND u.role='admin' AND d.enabled=1 AND node.enabled=1 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()) AND p.max_monthly_bytes=? AND ?<=p.max_monthly_bytes AND r.request_id=? AND r.mapping_revision=m.revision AND r.state IN ('starting','running') AND EXISTS(SELECT 1 FROM bandwidth_reservations b WHERE b.tenant_id=t.id AND b.mapping_id=m.id AND b.mapping_revision=m.revision AND b.request_id=r.request_id AND b.monthly_cap=p.max_monthly_bytes) ON CONFLICT(tenant_id,month_utc) DO UPDATE SET charged_bytes=tenant_monthly_usage.charged_bytes+excluded.charged_bytes WHERE tenant_monthly_usage.charged_bytes<=?-excluded.charged_bytes")
        .bind(n).bind(mapping).bind(revision).bind(cap).bind(n).bind(rid).bind(cap)
        .execute(pool).await.map_err(|_|"monthly debit unavailable")?;
    Ok(changed.rows_affected()==1)
}


/// Atomic same-tenant admission for a backend TCP stream or guarded UDP source.
/// Finite UDP launch remains gated by its supervisor and request admission.
/// Old or mismatched reservations cannot supply admission. Counts include
/// unknown/crashed slots until the exact reservation is safely recovered.
pub async fn acquire_connection(pool:&SqlitePool,mapping:&str,revision:i64,rid:&str,cap:i64)->Result<Option<String>,&'static str>{
    if !(1..=65536).contains(&cap){return Err("invalid connection cap")}
    let id=random_id()?;
    let n=sqlx::query("INSERT INTO connection_slots(id,reservation_id) SELECT ?,b.id FROM bandwidth_reservations b JOIN mappings m ON m.id=b.mapping_id AND m.revision=b.mapping_revision JOIN tenants t ON t.id=b.tenant_id AND t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id JOIN runtime_requests r ON r.mapping_id=m.id AND r.request_id=b.request_id JOIN users u ON u.id=m.owner_id JOIN devices d ON d.id=m.device_id AND d.owner_id=m.owner_id JOIN nodes node ON node.id=m.node_id WHERE m.id=? AND m.revision=? AND b.request_id=? AND r.mapping_revision=m.revision AND r.state IN ('starting','running') AND m.protocol IN ('tcp','http','https','udp') AND m.enabled=0 AND u.enabled=1 AND u.role='admin' AND d.enabled=1 AND node.enabled=1 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()) AND p.max_concurrent_connections=? AND b.connection_cap=p.max_concurrent_connections AND (m.protocol IN ('tcp','udp') OR EXISTS(SELECT 1 FROM domains h WHERE h.id=m.domain_id AND h.owner_id=m.owner_id AND h.verification_token IS NOT NULL AND h.verified_at BETWEEN unixepoch()-300 AND unixepoch())) AND (SELECT count(*) FROM connection_slots s JOIN bandwidth_reservations existing ON existing.id=s.reservation_id WHERE existing.tenant_id=t.id)<p.max_concurrent_connections")
        .bind(&id).bind(mapping).bind(revision).bind(rid).bind(cap).execute(pool).await.map_err(|_|"connection admission unavailable")?.rows_affected();
    match n{0=>Ok(None),1=>Ok(Some(id)),_=>Err("ambiguous connection admission")}
}
pub async fn release_connection(pool:&SqlitePool,id:&str)->Result<(),&'static str>{
    let n=sqlx::query("DELETE FROM connection_slots WHERE id=?").bind(id).execute(pool).await.map_err(|_|"connection release unavailable")?.rows_affected();
    if n!=1{return Err("connection release outcome unknown")}
    Ok(())
}
