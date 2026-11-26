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
}
#[derive(Serialize)]
struct View {
    scope:&'static str,
    commercial_enforcement:bool,
    enforced_admission:[&'static str;4],
    enforced_runtime_entitlement:bool,
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
        "SELECT t.id AS tenant_id,p.id AS plan_id,p.code AS plan_code,p.version AS plan_version,p.name AS plan_name,e.revision,e.state,e.expires_at,CASE WHEN e.state='suspended' THEN 'suspended' WHEN e.expires_at IS NOT NULL AND e.expires_at<=unixepoch() THEN 'expired' ELSE 'active' END AS effective_state,p.max_active_devices,p.max_retained_devices,p.max_mappings,p.max_bandwidth_bps,p.max_monthly_bytes,p.max_concurrent_connections,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id AND d.enabled=1) AS active_devices,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id) AS retained_devices,(SELECT count(*) FROM mappings m WHERE m.owner_id=u.id) AS mappings FROM users u JOIN admin_sessions a ON a.user_id=u.id JOIN tenants t ON t.owner_id=u.id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin'")
        .bind(digest).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(View{scope:"owner_inventory_only",commercial_enforcement:false,
        enforced_admission:["active_devices","retained_devices","mappings","active_entitlement_for_creation"],enforced_runtime_entitlement:true,entitlement})))
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
    // The first SQL statement is a write; stale assignment rolls it back.
    sqlx::query("UPDATE runtime_requests SET state=CASE WHEN state='queued' THEN 'stopped' ELSE 'stopping' END,updated_at=CASE WHEN state='queued' THEN unixepoch() ELSE updated_at END WHERE mapping_id IN (SELECT m.id FROM mappings m JOIN tenants t ON t.owner_id=m.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id WHERE t.id=? AND e.revision=? AND (runtime_requests.state='queued' OR (runtime_requests.state IN ('starting','running') AND (e.state<>'active' OR (e.expires_at IS NOT NULL AND e.expires_at<=unixepoch()) OR ?<>'active' OR (? IS NOT NULL AND ?<=unixepoch())))))")
        .bind(&c.tenant_id).bind(c.expected_revision).bind(&c.state).bind(c.expires_at).bind(c.expires_at)
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
