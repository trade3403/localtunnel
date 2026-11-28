//! Atomic control-plane reservations only; no relay credentials or execution authority.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,Query,State},http::{HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid scheduling request");
const CONFLICT:Failure=(StatusCode::CONFLICT,"allocation conflict or no eligible node");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"allocation service unavailable");
const MISSING:Failure=(StatusCode::NOT_FOUND,"allocation not found");
const FIELDS:&str="id,mapping_id,node_id,mapping_revision,generation,node_generation,bind_port,state";
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    request_key:String,device_id:String,region:Option<String>,node_id:Option<String>,
    domain_id:Option<String>,protocol:String,local_port:i64,bind_port:i64,
}
#[derive(Serialize,sqlx::FromRow)]
struct Allocation {
    id:String,mapping_id:String,node_id:String,mapping_revision:i64,generation:i64,node_generation:i64,bind_port:i64,state:String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel{expected_generation:i64}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn reference(s:&str)->bool{!s.is_empty()&&s.len()<=64&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
fn region(s:&str)->bool{!s.is_empty()&&s.len()<=32&&s.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'||b==b'_')}
fn db_error(e:sqlx::Error)->Failure{
    if let sqlx::Error::Database(db)=&e{
        if db.is_unique_violation()||db.is_foreign_key_violation()||db.is_check_violation(){return CONFLICT}
    }
    INTERNAL
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations",post(create).get(overview))
        .route("/api/v1/allocations/{id}",get(detail))
        .route("/api/v1/allocations/{id}/cancel",post(cancel))
        .layer(DefaultBodyLimit::max(4096)).with_state(pool)
}
async fn create(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Create>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&c.request_key)||!hex_id(&c.device_id)||c.node_id.as_deref().is_some_and(|v|!reference(v))||
       c.region.as_deref().is_some_and(|v|!region(v))||!(1..=65535).contains(&c.local_port)||!(20000..=29999).contains(&c.bind_port){return Err(BAD)}
    match (c.protocol.as_str(),c.domain_id.as_deref()){
        ("tcp"|"udp",None)=>{},
        ("http"|"https",Some(v)) if reference(v)=>{},
        _=>return Err(BAD),
    }
    let digest=Sha256::digest(serde_json::to_vec(&c).map_err(|_|INTERNAL)?).to_vec();
    let mapping=hex::encode(auth::random::<16>()?);
    let allocation=hex::encode(auth::random::<16>()?);
    let mut tx=pool.begin().await.map_err(db_error)?;
    // First transaction statement is a write, not a stale read snapshot.
    // SQLite serializes candidate selection with all mapping and policy writes.
    // Conservative capacity counts ALL existing desired mappings on a node.
    let sql="INSERT INTO mappings(id,owner_id,device_id,node_id,domain_id,protocol,local_port,bind_port)
        SELECT ?,d.owner_id,d.id,n.id,?,?,?,? FROM devices d JOIN users u ON u.id=d.owner_id
        JOIN admin_sessions a ON a.user_id=u.id CROSS JOIN nodes n
        JOIN relay_identities r ON r.node_id=n.id JOIN relay_heartbeat h ON h.node_id=n.id AND h.generation=r.generation
        WHERE d.id=? AND d.owner_id=? AND d.enabled=1 AND u.enabled=1 AND u.role='admin'
        AND a.token_digest=? AND a.expires_at>unixepoch()
        AND n.enabled=1 AND n.policy_mode='active' AND r.token_digest IS NOT NULL
        AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
        AND (? IS NULL OR n.region=?) AND (? IS NULL OR n.id=?)
        AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<min(n.approved_capacity,h.capacity)
        AND NOT EXISTS(SELECT 1 FROM mappings x WHERE x.node_id=n.id AND x.bind_port=?)
        AND (? IS NULL OR EXISTS(SELECT 1 FROM domains x WHERE x.id=? AND x.owner_id=d.owner_id))
        AND (SELECT count(*) FROM mappings x WHERE x.device_id=d.id)<64
        AND EXISTS(SELECT 1 FROM tenants t JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id
            WHERE t.owner_id=d.owner_id AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())
            AND (SELECT count(*) FROM mappings x WHERE x.owner_id=d.owner_id)<p.max_mappings)
        AND NOT EXISTS(SELECT 1 FROM relay_allocations x WHERE x.owner_id=d.owner_id AND x.request_key=?)
        ORDER BY (SELECT count(*) FROM mappings x WHERE x.node_id=n.id),n.id LIMIT 1 RETURNING node_id";
    let node=sqlx::query_scalar::<_,String>(sql).bind(&mapping).bind(&c.domain_id).bind(&c.protocol).bind(c.local_port).bind(c.bind_port)
        .bind(&c.device_id).bind(&owner).bind(&token).bind(&c.region).bind(&c.region).bind(&c.node_id).bind(&c.node_id)
        .bind(c.bind_port).bind(&c.domain_id).bind(&c.domain_id).bind(&c.request_key)
        .fetch_optional(&mut *tx).await.map_err(db_error)?;
    if let Some(node)=node{
        let query=format!("INSERT INTO relay_allocations(id,owner_id,request_key,request_digest,mapping_id,live_mapping_id,node_id,mapping_revision,generation,node_generation,bind_port,state)
            SELECT ?,?,?,?,?,?,r.node_id,1,1,r.generation,?,'reserved' FROM relay_identities r WHERE r.node_id=? RETURNING {FIELDS}");
        let row=sqlx::query_as::<_,Allocation>(&query).bind(&allocation).bind(&owner).bind(&c.request_key).bind(&digest)
            .bind(&mapping).bind(&mapping).bind(c.bind_port).bind(&node).fetch_one(&mut *tx).await.map_err(db_error)?;
        sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state) VALUES (?,'allocation.reserved',?,1,?,'reserved')")
            .bind(&owner).bind(&mapping).bind(&allocation).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        return Ok(auth::uncached((StatusCode::CREATED,Json(row))))
    }
    // Exact retries return the stored outcome, never allocate again after cancel.
    // Session validity is rechecked in the same transaction.
    let query=format!("SELECT {FIELDS} FROM relay_allocations WHERE owner_id=? AND request_key=? AND request_digest=? AND EXISTS(SELECT 1 FROM admin_sessions a JOIN users u ON u.id=a.user_id WHERE u.id=relay_allocations.owner_id AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch())");
    let row=sqlx::query_as::<_,Allocation>(&query).bind(&owner).bind(&c.request_key).bind(&digest).bind(&token)
        .fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or(CONFLICT)?;
    tx.commit().await.map_err(db_error)?;
    Ok(auth::uncached(Json(row)))
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let owner=auth::identify(&pool,&auth::bearer(&headers)?).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    let query=format!("SELECT {FIELDS} FROM relay_allocations WHERE id=? AND owner_id=?");
    let row=sqlx::query_as::<_,Allocation>(&query).bind(id).bind(owner).fetch_optional(&pool).await.map_err(db_error)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(row)))
}
async fn cancel(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Cancel>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    if c.expected_generation<1{return Err(BAD)}
    let mut tx=pool.begin().await.map_err(db_error)?;
    // Only the never-authorized reserved state is releasable in this version.
    // No expiry/heartbeat/revocation path frees reservations.
    let query=format!("UPDATE relay_allocations SET state='cancelled',live_mapping_id=NULL WHERE id=? AND owner_id=? AND generation=? AND state='reserved'
        AND EXISTS(SELECT 1 FROM admin_sessions a JOIN users u ON u.id=a.user_id WHERE u.id=relay_allocations.owner_id AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch())
        AND NOT EXISTS(SELECT 1 FROM runtime_requests r WHERE r.mapping_id=relay_allocations.mapping_id)
        AND NOT EXISTS(SELECT 1 FROM relay_grants g WHERE g.allocation_id=relay_allocations.id)
        AND NOT EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.allocation_id=relay_allocations.id)
        RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Allocation>(&query).bind(&id).bind(&owner).bind(c.expected_generation).bind(&token)
        .fetch_optional(&mut *tx).await.map_err(db_error)?;
    if let Some(row)=row{
        let changed=sqlx::query("DELETE FROM mappings WHERE id=? AND owner_id=? AND revision=? AND enabled=0")
            .bind(&row.mapping_id).bind(&owner).bind(row.mapping_revision).execute(&mut *tx).await.map_err(db_error)?;
        if changed.rows_affected()!=1{return Err(CONFLICT)}
        sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state) VALUES (?,'allocation.cancelled',?,?,?,'cancelled')")
            .bind(&owner).bind(&row.mapping_id).bind(row.mapping_revision).bind(&id).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        return Ok(auth::uncached(Json(row)))
    }
    let query=format!("SELECT {FIELDS} FROM relay_allocations WHERE id=? AND owner_id=? AND EXISTS(SELECT 1 FROM admin_sessions a JOIN users u ON u.id=a.user_id WHERE u.id=relay_allocations.owner_id AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch())");
    let row=sqlx::query_as::<_,Allocation>(&query).bind(id).bind(owner).bind(token).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or(MISSING)?;
    if row.state!="cancelled"||row.generation!=c.expected_generation{return Err(CONFLICT)}
    tx.commit().await.map_err(db_error)?;
    Ok(auth::uncached(Json(row)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor{after:Option<String>}
#[derive(Serialize,sqlx::FromRow)]
struct Overview{
    id:String,mapping_id:String,node_id:String,node_name:String,mapping_revision:i64,generation:i64,node_generation:i64,
    bind_port:i64,state:String,created_at:i64,protocol:Option<String>,local_port:Option<i64>,
    grant_id:Option<String>,grant_kind:Option<String>,expires_at:Option<i64>,revoked_at:Option<i64>,
    claimed_at:Option<i64>,relay_port:Option<i64>,authorization_state:String,
    failure_reason:Option<String>,failure_at:Option<i64>,fenced_at:Option<i64>,cleanup_at:Option<i64>,
    reclaimed_at:Option<i64>,retired_at:Option<i64>,auto_state:Option<String>,auto_entitlement_revision:Option<i64>,
    source_id:Option<String>,successor_id:Option<String>,lineage_epoch:i64,
    budget_entitlement_revision:Option<i64>,monthly_bytes:Option<i64>,connection_slots:Option<i64>,rate_bytes_per_second:Option<i64>,month_utc:Option<String>,
    cancellable:bool,
}
/// Owner-only snapshot, including historical records. A claimed lease is
/// authorization evidence, not process liveness or a successful data probe.
async fn overview(State(pool):State<SqlitePool>,headers:HeaderMap,Query(c):Query<Cursor>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    let after=c.after.unwrap_or_default();
    if !after.is_empty()&&!hex_id(&after){return Err(BAD)}
    let rows=sqlx::query_as::<_,Overview>("SELECT a.id,a.mapping_id,a.node_id,n.name AS node_name,a.mapping_revision,a.generation,a.node_generation,
      a.bind_port,a.state,a.created_at,coalesce(m.protocol,CASE WHEN retirement.allocation_id IS NOT NULL THEN 'tcp' END) AS protocol,
      coalesce(m.local_port,retirement.local_port) AS local_port,
      coalesce(bg.id,g.id) AS grant_id,CASE WHEN bg.id IS NOT NULL THEN 'finite' WHEN g.id IS NOT NULL THEN 'ordinary' END AS grant_kind,
      coalesce(bg.expires_at,g.expires_at) AS expires_at,coalesce(bg.revoked_at,g.revoked_at) AS revoked_at,
      i.claimed_at,i.relay_port,
      CASE WHEN retirement.allocation_id IS NOT NULL THEN 'retired'
      WHEN f.allocation_id IS NOT NULL THEN 'fenced'
      WHEN a.state='cancelled' THEN 'cancelled'
      WHEN coalesce(bg.id,g.id) IS NULL THEN 'not_issued'
      WHEN coalesce(bg.revoked_at,g.revoked_at) IS NOT NULL THEN 'revoked'
      WHEN coalesce(bg.expires_at,g.expires_at)<=unixepoch() THEN 'expired'
      WHEN i.claimed_at IS NOT NULL THEN 'claimed'
      WHEN i.grant_id IS NOT NULL THEN 'pending_claim'
      ELSE 'issued' END AS authorization_state,
      obs.reason AS failure_reason,obs.observed_at AS failure_at,f.fenced_at,cleanup.reported_at AS cleanup_at,
      reclaim.reclaimed_at,retirement.retired_at,
      CASE WHEN opt.cancelled_at IS NOT NULL THEN 'cancelled' WHEN opt.source_id IS NOT NULL THEN 'enabled' END AS auto_state,
      opt.entitlement_revision AS auto_entitlement_revision,
      parent.source_id,child.successor_id,coalesce(parent.lineage_epoch,1) AS lineage_epoch,
      b.entitlement_revision AS budget_entitlement_revision,b.monthly_bytes,b.connection_slots,b.rate_bytes_per_second,b.month_utc,
      CASE WHEN a.state='reserved' AND a.generation=1 AND b.allocation_id IS NULL AND g.id IS NULL AND bg.id IS NULL
      AND NOT EXISTS(SELECT 1 FROM runtime_requests rr WHERE rr.mapping_id=a.mapping_id) THEN 1 ELSE 0 END AS cancellable
      FROM relay_allocations a JOIN nodes n ON n.id=a.node_id
      LEFT JOIN mappings m ON m.id=a.live_mapping_id AND m.owner_id=a.owner_id
      LEFT JOIN relay_grants g ON g.allocation_id=a.id
      LEFT JOIN relay_budget_previews b ON b.allocation_id=a.id
      LEFT JOIN relay_budget_grants bg ON bg.allocation_id=a.id
      LEFT JOIN relay_budget_intents i ON i.grant_id=bg.id
      LEFT JOIN relay_allocation_fences f ON f.allocation_id=a.id
      LEFT JOIN relay_failure_observations obs ON obs.allocation_id=a.id
      LEFT JOIN relay_cleanup_reports cleanup ON cleanup.allocation_id=a.id
      LEFT JOIN relay_budget_reclaims reclaim ON reclaim.allocation_id=a.id
      LEFT JOIN relay_budget_retirements retirement ON retirement.allocation_id=a.id
      LEFT JOIN relay_auto_failover opt ON opt.source_id=a.id
      LEFT JOIN relay_failover_links parent ON parent.successor_id=a.id
      LEFT JOIN relay_failover_links child ON child.source_id=a.id
      WHERE a.owner_id=? AND a.id>? ORDER BY a.id LIMIT 101")
      .bind(owner).bind(after).fetch_all(&pool).await.map_err(db_error)?;
    let mut rows=rows;
    let more=rows.len()>100;rows.truncate(100);
    let next=if more{rows.last().map(|r|r.id.clone())}else{None};
    Ok(auth::uncached(Json(serde_json::json!({"scope":"owner_allocation_observations_only","executable":false,"allocations":rows,"next_after":next}))))
}
