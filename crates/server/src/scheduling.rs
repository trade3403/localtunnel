//! Atomic control-plane reservations only; no relay credentials or execution authority.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
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
    Router::new().route("/api/v1/allocations",post(create))
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
