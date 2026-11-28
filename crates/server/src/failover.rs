//! Owner-triggered failover reservation after explicit terminal retirement.
//! Never issues a grant, starts a relay, or refunds the old monthly slice.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::post,Json,Router};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid failover request");
const MISSING:Failure=(StatusCode::NOT_FOUND,"allocation not found");
const CONFLICT:Failure=(StatusCode::CONFLICT,"failover not eligible or capacity unavailable");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"failover unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request{expected_generation:i64,source_grant_id:String,expected_entitlement_revision:i64}
#[derive(Serialize,sqlx::FromRow)]
struct Link{source_id:String,successor_id:String,source_grant_id:String,lineage_epoch:i64,entitlement_revision:i64,created_at:i64,
    mapping_id:String,node_id:String,node_generation:i64,bind_port:i64}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
const SELECT_LINK:&str="SELECT l.*,a.mapping_id,a.node_id,a.node_generation,a.bind_port FROM relay_failover_links l
 JOIN relay_allocations a ON a.id=l.successor_id WHERE l.source_id=? AND a.owner_id=?";
const SESSION:&str="EXISTS(SELECT 1 FROM admin_sessions s JOIN users u ON u.id=s.user_id
 WHERE u.id=old.owner_id AND u.enabled=1 AND u.role='admin' AND s.token_digest=? AND s.expires_at>unixepoch())";
fn reply(row:Link,created:bool)->Response{
    auth::uncached((if created{StatusCode::CREATED}else{StatusCode::OK},Json(serde_json::json!({
      "scope":"failover_successor_reserved","executable":false,"monthly_refunded":false,"link":row}))))
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/failover",post(reserve).get(detail))
        .layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
async fn reserve(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Request>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    if c.expected_generation!=4||!hex_id(&c.source_grant_id)||c.expected_entitlement_revision<1{return Err(BAD)}
    let mapping=hex::encode(auth::random::<16>()?);
    let allocation=hex::encode(auth::random::<16>()?);
    let request_key=hex::encode(auth::random::<16>()?);
    let digest=Sha256::digest(format!("failover-v1:{id}:{}",c.source_grant_id).as_bytes()).to_vec();
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    // Write first. The old terminal state, current session, capacity,
    // ownership and all three quota dimensions are checked in this transaction.
    let query=format!("INSERT INTO mappings(id,owner_id,device_id,node_id,protocol,local_port,bind_port)
      SELECT ?,old.owner_id,d.id,n.id,'tcp',r.local_port,r.bind_port
      FROM relay_budget_retirements r JOIN relay_allocations old ON old.id=r.allocation_id
      JOIN devices d ON d.id=r.device_id AND d.owner_id=old.owner_id
      JOIN tenants t ON t.owner_id=old.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id
      JOIN commercial_plans p ON p.id=e.plan_id JOIN relay_budget_previews b ON b.allocation_id=old.id
      CROSS JOIN nodes n JOIN relay_identities ri ON ri.node_id=n.id
      JOIN relay_heartbeat h ON h.node_id=n.id AND h.generation=ri.generation
      WHERE old.id=? AND old.owner_id=? AND old.generation=4 AND old.state='cancelled' AND r.grant_id=?
      AND e.revision=? AND {SESSION} AND d.enabled=1 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())
      AND n.id<>old.node_id AND n.enabled=1 AND n.policy_mode='active' AND ri.token_digest IS NOT NULL
      AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
      AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<min(n.approved_capacity,h.capacity)
      AND NOT EXISTS(SELECT 1 FROM mappings x WHERE x.node_id=n.id AND x.bind_port=r.bind_port)
      AND (SELECT count(*) FROM mappings x WHERE x.device_id=d.id)<64
      AND (SELECT count(*) FROM mappings x WHERE x.owner_id=old.owner_id)<p.max_mappings
      AND (SELECT count(*) FROM devices x WHERE x.owner_id=old.owner_id AND x.enabled=1)<=p.max_active_devices
      AND NOT EXISTS(SELECT 1 FROM relay_failover_links l WHERE l.source_id=old.id)
      AND p.max_bandwidth_bps IS NOT NULL AND p.max_monthly_bytes IS NOT NULL AND p.max_concurrent_connections IS NOT NULL
      AND (SELECT coalesce(sum(x.rate_bytes_per_second),0) FROM relay_budget_active x WHERE x.tenant_id=t.id)<=p.max_bandwidth_bps/8-b.rate_bytes_per_second
      AND (SELECT coalesce(sum(x.connection_slots),0) FROM relay_budget_active x WHERE x.tenant_id=t.id)<=p.max_concurrent_connections-b.connection_slots
      AND (SELECT coalesce(sum(x.monthly_bytes),0) FROM relay_budget_previews x WHERE x.tenant_id=t.id AND x.month_utc=strftime('%Y-%m','now'))
        <=p.max_monthly_bytes-b.monthly_bytes-coalesce((SELECT charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=strftime('%Y-%m','now')),0)
      ORDER BY (SELECT count(*) FROM mappings x WHERE x.node_id=n.id),n.id LIMIT 1 RETURNING node_id");
    let node=sqlx::query_scalar::<_,String>(&query).bind(&mapping).bind(&id).bind(&owner).bind(&c.source_grant_id)
        .bind(c.expected_entitlement_revision).bind(&token).fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?;
    if let Some(node)=node{
        sqlx::query("INSERT INTO relay_allocations(id,owner_id,request_key,request_digest,mapping_id,live_mapping_id,node_id,mapping_revision,generation,node_generation,bind_port,state)
          SELECT ?,m.owner_id,?,?,m.id,m.id,m.node_id,m.revision,1,r.generation,m.bind_port,'reserved'
          FROM mappings m JOIN relay_identities r ON r.node_id=m.node_id WHERE m.id=? AND m.node_id=?")
          .bind(&allocation).bind(&request_key).bind(&digest).bind(&mapping).bind(&node).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        // Existing database admission trigger is the authoritative quota check.
        sqlx::query("INSERT INTO relay_budget_previews(allocation_id,tenant_id,node_id,node_generation,allocation_generation,mapping_revision,entitlement_revision,policy_revision,rate_bytes_per_second,monthly_bytes,connection_slots,month_utc,created_at)
          SELECT a.id,b.tenant_id,a.node_id,a.node_generation,a.generation,a.mapping_revision,?,n.policy_revision,b.rate_bytes_per_second,b.monthly_bytes,b.connection_slots,strftime('%Y-%m','now'),unixepoch()
          FROM relay_allocations a JOIN nodes n ON n.id=a.node_id JOIN relay_budget_previews b ON b.allocation_id=? WHERE a.id=?")
          .bind(c.expected_entitlement_revision).bind(&id).bind(&allocation).execute(&mut *tx).await.map_err(|e|{
              if matches!(&e,sqlx::Error::Database(db) if db.message()=="budget preview unavailable"){CONFLICT}else{INTERNAL}
          })?;
        sqlx::query("INSERT INTO relay_failover_links(source_id,successor_id,source_grant_id,lineage_epoch,entitlement_revision,created_at)
          VALUES(?,?,?,coalesce((SELECT lineage_epoch FROM relay_failover_links WHERE successor_id=?),1)+1,?,unixepoch())")
          .bind(&id).bind(&allocation).bind(&c.source_grant_id).bind(&id).bind(c.expected_entitlement_revision)
          .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
          SELECT ?,'allocation.failover_reserved',successor_id,lineage_epoch,source_id,'reserved' FROM relay_failover_links WHERE source_id=?")
          .bind(&owner).bind(&id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        let row=sqlx::query_as::<_,Link>(SELECT_LINK).bind(&id).bind(&owner).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
        tx.commit().await.map_err(|_|INTERNAL)?;
        return Ok(reply(row,true))
    }
    let query=format!("{SELECT_LINK} AND l.source_grant_id=? AND l.entitlement_revision=?
      AND EXISTS(SELECT 1 FROM relay_allocations old WHERE old.id=l.source_id AND {SESSION})");
    let row=sqlx::query_as::<_,Link>(&query).bind(&id).bind(&owner).bind(&c.source_grant_id)
      .bind(c.expected_entitlement_revision).bind(&token).fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?;
    if let Some(row)=row{tx.commit().await.map_err(|_|INTERNAL)?;return Ok(reply(row,false))}
    let query=format!("SELECT count(*) FROM relay_allocations old WHERE old.id=? AND old.owner_id=? AND {SESSION}");
    let exists=sqlx::query_scalar::<_,i64>(&query).bind(id).bind(owner).bind(token).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    Err(if exists==0{MISSING}else{CONFLICT})
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    let query=format!("{SELECT_LINK} AND EXISTS(SELECT 1 FROM relay_allocations old WHERE old.id=l.source_id AND {SESSION})");
    let row=sqlx::query_as::<_,Link>(&query).bind(id).bind(owner).bind(token).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(MISSING)?;
    Ok(reply(row,false))
}
