//! Shared relay inventory is managed by the trusted local operator only.
use crate::auth;
use axum::{extract::{Query,State},http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;

type Failure=(StatusCode,&'static str);
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"node service unavailable");
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid node input");
const CONFLICT:Failure=(StatusCode::CONFLICT,"node conflict or unavailable");
#[derive(Serialize,sqlx::FromRow)]
struct Node {id:String,name:String,enabled:bool}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {after:Option<String>}
pub async fn add(pool:&SqlitePool,name:&str)->Result<String,Failure>{
    if name.is_empty()||name.len()>64||name.trim()!=name||name.chars().any(char::is_control){return Err(BAD)}
    let id=hex::encode(auth::random::<16>()?);
    sqlx::query("INSERT INTO nodes(id,name) VALUES (?,?)").bind(&id).bind(name)
        .execute(pool).await.map_err(|_|CONFLICT)?;
    Ok(id)
}
pub async fn set_enabled(pool:&SqlitePool,id:&str,enabled:bool)->Result<(),Failure>{
    // No disable while any enabled desired mapping refers to the node.
    let r=sqlx::query("UPDATE nodes SET enabled=? WHERE id=? AND (?=1 OR NOT EXISTS(SELECT 1 FROM mappings WHERE node_id=nodes.id AND enabled=1))")
        .bind(enabled).bind(id).bind(enabled).execute(pool).await.map_err(|_|INTERNAL)?;
    if r.rows_affected()!=1{return Err(CONFLICT)}
    Ok(())
}
// Read-only snapshot, not free slots, a reservation or an authorization.
// Match only the current credential generation and use the database clock.
pub(crate) const HEALTH_SELECT:&str="SELECT n.id AS node_id,n.enabled,n.approved_capacity,n.region,n.policy_mode,n.policy_revision,r.generation,h.received_at,h.capacity AS reported_capacity,CASE WHEN n.enabled=0 THEN 'disabled' WHEN r.node_id IS NULL THEN 'unregistered' WHEN r.token_digest IS NULL THEN 'revoked' WHEN h.node_id IS NULL THEN 'awaiting_heartbeat' WHEN h.received_at BETWEEN unixepoch()-15 AND unixepoch() THEN 'online' ELSE 'offline' END AS health,CASE WHEN n.enabled=1 AND r.token_digest IS NOT NULL AND n.policy_mode='active' AND h.received_at BETWEEN unixepoch()-15 AND unixepoch() THEN min(n.approved_capacity,h.capacity) ELSE 0 END AS candidate_capacity FROM nodes n LEFT JOIN relay_identities r ON r.node_id=n.id LEFT JOIN relay_heartbeat h ON h.node_id=r.node_id AND h.generation=r.generation";
#[derive(Serialize,sqlx::FromRow)]
pub(crate) struct OperationalHealth {
    node_id:String,enabled:bool,approved_capacity:i64,region:String,policy_mode:String,policy_revision:i64,
    generation:Option<i64>,received_at:Option<i64>,reported_capacity:Option<i64>,health:String,candidate_capacity:i64,
}
pub async fn operator_health(pool:&SqlitePool,id:&str)->Result<String,Failure>{
    let query=format!("{HEALTH_SELECT} WHERE n.id=?");
    let row=sqlx::query_as::<_,OperationalHealth>(&query).bind(id).fetch_optional(pool).await.map_err(|_|INTERNAL)?.ok_or(CONFLICT)?;
    serde_json::to_string(&row).map_err(|_|INTERNAL)
}
pub async fn set_policy(pool:&SqlitePool,id:&str,expected:i64,capacity:i64,region:&str,mode:&str)->Result<(),Failure>{
    if !(1..i64::MAX).contains(&expected)||!(0..=65536).contains(&capacity)||region.is_empty()||region.len()>32||
        !region.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'||b==b'_')||
        !matches!(mode,"active"|"draining"|"maintenance"){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let changed=sqlx::query("UPDATE nodes SET approved_capacity=?,region=?,policy_mode=?,policy_revision=policy_revision+1 WHERE id=? AND policy_revision=?")
        .bind(capacity).bind(region).bind(mode).bind(id).bind(expected).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    if changed.rows_affected()!=1{return Err(CONFLICT)}
    sqlx::query("INSERT INTO node_policy_audit(node_id,revision,approved_capacity,region,mode) VALUES (?,?,?,?,?)")
        .bind(id).bind(expected+1).bind(capacity).bind(region).bind(mode).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    // A queued request has not been claimed and owns no worker authority.
    // Serialize cancellation with the claim write. Never touch claimed,
    // running, stopping or unknown requests, or their resource reservations.
    if mode!="active"{
        sqlx::query("UPDATE runtime_requests SET state='stopped',updated_at=unixepoch() WHERE state='queued' AND mapping_id IN (SELECT id FROM mappings WHERE node_id=?)")
            .bind(id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    }
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(())
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/nodes",get(list)).with_state(pool)
}
async fn list(State(pool):State<SqlitePool>,headers:HeaderMap,Query(q):Query<Cursor>)->Result<Response,Failure>{
    auth::identify(&pool,&auth::bearer(&headers)?).await?;
    let after=q.after.unwrap_or_default();
    if after.len()>64||after.chars().any(char::is_control){return Err(BAD)}
    let rows=sqlx::query_as::<_,Node>("SELECT id,name,enabled FROM nodes WHERE id>? ORDER BY id LIMIT 100")
        .bind(after).fetch_all(&pool).await.map_err(|_|INTERNAL)?;
    Ok(auth::uncached(Json(rows)))
}
