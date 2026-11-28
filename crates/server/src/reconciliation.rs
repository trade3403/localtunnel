//! Explicit owner-requested expiry fencing. No replacement grant, resource
//! release, or quota refund. A lost heartbeat or revocation is not expiry.
use crate::{auth,relay};
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::post,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid fence request");
const MISSING:Failure=(StatusCode::NOT_FOUND,"allocation not found");
const CONFLICT:Failure=(StatusCode::CONFLICT,"allocation not ready for fencing");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"reconciliation unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request{expected_generation:i64,grant_id:String}
#[derive(Serialize,sqlx::FromRow)]
struct Fence{allocation_id:String,grant_id:String,grant_kind:String,old_generation:i64,new_generation:i64,node_id:String,node_generation:i64,expires_at:i64,fenced_at:i64}
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/fence",post(fence).get(detail))
                .route("/api/v1/relay/budget-cleanup-report",post(cleanup))
        .route("/api/v1/allocations/{id}/cleanup-report",axum::routing::get(cleanup_detail))
        .layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
const SESSION:&str="EXISTS(SELECT 1 FROM admin_sessions s JOIN users u ON u.id=s.user_id
 WHERE u.id=a.owner_id AND u.enabled=1 AND u.role='admin' AND s.token_digest=? AND s.expires_at>unixepoch())";
fn reply(row:Fence,created:bool)->Response{
    auth::uncached((if created{StatusCode::CREATED}else{StatusCode::OK},Json(serde_json::json!({
        "scope":"expired_generation_fenced_resources_retained","executable":false,"resources_released":false,"fence":row}))))
}
async fn fence(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Request>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    if c.expected_generation!=2||!hex_id(&c.grant_id){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    // Write first to serialize with issuance, claims and other fencing.
    let query=format!("INSERT INTO relay_allocation_fences(allocation_id,grant_id,grant_kind,old_generation,new_generation,node_id,node_generation,expires_at,fenced_at)
      SELECT a.id,g.id,g.kind,a.generation,a.generation+1,a.node_id,a.node_generation,g.expires_at,unixepoch()
      FROM relay_allocations a JOIN (
        SELECT id,allocation_id,expires_at,'ordinary' AS kind FROM relay_grants
        UNION ALL SELECT id,allocation_id,expires_at,'finite' AS kind FROM relay_budget_grants
      ) g ON g.allocation_id=a.id
      WHERE a.id=? AND a.owner_id=? AND a.generation=? AND a.state='reserved' AND g.id=? AND g.expires_at+2<=unixepoch()
        AND {SESSION} AND NOT EXISTS(SELECT 1 FROM relay_allocation_fences f WHERE f.allocation_id=a.id)
      RETURNING *");
    let row=sqlx::query_as::<_,Fence>(&query).bind(&id).bind(&owner).bind(c.expected_generation).bind(&c.grant_id).bind(&token)
        .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?;
    if let Some(row)=row{
        sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
          VALUES (?,'allocation.expiry_fenced',?,?,?,'retained')")
            .bind(&owner).bind(&id).bind(row.new_generation).bind(&row.grant_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        tx.commit().await.map_err(|_|INTERNAL)?;
        return Ok(reply(row,true))
    }
    let query=format!("SELECT f.* FROM relay_allocation_fences f JOIN relay_allocations a ON a.id=f.allocation_id
      WHERE a.id=? AND a.owner_id=? AND f.old_generation=? AND f.grant_id=? AND {SESSION}");
    let row=sqlx::query_as::<_,Fence>(&query).bind(&id).bind(&owner).bind(c.expected_generation).bind(&c.grant_id).bind(&token)
        .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?;
    if let Some(row)=row{tx.commit().await.map_err(|_|INTERNAL)?;return Ok(reply(row,false))}
    let query=format!("SELECT count(*) FROM relay_allocations a WHERE a.id=? AND a.owner_id=? AND {SESSION}");
    let exists=sqlx::query_scalar::<_,i64>(&query).bind(id).bind(owner).bind(token).fetch_one(&mut *tx).await.map_err(|_|INTERNAL)?;
    Err(if exists==0{MISSING}else{CONFLICT})
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    let query=format!("SELECT f.* FROM relay_allocation_fences f JOIN relay_allocations a ON a.id=f.allocation_id
      WHERE a.id=? AND a.owner_id=? AND {SESSION}");
    let row=sqlx::query_as::<_,Fence>(&query).bind(id).bind(owner).bind(token).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(MISSING)?;
    Ok(reply(row,false))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupRequest{protocol_version:i64,allocation_id:String,grant_id:String,node_id:String,node_generation:i64,
    fenced_generation:i64,relay_port:i64,bind_port:i64,nonce:String}
#[derive(Serialize,sqlx::FromRow)]
struct CleanupReport{allocation_id:String,grant_id:String,node_id:String,node_generation:i64,
    fenced_generation:i64,relay_port:i64,bind_port:i64,reported_at:i64}
const CLEANUP_MATCH:&str="f.allocation_id=? AND f.grant_id=? AND f.node_id=? AND f.node_generation=? AND f.new_generation=?
 AND i.relay_port=? AND i.bind_port=? AND r.token_digest=? AND n.enabled=1 AND a.state='reserved' AND a.generation=f.new_generation
 AND f.grant_kind='finite' AND i.execution_opt_in=1 AND i.claimed_at IS NOT NULL AND unixepoch()>=f.fenced_at";
const CLEANUP_FROM:&str="FROM relay_allocation_fences f JOIN relay_allocations a ON a.id=f.allocation_id
 JOIN relay_budget_intents i ON i.grant_id=f.grant_id AND i.node_id=f.node_id AND i.bind_port=a.bind_port
 JOIN relay_identities r ON r.node_id=f.node_id AND r.generation=f.node_generation JOIN nodes n ON n.id=r.node_id";
fn cleanup_reply(row:CleanupReport,nonce:Option<String>)->Response{
    auth::uncached(Json(serde_json::json!({"protocol_version":1,"nonce":nonce,
      "scope":"node_cleanup_observation_only","executable":false,"resources_released":false,"report":row})))
}
async fn cleanup(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<CleanupRequest>)->Result<Response,Failure>{
    let credential=relay::digest(&headers)?;
    if c.protocol_version!=1||!hex_id(&c.allocation_id)||!hex_id(&c.grant_id)||!hex_id(&c.node_id)||!hex_id(&c.nonce)
      ||c.node_generation<1||c.fenced_generation!=3||!(30000..=59999).contains(&c.relay_port)||!(20000..=29999).contains(&c.bind_port){return Err(BAD)}
    let denied=(StatusCode::UNAUTHORIZED,"invalid relay credential or cleanup binding");
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let query=format!("INSERT INTO relay_cleanup_reports(allocation_id,grant_id,node_id,node_generation,fenced_generation,relay_port,bind_port,reported_at)
      SELECT f.allocation_id,f.grant_id,f.node_id,f.node_generation,f.new_generation,i.relay_port,i.bind_port,unixepoch()
      {CLEANUP_FROM} WHERE {CLEANUP_MATCH} AND NOT EXISTS(SELECT 1 FROM relay_cleanup_reports x WHERE x.allocation_id=f.allocation_id)
      RETURNING *");
    let row=sqlx::query_as::<_,CleanupReport>(&query).bind(&c.allocation_id).bind(&c.grant_id).bind(&c.node_id)
      .bind(c.node_generation).bind(c.fenced_generation).bind(c.relay_port).bind(c.bind_port).bind(&credential)
      .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?;
    let row=if let Some(row)=row{
        sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
          SELECT owner_id,'allocation.cleanup_observed',id,generation,?,'retained' FROM relay_allocations WHERE id=?")
          .bind(&row.grant_id).bind(&row.allocation_id).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        row
    }else{
        let query=format!("SELECT x.* {CLEANUP_FROM} JOIN relay_cleanup_reports x ON x.allocation_id=f.allocation_id WHERE {CLEANUP_MATCH}");
        sqlx::query_as::<_,CleanupReport>(&query).bind(&c.allocation_id).bind(&c.grant_id).bind(&c.node_id)
          .bind(c.node_generation).bind(c.fenced_generation).bind(c.relay_port).bind(c.bind_port).bind(&credential)
          .fetch_optional(&mut *tx).await.map_err(|_|INTERNAL)?.ok_or(denied)?
    };
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(cleanup_reply(row,Some(c.nonce)))
}
async fn cleanup_detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id){return Err(MISSING)}
    let query=format!("SELECT x.* FROM relay_cleanup_reports x JOIN relay_allocations a ON a.id=x.allocation_id
      WHERE a.id=? AND a.owner_id=? AND {SESSION}");
    let row=sqlx::query_as::<_,CleanupReport>(&query).bind(id).bind(owner).bind(token).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(MISSING)?;
    Ok(cleanup_reply(row,None))
}
