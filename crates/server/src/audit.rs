//! Owner-scoped committed state history; no raw requests or credentials.
use crate::auth;
use axum::{extract::{Query,State},http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;

type Failure=(StatusCode,&'static str);
const UNAVAILABLE:Failure=(StatusCode::SERVICE_UNAVAILABLE,"audit unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor{before:Option<i64>}
#[derive(Serialize,sqlx::FromRow)]
struct Event{seq:i64,event:String,resource_id:String,revision:Option<i64>,request_id:Option<String>,state:Option<String>,occurred_at:i64}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/audit",get(list)).with_state(pool)
}
async fn list(State(pool):State<SqlitePool>,headers:HeaderMap,Query(q):Query<Cursor>)->Result<Response,Failure>{
    let digest=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&digest).await?.id;
    if q.before.is_some_and(|n|n<=0){return Err((StatusCode::BAD_REQUEST,"invalid audit cursor"))}
    let mut rows=sqlx::query_as::<_,Event>("SELECT a.seq,a.event,a.resource_id,a.revision,a.request_id,a.state,a.occurred_at FROM management_audit a JOIN users u ON u.id=a.owner_id JOIN admin_sessions s ON s.user_id=u.id WHERE a.owner_id=? AND s.token_digest=? AND s.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin' AND (? IS NULL OR a.seq<?) ORDER BY a.seq DESC LIMIT 101")
        .bind(owner).bind(digest).bind(q.before).bind(q.before).fetch_all(&pool).await.map_err(|_|UNAVAILABLE)?;
    let next_before=if rows.len()>100{rows.truncate(100);rows.last().map(|e|e.seq)}else{None};
    Ok(auth::uncached(Json(serde_json::json!({"scope":"committed_owner_state_changes","events":rows,"next_before":next_before}))))
}

/// Explicit trusted local maintenance only. The current runtime observation
/// is retained even if older than the cutoff; no files are removed here.
pub async fn prune(pool:&SqlitePool)->Result<(),&'static str>{
    let mut tx=pool.begin().await.map_err(|_|"history maintenance unavailable")?;
    sqlx::query("DELETE FROM management_audit WHERE occurred_at<unixepoch()-7776000")
        .execute(&mut *tx).await.map_err(|_|"audit pruning failed")?;
    sqlx::query("DELETE FROM mapping_traffic WHERE sampled_at<unixepoch()-7776000 AND NOT EXISTS(SELECT 1 FROM runtime_requests r WHERE r.request_id=mapping_traffic.request_id)")
        .execute(&mut *tx).await.map_err(|_|"traffic pruning failed")?;
    tx.commit().await.map_err(|_|"history maintenance outcome unknown")?;
    Ok(())
}
