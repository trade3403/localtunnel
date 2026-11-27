//! Central, non-executable cross-node quota reservation preview.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,State},http::{HeaderMap,StatusCode},response::Response,routing::post,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid budget preview");
const CONFLICT:Failure=(StatusCode::CONFLICT,"budget preview unavailable or reconciliation required");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"budget preview unavailable");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request{expected_generation:i64,expected_mapping_revision:i64,expected_entitlement_revision:i64,rate_bytes_per_second:i64,monthly_bytes:i64,connection_slots:i64}
#[derive(Serialize,sqlx::FromRow)]
struct Budget{allocation_id:String,node_id:String,node_generation:i64,allocation_generation:i64,mapping_revision:i64,entitlement_revision:i64,policy_revision:i64,rate_bytes_per_second:i64,monthly_bytes:i64,connection_slots:i64,month_utc:String,created_at:i64}
const FIELDS:&str="allocation_id,node_id,node_generation,allocation_generation,mapping_revision,entitlement_revision,policy_revision,rate_bytes_per_second,monthly_bytes,connection_slots,month_utc,created_at";
fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn db_error(e:sqlx::Error)->Failure{
    if let sqlx::Error::Database(db)=&e{
        if db.is_unique_violation()||db.is_check_violation()||db.message()=="budget preview unavailable"{return CONFLICT}
    }
    INTERNAL
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/allocations/{id}/budget-preview",post(reserve).get(detail))
        .layer(DefaultBodyLimit::max(1024)).with_state(pool)
}
async fn reserve(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Request>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !hex_id(&id)||c.expected_generation!=1||c.expected_mapping_revision<1||c.expected_entitlement_revision<1||
        !(65536..=125000000).contains(&c.rate_bytes_per_second)||!(1..=9000000000000000).contains(&c.monthly_bytes)||
        !(1..=65536).contains(&c.connection_slots){return Err(BAD)}
    let mut tx=pool.begin().await.map_err(db_error)?;
    // First statement writes. The trigger rechecks all three quota dimensions
    // under the same SQLite writer lock, across every node of this tenant.
    let query=format!("INSERT INTO relay_budget_previews(allocation_id,tenant_id,node_id,node_generation,allocation_generation,mapping_revision,entitlement_revision,policy_revision,rate_bytes_per_second,monthly_bytes,connection_slots,month_utc,created_at)
        SELECT a.id,t.id,a.node_id,a.node_generation,a.generation,a.mapping_revision,e.revision,n.policy_revision,?,?,?,strftime('%Y-%m','now'),unixepoch()
        FROM relay_allocations a JOIN tenants t ON t.owner_id=a.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN nodes n ON n.id=a.node_id
        WHERE a.id=? AND a.owner_id=? AND a.generation=? AND a.mapping_revision=? AND e.revision=?
        AND EXISTS(SELECT 1 FROM admin_sessions s JOIN users u ON u.id=s.user_id WHERE u.id=a.owner_id AND u.enabled=1 AND u.role='admin' AND s.token_digest=? AND s.expires_at>unixepoch())
        AND NOT EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.allocation_id=a.id)
        RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Budget>(&query).bind(c.rate_bytes_per_second).bind(c.monthly_bytes).bind(c.connection_slots)
        .bind(&id).bind(owner).bind(c.expected_generation).bind(c.expected_mapping_revision).bind(c.expected_entitlement_revision).bind(token)
        .fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or(CONFLICT)?;
    sqlx::query("INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
        SELECT a.owner_id,'budget.preview_reserved',a.mapping_id,a.mapping_revision,a.id,'reserved' FROM relay_allocations a WHERE a.id=?")
        .bind(&id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(serde_json::json!({"scope":"reservation_preview_only","executable":false,"budget":row})))))
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let owner=auth::identify(&pool,&auth::bearer(&headers)?).await?.id;
    if !hex_id(&id){return Err((StatusCode::NOT_FOUND,"budget preview not found"))}
    let query=format!("SELECT {FIELDS} FROM relay_budget_previews b WHERE b.allocation_id=? AND EXISTS(SELECT 1 FROM relay_allocations a WHERE a.id=b.allocation_id AND a.owner_id=?)");
    let row=sqlx::query_as::<_,Budget>(&query).bind(id).bind(owner).fetch_optional(&pool).await.map_err(db_error)?.ok_or((StatusCode::NOT_FOUND,"budget preview not found"))?;
    Ok(auth::uncached(Json(serde_json::json!({"scope":"reservation_preview_only","executable":false,"budget":row}))))
}
