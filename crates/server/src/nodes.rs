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
