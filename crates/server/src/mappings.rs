//! Administrator-owned desired mappings. Activation is deliberately gated
//! until verified domains and the data-plane apply/rollback path exist.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,Query,State},http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;

type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid mapping input");
const MISSING:Failure=(StatusCode::NOT_FOUND,"mapping not found");
const CONFLICT:Failure=(StatusCode::CONFLICT,"mapping conflict or unavailable target");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"mapping service unavailable");
const ACTIVATION:Failure=(StatusCode::CONFLICT,"activation not available");
const FIELDS:&str="id,device_id,node_id,domain_id,protocol,local_host,local_port,bind_port,enabled,revision";

#[derive(Serialize,sqlx::FromRow)]
struct Mapping {
    id:String,device_id:String,node_id:String,domain_id:Option<String>,protocol:String,
    local_host:String,local_port:i64,bind_port:i64,enabled:bool,revision:i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    device_id:String,node_id:String,domain_id:Option<String>,protocol:String,
    local_port:i64,bind_port:i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    expected_revision:i64,local_port:Option<i64>,bind_port:Option<i64>,enabled:Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {after:Option<String>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteQuery {expected_revision:i64}

fn valid_id(s:&str)->bool{
    s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn valid_reference(s:&str)->bool{
    !s.is_empty()&&s.len()<=64&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')
}
fn local_port(p:i64)->bool{(1..=65535).contains(&p)}
fn bind_port(p:i64)->bool{(20000..=29999).contains(&p)}
fn db_error(e:sqlx::Error)->Failure{
    if let sqlx::Error::Database(db)=&e{
        if db.is_unique_violation()||db.is_foreign_key_violation()||db.is_check_violation(){return CONFLICT}
    }
    INTERNAL
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new()
        .route("/api/v1/mappings",get(list).post(create))
        .route("/api/v1/mappings/{id}",get(detail).patch(change).delete(remove))
        .layer(DefaultBodyLimit::max(4096)).with_state(pool)
}
async fn list(State(pool):State<SqlitePool>,headers:HeaderMap,Query(q):Query<Cursor>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    let after=q.after.unwrap_or_default();
    if !after.is_empty()&&!valid_id(&after){return Err(BAD)}
    let query=format!("SELECT {FIELDS} FROM mappings WHERE owner_id=? AND id>? ORDER BY id LIMIT 100");
    let rows=sqlx::query_as::<_,Mapping>(&query).bind(owner).bind(after).fetch_all(&pool).await.map_err(db_error)?;
    Ok(auth::uncached(Json(rows)))
}
async fn detail(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let owner=auth::identify(&pool,&auth::bearer(&headers)?).await?.id;
    if !valid_id(&id){return Err(MISSING)}
    let query=format!("SELECT {FIELDS} FROM mappings WHERE id=? AND owner_id=?");
    let row=sqlx::query_as::<_,Mapping>(&query).bind(id).bind(owner).fetch_optional(&pool).await.map_err(db_error)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(row)))
}
async fn create(State(pool):State<SqlitePool>,headers:HeaderMap,Json(c):Json<Create>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !valid_id(&c.device_id)||!valid_reference(&c.node_id)||!local_port(c.local_port)||!bind_port(c.bind_port){return Err(BAD)}
    match (c.protocol.as_str(),c.domain_id.as_deref()){
        ("tcp"|"udp",None)=>{},
        ("http"|"https",Some(d)) if valid_reference(d)=>{},
        _=>return Err(BAD),
    }
    let id=hex::encode(auth::random::<16>()?);
    // Guard session, ownership, target state, and the per-device limit in
    // the same SQLite write, not a separate count followed by insertion.
    let query=format!("INSERT INTO mappings(id,owner_id,device_id,node_id,domain_id,protocol,local_port,bind_port) SELECT ?,d.owner_id,d.id,n.id,?,?,?,? FROM devices d JOIN users u ON u.id=d.owner_id JOIN admin_sessions a ON a.user_id=u.id JOIN nodes n ON n.id=? WHERE d.id=? AND d.owner_id=? AND d.enabled=1 AND n.enabled=1 AND u.enabled=1 AND u.role='admin' AND a.token_digest=? AND a.expires_at>unixepoch() AND (? IS NULL OR EXISTS (SELECT 1 FROM domains h WHERE h.id=? AND h.owner_id=d.owner_id)) AND (SELECT count(*) FROM mappings m WHERE m.device_id=d.id)<64 RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Mapping>(&query)
        .bind(id).bind(&c.domain_id).bind(&c.protocol).bind(c.local_port).bind(c.bind_port)
        .bind(&c.node_id).bind(&c.device_id).bind(owner).bind(token)
        .bind(&c.domain_id).bind(&c.domain_id)
        .fetch_optional(&pool).await.map_err(db_error)?.ok_or(CONFLICT)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(row))))
}
async fn change(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Json(c):Json<Change>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !valid_id(&id){return Err(MISSING)}
    if c.expected_revision<1||c.local_port.is_some_and(|p|!local_port(p))||c.bind_port.is_some_and(|p|!bind_port(p))||
        (c.local_port.is_none()&&c.bind_port.is_none()&&c.enabled.is_none()){return Err(BAD)}
    if c.enabled==Some(true){return Err(ACTIVATION)}
    // Existing enabled rows may only be explicitly disabled, not edited in
    // place. All mutations use optimistic concurrency and current authority.
    let query=format!("UPDATE mappings SET local_port=COALESCE(?,local_port),bind_port=COALESCE(?,bind_port),enabled=COALESCE(?,enabled),revision=revision+1 WHERE id=? AND owner_id=? AND revision=? AND NOT EXISTS(SELECT 1 FROM runtime_requests r WHERE r.mapping_id=mappings.id AND r.state<>'stopped') AND (enabled=0 OR (?=0 AND ? IS NULL AND ? IS NULL)) AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin') RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Mapping>(&query).bind(c.local_port).bind(c.bind_port).bind(c.enabled)
        .bind(&id).bind(&owner).bind(c.expected_revision).bind(c.enabled).bind(c.local_port).bind(c.bind_port).bind(token)
        .fetch_optional(&pool).await.map_err(db_error)?;
    match row {
        Some(m)=>Ok(auth::uncached(Json(m))),
        None=>Err(mutation_failure(&pool,&owner,&id).await?),
    }
}
async fn mutation_failure(pool:&SqlitePool,owner:&str,id:&str)->Result<Failure,Failure>{
    let exists=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mappings WHERE id=? AND owner_id=?")
        .bind(id).bind(owner).fetch_one(pool).await.map_err(db_error)?;
    Ok(if exists==0{MISSING}else{CONFLICT})
}
async fn remove(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap,Query(q):Query<DeleteQuery>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&token).await?.id;
    if !valid_id(&id){return Err(MISSING)}
    if q.expected_revision<1{return Err(BAD)}
    let r=sqlx::query("DELETE FROM mappings WHERE id=? AND owner_id=? AND revision=? AND enabled=0 AND NOT EXISTS(SELECT 1 FROM runtime_requests r WHERE r.mapping_id=mappings.id AND r.state<>'stopped') AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin')")
        .bind(&id).bind(&owner).bind(q.expected_revision).bind(token).execute(&pool).await.map_err(db_error)?;
    if r.rows_affected()!=1{return Err(mutation_failure(&pool,&owner,&id).await?)}
    Ok(auth::uncached(StatusCode::NO_CONTENT))
}
