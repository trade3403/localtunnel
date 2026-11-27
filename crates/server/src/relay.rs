//! Node-only identity. No tenant or runtime authority is granted here.
use crate::auth;
use axum::{extract::State,http::{header,HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::Serialize;
use sha2::{Digest,Sha256};
use sqlx::SqlitePool;

type Failure=(StatusCode,&'static str);
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid relay credential");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"relay identity unavailable");
const CONFLICT:Failure=(StatusCode::CONFLICT,"relay identity conflict");
const PREFIX:&str="ltrelay_";

fn digest(headers:&HeaderMap)->Result<Vec<u8>,Failure>{
    let mut values=headers.get_all(header::AUTHORIZATION).iter();
    let raw=values.next().ok_or(DENIED)?.to_str().map_err(|_|DENIED)?;
    if values.next().is_some(){return Err(DENIED)}
    let token=raw.strip_prefix("Bearer ").and_then(|s|s.strip_prefix(PREFIX)).ok_or(DENIED)?;
    if token.len()!=64||!token.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(DENIED)}
    Ok(Sha256::digest(hex::decode(token).map_err(|_|DENIED)?).to_vec())
}

#[derive(Serialize,sqlx::FromRow)]
struct Identity{node_id:String,generation:i64}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/relay/identity",get(identity)).with_state(pool)
}
async fn identity(State(pool):State<SqlitePool>,headers:HeaderMap)->Result<Response,Failure>{
    let id=sqlx::query_as::<_,Identity>("SELECT r.node_id,r.generation FROM relay_identities r JOIN nodes n ON n.id=r.node_id WHERE r.token_digest=? AND n.enabled=1")
        .bind(digest(&headers)?).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(id)))
}

// First issuance is distinct from rotation. The latter requires an exact
// expected generation, including re-issuance after explicit revocation.
pub async fn change(pool:&SqlitePool,node:&str,expected:i64,revoke:bool)->Result<Option<String>,Failure>{
    if node.is_empty()||node.len()>64||node.chars().any(char::is_control)||expected<0||expected==i64::MAX||revoke&&expected==0{return Err(CONFLICT)}
    let secret=if revoke{None}else{Some(auth::random::<32>()?)};
    let hash=secret.as_ref().map(|s|Sha256::digest(s).to_vec());
    let mut tx=pool.begin().await.map_err(|_|INTERNAL)?;
    let event=if expected==0{
        let r=sqlx::query("INSERT INTO relay_identities(node_id,token_digest,generation) SELECT id,?,1 FROM nodes WHERE id=? AND enabled=1 ON CONFLICT(node_id) DO NOTHING")
            .bind(&hash).bind(node).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        if r.rows_affected()!=1{return Err(CONFLICT)}
        "issued"
    }else{
        let r=sqlx::query("UPDATE relay_identities SET token_digest=?,generation=generation+1,changed_at=unixepoch() WHERE node_id=? AND generation=? AND ((?=1 AND token_digest IS NOT NULL) OR (?=0 AND EXISTS(SELECT 1 FROM nodes WHERE id=? AND enabled=1)))")
            .bind(&hash).bind(node).bind(expected).bind(revoke).bind(revoke).bind(node)
            .execute(&mut *tx).await.map_err(|_|INTERNAL)?;
        if r.rows_affected()!=1{return Err(CONFLICT)}
        if revoke{"revoked"}else{"rotated"}
    };
    sqlx::query("INSERT INTO relay_identity_audit(node_id,generation,event) VALUES (?,?,?)")
        .bind(node).bind(expected+1).bind(event).execute(&mut *tx).await.map_err(|_|INTERNAL)?;
    tx.commit().await.map_err(|_|INTERNAL)?;
    Ok(secret.map(|s|format!("{PREFIX}{}",hex::encode(s))))
}
