//! DNS TXT proof for exact hostnames. A verified record does not activate traffic.
use crate::auth;
use axum::{extract::{DefaultBodyLimit,Path,Query,State},http::{HeaderMap,StatusCode},response::Response,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;
use std::{net::{IpAddr,SocketAddrV4},process::{Command,Stdio},sync::Arc};
use tokio::sync::Semaphore;

type Failure=(StatusCode,&'static str);
const BAD:Failure=(StatusCode::BAD_REQUEST,"invalid domain");
const MISSING:Failure=(StatusCode::NOT_FOUND,"domain not found");
const CONFLICT:Failure=(StatusCode::CONFLICT,"domain conflict or proof not found");
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"domain verification unavailable");
const LIMITED:Failure=(StatusCode::TOO_MANY_REQUESTS,"verification busy");
const FIELDS:&str="id,hostname,verified_at,verification_token";

#[derive(Clone)]
struct DomainState {pool:SqlitePool,workers:Arc<Semaphore>,resolver:Option<SocketAddrV4>}
#[derive(sqlx::FromRow)]
struct Row {id:String,hostname:String,verified_at:Option<i64>,verification_token:Option<String>}
#[derive(Serialize)]
struct Domain {id:String,hostname:String,verified_at:Option<i64>,txt_name:String,txt_value:Option<String>}
impl From<Row> for Domain{
    fn from(r:Row)->Self{
        let txt_name=format!("_localtunnel.{}",r.hostname);
        Self{id:r.id,hostname:r.hostname,verified_at:r.verified_at,txt_name,txt_value:r.verification_token.map(|t|format!("localtunnel-verification={t}"))}
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {hostname:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {after:Option<String>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {domain_id:String}

fn valid_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub(crate) fn valid_host(s:&str)->bool{
    // Reserve space for the TXT prefix and follow the gateway's hostname grammar.
    s.len()<=240&&s.contains('.')&&s.parse::<IpAddr>().is_err()&&s!="localtunnel-probe.invalid"&&
        s.split('.').all(|l|!l.is_empty()&&l.len()<=63&&!l.starts_with('-')&&!l.ends_with('-')&&
            l.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'))&&
        s.rsplit('.').next().is_some_and(|l|l.bytes().any(|b|b.is_ascii_lowercase()))
}
fn db_error(e:sqlx::Error)->Failure{
    if let sqlx::Error::Database(db)=&e{
        if db.is_unique_violation()||db.is_foreign_key_violation(){return CONFLICT}
    }
    INTERNAL
}
pub fn routes(pool:SqlitePool)->Result<Router,Failure>{
    // Optional operator-only loopback resolver, never supplied by HTTP callers.
    // Default: operating system's configured DNS resolver.
    let resolver=match std::env::var("LOCALTUNNEL_DNS_RESOLVER"){
        Ok(v)=>{
            let addr:SocketAddrV4=v.parse().map_err(|_|BAD)?;
            if !addr.ip().is_loopback()||addr.port()==0{return Err(BAD)}
            Some(addr)
        },
        Err(std::env::VarError::NotPresent)=>None,
        Err(_)=>return Err(BAD),
    };
    let state=DomainState{pool,workers:Arc::new(Semaphore::new(2)),resolver};
    Ok(Router::new()
        .route("/api/v1/domains",get(list).post(create))
        .route("/api/v1/domains/{id}",get(detail).delete(remove))
        .route("/api/v1/domains/{id}/challenge",post(challenge))
        .route("/api/v1/domains/verify",post(verify))
        .layer(DefaultBodyLimit::max(4096)).with_state(state))
}
async fn list(State(s):State<DomainState>,headers:HeaderMap,Query(q):Query<Cursor>)->Result<Response,Failure>{
    let owner=auth::identify(&s.pool,&auth::bearer(&headers)?).await?.id;
    let after=q.after.unwrap_or_default();
    if !after.is_empty()&&!valid_id(&after){return Err(BAD)}
    let query=format!("SELECT {FIELDS} FROM domains WHERE owner_id=? AND id>? ORDER BY id LIMIT 100");
    let rows=sqlx::query_as::<_,Row>(&query).bind(owner).bind(after).fetch_all(&s.pool).await.map_err(db_error)?;
    Ok(auth::uncached(Json(rows.into_iter().map(Domain::from).collect::<Vec<_>>())))
}
async fn detail(State(s):State<DomainState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let owner=auth::identify(&s.pool,&auth::bearer(&headers)?).await?.id;
    let query=format!("SELECT {FIELDS} FROM domains WHERE owner_id=? AND id=?");
    let row=sqlx::query_as::<_,Row>(&query).bind(owner).bind(id).fetch_optional(&s.pool).await.map_err(db_error)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(Domain::from(row))))
}
async fn create(State(s):State<DomainState>,headers:HeaderMap,Json(c):Json<Create>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&s.pool,&token).await?.id;
    let hostname=c.hostname.to_ascii_lowercase();
    if !valid_host(&hostname){return Err(BAD)}
    let query=format!("INSERT INTO domains(id,owner_id,hostname,verification_token) SELECT ?,u.id,?,? FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE u.id=? AND a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin' AND (SELECT count(*) FROM domains WHERE owner_id=u.id)<100 RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Row>(&query).bind(hex::encode(auth::random::<16>()?)).bind(hostname)
        .bind(hex::encode(auth::random::<32>()?)).bind(owner).bind(token)
        .fetch_optional(&s.pool).await.map_err(db_error)?.ok_or(CONFLICT)?;
    Ok(auth::uncached((StatusCode::CREATED,Json(Domain::from(row)))))
}
async fn challenge(State(s):State<DomainState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&s.pool,&token).await?.id;
    // New proof invalidates the old one. Never rotate an enabled mapping.
    let query=format!("UPDATE domains SET verification_token=?,verified_at=NULL WHERE id=? AND owner_id=? AND NOT EXISTS(SELECT 1 FROM mappings WHERE domain_id=domains.id AND enabled=1) AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin') RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Row>(&query).bind(hex::encode(auth::random::<32>()?)).bind(id).bind(owner).bind(token)
        .fetch_optional(&s.pool).await.map_err(db_error)?.ok_or(MISSING)?;
    Ok(auth::uncached(Json(Domain::from(row))))
}
fn answer_matches(output:&str,qname:&str,value:&str)->bool{
    // Only exact owner TXT answers, not CNAME targets or substring matches.
    if !output.lines().any(|l|l.starts_with(";; ->>HEADER<<-")&&l.contains("status: NOERROR,")){return false}
    let expected=format!("\"{value}\"");
    let mut matching=false;
    for line in output.lines().filter(|l|!l.starts_with(';')&&!l.trim().is_empty()){
        let fields:Vec<_>=line.split_whitespace().collect();
        if fields.len()>=4&&fields[0].eq_ignore_ascii_case(qname)&&fields[3]=="CNAME"{return false}
        if fields.len()==5&&fields[0].eq_ignore_ascii_case(qname)&&fields[1].parse::<u32>().is_ok()&&fields[2]=="IN"&&fields[3]=="TXT"&&fields[4]==expected{matching=true}
    }
    matching
}
fn dns_query(resolver:Option<SocketAddrV4>,host:&str,proof:&str)->Result<bool,Failure>{
    let qname=format!("_localtunnel.{host}.");
    let mut cmd=Command::new("/usr/bin/dig");
    cmd.args(["-r","+tcp","+time=2","+tries=1","+noall","+comments","+answer","+nocmd","+nostats"]);
    if let Some(addr)=resolver{
        cmd.arg(format!("@{}",addr.ip())).args(["-p",&addr.port().to_string()]);
    }
    let out=cmd.arg(&qname).arg("TXT").stdin(Stdio::null()).output().map_err(|_|INTERNAL)?;
    if !out.status.success()||out.stdout.len()>262144{return Err(INTERNAL)}
    let text=std::str::from_utf8(&out.stdout).map_err(|_|INTERNAL)?;
    Ok(answer_matches(text,&qname,&format!("localtunnel-verification={proof}")))
}
async fn verify(State(s):State<DomainState>,headers:HeaderMap,Json(v):Json<Verify>)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&s.pool,&token).await?.id;
    if !valid_id(&v.domain_id){return Err(MISSING)}
    let query=format!("SELECT {FIELDS} FROM domains WHERE id=? AND owner_id=?");
    let row=sqlx::query_as::<_,Row>(&query).bind(&v.domain_id).bind(&owner).fetch_optional(&s.pool).await.map_err(db_error)?.ok_or(MISSING)?;
    if !valid_host(&row.hostname){return Err(BAD)}
    let proof=row.verification_token.ok_or(CONFLICT)?;
    if proof.len()!=64||!proof.bytes().all(|b|b.is_ascii_hexdigit()){return Err(CONFLICT)}
    let permit=s.workers.clone().try_acquire_owned().map_err(|_|LIMITED)?;
    let host=row.hostname.clone();
    let candidate=proof.clone();
    let resolver=s.resolver;
    let matched=tokio::task::spawn_blocking(move||{let _permit=permit;dns_query(resolver,&host,&candidate)})
        .await.map_err(|_|INTERNAL)??;
    if !matched{return Err(CONFLICT)}
    // DNS runs outside the transaction. Recheck the unchanged challenge and
    // current administrator session in the same write.
    let query=format!("UPDATE domains SET verified_at=unixepoch() WHERE id=? AND owner_id=? AND hostname=? AND verification_token=? AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin') RETURNING {FIELDS}");
    let row=sqlx::query_as::<_,Row>(&query).bind(v.domain_id).bind(owner).bind(row.hostname).bind(proof).bind(token)
        .fetch_optional(&s.pool).await.map_err(db_error)?.ok_or(CONFLICT)?;
    Ok(auth::uncached(Json(Domain::from(row))))
}
async fn remove(State(s):State<DomainState>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let token=auth::bearer(&headers)?;
    let owner=auth::identify(&s.pool,&token).await?.id;
    let r=sqlx::query("DELETE FROM domains WHERE id=? AND owner_id=? AND owner_id IN (SELECT u.id FROM users u JOIN admin_sessions a ON a.user_id=u.id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin')")
        .bind(id).bind(owner).bind(token).execute(&s.pool).await.map_err(db_error)?;
    if r.rows_affected()!=1{return Err(MISSING)}
    Ok(auth::uncached(StatusCode::NO_CONTENT))
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn hostname_and_answer(){
        for bad in ["*.example.test","a..test","127.0.0.1","localhost","a.test.","a;\n.test","localtunnel-probe.invalid"]{assert!(!valid_host(bad))}
        assert!(valid_host("a.example.test"));
        let h=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n";
        let q="_localtunnel.a.example.test.";
        assert!(answer_matches(&format!("{h}{q} 60 IN TXT \"proof\""),q,"proof"));
        assert!(!answer_matches(&format!("{h}{q} 60 IN TXT \"proof-extra\""),q,"proof"));
        assert!(!answer_matches(&format!("{h}other.example.test. 60 IN TXT \"proof\""),q,"proof"));
        assert!(!answer_matches(&format!("{h}{q} 60 IN CNAME other.example.test.\n{q} 60 IN TXT \"proof\""),q,"proof"));
    }
}
