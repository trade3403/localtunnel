//! Bounded, best-effort observations from a dedicated checked gateway revision.
use crate::auth;
use axum::{extract::{Path,State},http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::Serialize;
use sqlx::SqlitePool;
use std::{fs,path::{Path as FsPath,PathBuf},io::{Read,Seek,SeekFrom},time::{Duration,Instant}};
type Failure=(StatusCode,&'static str);
const UNAVAILABLE:Failure=(StatusCode::SERVICE_UNAVAILABLE,"traffic unavailable");
const MISSING:Failure=(StatusCode::NOT_FOUND,"mapping not found");
const MAX_BYTES:u64=4*1024*1024;
const MAX_LOG_FILES:usize=32;
const MAX_LOG_BYTES:u64=32*1024*1024;
const MAX_DIRECTORY_ENTRIES:usize=512;
const RETENTION:Duration=Duration::from_secs(7*24*60*60);

fn log_name(name:&str)->bool{
    let Some(revision)=name.strip_prefix("traffic-").and_then(|s|s.strip_suffix(".log")) else{return false};
    let Some((pid,stamp))=revision.split_once('-') else{return false};
    revision.len()<=64&&!pid.is_empty()&&!stamp.is_empty()&&
        pid.bytes().all(|b|b.is_ascii_digit())&&stamp.bytes().all(|b|b.is_ascii_digit())
}

#[cfg(target_os="linux")]
fn inventory(prefix:&FsPath)->Result<Vec<(PathBuf,fs::Metadata)>,&'static str>{
    use std::os::unix::fs::MetadataExt;
    let mut logs=Vec::new();
    for (i,entry) in fs::read_dir(prefix).map_err(|_|"log directory unavailable")?.enumerate(){
        if i>=MAX_DIRECTORY_ENTRIES{return Err("log directory entry limit")}
        let entry=entry.map_err(|_|"log directory read failed")?;
        let name=entry.file_name();
        if !name.to_str().is_some_and(log_name){continue}
        let m=fs::symlink_metadata(entry.path()).map_err(|_|"log metadata unavailable")?;
        if !m.is_file()||m.nlink()!=1||m.uid()!=unsafe{libc::geteuid()}{
            return Err("unsafe gateway log file")
        }
        logs.push((entry.path(),m));
    }
    Ok(logs)
}
#[cfg(target_os="linux")]
pub fn check_log_budget(prefix:&FsPath,reserve:bool)->Result<(),&'static str>{
    let logs=inventory(prefix)?;
    let mut total=0u64;
    for (_,m) in &logs{
        if m.len()>MAX_BYTES{return Err("gateway log file budget exceeded")}
        total=total.checked_add(m.len()).ok_or("gateway log size overflow")?;
    }
    let (files,bytes)=if reserve{(MAX_LOG_FILES-1,MAX_LOG_BYTES-MAX_BYTES)}else{(MAX_LOG_FILES,MAX_LOG_BYTES)};
    if logs.len()>files||total>bytes{return Err("gateway log inventory budget exceeded")}
    Ok(())
}
#[cfg(not(target_os="linux"))]
pub fn check_log_budget(_: &FsPath,_:bool)->Result<(),&'static str>{Err("Linux gateway logs only")}

// Caller must hold the dedicated offline maintenance guards. This is
// explicit retention pruning, never rotation of an open Nginx descriptor.
#[cfg(target_os="linux")]
pub fn prune_offline(prefix:&FsPath)->Result<usize,&'static str>{
    use std::os::unix::fs::MetadataExt;
    let logs=inventory(prefix)?;
    let now=std::time::SystemTime::now();
    let mut removed=0;
    for (path,m) in logs{
        if now.duration_since(m.modified().map_err(|_|"log time unavailable")?).unwrap_or_default()<RETENTION{continue}
        let current=fs::symlink_metadata(&path).map_err(|_|"log changed during pruning")?;
        if !current.is_file()||current.nlink()!=1||current.dev()!=m.dev()||current.ino()!=m.ino()||
            current.len()!=m.len()||current.modified().ok()!=m.modified().ok(){
            return Err("log changed during pruning")
        }
        fs::remove_file(path).map_err(|_|"old log removal failed")?;
        removed+=1;
    }
    Ok(removed)
}
#[cfg(not(target_os="linux"))]
pub fn prune_offline(_: &FsPath)->Result<usize,&'static str>{Err("Linux gateway logs only")}
#[derive(Serialize,sqlx::FromRow)]
struct Observation{
    request_id:String,mapping_revision:i64,requests:i64,request_bytes:i64,response_bytes:i64,sampled_at:i64,sampling_state:String,
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/mappings/{id}/traffic",get(list)).with_state(pool)
}
async fn list(State(pool):State<SqlitePool>,Path(id):Path<String>,headers:HeaderMap)->Result<Response,Failure>{
    let digest=auth::bearer(&headers)?;
    let owner=auth::identify(&pool,&digest).await?.id;
    let owned=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mappings m JOIN admin_sessions s ON s.user_id=m.owner_id WHERE m.id=? AND m.owner_id=? AND s.token_digest=? AND s.expires_at>unixepoch()")
        .bind(&id).bind(&owner).bind(&digest).fetch_one(&pool).await.map_err(|_|UNAVAILABLE)?;
    if owned!=1{return Err(MISSING)}
    let rows=sqlx::query_as::<_,Observation>("SELECT t.request_id,t.mapping_revision,t.requests,t.request_bytes,t.response_bytes,t.sampled_at,t.sampling_state FROM mapping_traffic t JOIN mappings m ON m.id=t.mapping_id JOIN admin_sessions s ON s.user_id=m.owner_id WHERE m.id=? AND m.owner_id=? AND s.token_digest=? AND s.expires_at>unixepoch() ORDER BY t.sampled_at DESC,t.request_id DESC LIMIT 50")
        .bind(id).bind(owner).bind(digest).fetch_all(&pool).await.map_err(|_|UNAVAILABLE)?;
    Ok(auth::uncached(Json(serde_json::json!({"scope":"observed_http_gateway_bytes_not_billing","observations":rows}))))
}
#[derive(Default,Clone,Copy)]
struct Counts{requests:i64,request_bytes:i64,response_bytes:i64}
impl Counts{
    fn add(&mut self,line:&str)->Result<(),()>{
        let mut parts=line.split_ascii_whitespace();
        let request=parts.next().ok_or(())?.parse::<i64>().map_err(|_|())?;
        let response=parts.next().ok_or(())?.parse::<i64>().map_err(|_|())?;
        let status=parts.next().ok_or(())?.parse::<u16>().map_err(|_|())?;
        if parts.next().is_some()||request<0||response<0||!(100..=599).contains(&status){return Err(())}
        self.requests=self.requests.checked_add(1).ok_or(())?;
        self.request_bytes=self.request_bytes.checked_add(request).ok_or(())?;
        self.response_bytes=self.response_bytes.checked_add(response).ok_or(())?;
        Ok(())
    }
}
pub struct Meter{
    path:Option<PathBuf>,file:Option<fs::File>,offset:u64,counts:Counts,failed:bool,last:Option<Instant>,
}
impl Meter{
    pub fn new(prefix:&FsPath)->Self{
        let path=(||{
            let config=fs::read_to_string(prefix.join("nginx.conf")).ok()?;
            let line=config.lines().next()?;
            if !line.starts_with("# localtunnel-managed-http ")&&!line.starts_with("# localtunnel-managed-https "){return None}
            let revision=line.split_ascii_whitespace().last()?;
            let (pid,stamp)=revision.split_once('-')?;
            if pid.is_empty()||stamp.is_empty()||revision.len()>64||!pid.bytes().all(|b|b.is_ascii_digit())||!stamp.bytes().all(|b|b.is_ascii_digit()){return None}
            let name=format!("traffic-{revision}.log");
            if !config.contains(&format!("access_log {name} lt_traffic;")){return None}
            Some(prefix.join(name))
        })();
        Self{path,file:None,offset:0,counts:Counts::default(),failed:false,last:None}
    }
    #[cfg(target_os="linux")]
    fn read(&mut self)->Result<(),()>{
        use std::os::unix::fs::{OpenOptionsExt,MetadataExt};
        let path=self.path.as_ref().ok_or(())?;
        let meta=fs::symlink_metadata(path).map_err(|_|())?;
        if !meta.file_type().is_file()||meta.len()>MAX_BYTES{return Err(())}
        if self.file.is_none(){
            self.file=Some(fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path).map_err(|_|())?);
        }
        let file=self.file.as_mut().ok_or(())?;
        let open=file.metadata().map_err(|_|())?;
        if !open.is_file()||open.ino()!=meta.ino()||open.dev()!=meta.dev()||open.len()<self.offset||open.len()>MAX_BYTES{return Err(())}
        file.seek(SeekFrom::Start(self.offset)).map_err(|_|())?;
        let mut data=Vec::new();
        file.take(65536).read_to_end(&mut data).map_err(|_|())?;
        let end=data.iter().rposition(|b|*b==b'\n').map_or(0,|i|i+1);
        if end==0&&data.len()>=65536{return Err(())}
        let complete=std::str::from_utf8(&data[..end]).map_err(|_|())?;
        let mut next=self.counts;
        for line in complete.lines(){next.add(line)?}
        self.counts=next;
        self.offset+=end as u64;
        Ok(())
    }
    #[cfg(not(target_os="linux"))]
    fn read(&mut self)->Result<(),()>{Err(())}
    pub async fn sample(&mut self,pool:&SqlitePool,id:&str,revision:i64,rid:&str,final_sample:bool){
        if !final_sample&&self.last.is_some_and(|t|t.elapsed()<Duration::from_secs(2)){return}
        self.last=Some(Instant::now());
        if !self.failed{
            // A final snapshot drains up to the same bounded file cap.
            let rounds=if final_sample{65}else{1};
            for _ in 0..rounds{
                let before=self.offset;
                if self.read().is_err(){self.failed=true;break}
                if self.offset==before{break}
            }
        }
        // "partial" at shutdown: old workers may finish writing after reload.
        // A SIGKILL leaves the last sample; no claim of complete totals.
        let state=if self.failed{"unavailable"}else if final_sample{"partial"}else{"sampled"};
        let _=sqlx::query("INSERT INTO mapping_traffic(request_id,mapping_id,mapping_revision,requests,request_bytes,response_bytes,sampled_at,sampling_state) SELECT ?,?,?,?,?,?,unixepoch(),? WHERE EXISTS(SELECT 1 FROM runtime_requests WHERE mapping_id=? AND request_id=? AND mapping_revision=?) ON CONFLICT(request_id) DO UPDATE SET requests=excluded.requests,request_bytes=excluded.request_bytes,response_bytes=excluded.response_bytes,sampled_at=excluded.sampled_at,sampling_state=excluded.sampling_state WHERE mapping_traffic.mapping_id=excluded.mapping_id AND mapping_traffic.mapping_revision=excluded.mapping_revision")
            .bind(rid).bind(id).bind(revision).bind(self.counts.requests).bind(self.counts.request_bytes).bind(self.counts.response_bytes).bind(state).bind(id).bind(rid).bind(revision)
            .execute(pool).await;
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn exact_generated_log_names(){
        for s in ["traffic-1-2.log","traffic-123-456789.log"]{assert!(log_name(s))}
        for s in ["traffic.log","traffic-1-2.log.old","traffic-1-x.log","traffic--2.log","traffic-1-2-3.log","../traffic-1-2.log"]{assert!(!log_name(s))}
    }
    #[test]fn numeric_lines_only(){
        let mut c=Counts::default();c.add("100 200 200").unwrap();c.add("50 80 502").unwrap();
        assert_eq!((c.requests,c.request_bytes,c.response_bytes),(2,150,280));
        for bad in ["-1 2 200","1 2 999","1 2 200 secret","foo 2 200"]{assert!(c.add(bad).is_err())}
    }
}
