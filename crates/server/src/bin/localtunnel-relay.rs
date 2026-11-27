//! Independent relay control-plane client, Linux loopback preview only.
//! No database access, tunnel listener, or runtime assignment authority.
#[cfg(target_os="linux")]
mod linux {
    use serde::Deserialize;
    use std::{fs::{self,OpenOptions},io::{Read,Write},net::{Ipv4Addr,SocketAddrV4,TcpStream},os::unix::fs::{MetadataExt,OpenOptionsExt,PermissionsExt},path::Path,time::{Duration,Instant}};
    const DEADLINE:Duration=Duration::from_secs(4);
    const PERIOD:Duration=Duration::from_secs(3);
    const MAX_RESPONSE:usize=8192;
    #[derive(Debug)]
    pub(super) enum Failure{Transient,Denied,Protocol}
    type Result<T>=std::result::Result<T,Failure>;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity{node_id:String,generation:i64}

    fn private_token(dir:&Path)->Result<String>{
        let m=fs::symlink_metadata(dir).map_err(|_|Failure::Protocol)?;
        let uid=unsafe{libc::geteuid()};
        if !m.is_dir()||m.uid()!=uid||m.permissions().mode()&0o777!=0o700{return Err(Failure::Protocol)}
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(dir.join("relay.token")).map_err(|_|Failure::Protocol)?;
        let m=file.metadata().map_err(|_|Failure::Protocol)?;
        if !m.is_file()||m.uid()!=uid||m.nlink()!=1||m.permissions().mode()&0o777!=0o600{return Err(Failure::Protocol)}
        let mut raw=String::new();
        file.take(74).read_to_string(&mut raw).map_err(|_|Failure::Protocol)?;
        let token=raw.strip_suffix('\n').unwrap_or(&raw);
        let hex=token.strip_prefix("ltrelay_").ok_or(Failure::Protocol)?;
        if hex.len()!=64||!hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(Failure::Protocol)}
        Ok(token.to_owned())
    }
    fn remaining(end:Instant)->Result<Duration>{
        end.checked_duration_since(Instant::now()).filter(|d|!d.is_zero()).ok_or(Failure::Transient)
    }
    fn request(port:u16,token:&str,path:&str,body:Option<&str>)->Result<(u16,Vec<u8>)>{
        let end=Instant::now()+DEADLINE;
        let addr=SocketAddrV4::new(Ipv4Addr::LOCALHOST,port);
        let mut stream=TcpStream::connect_timeout(&addr.into(),remaining(end)?).map_err(|_|Failure::Transient)?;
        let payload=body.unwrap_or("");
        let method=if body.is_some(){"POST"}else{"GET"};
        let request=format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",payload.len());
        let mut pending=request.as_bytes();
        while !pending.is_empty(){
            stream.set_write_timeout(Some(remaining(end)?)).map_err(|_|Failure::Transient)?;
            let n=stream.write(pending).map_err(|_|Failure::Transient)?;
            if n==0{return Err(Failure::Transient)}
            pending=&pending[n..];
        }
        let mut raw=Vec::new();
        let mut buf=[0u8;1024];
        loop{
            stream.set_read_timeout(Some(remaining(end)?)).map_err(|_|Failure::Transient)?;
            let n=stream.read(&mut buf).map_err(|_|Failure::Transient)?;
            if n==0{break}
            if raw.len()+n>MAX_RESPONSE{return Err(Failure::Protocol)}
            raw.extend_from_slice(&buf[..n]);
        }
        let split=raw.windows(4).position(|w|w==b"\r\n\r\n").ok_or(Failure::Protocol)?;
        let header=std::str::from_utf8(&raw[..split]).map_err(|_|Failure::Protocol)?;
        let mut lines=header.split("\r\n");
        let mut status=lines.next().ok_or(Failure::Protocol)?.split_whitespace();
        if status.next()!=Some("HTTP/1.1"){return Err(Failure::Protocol)}
        let code:u16=status.next().ok_or(Failure::Protocol)?.parse().map_err(|_|Failure::Protocol)?;
        if code==401||code==403{return Err(Failure::Denied)}
        if matches!(code,429|500|502|503|504){return Err(Failure::Transient)}
        let mut length=None;
        for line in lines{
            let (key,value)=line.split_once(':').ok_or(Failure::Protocol)?;
            if key.eq_ignore_ascii_case("transfer-encoding"){return Err(Failure::Protocol)}
            if key.eq_ignore_ascii_case("content-length"){
                if length.is_some(){return Err(Failure::Protocol)}
                length=Some(value.trim().parse::<usize>().map_err(|_|Failure::Protocol)?);
            }
        }
        let data=&raw[split+4..];
        if length.unwrap_or(0)!=data.len()||code==204&&!data.is_empty(){return Err(Failure::Protocol)}
        Ok((code,data.to_vec()))
    }
    fn heartbeat(port:u16,token:&str,node:&str,generation:i64,capacity:i64)->Result<()>{
        let (code,data)=request(port,token,"/api/v1/relay/identity",None)?;
        if code!=200{return Err(Failure::Protocol)}
        let id:Identity=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        if id.node_id!=node||id.generation!=generation{return Err(Failure::Denied)}
        let payload=serde_json::json!({"protocol_version":1,"generation":generation,"capacity":capacity}).to_string();
        let (code,data)=request(port,token,"/api/v1/relay/heartbeat",Some(&payload))?;
        if code!=204||!data.is_empty(){return Err(Failure::Protocol)}
        Ok(())
    }
    pub(super) fn run()->Result<()>{
        let args:Vec<_>=std::env::args_os().skip(1).collect();
        if args.len()!=5{return Err(Failure::Protocol)}
        let arg=|i:usize|args[i].to_str().ok_or(Failure::Protocol);
        let port:u16=arg(1)?.parse().map_err(|_|Failure::Protocol)?;
        let node=arg(2)?;
        let generation:i64=arg(3)?.parse().map_err(|_|Failure::Protocol)?;
        let capacity:i64=arg(4)?.parse().map_err(|_|Failure::Protocol)?;
        if port==0||node.len()!=32||!node.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||generation<1||!(0..=65536).contains(&capacity){return Err(Failure::Protocol)}
        let token=private_token(Path::new(&args[0]))?;
        let mut online=false;
        loop{
            match heartbeat(port,&token,node,generation,capacity){
                Ok(())=>{if !online{println!("relay control connected");online=true;}},
                Err(Failure::Transient)=>{if online{eprintln!("relay control unavailable");online=false;}},
                Err(e)=>return Err(e),
            }
            std::thread::sleep(PERIOD);
        }
    }
}
fn main(){
    #[cfg(target_os="linux")]
    if linux::run().is_ok(){return}
    // Fixed diagnostics only, never paths, credentials or response bodies.
    eprintln!("relay control stopped; Linux loopback preview usage: localtunnel-relay <private-dir> <port> <node-id> <generation> <capacity>");
    std::process::exit(1);
}
