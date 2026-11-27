//! Independent relay control-plane client: loopback preview or verified HTTPS.
//! No database access, tunnel listener, or runtime assignment authority.
#[cfg(target_os="linux")]
mod linux {
    use serde::Deserialize;
    use rand_core::{OsRng,RngCore};
    use std::{fs::{self,OpenOptions},io::{Read,Write},net::{Ipv4Addr,SocketAddrV4,TcpStream},os::unix::fs::{MetadataExt,OpenOptionsExt,PermissionsExt},path::{Path,PathBuf},process::{Command,Stdio},time::{Duration,Instant}};
    const DEADLINE:Duration=Duration::from_secs(4);
    const PERIOD:Duration=Duration::from_secs(3);
    const MAX_RESPONSE:usize=8192;
    #[derive(Debug)]
    pub(super) enum Failure{Transient,Denied,Protocol}
    type Result<T>=std::result::Result<T,Failure>;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Control{protocol_version:i64,nonce:String,scope:String,policy:Policy}
    #[derive(Deserialize,PartialEq,Eq)]
    #[serde(deny_unknown_fields)]
    struct Policy{node_id:String,generation:i64,policy_revision:i64,approved_capacity:i64,region:String,policy_mode:String,received_at:i64}
    impl Policy{
        fn same_revision(&self,other:&Self)->bool{
            self.policy_revision==other.policy_revision&&self.approved_capacity==other.approved_capacity&&self.region==other.region&&self.policy_mode==other.policy_mode
        }
    }

    fn private_file(dir:&Path,name:&str)->Result<fs::File>{
        let m=fs::symlink_metadata(dir).map_err(|_|Failure::Protocol)?;
        let uid=unsafe{libc::geteuid()};
        if !m.is_dir()||m.uid()!=uid||m.permissions().mode()&0o777!=0o700{return Err(Failure::Protocol)}
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(dir.join(name)).map_err(|_|Failure::Protocol)?;
        let m=file.metadata().map_err(|_|Failure::Protocol)?;
        if !m.is_file()||m.uid()!=uid||m.nlink()!=1||m.permissions().mode()&0o777!=0o600{return Err(Failure::Protocol)}
        Ok(file)
    }
    fn private_token(dir:&Path)->Result<String>{
        let file=private_file(dir,"relay.token")?;
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
    enum Endpoint{
        Loopback(u16),
        Tls{host:String,port:u16,dir:PathBuf},
    }
    fn hostname(s:&str)->bool{
        !s.is_empty()&&s.len()<=253&&s.split('.').all(|label|!label.is_empty()&&label.len()<=63&&
            !label.starts_with('-')&&!label.ends_with('-')&&label.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'))
    }
    fn tls_request(host:&str,port:u16,dir:&Path,token:&str,path:&str,body:Option<&str>)->Result<(u16,Vec<u8>)>{
        let ca=private_file(dir,"center-ca.pem")?;
        if !(1..=65536).contains(&ca.metadata().map_err(|_|Failure::Protocol)?.len()){return Err(Failure::Protocol)}
        let url=format!("https://{host}:{port}{path}");
        let mut cmd=Command::new("/usr/bin/curl");
        // Explicit private trust store, no default config, proxy or downgrade.
        cmd.env_clear().args(["--disable","--silent","--proto","=https","--http1.1","--tlsv1.2",
            "--noproxy","*","--connect-timeout","3","--max-time","4","--max-filesize","8192",
            "--write-out","\n%{http_code}","--config","-","--cacert"])
            .arg(dir.join("center-ca.pem")).arg("--capath").arg(dir)
            .arg("--request").arg(if body.is_some(){"POST"}else{"GET"})
            .args(["--header","Content-Type: application/json","--header","Connection: close"]);
        if let Some(payload)=body{cmd.arg("--data-binary").arg(payload);}
        let mut child=cmd.arg("--url").arg(url).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().map_err(|_|Failure::Protocol)?;
        // Credential only in stdin, never argv, env or diagnostics.
        let sent=child.stdin.take().ok_or(Failure::Protocol).and_then(|mut input|
            writeln!(input,"header = \"Authorization: Bearer {token}\"").map_err(|_|Failure::Transient));
        if let Err(e)=sent{let _=child.kill();let _=child.wait();return Err(e)}
        let mut raw=Vec::new();
        let read=child.stdout.take().ok_or(Failure::Protocol).and_then(|out|
            out.take((MAX_RESPONSE+5) as u64).read_to_end(&mut raw).map_err(|_|Failure::Transient));
        if read.is_err()||raw.len()>MAX_RESPONSE+4{
            let _=child.kill();let _=child.wait();return Err(Failure::Protocol)
        }
        let status=child.wait().map_err(|_|Failure::Transient)?;
        if !status.success(){
            return Err(match status.code(){
                Some(5|6|7|18|28|52|55|56)=>Failure::Transient,
                _=>Failure::Protocol,
            })
        }
        if raw.len()<4{return Err(Failure::Protocol)}
        let split=raw.len()-4;
        if raw[split]!=b'\n'{return Err(Failure::Protocol)}
        let code=std::str::from_utf8(&raw[split+1..]).map_err(|_|Failure::Protocol)?.parse::<u16>().map_err(|_|Failure::Protocol)?;
        if code==401||code==403{return Err(Failure::Denied)}
        if matches!(code,429|500|502|503|504){return Err(Failure::Transient)}
        if !matches!(code,200|204){return Err(Failure::Protocol)}
        raw.truncate(split);
        if code==204&&!raw.is_empty(){return Err(Failure::Protocol)}
        Ok((code,raw))
    }
    fn request(endpoint:&Endpoint,token:&str,path:&str,body:Option<&str>)->Result<(u16,Vec<u8>)>{
        match endpoint{
            Endpoint::Loopback(port)=>loopback_request(*port,token,path,body),
            Endpoint::Tls{host,port,dir}=>tls_request(host,*port,dir,token,path,body),
        }
    }
    fn loopback_request(port:u16,token:&str,path:&str,body:Option<&str>)->Result<(u16,Vec<u8>)>{
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
    fn synchronize(endpoint:&Endpoint,token:&str,node:&str,generation:i64,capacity:i64,previous:Option<&Policy>)->Result<Policy>{
        let mut bytes=[0u8;16];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_|Failure::Protocol)?;
        let nonce=hex::encode(bytes);
        let payload=serde_json::json!({"protocol_version":1,"node_id":node,"generation":generation,"capacity":capacity,"nonce":nonce}).to_string();
        let (code,data)=request(endpoint,token,"/api/v1/relay/control",Some(&payload))?;
        if code!=200{return Err(Failure::Protocol)}
        let result:Control=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        if result.protocol_version!=1||result.nonce!=nonce||result.scope!="control_only"{return Err(Failure::Protocol)}
        let p=result.policy;
        if p.node_id!=node||p.generation!=generation{return Err(Failure::Denied)}
        if p.policy_revision<1||!(0..=65536).contains(&p.approved_capacity)||p.received_at<1||
            p.region.is_empty()||p.region.len()>32||!p.region.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'||b==b'_')||
            !matches!(p.policy_mode.as_str(),"active"|"draining"|"maintenance"){return Err(Failure::Protocol)}
        if let Some(old)=previous{
            // In-process monotonic policy observation, not an offline lease
            // or a persistent anti-rollback guarantee across node restarts.
            if p.policy_revision<old.policy_revision||(p.policy_revision==old.policy_revision&&!p.same_revision(old)){return Err(Failure::Protocol)}
        }
        Ok(p)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GrantResponse{protocol_version:i64,nonce:String,scope:String,server_time:i64,grant:Grant}
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Grant{
        id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,
        generation:i64,policy_revision:i64,device_revision:i64,entitlement_revision:i64,issued_at:i64,expires_at:i64,revoked_at:Option<i64>,
    }
    struct Expected<'a>{id:&'a str,allocation:&'a str,mapping:&'a str,revision:i64,generation:i64}
    fn hex_id(s:&str)->bool{s.len()==32&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
    fn validate_grant(reply:&GrantResponse,nonce:&str,policy:&Policy,expected:&Expected<'_>,started:Instant)->Result<Instant>{
        let g=&reply.grant;
        if reply.protocol_version!=1||reply.nonce!=nonce||reply.scope!="authorization_preview_only"||
            g.id!=expected.id||g.allocation_id!=expected.allocation||g.mapping_id!=expected.mapping||
            g.mapping_revision!=expected.revision||g.generation!=expected.generation||
            g.node_id!=policy.node_id||g.node_generation!=policy.generation||g.policy_revision!=policy.policy_revision||
            policy.policy_mode!="active"||g.device_revision<1||g.entitlement_revision<1||g.revoked_at.is_some()||
            g.issued_at<1||g.issued_at.checked_add(15)!=Some(g.expires_at)||
            reply.server_time<g.issued_at||reply.server_time<policy.received_at||reply.server_time>=g.expires_at{
            return Err(Failure::Denied)
        }
        // Start at the request send time, not the response arrival time.
        // Deduct one second for integer UTC quantization. This conservative
        // local observation deadline cannot be extended by a slow response.
        let seconds=g.expires_at.checked_sub(reply.server_time).and_then(|n|n.checked_sub(1)).filter(|n|*n>0).ok_or(Failure::Denied)?;
        let deadline=started.checked_add(Duration::from_secs(seconds as u64)).ok_or(Failure::Protocol)?;
        if deadline<=Instant::now(){return Err(Failure::Denied)}
        Ok(deadline)
    }
    fn verify_grant(endpoint:&Endpoint,token:&str,node:&str,generation:i64,capacity:i64,expected:&Expected<'_>)->Result<()>{
        // This mode is intentionally TLS only; never load cached grants.
        if !matches!(endpoint,Endpoint::Tls{..}){return Err(Failure::Protocol)}
        let policy=synchronize(endpoint,token,node,generation,capacity,None)?;
        if policy.policy_mode!="active"||policy.approved_capacity<1||capacity<1{return Err(Failure::Denied)}
        let mut bytes=[0u8;16];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_|Failure::Protocol)?;
        let nonce=hex::encode(bytes);
        let payload=serde_json::json!({"protocol_version":1,"allocation_id":expected.allocation,"mapping_id":expected.mapping,
            "mapping_revision":expected.revision,"node_id":node,"node_generation":generation,"generation":expected.generation,"nonce":nonce}).to_string();
        let started=Instant::now();
        let (code,data)=request(endpoint,token,"/api/v1/relay/grant",Some(&payload))?;
        if code!=200{return Err(Failure::Protocol)}
        let reply:GrantResponse=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        let deadline=validate_grant(&reply,&nonce,&policy,expected,started)?;
        println!("relay grant preview verified");
        // Only a local, non-executable observation; no listening socket,
        // renewal, cache, business authority or ability to release a port.
        while let Some(left)=deadline.checked_duration_since(Instant::now()){
            if left.is_zero(){break}
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
        println!("relay grant preview expired");
        Ok(())
    }

    #[cfg(test)]
    mod grant_tests{
        use super::*;
        #[test]
        fn exact_binding_and_conservative_deadline(){
            let id="a".repeat(32);let allocation="b".repeat(32);let mapping="c".repeat(32);let node="d".repeat(32);
            let expected=Expected{id:&id,allocation:&allocation,mapping:&mapping,revision:1,generation:2};
            let policy=Policy{node_id:node.clone(),generation:1,policy_revision:3,approved_capacity:4,region:"east".into(),policy_mode:"active".into(),received_at:100};
            let mut reply=GrantResponse{protocol_version:1,nonce:"nonce".into(),scope:"authorization_preview_only".into(),server_time:101,
                grant:Grant{id:id.clone(),allocation_id:allocation.clone(),mapping_id:mapping.clone(),mapping_revision:1,node_id:node,node_generation:1,generation:2,policy_revision:3,device_revision:2,entitlement_revision:1,issued_at:100,expires_at:115,revoked_at:None}};
            // Keep the borrowed expected id separate from the reply storage.
            let start=Instant::now();
            assert_eq!(validate_grant(&reply,"nonce",&policy,&expected,start).unwrap(),start+Duration::from_secs(13));
            assert!(validate_grant(&reply,"wrong",&policy,&expected,start).is_err());
            reply.grant.generation=1;
            assert!(validate_grant(&reply,"nonce",&policy,&expected,start).is_err());
            reply.grant.generation=2;
            reply.grant.policy_revision=2;
            assert!(validate_grant(&reply,"nonce",&policy,&expected,start).is_err());
            reply.grant.policy_revision=3;
            reply.grant.revoked_at=Some(102);
            assert!(validate_grant(&reply,"nonce",&policy,&expected,start).is_err());
            reply.grant.revoked_at=None;
            reply.server_time=114;
            assert!(validate_grant(&reply,"nonce",&policy,&expected,start).is_err());
            reply.server_time=101;
            let past=start.checked_sub(Duration::from_secs(14)).unwrap();
            assert!(validate_grant(&reply,"nonce",&policy,&expected,past).is_err());
        }
    }
    pub(super) fn run()->Result<()>{
        let args:Vec<_>=std::env::args_os().skip(1).collect();
        let arg=|i:usize|args.get(i).and_then(|a|a.to_str()).ok_or(Failure::Protocol);
        let verify=args.len()==12&&arg(0)?=="--verify-grant";
        let (endpoint,dir,index,port)=if (args.len()==7&&arg(0)?=="--tls")||verify{
            let host=arg(2)?;
            if !hostname(host){return Err(Failure::Protocol)}
            let port:u16=arg(3)?.parse().map_err(|_|Failure::Protocol)?;
            private_file(Path::new(&args[1]),"relay.token")?;
            let dir=fs::canonicalize(Path::new(&args[1])).map_err(|_|Failure::Protocol)?;
            (Endpoint::Tls{host:host.into(),port,dir:dir.clone()},dir,4,port)
        }else if args.len()==5{
            let port:u16=arg(1)?.parse().map_err(|_|Failure::Protocol)?;
            (Endpoint::Loopback(port),PathBuf::from(&args[0]),2,port)
        }else{return Err(Failure::Protocol)};
        let node=arg(index)?;
        let generation:i64=arg(index+1)?.parse().map_err(|_|Failure::Protocol)?;
        let capacity:i64=arg(index+2)?.parse().map_err(|_|Failure::Protocol)?;
        if port==0||node.len()!=32||!node.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))||generation<1||!(0..=65536).contains(&capacity){return Err(Failure::Protocol)}
        let token=private_token(&dir)?;
        if verify{
            let expected=Expected{allocation:arg(7)?,mapping:arg(8)?,revision:arg(9)?.parse().map_err(|_|Failure::Protocol)?,
                generation:arg(10)?.parse().map_err(|_|Failure::Protocol)?,id:arg(11)?};
            if !hex_id(expected.id)||!hex_id(expected.allocation)||!hex_id(expected.mapping)||expected.revision<1||expected.generation<2{return Err(Failure::Protocol)}
            return verify_grant(&endpoint,&token,node,generation,capacity,&expected)
        }
        let mut online=false;
        let mut previous:Option<Policy>=None;
        loop{
            match synchronize(&endpoint,&token,node,generation,capacity,previous.as_ref()){
                Ok(policy)=>{
                    if previous.as_ref().is_none_or(|p|p.policy_revision!=policy.policy_revision){
                        println!("relay policy synchronized revision={} mode={}",policy.policy_revision,policy.policy_mode);
                    }
                    previous=Some(policy);
                    if !online{println!("relay control connected");online=true;}
                },
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
    eprintln!("relay control stopped; Linux usage: localtunnel-relay <private-dir> <port> <node-id> <generation> <capacity> OR localtunnel-relay --tls <private-dir> <host> <port> <node-id> <generation> <capacity> OR --verify-grant <private-dir> <host> <port> <node-id> <node-generation> <capacity> <allocation-id> <mapping-id> <mapping-revision> <allocation-generation> <grant-id>");
    std::process::exit(1);
}
