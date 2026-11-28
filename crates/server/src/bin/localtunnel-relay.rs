//! Independent relay control-plane client: loopback preview or verified HTTPS.
//! No database access; bounded one-shot loopback data-plane previews.
#[cfg(target_os="linux")]
#[path="../relay_budget_guard.rs"]
mod relay_budget_guard;
#[cfg(target_os="linux")]
mod linux {
    use serde::Deserialize;
    use rand_core::{OsRng,RngCore};
    use std::{fs::{self,OpenOptions},io::{Read,Write},net::{Ipv4Addr,SocketAddrV4,TcpStream},os::unix::fs::{MetadataExt,OpenOptionsExt,PermissionsExt},path::{Path,PathBuf},process::{Child,Command,Stdio},time::{Duration,Instant}};
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
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TcpClaim{protocol_version:i64,nonce:String,scope:String,permit:TcpPermit}
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TcpPermit{
        grant_id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,
        generation:i64,policy_revision:i64,relay_port:u16,bind_port:u16,issued_at:i64,expires_at:i64,server_time:i64,claimed_at:i64,
        gateway_port:Option<u16>,hostname:Option<String>,certificate_sha256:Option<String>,
    }
    fn secret_file(dir:&Path,name:&str,valid:impl Fn(&str)->bool)->Result<String>{
        let mut raw=String::new();
        private_file(dir,name)?.take(130).read_to_string(&mut raw).map_err(|_|Failure::Protocol)?;
        let value=raw.strip_suffix('\n').unwrap_or(&raw);
        if !valid(value){return Err(Failure::Protocol)}
        Ok(value.to_owned())
    }
    fn noise_key(s:&str)->bool{
        s.len()==44&&s.ends_with('=')&&s.as_bytes()[..43].iter().all(|b|b.is_ascii_alphanumeric()||*b==b'+'||*b==b'/')
    }
    // Direct child ownership. No shell, PID file or arbitrary process kill.
    struct Engine(Child);
    impl Engine{
        fn stop(&mut self)->Result<()>{
            if self.0.try_wait().map_err(|_|Failure::Protocol)?.is_none(){
                if self.0.kill().is_err()&&self.0.try_wait().map_err(|_|Failure::Protocol)?.is_none(){return Err(Failure::Protocol)}
            }
            self.0.wait().map_err(|_|Failure::Protocol)?;
            Ok(())
        }
    }
    impl Drop for Engine{fn drop(&mut self){let _=self.stop();}}
    struct Web<'a>{hostname:&'a str,port:u16,tls:bool}
    fn web_hostname(s:&str)->bool{
        s.len()<=240&&s.contains('.')&&s!="localtunnel-probe.invalid"&&s.parse::<std::net::IpAddr>().is_err()&&
        hostname(s)&&s.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'||b==b'.')&&
        s.rsplit('.').next().is_some_and(|l|l.bytes().any(|b|b.is_ascii_lowercase()))
    }
    // Standalone single-process Nginx: no master/worker descendants which
    // could survive a killed supervisor. No service reload or global config.
    fn gateway_config(web:&Web<'_>,bind_port:u16)->String{
        let tls=if web.tls{" ssl"}else{""};
        let cert=if web.tls{"ssl_certificate leaf.pem;\n ssl_certificate_key leaf.key;\n ssl_protocols TLSv1.2 TLSv1.3;\n"}else{""};
        let reject=if web.tls{"ssl_reject_handshake on;"}else{""};
        let sni=if web.tls{"if ($ssl_server_name != $host) { return 421; }"}else{""};
        format!("daemon off;\nmaster_process off;\nworker_processes 1;\npid nginx.pid;\nerror_log /dev/null crit;\nevents {{ worker_connections 128; }}\nhttp {{\n access_log off;\n client_body_temp_path client_body_temp;\n proxy_temp_path proxy_temp;\n fastcgi_temp_path fastcgi_temp;\n uwsgi_temp_path uwsgi_temp;\n scgi_temp_path scgi_temp;\n server_tokens off;\n client_max_body_size 1m;\n client_header_timeout 5s;\n client_body_timeout 5s;\n map $http_upgrade $lt_connection {{ default upgrade; '' close; }}\n {cert} server {{ listen 127.0.0.1:{port}{tls} default_server; server_name _; {reject} return 421; }}\n server {{ listen 127.0.0.1:{port}{tls}; server_name {host};\n {sni}\n if ($host != {host}) {{ return 421; }}\n if ($http_host = '') {{ return 421; }}\n location / {{\n proxy_pass http://127.0.0.1:{bind_port};\n proxy_http_version 1.1;\n proxy_set_header Host $host;\n proxy_set_header X-Real-IP $remote_addr;\n proxy_set_header X-Forwarded-For $remote_addr;\n proxy_set_header X-Forwarded-Host $host;\n proxy_set_header X-Forwarded-Proto $scheme;\n proxy_set_header X-Forwarded-Port $server_port;\n proxy_set_header Forwarded \"\";\n proxy_set_header Upgrade $http_upgrade;\n proxy_set_header Connection $lt_connection;\n proxy_connect_timeout 2s;\n proxy_read_timeout 5s;\n proxy_send_timeout 5s;\n proxy_buffering off;\n }} }} }}\n",port=web.port,host=web.hostname)
    }
    // Snapshot only bounded, operator-owned files. The verified bytes, not
    // paths to mutable originals, are the sole input to the dedicated gateway.
    fn snapshot(dir:&Path,target:&Path,name:&str,limit:u64)->Result<()>{
        let mut bytes=Vec::new();
        private_file(dir,name)?.take(limit+1).read_to_end(&mut bytes).map_err(|_|Failure::Protocol)?;
        if bytes.is_empty()||bytes.len() as u64>limit{return Err(Failure::Protocol)}
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(target.join(name)).map_err(|_|Failure::Protocol)?;
        file.write_all(&bytes).and_then(|_|file.sync_all()).map_err(|_|Failure::Protocol)
    }
    fn openssl(dir:&Path,args:&[&str])->Result<Vec<u8>>{
        // Bounded inputs and fixed OpenSSL commands, no shell, password
        // prompts, default environment or diagnostic material on stderr.
        let output=Command::new("/usr/bin/openssl").args(args).current_dir(dir).env_clear()
            .env("PATH","/usr/bin:/bin").stdin(Stdio::null()).stderr(Stdio::null()).output().map_err(|_|Failure::Protocol)?;
        if !output.status.success()||output.stdout.len()>65536{return Err(Failure::Denied)}
        Ok(output.stdout)
    }
    fn certificate(dir:&Path,target:&Path,host:&str)->Result<String>{
        use sha2::{Digest,Sha256};
        snapshot(dir,target,"leaf.pem",65536)?;
        snapshot(dir,target,"leaf.key",16384)?;
        snapshot(dir,target,"web-ca.pem",65536)?;
        // This preview intentionally accepts a single PEM leaf, signed
        // directly by an operator-trusted CA (no automatic chain discovery).
        let pem=fs::read_to_string(target.join("leaf.pem")).map_err(|_|Failure::Protocol)?;
        if pem.matches("-----BEGIN CERTIFICATE-----").count()!=1||pem.matches("-----END CERTIFICATE-----").count()!=1{return Err(Failure::Denied)}
        let san=openssl(target,&["x509","-in","leaf.pem","-noout","-ext","subjectAltName"])?;
        let san=std::str::from_utf8(&san).map_err(|_|Failure::Protocol)?;
        let exact=format!("DNS:{host}");
        if !san.lines().skip(1).flat_map(|l|l.split(',')).any(|v|v.trim()==exact){return Err(Failure::Denied)}
        // Verify trust, purpose and hostname now and after the maximum
        // 15-second lease plus margin. No CN-only or wildcard-only acceptance.
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|Failure::Protocol)?.as_secs();
        let future=now.checked_add(30).ok_or(Failure::Protocol)?.to_string();
        for when in [now.to_string(),future]{
            openssl(target,&["verify","-CAfile","web-ca.pem","-no-CApath","-no-CAstore","-purpose","sslserver","-verify_hostname",host,"-attime",&when,"leaf.pem"])?;
        }
        let leaf_key=openssl(target,&["x509","-in","leaf.pem","-noout","-pubkey"])?;
        let private_key=openssl(target,&["pkey","-in","leaf.key","-passin","pass:","-pubout"])?;
        if leaf_key.is_empty()||leaf_key!=private_key{return Err(Failure::Denied)}
        let der=openssl(target,&["x509","-in","leaf.pem","-outform","DER"])?;
        if der.is_empty(){return Err(Failure::Denied)}
        Ok(hex::encode(Sha256::digest(der)))
    }
    fn protect(command:&mut Command){
        use std::os::unix::process::CommandExt;
        let parent=std::process::id() as libc::pid_t;
        unsafe{command.pre_exec(move||{
            if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong)!=0{return Err(std::io::Error::last_os_error())}
            if libc::getppid()!=parent{libc::_exit(125)}
            Ok(())
        });}
    }
    struct GatewayDir(PathBuf);
    impl Drop for GatewayDir{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
    // CLOCK_BOOTTIME includes system suspend on Linux; Instant alone may
    // pause during suspend. Require BOTH deadlines to remain valid.
    fn boot_now()->Result<Duration>{
        let mut value=libc::timespec{tv_sec:0,tv_nsec:0};
        if unsafe{libc::clock_gettime(libc::CLOCK_BOOTTIME,&mut value)}!=0||
            value.tv_sec<0||!(0..1_000_000_000).contains(&value.tv_nsec){return Err(Failure::Protocol)}
        Ok(Duration::new(value.tv_sec as u64,value.tv_nsec as u32))
    }
    fn lease_left(deadline:Instant,boot_deadline:Duration)->Result<Duration>{
        Ok(deadline.saturating_duration_since(Instant::now()).min(boot_deadline.saturating_sub(boot_now()?)))
    }
    fn supervise_tcp(protocol:&str,endpoint:&Endpoint,dir:&Path,token:&str,node:&str,generation:i64,capacity:i64,expected:&Expected<'_>,relay_port:u16,bind_port:u16,engine:&Path,web:Option<Web<'_>>)->Result<()>{
        if !matches!(endpoint,Endpoint::Tls{..})||!(30000..=59999).contains(&relay_port)||!(20000..=29999).contains(&bind_port)||!engine.is_absolute(){return Err(Failure::Protocol)}
        if matches!(protocol,"http"|"https")!=web.is_some()||web.as_ref().is_some_and(|w|w.tls!=(protocol=="https")){return Err(Failure::Protocol)}
        if let Some(w)=web.as_ref(){if !web_hostname(w.hostname)||!(60000..=64999).contains(&w.port){return Err(Failure::Protocol)}}
        let engine=fs::canonicalize(engine).map_err(|_|Failure::Protocol)?;
        if !engine.is_file(){return Err(Failure::Protocol)}
        // Trusted local operator provisions independent data-plane credentials.
        // Neither tenant nor relay-control credential is used as tunnel token.
        let private=secret_file(dir,"noise.private",noise_key)?;
        let service_token=secret_file(dir,match protocol{"udp"=>"udp.token","http"=>"http.token","https"=>"https.token",_=>"tcp.token"},|s|s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))?;
        let _probe=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,relay_port)).map_err(|_|Failure::Protocol)?;
        drop(_probe);
        if protocol=="udp"{
            let _probe=std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST,bind_port)).map_err(|_|Failure::Protocol)?;
        }else{
            let _probe=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,bind_port)).map_err(|_|Failure::Protocol)?;
        }
        let mut certificate_sha256=None;
        let gateway=if let Some(w)=web.as_ref(){
            let _probe=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,w.port)).map_err(|_|Failure::Protocol)?;
            let path=dir.join(format!("{protocol}-{}.gateway",expected.id));
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).map_err(|_|Failure::Protocol)?;
            let gateway=GatewayDir(path);
            if w.tls{certificate_sha256=Some(certificate(dir,&gateway.0,w.hostname)?);}
            let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(gateway.0.join("nginx.conf")).map_err(|_|Failure::Protocol)?;
            file.write_all(gateway_config(w,bind_port).as_bytes()).and_then(|_|file.sync_all()).map_err(|_|Failure::Protocol)?;
            Some(gateway)
        }else{None};
        // Exclusive private configuration file: a second invocation cannot
        // replace a running child's configuration. Retain on crash for review.
        let path=dir.join(format!("{protocol}-{}.toml",expected.id));
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(&path).map_err(|_|Failure::Protocol)?;
        struct Config(PathBuf);
        impl Drop for Config{fn drop(&mut self){let _=fs::remove_file(&self.0);}}
        let _config=Config(path.clone());
        write!(file,"[server]\nbind_addr = \"127.0.0.1:{relay_port}\"\nheartbeat_interval = 5\n\n[server.transport]\ntype = \"noise\"\n\n[server.transport.noise]\npattern = \"Noise_NK_25519_ChaChaPoly_BLAKE2s\"\nlocal_private_key = \"{private}\"\n\n[server.services.m_{}]\ntype = \"{}\"\ntoken = \"{service_token}\"\nbind_addr = \"127.0.0.1:{bind_port}\"\n",expected.mapping,if protocol=="udp"{"udp"}else{"tcp"}).map_err(|_|Failure::Protocol)?;
        file.sync_all().map_err(|_|Failure::Protocol)?;
        drop(file);
        let policy=synchronize(endpoint,token,node,generation,capacity,None)?;
        if policy.policy_mode!="active"||policy.approved_capacity<1||capacity<1{return Err(Failure::Denied)}
        let mut bytes=[0u8;16];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_|Failure::Protocol)?;
        let nonce=hex::encode(bytes);
        let mut payload=serde_json::json!({"protocol_version":1,"grant_id":expected.id,"allocation_id":expected.allocation,"mapping_id":expected.mapping,
            "mapping_revision":expected.revision,"node_id":node,"node_generation":generation,"generation":expected.generation,
            "relay_port":relay_port,"nonce":nonce});
        if let Some(w)=web.as_ref(){payload["gateway_port"]=serde_json::json!(w.port);payload["hostname"]=serde_json::json!(w.hostname);}
        if let Some(fp)=certificate_sha256.as_ref(){payload["certificate_sha256"]=serde_json::json!(fp);}
        let payload=payload.to_string();
        let started=Instant::now();
        let boot_started=boot_now()?;
        let (code,data)=request(endpoint,token,match protocol{"udp"=>"/api/v1/relay/udp-claim","http"=>"/api/v1/relay/http-claim","https"=>"/api/v1/relay/https-claim",_=>"/api/v1/relay/tcp-claim"},Some(&payload))?;
        if code!=200{return Err(Failure::Protocol)}
        let reply:TcpClaim=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        let p=reply.permit;
        if reply.protocol_version!=1||reply.nonce!=nonce||reply.scope!=format!("{protocol}_loopback_start_claim")||
            p.grant_id!=expected.id||p.allocation_id!=expected.allocation||p.mapping_id!=expected.mapping||
            p.mapping_revision!=expected.revision||p.generation!=expected.generation||p.node_id!=node||
            p.node_generation!=generation||p.policy_revision!=policy.policy_revision||p.relay_port!=relay_port||p.bind_port!=bind_port||
            p.gateway_port!=web.as_ref().map(|w|w.port)||p.hostname.as_deref()!=web.as_ref().map(|w|w.hostname)||
            p.certificate_sha256!=certificate_sha256||
            p.issued_at<1||p.issued_at.checked_add(15)!=Some(p.expires_at)||p.claimed_at<p.issued_at||
            p.claimed_at<policy.received_at||p.server_time<p.claimed_at||p.server_time>=p.expires_at{return Err(Failure::Denied)}
        let seconds=p.expires_at.checked_sub(p.server_time).and_then(|n|n.checked_sub(1)).filter(|n|*n>0).ok_or(Failure::Denied)?;
        let deadline=started.checked_add(Duration::from_secs(seconds as u64)).ok_or(Failure::Protocol)?;
        let boot_deadline=boot_started.checked_add(Duration::from_secs(seconds as u64)).ok_or(Failure::Protocol)?;
        if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
        let mut command=Command::new(engine);
        command.arg(&path).env_clear().env("PATH","/usr/bin:/bin").env("RUST_LOG","warn")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        protect(&mut command);
        let mut child=Engine(command.spawn().map_err(|_|Failure::Protocol)?);
        if lease_left(deadline,boot_deadline)?.is_zero(){child.stop()?;return Err(Failure::Denied)}
        let mut web_child=if let Some(g)=gateway.as_ref(){
            let mut command=Command::new("/usr/sbin/nginx");
            command.arg("-p").arg(&g.0).args(["-c","nginx.conf"]).env_clear().env("PATH","/usr/bin:/bin")
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            protect(&mut command);
            Some(Engine(command.spawn().map_err(|_|Failure::Protocol)?))
        }else{None};
        if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
        println!("relay {} engine started",protocol.to_ascii_uppercase());
        // No renewal or retry of a consumed claim. A local deadline closes
        // the entire engine, including existing connections, before exit.
        loop{
            let left=lease_left(deadline,boot_deadline)?;
            if left.is_zero(){break}
            if child.0.try_wait().map_err(|_|Failure::Protocol)?.is_some(){return Err(Failure::Protocol)}
            if let Some(g)=web_child.as_mut(){if g.0.try_wait().map_err(|_|Failure::Protocol)?.is_some(){return Err(Failure::Protocol)}}
            std::thread::sleep(left.min(Duration::from_millis(50)));
        }
        if let Some(g)=web_child.as_mut(){g.stop()?;}
        child.stop()?;
        println!("relay {} engine expired and stopped",protocol.to_ascii_uppercase());
        Ok(())
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BudgetResponse{protocol_version:i64,nonce:String,scope:String,executable:bool,grant:BudgetGrant,intent:Option<BudgetIntent>}
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BudgetIntent{grant_id:String,node_id:String,relay_port:u16,bind_port:u16,created_at:i64,claimed_at:Option<i64>}
    // The trusted operator owns the 0700 directory. Never replace, unlink,
    // or reuse an existing marker, including a symlink or partial file.
    fn unused_budget_marker(dir:&Path,id:&str)->Result<PathBuf>{
        if !hex_id(id){return Err(Failure::Protocol)}
        let path=dir.join(format!("budget-consumed-{id}"));
        match fs::symlink_metadata(&path){
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(path),
            Ok(_)=>Err(Failure::Denied),
            Err(_)=>Err(Failure::Protocol),
        }
    }
    fn consume_budget_marker(dir:&Path,id:&str,execution:bool)->Result<()>{
        let path=unused_budget_marker(dir,id)?;
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path).map_err(|_|Failure::Denied)?;
        let metadata=file.metadata().map_err(|_|Failure::Protocol)?;
        if !metadata.is_file()||metadata.nlink()!=1||metadata.uid()!=unsafe{libc::geteuid()}||
            metadata.permissions().mode()&0o777!=0o600{return Err(Failure::Protocol)}
        file.write_all(if execution{b"budget start consumed; no reuse\n"}else{b"budget claim consumed; non-executable\n"}).and_then(|_|file.sync_all()).map_err(|_|Failure::Protocol)?;
        let directory=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(dir).map_err(|_|Failure::Protocol)?;
        directory.sync_all().map_err(|_|Failure::Protocol)?;
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BudgetGrant{id:String,allocation_id:String,mapping_id:String,mapping_revision:i64,node_id:String,node_generation:i64,
        generation:i64,policy_revision:i64,entitlement_revision:i64,device_revision:i64,bind_port:u16,
        rate_bytes_per_second:u64,monthly_bytes:u64,connection_slots:u32,month_utc:String,issued_at:i64,expires_at:i64,server_time:i64}
    fn verify_budget(endpoint:&Endpoint,token:&str,node:&str,generation:i64,capacity:i64,expected:&Expected<'_>,bind:u16,rate:u64,monthly:u64,slots:u32,relay_port:Option<u16>,engine:Option<&Path>)->Result<()>{
        if !matches!(endpoint,Endpoint::Tls{..})||!(20000..=29999).contains(&bind)||!(65536..=125000000).contains(&rate)||
            !(1..=9000000000000000).contains(&monthly)||!(1..=65536).contains(&slots){return Err(Failure::Protocol)}
        let dir=match endpoint{Endpoint::Tls{dir,..}=>dir,_=>return Err(Failure::Protocol)};
        if let Some(port)=relay_port{
            if !(30000..=59999).contains(&port){return Err(Failure::Protocol)}
            unused_budget_marker(dir,expected.id)?;
        }
        let execution=engine.is_some();
        let engine=if let Some(path)=engine{
            if relay_port.is_none()||!path.is_absolute(){return Err(Failure::Protocol)}
            let path=fs::canonicalize(path).map_err(|_|Failure::Protocol)?;
            if !path.is_file(){return Err(Failure::Protocol)}
            Some(path)
        }else{None};
        let policy=synchronize(endpoint,token,node,generation,capacity,None)?;
        if policy.policy_mode!="active"||policy.approved_capacity<1||capacity<1{return Err(Failure::Denied)}
        let mut bytes=[0u8;16];OsRng.try_fill_bytes(&mut bytes).map_err(|_|Failure::Protocol)?;
        let nonce=hex::encode(bytes);
        let mut payload=serde_json::json!({"protocol_version":1,"grant_id":expected.id,"allocation_id":expected.allocation,"mapping_id":expected.mapping,
            "mapping_revision":expected.revision,"node_id":node,"node_generation":generation,"generation":expected.generation,"nonce":nonce});
        let (path,scope)=if let Some(port)=relay_port{
            payload["relay_port"]=serde_json::json!(port);
            if execution{("/api/v1/relay/budget-start-claim","budget_guarded_tcp_start")}else{("/api/v1/relay/budget-claim","budget_claim_preview_only")}
        }else{("/api/v1/relay/budget-grant","budget_authorization_preview_only")};
        let payload=payload.to_string();
        let started=Instant::now();let boot=boot_now()?;
        let (code,data)=request(endpoint,token,path,Some(&payload))?;
        if code!=200{return Err(Failure::Denied)}
        let reply:BudgetResponse=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        let g=reply.grant;
        if reply.protocol_version!=1||reply.nonce!=nonce||reply.scope!=scope||reply.executable!=execution||
            g.id!=expected.id||g.allocation_id!=expected.allocation||g.mapping_id!=expected.mapping||g.mapping_revision!=expected.revision||
            g.node_id!=node||g.node_generation!=generation||g.generation!=expected.generation||g.generation!=2||g.policy_revision!=policy.policy_revision||
            g.device_revision<1||g.entitlement_revision<1||g.bind_port!=bind||g.rate_bytes_per_second!=rate||g.monthly_bytes!=monthly||g.connection_slots!=slots||
            g.month_utc.len()!=7||g.month_utc.as_bytes()[4]!=b'-'||g.issued_at<1||g.issued_at.checked_add(15)!=Some(g.expires_at)||
            g.server_time<g.issued_at||g.server_time<policy.received_at||g.server_time>=g.expires_at{return Err(Failure::Denied)}
        match (relay_port,reply.intent){
            (None,None)=>{},
            (Some(port),Some(i))=>{
                let claimed=i.claimed_at.ok_or(Failure::Denied)?;
                if i.grant_id!=g.id||i.node_id!=g.node_id||i.relay_port!=port||i.bind_port!=bind||
                    i.created_at<g.issued_at||claimed<i.created_at||claimed>g.server_time||claimed>=g.expires_at{return Err(Failure::Denied)}
            },
            _=>return Err(Failure::Denied),
        }
        let seconds=g.expires_at.checked_sub(g.server_time).and_then(|n|n.checked_sub(1)).filter(|n|*n>0).ok_or(Failure::Denied)?;
        let duration=Duration::from_secs(seconds as u64);
        let deadline=started.checked_add(duration).ok_or(Failure::Protocol)?;
        let boot_deadline=boot.checked_add(duration).ok_or(Failure::Protocol)?;
        if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
        if relay_port.is_some(){
            // The center already consumed its one-shot claim. A disk failure
            // or expired response cannot reopen it. No listener or engine.
            consume_budget_marker(dir,expected.id,execution)?;
            if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
            if let Some(engine)=engine{
                return run_budget_engine(dir,expected,relay_port.ok_or(Failure::Protocol)?,bind,rate as u32,monthly,slots,
                    deadline,boot_deadline,&engine)
            }
            println!("relay budget claim consumed");
            return Ok(())
        }
        println!("relay budget preview verified");
        loop{let left=lease_left(deadline,boot_deadline)?;if left.is_zero(){break}std::thread::sleep(left.min(Duration::from_millis(50)));}
        println!("relay budget preview expired");
        Ok(())
    }
    // Confirm the private backend listening inode belongs to our direct child,
    // not an unrelated local process that won the port-binding race.
    fn owns_backend(pid:u32,port:u16)->std::io::Result<bool>{
        let address=format!("0100007F:{port:04X}");
        let mut table=String::new();
        fs::File::open(format!("/proc/{pid}/net/tcp"))?.take(1024*1024).read_to_string(&mut table)?;
        let mut inode=None;
        for line in table.lines().skip(1){
            let cols:Vec<_>=line.split_whitespace().collect();
            if cols.len()>9&&cols[1]==address&&cols[3]=="0A"{inode=Some(cols[9]);break}
        }
        let Some(inode)=inode else{return Ok(false)};
        let expected=format!("socket:[{inode}]");
        for fd in fs::read_dir(format!("/proc/{pid}/fd"))?{
            if let Ok(link)=fs::read_link(fd?.path()){
                if link.to_str()==Some(expected.as_str()){return Ok(true)}
            }
        }
        Ok(false)
    }
    fn run_budget_engine(dir:&Path,expected:&Expected<'_>,relay_port:u16,bind:u16,rate:u32,monthly:u64,slots:u32,
                         deadline:Instant,boot_deadline:Duration,engine:&Path)->Result<()>{
        use super::relay_budget_guard::{self,Deadline,End};
        use std::net::TcpListener;
        let private=secret_file(dir,"noise.private",noise_key)?;
        let service_token=secret_file(dir,"budget-tcp.token",|s|s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))?;
        let ingress=TcpListener::bind((Ipv4Addr::LOCALHOST,bind)).map_err(|_|Failure::Protocol)?;
        let relay_probe=TcpListener::bind((Ipv4Addr::LOCALHOST,relay_port)).map_err(|_|Failure::Protocol)?;
        let backend_probe=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|_|Failure::Protocol)?;
        let backend=backend_probe.local_addr().map_err(|_|Failure::Protocol)?.port();
        let path=dir.join(format!("budget-tcp-{}.toml",expected.id));
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(&path).map_err(|_|Failure::Protocol)?;
        struct Config(PathBuf);
        impl Drop for Config{fn drop(&mut self){let _=fs::remove_file(&self.0);}}
        let _config=Config(path.clone());
        write!(file,"[server]\nbind_addr = \"127.0.0.1:{relay_port}\"\nheartbeat_interval = 5\n\n[server.transport]\ntype = \"noise\"\n\n[server.transport.noise]\npattern = \"Noise_NK_25519_ChaChaPoly_BLAKE2s\"\nlocal_private_key = \"{private}\"\n\n[server.services.m_{}]\ntype = \"tcp\"\ntoken = \"{service_token}\"\nbind_addr = \"127.0.0.1:{backend}\"\n",expected.mapping).map_err(|_|Failure::Protocol)?;
        file.sync_all().map_err(|_|Failure::Protocol)?;
        drop(file);
        if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
        let mut command=Command::new(engine);
        command.arg(&path).env_clear().env("PATH","/usr/bin:/bin").env("RUST_LOG","warn")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        protect(&mut command);
        drop(relay_probe);drop(backend_probe);
        let mut child=Engine(command.spawn().map_err(|_|Failure::Protocol)?);
        if lease_left(deadline,boot_deadline)?.is_zero(){return Err(Failure::Denied)}
        println!("relay finite TCP engine started");
        let result=relay_budget_guard::run_checked(ingress,backend,rate,monthly,slots,Deadline{monotonic:deadline,boot:boot_deadline},|check_backend|{
            if child.0.try_wait()?.is_some(){return Err(std::io::Error::other("engine exited"))}
            if check_backend{owns_backend(child.0.id(),backend)}else{Ok(true)}
        });
        child.stop()?;
        let outcome=result.map_err(|_|Failure::Protocol)?;
        println!("relay finite TCP stopped reason={} bytes={}",if outcome.end==End::Exhausted{"exhausted"}else{"expired"},outcome.written);
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CleanupReply{protocol_version:i64,nonce:String,scope:String,executable:bool,resources_released:bool,report:CleanupRecord}
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CleanupRecord{allocation_id:String,grant_id:String,node_id:String,node_generation:i64,fenced_generation:i64,
        relay_port:u16,bind_port:u16,reported_at:i64}
    fn report_cleanup(endpoint:&Endpoint,token:&str,node:&str,generation:i64,expected:&Expected<'_>,relay_port:u16,bind_port:u16)->Result<()>{
        let dir=match endpoint{Endpoint::Tls{dir,..}=>dir,_=>return Err(Failure::Protocol)};
        if expected.generation!=3||!(30000..=59999).contains(&relay_port)||!(20000..=29999).contains(&bind_port){return Err(Failure::Protocol)}
        let mut marker=Vec::new();
        private_file(dir,&format!("budget-consumed-{}",expected.id))?.take(128).read_to_end(&mut marker).map_err(|_|Failure::Protocol)?;
        if marker!=b"budget start consumed; no reuse\n"{return Err(Failure::Denied)}
        match fs::symlink_metadata(dir.join(format!("budget-tcp-{}.toml",expected.id))){
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
            _=>return Err(Failure::Denied),
        }
        // Hold both exclusive loopback probes until the authenticated report
        // completes. This is a point-in-time observation, not OS isolation.
        let _relay=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,relay_port)).map_err(|_|Failure::Denied)?;
        let _bind=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,bind_port)).map_err(|_|Failure::Denied)?;
        let mut bytes=[0u8;16];OsRng.try_fill_bytes(&mut bytes).map_err(|_|Failure::Protocol)?;
        let nonce=hex::encode(bytes);
        let payload=serde_json::json!({"protocol_version":1,"allocation_id":expected.allocation,"grant_id":expected.id,
            "node_id":node,"node_generation":generation,"fenced_generation":expected.generation,"relay_port":relay_port,"bind_port":bind_port,"nonce":nonce}).to_string();
        let (code,data)=request(endpoint,token,"/api/v1/relay/budget-cleanup-report",Some(&payload))?;
        if code!=200{return Err(Failure::Denied)}
        let reply:CleanupReply=serde_json::from_slice(&data).map_err(|_|Failure::Protocol)?;
        let r=reply.report;
        if reply.protocol_version!=1||reply.nonce!=nonce||reply.scope!="node_cleanup_observation_only"||reply.executable||reply.resources_released
            ||r.allocation_id!=expected.allocation||r.grant_id!=expected.id||r.node_id!=node||r.node_generation!=generation
            ||r.fenced_generation!=expected.generation||r.relay_port!=relay_port||r.bind_port!=bind_port||r.reported_at<1{return Err(Failure::Denied)}
        println!("relay cleanup observation recorded; resources retained");
        Ok(())
    }
    pub(super) fn run()->Result<()>{
        let args:Vec<_>=std::env::args_os().skip(1).collect();
        let arg=|i:usize|args.get(i).and_then(|a|a.to_str()).ok_or(Failure::Protocol);
        let verify=args.len()==12&&arg(0)?=="--verify-grant";
        let cleanup=args.len()==14&&arg(0)?=="--report-budget-cleanup";
        let budget_claim=args.len()==17&&arg(0)?=="--claim-budget";
        let budget_start=args.len()==18&&arg(0)?=="--budget-tcp-preview";
        let budget=(args.len()==16&&arg(0)?=="--verify-budget")||budget_claim||budget_start;
        let tcp=args.len()==15&&matches!(arg(0)?,"--tcp-preview"|"--udp-preview");
        let http=args.len()==17&&matches!(arg(0)?,"--http-preview"|"--https-preview");
        let (endpoint,dir,index,port)=if (args.len()==7&&arg(0)?=="--tls")||verify||budget||tcp||http||cleanup{
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
        if verify||budget||tcp||http||cleanup{
            let expected=Expected{allocation:arg(7)?,mapping:arg(8)?,revision:arg(9)?.parse().map_err(|_|Failure::Protocol)?,
                generation:arg(10)?.parse().map_err(|_|Failure::Protocol)?,id:arg(11)?};
            if !hex_id(expected.id)||!hex_id(expected.allocation)||!hex_id(expected.mapping)||expected.revision<1||expected.generation<2{return Err(Failure::Protocol)}
            if cleanup{
                return report_cleanup(&endpoint,&token,node,generation,&expected,arg(12)?.parse().map_err(|_|Failure::Protocol)?,
                    arg(13)?.parse().map_err(|_|Failure::Protocol)?)
            }
            if budget{
                return verify_budget(&endpoint,&token,node,generation,capacity,&expected,arg(12)?.parse().map_err(|_|Failure::Protocol)?,
                    arg(13)?.parse().map_err(|_|Failure::Protocol)?,arg(14)?.parse().map_err(|_|Failure::Protocol)?,arg(15)?.parse().map_err(|_|Failure::Protocol)?,
                    if budget_claim||budget_start{Some(arg(16)?.parse().map_err(|_|Failure::Protocol)?)}else{None},
                    if budget_start{Some(Path::new(&args[17]))}else{None})
            }
            if tcp||http{
                let web=if http{Some(Web{port:arg(15)?.parse().map_err(|_|Failure::Protocol)?,hostname:arg(16)?,tls:arg(0)?=="--https-preview"})}else{None};
                return supervise_tcp(if http{if arg(0)?=="--https-preview"{"https"}else{"http"}}else if arg(0)?=="--udp-preview"{"udp"}else{"tcp"},&endpoint,&dir,&token,node,generation,capacity,&expected,
                    arg(12)?.parse().map_err(|_|Failure::Protocol)?,arg(13)?.parse().map_err(|_|Failure::Protocol)?,Path::new(&args[14]),web)
            }
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
    eprintln!("relay control stopped; Linux usage: localtunnel-relay <private-dir> <port> <node-id> <generation> <capacity> OR localtunnel-relay --tls <private-dir> <host> <port> <node-id> <generation> <capacity> OR --verify-grant <private-dir> <host> <port> <node-id> <node-generation> <capacity> <allocation-id> <mapping-id> <mapping-revision> <allocation-generation> <grant-id> OR --verify-budget (verify-grant arguments plus bind-port rate-bytes-per-second monthly-bytes connection-slots) OR --claim-budget (verify-budget arguments plus relay-port; non-executable) OR --report-budget-cleanup (verify-grant arguments with fenced generation 3 plus relay-port bind-port) OR --budget-tcp-preview (claim-budget arguments plus absolute-engine) OR --tcp-preview/--udp-preview <private-dir> <host> <port> <node-id> <node-generation> <capacity> <allocation-id> <mapping-id> <mapping-revision> <allocation-generation> <grant-id> <relay-port> <bind-port> <absolute-engine> OR --http-preview/--https-preview (same arguments plus gateway-port and hostname)");
    std::process::exit(1);
}
