//! Bounded loopback TCP stream guard for one managed mapping. Each direction
//! shares a single byte budget across all admitted connections. This is a
//! socket-write budget, not wire accounting or a tenant-wide limit.
use std::{io::{self,Read,Write},net::{Ipv4Addr,Shutdown,SocketAddr,TcpListener,TcpStream},
    sync::{Arc,atomic::{AtomicBool,Ordering}},thread::{self,JoinHandle},time::{Duration,Instant}};
const BURST:usize=4096;
const MAX_CONNECTIONS:usize=32;
const IDLE:Duration=Duration::from_secs(120);

struct Bucket{rate:f64,tokens:f64,last:Instant}
impl Bucket{
    fn new(rate:u32)->Self{Self{rate:f64::from(rate),tokens:BURST as f64,last:Instant::now()}}
    fn available(&mut self)->usize{
        let now=Instant::now();
        self.tokens=(self.tokens+now.saturating_duration_since(self.last).as_secs_f64()*self.rate).min(BURST as f64);
        self.last=now;
        self.tokens as usize
    }
    fn debit(&mut self,n:usize){self.tokens-=n as f64;}
}
fn retry(e:&io::Error)->bool{matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)}
struct Direction{buf:[u8;BURST],start:usize,end:usize,eof:bool}
impl Direction{
    fn new()->Self{Self{buf:[0;BURST],start:0,end:0,eof:false}}
    fn step(&mut self,from:&mut TcpStream,to:&mut TcpStream,budget:&mut Bucket)->io::Result<bool>{
        if self.eof{return Ok(false)}
        if self.start==self.end{
            match from.read(&mut self.buf){
                Ok(0)=>{self.eof=true;to.shutdown(Shutdown::Write)?;return Ok(true)}
                Ok(n)=>{self.start=0;self.end=n;}
                Err(e) if retry(&e)=>return Ok(false),
                Err(e)=>return Err(e),
            }
        }
        let n=budget.available().min(self.end-self.start);
        if n==0{return Ok(false)}
        match to.write(&self.buf[self.start..self.start+n]){
            Ok(0)=>Err(io::ErrorKind::WriteZero.into()),
            Ok(n)=>{budget.debit(n);self.start+=n;Ok(true)}
            Err(e) if retry(&e)=>Ok(false),
            Err(e)=>Err(e),
        }
    }
}
struct Connection{source:TcpStream,target:TcpStream,up:Direction,down:Direction,last:Instant}
impl Connection{
    fn new(source:TcpStream,target:SocketAddr)->io::Result<Self>{
        let target=TcpStream::connect_timeout(&target,Duration::from_millis(250))?;
        source.set_nonblocking(true)?;
        target.set_nonblocking(true)?;
        source.set_nodelay(true)?;
        target.set_nodelay(true)?;
        Ok(Self{source,target,up:Direction::new(),down:Direction::new(),last:Instant::now()})
    }
    fn poll(&mut self,up:&mut Bucket,down:&mut Bucket)->bool{
        let result=(||->io::Result<bool>{
            let a=self.up.step(&mut self.source,&mut self.target,up)?;
            let b=self.down.step(&mut self.target,&mut self.source,down)?;
            Ok(a||b)
        })();
        match result{
            Ok(progress)=>{
                if progress{self.last=Instant::now()}
                !(self.up.eof&&self.down.eof)&&self.last.elapsed()<IDLE
            },
            Err(_)=>false,
        }
    }
}
pub(crate) struct Guard{port:u16,stop:Arc<AtomicBool>,thread:Option<JoinHandle<io::Result<()>>>}
impl Guard{
    pub(crate) fn start(target:u16,rate:u32)->Result<Self,&'static str>{
        if target==0||!(65536..=125_000_000).contains(&rate){return Err("unsupported TCP preview byte rate")}
        let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|_|"TCP limiter bind failed")?;
        let port=listener.local_addr().map_err(|_|"TCP limiter address unavailable")?.port();
        if port==target{return Err("TCP limiter port collision")}
        listener.set_nonblocking(true).map_err(|_|"TCP limiter setup failed")?;
        let target=SocketAddr::from(([127,0,0,1],target));
        let stop=Arc::new(AtomicBool::new(false));
        let signal=stop.clone();
        let thread=thread::Builder::new().name("mapping-tcp-limit".into()).spawn(move||{
            let mut up=Bucket::new(rate);
            let mut down=Bucket::new(rate);
            let mut connections:Vec<Connection>=Vec::with_capacity(MAX_CONNECTIONS);
            while !signal.load(Ordering::Relaxed){
                match listener.accept(){
                    Ok((source,peer))=>{
                        if peer.ip().is_loopback()&&connections.len()<MAX_CONNECTIONS{
                            if let Ok(c)=Connection::new(source,target){connections.push(c)}
                        }
                    },
                    Err(e) if retry(&e)=>{},
                    Err(e)=>return Err(e),
                }
                connections.retain_mut(|c|c.poll(&mut up,&mut down));
                // Rotate servicing order so the same connection does not
                // always claim the first replenished tokens.
                if connections.len()>1{connections.rotate_left(1)}
                thread::sleep(Duration::from_millis(2));
            }
            Ok(())
        }).map_err(|_|"TCP limiter thread unavailable")?;
        Ok(Self{port,stop,thread:Some(thread)})
    }
    pub(crate) fn port(&self)->u16{self.port}
    pub(crate) fn healthy(&self)->bool{self.thread.as_ref().is_some_and(|t|!t.is_finished())}
    pub(crate) fn stop(&mut self)->Result<(),&'static str>{
        self.stop.store(true,Ordering::Relaxed);
        if let Some(t)=self.thread.take(){t.join().map_err(|_|"TCP limiter panicked")?.map_err(|_|"TCP limiter failed")?;}
        Ok(())
    }
}
impl Drop for Guard{fn drop(&mut self){let _=self.stop();}}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn actual_tcp_shared_bidirectional_budget_and_half_close(){
        let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
        let target=listener.local_addr().unwrap().port();
        let size=65536;
        let fixture=thread::spawn(move||{
            let mut tasks=Vec::new();
            for _ in 0..2{
                let (mut s,_)=listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                tasks.push(thread::spawn(move||{
                    let mut data=Vec::new();
                    s.read_to_end(&mut data).unwrap();
                    assert_eq!(data.len(),size);
                    (s,data)
                }));
            }
            let inputs:Vec<_>=tasks.into_iter().map(|t|t.join().unwrap()).collect();
            let received=Instant::now();
            let outputs:Vec<_>=inputs.into_iter().map(|(mut s,data)|thread::spawn(move||{
                s.write_all(&data).unwrap();
                s.shutdown(Shutdown::Write).unwrap();
            })).collect();
            for t in outputs{t.join().unwrap();}
            received
        });
        let mut guard=Guard::start(target,65536).unwrap();
        let started=Instant::now();
        let mut tasks=Vec::new();
        for value in [19,37]{
            let port=guard.port();
            tasks.push(thread::spawn(move||{
                let mut s=TcpStream::connect((Ipv4Addr::LOCALHOST,port)).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                let data=vec![value;size];
                s.write_all(&data).unwrap();
                s.shutdown(Shutdown::Write).unwrap();
                let mut reply=Vec::new();
                s.read_to_end(&mut reply).unwrap();
                assert_eq!(reply,data);
                Instant::now()
            }));
        }
        let done=tasks.into_iter().map(|t|t.join().unwrap()).max().unwrap();
        let received=fixture.join().unwrap();
        // Both streams share 65536 bytes/s per direction (4096 burst).
        assert!(received.duration_since(started)>=Duration::from_millis(1850));
        assert!(done.duration_since(received)>=Duration::from_millis(1850));
        assert!(guard.healthy());
        let port=guard.port();
        guard.stop().unwrap();
        assert!(TcpStream::connect_timeout(&SocketAddr::from(([127,0,0,1],port)),Duration::from_millis(500)).is_err());
    }
}
