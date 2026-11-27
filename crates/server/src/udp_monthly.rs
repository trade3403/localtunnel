//! Finite monthly-plan UDP ingress. Reuse the core's existing bounded
//! forwarder and precharge each admitted datagram, not periodic statistics.
use crate::udp_guard::{ByteLimits,UdpForwarder};
use std::{net::{SocketAddr,UdpSocket},sync::{Arc,atomic::{AtomicBool,Ordering}},thread::{self,JoinHandle},time::Duration};
use sqlx::SqlitePool;
pub struct Guard{
    stop:Arc<AtomicBool>,denied:Arc<AtomicBool>,thread:Option<JoinHandle<Result<(),&'static str>>>,
}
impl Guard{
    pub fn start(pool:&SqlitePool,mapping:&str,revision:i64,rid:&str,cap:i64,listen:SocketAddr,target:SocketAddr,rate:u32,burst:u32)->Result<Self,&'static str>{
        Self::start_with_policy(pool,mapping,revision,rid,Some(cap),None,None,listen,target,rate,burst)
    }
    // A finite connection policy requires the supervisor's exclusively owned
    // probe socket. This entry point is not exposed to an API caller.
    pub fn start_with_policy(pool:&SqlitePool,mapping:&str,revision:i64,rid:&str,monthly:Option<i64>,connections:Option<i64>,probe:Option<UdpSocket>,listen:SocketAddr,target:SocketAddr,rate:u32,burst:u32)->Result<Self,&'static str>{
        if connections.is_some() && probe.is_none(){return Err("UDP connection policy requires supervisor probe")}
        let mut forwarder=UdpForwarder::bind_with_limits(listen,target,Some(ByteLimits::new(rate,burst)?))?;
        let pool=pool.clone();
        let mapping=mapping.to_owned();
        let rid=rid.to_owned();
        let handle=tokio::runtime::Handle::current();
        let stop=Arc::new(AtomicBool::new(false));
        let denied=Arc::new(AtomicBool::new(false));
        let signal=stop.clone();
        let rejected=denied.clone();
        let thread=thread::Builder::new().name("mapping-udp-monthly".into()).spawn(move||{
            while !signal.load(Ordering::Acquire){
                let charge=|n|{
                    if signal.load(Ordering::Acquire){return Err("UDP guard stopping")}
                    let Some(cap)=monthly else{return Ok(())};
                    match handle.block_on(crate::commercial::charge_monthly(&pool,&mapping,revision,&rid,cap,n)){
                        Ok(true)=>Ok(()),
                        Ok(false)=>{rejected.store(true,Ordering::Release);Err("monthly UDP budget denied")},
                        Err(e)=>Err(e),
                    }
                };
                let acquire=||{
                    if signal.load(Ordering::Acquire){return Err("UDP guard stopping")}
                    match connections{
                        Some(cap)=>handle.block_on(crate::commercial::acquire_connection(&pool,&mapping,revision,&rid,cap)).map(|slot|slot.map(Some)),
                        None=>Ok(Some(None)),
                    }
                };
                let release=|id:&str|handle.block_on(crate::commercial::release_connection(&pool,id));
                let result=match probe.as_ref(){
                    Some(socket)=>forwarder.poll_with_probe(socket,charge,acquire,release),
                    None=>forwarder.poll_with_policy(charge,acquire,release),
                };
                if let Err(e)=result{
                    if rejected.load(Ordering::Acquire)||signal.load(Ordering::Acquire){return Ok(())}
                    return Err(e)
                }
                thread::sleep(Duration::from_millis(2));
            }
            Ok(())
        }).map_err(|_|"UDP monthly guard thread unavailable")?;
        Ok(Self{stop,denied,thread:Some(thread)})
    }
    pub fn denied(&self)->bool{self.denied.load(Ordering::Acquire)}
    pub fn healthy(&self)->bool{self.thread.as_ref().is_some_and(|t|!t.is_finished())}
    pub fn stop(&mut self)->Result<(),&'static str>{
        self.stop.store(true,Ordering::Release);
        if let Some(t)=self.thread.take(){t.join().map_err(|_|"UDP monthly guard panicked")??;}
        Ok(())
    }
}
impl Drop for Guard{fn drop(&mut self){let _=self.stop();}}
