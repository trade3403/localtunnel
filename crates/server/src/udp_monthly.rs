//! Finite monthly-plan UDP ingress. Reuse the core's existing bounded
//! forwarder and precharge each admitted datagram, not periodic statistics.
use crate::udp_guard::{ByteLimits,UdpForwarder};
use std::{net::SocketAddr,sync::{Arc,atomic::{AtomicBool,Ordering}},thread::{self,JoinHandle},time::Duration};
use sqlx::SqlitePool;
pub struct Guard{
    stop:Arc<AtomicBool>,denied:Arc<AtomicBool>,thread:Option<JoinHandle<Result<(),&'static str>>>,
}
impl Guard{
    pub fn start(pool:&SqlitePool,mapping:&str,revision:i64,rid:&str,cap:i64,listen:SocketAddr,target:SocketAddr,rate:u32,burst:u32)->Result<Self,&'static str>{
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
                let result=forwarder.poll_with_charge(|n|{
                    if signal.load(Ordering::Acquire){return Err("UDP guard stopping")}
                    match handle.block_on(crate::commercial::charge_monthly(&pool,&mapping,revision,&rid,cap,n)){
                        Ok(true)=>Ok(()),
                        Ok(false)=>{rejected.store(true,Ordering::Release);Err("monthly UDP budget denied")},
                        Err(e)=>Err(e),
                    }
                });
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
