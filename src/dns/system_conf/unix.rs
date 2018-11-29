use errors::*;
use resolv_conf;
use std::fs;
use std::net::{SocketAddr, IpAddr};


pub fn read_system_conf() -> Result<Vec<SocketAddr>> {
    let r = fs::read("/etc/resolv.conf")?;
    let conf = resolv_conf::Config::parse(&r)?;

    let ns = conf.nameservers.into_iter()
        .map(|x| match x {
            resolv_conf::ScopedIp::V4(x) => IpAddr::V4(x),
            resolv_conf::ScopedIp::V6(x, _) => IpAddr::V6(x),
        })
        .map(|x| SocketAddr::new(x, 53))
        .collect();
    Ok(ns)
}
