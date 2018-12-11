use errors::*;
use ipconfig::get_adapters;
use std::net::SocketAddr;

pub fn read_system_conf() -> Result<Vec<SocketAddr>> {
    let ns = get_adapters()?
        .iter()
        .flat_map(|adapter| adapter.dns_servers().iter())
        .map(|x| SocketAddr::new(*x, 53))
        .collect();

    Ok(ns)
}
