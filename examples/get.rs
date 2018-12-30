extern crate chrootable_https;
extern crate env_logger;
extern crate structopt;

use chrootable_https::{Client, Resolver};
use std::io;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Args {
    #[structopt(short = "-t", long = "--timeout")]
    timeout: Option<u64>,
    urls: Vec<String>,
    #[structopt(long = "--socks5")]
    socks5: Option<SocketAddr>,
}

fn main() {
    env_logger::init();
    let args = Args::from_args();

    let mut client = if let Some(proxy) = args.socks5 {
        Client::with_socks5(proxy)
    } else {
        let resolver = Resolver::cloudflare();
        Client::new(resolver)
    };

    if let Some(timeout) = args.timeout {
        client.timeout(Duration::from_millis(timeout));
    }

    for url in &args.urls {
        let reply = client
            .get(&url)
            .wait_for_response()
            .expect("request failed");
        eprintln!("{:#?}", reply);
        io::stdout()
            .write(&reply.body)
            .expect("failed to write body");
    }
}
