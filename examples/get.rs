extern crate env_logger;
extern crate chrootable_https;

use chrootable_https::{Resolver, Client};
use std::env;
use std::io;
use std::io::prelude::*;


fn main() {
    env_logger::init();

    let resolver = Resolver::cloudflare();

    let client = Client::new(resolver);

    for url in env::args().skip(1) {
        let reply = client.get(&url).expect("request failed");
        eprintln!("{:#?}", reply);
        io::stdout().write(&reply.body).expect("failed to write body");
    }
}
