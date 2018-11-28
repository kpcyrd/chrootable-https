# chrootable-https [![Build Status][travis-img]][travis] [![crates.io][crates-img]][crates] [![docs.rs][docs-img]][docs]

[travis-img]:   https://travis-ci.com/kpcyrd/chrootable-https.svg?branch=master
[travis]:       https://travis-ci.com/kpcyrd/chrootable-https
[crates-img]:   https://img.shields.io/crates/v/chrootable-https.svg
[crates]:       https://crates.io/crates/chrootable-https
[docs-img]:     https://docs.rs/chrootable-https/badge.svg
[docs]:         https://docs.rs/chrootable-https

If you ever tried chrooting an https client into an empty folder you probably
ran into two problems:

- /etc/resolv.conf doesn't exist in an empty folder
- ca-certificates doesn't exist in an empty folder

This crate is working around those issues by using:

- trust-dns so the recursor can be specified expliticly
- rustls and webpki-roots to avoid loading certificates from disk

We're also trying to avoid C dependencies and stick to safe rust as much as
possible.

## Examples

```rust
extern crate chrootable_https;
use chrootable_https::{Resolver, Client};

let resolver = Resolver::cloudflare();
let client = Client::new(resolver);

let reply = client.get("https://httpbin.org/anything").expect("request failed");
println!("{:#?}", reply);
```

## License

LGPL-3+
