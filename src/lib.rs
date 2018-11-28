//! This crate provides a chroot/sandbox friendly https client.
//!
//! It doesn't depend on any files from the filesystem which would usually
//! cause issues if /etc/resolv.conf or ca-certificates can not be found.
//!
//! # Example
//!
//! ```
//! extern crate chrootable_https;
//! use chrootable_https::{Resolver, Client};
//!
//! let resolver = Resolver::cloudflare();
//! let client = Client::new(resolver);
//!
//! let reply = client.get("https://httpbin.org/anything").expect("request failed");
//! println!("{:#?}", reply);
//! ```

#![warn(unused_extern_crates)]
pub extern crate hyper;
pub extern crate http;
extern crate tokio;
extern crate rustls;
extern crate hyper_rustls;
extern crate webpki_roots;
extern crate ct_logs;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate futures;
extern crate bytes;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;

#[cfg(unix)]
extern crate resolv_conf;
#[cfg(windows)]
extern crate ipconfig;

pub use hyper::Body;
use http::response::Parts;
pub use http::header;
use hyper_rustls::HttpsConnector;
use hyper::rt::Future;
use hyper::client::connect::HttpConnector;
pub use http::Request;
use bytes::Bytes;

use tokio::runtime::Runtime;
use tokio::prelude::FutureExt;
use futures::{future, Stream};

use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
pub use http::Uri;

mod connector;
pub mod dns;
pub mod dns_system_conf;
use self::connector::Connector;
pub use dns::{Resolver, DnsResolver, RecordType};

pub mod errors {
    pub use failure::{Error, ResultExt};
    pub type Result<T> = ::std::result::Result<T, Error>;
}
pub use errors::*;


#[derive(Debug)]
pub struct Client<R: DnsResolver> {
    client: Arc<hyper::Client<HttpsConnector<Connector<HttpConnector>>>>,
    resolver: R,
    records: Arc<Mutex<HashMap<String, IpAddr>>>,
    timeout: Option<Duration>,
}

impl<R: DnsResolver> Client<R> {
    /// Create a new client with a specific dns resolver.
    ///
    /// This bypasses /etc/resolv.conf
    pub fn new(resolver: R) -> Client<R> {
        let records = Arc::new(Mutex::new(HashMap::new()));
        let https = Connector::https(records.clone());
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        Client {
            client: Arc::new(client),
            resolver,
            records,
            timeout: None,
        }
    }

    /// Set a timeout, default is no timeout
    pub fn timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Pre-populate the dns-cache. This function is usually called internally
    pub fn pre_resolve(&self, uri: &Uri) -> Result<()> {
        let host = match uri.host() {
            Some(host) => host,
            None => bail!("url has no host"),
        };

        let record = self.resolver.resolve(&host, RecordType::A)?;
        match record.success()?.into_iter().next() {
            Some(record) => {
                // TODO: make sure we only add the records we want
                let mut cache = self.records.lock().unwrap();
                cache.insert(host.to_string(), record);
            },
            None => bail!("no record found"),
        }
        Ok(())
    }

    /// Shorthand function to do a GET request with [`HttpClient::request`]
    ///
    /// [`HttpClient::request`]: trait.HttpClient.html#tymethod.request
    pub fn get(&self, url: &str) -> Result<Response> {
        let url = url.parse::<Uri>()?;

        let mut request = Request::builder();
        let request = request.uri(url)
               .body(Body::empty())?;

        self.request(request)
    }
}

impl Client<Resolver> {
    /// Create a new client with the system resolver from /etc/resolv.conf
    pub fn with_system_resolver() -> Result<Client<Resolver>> {
        let resolver = Resolver::from_system()?;
        Ok(Client::new(resolver))
    }
}

pub trait HttpClient {
    fn request(&self, request: Request<hyper::Body>) -> Result<Response>;
}

impl<R: DnsResolver> HttpClient for Client<R> {
    fn request(&self, request: Request<hyper::Body>) -> Result<Response> {
        info!("sending request to {:?}", request.uri());
        self.pre_resolve(request.uri())?;

        let client = self.client.clone();
        let timeout = self.timeout.clone();

        let mut rt = Runtime::new()?;
        let fut = client.request(request)
            .and_then(|res| {
                debug!("http response: {:?}", res);
                let (parts, body) = res.into_parts();
                let body = body.concat2();
                (future::ok(parts), body)
            });

        let (parts, body) = match timeout {
            Some(timeout) => rt.block_on(fut.timeout(timeout))?,
            None => rt.block_on(fut)?,
        };

        let body = body.into_bytes();
        let reply = Response::from((parts, body));
        info!("got reply {:?}", reply);
        Ok(reply)
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<String>,
    pub body: Bytes,
}

impl From<(Parts, Bytes)> for Response {
    fn from(x: (Parts, Bytes)) -> Response {
        let parts = x.0;
        let body = x.1;

        let cookies = parts.headers.get_all("set-cookie").into_iter()
                        .flat_map(|x| x.to_str().map(|x| x.to_owned()).ok())
                        .collect();

        let mut headers = HashMap::new();

        for (k, v) in parts.headers {
            if let Some(k) = k {
                if let Ok(v) = v.to_str() {
                    let k = String::from(k.as_str());
                    let v = String::from(v);

                    headers.insert(k, v);
                }
            }
        }

        Response {
            status: parts.status.as_u16(),
            headers,
            cookies,
            body,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use dns::Resolver;
    use std::time::{Instant, Duration};

    #[test]
    fn verify_200_http() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client.get("http://httpbin.org/anything").expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_200_https() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client.get("https://httpbin.org/anything").expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_200_https_system_resolver() {
        let client = Client::with_system_resolver().expect("failed to create client");
        let reply = client.get("https://httpbin.org/anything").expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_302() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client.get("https://httpbin.org/redirect-to?url=/anything&status=302").expect("request failed");
        assert_eq!(reply.status, 302);
    }

    #[test]
    fn verify_timeout() {
        let resolver = Resolver::cloudflare();

        let mut client = Client::new(resolver);
        client.timeout(Duration::from_millis(250));

        let start = Instant::now();
        let _reply = client.get("http://1.2.3.4").err();
        let end = Instant::now();

        assert!(end.duration_since(start) < Duration::from_secs(1));
    }
}
