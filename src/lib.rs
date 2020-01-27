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
//! let reply = client.get("https://httpbin.org/anything").wait_for_response().expect("request failed");
//! println!("{:#?}", reply);
//! ```

#![warn(unused_extern_crates)]
pub use http;
pub use hyper;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

use bytes::Bytes;
pub use http::header;
use http::response::Parts;
pub use http::Request;
use hyper::client::connect::HttpConnector;
use hyper::rt::Future;
pub use hyper::Body;
use hyper_rustls::HttpsConnector;

use futures::{future, Poll, Stream};
use tokio::prelude::FutureExt;
use tokio::runtime::Runtime;

use crate::cache::{DnsCache, Value};
use std::sync::{Arc, Mutex};

pub use http::Uri;
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};

pub mod cache;
mod connector;
pub mod dns;
pub mod socks5;
use self::connector::Connector;
pub use crate::dns::{DnsResolver, RecordType, Resolver};

pub mod errors {
    pub use failure::{Error, ResultExt};
    pub type Result<T> = ::std::result::Result<T, Error>;
}
pub use crate::errors::*;

/// A Client to make outgoing HTTP requests.
///
/// Uses an specific DNS resolver.
#[derive(Debug)]
pub struct Client<R: DnsResolver> {
    client: hyper::Client<HttpsConnector<Connector<HttpConnector, R>>>,
    cache: Arc<Mutex<DnsCache>>,
}

impl<R: DnsResolver + 'static> Client<R> {
    /// Create a new client with a specific DNS resolver.
    ///
    /// This bypasses `/etc/resolv.conf`.
    pub fn new(resolver: R) -> Client<R> {
        let connector = Connector::new(resolver);
        let cache = connector.cache();
        let https = connector
            .with_https();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        Client {
            client,
            cache,
        }
    }

    /// Shorthand function to do a GET request with [`HttpClient::request`].
    ///
    /// [`HttpClient::request`]: trait.HttpClient.html#tymethod.request
    pub fn get(&self, url: &str) -> ResponseFuture {
        let url = match url.parse::<Uri>() {
            Ok(url) => url,
            Err(e) => return ResponseFuture::new(future::err(e.into())),
        };

        let mut request = Request::builder();
        let request = match request.uri(url).body(Body::empty()) {
            Ok(request) => request,
            Err(e) => return ResponseFuture::new(future::err(e.into())),
        };

        self.request(request)
    }
}

impl Client<Resolver> {
    /// Create a new client with the system resolver from `/etc/resolv.conf`.
    pub fn with_system_resolver() -> Result<Client<Resolver>> {
        let resolver = Resolver::from_system()?;
        Ok(Client::new(resolver))
    }

    /// Create a new client that is locked to a socks5 proxy
    pub fn with_socks5(proxy: SocketAddr) -> Client<Resolver> {
        let resolver = Resolver::empty();
        let connector = Connector::new(resolver);
        let cache = connector.cache();
        let https = connector
            .with_socks5(proxy)
            .with_https();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        Client {
            client,
            cache,
        }
    }
}

/// Generic abstraction over HTTP clients.
pub trait HttpClient {
    fn request(&self, request: Request<hyper::Body>) -> ResponseFuture;
}

impl<R: DnsResolver + 'static> HttpClient for Client<R> {
    fn request(&self, request: Request<hyper::Body>) -> ResponseFuture {
        let client = self.client.clone();
        let cache = self.cache.clone();

        let uri = request.uri().clone();
        info!("sending request to {:?}", uri);
        let fut = client.request(request).map_err(Error::from)
            .and_then(|res| {
                debug!("http response: {:?}", res);
                let (parts, body) = res.into_parts();
                let body = body.concat2().map_err(Error::from);
                (future::ok(parts), body)
            }).map_err(Error::from);

        let reply = fut.and_then(move |(parts, body)| {
            let ipaddr = {
                if let Some(host) = uri.host() {
                    let mut cache = cache.lock().unwrap();
                    if let Value::Some(ipaddr) = cache.get(host, Instant::now()) {
                        debug!("adding ip address to response: {}", ipaddr);
                        Some(ipaddr)
                    } else {
                        debug!("no ip address found in cache, this is unexpected");
                        None
                    }
                } else {
                    None
                }
            };

            let body = body.into_bytes();
            let reply = Response::build(ipaddr, parts, body);
            info!("got reply {:?}", reply);
            Ok(reply)
        });

        ResponseFuture::new(reply)
    }
}

/// A `Future` that will resolve to an HTTP Response.
#[must_use = "futures do nothing unless polled"]
pub struct ResponseFuture(Box<dyn Future<Item = Response, Error = Error> + Send>);

impl ResponseFuture {
    /// Creates a new `ResponseFuture`.
    pub(crate) fn new<F>(inner: F) -> Self
    where
        F: Future<Item = Response, Error = Error> + Send + 'static,
    {
        ResponseFuture(Box::new(inner))
    }

    /// Set a timeout (default setting is no timeout).
    pub fn with_timeout(self, timeout: Option<Duration>) -> Self {
        match timeout {
            Some(timeout) => {
                let fut = self.timeout(timeout)
                    .map_err(|err| match err.into_inner() {
                        Some(err) => err,
                        _ => format_err!("Request timed out"),
                    });
                ResponseFuture(Box::new(fut))
            },
            _ => self,
        }
    }

    /// Drives this future to completion, eventually returning an HTTP response.
    pub fn wait_for_response(self) -> Result<Response> {
        let mut rt = Runtime::new()?;
        rt.block_on(self)
    }
}

impl Future for ResponseFuture {
    type Item = Response;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// Represents an HTTP response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<String>,
    pub ipaddr: Option<IpAddr>,
    pub body: Bytes,
}

impl Response {
    fn build(ipaddr: Option<IpAddr>, parts: Parts, body: Bytes) -> Response {
        let cookies = parts
            .headers
            .get_all("set-cookie")
            .into_iter()
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
            ipaddr,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Resolver;
    use std::time::{Duration, Instant};

    #[test]
    fn verify_200_http() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client
            .get("http://httpbin.org/anything")
            .wait_for_response()
            .expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_200_https() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client
            .get("https://httpbin.org/anything")
            .wait_for_response()
            .expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_200_https_ipaddr() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client
            .get("http://1.1.1.1/")
            .wait_for_response()
            .expect("request failed");
        assert_eq!(reply.status, 301);
    }

    #[test]
    fn verify_200_https_system_resolver() {
        let client = Client::with_system_resolver().expect("failed to create client");
        let reply = client
            .get("https://httpbin.org/anything")
            .wait_for_response()
            .expect("request failed");
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn verify_302() {
        let resolver = Resolver::cloudflare();

        let client = Client::new(resolver);
        let reply = client
            .get("https://httpbin.org/redirect-to?url=/anything&status=302")
            .wait_for_response()
            .expect("request failed");
        assert_eq!(reply.status, 302);
    }

    #[test]
    fn verify_timeout() {
        let resolver = Resolver::cloudflare();
        let client = Client::new(resolver);

        let start = Instant::now();
        let _reply = client.get("http://1.2.3.4")
            .with_timeout(Some(Duration::from_millis(250)))
            .wait_for_response().err();
        let end = Instant::now();

        assert!(end.duration_since(start) < Duration::from_secs(1));
    }
}
