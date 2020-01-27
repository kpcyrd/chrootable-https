use ct_logs;
use crate::cache::{self, DnsCache};
use crate::dns::{DnsResolver, RecordType};
use crate::socks5::{self, ProxyDest};
use futures::{future, Poll};
use hyper::client::connect::Destination;
use hyper::client::connect::HttpConnector;
use hyper::client::connect::{self, Connect, Connected};
use hyper::rt::Future;
use hyper_rustls::HttpsConnector;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use webpki_roots;

use crate::errors::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};


pub struct Connector<T, R: DnsResolver> {
    http: T,
    proxy: Option<SocketAddr>,
    resolver: R,
    cache: Arc<Mutex<DnsCache>>,
}

pub fn parse_ipaddr_hostname(host: &str) -> Option<&str> {
    if host.starts_with('[') && host.ends_with(']') {
        info!("hostname is an ipv6 addr, skip resolver");
        Some(host)
    } else if host.parse::<Ipv4Addr>().is_ok() {
        info!("hostname is an ipv4 addr, skip resolver");
        Some(host)
    } else {
        info!("hostname is a domain, continue to resolver");
        None
    }
}

impl<T, R: DnsResolver + 'static> Connector<T, R> {
    #[inline]
    pub fn get_cache(&self, host: &str) -> cache::Value {
        let mut cache = self.cache.lock().unwrap();
        cache.get(host, Instant::now())
    }

    #[inline]
    pub fn insert_cache(cache: Arc<Mutex<DnsCache>>, host: String, ipaddr: Option<IpAddr>, ttl: Duration) {
        let mut cache = cache.lock().unwrap();
        cache.insert(host, ipaddr, ttl, Instant::now());
    }

    pub fn resolve_dest(&self, mut dest: Destination) -> Resolving {
        if parse_ipaddr_hostname(dest.host()).is_some() {
            let fut = Box::new(future::ok(dest));
            return Resolving(fut);
        }

        match self.get_cache(dest.host()) {
            cache::Value::Some(record) => {
                let ip = match record {
                    IpAddr::V4(ip) => ip.to_string(),
                    IpAddr::V6(ip) => format!("[{}]", ip),
                };
                match dest.set_host(&ip) {
                    Ok(_) => {
                        let fut = Box::new(future::ok(dest));
                        Resolving(fut)
                    },
                    Err(err) => {
                        let fut = Box::new(future::err(err.into()));
                        Resolving(fut)
                    },
                }
            },
            cache::Value::NX => {
                let fut = Box::new(future::err(format_err!("dns cache has a negative ttl")));
                Resolving(fut)
            },
            cache::Value::None => {
                let cache = self.cache.clone();
                let host = dest.host().to_string();

                let resolve = self.resolver
                    .resolve(&host, RecordType::A);

                let resolved = Box::new(resolve.and_then(move |reply| {
                    // TODO: we might have more than one record available
                    let record = reply.success()?.into_iter().next();
                    Self::insert_cache(cache, host, record, reply.ttl());

                    match record {
                        Some(record) => {
                            let ip = match record {
                                IpAddr::V4(ip) => ip.to_string(),
                                IpAddr::V6(ip) => format!("[{}]", ip),
                            };

                            dest.set_host(&ip)?;
                            Ok(dest)
                        }
                        None => bail!("no record found"),
                    }
                }));

                Resolving(resolved)
            },
        }
    }
}

impl<R: DnsResolver> Connector<HttpConnector, R> {
    pub fn new(resolver: R) -> Connector<HttpConnector, R> {
        let mut http = HttpConnector::new(4);
        http.enforce_http(false);
        Connector {
            http,
            proxy: None,
            resolver,
            cache: Arc::new(Mutex::new(DnsCache::default())),
        }
    }

    pub fn with_socks5(mut self, proxy: SocketAddr) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn with_https(self) -> HttpsConnector<Connector<HttpConnector, R>> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);

        HttpsConnector::from((self, config))
    }

    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        self.cache.clone()
    }
}

impl<R> Connect for Connector<HttpConnector, R>
where
    R: DnsResolver + 'static,
{
    type Transport = TcpStream;
    type Error = io::Error;
    type Future = Connecting<TcpStream>;

    fn connect(&self, dest: connect::Destination) -> Self::Future {
        match &self.proxy {
            Some(proxy) => {
                let (dest, port) = ProxyDest::from_hyper(dest);
                let fut = socks5::connect(proxy, dest, port)
                    .and_then(|stream| {
                        future::ok((stream, Connected::new()))
                    });
                Connecting(Box::new(fut))
            },
            None => {
                debug!("original destination: {:?}", dest);
                let resolving = self
                    .resolve_dest(dest)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));

                let http = self.http.clone();
                let fut = resolving.and_then(move |dest| {
                    debug!("resolved destination: {:?}", dest);
                    http.connect(dest)
                });

                Connecting(Box::new(fut))
            },
        }
    }
}

/// A Future representing work to connect to a URL.
#[must_use = "futures do nothing unless polled"]
pub struct Connecting<T>(Box<dyn Future<Item = (T, connect::Connected), Error = io::Error> + Send>);

impl<T> Future for Connecting<T> {
    type Item = (T, connect::Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A Future representing work to resolve a DNS query.
#[must_use = "futures do nothing unless polled"]
pub struct Resolving(Box<dyn Future<Item = Destination, Error = Error> + Send>);

impl Future for Resolving {
    type Item = Destination;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_ipv4_skip_resolve() {
        let x = parse_ipaddr_hostname("1.2.3.4");
        assert_eq!(x, Some("1.2.3.4"));
    }

    #[test]
    fn verify_ipv6_skip_resolve() {
        let x = parse_ipaddr_hostname("[::1]");
        assert_eq!(x, Some("[::1]"));
    }

    #[test]
    fn verify_domain_does_not_skip_resolve() {
        let x = parse_ipaddr_hostname("example.com");
        assert_eq!(x, None);
    }
}
