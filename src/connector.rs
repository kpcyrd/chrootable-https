use ct_logs;
use dns::{DnsResolver, RecordType};
use futures::{future, Poll};
use hyper::client::connect::Destination;
use hyper::client::connect::HttpConnector;
use hyper::client::connect::{self, Connect};
use hyper::rt::Future;
use hyper_rustls::HttpsConnector;
use rustls::ClientConfig;
use webpki_roots;

use errors::Error;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

pub struct Connector<T, R: DnsResolver> {
    http: T,
    resolver: Arc<R>,
}

impl<T, R: DnsResolver + 'static> Connector<T, R> {
    pub fn resolve_dest(&self, mut dest: Destination) -> Resolving {
        let resolver = self.resolver.clone();
        let host = dest.host().to_string();

        let resolve = future::lazy(move || {
            resolver
                .resolve(&host, RecordType::A)
        });

        let resolved = Box::new(resolve.and_then(move |record| {
            // TODO: we might have more than one record available
            match record.success()?.into_iter().next() {
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
    }
}

impl<R: DnsResolver> Connector<HttpConnector, R> {
    pub fn new(resolver: Arc<R>) -> Connector<HttpConnector, R> {
        let mut http = HttpConnector::new(4);
        http.enforce_http(false);
        Connector { http, resolver }
    }

    pub fn https(
        resolver: Arc<R>,
    ) -> HttpsConnector<Connector<HttpConnector, R>> {
        let http = Connector::new(resolver);

        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);

        HttpsConnector::from((http, config))
    }
}

impl<T, R> Connect for Connector<T, R>
where
    T: Connect<Error = io::Error>,
    T: Clone,
    T: 'static,
    T::Transport: 'static,
    T::Future: 'static,
    R: DnsResolver,
    R: 'static,
{
    type Transport = T::Transport;
    type Error = io::Error;
    type Future = Connecting<T::Transport>;

    fn connect(&self, dest: connect::Destination) -> Self::Future {
        debug!("original destination: {:?}", dest);
        let resolving = self
            .resolve_dest(dest)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));

        let http = self.http.clone();
        let fut = Box::new(resolving.and_then(move |dest| {
            debug!("resolved destination: {:?}", dest);
            http.connect(dest)
        }));

        Connecting(fut)
    }
}

/// A Future representing work to connect to a URL.
#[must_use = "futures do nothing unless polled"]
pub struct Connecting<T>(Box<Future<Item = (T, connect::Connected), Error = io::Error> + Send>);

impl<T> Future for Connecting<T> {
    type Item = (T, connect::Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A Future representing work to resolve a DNS query.
#[must_use = "futures do nothing unless polled"]
pub struct Resolving(Box<Future<Item = Destination, Error = Error> + Send>);

impl Future for Resolving {
    type Item = Destination;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}
