use ct_logs;
use futures::{future, Poll};
use hyper::client::connect::Destination;
use hyper::client::connect::HttpConnector;
use hyper::client::connect::{self, Connect};
use hyper::rt::Future;
use hyper_rustls::HttpsConnector;
use rustls::ClientConfig;
use webpki_roots;

use errors::Error;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct Connector<T> {
    http: T,
    records: Arc<Mutex<HashMap<String, IpAddr>>>,
}

impl<T> Connector<T> {
    pub fn resolve_dest(&self, dest: Destination) -> Resolving {
        let records = self.records.clone();
        let resolved = future::lazy(move || {
            let cache = records.lock().unwrap_or_else(|x| x.into_inner());
            let ip = cache.get(dest.host()).map(|x| x.to_owned());
            Ok((dest, ip))
        });

        let dest = Box::new(resolved.and_then(|(mut dest, ip)| {
            let ip = match ip {
                Some(IpAddr::V4(ip)) => ip.to_string(),
                Some(IpAddr::V6(ip)) => format!("[{}]", ip),
                None => bail!("host wasn't pre-resolved"),
            };

            dest.set_host(&ip)?;
            Ok(dest)
        }));

        Resolving(dest)
    }
}

impl Connector<HttpConnector> {
    pub fn new(records: Arc<Mutex<HashMap<String, IpAddr>>>) -> Connector<HttpConnector> {
        let mut http = HttpConnector::new(4);
        http.enforce_http(false);
        Connector { http, records }
    }

    pub fn https(
        records: Arc<Mutex<HashMap<String, IpAddr>>>,
    ) -> HttpsConnector<Connector<HttpConnector>> {
        let http = Connector::new(records);

        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);

        HttpsConnector::from((http, config))
    }
}

impl<T> Connect for Connector<T>
where
    T: Connect<Error = io::Error>,
    T: Clone,
    T: 'static,
    T::Transport: 'static,
    T::Future: 'static,
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

/// A Future representing work to connect to a URL
pub struct Connecting<T>(Box<Future<Item = (T, connect::Connected), Error = io::Error> + Send>);

impl<T> Future for Connecting<T> {
    type Item = (T, connect::Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A Future representing work to resolve a DNS query
pub struct Resolving(Box<Future<Item = Destination, Error = Error> + Send>);

impl Future for Resolving {
    type Item = Destination;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}
