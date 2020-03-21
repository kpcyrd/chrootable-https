use crate::errors::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::result;
use std::str::{self, FromStr};
use std::time::Duration;

use futures::Poll;
use futures::{future, Future};
use tokio::prelude::FutureExt;
use tokio::runtime::Runtime;
use trust_dns::client::ClientHandle;
use trust_dns::client::{Client, ClientConnection, SyncClient};
use trust_dns::op::ResponseCode;
use trust_dns::rr::rdata;
use trust_dns::rr::record_data;
pub use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::{DNSClass, Name};
use trust_dns::tcp::TcpClientConnection;
use trust_dns::udp::UdpClientConnection;

pub mod system_conf;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum DnsError {
    FormErr,
    ServFail,
    NXDomain,
    Other,
    Refused,
    NotAuth,
    NotZone,
    DnsSec,
}

impl DnsError {
    fn from_response_code(code: ResponseCode) -> Option<DnsError> {
        use trust_dns::op::ResponseCode::*;
        match code {
            NoError => None,
            FormErr => Some(DnsError::FormErr),
            ServFail => Some(DnsError::ServFail),
            NXDomain => Some(DnsError::NXDomain),
            NotImp => Some(DnsError::Other),
            Refused => Some(DnsError::Refused),
            YXDomain => Some(DnsError::Other),
            YXRRSet => Some(DnsError::Other),
            NXRRSet => Some(DnsError::Other),
            NotAuth => Some(DnsError::NotAuth),
            NotZone => Some(DnsError::NotZone),
            BADVERS => Some(DnsError::DnsSec),
            BADSIG => Some(DnsError::DnsSec),
            BADKEY => Some(DnsError::DnsSec),
            BADTIME => Some(DnsError::DnsSec),
            BADMODE => Some(DnsError::DnsSec),
            BADNAME => Some(DnsError::DnsSec),
            BADALG => Some(DnsError::DnsSec),
            BADTRUNC => Some(DnsError::DnsSec),
            BADCOOKIE => Some(DnsError::DnsSec),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX((u16, String)),
    NS(String),
    PTR(String),
    SOA(SOA),
    SRV((String, u16)),
    TXT(Vec<u8>),
    Other(String),
}

impl<'a> From<&'a record_data::RData> for RData {
    fn from(rdata: &'a record_data::RData) -> RData {
        use trust_dns::rr::record_data::RData::*;
        match rdata {
            A(ip) => RData::A(*ip),
            AAAA(ip) => RData::AAAA(*ip),
            CNAME(name) => RData::CNAME(name.to_string()),
            MX(mx) => RData::MX((mx.preference(), mx.exchange().to_string())),
            NS(ns) => RData::NS(ns.to_string()),
            PTR(ptr) => RData::PTR(ptr.to_string()),
            SOA(soa) => RData::SOA(soa.into()),
            SRV(srv) => RData::SRV((srv.target().to_string(), srv.port())),
            TXT(txt) => RData::TXT(txt.iter().fold(Vec::new(), |mut a, b| {
                a.extend(b.iter());
                a
            })),
            _ => RData::Other("unknown".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SOA {
    mname: String,
    rname: String,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl<'a> From<&'a rdata::soa::SOA> for SOA {
    fn from(soa: &'a rdata::soa::SOA) -> SOA {
        SOA {
            mname: soa.mname().to_string(),
            rname: soa.rname().to_string(),
            serial: soa.serial(),
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            minimum: soa.minimum(),
        }
    }
}

pub fn dns_name_to_string(name: &Name) -> Result<String> {
    let labels = name
        .iter()
        .map(str::from_utf8)
        .collect::<result::Result<Vec<_>, _>>()?;
    Ok(labels.join("."))
}

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, name: &str, query_type: RecordType) -> Resolving;
}

/// An asynchronous DNS resolver.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Resolver {
    pub ns: Vec<SocketAddr>,
    #[serde(default)]
    pub tcp: bool,
    pub timeout: Option<Duration>,
}

impl Resolver {
    pub fn new(ns: Vec<SocketAddr>) -> Resolver {
        Resolver {
            ns,
            tcp: false,
            timeout: Some(Duration::from_secs(3)),
        }
    }

    /// Build a resolver with no nameservers
    pub fn empty() -> Resolver {
        Resolver {
            ns: vec![],
            tcp: false,
            timeout: None,
        }
    }

    /// Creates a new resolver using the [CloudFlare Authoritative DNS][cf] service.
    ///
    /// [cf]: https://www.cloudflare.com/learning/dns/what-is-1.1.1.1/
    pub fn cloudflare() -> Resolver {
        Resolver::new(
            vec!["1.1.1.1:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()],
        )
    }
    
    /// Creates a new resolver using the [Google Public DNS][ggl] service.
    ///
    /// [ggl]: https://developers.google.com/speed/public-dns/
    pub fn google() -> Resolver {
        Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()],
        )
    }

    /// Creates a new resolver from `/etc/resolv.conf`.
    pub fn from_system() -> Result<Resolver> {
        let ns = system_conf::read_system_conf()?;
        Ok(Resolver::new(ns))
    }

    /// Creates a new resolver from `/etc/resolv.conf`.
    pub fn from_system_v4() -> Result<Resolver> {
        let ns = system_conf::read_system_conf()?
            .into_iter()
            .filter(|ns| ns.is_ipv4())
            .collect();
        Ok(Resolver::new(ns))
    }

    /// Sets a timeout within which each DNS query must complete.
    ///
    /// Default setting is no timeout.
    pub fn timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }
}

impl Resolver {
    fn resolve_with<T>(&self, conn: T, name: Name, query_type: RecordType) -> Resolving
    where
        T: ClientConnection,
    {
        let client = SyncClient::new(conn);
        let (bg, mut client) = client.new_future();

        let query = future::lazy(move || {
            tokio::executor::spawn(bg);
            client
                .query(name, DNSClass::IN, query_type)
                .map_err(Error::from)
        });

        let response: Box<dyn Future<Item = _, Error = _> + Send> = match self.timeout {
            Some(ref timeout) => Box::new(query.timeout(*timeout).map_err(|e| {
                e.into_inner()
                    .unwrap_or_else(|| format_err!("DNS query timed out"))
            })),
            None => Box::new(query),
        };

        let reply = response.and_then(|response| {
            let error = DnsError::from_response_code(response.response_code());

            let answers = response
                .answers()
                .iter()
                .map(|x| {
                    let name = dns_name_to_string(x.name())?;
                    let rdata = x.rdata().into();
                    let ttl = x.ttl();
                    Ok((name, rdata, ttl))
                }).collect::<Result<Vec<_>>>()?;

            Ok(DnsReply { answers, error })
        });

        Resolving::new(reply)
    }
}

impl DnsResolver for Resolver {
    fn resolve(&self, name: &str, query_type: RecordType) -> Resolving {
        let name = match Name::from_str(name) {
            Ok(name) => name,
            Err(e) => return Resolving::new(future::err(e.into())),
        };

        let address = match self.ns.first() {
            Some(ref address) => *address,
            None => return Resolving::new(future::err(format_err!("No nameserver configured"))),
        };

        if self.tcp {
            match TcpClientConnection::new(*address) {
                Ok(conn) => self.resolve_with(conn, name, query_type),
                Err(e) => Resolving::new(future::err(e.into())),
            }
        } else {
            match UdpClientConnection::new(*address) {
                Ok(conn) => self.resolve_with(conn, name, query_type),
                Err(e) => Resolving::new(future::err(e.into())),
            }
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsReply {
    pub answers: Vec<(String, RData, u32)>,
    pub error: Option<DnsError>,
}

impl DnsReply {
    pub fn success(&self) -> Result<Vec<IpAddr>> {
        if let Some(ref error) = self.error {
            bail!("dns server returned error: {:?}", error)
        }

        let ips = self
            .answers
            .iter()
            .flat_map(|x| match x.1 {
                RData::A(ip) => Some(IpAddr::V4(ip)),
                RData::AAAA(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            }).collect();

        Ok(ips)
    }

    pub fn ttl(&self) -> Duration {
        let ttl = if self.error.is_none() {
            self.answers.iter()
                .map(|(_, _, ttl)| *ttl)
                .min()
        } else {
            self.answers.iter()
                .filter_map(|x| match x {
                    (_, RData::SOA(soa), _) => Some(soa.minimum),
                    _ => None,
                })
                .next()
        };
        Duration::from_secs(u64::from(ttl.unwrap_or(0)))
    }
}

/// A `Future` that represents a resolving DNS query.
#[must_use = "futures do nothing unless polled"]
pub struct Resolving(Box<dyn Future<Item = DnsReply, Error = Error> + Send>);

impl Resolving {
    /// Creates a new `Resolving` future.
    pub(crate) fn new<F>(inner: F) -> Self
    where
        F: Future<Item = DnsReply, Error = Error> + Send + 'static,
    {
        Resolving(Box::new(inner))
    }

    /// Drives this future to completion, eventually returning a DNS reply.
    pub fn wait_for_response(self) -> Result<DnsReply> {
        let mut rt = Runtime::new()?;
        rt.block_on(self)
    }
}

impl Future for Resolving {
    type Item = DnsReply;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use tokio::runtime::current_thread::Runtime;

    #[test]
    fn verify_dns_config() {
        let mut runtime = Runtime::new().unwrap();

        let config = Resolver::from_system().expect("DnsConfig::from_system");
        let json = serde_json::to_string(&config).expect("to json");
        println!("{:?}", json);
        let resolver = serde_json::from_str::<Resolver>(&json).expect("to json");

        let fut = resolver.resolve("example.com", RecordType::A);
        runtime.block_on(fut).expect("resolve failed");
    }

    #[test]
    fn verify_dns_config_from_json() {
        let json = r#"{"ns":["1.1.1.1:53","1.0.0.1:53"]}"#;
        let _resolver = serde_json::from_str::<Resolver>(&json).expect("to json");
    }

    #[test]
    fn verify_dns_query() {
        let mut runtime = Runtime::new().unwrap();
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let fut = resolver.resolve("example.com", RecordType::A);
        let x = runtime.block_on(fut).expect("resolve failed");
        println!("{:?}", x);
        assert!(x.error.is_none());
    }

    #[test]
    fn verify_dns_query_timeout() {
        let mut runtime = Runtime::new().unwrap();
        let resolver = Resolver {
            ns: vec!["1.2.3.4:53".parse().unwrap()],
            tcp: false,
            timeout: Some(Duration::from_millis(100)),
        };
        let fut = resolver.resolve("example.com", RecordType::A);
        let x = runtime.block_on(fut);
        assert!(x.is_err());
    }

    #[test]
    fn verify_dns_query_nx() {
        let mut runtime = Runtime::new().unwrap();
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let fut = resolver.resolve("nonexistant.example.com", RecordType::A);
        let x = runtime.block_on(fut).expect("resolve failed");
        println!("{:?}", x);
        assert_eq!(
            x,
            DnsReply {
                answers: Vec::new(),
                error: Some(DnsError::NXDomain),
            }
        );
    }

    #[test]
    fn verify_dns_query_empty_cname() {
        let mut runtime = Runtime::new().unwrap();
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let fut = resolver.resolve("example.com", RecordType::CNAME);
        let x = runtime.block_on(fut).expect("resolve failed");
        println!("{:?}", x);
        assert_eq!(
            x,
            DnsReply {
                answers: Vec::new(),
                error: None,
            }
        );
    }
}
