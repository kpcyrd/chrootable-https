use errors::Result;
use failure::Fail;
use std::time::Duration;
use std::net::IpAddr;
use std::fmt;

use futures::Future;
use futures::Poll;
use tokio::runtime::Runtime;
use trust_dns_resolver as tdr;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::system_conf;
use trust_dns_proto::rr::rdata;
use trust_dns_proto::rr::record_data;
pub use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_resolver::config::{ResolverConfig,
                                 ResolverOpts,
                                 NameServerConfig,
                                 Protocol};

use std::io;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};


#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    pub ns: Vec<SocketAddr>,
}

impl DnsConfig {
    pub fn from_system() -> Result<DnsConfig> {
        let (conf, _opts) = system_conf::read_system_conf()?;
        let ns = conf.name_servers().into_iter()
            .map(|x| x.socket_addr)
            .collect();
        Ok(DnsConfig {
            ns,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DnsReply {
    #[serde(rename = "success")]
    Success(Vec<RData>),
    #[serde(rename = "error")]
    Error(DnsError),
}

impl From<Lookup> for DnsReply {
    fn from(lookup: Lookup) -> DnsReply {
        let mut records = Vec::new();
        for data in lookup.iter() {
            records.push(data.into());
        }
        DnsReply::Success(records)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DnsError {
    #[serde(rename = "NX")]
    NXDomain,
}

impl Into<DnsReply> for DnsError {
    #[inline]
    fn into(self) -> DnsReply {
        DnsReply::Error(self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
        use trust_dns_proto::rr::record_data::RData::*;
        match rdata {
            A(ip)       => RData::A(ip.clone()),
            AAAA(ip)    => RData::AAAA(ip.clone()),
            CNAME(name) => RData::CNAME(name.to_string()),
            MX(mx)      => RData::MX((mx.preference(), mx.exchange().to_string())),
            NS(ns)      => RData::NS(ns.to_string()),
            PTR(ptr)    => RData::PTR(ptr.to_string()),
            SOA(soa)    => RData::SOA(soa.into()),
            SRV(srv)    => RData::SRV((srv.target().to_string(), srv.port())),
            TXT(txt)    => RData::TXT(txt.iter()
                                        .fold(Vec::new(), |mut a, b| {
                                            a.extend(b.iter());
                                            a
                                        })),
            _           => RData::Other("unknown".to_string()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SOA {
    mname: String,
    rname: String,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32
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


pub struct Resolver {
    resolver: tdr::Resolver,
}

impl Resolver {
    pub fn cloudflare() -> Resolver {
        Resolver::with_udp_addr(&["1.1.1.1:53".parse().unwrap(),
                                  "1.0.0.1:53".parse().unwrap()]).unwrap()
    }

    /// Create a new resolver from /etc/resolv.conf
    pub fn from_system() -> Result<Resolver> {
        let resolver = tdr::Resolver::from_system_conf()?;
        Ok(Resolver {
            resolver,
        })
    }

    pub fn from_config(config: DnsConfig) -> Result<Resolver> {
        let mut ns = ResolverConfig::default();
        for socket_addr in config.ns {
            ns.add_name_server(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
            });
        }
        let opts = ResolverOpts::default();
        let resolver = tdr::Resolver::new(ns, opts)?;
        Ok(Resolver {
            resolver,
        })
    }

    pub fn with_udp_addr(recursors: &[SocketAddr]) -> Result<Resolver> {
        let mut config = ResolverConfig::new();

        for recursor in recursors {
            config.add_name_server(NameServerConfig {
                socket_addr: recursor.to_owned(),
                protocol: Protocol::Udp,
                tls_dns_name: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        opts.timeout = Duration::from_secs(1);

        let resolver = tdr::Resolver::new(config, opts)?;

        Ok(Resolver {
            resolver,
        })
    }

    pub fn with_udp(recursors: &[IpAddr]) -> Result<Resolver> {
        let recursors = recursors.into_iter()
                            .map(|x| SocketAddr::new(x.to_owned(), 53))
                            .collect::<Vec<_>>();
        Resolver::with_udp_addr(&recursors)
    }

    #[inline]
    fn transform(lookup: LookupIp) -> Vec<IpAddr> {
        lookup.iter().collect()
    }
}

impl fmt::Debug for Resolver {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Resolver {{ ... }}")
    }
}

pub trait DnsResolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>>;

    fn resolve_adv(&self, name: &str, record: RecordType) -> Result<DnsReply>;
}

impl DnsResolver for Resolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        self.resolver.lookup_ip(name)
            .map(Resolver::transform)
            .map_err(|err| format_err!("resolve error: {}", err))
    }

    fn resolve_adv(&self, name: &str, record: RecordType) -> Result<DnsReply> {
        match self.resolver.lookup(name, record) {
            Ok(reply) => Ok(reply.into()),
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound {
                    query: _,
                    valid_until: _,
                } => Ok(DnsError::NXDomain.into()),
                _ => Err(err.context("Failed to resolve").into()),
            },
        }
    }
}

pub struct AsyncResolver {
    resolver: tdr::AsyncResolver,
}

impl AsyncResolver {
    pub fn cloudflare() -> AsyncResolver {
        AsyncResolver::with_udp_addr(&[String::from("1.1.1.1:53"),
                                        String::from("1.0.0.1:53")]).unwrap()
    }

    pub fn with_udp_addr(recursors: &[String]) -> Result<AsyncResolver> {
        let mut config = ResolverConfig::new();

        for recursor in recursors {
            config.add_name_server(NameServerConfig {
                socket_addr: recursor.parse()?,
                protocol: Protocol::Udp,
                tls_dns_name: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(1);

        let mut rt = Runtime::new()?;
        let (resolver, worker) = tdr::AsyncResolver::new(config, opts);
        let worker = rt.block_on(worker);

        let _worker = match worker {
            Ok(worker) => worker,
            Err(_) => bail!("resolver init error"), // TODO
        };

        Ok(AsyncResolver {
            resolver,
        })
    }

    pub fn with_udp(recursors: &[String]) -> Result<AsyncResolver> {
        let recursors = recursors.iter()
                            .map(|x| format!("{}:53", x))
                            .collect::<Vec<_>>();
        AsyncResolver::with_udp_addr(&recursors)
    }

    pub fn resolve(&self, name: &str) -> Resolving {
        let fut = self.resolver.lookup_ip(name)
            .map(|lookup| {
                Resolver::transform(lookup)
            })
            .map_err(|err| {
                io::Error::new(io::ErrorKind::Other, format!("{:?}", err)) // TODO
            });
        Resolving(Box::new(fut))
    }
}

/// A Future representing work to connect to a URL
pub struct Resolving(
    Box<Future<Item = Vec<IpAddr>, Error = io::Error> + Send>,
);

impl Future for Resolving {
    type Item = Vec<IpAddr>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}


#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn verify_dns_config() {
        let config = DnsConfig::from_system().expect("DnsConfig::from_system");
        let json = serde_json::to_string(&config).expect("to json");
        println!("{:?}", json);
        let config = serde_json::from_str::<DnsConfig>(&json).expect("to json");

        let resolver = Resolver::from_config(config).expect("Resolver::from_config");
        resolver.resolve("example.com").expect("resolve failed");
    }

    #[test]
    fn verify_dns_config_from_json() {
        let json = r#"{"ns":["1.1.1.1:53","1.1.1.1:53","1.0.0.1:53","1.0.0.1:53"]}"#;
        let _config = serde_json::from_str::<DnsConfig>(&json).expect("to json");
    }
}
