use errors::*;
use dns_system_conf;
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use futures::Future;
use futures::Poll;
use tokio::prelude::FutureExt;
use tokio::runtime::Runtime;
use tokio::net::TcpStream;
use trust_dns::client::ClientHandle;
use trust_dns::rr::rdata;
use trust_dns::rr::record_data;
pub use trust_dns::rr::record_type::RecordType;
use trust_dns::client::{Client, ClientConnection, ClientFuture, SyncClient};
use trust_dns::udp::{UdpClientConnection, UdpClientStream};
use trust_dns_proto::udp::UdpClientConnect;
use trust_dns::tcp::{TcpClientConnection, TcpClientStream};
use trust_dns_proto::tcp::TcpClientConnect;
use trust_dns::op::{DnsResponse, ResponseCode};
use trust_dns::rr::{DNSClass, Name};
use trust_dns::rr::dnssec::Signer;
use trust_dns_proto::DnsMultiplexer;
use trust_dns_proto::xfer;


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum DnsError {
    FormErr,
    ServFail,
    #[serde(rename = "NX")]
    NXDomain,
    Other,
    Refused,
    NotAuth,
    NotZone,
    DnsSec,
}

impl DnsError {
    fn from_response_code(code: &ResponseCode) -> Option<DnsError> {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

pub trait DnsResolver {
    fn resolve(&self, name: &str, query_type: RecordType) -> Result<DnsReply>;
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Resolver {
    pub ns: Vec<SocketAddr>,
    #[serde(default)]
    pub tcp: bool,
    pub timeout: Option<Duration>,
}

impl Resolver {
    pub fn cloudflare() -> Resolver {
        Resolver {
            ns: vec![
                "1.1.1.1:53".parse().unwrap(),
                "1.0.0.1:53".parse().unwrap(),
            ],
            tcp: false,
            timeout: Some(Duration::from_secs(1)),
        }
    }

    /// Create a new resolver from /etc/resolv.conf
    pub fn from_system() -> Result<Resolver> {
        let ns = dns_system_conf::read_system_conf()?;
        Ok(Resolver {
            ns,
            tcp: false,
            timeout: Some(Duration::from_secs(1)),
        })
    }

    pub fn timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }
}

impl Resolver {
    fn resolve_with<T: ClientConnection>(&self, conn: T, name: &Name, query_type: RecordType) -> Result<DnsResponse> {
        let client = SyncClient::new(conn);

        let mut reactor = Runtime::new()?;
        let (bg, mut client) = client.new_future();
        let rt = reactor
            .spawn(bg);

        let fut = client.query(name.clone(), DNSClass::IN, query_type)
            .map_err(Error::from);

        let response = match self.timeout {
            Some(timeout) => rt.block_on(fut.timeout(timeout))
                .map_err(|x| match x.into_inner() {
                    Some(e) => e,
                    _ => format_err!("Dns query timed out"),
                })?,
            None => rt.block_on(fut)?,
        };

        Ok(response)
    }
}

impl DnsResolver for Resolver {
    fn resolve(&self, name: &str, query_type: RecordType) -> Result<DnsReply> {
        let name = Name::from_str(name)?;

        let address = self.ns.iter().next()
            .ok_or_else(|| format_err!("No nameserver configured"))?;

        let response: DnsResponse = if self.tcp {
            let conn = TcpClientConnection::new(*address)?;
            self.resolve_with(conn, &name, query_type)?
        } else {
            let conn = UdpClientConnection::new(*address)?;
            self.resolve_with(conn, &name, query_type)?
        };

        let error = DnsError::from_response_code(&response.response_code());

        let answers = response.answers().iter()
            .map(|x| x.rdata().into())
            .collect::<Vec<_>>();

        Ok(DnsReply {
            success: answers.clone(),
            answers,
            error,
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsReply {
    pub answers: Vec<RData>,
    // TODO: this field is deprecated
    pub success: Vec<RData>,
    pub error: Option<DnsError>,
}

impl DnsReply {
    pub fn success(&self) -> Result<Vec<IpAddr>> {
        if let Some(ref error) = self.error {
            bail!("dns server returned error: {:?}", error)
        }

        let ips = self.answers.iter()
            .flat_map(|x| match x {
                RData::A(ip) => Some(IpAddr::V4(ip.clone())),
                RData::AAAA(ip) => Some(IpAddr::V6(ip.clone())),
                _ => None,
            })
            .collect();
        Ok(ips)
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AsyncResolver {
    pub ns: Vec<SocketAddr>,
    #[serde(default)]
    pub tcp: bool,
}

impl AsyncResolver {
    pub fn cloudflare() -> AsyncResolver {
        AsyncResolver {
            ns: vec![
                "1.1.1.1:53".parse().unwrap(),
                "1.0.0.1:53".parse().unwrap(),
            ],
            tcp: false,
        }
    }

    /// Create a new resolver from /etc/resolv.conf
    pub fn from_system() -> Result<AsyncResolver> {
        let ns = dns_system_conf::read_system_conf()?;
        Ok(AsyncResolver {
            ns,
            tcp: false,
        })
    }

    fn resolve_with<T: ClientConnection>(conn: T, name: &Name, query_type: RecordType) -> Result<(ClientFuture<T::SenderFuture, T::Sender, T::Response>, Resolving)> {
        let client = SyncClient::new(conn);

        let (bg, mut client) = client.new_future();

        let fut = client.query(name.clone(), DNSClass::IN, query_type)
            .map_err(Error::from)
            .and_then(|response| {
                let error = DnsError::from_response_code(&response.response_code());

                let answers = response.answers().iter()
                    .map(|x| x.rdata().into())
                    .collect::<Vec<_>>();

                Ok(DnsReply {
                    success: answers.clone(),
                    answers,
                    error,
                })
            });

        Ok((bg, Resolving(Box::new(fut))))
    }

    pub fn resolve(&self, name: &str, query_type: RecordType) -> Result<(AsyncResolverFuture, Resolving)> {
        let name = Name::from_str(name)?;

        let address = self.ns.iter().next()
            .ok_or_else(|| format_err!("No nameserver configured"))?;

        if self.tcp {
            let conn = TcpClientConnection::new(*address)?;
            let (bg, fut) = Self::resolve_with(conn, &name, query_type)?;
            Ok((AsyncResolverFuture::Tcp(bg), fut))
        } else {
            let conn = UdpClientConnection::new(*address)?;
            let (bg, fut) = Self::resolve_with(conn, &name, query_type)?;
            Ok((AsyncResolverFuture::Udp(bg), fut))
        }
    }
}

pub enum AsyncResolverFuture {
    Udp(ClientFuture<xfer::DnsMultiplexerConnect<UdpClientConnect, UdpClientStream, Signer>, DnsMultiplexer<UdpClientStream, Signer>, xfer::DnsMultiplexerSerialResponse>),
    Tcp(ClientFuture<xfer::DnsMultiplexerConnect<TcpClientConnect, TcpClientStream<TcpStream>, Signer>, DnsMultiplexer<TcpClientStream<TcpStream>, Signer>, xfer::DnsMultiplexerSerialResponse>),
}

/// A Future representing work to connect to a URL
pub struct Resolving(
    Box<Future<Item = DnsReply, Error = Error> + Send>,
);

impl Future for Resolving {
    type Item = DnsReply;
    type Error = Error;

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
        let config = Resolver::from_system().expect("DnsConfig::from_system");
        let json = serde_json::to_string(&config).expect("to json");
        println!("{:?}", json);
        let resolver = serde_json::from_str::<Resolver>(&json).expect("to json");

        resolver.resolve("example.com", RecordType::A).expect("resolve failed");
    }

    #[test]
    fn verify_dns_config_from_json() {
        let json = r#"{"ns":["1.1.1.1:53","1.0.0.1:53"]}"#;
        let _resolver = serde_json::from_str::<Resolver>(&json).expect("to json");
    }

    #[test]
    fn verify_dns_query() {
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let x = resolver.resolve("example.com", RecordType::A).expect("resolve failed");
        println!("{:?}", x);
        assert!(x.error.is_none());
    }

    #[test]
    fn verify_dns_query_timeout() {
        let resolver = Resolver {
            ns: vec!["1.2.3.4:53".parse().unwrap()],
            tcp: false,
            timeout: Some(Duration::from_millis(100)),
        };
        let x = resolver.resolve("example.com", RecordType::A);
        assert!(x.is_err());
    }

    #[test]
    fn verify_dns_query_nx() {
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let x = resolver.resolve("nonexistant.example.com", RecordType::A).expect("resolve failed");
        println!("{:?}", x);
        assert_eq!(x, DnsReply {
            answers: Vec::new(),
            success: Vec::new(),
            error: Some(DnsError::NXDomain),
        });
    }

    #[test]
    fn verify_dns_query_empty_cname() {
        let resolver = Resolver::from_system().expect("DnsConfig::from_system");
        let x = resolver.resolve("example.com", RecordType::CNAME).expect("resolve failed");
        println!("{:?}", x);
        assert_eq!(x, DnsReply {
            answers: Vec::new(),
            success: Vec::new(),
            error: None,
        });
    }
}
