use byteorder::{NetworkEndian, WriteBytesExt};
use hyper::client::connect;
use std::io;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::net::tcp::TcpStream;
use tokio::prelude::*;


pub enum ProxyDest {
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Domain(String),
}

impl ProxyDest {
    fn apply_ipv4(buf: &mut Vec<u8>, addr: &Ipv4Addr) {
        info!("Setting socks5 destination as ipv4: {:?}", addr);
        buf.push(0x01); // ipv4
        buf.extend(&addr.octets());
    }

    fn apply_ipv6(buf: &mut Vec<u8>, addr: &Ipv6Addr) {
        info!("Setting socks5 destination as ipv6: {:?}", addr);
        buf.push(0x04); // ipv6
        buf.extend(&addr.octets());
    }

    fn apply_domain(buf: &mut Vec<u8>, domain: &str) {
        info!("Setting socks5 destination as domain: {:?}", domain);
        let domain = domain.bytes();
        buf.push(0x03); // domain
        buf.push(domain.len() as u8);
        buf.extend(domain);
    }

    fn apply(&self, buf: &mut Vec<u8>) {
        match self {
            ProxyDest::Ipv4Addr(addr) => Self::apply_ipv4(buf, addr),
            ProxyDest::Ipv6Addr(addr) => Self::apply_ipv6(buf, addr),
            ProxyDest::Domain(domain) => Self::apply_domain(buf, domain),
        }
    }

    pub fn from_hyper(dest: connect::Destination) -> (ProxyDest, u16) {
        let port = match (dest.scheme(), dest.port()) {
            (_, Some(port)) => port,
            ("https", None) => 443,
            ("http", None) => 80,
            (_, None) => 443, // TODO: raise error
        };

        let host = dest.host();
        let host = match host.parse::<Ipv4Addr>() {
            Ok(ipaddr) => ProxyDest::Ipv4Addr(ipaddr),
            _ => ProxyDest::Domain(host.to_string()),
        };

        (host, port)
    }
}

/// A `Future` that will resolve to an tcp connection.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture(Box<Future<Item = TcpStream, Error = io::Error> + Send>);

impl Future for ConnectionFuture {
    type Item = TcpStream;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A `Future` that will resolve to an tcp connection.
#[must_use = "futures do nothing unless polled"]
pub struct SkipFuture(Box<Future<Item = (TcpStream, usize), Error = io::Error> + Send>);

impl Future for SkipFuture {
    type Item = (TcpStream, usize);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

fn err<T: 'static + Send>(msg: &str) -> Box<Future<Item = T, Error = io::Error> + Send> {
    Box::new(future::err(io::Error::new(io::ErrorKind::InvalidData, msg)))
}

fn socks5_request_connect(stream: TcpStream, buf: Vec<u8>, dest: &ProxyDest, port: u16) -> ConnectionFuture {
    info!("Reading socks5 server hello");

    // version
    if buf[0] != 0x05 {
        return ConnectionFuture(err("wrong version"));
    }

    // unauthenticated
    if buf[1] != 0x00 {
        return ConnectionFuture(err("auth failed"));
    }

    info!("Socks5 authentication successful");

    let mut buf = vec![
        0x05, // version
        0x01, // tcp connect
        0x00, // reserved
    ];

    dest.apply(&mut buf);
    buf.write_u16::<NetworkEndian>(port).unwrap();
    info!("Sending connect request");
    let fut = tokio::io::write_all(stream, buf)
        .and_then(|(stream, _)| future::ok(stream));
    ConnectionFuture(Box::new(fut))
}

pub fn connect(addr: &SocketAddr, dest: ProxyDest, port: u16) -> ConnectionFuture {
    let fut = TcpStream::connect(&addr)
        .and_then(|stream| {
            info!("Sending socks5 hello");
            tokio::io::write_all(stream, &[
                0x05, // version
                0x01, // number of supported auths
                0x00, // unauthenticated
            ])
        })
        .and_then(|(stream, _)| {
            let buf = vec![0; 2];
            tokio::io::read_exact(stream, buf)
        })
        .and_then(move |(stream, buf)| socks5_request_connect(stream, buf, &dest, port))
        .and_then(|stream| {
            let buf = vec![0; 4];
            tokio::io::read_exact(stream, buf)
        })
        .and_then(|(stream, buf)| {
            info!("Reading connect response");

            // version
            if buf[0] != 0x05 {
                return SkipFuture(err("wrong version"));
            }
            // status
            match buf[1] {
                0x00 => (),
                0x01 => return SkipFuture(err("general failure")),
                0x02 => return SkipFuture(err("connection not allowed by ruleset")),
                0x03 => return SkipFuture(err("network unreachable")),
                0x04 => return SkipFuture(err("host unreachable")),
                0x05 => return SkipFuture(err("connection refused by destination host")),
                0x06 => return SkipFuture(err("TTL expired")),
                0x07 => return SkipFuture(err("command not supported / protocol error")),
                0x08 => return SkipFuture(err("address type not supported")),
                _    => return SkipFuture(err("unknown connection error")),
            }
            // reserved
            if buf[2] != 0x00 {
                return SkipFuture(err("wrong reserved bytes"));
            }
            info!("Connection successful");

            match buf[3] {
                0x01 => SkipFuture(Box::new(future::ok((stream, 4)))), // ipv4
                0x03 => {
                    let buf = vec![0; 1];
                    let fut = tokio::io::read_exact(stream, buf)
                        .and_then(|(stream, buf)| {
                            Ok((stream, buf[0] as usize))
                        });
                    SkipFuture(Box::new(fut))
                },
                0x04 => SkipFuture(Box::new(future::ok((stream, 16)))), // ipv6
                _ => SkipFuture(err("wrong address type")),
            }
        })
        .and_then(|(stream, n)| {
            let buf = vec![0; n + 2];
            tokio::io::read_exact(stream, buf)
        })
        .and_then(|(stream, _)| {
            info!("Socks5 tunnel established");
            future::ok(stream)
        });
    ConnectionFuture(Box::new(fut))
}
