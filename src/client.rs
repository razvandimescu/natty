use std::io;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::wire::{self, Frame, Welcome};
use crate::SecretKey;

/// Opens an authenticated session to `relay`, given as `host[:port]` with
/// IPv6 literals in brackets. The returned stream carries frames.
pub async fn connect(
    tls: Arc<ClientConfig>,
    relay: &str,
    key: &SecretKey,
) -> io::Result<(Welcome, TlsStream<TcpStream>)> {
    connect_to(tls, &RelayAddr::parse(relay)?, key).await
}

/// A relay address validated once: the authority as given, the host to dial
/// and name in TLS, and the port.
#[derive(Debug, Clone)]
pub(crate) struct RelayAddr {
    authority: String,
    pub(crate) host: String,
    server_name: ServerName<'static>,
    port: u16,
}

impl RelayAddr {
    pub(crate) fn parse(relay: &str) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "relay must be host[:port]");
        let (host, port) = match relay.strip_prefix('[') {
            Some(rest) => match rest.split_once(']').ok_or_else(bad)? {
                (host, "") => (host, None),
                (host, rest) => (host, Some(rest.strip_prefix(':').ok_or_else(bad)?)),
            },
            None => match relay.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (relay, None),
            },
        };
        let port = port.map_or(Ok(443), |p| p.parse().map_err(|_| bad()))?;
        let server_name = ServerName::try_from(host.to_owned()).map_err(|_| bad())?;
        Ok(Self {
            authority: relay.to_owned(),
            host: host.to_owned(),
            server_name,
            port,
        })
    }
}

pub(crate) async fn connect_to(
    tls: Arc<ClientConfig>,
    relay: &RelayAddr,
    key: &SecretKey,
) -> io::Result<(Welcome, TlsStream<TcpStream>)> {
    let tcp = TcpStream::connect((relay.host.as_str(), relay.port)).await?;
    tcp.set_nodelay(true)?;
    let mut stream = TlsConnector::from(tls)
        .connect(relay.server_name.clone(), tcp)
        .await?;

    // The relay reads the HTTP head byte by byte, so the hello can follow the
    // upgrade request without waiting for 101.
    let hello = Frame::ClientHello {
        key: key.public(),
        sig: key.sign(&wire::auth_message(stream.get_ref().1)?),
    };
    let mut request = format!(
        "GET /natty HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
        relay.authority,
        wire::UPGRADE
    )
    .into_bytes();
    hello.encode(&mut request);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let head = wire::read_http_head(&mut stream).await?;
    if !head.starts_with("HTTP/1.1 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "relay refused the upgrade",
        ));
    }
    match wire::read_frame(&mut stream).await? {
        Frame::Welcome(welcome) => Ok((welcome, stream)),
        Frame::Close(reason) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("relay closed the session: {reason:?}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected WELCOME from relay",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::RelayAddr;

    fn parts(relay: &str) -> (String, u16) {
        let addr = RelayAddr::parse(relay).unwrap();
        (addr.host, addr.port)
    }

    #[test]
    fn parses_relay_addresses() {
        assert_eq!(parts("relay.example"), ("relay.example".into(), 443));
        assert_eq!(parts("relay.example:4443"), ("relay.example".into(), 4443));
        assert_eq!(parts("[2001:db8::1]"), ("2001:db8::1".into(), 443));
        assert_eq!(parts("[2001:db8::1]:4443"), ("2001:db8::1".into(), 4443));
        for bad in [
            "2001:db8::1",
            "[2001:db8::1]4443",
            ":443",
            "bad host",
            "relay:x",
        ] {
            assert!(RelayAddr::parse(bad).is_err(), "{bad}");
        }
    }
}
