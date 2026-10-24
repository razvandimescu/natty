use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

/// Routing lookups only; nothing is sent to these.
const PUBLIC_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
const PUBLIC_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    53,
);

/// One socket per family: QUIC on direct paths, probes, and STUN share them,
/// so the NAT mapping a probe opens is the one QUIC uses.
#[derive(Debug)]
pub(crate) struct Udp {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

impl Udp {
    /// Must run inside a Tokio runtime.
    pub(crate) fn bind() -> io::Result<Self> {
        let bind = |addr: SocketAddr| {
            let socket = std::net::UdpSocket::bind(addr)?;
            socket.set_nonblocking(true)?;
            UdpSocket::from_std(socket)
        };
        Ok(Self {
            v4: bind((Ipv4Addr::UNSPECIFIED, 0).into())?,
            v6: bind((Ipv6Addr::UNSPECIFIED, 0).into()).ok(),
        })
    }

    pub(crate) fn sockets(&self) -> impl Iterator<Item = &UdpSocket> {
        std::iter::once(&self.v4).chain(&self.v6)
    }

    /// Best effort, like any UDP send: a full buffer or a missing family
    /// drops the datagram.
    pub(crate) fn send_to(&self, data: &[u8], to: SocketAddr) {
        let socket = match to {
            SocketAddr::V4(_) => Some(&self.v4),
            SocketAddr::V6(_) => self.v6.as_ref(),
        };
        if let Some(socket) = socket {
            let _ = socket.try_send_to(data, to);
        }
    }

    /// IPv4 only; other destinations are skipped. The TTL belongs to the
    /// socket, so a QUIC datagram sent in the same instant can leave with it
    /// and be lost, which QUIC repairs.
    pub(crate) fn send_with_ttl(&self, data: &[u8], to: SocketAddr, ttl: u32) {
        if !to.is_ipv4() {
            return;
        }
        let Ok(old) = self.v4.ttl() else {
            return;
        };
        if self.v4.set_ttl(ttl).is_ok() {
            let _ = self.v4.try_send_to(data, to);
            let _ = self.v4.set_ttl(old);
        }
    }

    /// Local candidates: the default-route address of each family with the
    /// port of that family's socket.
    pub(crate) fn local_candidates(&self) -> Vec<SocketAddr> {
        self.sockets()
            .filter_map(|socket| {
                let local = socket.local_addr().ok()?;
                let public = if local.is_ipv4() {
                    PUBLIC_V4
                } else {
                    PUBLIC_V6
                };
                Some(SocketAddr::new(local_ip_toward(public).ok()?, local.port()))
            })
            .collect()
    }
}

/// The local address the kernel would use toward `dst`. A connected UDP
/// socket sends nothing, so this is a routing-table lookup.
pub(crate) fn local_ip_toward(dst: SocketAddr) -> io::Result<IpAddr> {
    let unspecified: SocketAddr = match dst {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = std::net::UdpSocket::bind(unspecified)?;
    socket.connect(dst)?;
    Ok(socket.local_addr()?.ip())
}
