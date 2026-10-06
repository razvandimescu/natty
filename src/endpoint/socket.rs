use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use super::net::Udp;
use super::paths::Paths;
use super::signal;
use crate::wire::{canonical, Frame, MAX_DATAGRAM};
use crate::{stun, PublicKey};

pub(crate) type Datagram = (PublicKey, Vec<u8>);

/// A datagram for the traversal task.
#[derive(Debug)]
pub(crate) enum Packet {
    Stun(Vec<u8>),
    RelayPunch(Vec<u8>),
    UdpPunch(SocketAddr, Vec<u8>),
}

enum Kind {
    Stun,
    Punch,
    Quic,
}

/// By first bytes, the same for relay and UDP datagrams (docs/design.md).
fn classify(data: &[u8]) -> Kind {
    if stun::is_binding_response(data) {
        Kind::Stun
    } else if signal::is_signal(data) {
        Kind::Punch
    } else {
        Kind::Quic
    }
}

/// quinn addresses paths by socket address, so each key gets a stable
/// synthetic one in fd00::/8. These addresses never reach a real socket.
pub(crate) fn virtual_addr(key: &PublicKey) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&key.0[..15]);
    SocketAddr::new(Ipv6Addr::from(octets).into(), 1)
}

/// The only place a datagram's path is chosen, and the only place outbound
/// datagrams are dropped.
#[derive(Debug)]
pub(crate) struct VirtualSocket {
    pub(crate) local: SocketAddr,
    pub(crate) relay: mpsc::Sender<Frame>,
    pub(crate) inbound: Mutex<mpsc::Receiver<Datagram>>,
    pub(crate) udp: Arc<Udp>,
    pub(crate) paths: Arc<Mutex<Paths>>,
    pub(crate) signals: mpsc::Sender<Packet>,
}

impl AsyncUdpSocket for VirtualSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (dst, direct) = self
            .paths
            .lock()
            .unwrap()
            .route(&transmit.destination, Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "unknown peer address")
            })?;
        if let Some((addr, trusted)) = direct {
            self.udp.send_to(transmit.contents, addr);
            if trusted {
                return Ok(());
            }
        }
        // Oversize datagrams are lost as above a link MTU, so MTU discovery
        // backs off; a full queue drops, as a congested UDP socket would.
        if transmit.contents.len() > MAX_DATAGRAM {
            return Ok(());
        }
        let data = transmit.contents.to_vec();
        let _ = self.relay.try_send(Frame::Send { dst, data });
        Ok(())
    }

    /// Every source is polled until it is pending or the batch is full, so
    /// each one has a waker registered whenever this returns pending.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let now = Instant::now();
        let mut count = 0;

        let mut inbound = self.inbound.lock().unwrap();
        while count < bufs.len() {
            let (src, data) = match inbound.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => datagram,
                Poll::Ready(None) if count == 0 => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                }
                Poll::Ready(None) | Poll::Pending => break,
            };
            match classify(&data) {
                Kind::Stun => {}
                Kind::Punch => {
                    let _ = self.signals.try_send(Packet::RelayPunch(data));
                }
                Kind::Quic => {
                    let len = data.len().min(bufs[count].len());
                    bufs[count][..len].copy_from_slice(&data[..len]);
                    let addr = self.paths.lock().unwrap().touch(src, now);
                    meta[count] = recv_meta(addr, len);
                    count += 1;
                }
            }
        }
        drop(inbound);

        for socket in self.udp.sockets() {
            while count < bufs.len() {
                let mut buf = ReadBuf::new(&mut bufs[count]);
                let from = match socket.poll_recv_from(cx, &mut buf) {
                    Poll::Ready(Ok(from)) => canonical(from),
                    // ICMP errors surface here; quinn would treat them as fatal.
                    Poll::Ready(Err(_)) => {
                        cx.waker().wake_by_ref();
                        break;
                    }
                    Poll::Pending => break,
                };
                let data = buf.filled();
                let packet = match classify(data) {
                    Kind::Stun => Packet::Stun(data.to_vec()),
                    Kind::Punch => Packet::UdpPunch(from, data.to_vec()),
                    Kind::Quic => {
                        if let Some(addr) = self.paths.lock().unwrap().quic_from(from, now) {
                            meta[count] = recv_meta(addr, data.len());
                            count += 1;
                        }
                        continue;
                    }
                };
                let _ = self.signals.try_send(packet);
            }
        }

        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

fn recv_meta(addr: SocketAddr, len: usize) -> RecvMeta {
    RecvMeta {
        addr,
        len,
        stride: len,
        ecn: None,
        dst_ip: None,
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
