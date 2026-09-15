use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{ConnectionCommon, ProtocolVersion};

use crate::PublicKey;

pub const UPGRADE: &str = "natty/1";
pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_DATAGRAM: usize = MAX_PAYLOAD - 32;
const MAX_HTTP_HEAD: usize = 4096;
const WRITE_BUF_RETAINED: usize = 4096;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-natty-relay-auth-v1";
const AUTH_CONTEXT: &[u8] = b"natty relay auth v1\0";

const CLIENT_HELLO: u8 = 1;
const WELCOME: u8 = 2;
const SEND: u8 = 3;
const RECV: u8 = 4;
const PEER_GONE: u8 = 5;
const PING: u8 = 6;
const PONG: u8 = 7;
const CLOSE: u8 = 8;

/// The signed message is bound to the TLS session so a relay cannot replay a
/// client's proof to another relay. TLS 1.2 exporters without extended master
/// secret can be synchronised across two sessions, so only TLS 1.3 qualifies.
pub fn auth_message<D>(conn: &ConnectionCommon<D>) -> io::Result<Vec<u8>> {
    if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "natty requires TLS 1.3",
        ));
    }
    let exporter = conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, None)
        .map_err(io::Error::other)?;
    Ok([AUTH_CONTEXT, &exporter].concat())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Normal = 0,
    Protocol = 1,
    Auth = 2,
    Idle = 3,
    Replaced = 4,
}

impl From<u8> for CloseReason {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::Protocol,
            2 => Self::Auth,
            3 => Self::Idle,
            4 => Self::Replaced,
            _ => Self::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Welcome {
    pub epoch: u64,
    pub cap: u32,
    /// UDP port of the relay host's STUN responder; 0 when there is none.
    pub stun_port: u16,
    pub observed: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ClientHello { key: PublicKey, sig: [u8; 64] },
    Welcome(Welcome),
    Send { dst: PublicKey, data: Vec<u8> },
    Recv { src: PublicKey, data: Vec<u8> },
    PeerGone(PublicKey),
    Ping([u8; 8]),
    Pong([u8; 8]),
    Close(CloseReason),
    Unknown(u8),
}

impl Frame {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend_from_slice(&[0; 5]);
        let ty = match self {
            Frame::ClientHello { key, sig } => {
                buf.extend_from_slice(&key.0);
                buf.extend_from_slice(sig);
                CLIENT_HELLO
            }
            Frame::Welcome(welcome) => {
                buf.extend_from_slice(&welcome.epoch.to_be_bytes());
                buf.extend_from_slice(&welcome.cap.to_be_bytes());
                buf.extend_from_slice(&welcome.stun_port.to_be_bytes());
                put_addr(buf, welcome.observed);
                WELCOME
            }
            Frame::Send { dst, data } => {
                buf.extend_from_slice(&dst.0);
                buf.extend_from_slice(data);
                SEND
            }
            Frame::Recv { src, data } => {
                buf.extend_from_slice(&src.0);
                buf.extend_from_slice(data);
                RECV
            }
            Frame::PeerGone(key) => {
                buf.extend_from_slice(&key.0);
                PEER_GONE
            }
            Frame::Ping(nonce) => {
                buf.extend_from_slice(nonce);
                PING
            }
            Frame::Pong(nonce) => {
                buf.extend_from_slice(nonce);
                PONG
            }
            Frame::Close(reason) => {
                buf.push(*reason as u8);
                CLOSE
            }
            Frame::Unknown(ty) => *ty,
        };
        let len = (buf.len() - start - 5) as u32;
        buf[start] = ty;
        buf[start + 1..start + 5].copy_from_slice(&len.to_be_bytes());
    }

    pub fn decode(ty: u8, mut payload: Vec<u8>) -> io::Result<Frame> {
        let p = &payload[..];
        let exact = |n: usize| {
            if p.len() == n {
                Ok(())
            } else {
                Err(invalid("frame payload has wrong length"))
            }
        };
        Ok(match ty {
            CLIENT_HELLO => {
                exact(96)?;
                Frame::ClientHello {
                    key: PublicKey(take(p, 0)?),
                    sig: take(p, 32)?,
                }
            }
            WELCOME => Frame::Welcome(Welcome {
                epoch: u64::from_be_bytes(take(p, 0)?),
                cap: u32::from_be_bytes(take(p, 8)?),
                stun_port: u16::from_be_bytes(take(p, 12)?),
                observed: get_addr(&p[14..])?,
            }),
            SEND | RECV => {
                let key = PublicKey(take(p, 0)?);
                payload.drain(..32);
                if ty == SEND {
                    Frame::Send {
                        dst: key,
                        data: payload,
                    }
                } else {
                    Frame::Recv {
                        src: key,
                        data: payload,
                    }
                }
            }
            PEER_GONE => {
                exact(32)?;
                Frame::PeerGone(PublicKey(take(p, 0)?))
            }
            PING => {
                exact(8)?;
                Frame::Ping(take(p, 0)?)
            }
            PONG => {
                exact(8)?;
                Frame::Pong(take(p, 0)?)
            }
            CLOSE => {
                exact(1)?;
                Frame::Close(p[0].into())
            }
            other => Frame::Unknown(other),
        })
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let len = u32::from_be_bytes(take(&head, 1)?) as usize;
    if len > MAX_PAYLOAD {
        return Err(invalid("frame exceeds maximum payload"));
    }
    let mut payload = vec![0; len];
    r.read_exact(&mut payload).await?;
    Frame::decode(head[0], payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let mut buf = Vec::new();
    frame.encode(&mut buf);
    if buf.len() > 5 + MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum payload",
        ));
    }
    w.write_all(&buf).await?;
    w.flush().await
}

/// Writes frames as they arrive, coalescing whatever is already queued into
/// one write. Returns when every sender is gone. The buffer is released after
/// a burst so an idle writer does not hold a maximal frame.
pub async fn write_frames<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &mut mpsc::Receiver<Frame>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    while let Some(frame) = frames.recv().await {
        buf.clear();
        frame.encode(&mut buf);
        while buf.len() < MAX_PAYLOAD {
            let Ok(next) = frames.try_recv() else { break };
            next.encode(&mut buf);
        }
        writer.write_all(&buf).await?;
        writer.flush().await?;
        if buf.capacity() > WRITE_BUF_RETAINED && frames.is_empty() {
            buf = Vec::new();
        }
    }
    Ok(())
}

pub async fn read_http_head<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<String> {
    let mut head = Vec::with_capacity(256);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_HTTP_HEAD {
            return Err(invalid("HTTP head too large"));
        }
        head.push(r.read_u8().await?);
    }
    String::from_utf8(head).map_err(|_| invalid("HTTP head is not UTF-8"))
}

/// IPv4-mapped IPv6 as plain IPv4, so one peer has one address.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

pub(crate) fn put_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn get_addr(p: &[u8]) -> io::Result<SocketAddr> {
    match split_addr(p)? {
        (addr, []) => Ok(addr),
        _ => Err(invalid("address has wrong length")),
    }
}

/// Reads one address and returns the bytes after it.
pub(crate) fn split_addr(p: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    let (ip, port_at): (IpAddr, usize) = match p.first() {
        Some(4) => (Ipv4Addr::from(take::<4>(p, 1)?).into(), 5),
        Some(6) => (Ipv6Addr::from(take::<16>(p, 1)?).into(), 17),
        _ => return Err(invalid("unknown address family")),
    };
    let port = u16::from_be_bytes(take(p, port_at)?);
    Ok((SocketAddr::new(ip, port), &p[port_at + 2..]))
}

fn take<const N: usize>(p: &[u8], at: usize) -> io::Result<[u8; N]> {
    p.get(at..at + N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("frame payload too short"))
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let decoded = Frame::decode(buf[0], buf[5..].to_vec()).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn frames_roundtrip() {
        let key = PublicKey([9; 32]);
        roundtrip(Frame::ClientHello { key, sig: [3; 64] });
        roundtrip(Frame::Welcome(Welcome {
            epoch: u64::MAX,
            cap: 1 << 20,
            stun_port: 3478,
            observed: "203.0.113.7:4242".parse().unwrap(),
        }));
        roundtrip(Frame::Welcome(Welcome {
            epoch: 1,
            cap: 0,
            stun_port: 0,
            observed: "[2001:db8::1]:443".parse().unwrap(),
        }));
        roundtrip(Frame::Send {
            dst: key,
            data: b"quic".to_vec(),
        });
        roundtrip(Frame::Recv {
            src: key,
            data: Vec::new(),
        });
        roundtrip(Frame::PeerGone(key));
        roundtrip(Frame::Ping([1; 8]));
        roundtrip(Frame::Pong([2; 8]));
        roundtrip(Frame::Close(CloseReason::Replaced));
        roundtrip(Frame::Unknown(200));
    }

    #[test]
    fn rejects_malformed_payloads() {
        assert!(Frame::decode(CLIENT_HELLO, vec![0; 95]).is_err());
        assert!(Frame::decode(SEND, vec![0; 31]).is_err());
        assert!(Frame::decode(WELCOME, vec![0; 13]).is_err());
        assert!(Frame::decode(WELCOME, [&[0; 14][..], &[4, 1, 2, 3, 4, 0]].concat()).is_err());
        assert!(Frame::decode(PING, vec![0; 9]).is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_length_before_allocating() {
        let mut input = &[SEND, 0, 1, 0, 1][..];
        assert!(read_frame(&mut input).await.is_err());
    }
}
