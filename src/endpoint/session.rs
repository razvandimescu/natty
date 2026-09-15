use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::ReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, interval_at, sleep, timeout, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;

use super::net::local_ip_toward;
use super::socket::Datagram;
use crate::client::{self, RelayAddr};
use crate::wire::{self, Frame, Welcome};
use crate::SecretKey;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(15);
const SILENCE_LIMIT: Duration = Duration::from_secs(45);
const ROUTE_CHECK: Duration = Duration::from_secs(2);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

pub(crate) struct Relay {
    pub tls: Arc<ClientConfig>,
    pub addr: RelayAddr,
    pub key: SecretKey,
}

/// Keeps one session to the relay alive for the life of the endpoint. A
/// session that lasted a keepalive interval reconnects at once; one that
/// failed sooner backs off, so a key held twice cannot flap at full speed.
/// `outbound` is shared with the virtual socket; `control` is a sender on it.
pub(crate) async fn run(
    relay: Relay,
    mut outbound: mpsc::Receiver<Frame>,
    control: mpsc::Sender<Frame>,
    inbound: mpsc::Sender<Datagram>,
    state: watch::Sender<Option<Welcome>>,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let began = Instant::now();
        let connect = client::connect_to(relay.tls.clone(), &relay.addr, &relay.key);
        if let Ok(Ok((welcome, stream))) = timeout(CONNECT_TIMEOUT, connect).await {
            state.send_replace(Some(welcome));
            let _ = serve(stream, &mut outbound, &control, &inbound).await;
            state.send_replace(None);
        }
        if began.elapsed() >= KEEPALIVE {
            backoff = MIN_BACKOFF;
        } else {
            sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// The writer is polled beside the timers, not awaited between them, so a
/// write stuck on a dead link cannot hide it. A stalled writer backs up the
/// shared queue, which drops at the virtual socket.
async fn serve(
    stream: TlsStream<TcpStream>,
    outbound: &mut mpsc::Receiver<Frame>,
    control: &mpsc::Sender<Frame>,
    inbound: &mpsc::Sender<Datagram>,
) -> io::Result<()> {
    let tcp = stream.get_ref().0;
    let (local, remote) = (tcp.local_addr()?, tcp.peer_addr()?);
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = tokio::spawn(read_loop(reader, inbound.clone(), control.clone()));
    let write = wire::write_frames(&mut writer, outbound);
    tokio::pin!(write);

    let mut keepalive = interval_at(Instant::now() + KEEPALIVE, KEEPALIVE);
    let mut route = interval(ROUTE_CHECK);
    let result = loop {
        tokio::select! {
            ended = &mut reader => break ended.map_err(io::Error::other).and_then(|r| r),
            ended = &mut write => break ended,
            _ = keepalive.tick() => {
                let _ = control.try_send(Frame::Ping([0; 8]));
            }
            _ = route.tick() => {
                if route_changed(local, remote) {
                    break Err(io::Error::new(io::ErrorKind::NetworkDown, "route to relay changed"));
                }
            }
        }
    };
    reader.abort();
    result
}

async fn read_loop(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    inbound: mpsc::Sender<Datagram>,
    control: mpsc::Sender<Frame>,
) -> io::Result<()> {
    loop {
        let frame = timeout(SILENCE_LIMIT, wire::read_frame(&mut reader))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay stopped answering"))??;
        match frame {
            Frame::Recv { src, data } => {
                let _ = inbound.try_send((src, data));
            }
            Frame::Ping(nonce) => {
                let _ = control.try_send(Frame::Pong(nonce));
            }
            Frame::Close(reason) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("relay closed the session: {reason:?}"),
                ))
            }
            _ => {}
        }
    }
}

/// Only a missing route counts as a change; if the lookup itself cannot run
/// (no UDP sockets allowed, descriptors exhausted), the silence limit decides.
fn route_changed(local: SocketAddr, relay: SocketAddr) -> bool {
    match local_ip_toward(relay) {
        Ok(current) => current != local.ip(),
        Err(e) => matches!(
            e.kind(),
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_change_is_only_reported_when_the_lookup_runs() {
        let local = "127.0.0.1:50000".parse().unwrap();
        let other = "127.0.0.2:50000".parse().unwrap();
        let relay: SocketAddr = "127.0.0.1:4443".parse().unwrap();
        assert!(!route_changed(local, relay));
        let lookup_runs = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.connect(relay))
            .is_ok();
        assert_eq!(route_changed(other, relay), lookup_runs);
    }
}
