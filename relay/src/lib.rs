//! natty relay: key-authenticated sessions, forwarding between connected
//! keys, STUN. Aggregate counters only; there is no per-session log path.

mod limit;

use std::collections::HashMap;
use std::fmt::Write;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use natty::wire::{self, CloseReason, Frame, Welcome};
use natty::{stun, PublicKey};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use limit::TokenBucket;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CLOSE_LINGER: Duration = Duration::from_secs(5);
const SESSION_QUEUE: usize = 256;

pub struct Config {
    pub tls: Arc<ServerConfig>,
    /// Forwarded bytes per second per session; 0 is uncapped.
    pub cap: u32,
    /// Forwarded bytes per second across all sessions; 0 is uncapped.
    pub total_cap: u32,
    /// Concurrent connections per IPv4 address or IPv6 /64.
    pub max_conns_per_ip: usize,
    /// Advertised in WELCOME; 0 when no STUN responder runs.
    pub stun_port: u16,
}

#[derive(Clone)]
pub struct Relay {
    state: Arc<State>,
}

struct State {
    acceptor: TlsAcceptor,
    cap: u32,
    total: Mutex<TokenBucket>,
    max_conns_per_ip: usize,
    stun_port: u16,
    epoch: u64,
    started: Instant,
    peers: Mutex<HashMap<PublicKey, Peer>>,
    conns: Mutex<HashMap<IpAddr, usize>>,
    stats: Stats,
}

struct Peer {
    tx: mpsc::Sender<Frame>,
    _kill: oneshot::Sender<()>,
}

#[derive(Default)]
struct Stats {
    sessions_total: AtomicU64,
    auth_failed: AtomicU64,
    conns_rejected: AtomicU64,
    forwarded_frames: AtomicU64,
    forwarded_bytes: AtomicU64,
    dropped_frames: AtomicU64,
    peer_gone: AtomicU64,
    stun_responses: AtomicU64,
}

fn bump(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

impl Relay {
    pub fn new(config: Config) -> Self {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self {
            state: Arc::new(State {
                acceptor: TlsAcceptor::from(config.tls),
                cap: config.cap,
                total: Mutex::new(TokenBucket::new(config.total_cap)),
                max_conns_per_ip: config.max_conns_per_ip,
                stun_port: config.stun_port,
                epoch,
                started: Instant::now(),
                peers: Mutex::default(),
                conns: Mutex::default(),
                stats: Stats::default(),
            }),
        }
    }

    pub async fn serve_tcp(&self, listener: TcpListener) {
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => {
                    // Typically fd exhaustion; back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let addr = wire::canonical(addr);
            let Some(guard) = ConnGuard::acquire(&self.state, addr.ip()) else {
                bump(&self.state.stats.conns_rejected, 1);
                continue;
            };
            let state = self.state.clone();
            tokio::spawn(async move {
                let _guard = guard;
                handle_conn(state, tcp, addr).await;
            });
        }
    }

    pub async fn serve_stun(&self, socket: UdpSocket) {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(resp) = stun::binding_response(&buf[..n], src) {
                bump(&self.state.stats.stun_responses, 1);
                let _ = socket.send_to(&resp, src).await;
            }
        }
    }
}

struct ConnGuard {
    state: Arc<State>,
    bucket: IpAddr,
}

impl ConnGuard {
    fn acquire(state: &Arc<State>, ip: IpAddr) -> Option<Self> {
        let bucket = match ip {
            IpAddr::V6(v6) => Ipv6Addr::from_bits(v6.to_bits() & (u128::MAX << 64)).into(),
            v4 => v4,
        };
        let mut conns = state.conns.lock().unwrap();
        let count = conns.entry(bucket).or_default();
        if *count >= state.max_conns_per_ip {
            return None;
        }
        *count += 1;
        Some(Self {
            state: state.clone(),
            bucket,
        })
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut conns = self.state.conns.lock().unwrap();
        if let Some(count) = conns.get_mut(&self.bucket) {
            *count -= 1;
            if *count == 0 {
                conns.remove(&self.bucket);
            }
        }
    }
}

async fn handle_conn(state: Arc<State>, tcp: TcpStream, addr: SocketAddr) {
    let _ = tcp.set_nodelay(true);
    // Boxed so the handshake's state is freed before the long-lived session.
    let handshake = Box::pin(handshake(&state, tcp));
    if let Ok(Ok(Some((stream, key)))) = timeout(HANDSHAKE_TIMEOUT, handshake).await {
        run_session(state, stream, key, addr).await;
    }
}

async fn handshake(
    state: &State,
    tcp: TcpStream,
) -> io::Result<Option<(TlsStream<TcpStream>, PublicKey)>> {
    let mut stream = state.acceptor.accept(tcp).await?;
    let head = wire::read_http_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or_default();

    if request_line == "GET /health HTTP/1.1" {
        respond(&mut stream, "200 OK", &state.health()).await?;
        return Ok(None);
    }
    if request_line != "GET /natty HTTP/1.1" || !upgrade_requested(&head) {
        let hint = format!(
            "natty relay: GET /natty with Upgrade: {}, or GET /health\n",
            wire::UPGRADE
        );
        respond(&mut stream, "404 Not Found", &hint).await?;
        return Ok(None);
    }

    let switching = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
        wire::UPGRADE
    );
    stream.write_all(switching.as_bytes()).await?;
    stream.flush().await?;

    let message = wire::auth_message(stream.get_ref().1)?;
    let reason = match wire::read_frame(&mut stream).await? {
        Frame::ClientHello { key, sig } if key.verify(&message, &sig) => {
            return Ok(Some((stream, key)));
        }
        Frame::ClientHello { .. } => {
            bump(&state.stats.auth_failed, 1);
            CloseReason::Auth
        }
        _ => CloseReason::Protocol,
    };
    wire::write_frame(&mut stream, &Frame::Close(reason)).await?;
    stream.shutdown().await?;
    Ok(None)
}

fn upgrade_requested(head: &str) -> bool {
    head.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case(wire::UPGRADE)
        })
    })
}

async fn respond(stream: &mut TlsStream<TcpStream>, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn run_session(
    state: Arc<State>,
    stream: TlsStream<TcpStream>,
    key: PublicKey,
    addr: SocketAddr,
) {
    let (mut reader, writer) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(SESSION_QUEUE);
    let (kill_tx, mut kill) = oneshot::channel();
    let mut writer = tokio::spawn(write_loop(writer, rx));

    let _ = tx.try_send(Frame::Welcome(Welcome {
        epoch: state.epoch,
        cap: state.cap,
        stun_port: state.stun_port,
        observed: addr,
    }));
    // Dropping a replaced session's kill sender ends that session.
    let peer = Peer {
        tx: tx.clone(),
        _kill: kill_tx,
    };
    state.peers.lock().unwrap().insert(key, peer);
    bump(&state.stats.sessions_total, 1);

    let mut bucket = TokenBucket::new(state.cap);
    let reason = loop {
        tokio::select! {
            _ = &mut kill => break CloseReason::Replaced,
            read = timeout(IDLE_TIMEOUT, wire::read_frame(&mut reader)) => match read {
                Err(_) => break CloseReason::Idle,
                Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => break CloseReason::Protocol,
                Ok(Err(_)) | Ok(Ok(Frame::Close(_))) => break CloseReason::Normal,
                Ok(Ok(Frame::Send { dst, data })) => {
                    state.forward(key, dst, data, &tx, &mut bucket);
                }
                Ok(Ok(Frame::Ping(nonce))) => {
                    let _ = tx.try_send(Frame::Pong(nonce));
                }
                Ok(Ok(Frame::Pong(_) | Frame::Unknown(_))) => {}
                Ok(Ok(_)) => break CloseReason::Protocol,
            },
        }
    };

    {
        let mut peers = state.peers.lock().unwrap();
        if peers.get(&key).is_some_and(|p| p.tx.same_channel(&tx)) {
            peers.remove(&key);
        }
    }
    let _ = tx.try_send(Frame::Close(reason));
    drop(tx);
    if timeout(CLOSE_LINGER, &mut writer).await.is_err() {
        writer.abort();
    }
}

async fn write_loop(
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    mut rx: mpsc::Receiver<Frame>,
) -> io::Result<()> {
    wire::write_frames(&mut writer, &mut rx).await?;
    writer.shutdown().await
}

impl State {
    fn forward(
        &self,
        src: PublicKey,
        dst: PublicKey,
        data: Vec<u8>,
        own: &mpsc::Sender<Frame>,
        bucket: &mut TokenBucket,
    ) {
        let len = data.len() as u64;
        // The session's own cap first, so its excess never spends the shared budget.
        if !bucket.take(data.len()) || !self.total.lock().unwrap().take(data.len()) {
            bump(&self.stats.dropped_frames, 1);
            return;
        }
        let target = self.peers.lock().unwrap().get(&dst).map(|p| p.tx.clone());
        let Some(target) = target else {
            bump(&self.stats.peer_gone, 1);
            let _ = own.try_send(Frame::PeerGone(dst));
            return;
        };
        match target.try_send(Frame::Recv { src, data }) {
            Ok(()) => {
                bump(&self.stats.forwarded_frames, 1);
                bump(&self.stats.forwarded_bytes, len);
            }
            Err(_) => bump(&self.stats.dropped_frames, 1),
        }
    }

    fn health(&self) -> String {
        let s = &self.stats;
        let mut out = format!(
            "ok\nuptime_secs {}\nsessions {}\n",
            self.started.elapsed().as_secs(),
            self.peers.lock().unwrap().len()
        );
        for (name, counter) in [
            ("sessions_total", &s.sessions_total),
            ("auth_failed", &s.auth_failed),
            ("conns_rejected", &s.conns_rejected),
            ("forwarded_frames", &s.forwarded_frames),
            ("forwarded_bytes", &s.forwarded_bytes),
            ("dropped_frames", &s.dropped_frames),
            ("peer_gone", &s.peer_gone),
            ("stun_responses", &s.stun_responses),
        ] {
            let _ = writeln!(out, "{name} {}", counter.load(Ordering::Relaxed));
        }
        out
    }
}
