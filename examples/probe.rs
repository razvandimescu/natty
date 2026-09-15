//! Relay probe for gate and soak tests.
//!   probe <relay-host[:port]> [peer-key] [--interval SECS]
//! Pings the relay every interval and reconnects when three pings go
//! unanswered, which is how a silently dropped NAT mapping shows up. With a
//! peer key it also sends a numbered message each interval. Lines start with
//! Unix time so logs from different machines line up.
//! NATTY_CA=<pem> adds a trusted root, for relays with self-signed certs.

mod common;

use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use natty::wire::{self, Frame};
use natty::{PublicKey, SecretKey};
use tokio::io::WriteHalf;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;

const USAGE: &str = "usage: probe <relay-host[:port]> [peer-key] [--interval SECS]";
const MISSED_PONGS: u32 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct Probe {
    tls: Arc<ClientConfig>,
    relay: String,
    key: SecretKey,
    peer: Option<PublicKey>,
    interval: Duration,
    start: Instant,
    seq: AtomicU64,
    outstanding: AtomicU32,
}

fn log(msg: impl std::fmt::Display) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    println!("{}.{:03} {msg}", now.as_secs(), now.subsec_millis());
}

#[tokio::main]
async fn main() {
    let probe = Arc::new(parse_args().unwrap_or_else(|e| {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2);
    }));
    log(format_args!(
        "key {} interval {}s",
        probe.key.public(),
        probe.interval.as_secs()
    ));

    let mut backoff = Duration::from_secs(1);
    loop {
        let began = Instant::now();
        match run_session(&probe).await {
            Err(e) if began.elapsed() < probe.interval => {
                log(format_args!("connect failed: {e}"));
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(e) => {
                log(format_args!(
                    "disconnected after {}s: {e}",
                    began.elapsed().as_secs()
                ));
                backoff = Duration::from_secs(1);
            }
            Ok(()) => unreachable!("sessions end only with an error"),
        }
    }
}

async fn run_session(probe: &Arc<Probe>) -> io::Result<()> {
    let (welcome, stream) = natty::connect(probe.tls.clone(), &probe.relay, &probe.key).await?;
    log(format_args!(
        "connected observed {} epoch {}",
        welcome.observed, welcome.epoch
    ));
    probe.outstanding.store(0, Ordering::Relaxed);

    let (mut reader, writer) = tokio::io::split(stream);
    let mut pinger = tokio::spawn(ping_loop(probe.clone(), writer));
    let result = loop {
        tokio::select! {
            ended = &mut pinger => break ended.map_err(io::Error::other).and_then(|r| r),
            frame = wire::read_frame(&mut reader) => match frame {
                Err(e) => break Err(e),
                Ok(Frame::Pong(nonce)) => {
                    probe.outstanding.store(0, Ordering::Relaxed);
                    let sent = Duration::from_micros(u64::from_be_bytes(nonce));
                    let rtt = probe.start.elapsed().saturating_sub(sent);
                    log(format_args!("rtt {:.1}ms", rtt.as_secs_f64() * 1000.0));
                }
                Ok(Frame::Recv { src, data }) => {
                    log(format_args!("from {src}: {}", String::from_utf8_lossy(&data)));
                }
                Ok(other) => log(format_args!("{other:?}")),
            },
        }
    };
    pinger.abort();
    result
}

async fn ping_loop(
    probe: Arc<Probe>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
) -> io::Result<()> {
    let mut ticker = tokio::time::interval(probe.interval);
    loop {
        ticker.tick().await;
        if probe.outstanding.fetch_add(1, Ordering::Relaxed) >= MISSED_PONGS {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{MISSED_PONGS} pings unanswered"),
            ));
        }
        let nonce = (probe.start.elapsed().as_micros() as u64).to_be_bytes();
        wire::write_frame(&mut writer, &Frame::Ping(nonce)).await?;
        if let Some(dst) = probe.peer {
            let seq = probe.seq.fetch_add(1, Ordering::Relaxed);
            let data = format!("seq {seq}").into_bytes();
            wire::write_frame(&mut writer, &Frame::Send { dst, data }).await?;
        }
    }
}

fn parse_args() -> Result<Probe, String> {
    let mut positional = Vec::new();
    let mut interval = 15;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--interval" {
            let value = args.next().ok_or("--interval needs a value")?;
            interval = value
                .parse()
                .map_err(|_| format!("invalid interval: {value}"))?;
        } else {
            positional.push(arg);
        }
    }
    let (relay, peer) = match positional.as_slice() {
        [relay] => (relay, None),
        [relay, peer] => (relay, Some(peer.parse().map_err(|e| format!("{e}"))?)),
        _ => return Err("expected a relay and an optional peer key".into()),
    };

    let tls = common::relay_tls().map_err(|e| e.to_string())?;

    Ok(Probe {
        tls,
        relay: relay.clone(),
        key: SecretKey::generate(),
        peer,
        interval: Duration::from_secs(interval),
        start: Instant::now(),
        seq: AtomicU64::new(0),
        outstanding: AtomicU32::new(0),
    })
}
