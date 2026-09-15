//! A QUIC stream between two keys, direct when a punch succeeds, else relayed.
//!   pipe listen <relay-host[:port]>      prints its address, serves one peer
//!   pipe connect <key>@<relay-host[:port]>
//! Both sides copy stdin to the peer and the peer to stdout, then report
//! bytes, throughput, QUIC's RTT estimate, and the path on stderr.
//! NATTY_CA=<pem> adds a trusted root, for relays with self-signed certs.

mod common;

use std::io;
use std::time::Instant;

use natty::{Endpoint, PublicKey, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"natty-pipe/1";
const USAGE: &str = "usage: pipe listen <relay> | pipe connect <key>@<relay>";

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (endpoint, peer, conn, (mut send, mut recv)) = match args.as_slice() {
        [mode, relay] if mode == "listen" => {
            let endpoint = bind(relay).await?;
            eprintln!("listening as {}@{relay}", endpoint.public_key());
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::other("endpoint closed"))?;
            let conn = incoming.await.map_err(io::Error::other)?;
            let peer =
                natty::peer_key(&conn).ok_or_else(|| io::Error::other("peer without key"))?;
            eprintln!("accepted {peer}");
            let (send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
            recv.read_u8().await?;
            (endpoint, peer, conn, (send, recv))
        }
        [mode, target] if mode == "connect" => {
            let (key, relay) = target
                .split_once('@')
                .ok_or_else(|| io::Error::other(USAGE))?;
            let peer: PublicKey = key.parse().map_err(io::Error::other)?;
            let endpoint = bind(relay).await?;
            let dialed = Instant::now();
            let conn = endpoint.connect(peer).await?;
            eprintln!("connected in {:?}", dialed.elapsed());
            let (mut send, recv) = conn.open_bi().await.map_err(io::Error::other)?;
            // A QUIC stream is invisible to the peer until it carries a byte.
            send.write_u8(0).await?;
            (endpoint, peer, conn, (send, recv))
        }
        _ => return Err(io::Error::other(USAGE)),
    };

    let started = Instant::now();
    let upload = async {
        let bytes = tokio::io::copy(&mut tokio::io::stdin(), &mut send).await?;
        send.finish().map_err(io::Error::other)?;
        send.stopped().await.map_err(io::Error::other)?;
        Ok::<_, io::Error>(bytes)
    };
    let mut stdout = tokio::io::stdout();
    let download = tokio::io::copy(&mut recv, &mut stdout);
    let (sent, received) = tokio::try_join!(upload, download)?;
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "sent {sent} B, received {received} B in {secs:.2} s ({:.2} MiB/s), rtt {:?}, path {}",
        sent.max(received) as f64 / secs / (1 << 20) as f64,
        conn.rtt(),
        endpoint
            .direct_addr(&peer)
            .map_or("relay".to_owned(), |addr| format!("direct {addr}"))
    );
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn bind(relay: &str) -> io::Result<Endpoint> {
    let endpoint = Endpoint::bind(SecretKey::generate(), relay, common::relay_tls()?, &[ALPN])?;
    endpoint
        .relay_state()
        .wait_for(Option::is_some)
        .await
        .map_err(io::Error::other)?;
    Ok(endpoint)
}
