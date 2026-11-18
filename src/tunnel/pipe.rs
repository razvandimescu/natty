use std::io;
use std::time::Duration;

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const IDLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 600 });

/// Copies both directions until each side finishes; a half-close on one
/// side propagates without ending the other. `IDLE` with no byte moving
/// either way, or one write stuck that long, ends the pipe.
pub async fn pipe(send: SendStream, recv: RecvStream, tcp: TcpStream) -> io::Result<()> {
    splice(tokio::io::join(recv, send), tcp).await
}

async fn splice(
    a: impl AsyncRead + AsyncWrite + Unpin,
    b: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<()> {
    let (mut a_rx, mut a_tx) = tokio::io::split(a);
    let (mut b_rx, mut b_tx) = tokio::io::split(b);
    let (mut a_buf, mut b_buf) = (vec![0; 16 * 1024], vec![0; 16 * 1024]);
    let (mut a_open, mut b_open) = (true, true);
    while a_open || b_open {
        tokio::select! {
            n = a_rx.read(&mut a_buf), if a_open => a_open = forward(&a_buf[..n?], &mut b_tx).await?,
            n = b_rx.read(&mut b_buf), if b_open => b_open = forward(&b_buf[..n?], &mut a_tx).await?,
            () = tokio::time::sleep(IDLE) => return Err(io::ErrorKind::TimedOut.into()),
        }
    }
    Ok(())
}

/// Writes `bytes` on, or passes an end of stream on when it is empty. Returns
/// whether the direction is still open.
async fn forward(bytes: &[u8], to: &mut (impl AsyncWrite + Unpin)) -> io::Result<bool> {
    let write = async {
        if bytes.is_empty() {
            to.shutdown().await
        } else {
            to.write_all(bytes).await
        }
    };
    tokio::time::timeout(IDLE, write)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    Ok(!bytes.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_idle_pipe_ends() {
        let (a, _a_peer) = tokio::io::duplex(64);
        let (b, _b_peer) = tokio::io::duplex(64);
        let piped = tokio::time::timeout(Duration::from_secs(5), splice(a, b));
        let err = piped.await.expect("the pipe never gave up").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_pipe_copies_both_ways_until_both_sides_finish() {
        let (a, mut a_peer) = tokio::io::duplex(64);
        let (b, mut b_peer) = tokio::io::duplex(64);
        let piped = tokio::spawn(splice(a, b));
        a_peer.write_all(b"ping").await.unwrap();
        a_peer.shutdown().await.unwrap();
        let mut got = Vec::new();
        b_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        b_peer.write_all(b"pong").await.unwrap();
        b_peer.shutdown().await.unwrap();
        got.clear();
        a_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong");
        piped.await.unwrap().unwrap();
    }
}
