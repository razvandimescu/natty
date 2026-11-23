use std::io;
use std::time::Duration;

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

const IDLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 600 });

/// Copies both directions at once until each side finishes or one fails; a
/// half-close on one side propagates without ending the other. `IDLE` with
/// no byte moving either way, or one write stuck that long, ends the pipe.
pub async fn pipe(send: SendStream, recv: RecvStream, tcp: TcpStream) -> io::Result<()> {
    splice(tokio::io::join(recv, send), tcp).await
}

async fn splice(
    a: impl AsyncRead + AsyncWrite + Unpin,
    b: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<()> {
    let (a_rx, a_tx) = tokio::io::split(a);
    let (b_rx, b_tx) = tokio::io::split(b);
    let moved = Notify::new();
    let both = async { tokio::try_join!(copy(a_rx, b_tx, &moved), copy(b_rx, a_tx, &moved)) };
    tokio::select! {
        both = both => both.map(drop),
        () = idle(&moved) => Err(io::ErrorKind::TimedOut.into()),
    }
}

async fn copy(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    moved: &Notify,
) -> io::Result<()> {
    let mut buf = vec![0; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if !forward(&buf[..n], &mut to).await? {
            return Ok(());
        }
        moved.notify_one();
    }
}

async fn idle(moved: &Notify) {
    while tokio::time::timeout(IDLE, moved.notified()).await.is_ok() {}
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

    #[tokio::test]
    async fn a_pipe_moves_both_ways_at_once() {
        let (a, a_peer) = tokio::io::duplex(64 * 1024);
        let (b, mut echo) = tokio::io::duplex(64);
        tokio::spawn(splice(a, b));
        tokio::spawn(async move {
            let mut chunk = [0; 1024];
            while let Ok(n @ 1..) = echo.read(&mut chunk).await {
                echo.write_all(&chunk[..n]).await.unwrap();
            }
        });
        let (mut from_echo, mut to_echo) = tokio::io::split(a_peer);
        let sent: Vec<u8> = (0..64 * 1024).map(|i| i as u8).collect();
        tokio::spawn({
            let sent = sent.clone();
            async move { to_echo.write_all(&sent).await }
        });
        let mut echoed = vec![0; sent.len()];
        let read = tokio::time::timeout(Duration::from_secs(5), from_echo.read_exact(&mut echoed));
        read.await.expect("the pipe stalled").unwrap();
        assert_eq!(echoed, sent);
    }
}
