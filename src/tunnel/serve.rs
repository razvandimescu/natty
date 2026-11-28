use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info, warn};
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use super::pipe::pipe;
use super::proto::{parse_request, Status, LIST, MAX_REQUEST_LEN};
use super::Policy;
use crate::{peer_key, Endpoint, PublicKey};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 64;
const PEER_CONNECTIONS: usize = 4;
const STRANGER_CONNECTIONS: usize = 8;

/// Serves the services of the policy until the endpoint closes. The endpoint
/// must be bound with [`ALPN`](super::ALPN). A new value on the channel
/// changes access at once: a key is allowed a direct path only while the
/// grants hold an entry for it, and an open stream ends when its grant goes or
/// its service moves.
pub async fn serve(endpoint: &Endpoint, policy: watch::Receiver<Policy>) {
    tokio::select! {
        () = accept(endpoint, &policy) => {}
        () = follow(endpoint, policy.clone()) => {}
    }
}

async fn accept(endpoint: &Endpoint, policy: &watch::Receiver<Policy>) {
    let total = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut slots = Slots::new();
    while let Some(incoming) = endpoint.accept().await {
        let claimed = endpoint
            .claimed_key(&incoming)
            .filter(|key| policy.borrow().knows(key));
        let held = slots
            .take(claimed)
            .zip(Arc::clone(&total).try_acquire_owned().ok());
        let Some(held) = held else {
            debug!("tunnel: connection limit reached, refusing a handshake");
            incoming.refuse();
            continue;
        };
        let policy = policy.clone();
        tokio::spawn(async move {
            let _held = held;
            let handshake = timeout(HANDSHAKE_TIMEOUT, incoming).await;
            let conn = match handshake.unwrap_or(Err(ConnectionError::TimedOut)) {
                Ok(conn) => conn,
                Err(e) => {
                    debug!("tunnel: handshake failed: {e}");
                    return;
                }
            };
            let Some(peer) = peer_key(&conn) else {
                conn.close(1u32.into(), b"no key");
                return;
            };
            let known = policy.borrow().knows(&peer);
            tokio::select! {
                () = serve_peer(&conn, peer, policy.clone()) => {}
                () = until(policy, |p| !p.knows(&peer)), if known => {
                    conn.close(3u32.into(), b"removed");
                }
            }
        });
    }
}

/// Keeps the keys that the endpoint allows equal to the keys in the policy.
async fn follow(endpoint: &Endpoint, mut policy: watch::Receiver<Policy>) {
    let mut allowed = HashSet::new();
    loop {
        let keys: HashSet<PublicKey> = policy.borrow_and_update().grants.keys().copied().collect();
        for key in keys.difference(&allowed) {
            endpoint.allow(*key);
        }
        for key in allowed.difference(&keys) {
            endpoint.revoke(key);
        }
        allowed = keys;
        if policy.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

async fn serve_peer(conn: &Connection, peer: PublicKey, policy: watch::Receiver<Policy>) {
    while let Ok((send, recv)) = conn.accept_bi().await {
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(policy, peer, send, recv).await {
                debug!("tunnel: {peer}: {e}");
            }
        });
    }
}

/// Connection slots, taken before the handshake for the key that the relay
/// names as the sender. Each known key has its own, so one key cannot crowd
/// out the others; every other key shares one small pool, so new keys cannot
/// grow the map.
struct Slots {
    known: HashMap<PublicKey, Arc<Semaphore>>,
    strangers: Arc<Semaphore>,
}

impl Slots {
    fn new() -> Self {
        Self {
            known: HashMap::new(),
            strangers: Arc::new(Semaphore::new(STRANGER_CONNECTIONS)),
        }
    }

    fn take(&mut self, known: Option<PublicKey>) -> Option<OwnedSemaphorePermit> {
        let pool = match known {
            Some(peer) => self
                .known
                .entry(peer)
                .or_insert_with(|| Arc::new(Semaphore::new(PEER_CONNECTIONS))),
            None => &self.strangers,
        };
        Arc::clone(pool).try_acquire_owned().ok()
    }
}

async fn handle_stream(
    policy: watch::Receiver<Policy>,
    peer: PublicKey,
    mut send: SendStream,
    mut recv: RecvStream,
) -> io::Result<()> {
    let service = read_request(&mut recv).await?;
    if service == LIST {
        let names = policy.borrow().listing(&peer).join("\n");
        return reply(&mut send, Status::Ok, names.as_bytes()).await;
    }
    let resolved = policy.borrow().resolve(&peer, &service).map(str::to_owned);
    let target = match resolved {
        Ok(target) => target,
        Err(status) => {
            info!("{peer} -> {service}: {status}");
            return reply(&mut send, status, &[]).await;
        }
    };
    let tcp = match timeout(UPSTREAM_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            warn!("{peer} -> {service} ({target}): {e}");
            return reply(&mut send, Status::Unavailable, &[]).await;
        }
        Err(_) => {
            warn!("{peer} -> {service} ({target}): no answer");
            return reply(&mut send, Status::Unavailable, &[]).await;
        }
    };
    write(&mut send, &[Status::Ok.byte()]).await?;
    info!("{peer} -> {service} ({target})");
    tokio::select! {
        piped = pipe(send, recv, tcp) => piped,
        () = revoked(policy, peer, &service, &target) => {
            info!("{peer} -> {service}: closed, the grant or the service changed");
            Ok(())
        }
    }
}

async fn reply(send: &mut SendStream, status: Status, body: &[u8]) -> io::Result<()> {
    write(send, &[&[status.byte()], body].concat()).await?;
    send.finish().map_err(io::Error::other)
}

async fn write(to: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<()> {
    timeout(REQUEST_TIMEOUT, to.write_all(bytes))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Resolves when a new policy no longer sends `service` of `peer` to `target`.
async fn revoked(policy: watch::Receiver<Policy>, peer: PublicKey, service: &str, target: &str) {
    until(policy, |p| p.resolve(&peer, service) != Ok(target)).await
}

async fn until(mut policy: watch::Receiver<Policy>, gone: impl Fn(&Policy) -> bool) {
    while policy.changed().await.is_ok() {
        if gone(&policy.borrow()) {
            return;
        }
    }
    std::future::pending().await
}

async fn read_request(recv: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let read = async {
        let mut line = Vec::with_capacity(16);
        loop {
            let byte = recv.read_u8().await?;
            if byte == b'\n' {
                return parse_request(&line);
            }
            if line.len() == MAX_REQUEST_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request line too long",
                ));
            }
            line.push(byte);
        }
    };
    timeout(REQUEST_TIMEOUT, read)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::SecretKey;

    #[tokio::test]
    async fn a_stalled_request_line_times_out() {
        let (mut dialer, mut host) = tokio::io::duplex(64);
        dialer.write_all(b"pe").await.unwrap();
        let read = timeout(Duration::from_secs(5), read_request(&mut host));
        let err = read
            .await
            .expect("the request read never gave up")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_reply_the_dialer_does_not_take_times_out() {
        let (mut host, _dialer) = tokio::io::duplex(1);
        let wrote = timeout(Duration::from_secs(5), write(&mut host, b"\0web"));
        let err = wrote
            .await
            .expect("the reply write never gave up")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_request_line_ends_at_its_newline_or_its_limit() {
        let (mut dialer, mut host) = tokio::io::duplex(256);
        dialer.write_all(b"Web\r\nGET /").await.unwrap();
        assert_eq!(read_request(&mut host).await.unwrap(), "web");
        let mut rest = [0; 5];
        host.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"GET /");

        dialer
            .write_all(&[b'a'; MAX_REQUEST_LEN + 1])
            .await
            .unwrap();
        let err = read_request(&mut host).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn each_known_key_and_the_strangers_have_capped_slots() {
        let mut slots = Slots::new();
        let key = || SecretKey::generate().public();
        let alice = key();
        let held: Vec<_> = (0..PEER_CONNECTIONS)
            .map(|_| slots.take(Some(alice)).unwrap())
            .collect();
        assert!(slots.take(Some(alice)).is_none());
        assert!(slots.take(Some(key())).is_some());
        let _strangers: Vec<_> = (0..STRANGER_CONNECTIONS)
            .map(|_| slots.take(None).unwrap())
            .collect();
        assert!(slots.take(None).is_none());
        drop(held);
        assert!(slots.take(Some(alice)).is_some());
    }

    #[tokio::test]
    async fn a_stream_ends_when_its_grant_or_its_upstream_changes() {
        let peer = SecretKey::generate().public();
        let policy = |services: &[&str], web: Option<&str>| Policy {
            grants: HashMap::from([(
                peer,
                services
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<BTreeSet<_>>(),
            )]),
            upstreams: web
                .map(|to| ("web".to_string(), to.to_string()))
                .into_iter()
                .collect(),
        };
        for (what, change, ends) in [
            (
                "another grant went",
                policy(&["web"], Some("127.0.0.1:80")),
                false,
            ),
            (
                "the grant went",
                policy(&["db"], Some("127.0.0.1:80")),
                true,
            ),
            (
                "the service moved",
                policy(&["web", "db"], Some("127.0.0.1:81")),
                true,
            ),
            ("the service went", policy(&["web", "db"], None), true),
        ] {
            let (tx, rx) = watch::channel(policy(&["web", "db"], Some("127.0.0.1:80")));
            let gone = tokio::spawn(revoked(rx, peer, "web", "127.0.0.1:80"));
            tx.send_replace(change);
            let ended = timeout(Duration::from_millis(200), gone).await.is_ok();
            assert_eq!(ended, ends, "{what}");
        }
    }
}
