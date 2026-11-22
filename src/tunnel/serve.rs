use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{debug, info, warn};
use quinn::{Connection, RecvStream, SendStream};
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
const MAX_CONNECTIONS: usize = 64;
const PEER_CONNECTIONS: usize = 4;
const STRANGER_CONNECTIONS: usize = 8;

/// Serves the services of the policy until the endpoint closes. The endpoint
/// must be bound with [`ALPN`](super::ALPN). A new value on the channel
/// changes access at once: a key is allowed a direct path only while the
/// grants hold an entry for it, and an open stream ends when its grant is gone.
pub async fn serve(endpoint: &Endpoint, policy: watch::Receiver<Policy>) {
    tokio::select! {
        () = accept(endpoint, &policy) => {}
        () = follow(endpoint, policy.clone()) => {}
    }
}

async fn accept(endpoint: &Endpoint, policy: &watch::Receiver<Policy>) {
    let total = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let slots = Arc::new(Slots::new());
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&total).try_acquire_owned() else {
            debug!("tunnel: connection limit reached, refusing a handshake");
            incoming.refuse();
            continue;
        };
        let policy = policy.clone();
        let slots = Arc::clone(&slots);
        tokio::spawn(async move {
            let conn = match incoming.await {
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
            let Some(slot) = slots.take(peer, known) else {
                debug!("tunnel: {peer}: connection limit reached");
                conn.close(2u32.into(), b"busy");
                return;
            };
            let _held = (permit, slot);
            serve_peer(conn, peer, policy).await;
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

async fn serve_peer(conn: Connection, peer: PublicKey, policy: watch::Receiver<Policy>) {
    while let Ok((send, recv)) = conn.accept_bi().await {
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(policy, peer, send, recv).await {
                debug!("tunnel: {peer}: {e}");
            }
        });
    }
}

/// Connection slots once the key of the peer is known. Each known key has
/// its own, so one key cannot crowd out the others; every other key shares
/// one small pool, so new keys cannot grow the map.
struct Slots {
    known: Mutex<HashMap<PublicKey, Arc<Semaphore>>>,
    strangers: Arc<Semaphore>,
}

impl Slots {
    fn new() -> Self {
        Self {
            known: Mutex::default(),
            strangers: Arc::new(Semaphore::new(STRANGER_CONNECTIONS)),
        }
    }

    fn take(&self, peer: PublicKey, known: bool) -> Option<OwnedSemaphorePermit> {
        let pool = if known {
            let mut pools = self.known.lock().unwrap();
            let pool = pools
                .entry(peer)
                .or_insert_with(|| Arc::new(Semaphore::new(PEER_CONNECTIONS)));
            Arc::clone(pool)
        } else {
            Arc::clone(&self.strangers)
        };
        pool.try_acquire_owned().ok()
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
        () = revoked(policy, peer, &service) => {
            info!("{peer} -> {service}: closed, the grant is gone");
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

/// Resolves when a new policy no longer grants `service` to `peer`.
async fn revoked(mut policy: watch::Receiver<Policy>, peer: PublicKey, service: &str) {
    while policy.changed().await.is_ok() {
        if !policy.borrow().permits(&peer, service) {
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
        let slots = Slots::new();
        let key = || SecretKey::generate().public();
        let alice = key();
        let held: Vec<_> = (0..PEER_CONNECTIONS)
            .map(|_| slots.take(alice, true).unwrap())
            .collect();
        assert!(slots.take(alice, true).is_none());
        assert!(slots.take(key(), true).is_some());
        let _strangers: Vec<_> = (0..STRANGER_CONNECTIONS)
            .map(|_| slots.take(key(), false).unwrap())
            .collect();
        assert!(slots.take(key(), false).is_none());
        drop(held);
        assert!(slots.take(alice, true).is_some());
    }

    #[tokio::test]
    async fn a_stream_is_revoked_only_when_its_grant_goes() {
        let peer = SecretKey::generate().public();
        let grant = |services: &[&str]| Policy {
            grants: HashMap::from([(
                peer,
                services
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<BTreeSet<_>>(),
            )]),
            ..Policy::default()
        };
        let (tx, rx) = watch::channel(grant(&["web", "db"]));
        let mut gone = tokio::spawn(revoked(rx, peer, "web"));

        tx.send_replace(grant(&["web"]));
        let still_open = timeout(Duration::from_millis(100), &mut gone).await;
        assert!(still_open.is_err(), "another grant went, not this one");

        tx.send_replace(grant(&[]));
        timeout(Duration::from_secs(5), gone)
            .await
            .expect("the removed grant never ended the stream")
            .unwrap();
    }
}
