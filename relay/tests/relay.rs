use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use natty::quinn::Connection;
use natty::tunnel::{self, OpenError, Policy, Status};
use natty::wire::{self, CloseReason, Frame};
use natty::{Endpoint, PublicKey, SecretKey};
use natty_relay::{Config, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::{version, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

struct Harness {
    relay: String,
    stun: SocketAddr,
    tls: Arc<ClientConfig>,
}

async fn start(cap: u32, max_conns_per_ip: usize) -> Harness {
    start_capped(cap, 0, max_conns_per_ip).await
}

async fn start_capped(cap: u32, total_cap: u32, max_conns_per_ip: usize) -> Harness {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let provider = Arc::new(ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = Relay::new(Config {
        tls: Arc::new(server),
        cap,
        total_cap,
        max_conns_per_ip,
        max_conns: 1000,
        stun_port: udp.local_addr().unwrap().port(),
    });
    let harness = Harness {
        relay: listener.local_addr().unwrap().to_string(),
        stun: udp.local_addr().unwrap(),
        tls: Arc::new(client),
    };
    let tcp_relay = relay.clone();
    tokio::spawn(async move { tcp_relay.serve_tcp(listener).await });
    tokio::spawn(async move { relay.serve_stun(udp).await });
    harness
}

type Session = TlsStream<TcpStream>;

async fn connect(h: &Harness, key: &SecretKey) -> Session {
    natty::connect(h.tls.clone(), &h.relay, key)
        .await
        .unwrap()
        .1
}

async fn next(s: &mut Session) -> Frame {
    tokio::time::timeout(Duration::from_secs(5), wire::read_frame(s))
        .await
        .expect("timed out waiting for a frame")
        .expect("read failed")
}

async fn send(s: &mut Session, frame: Frame) {
    wire::write_frame(s, &frame).await.unwrap();
}

/// PONG arrives only after the relay has handled every earlier frame.
async fn sync(s: &mut Session) {
    send(s, Frame::Ping([42; 8])).await;
    loop {
        if next(s).await == Frame::Pong([42; 8]) {
            return;
        }
    }
}

async fn tls(h: &Harness) -> Session {
    let tcp = TcpStream::connect(&h.relay).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    TlsConnector::from(h.tls.clone())
        .connect(name, tcp)
        .await
        .unwrap()
}

async fn get(h: &Harness, path: &str) -> String {
    let mut s = tls(h).await;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn forwards_between_connected_keys() {
    let h = start(0, 16).await;
    let (a, b) = (SecretKey::generate(), SecretKey::generate());
    let (welcome, mut sa) = natty::connect(h.tls.clone(), &h.relay, &a).await.unwrap();
    assert_eq!(
        welcome.observed.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    let mut sb = connect(&h, &b).await;

    send(
        &mut sa,
        Frame::Send {
            dst: b.public(),
            data: b"hello".to_vec(),
        },
    )
    .await;
    assert_eq!(
        next(&mut sb).await,
        Frame::Recv {
            src: a.public(),
            data: b"hello".to_vec()
        }
    );
    send(
        &mut sb,
        Frame::Send {
            dst: a.public(),
            data: b"back".to_vec(),
        },
    )
    .await;
    assert_eq!(
        next(&mut sa).await,
        Frame::Recv {
            src: b.public(),
            data: b"back".to_vec()
        }
    );

    let body = get(&h, "/health").await;
    assert!(body.contains("\r\n\r\nok\n"), "{body}");
    assert!(body.contains("\nsessions 2\n"), "{body}");
    assert!(body.contains("\nforwarded_frames 2\n"), "{body}");
    assert!(body.contains("\nforwarded_bytes 9\n"), "{body}");
}

#[tokio::test]
async fn unconnected_destination_gets_peer_gone() {
    let h = start(0, 16).await;
    let mut s = connect(&h, &SecretKey::generate()).await;
    let absent = SecretKey::generate().public();

    send(
        &mut s,
        Frame::Send {
            dst: absent,
            data: b"x".to_vec(),
        },
    )
    .await;
    assert_eq!(next(&mut s).await, Frame::PeerGone(absent));
    assert!(get(&h, "/health").await.contains("\nforwarded_frames 0\n"));
}

#[tokio::test]
async fn newest_session_replaces_older() {
    let h = start(0, 16).await;
    let (key, peer) = (SecretKey::generate(), SecretKey::generate());
    let mut old = connect(&h, &key).await;
    let mut new = connect(&h, &key).await;
    assert_eq!(next(&mut old).await, Frame::Close(CloseReason::Replaced));

    let mut sp = connect(&h, &peer).await;
    send(
        &mut sp,
        Frame::Send {
            dst: key.public(),
            data: b"y".to_vec(),
        },
    )
    .await;
    assert_eq!(
        next(&mut new).await,
        Frame::Recv {
            src: peer.public(),
            data: b"y".to_vec()
        }
    );
}

#[tokio::test]
async fn rejects_signature_not_bound_to_this_session() {
    let h = start(0, 16).await;
    let key = SecretKey::generate();
    let mut s = tls(&h).await;
    let upgrade = format!(
        "GET /natty HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
        wire::UPGRADE
    );
    s.write_all(upgrade.as_bytes()).await.unwrap();
    assert!(wire::read_http_head(&mut s)
        .await
        .unwrap()
        .starts_with("HTTP/1.1 101 "));

    let replayed = key.sign(b"a message not bound to this TLS session");
    send(
        &mut s,
        Frame::ClientHello {
            key: key.public(),
            sig: replayed,
        },
    )
    .await;
    assert_eq!(next(&mut s).await, Frame::Close(CloseReason::Auth));
    assert!(get(&h, "/health").await.contains("\nauth_failed 1\n"));
}

#[tokio::test]
async fn cap_drops_excess_instead_of_queueing() {
    let h = start(1000, 16).await;
    let (a, b) = (SecretKey::generate(), SecretKey::generate());
    let mut sa = connect(&h, &a).await;
    let _sb = connect(&h, &b).await;

    for _ in 0..2 {
        let data = vec![0; wire::MAX_DATAGRAM];
        send(
            &mut sa,
            Frame::Send {
                dst: b.public(),
                data,
            },
        )
        .await;
    }
    sync(&mut sa).await;
    let body = get(&h, "/health").await;
    assert!(body.contains("\nforwarded_frames 1\n"), "{body}");
    assert!(body.contains("\ndropped_frames 1\n"), "{body}");
}

#[tokio::test]
async fn cap_charges_the_key_of_an_empty_datagram() {
    let h = start(1000, 16).await;
    let (a, b) = (SecretKey::generate(), SecretKey::generate());
    let mut sa = connect(&h, &a).await;
    let _sb = connect(&h, &b).await;

    for _ in 0..128 {
        send(
            &mut sa,
            Frame::Send {
                dst: b.public(),
                data: Vec::new(),
            },
        )
        .await;
    }
    sync(&mut sa).await;
    let body = get(&h, "/health").await;
    assert!(!body.contains("\ndropped_frames 0\n"), "{body}");
}

#[tokio::test]
async fn total_cap_is_shared_by_all_sessions() {
    let h = start_capped(0, 1000, 16).await;
    let (a, b) = (SecretKey::generate(), SecretKey::generate());
    let mut sa = connect(&h, &a).await;
    let mut sb = connect(&h, &b).await;

    for (from, to) in [(&mut sa, b.public()), (&mut sb, a.public())] {
        let data = vec![0; wire::MAX_DATAGRAM];
        send(from, Frame::Send { dst: to, data }).await;
        sync(from).await;
    }
    let body = get(&h, "/health").await;
    assert!(body.contains("\nforwarded_frames 1\n"), "{body}");
    assert!(body.contains("\ndropped_frames 1\n"), "{body}");
}

#[tokio::test]
async fn per_ip_limit_refuses_extra_connections() {
    let h = start(0, 1).await;
    let _held = connect(&h, &SecretKey::generate()).await;
    let refused = natty::connect(h.tls.clone(), &h.relay, &SecretKey::generate()).await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn session_that_stops_reading_is_closed() {
    let h = start(0, 16).await;
    let (a, b) = (SecretKey::generate(), SecretKey::generate());
    let mut sa = connect(&h, &a).await;
    let _unread = connect(&h, &b).await;
    let datagram = Frame::Send {
        dst: b.public(),
        data: vec![0; wire::MAX_DATAGRAM],
    };
    for _ in 0..16384 {
        send(&mut sa, datagram.clone()).await;
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            send(
                &mut sa,
                Frame::Send {
                    dst: b.public(),
                    data: vec![1],
                },
            )
            .await;
            send(&mut sa, Frame::Ping([1; 8])).await;
            loop {
                match next(&mut sa).await {
                    Frame::PeerGone(key) if key == b.public() => return,
                    Frame::Pong(_) => break,
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("the relay kept a session that stopped reading");
}

#[tokio::test]
async fn unknown_path_is_not_upgraded() {
    let h = start(0, 16).await;
    let out = get(&h, "/derp").await;
    assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
    assert!(!out.contains("natty"), "{out}");
}

#[tokio::test]
async fn stun_reports_reflexive_address() {
    let h = start(0, 16).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = [
        &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42][..],
        &[7; 12],
    ]
    .concat();
    socket.send_to(&request, h.stun).await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 32);
    let port = u16::from_be_bytes([buf[26], buf[27]]) ^ 0x2112;
    let ip: Vec<u8> = buf[28..32]
        .iter()
        .zip(&buf[4..8])
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(port, socket.local_addr().unwrap().port());
    assert_eq!(ip, [127, 0, 0, 1]);
}

async fn endpoint(h: &Harness, secret: SecretKey) -> Endpoint {
    bound(h, secret, b"test").await
}

async fn bound(h: &Harness, secret: SecretKey, alpn: &[u8]) -> Endpoint {
    let endpoint = Endpoint::bind(secret, &h.relay, h.tls.clone(), &[alpn]).unwrap();
    endpoint
        .relay_state()
        .wait_for(Option::is_some)
        .await
        .unwrap();
    endpoint
}

async fn connected(a: &Endpoint, b: &Endpoint) -> (Connection, Connection) {
    let (dialed, accepted) = tokio::join!(a.connect(b.public_key()), async {
        b.accept().await.unwrap().await
    });
    (dialed.unwrap(), accepted.unwrap())
}

#[tokio::test]
async fn endpoints_exchange_a_quic_stream_through_the_relay() {
    let h = start(0, 16).await;
    let a = endpoint(&h, SecretKey::generate()).await;
    let b = endpoint(&h, SecretKey::generate()).await;

    let accept = async {
        let conn = b.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let request = recv.read_to_end(1024).await.unwrap();
        send.write_all(&request).await.unwrap();
        send.finish().unwrap();
        conn
    };
    let dial = async {
        let conn = a.connect(b.public_key()).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"over the relay").await.unwrap();
        send.finish().unwrap();
        recv.read_to_end(1024).await.unwrap()
    };
    let (accepted, echoed) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(accept, dial)
    })
    .await
    .expect("QUIC exchange timed out");

    assert_eq!(echoed, b"over the relay");
    assert_eq!(natty::peer_key(&accepted), Some(a.public_key()));
    assert!(!get(&h, "/health").await.contains("\nforwarded_frames 0\n"));
}

#[tokio::test]
async fn endpoint_session_recovers_after_being_replaced() {
    let h = start(0, 16).await;
    let secret = SecretKey::generate();
    let seed = *secret.seed();
    let endpoint = endpoint(&h, secret).await;
    let mut state = endpoint.relay_state();

    let _intruder = connect(&h, &SecretKey::from_seed(seed)).await;
    tokio::time::timeout(Duration::from_secs(5), state.wait_for(Option::is_none))
        .await
        .expect("replacement not noticed")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), state.wait_for(Option::is_some))
        .await
        .expect("session did not come back")
        .unwrap();
}

async fn forwarded_bytes(h: &Harness) -> u64 {
    let body = get(h, "/health").await;
    let line = body
        .lines()
        .find_map(|l| l.strip_prefix("forwarded_bytes "));
    line.expect("counter present").parse().unwrap()
}

#[tokio::test]
async fn endpoints_punch_a_direct_path_that_carries_the_data() {
    let h = start(0, 16).await;
    let a = endpoint(&h, SecretKey::generate()).await;
    let b = endpoint(&h, SecretKey::generate()).await;
    b.allow(a.public_key());
    let (conn, accepted) = connected(&a, &b).await;

    tokio::time::timeout(Duration::from_secs(10), async {
        while a.direct_addr(&b.public_key()).is_none() || b.direct_addr(&a.public_key()).is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no direct path");

    let before = forwarded_bytes(&h).await;
    let payload = vec![7u8; 1 << 20];
    let ((), received) = tokio::join!(
        async {
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        },
        async {
            let (_send, mut recv) = accepted.accept_bi().await.unwrap();
            recv.read_to_end(2 << 20).await.unwrap()
        }
    );
    assert_eq!(received, payload);
    let relayed = forwarded_bytes(&h).await - before;
    assert!(
        relayed < 16 * 1024,
        "{relayed} bytes still went through the relay"
    );

    let before = forwarded_bytes(&h).await;
    tokio::time::timeout(Duration::from_secs(3), connected(&a, &b))
        .await
        .expect("handshake stalled on the direct path");
    // The first Initial datagram of each side, padded to 1200 bytes.
    let relayed = forwarded_bytes(&h).await - before;
    assert!(relayed >= 2 * 1200, "{relayed} bytes relayed");
}

#[tokio::test]
async fn unallowed_dialer_is_served_through_the_relay_only() {
    let h = start(0, 16).await;
    let a = endpoint(&h, SecretKey::generate()).await;
    let b = endpoint(&h, SecretKey::generate()).await;
    let (conn, accepted) = connected(&a, &b).await;

    let payload = vec![7u8; 256 * 1024];
    let ((), received) = tokio::join!(
        async {
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        },
        async {
            let (_send, mut recv) = accepted.accept_bi().await.unwrap();
            recv.read_to_end(1 << 20).await.unwrap()
        }
    );
    assert_eq!(received, payload);
    // Longer than a punch, which the dialer starts at once.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(a.direct_addr(&b.public_key()), None);
    assert_eq!(b.direct_addr(&a.public_key()), None);
    assert!(forwarded_bytes(&h).await >= payload.len() as u64);
}

#[tokio::test]
async fn idle_connection_outlives_the_quic_idle_timeout() {
    let h = start(0, 16).await;
    let a = endpoint(&h, SecretKey::generate()).await;
    let b = endpoint(&h, SecretKey::generate()).await;
    let (conn, accepted) = connected(&a, &b).await;

    // quinn's default idle timeout is 30 s.
    tokio::time::sleep(Duration::from_secs(33)).await;
    assert_eq!(conn.close_reason(), None);
    assert_eq!(accepted.close_reason(), None);
}

#[tokio::test]
async fn closed_endpoint_tells_its_peers_before_it_goes() {
    let h = start(0, 16).await;
    let a = endpoint(&h, SecretKey::generate()).await;
    let b = endpoint(&h, SecretKey::generate()).await;
    let (_conn, accepted) = connected(&a, &b).await;

    a.close().await;
    drop(a);
    let reason = tokio::time::timeout(Duration::from_secs(5), accepted.closed())
        .await
        .expect("peer never heard the close");
    assert!(matches!(
        reason,
        natty::quinn::ConnectionError::ApplicationClosed(_)
    ));
}

async fn echo_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rx, mut tx) = tcp.split();
                let _ = tokio::io::copy(&mut rx, &mut tx).await;
            });
        }
    });
    addr
}

fn grants(peer: PublicKey, services: &[&str]) -> HashMap<PublicKey, BTreeSet<String>> {
    HashMap::from([(peer, services.iter().map(|s| s.to_string()).collect())])
}

/// A host that serves the policy made for the dialer's key, and the dialer
/// connected to it.
async fn tunnel_pair(
    h: &Harness,
    policy: impl FnOnce(PublicKey) -> Policy,
) -> (watch::Sender<Policy>, Endpoint, Connection) {
    let dialer = bound(h, SecretKey::generate(), tunnel::ALPN).await;
    let host = bound(h, SecretKey::generate(), tunnel::ALPN).await;
    let host_key = host.public_key();
    let (tx, rx) = watch::channel(policy(dialer.public_key()));
    tokio::spawn(async move { tunnel::serve(&host, rx).await });
    let conn = tunnel::dial(&dialer, host_key).await.unwrap();
    (tx, dialer, conn)
}

#[tokio::test]
async fn tunnel_opens_granted_services_and_refuses_the_rest() {
    let h = start(0, 16).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down = closed.local_addr().unwrap().to_string();
    drop(closed);
    let upstreams = HashMap::from([
        ("echo".to_string(), echo_upstream().await),
        ("down".to_string(), down),
        ("private".to_string(), echo_upstream().await),
    ]);
    let (tx, dialer, conn) = tunnel_pair(&h, |_| Policy::default()).await;
    assert!(matches!(
        tunnel::open(&conn, "echo").await,
        Err(OpenError::Refused(Status::Denied))
    ));
    assert!(tunnel::list(&conn).await.unwrap().is_empty());

    tx.send_replace(Policy {
        grants: grants(dialer.public_key(), &["echo", "down", "gone"]),
        upstreams,
    });
    assert_eq!(tunnel::list(&conn).await.unwrap(), ["down", "echo"]);
    let (mut send, mut recv) = tunnel::open(&conn, "Echo").await.unwrap();
    send.write_all(b"through the tunnel").await.unwrap();
    send.finish().unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(1024))
        .await
        .expect("the upstream never answered")
        .unwrap();
    assert_eq!(echoed, b"through the tunnel");

    for (service, status) in [
        ("private", Status::Denied),
        ("nowhere", Status::Denied),
        ("gone", Status::Unknown),
        ("down", Status::Unavailable),
    ] {
        match tunnel::open(&conn, service).await {
            Err(OpenError::Refused(refused)) => assert_eq!(refused, status, "{service}"),
            other => panic!("{service}: {:?}", other.map(|_| "opened")),
        }
    }
}

#[tokio::test]
async fn tunnel_ends_an_open_stream_when_its_grant_goes() {
    let h = start(0, 16).await;
    let upstreams = HashMap::from([("echo".to_string(), echo_upstream().await)]);
    let (tx, dialer, conn) = tunnel_pair(&h, |_| Policy::default()).await;
    let granted = |services: &[&str]| Policy {
        grants: grants(dialer.public_key(), services),
        upstreams: upstreams.clone(),
    };
    tx.send_replace(granted(&["echo", "other"]));

    let (mut send, mut recv) = tunnel::open(&conn, "echo").await.unwrap();
    send.write_all(b"1").await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), b'1');

    tx.send_replace(granted(&["echo"]));
    send.write_all(b"2").await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), b'2');

    tx.send_replace(granted(&[]));
    let rest = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(1024))
        .await
        .expect("the stream outlived its grant")
        .unwrap();
    assert!(rest.is_empty());
    assert!(matches!(
        tunnel::open(&conn, "echo").await,
        Err(OpenError::Refused(Status::Denied))
    ));
}

#[tokio::test]
async fn tunnel_gives_up_on_a_host_that_never_answers() {
    let h = start(0, 16).await;
    let host = bound(&h, SecretKey::generate(), tunnel::ALPN).await;
    let dialer = bound(&h, SecretKey::generate(), tunnel::ALPN).await;
    let (conn, accepted) = connected(&dialer, &host).await;
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut send, mut recv)) = accepted.accept_bi().await {
            if recv.read_u8().await.unwrap() == b'?' {
                send.write_all(&[0]).await.unwrap();
            }
            held.push((send, recv));
        }
    });
    let answers = async { tokio::join!(tunnel::open(&conn, "echo"), tunnel::list(&conn)) };
    let (opened, listed) = tokio::time::timeout(Duration::from_secs(25), answers)
        .await
        .expect("the dialer never gave up");
    assert!(matches!(opened, Err(OpenError::Unreachable(_))));
    assert!(matches!(listed, Err(OpenError::Unreachable(_))));
}

#[tokio::test]
async fn tunnel_streams_past_the_limit_wait_to_open() {
    let h = start(0, 16).await;
    let upstreams = HashMap::from([("echo".to_string(), echo_upstream().await)]);
    let (tx, dialer, conn) = tunnel_pair(&h, |_| Policy::default()).await;
    tx.send_replace(Policy {
        grants: grants(dialer.public_key(), &["echo"]),
        upstreams,
    });
    let mut open = Vec::new();
    for _ in 0..32 {
        open.push(tunnel::open(&conn, "echo").await.unwrap());
    }
    let one_way = tokio::time::timeout(Duration::from_secs(1), conn.open_uni()).await;
    assert!(one_way.is_err(), "a unidirectional stream opened");
    let mut past_the_limit = Box::pin(tunnel::open(&conn, "echo"));
    let waited = tokio::time::timeout(Duration::from_secs(16), &mut past_the_limit).await;
    assert!(waited.is_err(), "a 33rd stream did not wait to open");

    for (mut send, mut recv) in open {
        send.finish().unwrap();
        recv.read_to_end(1024).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), past_the_limit)
        .await
        .expect("no stream opened after the others ended")
        .unwrap();
}

#[tokio::test]
async fn tunnel_closes_the_connections_of_a_key_that_goes() {
    let h = start(0, 16).await;
    let known = |dialer| Policy {
        grants: grants(dialer, &[]),
        ..Policy::default()
    };
    let (tx, _dialer, conn) = tunnel_pair(&h, known).await;
    let stranger = bound(&h, SecretKey::generate(), tunnel::ALPN).await;
    let host_key = natty::peer_key(&conn).unwrap();
    let stranger_conn = tunnel::dial(&stranger, host_key).await.unwrap();
    for conn in [&conn, &stranger_conn] {
        assert!(tunnel::list(conn).await.unwrap().is_empty());
    }

    tx.send_replace(Policy::default());
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("the key that went kept its connection");
    assert!(matches!(
        closed,
        natty::quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code == natty::quinn::VarInt::from_u32(3)
    ));
    assert!(tunnel::list(&stranger_conn).await.unwrap().is_empty());
}

async fn initials_nobody_finishes(h: &Harness, count: usize) -> Vec<Vec<u8>> {
    let silent = SecretKey::generate();
    let mut sink = connect(h, &silent).await;
    let dialer = Arc::new(bound(h, SecretKey::generate(), tunnel::ALPN).await);
    for _ in 0..count {
        let (dialer, key) = (Arc::clone(&dialer), silent.public());
        tokio::spawn(async move { dialer.connect(key).await });
    }
    let mut initials = HashMap::new();
    while initials.len() < count {
        let Frame::Recv { data, .. } = next(&mut sink).await else {
            continue;
        };
        if data.first().is_some_and(|b| b & 0xB0 == 0x80) {
            let dcid = data[6..6 + usize::from(data[5])].to_vec();
            initials.entry(dcid).or_insert(data);
        }
    }
    initials.into_values().collect()
}

#[tokio::test]
async fn tunnel_serves_a_granted_key_while_a_stranger_leaves_handshakes_unfinished() {
    let h = start(0, 16).await;
    let host = bound(&h, SecretKey::generate(), tunnel::ALPN).await;
    let host_key = host.public_key();
    let friend = bound(&h, SecretKey::generate(), tunnel::ALPN).await;
    let (_policy, rx) = watch::channel(Policy {
        grants: grants(friend.public_key(), &[]),
        ..Policy::default()
    });
    tokio::spawn(async move { tunnel::serve(&host, rx).await });

    let mut stranger = connect(&h, &SecretKey::generate()).await;
    for data in initials_nobody_finishes(&h, 64).await {
        send(
            &mut stranger,
            Frame::Send {
                dst: host_key,
                data,
            },
        )
        .await;
    }
    sync(&mut stranger).await;

    let conn = tunnel::dial(&friend, host_key)
        .await
        .expect("the granted key was refused");
    assert!(tunnel::list(&conn).await.unwrap().is_empty());
}
