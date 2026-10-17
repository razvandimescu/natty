mod net;
mod paths;
mod peer_tls;
mod session;
mod signal;
mod socket;
mod traversal;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::ClientConfig;

pub use peer_tls::peer_key;

use crate::client::RelayAddr;
use crate::wire::Welcome;
use crate::{PublicKey, SecretKey};
use net::Udp;
use paths::Paths;
use peer_tls::PeerTls;
use session::Relay;
use socket::{virtual_addr, VirtualSocket};
use traversal::Traversal;

const QUEUE: usize = 1024;

/// A QUIC endpoint addressed by key, reachable through one relay and, once a
/// punch succeeds, directly over UDP.
pub struct Endpoint {
    quic: quinn::Endpoint,
    socket: Arc<VirtualSocket>,
    tls: PeerTls,
    key: PublicKey,
    relay_state: watch::Receiver<Option<Welcome>>,
    tasks: [JoinHandle<()>; 2],
}

impl Endpoint {
    /// Starts the relay session in the background and returns at once; the
    /// session reconnects on its own. Must run inside a Tokio runtime.
    /// `relay` is `host[:port]`; `relay_tls` verifies the relay's certificate.
    pub fn bind(
        secret: SecretKey,
        relay: &str,
        relay_tls: Arc<ClientConfig>,
        alpn: &[&[u8]],
    ) -> io::Result<Self> {
        let addr = RelayAddr::parse(relay)?;
        let key = secret.public();
        let tls = PeerTls::new(&secret, alpn)?;
        let udp = Arc::new(Udp::bind()?);
        let paths = Arc::new(Mutex::new(Paths::default()));
        let (outbound_tx, outbound_rx) = mpsc::channel(QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel(QUEUE);
        let (signals_tx, signals_rx) = mpsc::channel(QUEUE);
        let (state_tx, relay_state) = watch::channel(None);
        let socket = Arc::new(VirtualSocket {
            local: virtual_addr(&key),
            relay: outbound_tx.clone(),
            inbound: Mutex::new(inbound_rx),
            udp: udp.clone(),
            paths: paths.clone(),
            signals: signals_tx,
        });
        let mut config = quinn::EndpointConfig::default();
        // Keeps the fixed bit set on every QUIC packet, so punch messages and
        // STUN can be told apart by their first byte.
        config.grease_quic_bit(false);
        let quic = quinn::Endpoint::new_with_abstract_socket(
            config,
            Some(tls.server_config()?),
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        let traversal = Traversal {
            secret: SecretKey::from_seed(*secret.seed()),
            relay_host: addr.host.clone(),
            udp,
            relay: outbound_tx.clone(),
            paths,
        };
        let relay = Relay {
            tls: relay_tls,
            addr,
            key: secret,
        };
        let tasks = [
            tokio::spawn(traversal::run(traversal, signals_rx, relay_state.clone())),
            tokio::spawn(session::run(
                relay,
                outbound_rx,
                outbound_tx,
                inbound_tx,
                state_tx,
            )),
        ];
        Ok(Self {
            quic,
            socket,
            tls,
            key,
            relay_state,
            tasks,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.key
    }

    /// `Some` while a relay session is up, carrying that session's WELCOME.
    pub fn relay_state(&self) -> watch::Receiver<Option<Welcome>> {
        self.relay_state.clone()
    }

    /// The peer's direct UDP address while that path is trusted; `None` while
    /// datagrams to the peer go through the relay.
    pub fn direct_addr(&self, peer: &PublicKey) -> Option<SocketAddr> {
        self.socket
            .paths
            .lock()
            .unwrap()
            .direct(peer, Instant::now())
    }

    /// Lets `peer` learn this endpoint's addresses and try a direct path, now
    /// or whenever it next sends. Without it a peer still connects, through
    /// the relay only. Dialing allows the dialed key.
    pub fn allow(&self, peer: PublicKey) {
        self.socket.paths.lock().unwrap().allow(peer);
    }

    /// Withdraws [`allow`](Self::allow): punching stops and the direct path is
    /// dropped, so open connections continue through the relay. Addresses the
    /// peer already learned stay learned.
    pub fn revoke(&self, peer: &PublicKey) {
        self.socket.paths.lock().unwrap().revoke(peer);
    }

    /// Dials `peer` through the relay, and directly once a punch succeeds.
    /// The handshake fails unless the other side proves it holds `peer`.
    pub async fn connect(&self, peer: PublicKey) -> io::Result<quinn::Connection> {
        let addr = {
            let mut paths = self.socket.paths.lock().unwrap();
            paths.allow(peer);
            paths.touch(peer, Instant::now())
        };
        let config = self.tls.client_config(peer)?;
        self.quic
            .connect_with(config, addr, &peer.to_string())
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)
    }

    /// The next inbound connection attempt. Await it to finish the handshake,
    /// then read the dialer's key with [`peer_key`].
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.quic.accept().await
    }

    /// Closes every connection and waits until the peers have been told, so
    /// the process can exit right after. A process that exits without it
    /// leaves its peers to wait out the idle timeout.
    pub async fn close(&self) {
        self.quic.close(0u32.into(), b"");
        self.quic.wait_idle().await;
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
