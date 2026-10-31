use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, trace};
use tokio::net::lookup_host;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout};

use super::net::Udp;
use super::paths::{elapsed, Action, Paths, TICK};
use super::signal::{self, Message, Nonce};
use super::socket::Packet;
use crate::key::random;
use crate::wire::{Frame, Welcome};
use crate::{stun, SecretKey};

const STUN_REFRESH: Duration = Duration::from_secs(30);
const STUN_ATTEMPTS: u32 = 3;
const STUN_RETRY: Duration = Duration::from_millis(500);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
/// Past a NAT on the first hop, short of a peer many hops away.
const OPENER_TTL: u32 = 2;

pub(crate) struct Traversal {
    pub secret: SecretKey,
    pub relay_host: String,
    pub udp: Arc<Udp>,
    pub relay: mpsc::Sender<Frame>,
    pub paths: Arc<Mutex<Paths>>,
}

#[derive(Default)]
struct Stun {
    txid: [u8; 12],
    port: u16,
    refreshed: Option<Instant>,
    /// The latest mapped address per family, IPv6 first.
    reflexive: [Option<SocketAddr>; 2],
    round: Option<JoinHandle<()>>,
}

/// Runs punches and path upkeep for the life of the endpoint: timers from
/// `Paths::tick`, punch messages and STUN responses from the virtual socket,
/// and relay session changes, which refresh candidates and punch again.
pub(crate) async fn run(
    t: Traversal,
    mut packets: mpsc::Receiver<Packet>,
    mut relay_state: watch::Receiver<Option<Welcome>>,
) {
    let mut stun = Stun::default();
    let mut tick = interval(TICK);
    let mut actions = Vec::new();
    loop {
        tokio::select! {
            _ = tick.tick() => t.paths.lock().unwrap().tick(Instant::now(), &mut actions),
            Some(packet) = packets.recv() => t.handle(packet, &mut stun, &mut actions),
            changed = relay_state.changed() => {
                if changed.is_err() {
                    return;
                }
                let Some(welcome) = *relay_state.borrow_and_update() else {
                    continue;
                };
                stun.port = welcome.stun_port;
                stun.reflexive = [None; 2];
                t.refresh_stun(&mut stun);
                let candidates = t.candidates(&stun);
                let now = Instant::now();
                let mut paths = t.paths.lock().unwrap();
                paths.set_local(candidates, now, &mut actions);
                paths.relay_connected(now, &mut actions);
            }
        }
        if actions.iter().any(|a| matches!(a, Action::Offer { .. }))
            && elapsed(stun.refreshed, Instant::now(), STUN_REFRESH)
        {
            t.refresh_stun(&mut stun);
        }
        t.perform(&mut actions);
    }
}

impl Traversal {
    fn handle(&self, packet: Packet, stun: &mut Stun, actions: &mut Vec<Action>) {
        let now = Instant::now();
        match packet {
            Packet::Stun(data) => {
                let Some(mapped) = stun::mapped_address(&data, &stun.txid) else {
                    return;
                };
                let slot = &mut stun.reflexive[usize::from(mapped.is_ipv4())];
                if slot.replace(mapped) == Some(mapped) {
                    return;
                }
                debug!("stun: mapped {mapped}");
                let candidates = self.candidates(stun);
                self.paths
                    .lock()
                    .unwrap()
                    .set_local(candidates, now, actions);
            }
            Packet::UdpPunch(from, data) => {
                // Looked up before the signature is checked, so a key that is
                // not allowed never hears from this socket; noise costs a
                // lookup, not a signature.
                let owner = signal::signer(&data)
                    .and_then(|signer| self.paths.lock().unwrap().owner(&signer));
                let Some((key, mine)) = owner else {
                    return;
                };
                match Message::open(&data) {
                    Some((_, Message::Probe(nonce))) => {
                        let ack = Message::ProbeAck(nonce).seal(&mine.secret());
                        self.udp.send_to(&ack, from);
                        let mut paths = self.paths.lock().unwrap();
                        paths.on_probe(key, from, now, actions);
                    }
                    Some((_, Message::ProbeAck(nonce))) => {
                        let mut paths = self.paths.lock().unwrap();
                        paths.on_ack(key, from, nonce, now);
                    }
                    _ => {}
                }
            }
            Packet::RelayPunch(data) => {
                if let Some((
                    key,
                    Message::Candidates {
                        reply,
                        probe_key,
                        addrs,
                    },
                )) = Message::open(&data)
                {
                    let mut paths = self.paths.lock().unwrap();
                    paths.on_candidates(key, probe_key, reply, addrs, now, actions);
                }
            }
        }
    }

    fn perform(&self, actions: &mut Vec<Action>) {
        if actions.is_empty() {
            return;
        }
        let mut sealed: Option<(Nonce, Vec<u8>)> = None;
        let local = self.paths.lock().unwrap().local().to_vec();
        for action in actions.drain(..) {
            match action {
                Action::Offer { to, reply, mine } => {
                    let message = Message::Candidates {
                        reply,
                        probe_key: mine.public,
                        addrs: local.clone(),
                    };
                    let data = message.seal(&self.secret);
                    trace!("candidates to {to}: {local:?}");
                    let _ = self.relay.try_send(Frame::Send { dst: to, data });
                }
                Action::Probe { to, nonce, mine } | Action::Open { to, nonce, mine } => {
                    let (_, probe) = match &mut sealed {
                        Some(cached) if cached.0 == nonce => cached,
                        slot => slot.insert((nonce, Message::Probe(nonce).seal(&mine.secret()))),
                    };
                    if matches!(action, Action::Open { .. }) {
                        trace!("opener to {to}");
                        self.udp.send_with_ttl(probe, to, OPENER_TTL);
                    } else {
                        trace!("probe to {to}");
                        self.udp.send_to(probe, to);
                    }
                }
            }
        }
    }

    fn candidates(&self, stun: &Stun) -> Vec<SocketAddr> {
        let mut candidates = self.udp.local_candidates();
        candidates.extend(stun.reflexive.iter().flatten());
        candidates
    }

    fn refresh_stun(&self, stun: &mut Stun) {
        if stun.port == 0 {
            return;
        }
        stun.txid = random();
        stun.refreshed = Some(Instant::now());
        if let Some(round) = stun.round.take() {
            round.abort();
        }
        let (udp, host, port) = (self.udp.clone(), self.relay_host.clone(), stun.port);
        let request = stun::binding_request(&stun.txid);
        stun.round = Some(tokio::spawn(async move {
            let Ok(Ok(addrs)) = timeout(RESOLVE_TIMEOUT, lookup_host((host, port))).await else {
                return;
            };
            let addrs: Vec<SocketAddr> = addrs.collect();
            let targets = [
                addrs.iter().find(|a| a.is_ipv6()),
                addrs.iter().find(|a| a.is_ipv4()),
            ];
            for _ in 0..STUN_ATTEMPTS {
                for target in targets.iter().flatten() {
                    udp.send_to(&request, **target);
                }
                sleep(STUN_RETRY).await;
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use super::signal::ProbeKey;
    use super::*;

    fn names(packet: &[u8], key: &crate::PublicKey) -> bool {
        packet.windows(key.0.len()).any(|w| w == key.0)
    }

    async fn next(socket: &UdpSocket) -> Vec<u8> {
        let mut buf = [0; 1500];
        let n = timeout(Duration::from_secs(1), socket.recv(&mut buf))
            .await
            .expect("a datagram")
            .unwrap();
        buf[..n].to_vec()
    }

    #[tokio::test]
    async fn punch_datagrams_name_neither_key() {
        let (ours, peer) = (SecretKey::generate(), SecretKey::generate());
        let (us, them) = (ours.public(), peer.public());
        let wire = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = wire.local_addr().unwrap();
        let (relay, _relayed) = mpsc::channel(8);
        let t = Traversal {
            secret: ours,
            relay_host: String::new(),
            udp: Arc::new(Udp::bind().unwrap()),
            relay,
            paths: Arc::default(),
        };
        for socket in t.udp.sockets() {
            socket.writable().await.unwrap();
        }
        {
            let mut paths = t.paths.lock().unwrap();
            paths.allow(them);
            paths.touch(them, Instant::now());
        }
        let (mut stun, mut actions) = (Stun::default(), Vec::new());
        let probe_key = ProbeKey::random();
        let offer = Message::Candidates {
            reply: true,
            probe_key: probe_key.public,
            addrs: vec![from],
        };
        t.handle(
            Packet::RelayPunch(offer.seal(&peer)),
            &mut stun,
            &mut actions,
        );
        t.perform(&mut actions);
        let opener = next(&wire).await;

        let probe = Message::Probe([9; 12]).seal(&probe_key.secret());
        t.handle(Packet::UdpPunch(from, probe), &mut stun, &mut actions);
        let ack = next(&wire).await;

        assert!(matches!(
            Message::open(&opener),
            Some((_, Message::Probe(_)))
        ));
        let answer = Message::open(&ack).map(|(_, message)| message);
        assert_eq!(answer, Some(Message::ProbeAck([9; 12])));
        for packet in [opener, ack] {
            assert!(!names(&packet, &us), "{packet:?}");
            assert!(!names(&packet, &them), "{packet:?}");
        }
    }
}
