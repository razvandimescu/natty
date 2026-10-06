use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
                let candidates = self.candidates(stun);
                self.paths
                    .lock()
                    .unwrap()
                    .set_local(candidates, now, actions);
            }
            Packet::UdpPunch(from, data) => {
                // Checked before answering, so a key that is not allowed never
                // hears from this socket; noise costs a lookup, not a signature.
                let sender = signal::sender(&data);
                if !sender.is_some_and(|key| self.paths.lock().unwrap().allows(&key)) {
                    return;
                }
                match Message::open(&data) {
                    Some((key, Message::Probe(nonce))) => {
                        let ack = Message::ProbeAck {
                            nonce,
                            observed: from,
                        };
                        self.udp.send_to(&ack.seal(&self.secret), from);
                        let mut paths = self.paths.lock().unwrap();
                        paths.on_probe(key, from, now, actions);
                    }
                    Some((key, Message::ProbeAck { nonce, .. })) => {
                        let mut paths = self.paths.lock().unwrap();
                        paths.on_ack(key, from, nonce, now);
                    }
                    _ => {}
                }
            }
            Packet::RelayPunch(data) => {
                if let Some((key, Message::Candidates { reply, addrs })) = Message::open(&data) {
                    let mut paths = self.paths.lock().unwrap();
                    paths.on_candidates(key, reply, addrs, now, actions);
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
                Action::Offer { to, reply } => {
                    let message = Message::Candidates {
                        reply,
                        addrs: local.clone(),
                    };
                    let data = message.seal(&self.secret);
                    let _ = self.relay.try_send(Frame::Send { dst: to, data });
                }
                Action::Probe { to, nonce } => {
                    let (_, probe) = match &mut sealed {
                        Some(cached) if cached.0 == nonce => cached,
                        slot => slot.insert((nonce, Message::Probe(nonce).seal(&self.secret))),
                    };
                    self.udp.send_to(probe, to);
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
