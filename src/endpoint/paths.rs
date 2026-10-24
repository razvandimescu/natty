use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use log::debug;

use super::signal::{Nonce, MAX_CANDIDATES};
use super::socket::virtual_addr;
use crate::key::random;
use crate::wire::canonical;
use crate::PublicKey;

pub(crate) const TICK: Duration = Duration::from_millis(200);
const ACTIVE: Duration = Duration::from_secs(5);
const TRUST: Duration = Duration::from_secs(5);
const PUNCH: Duration = Duration::from_secs(3);
/// Openers lead the first probes by this much, so both sides' openers have
/// left before either side's probes arrive.
const OPENER_LEAD: Duration = Duration::from_millis(200);
const OFFER_RETRY: Duration = Duration::from_secs(1);
const REPLY_GAP: Duration = Duration::from_millis(500);
const INITIATE_GAP: Duration = Duration::from_secs(60);
const RESPOND_GAP: Duration = Duration::from_secs(10);
const PROBE_GAP: Duration = Duration::from_secs(1);
const KEEPALIVE: Duration = Duration::from_secs(25);
const PATH_TIMEOUT: Duration = Duration::from_secs(5);
/// Twice quinn's default idle timeout: a key silent this long has no open
/// connection left.
const PEER_IDLE: Duration = Duration::from_secs(60);
/// Keys cost nothing, so per-key gaps do not bound the probes sent to
/// addresses a peer names; this does.
const MAX_PUNCHES: usize = 8;
/// Keys that are not allowed get relay routing only; this bounds how many.
const MAX_UNALLOWED: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Offer {
        to: PublicKey,
        reply: bool,
    },
    Probe {
        to: SocketAddr,
        nonce: Nonce,
    },
    /// A probe sent with a TTL that expires past the local NAT: it opens the
    /// mapping toward `to` without landing early at the far NAT, which makes
    /// some NATs remap (docs/results.md, 2026-10-24).
    Open {
        to: SocketAddr,
        nonce: Nonce,
    },
}

/// Per-key path state shared by the virtual socket (which reads routes and
/// reports what it receives) and the traversal task (which runs punches and
/// upkeep). Timing is passed in, so the rules in docs/design.md are testable
/// without sockets.
#[derive(Debug, Default)]
pub(crate) struct Paths {
    peers: HashMap<SocketAddr, Peer>,
    /// Owner of every address in any peer's `proven`; the two always agree.
    proven: HashMap<SocketAddr, SocketAddr>,
    local: Vec<SocketAddr>,
    /// Keys that may learn our addresses and punch. Kept apart from `peers`,
    /// so forgetting a key's routing never forgets the application's decision.
    allowed: HashSet<PublicKey>,
}

#[derive(Debug)]
struct Peer {
    key: PublicKey,
    seen: Instant,
    candidates: Vec<SocketAddr>,
    proven: Vec<SocketAddr>,
    direct: Option<Direct>,
    nonce: Nonce,
    punch: Option<Punch>,
    punched: Option<Instant>,
    offered: Option<Instant>,
}

#[derive(Debug)]
struct Direct {
    addr: SocketAddr,
    heard: Instant,
    probed: Option<Instant>,
    unanswered: Option<Instant>,
}

#[derive(Debug)]
struct Punch {
    until: Instant,
    awaiting_answer: bool,
    next_offer: Instant,
    probe_from: Instant,
}

pub(crate) fn elapsed(since: Option<Instant>, now: Instant, gap: Duration) -> bool {
    since.is_none_or(|t| now.saturating_duration_since(t) >= gap)
}

/// Usable, unique, IPv6 first, at most MAX_CANDIDATES.
fn sanitize(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in addrs.into_iter().map(canonical) {
        if addr.port() != 0
            && !addr.ip().is_unspecified()
            && !addr.ip().is_multicast()
            && !out.contains(&addr)
        {
            out.push(addr);
        }
    }
    out.sort_by_key(|addr| addr.is_ipv4());
    out.truncate(MAX_CANDIDATES);
    out
}

impl Direct {
    fn trusted(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.heard) < TRUST
    }
}

impl Peer {
    fn hear(&mut self, from: SocketAddr, now: Instant) {
        if let Some(direct) = self.direct.as_mut().filter(|d| d.addr == from) {
            direct.heard = now;
            direct.unanswered = None;
        }
    }

    fn offer(&mut self, reply: bool, now: Instant, out: &mut Vec<Action>) {
        self.offered = Some(now);
        out.push(Action::Offer {
            to: self.key,
            reply,
        });
    }

    fn start_punch(&mut self, initiator: bool, now: Instant, out: &mut Vec<Action>) {
        debug!(
            "punch {}: start ({}), candidates {:?}, learned {:?}",
            self.key,
            if initiator { "initiator" } else { "responder" },
            self.candidates,
            self.proven
        );
        self.punch = Some(Punch {
            until: now + PUNCH,
            awaiting_answer: initiator,
            next_offer: now + OFFER_RETRY,
            probe_from: now + OPENER_LEAD,
        });
        self.punched = Some(now);
        self.offer(initiator, now, out);
        self.open(self.targets(), now, out);
    }

    /// Offered candidates, then addresses learned from probes, which outlive
    /// the offer they did not appear in.
    fn targets(&self) -> Vec<SocketAddr> {
        let learned = self.proven.iter().filter(|a| !self.candidates.contains(a));
        self.candidates.iter().chain(learned).copied().collect()
    }

    fn probe_candidates(&self, out: &mut Vec<Action>) {
        let nonce = self.nonce;
        out.extend(
            self.targets()
                .into_iter()
                .map(|to| Action::Probe { to, nonce }),
        );
    }

    /// Opens `addrs` during a punch and holds probing back until the openers
    /// have left.
    fn open(&mut self, addrs: Vec<SocketAddr>, now: Instant, out: &mut Vec<Action>) {
        let nonce = self.nonce;
        let Some(punch) = &mut self.punch else {
            return;
        };
        if addrs.is_empty() {
            return;
        }
        punch.probe_from = punch.probe_from.max(now + OPENER_LEAD);
        out.extend(addrs.into_iter().map(|to| Action::Open { to, nonce }));
    }

    fn knows(&self, addr: &SocketAddr) -> bool {
        self.candidates.contains(addr) || self.proven.contains(addr)
    }

    fn active(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.seen) < ACTIVE
    }

    fn wants_to_initiate(&self, now: Instant) -> bool {
        self.punch.is_none()
            && self.direct.is_none()
            && self.active(now)
            && elapsed(self.punched, now, INITIATE_GAP)
    }
}

impl Paths {
    fn has_room(&self) -> bool {
        self.peers.values().filter(|p| p.punch.is_some()).count() < MAX_PUNCHES
    }

    fn initiate(&mut self, addrs: Vec<SocketAddr>, now: Instant, out: &mut Vec<Action>) {
        for addr in addrs {
            if !self.has_room() {
                return;
            }
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.start_punch(true, now, out);
            }
        }
    }

    /// QUIC to or from `key` through the relay: the key is active. Only this
    /// starts tracking a key.
    pub(crate) fn touch(&mut self, key: PublicKey, now: Instant) -> SocketAddr {
        let addr = virtual_addr(&key);
        if !self.peers.contains_key(&addr) && !self.allowed.contains(&key) {
            self.make_room_for_unallowed();
        }
        let peer = self.peers.entry(addr).or_insert_with(|| Peer {
            key,
            seen: now,
            candidates: Vec::new(),
            proven: Vec::new(),
            direct: None,
            nonce: random(),
            punch: None,
            punched: None,
            offered: None,
        });
        peer.seen = now;
        addr
    }

    /// QUIC from a real address; `None` unless the address is proven.
    pub(crate) fn quic_from(&mut self, from: SocketAddr, now: Instant) -> Option<SocketAddr> {
        let addr = *self.proven.get(&from)?;
        let peer = self.peers.get_mut(&addr)?;
        peer.seen = now;
        peer.hear(from, now);
        Some(addr)
    }

    /// The key behind a virtual address and its direct path, if any, with
    /// whether the path is trusted.
    pub(crate) fn route(
        &self,
        addr: &SocketAddr,
        now: Instant,
    ) -> Option<(PublicKey, Option<(SocketAddr, bool)>)> {
        let peer = self.peers.get(addr)?;
        let direct = peer.direct.as_ref().map(|d| (d.addr, d.trusted(now)));
        Some((peer.key, direct))
    }

    /// Evicts the longest-silent key that is not allowed. Its relay
    /// connections lose their route until it sends again.
    fn make_room_for_unallowed(&mut self) {
        let unallowed = || {
            self.peers
                .iter()
                .filter(|(_, p)| !self.allowed.contains(&p.key))
        };
        if unallowed().count() < MAX_UNALLOWED {
            return;
        }
        if let Some(addr) = unallowed().min_by_key(|(_, p)| p.seen).map(|(a, _)| *a) {
            self.forget(&addr);
        }
    }

    fn forget(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.remove(addr) {
            for from in &peer.proven {
                self.proven.remove(from);
            }
        }
    }

    pub(crate) fn allows(&self, key: &PublicKey) -> bool {
        self.allowed.contains(key)
    }

    pub(crate) fn allow(&mut self, key: PublicKey) {
        self.allowed.insert(key);
    }

    /// Ends traversal toward `key` and drops its direct path; its traffic
    /// goes through the relay from the next datagram on.
    pub(crate) fn revoke(&mut self, key: &PublicKey) {
        self.allowed.remove(key);
        if let Some(peer) = self.peers.get_mut(&virtual_addr(key)) {
            for from in peer.proven.drain(..) {
                self.proven.remove(&from);
            }
            peer.candidates.clear();
            peer.direct = None;
            peer.punch = None;
            peer.punched = None;
        }
    }

    pub(crate) fn direct(&self, key: &PublicKey) -> Option<SocketAddr> {
        let peer = self.peers.get(&virtual_addr(key))?;
        peer.direct.as_ref().map(|direct| direct.addr)
    }

    pub(crate) fn local(&self) -> &[SocketAddr] {
        &self.local
    }

    pub(crate) fn set_local(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let addrs = sanitize(addrs);
        if addrs == self.local {
            return;
        }
        debug!("local candidates {addrs:?}");
        self.local = addrs;
        for peer in self.peers.values_mut() {
            if let Some(punch) = &peer.punch {
                let reply = punch.awaiting_answer;
                peer.offer(reply, now, out);
            }
        }
    }

    pub(crate) fn relay_connected(&mut self, now: Instant, out: &mut Vec<Action>) {
        let idle = self
            .peers
            .iter()
            .filter(|(_, p)| self.allowed.contains(&p.key) && p.active(now) && p.punch.is_none())
            .map(|(addr, _)| *addr)
            .collect();
        self.initiate(idle, now, out);
    }

    pub(crate) fn on_candidates(
        &mut self,
        key: PublicKey,
        reply: bool,
        addrs: Vec<SocketAddr>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let room = self.has_room();
        if !self.allowed.contains(&key) {
            return;
        }
        let Some(peer) = self.peers.get_mut(&virtual_addr(&key)) else {
            return;
        };
        let addrs = sanitize(addrs);
        let fresh = addrs
            .iter()
            .filter(|a| !peer.candidates.contains(a))
            .copied()
            .collect();
        peer.candidates = addrs;
        debug!("candidates from {key}: {:?}", peer.candidates);
        if let Some(punch) = &mut peer.punch {
            punch.awaiting_answer = false;
        } else if room && elapsed(peer.punched, now, RESPOND_GAP) {
            peer.start_punch(false, now, out);
            return;
        }
        peer.open(fresh, now, out);
        if reply && elapsed(peer.offered, now, REPLY_GAP) {
            peer.offer(false, now, out);
        }
    }

    /// A verified PROBE from `from`. The caller answers it with PROBE_ACK.
    pub(crate) fn on_probe(
        &mut self,
        key: PublicKey,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let addr = virtual_addr(&key);
        let room = self.has_room();
        if !self.allowed.contains(&key) {
            return;
        }
        let Some(peer) = self.peers.get_mut(&addr) else {
            return;
        };
        debug!(
            "probe from {key} at {from}{}",
            if peer.knows(&from) {
                ""
            } else {
                " (not a candidate it offered)"
            }
        );
        let respond = !peer.knows(&from)
            && peer.direct.is_none()
            && peer.punch.is_none()
            && elapsed(peer.punched, now, RESPOND_GAP);
        self.prove(addr, from);
        let Some(peer) = self.peers.get_mut(&addr) else {
            return;
        };
        peer.hear(from, now);
        if room && respond {
            peer.start_punch(false, now, out);
        }
    }

    /// A verified PROBE_ACK from `from`.
    pub(crate) fn on_ack(&mut self, key: PublicKey, from: SocketAddr, nonce: Nonce, now: Instant) {
        let addr = virtual_addr(&key);
        if !self.allowed.contains(&key) {
            return;
        }
        let Some(peer) = self.peers.get_mut(&addr) else {
            return;
        };
        if nonce != peer.nonce || !peer.knows(&from) {
            debug!(
                "ack from {key} at {from} ignored: {}",
                if nonce != peer.nonce {
                    "stale nonce"
                } else {
                    "unknown address"
                }
            );
            return;
        }
        peer.nonce = random();
        let switch = peer.direct.as_ref().is_none_or(|d| {
            d.addr != from && (!d.trusted(now) || (from.is_ipv6() && d.addr.is_ipv4()))
        });
        if switch {
            debug!("direct path to {key}: {from}");
            peer.direct = Some(Direct {
                addr: from,
                heard: now,
                probed: None,
                unanswered: None,
            });
        }
        peer.hear(from, now);
        self.prove(addr, from);
    }

    /// Records that `from` spoke for the peer at `addr`, keeping its newest
    /// few addresses. An address speaks for one peer at a time.
    fn prove(&mut self, addr: SocketAddr, from: SocketAddr) {
        let Some(peer) = self.peers.get_mut(&addr) else {
            return;
        };
        if !peer.proven.contains(&from) {
            if peer.proven.len() == MAX_CANDIDATES {
                self.proven.remove(&peer.proven.remove(0));
            }
            peer.proven.push(from);
        }
        if let Some(owner) = self.proven.insert(from, addr).filter(|o| *o != addr) {
            if let Some(previous) = self.peers.get_mut(&owner) {
                previous.proven.retain(|a| *a != from);
            }
        }
    }

    pub(crate) fn tick(&mut self, now: Instant, out: &mut Vec<Action>) {
        let (proven, allowed) = (&mut self.proven, &self.allowed);
        let mut initiating = Vec::new();
        self.peers.retain(|addr, peer| {
            let ipv6 = peer.direct.as_ref().is_some_and(|d| d.addr.is_ipv6());
            if ipv6 || peer.punch.as_ref().is_some_and(|p| now >= p.until) {
                let ended = peer.punch.take().is_some();
                if ended && peer.direct.is_none() {
                    debug!("punch {}: no answer, staying on the relay", peer.key);
                }
            }
            if peer.punch.is_none() && now.saturating_duration_since(peer.seen) >= PEER_IDLE {
                for from in &peer.proven {
                    proven.remove(from);
                }
                return false;
            }
            if allowed.contains(&peer.key) && peer.wants_to_initiate(now) {
                initiating.push(*addr);
            }
            upkeep(peer, now, out);
            true
        });
        self.initiate(initiating, now, out);
    }
}

fn upkeep(peer: &mut Peer, now: Instant, out: &mut Vec<Action>) {
    if let Some(punch) = &mut peer.punch {
        let probing = now >= punch.probe_from;
        if punch.awaiting_answer && now >= punch.next_offer {
            punch.next_offer = now + OFFER_RETRY;
            peer.offer(true, now, out);
        }
        if probing {
            peer.probe_candidates(out);
        }
    }

    let active = peer.active(now);
    let Some(direct) = &mut peer.direct else {
        return;
    };
    if direct
        .unanswered
        .is_some_and(|t| now.saturating_duration_since(t) >= PATH_TIMEOUT)
    {
        debug!("direct path to {} via {} lost", peer.key, direct.addr);
        peer.direct = None;
        peer.punched = None;
        return;
    }
    let silent = now.saturating_duration_since(direct.heard);
    let due = silent >= KEEPALIVE || (!direct.trusted(now) && active);
    if due && peer.punch.is_none() && elapsed(direct.probed, now, PROBE_GAP) {
        direct.probed = Some(now);
        direct.unanswered.get_or_insert(now);
        out.push(Action::Probe {
            to: direct.addr,
            nonce: peer.nonce,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn probes(out: &[Action]) -> Vec<SocketAddr> {
        out.iter()
            .filter_map(|a| match a {
                Action::Probe { to, .. } => Some(*to),
                _ => None,
            })
            .collect()
    }

    fn openers(out: &[Action]) -> Vec<SocketAddr> {
        out.iter()
            .filter_map(|a| match a {
                Action::Open { to, .. } => Some(*to),
                _ => None,
            })
            .collect()
    }

    fn nonce_for(out: &[Action], target: SocketAddr) -> Nonce {
        out.iter()
            .find_map(|a| match a {
                Action::Probe { to, nonce } if *to == target => Some(*nonce),
                _ => None,
            })
            .expect("probe sent")
    }

    fn offers(out: &[Action]) -> Vec<bool> {
        out.iter()
            .filter_map(|a| match a {
                Action::Offer { reply, .. } => Some(*reply),
                _ => None,
            })
            .collect()
    }

    fn allowed(paths: &mut Paths, key: PublicKey, now: Instant) -> SocketAddr {
        paths.allow(key);
        paths.touch(key, now)
    }

    /// A dialed peer whose candidates `v4` and `v6` arrived; returns the nonce.
    fn punching(paths: &mut Paths, key: PublicKey, now: Instant) -> Nonce {
        let (v4, v6) = (addr("198.51.100.1:1000"), addr("[2001:db8::1]:1000"));
        let virt = allowed(paths, key, now);
        let mut out = Vec::new();
        paths.tick(now, &mut out);
        assert_eq!(offers(&out), [true]);
        out.clear();
        paths.on_candidates(key, false, vec![v4, v6], now, &mut out);
        assert!(offers(&out).is_empty(), "an answer is not answered");
        assert_eq!(openers(&out), [v6, v4]);
        assert!(probes(&out).is_empty(), "probes wait for the openers");
        assert_eq!(paths.route(&virt, now), Some((key, None)));
        paths.tick(now + TICK, &mut out);
        assert_eq!(probes(&out), [v6, v4]);
        nonce_for(&out, v4)
    }

    #[test]
    fn acknowledged_probe_becomes_the_trusted_path() {
        let mut paths = Paths::default();
        let key = PublicKey([1; 32]);
        let now = Instant::now();
        let nonce = punching(&mut paths, key, now);
        let v4 = addr("198.51.100.1:1000");

        paths.on_ack(key, addr("203.0.113.9:1000"), nonce, now);
        assert_eq!(paths.direct(&key), None, "ACK from a non-candidate");

        paths.on_ack(key, v4, nonce, now);
        assert_eq!(paths.direct(&key), Some(v4));
        assert_eq!(paths.quic_from(v4, now), Some(virtual_addr(&key)));
        assert_eq!(paths.quic_from(addr("203.0.113.9:1000"), now), None);

        let v6 = addr("[2001:db8::1]:1000");
        paths.on_ack(key, v6, nonce, now);
        assert_eq!(paths.direct(&key), Some(v4), "a used nonce counts once");
    }

    #[test]
    fn ipv6_replaces_a_trusted_ipv4_path_and_ends_the_punch() {
        let mut paths = Paths::default();
        let key = PublicKey([2; 32]);
        let now = Instant::now();
        let nonce = punching(&mut paths, key, now);
        paths.on_ack(key, addr("198.51.100.1:1000"), nonce, now);

        let mut out = Vec::new();
        paths.tick(now + TICK * 2, &mut out);
        let v6 = addr("[2001:db8::1]:1000");
        paths.on_ack(key, v6, nonce_for(&out, v6), now + TICK * 2);
        assert_eq!(paths.direct(&key), Some(v6));

        out.clear();
        paths.tick(now + TICK * 3, &mut out);
        assert!(out.is_empty(), "punch continued: {out:?}");
    }

    #[test]
    fn silent_path_becomes_untrusted_then_is_dropped() {
        let mut paths = Paths::default();
        let key = PublicKey([3; 32]);
        let start = Instant::now();
        let nonce = punching(&mut paths, key, start);
        let v4 = addr("198.51.100.1:1000");
        paths.on_ack(key, v4, nonce, start);
        let virt = virtual_addr(&key);

        let mut out = Vec::new();
        let mut now = start;
        while paths.route(&virt, now).unwrap().1.is_some_and(|(_, t)| t) {
            now += TICK;
            paths.touch(key, now);
            paths.tick(now, &mut out);
        }
        assert!(now - start >= TRUST);
        assert_eq!(paths.route(&virt, now), Some((key, Some((v4, false)))));
        assert_eq!(
            paths.direct(&key),
            Some(v4),
            "datagrams still go to an untrusted path"
        );

        out.clear();
        while paths.route(&virt, now).unwrap().1.is_some() {
            now += TICK;
            paths.touch(key, now);
            paths.tick(now, &mut out);
        }
        assert_eq!(
            probes(&out),
            [v4; 4],
            "one probe a second until the timeout"
        );
        assert_eq!(paths.direct(&key), None);

        out.clear();
        paths.tick(now + TICK, &mut out);
        assert_eq!(offers(&out), [true], "a dropped path punches again at once");
    }

    #[test]
    fn answered_probe_keeps_the_path() {
        let mut paths = Paths::default();
        let key = PublicKey([4; 32]);
        let start = Instant::now();
        let nonce = punching(&mut paths, key, start);
        let v4 = addr("198.51.100.1:1000");
        paths.on_ack(key, v4, nonce, start);

        let mut out = Vec::new();
        let mut now = start;
        for _ in 0..200 {
            now += TICK;
            out.clear();
            paths.tick(now, &mut out);
            if out
                .iter()
                .any(|a| matches!(a, Action::Probe { to, .. } if *to == v4))
            {
                paths.on_ack(key, v4, nonce_for(&out, v4), now);
            }
            assert_eq!(
                paths.route(&virtual_addr(&key), now).unwrap().1.unwrap().0,
                v4
            );
        }
    }

    #[test]
    fn probe_from_an_unknown_source_is_answered_and_probed_back() {
        let mut paths = Paths::default();
        let key = PublicKey([5; 32]);
        let now = Instant::now();
        let mut out = Vec::new();
        allowed(&mut paths, key, now);
        paths.on_candidates(key, true, vec![], now, &mut out);
        assert_eq!(offers(&out), [false]);

        out.clear();
        let reflexive = addr("198.51.100.7:4000");
        paths.on_probe(key, reflexive, now + TICK, &mut out);
        assert_eq!(paths.quic_from(reflexive, now), Some(virtual_addr(&key)));
        out.clear();
        paths.tick(now + TICK * 2, &mut out);
        assert_eq!(probes(&out), [reflexive]);
    }

    #[test]
    fn new_candidates_keep_the_addresses_probes_came_from() {
        let mut paths = Paths::default();
        let key = PublicKey([7; 32]);
        let now = Instant::now();
        let nonce = punching(&mut paths, key, now);
        let learned = addr("203.0.113.5:7000");
        let mut out = Vec::new();
        paths.on_probe(key, learned, now, &mut out);
        paths.on_ack(key, learned, nonce, now);
        assert_eq!(paths.direct(&key), Some(learned));

        paths.on_candidates(key, true, vec![addr("198.51.100.1:1000")], now, &mut out);
        let later = now + KEEPALIVE;
        out.clear();
        paths.tick(later, &mut out);
        assert_eq!(probes(&out), [learned], "keepalive");
        paths.on_ack(key, learned, nonce_for(&out, learned), later);
        paths.tick(later + PATH_TIMEOUT, &mut out);
        assert_eq!(
            paths
                .route(&virtual_addr(&key), later + PATH_TIMEOUT)
                .unwrap()
                .1,
            Some((learned, false)),
            "an answered keepalive keeps the path"
        );
    }

    #[test]
    fn unallowed_key_is_routed_through_the_relay_and_nothing_else() {
        let mut paths = Paths::default();
        let key = PublicKey([8; 32]);
        let now = Instant::now();
        let mut out = Vec::new();
        let virt = paths.touch(key, now);
        assert_eq!(paths.route(&virt, now), Some((key, None)));

        paths.tick(now, &mut out);
        paths.relay_connected(now, &mut out);
        let named = addr("198.51.100.9:9");
        paths.on_candidates(key, true, vec![named], now, &mut out);
        paths.on_probe(key, named, now, &mut out);
        paths.on_ack(key, named, paths.peers[&virt].nonce, now);
        paths.tick(now + TICK, &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(paths.quic_from(named, now), None);
        assert_eq!(paths.direct(&key), None);
    }

    #[test]
    fn allowing_an_active_key_starts_a_punch() {
        let mut paths = Paths::default();
        let key = PublicKey([11; 32]);
        let now = Instant::now();
        let mut out = Vec::new();
        paths.touch(key, now);
        paths.tick(now, &mut out);
        assert!(out.is_empty(), "{out:?}");

        paths.allow(key);
        paths.tick(now + TICK, &mut out);
        assert_eq!(offers(&out), [true]);
    }

    #[test]
    fn revoke_ends_traversal_and_the_direct_path() {
        let mut paths = Paths::default();
        let key = PublicKey([12; 32]);
        let now = Instant::now();
        let nonce = punching(&mut paths, key, now);
        let v4 = addr("198.51.100.1:1000");
        paths.on_ack(key, v4, nonce, now);
        assert_eq!(paths.direct(&key), Some(v4));

        paths.revoke(&key);
        let virt = paths.touch(key, now);
        assert_eq!(paths.route(&virt, now), Some((key, None)));
        assert_eq!(paths.quic_from(v4, now), None);
        let mut out = Vec::new();
        paths.tick(now + TICK, &mut out);
        paths.on_probe(key, v4, now + TICK, &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn unknown_key_churn_stays_bounded_and_keeps_allows() {
        let mut paths = Paths::default();
        let (friend, preloaded) = (PublicKey([13; 32]), PublicKey([14; 32]));
        let start = Instant::now();
        allowed(&mut paths, friend, start);
        paths.allow(preloaded);

        let mut now = start;
        for i in 0..2 * MAX_UNALLOWED as u32 {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            now += Duration::from_millis(1);
            paths.touch(PublicKey(key), now);
            paths.touch(friend, now);
        }
        assert_eq!(paths.peers.len(), MAX_UNALLOWED + 1);
        assert!(paths.peers.contains_key(&virtual_addr(&friend)));

        paths.touch(preloaded, now);
        let mut out = Vec::new();
        paths.tick(now, &mut out);
        assert_eq!(offers(&out), [true, true]);
    }

    #[test]
    fn punches_wait_for_room() {
        let mut paths = Paths::default();
        let now = Instant::now();
        let keys: Vec<PublicKey> = (0..=MAX_PUNCHES as u8)
            .map(|i| PublicKey([100 + i; 32]))
            .collect();
        for key in &keys {
            allowed(&mut paths, *key, now);
        }
        let mut out = Vec::new();
        paths.tick(now, &mut out);
        assert_eq!(offers(&out).len(), MAX_PUNCHES);

        let waiting = keys
            .iter()
            .find(|key| paths.peers[&virtual_addr(key)].punch.is_none())
            .copied()
            .unwrap();
        out.clear();
        paths.on_candidates(waiting, true, vec![addr("198.51.100.9:9")], now, &mut out);
        assert_eq!(offers(&out), [false], "answered, not probed");
        assert!(probes(&out).is_empty());

        out.clear();
        paths.tick(now + PUNCH, &mut out);
        assert_eq!(openers(&out), [addr("198.51.100.9:9")]);
        paths.tick(now + PUNCH + OPENER_LEAD, &mut out);
        assert!(probes(&out).contains(&addr("198.51.100.9:9")));
    }

    #[test]
    fn a_responder_opens_before_it_probes() {
        let mut paths = Paths::default();
        let key = PublicKey([15; 32]);
        let now = Instant::now();
        let v4 = addr("198.51.100.1:1000");
        allowed(&mut paths, key, now);
        let mut out = Vec::new();
        paths.on_candidates(key, true, vec![v4], now, &mut out);
        assert_eq!(offers(&out), [false]);
        assert_eq!(openers(&out), [v4]);
        assert!(probes(&out).is_empty());

        out.clear();
        paths.tick(now + OPENER_LEAD - Duration::from_millis(1), &mut out);
        assert!(probes(&out).is_empty(), "{out:?}");
        paths.tick(now + OPENER_LEAD, &mut out);
        assert_eq!(probes(&out), [v4]);
    }

    #[test]
    fn an_address_speaks_for_one_key() {
        let mut paths = Paths::default();
        let (a, b) = (PublicKey([9; 32]), PublicKey([10; 32]));
        let now = Instant::now();
        let mut out = Vec::new();
        let shared = addr("198.51.100.10:5000");
        for key in [a, b] {
            allowed(&mut paths, key, now);
            paths.on_probe(key, shared, now, &mut out);
        }
        for port in 1..=MAX_CANDIDATES as u16 {
            let from = SocketAddr::new(addr("203.0.113.1:1").ip(), port);
            paths.on_probe(a, from, now, &mut out);
        }
        assert_eq!(paths.quic_from(shared, now), Some(virtual_addr(&b)));
    }

    #[test]
    fn idle_peers_are_forgotten_with_their_addresses() {
        let mut paths = Paths::default();
        let key = PublicKey([6; 32]);
        let now = Instant::now();
        let mut out = Vec::new();
        allowed(&mut paths, key, now);
        paths.on_candidates(key, false, vec![], now, &mut out);
        let from = addr("198.51.100.8:4000");
        paths.on_probe(key, from, now, &mut out);
        assert_eq!(paths.quic_from(from, now), Some(virtual_addr(&key)));

        paths.tick(now + PEER_IDLE, &mut out);
        assert!(!paths.peers.contains_key(&virtual_addr(&key)));
        assert_eq!(paths.quic_from(from, now + PEER_IDLE), None);
        assert!(paths.allows(&key), "forgetting routing keeps the allow");
    }
}
