use std::fmt;
use std::net::SocketAddr;

use crate::key::random;
use crate::wire::{put_addr, split_addr};
use crate::{PublicKey, SecretKey};

/// Starts below 0x40, where no ungreased QUIC packet and no STUN response do.
const MAGIC: [u8; 4] = *b"*nty";
pub(crate) const MAX_CANDIDATES: usize = 8;
const CONTEXT: &[u8] = b"natty punch v2\0";
const CANDIDATES: u8 = 1;
const PROBE: u8 = 2;
const PROBE_ACK: u8 = 3;
const HEADER: usize = 4 + 1 + 32;
const SIGNATURE: usize = 64;

pub(crate) type Nonce = [u8; 12];

/// Made for one peer at every punch and sent to it in CANDIDATES. PROBE and
/// PROBE_ACK are signed with it, so they carry neither endpoint's key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeKey {
    seed: [u8; 32],
    pub public: PublicKey,
}

impl ProbeKey {
    pub(crate) fn random() -> Self {
        let seed = random();
        Self {
            seed,
            public: SecretKey::from_seed(seed).public(),
        }
    }

    pub(crate) fn secret(&self) -> SecretKey {
        SecretKey::from_seed(self.seed)
    }
}

impl fmt::Debug for ProbeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProbeKey({})", self.public)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    Candidates {
        reply: bool,
        probe_key: PublicKey,
        addrs: Vec<SocketAddr>,
    },
    Probe(Nonce),
    ProbeAck(Nonce),
}

pub(crate) fn is_signal(packet: &[u8]) -> bool {
    packet.starts_with(&MAGIC)
}

/// The claimed signer, before any signature check.
pub(crate) fn signer(packet: &[u8]) -> Option<PublicKey> {
    let key = packet.get(5..HEADER)?;
    Some(PublicKey(key.try_into().ok()?))
}

impl Message {
    pub(crate) fn seal(&self, secret: &SecretKey) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER + 192 + SIGNATURE);
        buf.extend_from_slice(&MAGIC);
        buf.push(0);
        buf.extend_from_slice(&secret.public().0);
        buf[4] = match self {
            Message::Candidates {
                reply,
                probe_key,
                addrs,
            } => {
                buf.push(u8::from(*reply));
                buf.extend_from_slice(&probe_key.0);
                for addr in addrs {
                    put_addr(&mut buf, *addr);
                }
                CANDIDATES
            }
            Message::Probe(nonce) => {
                buf.extend_from_slice(nonce);
                PROBE
            }
            Message::ProbeAck(nonce) => {
                buf.extend_from_slice(nonce);
                PROBE_ACK
            }
        };
        let sig = secret.sign(&[CONTEXT, &buf].concat());
        buf.extend_from_slice(&sig);
        buf
    }

    /// The signer and message, only if the signature holds.
    pub(crate) fn open(packet: &[u8]) -> Option<(PublicKey, Message)> {
        if packet.len() < HEADER + SIGNATURE {
            return None;
        }
        let (signed, sig) = packet.split_at(packet.len() - SIGNATURE);
        let key = signer(packet)?;
        if !key.verify(&[CONTEXT, signed].concat(), sig) {
            return None;
        }
        Some((key, Self::decode(signed[4], &signed[HEADER..])?))
    }

    fn decode(ty: u8, body: &[u8]) -> Option<Message> {
        Some(match ty {
            CANDIDATES => {
                let (&reply, rest) = body.split_first()?;
                let (probe_key, mut rest) = rest.split_first_chunk()?;
                let mut addrs = Vec::new();
                while !rest.is_empty() && addrs.len() < MAX_CANDIDATES {
                    let (addr, tail) = split_addr(rest).ok()?;
                    addrs.push(addr);
                    rest = tail;
                }
                Message::Candidates {
                    reply: reply == 1,
                    probe_key: PublicKey(*probe_key),
                    addrs,
                }
            }
            PROBE => Message::Probe(*body.first_chunk()?),
            PROBE_ACK => Message::ProbeAck(*body.first_chunk()?),
            _ => return None,
        })
    }
}

/// A peer signs with a key of its own choice, so `decode` sees any bytes behind
/// a valid signature.
#[cfg(fuzzing)]
pub fn fuzz_signal(data: &[u8]) {
    let _ = Message::open(data);
    let Some((&ty, body)) = data.split_first() else {
        return;
    };
    if let Some(message) = Message::decode(ty, body) {
        let secret = SecretKey::from_seed([7; 32]);
        let packet = message.seal(&secret);
        assert_eq!(Message::open(&packet), Some((secret.public(), message)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_roundtrip_with_their_signer() {
        let secret = SecretKey::generate();
        for message in [
            Message::Candidates {
                reply: true,
                probe_key: ProbeKey::random().public,
                addrs: vec![
                    "[2001:db8::1]:40000".parse().unwrap(),
                    "198.51.100.4:9".parse().unwrap(),
                ],
            },
            Message::Probe([7; 12]),
            Message::ProbeAck([7; 12]),
        ] {
            let packet = message.seal(&secret);
            assert!(is_signal(&packet));
            assert_eq!(signer(&packet), Some(secret.public()));
            assert_eq!(Message::open(&packet), Some((secret.public(), message)));
        }
    }

    #[test]
    fn rejects_tampering_and_forged_senders() {
        let secret = SecretKey::generate();
        let mut packet = Message::Probe([1; 12]).seal(&secret);
        packet[HEADER] ^= 1;
        assert_eq!(Message::open(&packet), None);

        let mut forged = Message::Probe([1; 12]).seal(&secret);
        forged[5..HEADER].copy_from_slice(&SecretKey::generate().public().0);
        assert_eq!(Message::open(&forged), None);
    }
}
