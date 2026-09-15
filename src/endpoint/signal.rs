use std::net::SocketAddr;

use crate::wire::{put_addr, split_addr};
use crate::{PublicKey, SecretKey};

/// Starts below 0x40, where no ungreased QUIC packet and no STUN response do.
const MAGIC: [u8; 4] = *b"*nty";
pub(crate) const MAX_CANDIDATES: usize = 8;
const CONTEXT: &[u8] = b"natty punch v1\0";
const CANDIDATES: u8 = 1;
const PROBE: u8 = 2;
const PROBE_ACK: u8 = 3;
const HEADER: usize = 4 + 1 + 32;
const SIGNATURE: usize = 64;
/// The largest encoded address, so a PROBE_ACK never outgrows its PROBE.
const PROBE_PADDING: usize = 19;

pub(crate) type Nonce = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    Candidates { reply: bool, addrs: Vec<SocketAddr> },
    Probe(Nonce),
    ProbeAck { nonce: Nonce, observed: SocketAddr },
}

pub(crate) fn is_signal(packet: &[u8]) -> bool {
    packet.starts_with(&MAGIC)
}

/// The claimed sender, before any signature check.
pub(crate) fn sender(packet: &[u8]) -> Option<PublicKey> {
    let key = packet.get(5..HEADER)?;
    Some(PublicKey(key.try_into().ok()?))
}

impl Message {
    pub(crate) fn seal(&self, secret: &SecretKey) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER + 160 + SIGNATURE);
        buf.extend_from_slice(&MAGIC);
        buf.push(0);
        buf.extend_from_slice(&secret.public().0);
        buf[4] = match self {
            Message::Candidates { reply, addrs } => {
                buf.push(u8::from(*reply));
                for addr in addrs {
                    put_addr(&mut buf, *addr);
                }
                CANDIDATES
            }
            Message::Probe(nonce) => {
                buf.extend_from_slice(nonce);
                buf.extend_from_slice(&[0; PROBE_PADDING]);
                PROBE
            }
            Message::ProbeAck { nonce, observed } => {
                buf.extend_from_slice(nonce);
                put_addr(&mut buf, *observed);
                PROBE_ACK
            }
        };
        let sig = secret.sign(&[CONTEXT, &buf].concat());
        buf.extend_from_slice(&sig);
        buf
    }

    /// The sender and message, only if the sender's signature holds.
    pub(crate) fn open(packet: &[u8]) -> Option<(PublicKey, Message)> {
        if !is_signal(packet) || packet.len() < HEADER + SIGNATURE {
            return None;
        }
        let (signed, sig) = packet.split_at(packet.len() - SIGNATURE);
        let key = sender(packet)?;
        if !key.verify(&[CONTEXT, signed].concat(), sig) {
            return None;
        }
        let body = &signed[HEADER..];
        let message = match signed[4] {
            CANDIDATES => {
                let (&reply, mut rest) = body.split_first()?;
                let mut addrs = Vec::new();
                while !rest.is_empty() && addrs.len() < MAX_CANDIDATES {
                    let (addr, tail) = split_addr(rest).ok()?;
                    addrs.push(addr);
                    rest = tail;
                }
                Message::Candidates {
                    reply: reply == 1,
                    addrs,
                }
            }
            PROBE => Message::Probe(*body.first_chunk()?),
            PROBE_ACK => {
                let (nonce, rest) = body.split_first_chunk()?;
                Message::ProbeAck {
                    nonce: *nonce,
                    observed: split_addr(rest).ok()?.0,
                }
            }
            _ => return None,
        };
        Some((key, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_roundtrip_with_their_sender() {
        let secret = SecretKey::generate();
        let observed = "[2001:db8::1]:40000".parse().unwrap();
        for message in [
            Message::Candidates {
                reply: true,
                addrs: vec![observed, "198.51.100.4:9".parse().unwrap()],
            },
            Message::Probe([7; 12]),
            Message::ProbeAck {
                nonce: [7; 12],
                observed,
            },
        ] {
            let packet = message.seal(&secret);
            assert!(is_signal(&packet));
            assert_eq!(sender(&packet), Some(secret.public()));
            assert_eq!(Message::open(&packet), Some((secret.public(), message)));
        }
    }

    #[test]
    fn ack_is_never_larger_than_its_probe() {
        let secret = SecretKey::generate();
        let probe = Message::Probe([0; 12]).seal(&secret);
        let ack = Message::ProbeAck {
            nonce: [0; 12],
            observed: "[2001:db8::1]:1".parse().unwrap(),
        }
        .seal(&secret);
        assert_eq!(probe.len(), ack.len());
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
