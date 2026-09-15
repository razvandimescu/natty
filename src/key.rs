use std::fmt;
use std::str::FromStr;

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
const ENCODED_LEN: usize = 52;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(msg, sig)
            .is_ok()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut acc = 0u32;
        let mut bits = 0;
        let mut out = String::with_capacity(ENCODED_LEN);
        for &byte in &self.0 {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ZBASE32[(acc >> bits) as usize & 31] as char);
            }
            acc &= (1 << bits) - 1;
        }
        out.push(ZBASE32[(acc << (5 - bits)) as usize & 31] as char);
        f.write_str(&out)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug)]
pub struct InvalidKey;

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid key: expected 52 z-base-32 characters")
    }
}

impl std::error::Error for InvalidKey {}

impl FromStr for PublicKey {
    type Err = InvalidKey;

    fn from_str(s: &str) -> Result<Self, InvalidKey> {
        if s.len() != ENCODED_LEN {
            return Err(InvalidKey);
        }
        let mut key = [0u8; 32];
        let mut acc = 0u32;
        let mut bits = 0;
        let mut i = 0;
        for c in s.bytes() {
            let v = ZBASE32.iter().position(|&z| z == c).ok_or(InvalidKey)?;
            acc = (acc << 5) | v as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                key[i] = (acc >> bits) as u8;
                i += 1;
            }
            acc &= (1 << bits) - 1;
        }
        if acc != 0 {
            return Err(InvalidKey);
        }
        Ok(PublicKey(key))
    }
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness unavailable");
    bytes
}

pub struct SecretKey {
    seed: [u8; 32],
    pair: Ed25519KeyPair,
}

impl SecretKey {
    pub fn generate() -> Self {
        Self::from_seed(random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("every 32-byte seed is a valid Ed25519 key");
        Self { seed, pair }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(
            self.pair
                .public_key()
                .as_ref()
                .try_into()
                .expect("Ed25519 public keys are 32 bytes"),
        )
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.pair
            .sign(msg)
            .as_ref()
            .try_into()
            .expect("Ed25519 signatures are 64 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zbase32_roundtrip() {
        let key = SecretKey::generate().public();
        let text = key.to_string();
        assert_eq!(text.len(), ENCODED_LEN);
        assert_eq!(text.parse::<PublicKey>().unwrap(), key);
    }

    #[test]
    fn zbase32_rejects_noncanonical_padding() {
        let mut text = PublicKey([0; 32]).to_string().into_bytes();
        text[ENCODED_LEN - 1] = ZBASE32[1];
        assert!(std::str::from_utf8(&text)
            .unwrap()
            .parse::<PublicKey>()
            .is_err());
    }

    #[test]
    fn sign_verify() {
        let secret = SecretKey::from_seed([7; 32]);
        let sig = secret.sign(b"msg");
        assert!(secret.public().verify(b"msg", &sig));
        assert!(!secret.public().verify(b"other", &sig));
    }
}
