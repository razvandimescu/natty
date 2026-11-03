//! NAT traversal, no frameworks. Wire format: docs/design.md.

mod client;
#[cfg(feature = "quic")]
mod endpoint;
mod key;
pub mod stun;
pub mod wire;

pub use client::connect;
#[cfg(all(fuzzing, feature = "quic"))]
pub use endpoint::fuzz_signal;
#[cfg(feature = "quic")]
pub use endpoint::{peer_key, Endpoint};
pub use key::{InvalidKey, PublicKey, SecretKey};
#[cfg(feature = "quic")]
pub use quinn;
pub use wire::Welcome;
