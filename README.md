# natty

natty is a Rust library and a relay server. An application uses them to open an
encrypted QUIC connection to a peer behind NAT. The application needs only the
peer's public key and relay host. The connection uses a direct UDP path when
hole punching succeeds. If it does not succeed, the relay forwards the encrypted
packets. natty has no default relay. Each application chooses its relay, and
anyone can run one.

Status: pre-0.1. natty is not on crates.io, and the API can change.

- Built: the relay, QUIC through the relay, and hole punching.
- Measured: the relay path between two networks, and a direct path from behind
  one NAT to a host without NAT ([docs/results.md](docs/results.md)).
- Not yet shown: a direct path between two NATs.
- Not started: port mapping and hardening ([ROADMAP.md](ROADMAP.md)).

## How it works

Each endpoint has an Ed25519 key and one TLS session to a relay. A peer address
is `<key>@<relay-host[:port]>`.

1. The dialer sends its QUIC handshake to the relay. The relay forwards it on
   the peer's session.
2. Each endpoint gets its public address from the STUN responder of the relay.
3. Allowed peers send signed address candidates through the relay. Then they
   send UDP probes to each other.
4. When a probe gets an answer, the QUIC connection moves to the direct path.
   The relay session stays open as a fallback.
5. When no probe gets an answer, the relay continues to forward the packets.
   A rate cap applies to each session.

Peers authenticate with raw Ed25519 public keys in TLS 1.3 (RFC 7250). The
dialer accepts only the key that it dialed. The acceptor accepts any key. The
application decides what that key can do.

A study of 4.4 million punch attempts measured 70% ± 7 success for punches that
start ([Trautwein et al., IMC 2026](https://arxiv.org/abs/2604.12484)). Thus the relay path is a normal path, not an
error path.

The design follows Tailscale's DERP, with its own framing. natty is not
compatible with DERP. [docs/design.md](docs/design.md) specifies the wire format.

## When to use natty

Use natty when all of these apply:

- Your application already has the public keys of its peers.
- You want an encrypted QUIC connection to a key, direct when possible.
- You want few dependencies. natty uses tokio, rustls, ring and quinn. In
  numa's lockfile on 2026-09-15, iroh 1.2.0 added 131 crates, and natty with
  QUIC added 8. iroh also includes port mapping and key discovery. natty does
  not.

Use a different tool when you need:

- Discovery or lookup of keys. natty never publishes or looks up keys.
- A mesh, a VPN or an overlay network, for example Tailscale or ZeroTier.
- Connections to browsers, for example WebRTC.
- Failover between relays.
- A stable API now.

natty is built for the friend-to-friend service sharing in
[numa](https://github.com/razvandimescu/numa). It has no numa dependency.

## Quickstart

You need three machines: a relay host and two peers. The relay host needs a DNS
name, for example `relay.example.net`. It must accept TCP 443 and UDP 3478. The
peers need only outbound access. Clone this repository on all three machines.

To try natty on one machine, use three terminals and make these changes:

- Step 2: use `localhost` in place of `relay.example.net`.
- Step 3: add `--listen [::]:4443`.
- Steps 4 to 6: use `localhost:4443` in place of `relay.example.net`.

1. On the relay host, build the relay:
   ```sh
   cargo build --release -p natty-relay
   ```
2. Get a certificate for the relay host name. A certificate from a public CA
   needs no more steps. To make a self-signed certificate, use this command:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
     -subj /CN=relay.example.net -addext subjectAltName=DNS:relay.example.net \
     -addext basicConstraints=critical,CA:FALSE -keyout key.pem -out cert.pem
   ```
   Copy `cert.pem` to the two peers. Do not use a plain `openssl req -x509`
   certificate. It has CA:TRUE and no subjectAltName, so rustls rejects it.
3. Start the relay:
   ```sh
   ./target/release/natty-relay --cert cert.pem --key key.pem
   ```
   To run the relay without root, add `--listen [::]:4443`. Then use
   `relay.example.net:4443` in the steps that follow.
4. Make sure that the relay answers:
   ```sh
   curl --cacert cert.pem https://relay.example.net/health
   ```
   The first line is `ok`. Aggregate counters follow.
5. On peer A, start a listener:
   ```sh
   NATTY_CA=cert.pem cargo run --example pipe -- listen relay.example.net < /dev/null
   ```
   It prints `listening as <key>@relay.example.net`.
6. On peer B, connect to that address and send a line:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect <key>@relay.example.net
   ```
7. Peer A prints `hello`. Peer B prints the byte counts, the RTT and the path:
   `path relay` or `path direct <address>`.

Notes:

- `path relay` is a normal result. A small transfer can end before the punch
  completes. Some pairs of NATs never get a direct path.
- Each `pipe` run makes a new key. The listener serves one peer and then stops.
- With a certificate from a public CA, remove `NATTY_CA` and `--cacert`.
  `NATTY_CA` is a feature of the examples only.
- Relay flags: `--listen` (default `[::]:443`), `--stun` (default
  `[::]:3478`), `--cap` and `--per-ip`. The cap is 1 MiB/s for each session by
  default, and 0 removes it. By default, `--per-ip` allows 16 connections for
  each IPv4 address or IPv6 /64.
- The [Dockerfile](Dockerfile) builds a static relay image.

## Use the library

Add natty as a git dependency:

```toml
[dependencies]
natty = { git = "https://github.com/razvandimescu/natty" }
```

A sketch, with short error handling:

```rust
use natty::{Endpoint, SecretKey};

// relay_tls is an Arc<rustls::ClientConfig> that trusts the relay
// certificate. examples/common/mod.rs shows one.
let endpoint = Endpoint::bind(SecretKey::generate(), "relay.example.net", relay_tls, &[b"my-app/1"])?;
endpoint.relay_state().wait_for(Option::is_some).await?;
println!("{}@relay.example.net", endpoint.public_key());

// Connect. The handshake fails unless the peer holds the key `peer`.
let conn = endpoint.connect(peer).await?;

// Accept. Any key can connect, so check the key before you serve it.
let conn = endpoint.accept().await.expect("endpoint open").await?;
let key = natty::peer_key(&conn);

// An allowed key can learn the addresses of this endpoint and get a direct path.
endpoint.allow(friend);

// Before the process exits. Without it, peers wait for the idle timeout.
endpoint.close().await;
```

A connection is a `quinn::Connection` from quinn 0.11. natty re-exports quinn as
`natty::quinn`. To keep the same address after a restart, store the key with
`SecretKey::seed` and load it with `SecretKey::from_seed`.

## Limits

- There is no port mapping (NAT-PMP, PCP).
- An endpoint uses one relay, with no failover. To reach a peer on a different
  relay, bind a second endpoint on that relay.
- There is no port prediction for hard NATs.
- Local candidates come only from the interface of the default route.
- The relay path has a cap of 1 MiB/s for each session by default.
- In the measured cases, two NATs that remap on an early packet did not get a
  direct path ([docs/results.md](docs/results.md)).
- There is no fuzzing and no NAT simulation in CI.
- Memory use and binary size are not measured.

## What the relay sees

The relay sees:

- The keys that are online, and their addresses.
- When each session starts and stops.
- Which pairs of keys exchange packets, and the byte counts.
- The local and public addresses of peers that punch. Candidates are signed,
  but not encrypted.

The relay does not see the QUIC payload. The relay code has no per-session log
path. It keeps only aggregate counters, which `/health` shows.

An allowed key can learn the addresses of an endpoint and get a direct path. A
dial allows the dialed key. Any other key that knows `<key>@<relay>` can open a
QUIC connection through the relay. That key learns that the endpoint is online.
A revoke removes the direct path, but the key keeps the addresses that it
learned.

## Security

natty has had no security review. Do not open a public issue for a
vulnerability. Report it through the
[private advisory form](https://github.com/razvandimescu/natty/security/advisories/new).

## Documents

- [docs/design.md](docs/design.md): wire format and protocol rules.
- [docs/results.md](docs/results.md): measurements on real networks.
- [docs/research.md](docs/research.md): design decisions, with sources.
- [ROADMAP.md](ROADMAP.md): phases and gates.

## License

natty is available under the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
