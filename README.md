# natty

natty is a Rust library and a relay server. An application uses them to open an
encrypted QUIC connection to a peer behind NAT. The application must already
have the public key of the peer, and both peers must use the same relay. The
connection uses a direct UDP path when hole punching succeeds. If it does not
succeed, the relay forwards the encrypted packets. natty has no default relay.
Each application chooses its relay, and anyone can run one.

Status: pre-0.1. natty is not on crates.io, and the API can change.

- Built: the relay, QUIC through the relay, and hole punching.
- Measured ([docs/results.md](docs/results.md)):
  - the relay path between two networks;
  - a direct path from behind one NAT to a host without NAT;
  - a direct path between two NATs that remap on an early packet (home and
    office, 2026-10-24).
- Not yet shown: direct paths over IPv6, through double NAT or carrier-grade
  NAT, or between peers a few hops apart.
- Not started: port mapping and hardening ([ROADMAP.md](ROADMAP.md)).
- Platforms in the measurements: macOS, Linux (Raspberry Pi) and Windows 11.

## When to use natty

Use natty when all of these apply:

- You want an encrypted QUIC connection to a key, direct when possible.
- You want few dependencies. On top of tokio and rustls, natty with QUIC added 8
  crates to numa's lockfile, and iroh 1.2.0 with port mapping added 131.
- You want no third-party service by default. iroh uses n0's DNS service and
  pkarr relay by default ([docs/research.md](docs/research.md)). natty
  publishes nothing.

Use a different tool when you need:

- Discovery or lookup of keys. natty never publishes or looks up keys.
- Many transports and peer discovery in one protocol suite, for example libp2p.
- A mesh, a VPN or an overlay network, for example Tailscale or ZeroTier.
- Connections to browsers, for example WebRTC.
- A stable API now.

natty is built for the friend-to-friend service sharing in
[numa](https://github.com/razvandimescu/numa). It has no numa dependency.

## Quickstart

You need three machines: a relay host and two peers. Each machine needs a Rust
toolchain and a clone of this repository. Run all commands from the root of the
repository. The relay host needs a DNS name, for example `relay.example.net`. It
must accept TCP 443 and UDP 3478. The peers need only outbound access.

1. On the relay host, build the relay:
   ```sh
   cargo build --release -p natty-relay
   ```
2. On the relay host, make a self-signed certificate for the host name:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
     -subj /CN=relay.example.net -addext subjectAltName=DNS:relay.example.net \
     -addext basicConstraints=critical,CA:FALSE -keyout key.pem -out cert.pem
   ```
   If you have a certificate from a public CA, go to step 4. Do not use a plain
   `openssl req -x509` certificate. It has CA:TRUE and no subjectAltName, so
   rustls rejects it.
3. Copy `cert.pem` to the two peers.
4. Start the relay:
   ```sh
   ./target/release/natty-relay --cert cert.pem --key key.pem
   ```
   With a public CA certificate, use its full chain and its key, for example
   `--cert fullchain.pem --key privkey.pem`. To run the relay without root, add
   `--listen '[::]:4443'`. Then the relay host must accept TCP 4443, and the
   relay address in steps 5 to 7 is `relay.example.net:4443`.
5. On peer A, make sure that the relay answers:
   ```sh
   curl --cacert cert.pem https://relay.example.net/health
   ```
   The first line is `ok`. Aggregate counters follow.
6. On peer A, start a listener:
   ```sh
   NATTY_CA=cert.pem cargo run --example pipe -- listen relay.example.net < /dev/null
   ```
   The first run compiles for some minutes. Then the listener prints
   `listening as <key>@relay.example.net`. It serves one peer and then stops.
7. On peer B, connect to the address that peer A printed, and send a line:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect <key>@relay.example.net
   ```

Result: peer A prints `hello`. Peer B prints the byte counts, the RTT and the
path: `path relay` or `path direct <address>`.

If `listening as` does not appear after the build, the peer cannot reach the
relay. The example retries in silence. Do step 5 on that peer again. Then
examine the certificate, the host name and the open ports.

Notes:

- `path relay` is a normal result. A small transfer can end before the punch
  completes. Some pairs of NATs never get a direct path.
- Each `pipe` run makes a new key. To keep the same key, set
  `NATTY_KEY=<file>`. The first run creates the file.
- With a certificate from a public CA, remove `NATTY_CA` and `--cacert`.
  `NATTY_CA` and `NATTY_KEY` are features of the examples only.

To try natty on one machine, use three terminals:

- In step 2, use `localhost` in place of `relay.example.net`. Skip step 3.
- In step 4, add `--listen '[::]:4443'`.
- In steps 5 to 7, use `localhost:4443` in place of `relay.example.net`.

## Use the library

Add natty as a git dependency. Pin a commit, because the API can change:

```toml
[dependencies]
natty = { git = "https://github.com/razvandimescu/natty", rev = "<commit>" }
```

A sketch. Errors use `?` for brevity. [examples/pipe.rs](examples/pipe.rs) is a
complete program.

```rust
use natty::{Endpoint, PublicKey, SecretKey};

// relay_tls is an Arc<rustls::ClientConfig> that trusts the relay
// certificate. examples/common/mod.rs makes one with tokio-rustls and
// webpki-roots.
let endpoint = Endpoint::bind(SecretKey::generate(), "relay.example.net", relay_tls, &[b"my-app/1"])?;
endpoint.relay_state().wait_for(Option::is_some).await?;
println!("{}@relay.example.net", endpoint.public_key());

// A peer address is <key>@<relay>. Parse the part before the @.
let peer: PublicKey = "<key>".parse()?;

// Connect. The handshake fails unless the peer holds the key `peer`.
let conn = endpoint.connect(peer).await?;
let (mut send, mut recv) = conn.open_bi().await?;
// The peer sees a new stream only when the stream carries a byte.
send.write_all(b"hello").await?;

// Accept. Any key can connect, so check the key before you serve it.
let conn = endpoint.accept().await.expect("endpoint open").await?;
let key = natty::peer_key(&conn);

// friend is a PublicKey that your application trusts. An allowed peer can
// learn the addresses of this endpoint and get a direct path.
endpoint.allow(friend);

// Call close before the process exits. Otherwise, peers wait for the idle
// timeout.
endpoint.close().await;
```

A connection is a `quinn::Connection` from quinn 0.11. natty re-exports quinn as
`natty::quinn`. To keep the same address after a restart, store the key with
`SecretKey::seed` and load it with `SecretKey::from_seed`. To read the API
documentation, run `cargo doc --open`.

## Run a relay

A relay needs a DNS name, a TLS certificate for that name, TCP 443 and UDP 3478.
Steps 1 to 5 of the quickstart start and test a relay.

Flags:

- `--cert` and `--key`: PEM files. The relay reads them only at start. Restart
  the relay after you renew the certificate.
- `--listen`: the TCP address for relay sessions. The default is `[::]:443`.
- `--stun`: the UDP address of the STUN responder. The default is `[::]:3478`.
- `--cap`: the forwarded bytes per second for each session. The default is
  1 MiB/s. A value of 0 removes the cap.
- `--total-cap`: the forwarded bytes per second for all sessions together. The
  default is 0, no ceiling. A public relay can use it to stay inside its
  traffic budget.
- `--per-ip`: the connection limit for each IPv4 address or IPv6 /64. The
  default is 16.

The [Dockerfile](Dockerfile) builds a static relay image.

## How it works

[An animated walk-through](https://razvandimescu.github.io/natty/how-it-works.html)
shows one connection, step by step.

Each endpoint has an Ed25519 key and one TLS session to a relay. A peer address
is `<key>@<relay-host[:port]>`.

1. The dialer sends its QUIC handshake to the relay. The relay forwards it on
   the session of the peer.
2. Each endpoint gets its public address from the STUN responder of the relay.
3. Allowed peers send signed address candidates through the relay. A peer is
   allowed after `Endpoint::allow` or a dial. IPv6 candidates go first.
4. Each peer sends an opener to each IPv4 candidate of the other peer. An opener
   is a UDP packet with TTL 2. It makes the mapping in the local NAT and expires
   before the far NAT.
5. 200 ms later, the peers send UDP probes to each other.
6. When a probe gets an answer, the QUIC connection moves to the direct path.
   The relay session stays open as a fallback.
7. When no probe gets an answer, the relay continues to forward the packets.

Peers authenticate with raw Ed25519 public keys in TLS 1.3 (RFC 7250). The
dialer accepts only the key that it dialed. The accepting endpoint accepts any
key. The application decides what that key can do.

A study measured 4.4 million DCUtR punch attempts in IPFS
([Trautwein et al., IMC 2026](https://arxiv.org/abs/2604.12484)). 29% failed
before the punch started, and 70% ± 7.1% of the rest succeeded. So about half of
all pairs stay on the relay, and the relay path is a normal path.

The design follows Tailscale's DERP, with its own framing. natty is not
compatible with DERP. [docs/design.md](docs/design.md) specifies the wire format.

## Limits

- There is no port mapping (NAT-PMP, PCP).
- An endpoint uses one relay, with no failover. To reach a peer on a different
  relay, bind a second endpoint on that relay.
- There is no port prediction for hard NATs.
- Local candidates come only from the interface of the default route.
- Openers are IPv4 only.
- There is no fuzzing and no NAT simulation in CI.
- Memory use and binary size are not measured.
- There is no declared minimum Rust version.

## What the relay sees

The relay sees:

- The keys that are online, and their addresses.
- When each session starts and stops.
- Which pairs of keys exchange packets, and the byte counts.
- The local and public addresses of peers that punch. Candidates are signed,
  but not encrypted.

The relay does not see the QUIC payload. The relay code has no per-session log
path. It keeps only aggregate counters, which `/health` shows.

An allowed peer can learn the addresses of an endpoint and get a direct path.
Any other peer that knows `<key>@<relay>` can open a QUIC connection through the
relay. That peer learns that the endpoint is online. A revoke removes the direct
path, but the peer keeps the addresses that it learned.

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
