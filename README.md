# natty

natty is a Rust library and a relay server. An application uses them to open an encrypted QUIC connection to a peer behind NAT. A peer address is `<key>@<relay>`: the public key of the peer and its relay. The application must already have this address. Both peers must use the same relay and the same ALPN. The connection uses a direct UDP path when hole punching succeeds. If it does not succeed, the relay forwards the encrypted packets. A connection is a `quinn::Connection` from quinn 0.11. natty has no default relay. Each application chooses its relay, and anyone can run one.

[An animated walk-through](https://razvandimescu.github.io/natty/how-it-works.html) shows one connection, step by step.

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

natty is built for the friend-to-friend service sharing in
[numa](https://github.com/razvandimescu/numa). It has no numa dependency.

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

## Quickstart

This test uses one machine and three terminals. You need a Rust toolchain and a clone of this repository. Run all commands from the root of the repository.

1. Make a self-signed certificate for `localhost`:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
     -subj /CN=localhost -addext subjectAltName=DNS:localhost \
     -addext basicConstraints=critical,CA:FALSE -keyout key.pem -out cert.pem
   ```
2. In terminal 1, start the relay:
   ```sh
   cargo run -p natty-relay -- --cert cert.pem --key key.pem --listen '[::]:4443'
   ```
   The first run compiles for some minutes.
3. In terminal 2, start a listener:
   ```sh
   NATTY_CA=cert.pem cargo run --example pipe -- listen localhost:4443 < /dev/null
   ```
   The listener prints `listening as <key>@localhost:4443`. It serves one peer and then stops.
4. In terminal 3, connect to the address that the listener printed, and send a line:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect <key>@localhost:4443
   ```

Result: terminal 2 prints `hello`. Terminal 3 prints the byte counts, the RTT and `path relay`. This short transfer ends before the punch completes.

This test shows that the relay and the API work. It does not test NAT traversal. On one machine, a longer transfer moves to a direct path over loopback, which does not cross a NAT. To test NAT traversal, see [Test across networks](#test-across-networks).

If `listening as` does not appear, the listener cannot reach the relay. The example retries in silence. To test the relay, run `curl --cacert cert.pem https://localhost:4443/health`. The first line must be `ok`.

## Use the library

Add natty as a git dependency. Pin a commit, because the API can change:

```toml
[dependencies]
natty = { git = "https://github.com/razvandimescu/natty", rev = "<commit>" }
```

A sketch. Errors use `?` for brevity. [examples/pipe.rs](examples/pipe.rs) is a
complete program.

Both peers bind an endpoint on the same relay:

```rust
use natty::{Endpoint, PublicKey, SecretKey};

// relay_tls is an Arc<natty::quinn::rustls::ClientConfig> that trusts the
// relay certificate. examples/common/mod.rs makes one with webpki-roots.
let endpoint = Endpoint::bind(SecretKey::generate(), "relay.example.net", relay_tls, &[b"my-app/1"])?;
// This waits with no limit while the relay is unreachable, for example
// because of a bad certificate or a closed port.
endpoint.relay_state().wait_for(Option::is_some).await?;
println!("{}@relay.example.net", endpoint.public_key());
```

The dialer connects to the key of the listener:

```rust
// A peer address is <key>@<relay>. Parse the part before the @.
let peer: PublicKey = "<key>".parse()?;
// The handshake fails unless the peer holds the key `peer`.
let conn = endpoint.connect(peer).await?;
let (mut send, mut recv) = conn.open_bi().await?;
// The listener sees a new stream only when the stream carries a byte.
send.write_all(b"hello").await?;
```

The listener accepts any key. The application decides which keys it serves:

```rust
let conn = endpoint.accept().await.ok_or("endpoint closed")?.await?;
let key = natty::peer_key(&conn).ok_or("peer without a key")?;
// trusted is a check of your application, for example a list of friend keys.
if !trusted(&key) {
    conn.close(0u32.into(), b"not allowed");
    return Ok(());
}
// allow is not access control. It lets the peer learn the addresses of this
// endpoint and get a direct path. Without it, the connection uses the relay.
endpoint.allow(key);
let (mut send, mut recv) = conn.accept_bi().await?;
```

Before the process exits, call `endpoint.close().await`. Otherwise, peers wait for the idle timeout.

natty re-exports quinn as `natty::quinn`. To keep the same address after a restart, store the key with `SecretKey::seed` and load it with `SecretKey::from_seed`.

## Run a relay

A relay needs a DNS name, a TLS certificate for that name, TCP 443 and UDP 3478. The peers need only outbound access. These steps use the name `relay.example.net`. Run them from the root of a clone of this repository.

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
3. Copy `cert.pem` to the peers.
4. Start the relay:
   ```sh
   ./target/release/natty-relay --cert cert.pem --key key.pem
   ```
   With a public CA certificate, use its full chain and its key, for example
   `--cert fullchain.pem --key privkey.pem`. To run the relay without root, add `--listen '[::]:4443'`. Then the relay host must accept TCP 4443, and the relay address is `relay.example.net:4443`.
5. On a peer, make sure that the relay answers:
   ```sh
   curl --cacert cert.pem https://relay.example.net/health
   ```
   The first line is `ok`. Aggregate counters follow.

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

### Test across networks

You need two peers on different networks, for example a home and an office. Each peer needs a Rust toolchain, a clone of this repository and `cert.pem` from step 3.

1. On peer A, start a listener:
   ```sh
   NATTY_CA=cert.pem cargo run --example pipe -- listen relay.example.net < /dev/null
   ```
2. On peer B, connect to the address that peer A printed, and send a line:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect <key>@relay.example.net
   ```

Peer B prints `path relay` or `path direct <address>`. `path relay` is a normal result. A small transfer can end before the punch completes. Some pairs of NATs never get a direct path.

If `listening as` does not appear, the peer cannot reach the relay. Do step 5 on that peer. Then examine the certificate, the host name and the open ports.

With a certificate from a public CA, remove `NATTY_CA` here and `--cacert` in step 5.

## How it works

Each endpoint has an Ed25519 key and one TLS session to a relay.

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
- The ALPN of each connection. The first QUIC packet is not confidential.
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

## License

natty is available under the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
