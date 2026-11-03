# natty

natty is a Rust library and a relay server. An application uses them to open an encrypted QUIC connection to a peer behind NAT. A connection is a `quinn::Connection` from quinn 0.11. The connection uses a direct UDP path when hole punching succeeds. If it does not succeed, the relay forwards the encrypted packets.

A peer address is `<key>@<relay>`: the public key of the peer and its relay. The application must already have this address, and both peers must use the same relay. natty has no default relay. Each application chooses its relay, and anyone can run one.

[An animated walk-through](https://razvandimescu.github.io/natty/how-it-works.html) shows one connection, step by step.

natty is built for the friend-to-friend service sharing in
[numa](https://github.com/razvandimescu/numa). It has no numa dependency.

Status:

- Built: the relay, QUIC through the relay, and hole punching.
- Measured ([docs/results.md](docs/results.md)):
  - the relay path between two networks;
  - a direct path from behind one NAT to a host without NAT;
  - a direct path between one pair of NATs that remap on an early packet
    (home and office routers, 2026-10-24).
- Not yet shown: direct paths over IPv6, through double NAT or carrier-grade
  NAT, or between peers a few hops apart.
- Not started: port mapping ([ROADMAP.md](ROADMAP.md)).
- Runs on macOS, Linux and Windows. CI tests only Linux.

## When to use natty

natty connects the peers of one application through NAT. It is not a VPN. The application decides which keys can connect, not a server.

Use natty when:

- You want to choose the relay. natty has no default service. It connects only to the relay and to peers.
- You want few dependencies. natty uses quinn, tokio, rustls, ring and log.

Use a different tool when you need:

- Discovery or lookup of keys. natty never publishes or looks up keys.
- Many transports and peer discovery in one protocol suite, for example libp2p.
- A mesh, a VPN or an overlay network, for example Tailscale or ZeroTier.
- Connections to browsers, for example WebRTC.
- Port mapping or more than one relay for each endpoint now, for example iroh.
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

This test shows that the relay and the API work. It does not test NAT traversal. On one machine, a longer transfer moves to a direct path over loopback, which does not cross a NAT. To test NAT traversal, see [Run a relay](#run-a-relay).

If `listening as` does not appear, the listener cannot reach the relay. The example retries in silence. To test the relay, run `curl --cacert cert.pem https://localhost:4443/health`. The first line must be `ok`.

## Use the library

Add natty from crates.io:

```toml
[dependencies]
natty = "0.0.1"
```

A sketch. Errors use `?` for brevity. [examples/pipe.rs](examples/pipe.rs) is a
complete program.

Both peers bind an endpoint on the same relay:

```rust
use natty::{Endpoint, PublicKey, SecretKey};

// relay_tls is an Arc<natty::quinn::rustls::ClientConfig> that trusts the
// relay certificate. examples/common/mod.rs makes one with webpki-roots.
// Both peers must offer the same ALPN. The pipe example uses natty-pipe/1.
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

A relay needs a DNS name, a TLS certificate for that name, TCP 443 and UDP 3478. The peers need only outbound access.

Build the relay with `cargo build --release -p natty-relay`, or use the [Dockerfile](Dockerfile) for a static image. Start it with `./target/release/natty-relay --cert fullchain.pem --key privkey.pem`. With a public CA certificate, the peers need no `NATTY_CA`. For a self-signed certificate, use the command in quickstart step 1 with the host name in place of `localhost`, and copy `cert.pem` to the peers. A plain `openssl req -x509` certificate has CA:TRUE and no subjectAltName, so rustls rejects it.

To test the relay from a peer, run `curl https://relay.example.net/health`. Add `--cacert cert.pem` for a self-signed certificate. The first line is `ok`.

To test NAT traversal, do quickstart steps 3 and 4 on two peers on different networks, with the relay host name in place of `localhost:4443`. The connector prints `path relay` or `path direct <address>`. `path relay` is a normal result. A small transfer can end before the punch completes, and some pairs of NATs never get a direct path.

Flags:

- `--cert` and `--key`: PEM files. The relay reads them only at start. Restart
  the relay after you renew the certificate.
- `--listen`: the TCP address for relay sessions. The default is `[::]:443`. A port above 1023 needs no root. Then the relay address includes the port, for example `relay.example.net:4443`.
- `--stun`: the UDP address of the STUN responder. The default is `[::]:3478`.
- `--cap`: the forwarded bytes per second for each session. The default is
  1 MiB/s. A value of 0 removes the cap.
- `--total-cap`: the forwarded bytes per second for all sessions together. The
  default is 0, no ceiling. A public relay can use it to stay inside its
  traffic budget.
- `--per-ip`: the connection limit for each IPv4 address or IPv6 /64. The
  default is 16.

## How it works

Each endpoint has an Ed25519 key and one TLS session to a relay.

1. The dialer starts its QUIC handshake through the relay, also when a direct
   path to the peer is up. The relay forwards it on the session of the peer.
2. Each endpoint gets its public address from the STUN responder of the relay.
3. Allowed peers send signed address candidates through the relay. A peer is
   allowed after `Endpoint::allow` or a dial. IPv6 candidates go first.
4. Each peer sends an opener to each IPv4 candidate of the other peer. An opener
   is a UDP packet with TTL 2. It opens the local NAT to the peer and expires
   before the far NAT.
5. 200 ms later, the peers send UDP probes to each other. A probe is signed
   with a new key from the candidates, not with the endpoint key.
6. When a probe gets an answer, the QUIC connection moves to the direct path.
   The relay session stays open as a fallback.
7. When no probe gets an answer, the relay continues to forward the packets.

Peers authenticate with raw Ed25519 public keys in TLS 1.3 (RFC 7250). The
dialer accepts only the key that it dialed. The accepting endpoint accepts any
key. The application decides what that key can do.

The design follows Tailscale's DERP, with its own framing. natty is not
compatible with DERP. [docs/design.md](docs/design.md) specifies the wire format, and [docs/research.md](docs/research.md) gives the design decisions with sources.

## Limits

- There is no port mapping (NAT-PMP, PCP).
- An endpoint uses one relay, with no failover. To reach a peer on a different
  relay, bind a second endpoint on that relay.
- There is no port prediction for hard NATs.
- Local candidates come only from the interface of the default route.
- Openers are IPv4 only.
- There is no NAT simulation in CI.
- Memory use and binary size are not measured.
- There is no declared minimum Rust version.
- There has been no security review. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What the relay sees

The relay sees:

- The keys that are online, and their addresses.
- When each session starts and stops.
- Which pairs of keys exchange packets, and the byte counts.
- The ALPN of each connection. The first QUIC packet is not confidential.
- The local and public addresses and the probe keys of peers that punch.
  Candidates are signed, but not encrypted.

The relay does not see the QUIC payload. The relay code has no per-session log
path. It keeps only aggregate counters, which `/health` shows.

Any peer that knows `<key>@<relay>` can open a QUIC connection through the
relay. That peer learns that the endpoint is online. A revoke removes the direct
path, but the revoked peer keeps the addresses that it learned.

## What the network sees

Anyone on the network path of a peer sees:

- The relay that the peer uses.
- The punch packets. They are signed, but not encrypted. Each one starts with
  `*nty` and contains a probe key, not an endpoint key.

No endpoint key goes out in clear. One gap remains:

- After a network change, keepalives use the old probe key until the next
  punch. An observer on both networks can link them with that key.

## License

natty is available under the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
