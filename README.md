# natty

natty connects two applications behind NAT. The address of a peer is `<key>@<relay>`: its public key and a relay that both peers use. The application gets an encrypted `quinn::Connection` from quinn 0.11.

[![A laptop behind a home router and a Raspberry Pi behind an office router. Each one keeps a session to one relay. A direct UDP path can join them.](docs/map.png)](https://razvandimescu.github.io/natty/)

[The project page](https://razvandimescu.github.io/natty/) replays two runs between the laptop and the Raspberry Pi. The run with the [opener](#how-it-works) moves to a direct path. The run without it stays on the relay.

natty has three parts:

- [The library](#use-the-library) gives a Rust application a connection to a peer key.
- [The relay server](#run-a-relay) helps the peers open a direct UDP path through their NATs (hole punching). If the punch does not succeed, the relay forwards the encrypted packets.
- [The `natty` CLI](#share-a-tcp-service) shares a TCP service with the keys that you list. The machine that shares it needs no inbound port.

The application must already have the address of the peer. natty has no default relay. Each application chooses its relay. Anyone can run a relay.

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
   The listener prints `listening as <key>@localhost:4443`. It serves one peer. It then stops.
4. In terminal 3, send a line to the listener. Replace `<key>` with the key that the listener printed:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect '<key>@localhost:4443'
   ```

Result: terminal 2 prints `hello`. Terminal 3 prints the byte counts, the RTT and `path relay`. This short transfer ends before the punch completes.

This test shows that the relay and the API work. It does not cross a NAT. To test NAT traversal, see [Test NAT traversal](#test-nat-traversal).

If `listening as` does not appear, the listener cannot reach the relay. The example retries in silence. To test the relay, run `curl --cacert cert.pem https://localhost:4443/health`. The first line must be `ok`.

## Use the library

Add natty from crates.io:

```toml
[dependencies]
natty = "0.0.3"
```

This code is a sketch. [examples/pipe.rs](examples/pipe.rs) is a complete program.

The endpoint needs `relay_tls`: an `Arc<natty::quinn::rustls::ClientConfig>` that trusts the certificate of the relay. [src/bin/natty/env.rs](src/bin/natty/env.rs) makes this value with the `webpki-roots` crate. That crate is not a dependency of the library.

Both peers bind an endpoint on the same relay:

```rust
use natty::{Endpoint, PublicKey, SecretKey};

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

natty re-exports quinn as `natty::quinn`. To keep the same address after a restart, store the key with `SecretKey::seed`. Load it with `SecretKey::from_seed`.

The `tunnel` feature adds the module `natty::tunnel`. It holds the protocol of the CLI: `serve` for the side with the services, and `dial`, `open` and `list` for the side that connects.

## Share a TCP service

The `natty` CLI shares TCP services by name between two keys. An agent, `natty serve`, runs on a machine that can reach the services. It needs no inbound port. On another machine, `natty connect` gives one service a local port.

Install the CLI on both machines. This command needs a Rust toolchain:

```sh
cargo install natty --features cli
```

Each machine keeps its key in the file that `NATTY_KEY` names. natty makes the file on first use.

These steps use the [test relay](#run-a-relay) `relay.numa.rs`. Do not use it for a service that you depend on.

1. On the machine that connects, print its public key:
   ```sh
   export NATTY_KEY="$HOME/.natty/key"
   natty key
   ```
2. On the machine with the service, write the grants file. Each line holds one key and then its services:
   ```sh
   echo '<key from step 1> web' > grants
   ```
3. On the same machine, start the agent. This example shares a web server on port 8000:
   ```sh
   export NATTY_KEY="$HOME/.natty/key"
   natty serve relay.numa.rs --grants grants --service web=127.0.0.1:8000
   ```
   The agent prints `serving as <key>@relay.numa.rs`.
4. On the first machine, in the shell of step 1, give the service a local port. Use the address that the agent printed:
   ```sh
   natty connect '<key>@relay.numa.rs' web --port 8080
   ```
   The command prints `127.0.0.1:8080 -> web`.

Result: `curl http://127.0.0.1:8080/` on the first machine gets the answer of the web server.

To see the path of the connection, set `NATTY_LOG=debug`. The log shows `direct path to <key>` when the connection moves to a direct path. On the relay path, the relay caps the speed of each session. The default cap is 1 MiB/s.

`natty connect` first dials the agent. It then checks the grant. If one of these steps fails, the command stops with an error. When the connection to the agent closes later, `natty connect` dials again for the next TCP connection.

For a second service at the same time, start a second `natty connect` with its own key file. Add that key to the grants file. To see the services that the agent grants to your key, run `natty list '<key>@relay.numa.rs'`. `natty help` prints the commands and the environment variables.

The agent reads the grants file again every 5 s. When you remove a grant, the agent ends the open streams of that grant. A key with no grant gets the same refusal for every service name. It cannot learn which services exist. The client sends a service name, never an address.

The image `ghcr.io/razvandimescu/natty:v0.0.3` holds the CLI for linux/amd64. It runs as user 65532. In CI, the image runs `natty key` with a read-only root file system and no capabilities. Keep the key file on a volume. A new key file gives the agent a new address.

[docs/design.md](docs/design.md#tunnel) specifies the protocol and the limits of the agent.

## Run a relay

A relay needs a TLS certificate for its host name or IP address, a TCP port for sessions and a UDP port for STUN. The defaults are TCP 443 and UDP 3478. The peers need only outbound access. The relay accepts a session from any key. [What the relay knows](docs/design.md#what-the-relay-knows) lists the data that its operator can see.

A pair of peers without a direct path sends all of its traffic through the relay. To limit the load, use `--cap`, `--total-cap` and `--per-ip`. Published measurements of other systems give punch success rates from 57% to 93% ([docs/research.md](docs/research.md#hole-punching-success-measured)). natty has no rate of its own yet.

To install the relay, run `cargo install natty-relay`. The image `ghcr.io/razvandimescu/natty-relay:v0.0.3` holds the relay for linux/amd64. It takes the same flags. [relay/README.md](relay/README.md) describes the certificate setup, the health check and the flags.

The author of natty runs the test relay `relay.numa.rs` for the friend-to-friend feature of [numa](https://github.com/razvandimescu/numa). It can stop or change at any time. It shares a traffic cap with numa users. Its operator sees the data that [What the relay knows](docs/design.md#what-the-relay-knows) lists.

## Test NAT traversal

Use two peers on different networks and a relay that both peers can reach.

For this test, you can use the [test relay](#run-a-relay) `relay.numa.rs`. Do not use it in a released application.

On one peer, start a listener:

```sh
cargo run --example pipe -- listen relay.numa.rs < /dev/null
```

On the other peer, build the example:

```sh
cargo build --example pipe
```

Then send a line to the listener. Replace `<key>` with the key that the listener printed. The `sleep` keeps the stream open for 5 s during the punch. Without the build step, `cargo run` can use all of the 5 s to compile. The peers then print `path relay`, also when a direct path is possible.

```sh
(echo hello; sleep 5) | cargo run --example pipe -- connect '<key>@relay.numa.rs'
```

Both peers print `path relay` or `path direct <address>`. `path relay` is a normal result. Some pairs of NATs never get a direct path. For your own relay, use its address. For a self-signed certificate, set `NATTY_CA` as in the quickstart.

## How it works

Each endpoint has an Ed25519 key and one TLS session to a relay.

1. The dialer starts its QUIC handshake through the relay, also when a direct
   path to the peer is up. The relay forwards it on the session of the peer.
2. Each endpoint gets its public address from the STUN responder of the relay.
3. Allowed peers send signed address candidates through the relay. A peer is
   allowed after `Endpoint::allow` or a dial. IPv6 candidates go first.
4. Each peer sends an opener to each IPv4 candidate of the other peer. An opener
   is a UDP packet with TTL 2. It opens the local NAT to the peer. It expires
   before the far NAT.
5. 200 ms later, the peers send UDP probes to each other. The peers sign
   each probe with a new key from the candidates, not with the endpoint key.
6. When a probe gets an answer, the QUIC connection moves to the direct path.
   The relay session stays open as a fallback.
7. When no probe gets an answer, the relay continues to forward the packets.

[An animated walk-through](https://razvandimescu.github.io/natty/how-it-works.html) shows these steps.

Peers authenticate with raw Ed25519 public keys in TLS 1.3 (RFC 7250). The
dialer accepts only the key that it dialed. The listener accepts any
key. The application decides what that key can do.

The design follows Tailscale's DERP, with its own framing. natty is not
compatible with DERP. [docs/design.md](docs/design.md) specifies the wire format. [docs/research.md](docs/research.md) gives the design decisions with sources.

## Limits

- There is no port mapping (NAT-PMP, PCP). [ROADMAP.md](ROADMAP.md) has it as phase 4.
- An endpoint uses one relay. It has no failover. To reach a peer on a different
  relay, bind a second endpoint on that relay.
- A relay keeps one session for each key. A second process with the same key replaces the session of the first.
- There is no port prediction for hard NATs.
- Local candidates come only from the interface of the default route.
- Openers are IPv4 only.
- There is no NAT simulation in CI.
- There is no measurement of memory use or binary size.
- There is no declared minimum Rust version.
- natty has no security review yet. To report a vulnerability, see [SECURITY.md](SECURITY.md).


## License

natty is available under the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
