# Use the natty library

Add natty from crates.io:

```toml
[dependencies]
natty = "0.0.3"
```

This code is a sketch. [examples/pipe.rs](../examples/pipe.rs) is a complete program.

The endpoint needs `relay_tls`: an `Arc<natty::quinn::rustls::ClientConfig>` that trusts the certificate of the relay. [src/bin/natty/env.rs](../src/bin/natty/env.rs) makes this value with the `webpki-roots` crate. That crate is not a dependency of the library.

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

## Quickstart

This test uses one machine and three terminals.

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
3. In terminal 2, start a listener:
   ```sh
   NATTY_CA=cert.pem cargo run --example pipe -- listen localhost:4443 < /dev/null
   ```
   The listener prints `listening as <key>@localhost:4443`. It serves one peer.
4. In terminal 3, send a line to the listener. Replace `<key>` with the key that the listener printed:
   ```sh
   echo hello | NATTY_CA=cert.pem cargo run --example pipe -- connect '<key>@localhost:4443'
   ```

Result: terminal 2 prints `hello`. Terminal 3 prints the byte counts, the RTT and `path relay`. This short transfer ends before the punch completes.
