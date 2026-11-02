# natty-relay

natty-relay is the relay server for [natty](https://github.com/razvandimescu/natty), a Rust library that connects applications behind NAT.

Each peer keeps one TLS session to a relay. The relay forwards packets between the sessions by public key. Its STUN responder tells each peer its public address. The peers use these addresses to open a direct path through their NATs (hole punching). If the punch does not succeed, the relay continues to forward the encrypted packets.

[An animated walk-through](https://razvandimescu.github.io/natty/how-it-works.html) shows one connection, step by step.

## Install

```sh
cargo install natty-relay
```

To build a static Linux image, use the [Dockerfile](https://github.com/razvandimescu/natty/blob/main/Dockerfile) in the natty repository.

## Run

A relay needs a DNS name, a TLS certificate for that name, TCP 443 and UDP 3478. The peers need only outbound access. The relay accepts a session from any key. To limit its load, use `--cap`, `--total-cap` and `--per-ip`.

### Certificate from a public CA

Start the relay with the certificate chain and its key. For example, with a Let's Encrypt certificate:

```sh
natty-relay --cert fullchain.pem --key privkey.pem
```

Peers that trust the public CA roots accept this certificate. The natty examples trust these roots.

### Self-signed certificate

Make the certificate. Use your host name in place of `relay.example.net`:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj /CN=relay.example.net -addext subjectAltName=DNS:relay.example.net \
  -addext basicConstraints=critical,CA:FALSE -keyout key.pem -out cert.pem
```

Keep the `-addext` options. Without them, the certificate has CA:TRUE and no subjectAltName. rustls rejects such a certificate.

Start the relay:

```sh
natty-relay --cert cert.pem --key key.pem
```

Copy `cert.pem` to the peers. The natty examples read it from `NATTY_CA`.

### Test the relay

Run `curl https://relay.example.net/health`. For a self-signed certificate, add `--cacert cert.pem`. The first line is `ok`. The other lines are aggregate counters.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--cert`, `--key` | required | The PEM files of the certificate and its key. |
| `--listen` | `[::]:443` | The TCP address for relay sessions. |
| `--stun` | `[::]:3478` | The UDP address of the STUN responder. |
| `--cap` | `1048576` (1 MiB/s) | The forwarded bytes per second for each session. 0 removes the cap. |
| `--total-cap` | `0` | The forwarded bytes per second for all sessions together. 0 removes the cap. |
| `--per-ip` | `16` | The connection limit for each IPv4 address or IPv6 /64. |

The relay reads the certificate files only at start. After you renew the certificate, restart the relay.

A port above 1023 does not need root. With a port other than 443, the relay address includes the port, for example `relay.example.net:4443`.

A public relay can use `--total-cap` to stay inside its traffic budget.

## What the relay sees

The relay sees which keys are online, their addresses, and which pairs of keys exchange packets. It does not see the QUIC payload. The relay code has no per-session log path. It keeps only aggregate counters. The [natty README](https://github.com/razvandimescu/natty#what-the-relay-sees) has the full list.

## Security

CI fuzzes the frame parser and the STUN responder. To report a vulnerability, see [SECURITY.md](https://github.com/razvandimescu/natty/blob/main/SECURITY.md).

## License

natty-relay is available under the [Apache License 2.0](https://github.com/razvandimescu/natty/blob/main/LICENSE-APACHE) or the [MIT license](https://github.com/razvandimescu/natty/blob/main/LICENSE-MIT), at your option.
