# Roadmap

Each phase ends with a gate: a result that is measured and recorded in
[docs/results.md](docs/results.md).

## Done

- **Phase 0, specification.** [docs/design.md](docs/design.md) specifies the
  wire format. QUIC runs on quinn over a virtual socket.
- **Phase 1, relay server.** Gate passed on 2026-09-15: forwarding from home to
  cellular through a relay on a VPS.
- **Phase 2, relay-path client.** Gate passed on 2026-09-15: a QUIC stream
  between two networks, with every byte relayed. The reconnect on a route
  change is built, but not measured on a real network switch.

## Phase 3: direct path

Built: STUN, local candidates, and signed candidate exchange through the relay.
Also built: UDP probes with a 25 s keepalive, and path migration with relay
fallback. IPv6 candidates go first.

Measured on 2026-09-15: a direct path through one NAT. Two NATs that remap on an
early packet stayed relayed.

Measured on 2026-10-24: with a TTL-2 opener before the probes, the same two NATs
got a direct path in about 0.5 s.

Gate: the four cases below pass on networks without early-packet remapping.
Each entry records the NAT types. The relay-path half passed on 2026-09-15
(home to cellular).

| case | expectation |
|---|---|
| home NAT to home NAT | direct within a few RTT |
| home NAT to cellular (CGNAT) | direct or relayed, no failure |
| CGNAT to CGNAT | relayed, no failure |
| IPv6 both ends | direct, relay untouched |

## Phase 4: port mapping

- [ ] NAT-PMP and PCP MAP request, renew at half lifetime, epoch watch,
      external address sanity check (reject RFC 1918 and 100.64/10 results).
- [ ] Mapped endpoint published as a candidate.

Gate: on a router that supports mapping, a cold inbound dial succeeds with the
relay carrying only the handshake.

## Phase 5: hardening and release

- [x] Fuzz the frame, STUN, signal and key parsers (`fuzz/`).
- [x] No endpoint key goes out in clear: probes carry probe keys
      ([#14](https://github.com/razvandimescu/natty/pull/14)), and QUIC
      handshakes start only through the relay
      ([#17](https://github.com/razvandimescu/natty/pull/17)).
- [x] `natty-relay` deployable as a single binary: `cargo install natty-relay`
      or the static Docker image.
- [ ] NAT simulation in Docker (iptables masquerade variants) in CI.
- [ ] RSS measurement on a Pi Zero. The armv6 cross-build
      (`messense/rust-musl-cross:arm-musleabihf`) already runs there.
- [ ] Binary size budget: library adds under 1 MiB to a stripped LTO binary.
- [ ] A pending connect fails at once on PEER_GONE, not after 30 s.
- [ ] 0.1.0 on crates.io. Until then, each 0.0.x release can change the API.

Gate: numa can build its friend-to-friend feature against 0.1.0 behind a
feature flag without touching natty internals.

## Explicitly deferred

- Hard-NAT port spraying (birthday attack). Measure how often the relay path is
  taken first; add only if the number justifies it.
- Relay mesh and multi-relay failover.
- Mobile lifecycle (background, rebind). Belongs to the consuming app.
- Any discovery layer.
