# Research notes (2026-09-15)

Facts gathered while designing natty. Sources inline. Numbers were measured
on this date; re-measure before quoting them later.

## Why not iroh

Measured against numa's lockfile (345 crates) and release profile (fat LTO,
codegen-units=1, strip):

| option | new crates | binary delta |
|---|---|---|
| iroh 1.2.0 (tls-ring, portmapper) | 131 | +4.16 MiB floor, ~4.5-5 in real use |
| quinn | 6 | not measured, expected < 1 MiB |
| natty (path dep, quic feature) | 8, measured 2026-09-15 | not measured; natty + quinn, quinn-proto, lru-slab, rand_pcg, rustc-hash, web-time |
| snow (Noise) | 2 | |
| natpmp | 10 | mostly netlink |
| stun_codec | 10 | |
| webrtc-ice | 15 | |
| str0m | 19 | |

iroh uses its own QUIC (noq), its own DNS resolver (n0-dns-resolver), and by
default looks up keys through n0's DNS service and publishes the endpoint's
key and addresses to n0's pkarr relay. All of that must be turned off for a
privacy posture; natty has nothing to turn off.

## Rust landscape (crates.io)

- iroh: 2.5M downloads.
- ant-quic: quinn fork, no relay server, 54 deps including aws-lc-rs, PQC,
  Bluetooth.
- tailscale-rs (official, BSD + patents): DERP client to public relays only,
  no server. Its README says NAT traversal is "coming soon" and gives "no
  compatibility guarantees".
- Sans-IO ICE (`is`), `stun`, `stun_codec`, `stunclient`: codecs and ICE,
  WebRTC-shaped.
- Nothing small and standalone exists.

## DERP, the reference shape

tailscale/tailscale at 6b0c1de (2026-09-14):

- `derp/derp.go` 309 lines (protocol), `derp_client.go` 743,
  `derpserver.go` 2703 (includes mesh, verify hooks, metrics),
  `disco/disco.go` 658.
- Frame: 1-byte type + 4-byte length. 16 types: ServerKey, ClientInfo,
  ServerInfo, SendPacket, RecvPacket, KeepAlive, NotePreferred, PeerGone,
  PeerPresent, ForwardPacket, WatchConns, ClosePeer, Ping, Pong, Health,
  Restarting.
- Transport: TLS on 443, `GET /derp` + `Upgrade: DERP`, WebSocket fallback.
- Auth: server magic + curve25519 key; client key + nonce + NaCl box.
- STUN is separate: `derper --stun` on UDP 3478.
- Disco types: Ping, Pong, CallMeMaybe, plus UDP-relay-endpoint messages
  added in 2025.
- Wire-stable since 2020.

## Hole punching success, measured

- Seemann, Inden, Vyzovitis (ICDCSW 2022): 86% TCP, 93% QUIC; retrying more
  than 3 times gives nothing.
- libp2p hole-punching month (Dec 2022): 6.25M results; roughly 57% success
  among decided attempts.
- Trautwein et al., IMC 2026 (arXiv 2604.12484): 4.4M attempts, 85k networks,
  167 countries. Conditional success 70% ± 7, TCP ≈ QUIC. 29% of attempts fail
  before the punch (relay reservation, address discovery). 97.6% of successes
  are first-try. Success independent of relay characteristics.
- Tailscale blog (2025-10): "well north of 90%", no breakdown.

Consequence: about half of all pairs end relayed. Forwarding is a first-class
path. A relay that only does discovery does not fit this data.

## Tailscale's technique list (2020 blog)

STUN for reflexive address; endpoint-independent vs endpoint-dependent NAT;
simultaneous send; birthday-paradox port probing for one hard NAT (256 probes
~64%, 1024 ~98%); two hard NATs impractical (~170k probes/side); UPnP,
NAT-PMP, PCP; IPv6 and NAT64 via ipv4only.arpa; hairpinning; relay fallback;
ICE-style racing.

## Early-packet remapping (measured 2026-09-15)

Two consumer routers (office and home, docs/results.md) look punchable by the
usual classification: endpoint-independent mapping, address and port dependent
filtering. Both remap when a datagram from the peer arrives before their own
datagram to the peer has left: the next outbound datagram to that peer gets a
new external port. With both sides probing at once, each side's probes arrive
early at the other, so the pair never finds a reachable port. Tailscale fails
on the same pair and stays on DERP.

One NAT with this behaviour is fine: natty learns the new port from the probe
that arrives from it (office to a public host went direct). Two are not.

Candidate mitigation, untested here: send the first probes with a TTL that
expires past the local NAT but before the peer's, so they open the local
mapping without landing early at the far end. Needs a hop count per path and
does not help when the NATs are few hops apart. Measure how common the
behaviour is before building it.

Measured 2026-10-24 on both routers: TTL 2 makes the local mapping and expires before the far end, and the reply from the far end then gets through with the port kept. See docs/results.md.

## QUIC-native traversal: not settled

- draft-seemann-quic-nat-traversal-02: expired 2024-09, individual, never
  adopted; editor's copy still changing (Sept 2026).
- draft-ietf-quic-address-discovery: WG-adopted March 2025, -01 August 2026,
  standards track, no last call.
- n0's draft-bruynooghe-n0-quic-nat-traversal: "based on Seemann with heavy
  modifications", "not yet a specification".

Conclusion: keep traversal beside QUIC (DERP shape), not inside it.

## Port mapping

NAT-PMP (RFC 6886) and PCP (RFC 6887): UDP 5351 to the default gateway,
version 0 vs 2 in the first byte. NAT-PMP MAP is 12 bytes out, 16 back; PCP
MAP is 24-byte header + 36-byte opcode. Reply carries external ip:port,
granted lifetime, and an epoch (server uptime); renew at half lifetime,
re-request if epoch goes backwards. Fails on routers without it, on CGNAT
(external address is private or 100.64/10), on hotspots and enterprise nets.
The router at the author's desk answered none of NAT-PMP, PCP, or UPnP SSDP.

## Relay sizing

- Estimate, not measured: idle relay sessions cost roughly 50-100 KiB each
  (TLS buffers + task), so a 512 MiB VPS holds about 5-10k idle sessions;
  raise the fd limit. n0 quotes 60k per dedicated relay on larger boxes.
- Forwarding mode is bandwidth-bound, not connection-bound.
- Calibration from numa's public ODoH relay: an opt-in relay for a small
  user base carries modest request rates, so a natty relay for a comparable
  population would hold tens to low hundreds of standing sessions.

## Name

`natty`: NAT traversal, and "natural" as in no enhancement, few crates.
Collisions: getlantern/natty, a 2018 C++ WebRTC NAT-traversal tool; a Java date
parser; NatTypeTester in the search neighbourhood.
