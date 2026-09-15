# Test results

Newest first. Each entry states the setup, what was measured, and what it
changes. Numbers come from the probe logs of the run; re-measure before
reusing them.

## 2026-09-15: direct path on real networks (Phase 3, partial)

Setup: Phase 3 code. Relay on the Hetzner VPS (TLS on 4443, STUN on UDP 3478,
1 MiB/s per-session cap). `pipe connect` sends 8 MB from a Windows 11 mini PC
behind the office router to `pipe listen` on two peers in turn. NAT behaviour was measured separately, with the VPS as the
far end and `tailscale netcheck` on each network.

| network | mapping | filtering | outbound UDP | early packet |
|---|---|---|---|---|
| office | endpoint-independent, port not always kept | address and port dependent | open | remaps |
| home (Pi Zero) | endpoint-independent, port kept | address and port dependent | open | remaps |

"Early packet": the far end sends to the client's mapped port from a port the
client has not sent to yet. The client's next datagram to that port then
leaves from a new external port (office 56011 to 1599, home 53761 to 1876).
The unsolicited packet occupies the 5-tuple, so the NAT picks another port.

| run | path | handshake | throughput | RTT | relay bytes |
|---|---|---|---|---|---|
| office to VPS (no NAT on the listener) | direct | 35 ms | 2.52 MiB/s | 28-31 ms | 109,118 |
| office to home Pi | relayed | 104 ms | 0.80 MiB/s | 333-717 ms | all |

Findings:

1. Punching works through a real NAT. Candidates went over the relay, probes
   crossed the office NAT, and QUIC moved to UDP on a Windows endpoint. The
   relay carried 109 KB, about 1.3% of the payload (handshake, candidates, the
   first datagrams): roughly 0.1 s of sending at the relay cap. 2.52 MiB/s
   is above the relay cap and probably the office uplink; not checked against
   a baseline.
2. Office to home did not go direct. Neither did a bare UDP punch without
   natty (nothing received either way), nor Tailscale between the same two
   networks (it stays on DERP). Both NATs remap on an early packet, so each side's first
   probes move the other side's mapping and neither learns a reachable port.
   The pair ended relayed with no failure, which is what forwarding is for.
3. Mapping and filtering alone predicted success here. The early-packet test
   is what explains the failure, so it belongs with NAT type in every entry.

Not measured yet: the four gate cases on networks without early-packet
remapping, time to go direct (`pipe` reports only the final path), and whether
the office port 63121 was the STUN mapping or one learned from a probe.

## 2026-09-15: QUIC over the relay path (Phase 2 gate)

Setup: same Hetzner relay, default per-session cap (1 MiB/s). `examples/pipe.rs`
listening on one machine, `pipe connect <key>@<relay>` on the other, 8 MB
through one QUIC stream, every datagram carried by the relay session. Peer TLS
is RFC 7250 raw Ed25519 keys, TLS 1.3 only. Numbers from the commit that
landed Phase 2; the two endpoints and their networks were not recorded.

| measure | value |
|---|---|
| payload | 8 MB, byte-identical both ways |
| QUIC handshake | 79 ms |
| throughput | 1.07 MiB/s, at the relay's per-session cap |

Findings:

1. Gate holds: a QUIC stream between two keys with no direct path. The 79 ms
   handshake is about two relay round trips at the ~40 ms measured earlier.
2. The throughput figure is the cap, not a transport ceiling. Re-measure with
   `--cap 0` on the relay before quoting relay throughput anywhere.
3. quinn moved natty's lockfile from 74 to 102 crates. It sits behind the
   default `quic` feature; `natty-relay` builds without it.

Open: the 2 s route watch that reconnects on a local-address change is in the
client but has not been measured on a real Wi-Fi to hotspot switch. Repeat the
Phase 1 switch and record detection time; expect low seconds, not 60.

## 2026-09-15: relay path, home to cellular (Phase 1 gate, extended)

Setup: `natty-relay` on a Hetzner VPS (scratch container, TLS on 443, STUN on
UDP). `examples/probe.rs` on a Pi at home behind the home router and on a
laptop, ping every 15 s, numbered message to the Pi's key each interval,
reconnect after three unanswered pings. Mid-run the laptop moved from home
Wi-Fi to an iPhone hotspot, so its path became hotspot NAT, carrier NAT (the
relay observed a carrier-owned source address), relay, home NAT.

| measure | value |
|---|---|
| round trip, laptop on home Wi-Fi | ~40 ms |
| round trip, laptop on cellular | ~51 ms |
| time to notice the dead session after the Wi-Fi switch | ~60 s (3 pings × 15 s) |
| time to reconnect once noticed | 254 ms |
| messages lost during the switch | seq 4-6, written into the dead session, no error |
| delivery after reconnect | seq 7 onward received continuously |

Findings:

1. Home to cellular forwarding works through two NATs on the client side and
   one on the server side. Phase 1 gate holds on real networks, not just LAN.
2. Nearly the whole outage was detection, not reconnection. A shorter ping
   timeout would cost battery on phones and laptops. The right fix is to
   reconnect on interface or default-route change and keep pings as the
   backstop. Added to Phase 2.
3. Frames written into a dead TCP session are silently lost. The relay path is
   datagram delivery with no reliability promise, which is fine under QUIC
   (it retransmits) and must never be relied on by signalling messages
   without their own retry. Stated in design.md.

Open: whether sessions survive hours of near-idle traffic on cellular and on
the home router (NAT mapping timeouts against the 15 s ping). Both probes left
running; analyse drops per network, reconnect times, round-trip percentiles,
and missing sequence numbers.
