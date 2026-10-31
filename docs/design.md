# natty wire design (draft 1)

Every section below is specified. The direct path is measured on real networks through one NAT, and between one pair of NATs that remap on an early packet (docs/results.md).

## Identities

- Endpoint identity: Ed25519 public key, 32 bytes. Displayed z-base-32.
- A peer is addressed by `<key>@<relay-host>`. Nothing else is needed to dial.
- TLS between peers (QUIC) uses RFC 7250 raw public keys, TLS 1.3 only,
  signature scheme ed25519. Each side presents its Ed25519
  SubjectPublicKeyInfo and nothing else: no certificate, no chain, no CA.
  The dialer requires the presented key to equal the dialed key. The acceptor
  takes any key and hands it to the application, which decides authorization.
  The dialer sends no SNI: the server name is the dialed key, and anyone who
  sees the first QUIC packet of a connection can read it.
- Separately, the application allows keys to traverse: an allowed key may
  learn this endpoint's addresses and get a direct path (see Punch). Dialing
  allows the dialed key; any other key needs an explicit allow, which can be
  given before the key is ever seen. Allowing is not needed to connect: an
  unallowed key is served through the relay.

## Relay session (TCP)

### Upgrade

- Client opens TLS 1.3 to the relay on 443. TLS 1.2 is refused by both ends:
  the auth binding below relies on the RFC 8446 exporter.
- Client sends `GET /natty HTTP/1.1` with `Connection: Upgrade` and
  `Upgrade: natty/1`. The relay answers `101 Switching Protocols`. Everything
  after is frames. The protocol version lives in the upgrade token.
- `GET /health HTTP/1.1` on the same listener returns `200` with aggregate
  counters as `name value` lines. Anything else gets `404` with a usage hint.
- The request head is capped at 4 KiB. Upgrade and hello must complete within
  10 s of TCP accept.

### Frames

Frame: 1-byte type, 4-byte big-endian payload length, payload. Max payload
2048 bytes, so a datagram is at most 2016 bytes: one QUIC packet at any MTU
quinn discovers by default (1452), with room to spare. The relay queues up to
256 frames per session, so a stalled receiver holds at most 512 KiB. An
endpoint drops larger datagrams as a link drops packets above its MTU. A
length above the maximum is a protocol error; the reader never allocates for
it.

| type | name | dir | payload |
|---|---|---|---|
| 1 | CLIENT_HELLO | c→s | key (32), signature (64) |
| 2 | WELCOME | s→c | epoch (u64), cap (u32 bytes/s, 0 = uncapped), STUN port (u16, 0 = none), observed addr |
| 3 | SEND | c→s | dst key (32), datagram |
| 4 | RECV | s→c | src key (32), datagram |
| 5 | PEER_GONE | s→c | key (32) |
| 6 | PING | both | nonce (8) |
| 7 | PONG | both | nonce (8) |
| 8 | CLOSE | both | reason (u8) |

- Address encoding: family byte `4` or `6`, then 4 or 16 address bytes, then
  port (u16). IPv4-mapped IPv6 addresses are sent as IPv4.
- CLOSE reasons: 0 normal, 1 protocol error, 2 auth failed, 3 idle,
  4 replaced. Unknown codes read as normal.
- Unknown frame types after the handshake are ignored, so types can be added
  without a version bump. A known type with a malformed payload closes the
  session with reason 1.

### Handshake

1. Both sides derive `ekm = TLS-Exporter("EXPORTER-natty-relay-auth-v1", "", 32)`.
2. Client sends CLIENT_HELLO: its key and
   `Ed25519-Sign(key, "natty relay auth v1\0" || ekm)`. It may send the hello
   in the same write as the upgrade request, without waiting for `101`; the
   relay reads the request head exactly and never past it.
3. The relay verifies and answers WELCOME, or sends CLOSE (2 for a bad
   signature, 1 for any other first frame) and closes.

The signature is bound to the TLS session, so a relay cannot replay a
client's proof to another relay. There is no relay-issued challenge; the
exporter is already unique per session. The context string keeps this
signature from colliding with other uses of the same key.

### Session rules

- Forwarding: SEND is delivered as RECV only if `dst` holds a session on this
  relay. Otherwise the relay replies PEER_GONE and drops it. No
  store-and-forward. Forwarding never crosses relays: a dialer opens its own
  session on the peer's relay.
- Delivery is best-effort datagram semantics end to end. Frames written into a
  session whose TCP peer has silently gone (NAT rebinding, network switch) are
  lost without error. QUIC retransmits; signalling messages carry their own
  retry. Nothing above the relay may assume delivery.
- One session per key. A new session for a key that is already connected
  replaces it; the old one receives CLOSE 4.
- Epoch: the relay's start time in Unix nanoseconds, compared for equality. A
  client that sees a different epoch after reconnecting treats every peer as
  gone and re-probes. (A start time is exact where "uptime went backwards"
  misses restarts that happen during a long disconnection.)
- Keepalive: the client sends PING every 15 s when idle. The relay answers
  PONG and closes a session that sends nothing for 60 s (CLOSE 3). Either
  side answers PING with PONG.
- Cap: the per-session byte budget applies to datagrams the session sends,
  as a token bucket with a burst of one second or one maximal frame,
  whichever is larger. Excess is dropped, never queued. Since forwarding is
  always within one relay, a pair gets the cap in each direction regardless of
  where either peer's standing session lives.
- Backpressure: each session has a bounded outbound queue (256 frames). A RECV
  for a full queue is dropped.
- Connection limit: concurrent TCP connections per IPv4 address or per IPv6
  /64, enforced at accept before TLS. Excess connections are closed without a
  response.

## STUN responder (UDP)

- RFC 5389 binding request and success response with XOR-MAPPED-ADDRESS only.
  Same host as the relay, on the UDP port set by `--stun` (3478 by default),
  which WELCOME carries. No attributes beyond that are parsed.

## Relay session client

One standing session per endpoint, kept by a background task.

- Connect times out after 10 s. A session that lasted at least one keepalive
  interval reconnects at once when it ends; a shorter one backs off from 1 s,
  doubling to 10 s, so two holders of one key cannot replace each other at
  full speed.
- Keepalive: the client sends PING every 15 s. Any received frame counts as
  liveness; 45 s with nothing received ends the session.
- Writes never block these checks: the writer runs beside the keepalive and
  route timers, so a write stuck on a dead link cannot hide it.
- Route watch: every 2 s the client asks the kernel which local address a
  connected UDP socket to the relay would use (no packet is sent). If it
  differs from the session's local address, the session ends and reconnects.
  This catches Wi-Fi to cellular moves in seconds instead of three keepalive
  intervals. Rotation of temporary IPv6 addresses also triggers it, at the
  cost of one reconnect.

## Virtual socket

A quinn `AsyncUdpSocket` whose address space is keys. quinn identifies paths
by socket address, so each key maps to a synthetic one: `fd` followed by the
first 15 bytes of the key, port 1. These addresses never reach a real socket.

- Outgoing datagrams become SEND frames on the relay session. Incoming RECV
  frames surface with the sender's synthetic address.
- Queues in both directions hold 1024 frames; a full queue drops, as a
  congested UDP socket would. The outbound queue is shared with the session's
  PING and PONG frames and is the only place outbound data is dropped: a
  stalled relay link backs it up rather than losing frames further down.
- The peer's identity comes from the QUIC handshake, never from the relay's
  `src` field or the synthetic address.
- This is the only place path selection happens: per key, the relay, a
  direct UDP path, or both (see Direct path).

## Direct path

Traversal runs beside QUIC, not inside it. quinn keeps one synthetic address
per key; underneath it the virtual socket moves datagrams between the relay and
a direct UDP path without quinn noticing. The relay session never goes away.

### UDP sockets and demultiplexing

Each endpoint binds one UDP socket per family (IPv4 required, IPv6 when the
host has it) on an ephemeral port. QUIC on a direct path, punch messages, and
STUN all use these sockets, so the mapping a probe opens in a NAT is the one
QUIC uses. A received datagram is, by its first bytes:

- a STUN binding response: first byte `0x01`, bytes 4 to 8 the magic cookie;
- a punch message: the magic `2a 6e 74 79` (`*nty`);
- otherwise QUIC, accepted only from an address proven for some key (below),
  else dropped.

QUIC bit greasing (RFC 9287) is disabled, so every QUIC packet carries the
fixed bit `0x40`; STUN and punch messages start below `0x40`. Datagrams
arriving through the relay are classified the same way; STUN among them is
dropped.

### Candidates

- Local: per family, the address the kernel would use toward a public
  destination (a routing lookup; nothing is sent) with that socket's port.
  Only the default-route interface is listed.
- Reflexive: a STUN binding response from the relay's responder (relay host,
  port from WELCOME), sent from the socket itself, per family. The
  transaction ID must match. Refreshed when a relay session starts, and when
  CANDIDATES go out and the last refresh is older than 30 s; a changed result
  goes out again to every punch still running.
- At most 8 addresses per message, IPv6 first, no duplicates.

### Punch messages

`magic (4) | type (1) | signer (32) | body | signature (64)`, where the
signature is `Ed25519-Sign(signer, "natty punch v2\0" || every preceding
byte)`. It is checked against the key in the message, never against the
relay's `src`.

CANDIDATES go through the relay, signed by the sender's key. CANDIDATES from a
key that is not allowed are dropped. They carry a probe key: a new Ed25519 key
that the sender makes for this peer at every punch. CANDIDATES that carry
another key's probe key are dropped.

PROBE and PROBE_ACK go over UDP, where anyone on the path reads them, so they
are signed by the sender's probe key, and neither endpoint's key appears. The
receiver looks the signer up among the probe keys of allowed keys. A signer it
does not find is dropped before the signature is checked, and such a PROBE
gets no PROBE_ACK, so a key that is not allowed never hears from the
endpoint's sockets.

| type | name | path | body |
|---|---|---|---|
| 1 | CANDIDATES | relay | reply wanted (u8), probe key (32), addresses (address encoding, repeated) |
| 2 | PROBE | UDP | nonce (12) |
| 3 | PROBE_ACK | UDP | nonce (12) |

PROBE and PROBE_ACK are the same size, so answering a replayed probe cannot
amplify.

### Punch

A key is tracked once the endpoint has dialed it or received QUIC from it
through the relay, until it is forgotten (see Path upkeep), and active while
that happened in the last 5 s. Tracking only routes replies through the relay;
it grants nothing. Every step below (sending or answering CANDIDATES, sending
or answering PROBE, accepting PROBE_ACK) applies only to allowed keys. At most
256 keys that are not allowed are tracked; past that, the one silent longest
is forgotten, and its relay connections lose their route until it sends
again. Allowed keys are never evicted this way, and forgetting a key never
forgets that it is allowed.

Revoking an allow ends any punch toward the key, drops its direct path and
proven addresses, and stops all of the above; open connections continue
through the relay. Addresses the key already learned cannot be taken back.

A punch toward an allowed peer starts when:

1. the peer is active, has no direct path, and no punch started in the last
   60 s (the endpoint initiates);
2. the relay session (re)connects, for every active peer (initiates);
3. CANDIDATES arrive and no punch started in the last 10 s (responds).

At most 8 punches run at once. Keys cost nothing, so the per-key gaps above do
not bound the probes an endpoint sends to addresses peers name; this cap does.
A punch without room does not start: case 1 retries on the next tick, and
CANDIDATES are still stored and answered.

During a punch, which lasts 3 s:

- The endpoint sends its candidates in CANDIDATES over the relay at the start
  and again whenever they change. An initiator sets reply wanted and repeats
  every second until CANDIDATES from the peer arrive.
- CANDIDATES with reply wanted are answered with CANDIDATES without it, at
  most once per 500 ms per peer. A reply never asks for a reply, so the
  exchange ends.
- At the start, and for each candidate that arrives later, it sends one PROBE with IPv4 TTL 2 (an opener). The opener passes a NAT on the first hop and expires before the peer, so it makes the local mapping without arriving early at the peer's NAT, which makes some NATs remap (docs/results.md, 2026-10-24). IPv6 gets no opener. The TTL is set on the shared socket for that one send.
- From 200 ms after the last opener, every 200 ms it sends PROBE to each of the peer's candidates, IPv6 first, then to each address proven for the peer that is not a candidate.
- It ends early once the peer has an IPv6 direct path.

A PROBE from source `S`, signed by `K`'s probe key, is answered with PROBE_ACK to `S`. `S`
becomes proven for `K`, and for no other key: QUIC from `S` is accepted as
`K`'s, and `S` is probed with `K`'s candidates, which is how a peer behind an
endpoint-dependent NAT is reached. Proven addresses, the newest 8 per key, are
kept apart from candidates, so new CANDIDATES from `K` do not drop them. If `S`
was neither a candidate nor proven and `K` has no direct path, a punch starts
as in case 3.

A PROBE_ACK from `S`, signed by `K`'s probe key, counts only if `S` is one of `K`'s
candidates or proven addresses (probes went there, so the answer must come
from there) and its nonce is `K`'s current one. The nonce is renewed after
every accepted ACK, so each ACK counts once. `S` becomes `K`'s direct path if
there is none, if the current one is untrusted, or if `S` is IPv6 and the
current one IPv4.

### Path upkeep

- Heard: any datagram from the path's address, QUIC or punch message.
- Trusted while heard in the last 5 s: QUIC goes only to the path.
- Untrusted: QUIC goes to the path and to the relay; QUIC discards the
  duplicates.
- A path is probed at most once a second: while untrusted and the peer is
  active, or after 25 s of silence (keepalive for the NAT mapping). A path
  whose probes go unanswered for 5 s is dropped, and case 1 may punch again
  at once, without waiting out its 60 s.
- A key with no QUIC for 60 s is forgotten with its paths.
- Each side of a QUIC connection sends a keep-alive after 15 s of inactivity.
  An idle connection thus outlives the 30 s QUIC idle timeout, and its key is
  not forgotten.

## What the relay knows

Keys online and their addresses, session lifetimes, which pairs exchange
frames, and forwarded byte counts. CANDIDATES are signed, not encrypted, so the
relay also sees the local and reflexive addresses of peers that punch, and
their probe keys. The first QUIC packet of a connection is not confidential, so the relay can read its ALPN. Never
QUIC payload. The code has aggregate
counters and no per-session log path.

## Open questions

- Encrypting CANDIDATES so the relay does not learn local addresses. ring has
  no static X25519, so this would mean carrying candidates inside the QUIC
  connection instead, which the application owns.
- Whether a dialer without a standing session can be punched to (client-only
  mode). Affects presence exposure. Test, then decide.

## Resolved

- CANDIDATES on interface change: yes. A route change reconnects the relay
  session, and a reconnect punches toward every active peer.

- Frame-level compression over the relay: no. QUIC packets are encrypted and
  do not compress, and compression over attacker-influenced data invites
  length side channels.
- Cap semantics across relays: forwarding is always within one relay (the
  dialer connects to the peer's relay), so the cap is per sending session.
