# natty wire design (draft 1)

The reasons for the security rules are in [research.md](research.md#wire-decisions).

## Identities

- Key: an Ed25519 public key, 32 bytes, z-base-32 in text. Peer address: `<key>@<relay-host>`.
- Peers use QUIC with TLS 1.3 and RFC 7250 raw public keys (ed25519). The dialer sends no SNI. It accepts only the dialed key. The listener accepts any key.
- Each side lets its peer open 32 bidirectional streams at once and no unidirectional streams. A further stream waits until another one ends.
- Only allowed keys learn the addresses of an endpoint and get a direct path. A dial allows the dialed key.

## Relay session (TCP)

The client opens TLS 1.3 to the relay on port 443. Both sides refuse TLS 1.2. The client sends `GET /natty HTTP/1.1` with `Connection: Upgrade` and `Upgrade: natty/1`. After `101 Switching Protocols`, the connection carries frames.

Frame: type (u8), payload length (u32, big-endian), payload. The payload is at most 2048 bytes. A greater length is a protocol error.

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

- Address: family `4` or `6`, 4 or 16 address bytes, port (u16). IPv4-mapped addresses go as IPv4.
- CLOSE reasons: 0 normal, 1 protocol error, 2 auth failed, 3 idle, 4 replaced. An unknown reason reads as normal.
- After the handshake, the receiver ignores unknown frame types. A bad payload of a known type closes the session with reason 1.

Handshake:

1. Both sides derive `ekm = TLS-Exporter("EXPORTER-natty-relay-auth-v1", "", 32)`.
2. The client sends CLIENT_HELLO: its key and `Ed25519-Sign(key, "natty relay auth v1\0" || ekm)`. It can send the hello in the same write as the request. The relay never reads past the request head.
3. The relay answers WELCOME. A bad signature gets CLOSE 2. Any other first frame gets CLOSE 1.

Session rules:

- The relay delivers SEND as RECV if `dst` has a session on the same relay. Otherwise, it answers PEER_GONE. A dialer connects to the relay of the peer.
- Delivery is best effort. Messages above the relay need their own retry.
- Peer keys come from the QUIC handshake and from signed punch messages, never from `src` in RECV.
- One session per key. A new session for a key closes the old one with CLOSE 4.
- Epoch: the start time of the relay in Unix nanoseconds. A new epoch after a reconnect means that all peers are gone.
- An idle client sends PING every 15 s. The relay closes a session that is silent for 60 s with CLOSE 3. Each side answers PING with PONG.
- The relay closes a session when one write to it takes longer than 10 s. A client gives up on a write after 45 s.
- Cap: the datagram bytes per second that a session can send. The relay drops the excess.

## STUN responder (UDP)

The relay host answers RFC 5389 binding requests on the port in WELCOME, with XOR-MAPPED-ADDRESS only.

## Direct path

QUIC, punch messages and STUN share one UDP socket per address family. The first bytes give the kind:

- STUN binding response: first byte `0x01`, magic cookie in bytes 4 to 8.
- Punch message: `2a 6e 74 79` (`*nty`).
- QUIC: all other datagrams. QUIC bit greasing (RFC 9287) is off. QUIC packets have the fixed bit `0x40`. STUN and punch messages start below `0x40`.

An endpoint accepts QUIC over UDP only from proven addresses. QUIC Initials go only through the relay, in the two directions.

Punch message: `magic (4) | type (1) | signer (32) | body | signature (64)`. The signature is `Ed25519-Sign(signer, "natty punch v2\0" || every preceding byte)`.

| type | name | path | body |
|---|---|---|---|
| 1 | CANDIDATES | relay | reply wanted (u8), probe key (32), addresses |
| 2 | PROBE | UDP | nonce (12) |
| 3 | PROBE_ACK | UDP | nonce (12) |

- CANDIDATES: signed by the endpoint key, at most 8 addresses, IPv6 first, no duplicates. Reply wanted asks for one CANDIDATES without it.
- The probe key is a new Ed25519 key for each punch. It signs PROBE and PROBE_ACK. The endpoint key never goes over UDP.
- The receiver drops CANDIDATES from a key that is not allowed or with the probe key of another key. It drops a PROBE with an unknown probe key.
- A PROBE from `S` with the probe key of `K` gets a PROBE_ACK to `S` with the same nonce. `S` then becomes proven for `K` only.
- A PROBE_ACK counts only if it comes from a candidate or proven address of `K` and holds the current nonce. Each nonce counts once.

## Tunnel

The `tunnel` feature serves TCP services by name with the ALPN `natty-tunnel/1`. The dialer opens one bidirectional stream for each TCP connection:

1. The dialer sends a service name or `?`, then `\n`. The line has at most 64 bytes before `\n`. It must arrive within 10 s.
2. The host answers one status byte. After a line that is too long, empty or not UTF-8, it ends the stream with no status.
3. After status 0, both sides copy bytes. The end of one direction is a TCP half-close. The stream ends when both directions end.

- Names: 1 to 63 letters, digits and hyphens. The host trims white space and compares in lower case.
- `?` gets status 0, the names that the dialer can open, one per line, then the end of the stream. The dialer reads at most 64 KiB and keeps at most 256 valid, distinct names.
- Status: 0 OK, 1 DENIED (no grant), 2 UNKNOWN (no such service), 3 UNAVAILABLE (no upstream connection within 10 s). The dialer reads all other values as a refusal.
- The dialer stops 15 s after it opens the stream if the status or the end of the listing has not arrived. The host stops after 10 s if the dialer does not read the status or the listing.
- The dialer key comes from the QUIC handshake. The dialer never sends an address.
- The host checks the grant before the service. Without a grant, every name gets DENIED. A listing holds only granted services that exist.
- When a grant goes, or its service gets another upstream or none, its open streams end. When a key loses its entry in the grants, its connections close. The host allows only the keys with a grant.
- The host counts a connection against a key before the handshake. That key is the sender of the first Initial, as the relay gives it. Each key with an entry in the grants has 4 connections. All other keys share 8. The host has 64 connections in total. Past a limit, the host refuses the handshake. A handshake that does not end within 10 s stops.
- Close codes: 1 for a peer with no key, 3 for a key that lost its entry in the grants. The host does not send code 2.

## What the relay knows

- The keys that are online, their addresses and the lifetime of each session.
- The pairs of keys that exchange frames, and the byte counts.
- The local and reflexive addresses and the probe keys of peers that punch. CANDIDATES carry a signature, not encryption.
- The ALPN of each connection, from the first QUIC packet.

The relay never sees the QUIC payload. The relay code keeps aggregate counters only, with no log for each session.
