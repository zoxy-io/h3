# h3 — design

What this package is, where its edges are, and which decisions are already made
against which are still open. [README.md](../README.md) is the short version;
this is the argument behind it.

---

## 1. The scope is five RFCs, not three

The request that started this package named RFC 9114 (HTTP/3), RFC 9204 (QPACK)
and RFC 9000 (QUIC transport). Two more are here, and they are not scope creep —
without either one the other three do not run.

**RFC 9001 — Using TLS to Secure QUIC.** RFC 9000 describes packets whose
payloads are, without exception, encrypted. There is no plaintext mode. The bits
that say how long a packet number is are themselves protected, so a parser that
stops at RFC 9000 cannot read a single packet — not even the first Initial, whose
keys are derived from a salt printed in RFC 9001 and the client's own connection
identifier. A package containing RFC 9000 and not RFC 9001 is a package that
cannot parse anything.

**RFC 9002 — Loss Detection and Congestion Control.** QUIC has no retransmission
in RFC 9000: a lost packet is gone, and it is RFC 9002 that decides what was
lost and re-sends the frames that were in it. A sender without it stalls at the
first dropped datagram. For zrk specifically it is worse than a stall — a load
generator without congestion control does not measure a server, it measures
whether the network buffered enough.

Both are in `src/quic/`, because they are one protocol with three documents. See
§3 for what stays outside.

**What each RFC contributes:**

| RFC | What comes from it | Where |
|---|---|---|
| 9000 | varints, packet headers, packet numbers, 20 frame types, transport parameters, stream identifiers, error codes | `src/varint.zig`, `src/quic/` |
| 9001 | Initial secrets, packet protection, header protection, Retry integrity, key update | `src/quic/crypto/` |
| 9002 | RTT estimation, loss detection, PTO, congestion control | `src/quic/Recovery.zig` |
| 9204 | prefixed integers, static table, field line representations, encoder/decoder streams | `src/qpack/` |
| 9114 | frame layer, unidirectional stream types, settings, message validation | `src/frame.zig`, `src/stream.zig`, `src/fields.zig` |

## 2. The boundary moves, compared with h2

h2 keeps the connection state machine *out*: it is a frame codec and HPACK, and
zoxy and zrk each write their own HTTP/2 connection. That was the right call
there, because an HTTP/2 connection state machine is thin and mostly policy — a
few dozen lines of "what do I do about a malformed message", answered
differently by a proxy and by a load generator.

It is the wrong call here, and this is the single biggest design decision in the
package. In QUIC the state machine **is** the protocol:

- packet number spaces and the ACK ranges that track them,
- flow control at two levels, with the connection-level accounting that stops a
  peer opening a stream to consume the connection's whole window,
- the amplification limit (RFC 9000 §8.1: three times what an unvalidated
  address sent) that stops the server being a reflector,
- loss detection and congestion control,
- key update, and the AEAD confidentiality and integrity limits (RFC 9001 §6.6)
  that force one.

Every item on that list is security-critical, and every one of them would be
written twice — once in zoxy, once in zrk — if this package stopped at codecs.
Two implementations of the amplification limit is one implementation of the
amplification limit and a reflector.

So: **h3 owns the QUIC connection.** It stays sans-I/O, allocation-free and
runtime-agnostic, which is what §3 is about.

## 3. The seam: datagrams in, datagrams and events out

The consumer owns exactly four things this package refuses to touch.

**The socket.** `zig build lint` forbids `std.Io`, `std.posix`, `std.os`,
`std.net` and `std.fs` under `src/`. zoxy drives libxev completion callbacks and
zrk drives zio green threads through `std.Io`; a reader, a writer or a file
descriptor in a signature excludes one of them. The temptation is stronger here
than it was in h2 — a QUIC stack *wants* to own a UDP socket, because
`recvmmsg`, GSO and ECN are all socket-level — and the answer is that those are
the consumer's to use, with this package told the results.

**The clock.** `now` is a parameter, in nanoseconds, on every function whose
behaviour depends on time. Nothing here calls `clock_gettime`. That is what lets
zoxy's deterministic simulator drive a QUIC connection on a virtual clock, and
it is what makes loss recovery testable at all — a PTO that fires after a real
second is a test nobody runs.

**Randomness.** Connection identifiers, PATH_CHALLENGE payloads, stateless reset
tokens and the client's initial packet number all need unpredictable bytes.
This package draws none: they arrive as arguments. Same reason as zssl's
identical rule — a seeded simulation can replay a connection byte for byte —
and the same cost, which is that the consumer must actually supply good entropy.

**The TLS handshake.** §4.

**Timers** come back the other way: `Connection.timeout()` answers the absolute
time the caller must wake it at, and the caller arms whatever its runtime uses.

## 4. Where TLS attaches

QUIC needs TLS 1.3. This package does not implement it, will not implement it,
and does not depend on a package that does.

The reason is concrete rather than aesthetic: **zoxy uses ztls and zrk uses
zssl.** They are different libraries with different backends, and neither
consumer wants the other's linked into its binary. A dependency here on either
one would make this package unusable by the other consumer — which is the same
argument that keeps `std.Io` out of the seam, applied to a different axis.

So the handshake attaches as **data, in both directions**:

```
      consumer's TLS engine                    h3
    ────────────────────────────────────────────────────────────
      ClientHello octets            ──▶  cryptoIn(.initial, bytes)
                                          (framed into CRYPTO frames,
                                           protected, sent)

      ◀── cryptoOut(.handshake)          CRYPTO frames received at a
                                          level, reassembled in order

      installSecret(.handshake, .receive, secret, suite)  ──▶
      installSecret(.handshake, .send,    secret, suite)  ──▶

      transport parameters, as the extension's octets, both ways
```

No function pointers, no vtable, no callback into the consumer's runtime. Five
entry points and a `Level` enum, which is why `crypto.Level` and
`crypto.Secret` are public types rather than internal ones — they are the shared
vocabulary, not implementation detail.

What the consumer owes in return: certificate verification, hostname checking,
ALPN, and the decision about 0-RTT. Those are policy, they differ between a
proxy and a benchmark client, and zrk already carries them for TLS over TCP
(`src/tls.zig`) — this reuses that work rather than duplicating it.

**Packet protection is a different question and lands the other way.** It is
computation, not policy: AES-GCM, ChaCha20-Poly1305, one raw AES block for
header protection, HKDF-SHA256/384. All of it is in `std.crypto`, so
`src/quic/crypto/` needs no dependency and the `dependencies` table stays empty.
Keeping the AEAD here rather than in the consumer is not optional either — the
nonce construction, the header protection sampling offset and the key update
accounting are where QUIC's cryptographic mistakes live, and they belong beside
the packet parser that produces their inputs.

## 5. No allocator, with a QUIC-sized asterisk

h2's rule — no `std.mem.Allocator` anywhere in `src/`, every buffer caller-owned
and caller-sized — carries over unchanged, and `zig build lint` enforces it.

It is harder to keep here, because a QUIC connection has genuinely open-ended
state: sent-packet records awaiting acknowledgement, stream send and receive
buffers, an ACK range set, the QPACK dynamic table, and a set of connection
identifiers per side. The answer is the one zoxy already uses for its own
memory: **the connection is comptime-parameterised by its limits**, so every
buffer is a fixed array whose size is a closed-form function of constants the
consumer picked.

```zig
const Connection = h3.quic.Connection(.{
    .streams_bidirectional_max = 128,
    .stream_receive_buffer_octets = 64 * 1024,
    .sent_packets_max = 1024,
    .ack_ranges_max = 32,
    .connection_ids_max = 8,
});
```

That shape is what lets zoxy print a connection's exact footprint at startup,
which is its whole pitch, and it is why the limits are comptime rather than
runtime: a `Connection` whose size is not knowable at compile time cannot be
placed in a pre-allocated arena of them.

The two consumers will pick very different numbers. zrk wants many small
connections; zoxy wants a bounded arena sized at startup. Neither number belongs
in this package.

## 6. What is built, and what is next

**Built and tested** (115 unit tests, 10 fuzz targets, `zig build ci` green on
all three build legs):

- `varint.zig` — RFC 9000 §16, with appendix A.1's vectors.
- `quic/packet_number.zig` — §17.1, with appendix A.2 and A.3's pseudocode.
- `quic/ConnectionId.zig` — §5.1.
- `quic/packet.zig` — §17's headers, both forms, all four long types, Version
  Negotiation, and unknown versions; parse and write.
- `quic/frame.zig` — §19's twenty frame types, parse and encode, with §12.4's
  Table 3 and ACK ranges as an iterator over the wire bytes.
- `quic/transport_parameters.zig` — §18, with the defaults and the ranges.
- `quic/error_code.zig` — §20 and RFC 9114 §8.1.
- `quic/stream_id.zig` — §2.1.
- `quic/crypto/` — RFC 9001 §5.1, §5.2, §5.3, §5.4, §5.8 and §6.1. **Verified
  against RFC 9001 appendix A.1's known-answer vectors**: both Initial secrets
  and all six key/IV/header-key values.
- `frame.zig`, `stream.zig` — RFC 9114 §6.2, §7.1, §7.2.4, §11.2.
- `corpus/` — RFC 9001 appendix A's four worked packets, octet for octet.
- `quic/Reassembler.zig` — ordered byte reassembly, for the CRYPTO stream and
  for every request and response stream. Section 2.2's "data at an offset never
  changes" and section 4.5's final size.
- `quic/AckRanges.zig` — the received-packet set for one number space, and the
  ACK frames rendered from it (sections 13.2 and 19.3).
- `quic/Recovery.zig` — RFC 9002: RTT estimation, packet- and time-threshold
  loss detection, the PTO with its backoff, and NewReno — slow start, recovery,
  per-packet window growth (appendix B.5) and persistent congestion (section
  7.6). Not "RFC 9002 entire", which this line claimed before anyone counted:
  **ECN is parsed but not acted on** (an `ACK_ECN` frame's counts reach
  `frame.Ack.ecn` and go no further, so section 7.3.2's congestion signal is
  ignored) and **there is no pacer** (section 7.7, a SHOULD). Both are listed in
  §6's ledger rather than hidden here. It never learns what a packet contained;
  `Config.Context` is an opaque token the connection attaches on send and gets
  back on loss.
- `qpack/field_line.zig` — RFC 9204 section 4.5's representations, both
  directions, against the static table with the dynamic table disabled.
- `fields.zig` — RFC 9114 sections 4.2 and 4.3: the octet rules and the
  pseudo-header rules, which between them are the guard against smuggling
  through an HTTP/1.1 downgrade.
- `quic/Streams.zig` — streams, their states, and both levels of flow control.
  The connection-level window is the one that bounds memory; see the file.
- `quic/Connection.zig` — the state machine, including RFC 9001 section 6's key
  update and section 6.6's AEAD confidentiality and integrity limits. The state machine: three packet number spaces, four
  encryption levels and their keys, CRYPTO reassembly per level, ACK
  generation, section 12.4's frame permissions, section 8.1's amplification
  limit, section 14.1's Initial padding, section 4.9's key discarding, and the
  close sequence. The TLS seam of §4 above, implemented.
- `qpack/static_table.zig` — RFC 9204 appendix A. §4.1.1's integer and §4.1.2's
  Huffman code come from zoxy-io/hpack and are re-exported by `qpack.zig`.

**Next, in the order they unblock each other:**

1. **QPACK field lines** (RFC 9204 §4.5). Enough to decode a field section
   against the static table with the dynamic table disabled, which is what a
   consumer advertising `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` needs — and zrk
   already makes exactly that choice for HPACK, for exactly the same reason (see
   `zrk/src/h2conn.zig`, `advertised_header_table_size`). Huffman is no longer
   part of this slice: it arrives from hpack already fuzzed.
2. **RFC 9114 §4.3 message validation.** The pseudo-header and field-name rules
   that decide whether a response is a message at all. Nearly identical to
   h2's `fields/`, and the same request-smuggling surface.
3. ~~**RFC 9002 recovery.**~~ — done, and wired into the connection. RTT
   estimation, both loss thresholds, the PTO with its exponential backoff, and
   NewReno. Pure computation over a caller-supplied `now`, so a probe timeout is
   tested by moving a number rather than by waiting a second. A handshake now
   survives a dropped datagram, which is the property the whole document exists
   for.

   "Wired into the connection" was a claim before it was a fact. The window was
   computed, halved, floored and unit-tested for weeks while `canSend` had no
   callers at all, so the sender obeyed nothing: `Connection.sendPacket` now
   consults it and rolls the packet back when it does not fit, exempting
   ACK-only packets and PTO probes. A congestion controller nothing calls is a
   comment. Still open, and deliberately: **ECN** (section 7.3.2 — the counts
   are parsed into `frame.Ack.ecn` and dropped) and **pacing** (section 7.7, a
   SHOULD). Both matter more to zoxy than to zrk, and neither blocks a
   handshake.
4. **The connection.** The largest item, and the one everything else serves. It
   decomposes into three pieces that are worth building and reviewing apart,
   because two of them are pure data structures with no policy in them:

   a. ~~**`Reassembler`**~~ — done.
   b. ~~**`AckRanges`**~~ — done.
   c. ~~**The connection itself**~~ — done, less the two things below, which
      belong to other slices and are named at the top of `Connection.zig` so a
      reader meets them before the code:

      * Nothing. Slice 5 landed on top of it.
5. ~~**Streams and flow control.**~~ — done. `quic/Streams.zig` carries the
   stream states of sections 3.1 and 3.2, the final size rules of 4.5, and both
   levels of flow control from 4.1. What is left of this item is the HTTP/3
   request layer on top, which needs QPACK first and so has swapped places with
   item 6.
6. ~~**QPACK field line representations**~~ and ~~**RFC 9114 section 4.3
   message validation**~~ — done. An HTTP/3 request now crosses a QUIC stream
   and validates at the far end, which is the whole of what this package was
   asked for.

   What remains is depth rather than reach:

   * **QPACK's dynamic table**, its encoder and decoder streams, and blocked
     streams. Not needed by a consumer advertising
     `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, which is the choice zrk already
     makes for HPACK; needed to compress as well as a browser does.
   * **The HTTP/3 connection layer** — the control stream, SETTINGS exchange,
     GOAWAY, and the request/response state machine over `Streams`. The frames
     and stream types are built; what is missing is the sequencing.
   * **Migration, stateless reset, 0-RTT, and ECN.**
   * **A second corpus**: encodings captured from other implementations, the
     way hpack vendors http2jp/hpack-test-case. RFC 9001 appendix A proves
     agreement with the specification, not with the implementations a real peer
     is running.

**Corpus — done.** RFC 9001 appendix A's four worked packets are in `corpus/`,
machine-lifted from the RFC text and checked octet for octet. The strongest case
is A.2: sealing the appendix's header and payload reproduces its 1200-octet
protected packet exactly, which needs the nonce, the associated data, the AEAD,
the sampling offset, the mask and the masked bits all correct at once. See
`corpus/README.md` for why that is a different kind of evidence from a
round-trip, and for the second corpus — encodings from other implementations —
which is still outstanding and belongs with the connection slice.

## 7. Open decisions

**The field syntax is stated twice.** `fields.zig`'s octet rules are RFC 9110's
and so are h2's `fields/syntax.zig`'s, which means the two files say the same
thing in two repositories — the same situation RFC 7541's primitives were in
before hpack. It is smaller (a hundred lines against nine hundred) and h2's
version is vectorised where this one is not, so the trade is not identical. Left
alone deliberately, and recorded here so the next person notices it on purpose
rather than by surprise.

**Huffman: port, share, or rewrite? — settled.** RFC 9204 §4.1.2 uses RFC 7541's
Huffman code unchanged, and §4.1.1 its prefixed integer. Three options were on
the table: copy them, depend on `zoxy-io/h2`, or extract a shared package.

The answer was to extract, and to extract *more* than the shared part:
[zoxy-io/hpack](https://github.com/zoxy-io/hpack) now holds RFC 7541 whole — the
Huffman code, the integer, both tables and the representations — and h2
re-exports it as `h2.hpack`. Taking only the two shared pieces was tried first
and produced a package called hpack whose README had to open by explaining that
it was not HPACK; moving the whole RFC made the name true and gave h2 one job.

This package builds against `huffman` and `integer` and nothing else there. The
policy that replaced "zero dependencies" is **no dependency outside the
organisation, and none that pulls in a runtime or a libcrypto**; hpack has none
of its own, so the graph is one deep.

The width is the one thing the two protocols differ on, and it is a parameter:
`Integer(u32)` in h2, `Integer(u62)` here, because QPACK's values are bounded by
a QUIC stream offset rather than by an HTTP/2 SETTINGS value.

**Does `-Dassertions=false` still make sense here?** In h2 the argument for it is
that zrk is a latency-measuring tool and HPACK decode is on its hot path. Here
the hot path includes packet protection, where the per-packet cost is dominated
by the AEAD rather than by invariant checks. The option is implemented and
defaults to on; the first measurement says the trade is much weaker than it was
in h2 (`zig build bench -Druns=3 -Diterations=1000000`, one laptop, so read the
shape rather than the digits):

| row | assertions on | assertions off | delta |
|---|---:|---:|---:|
| varint decode | 3.84 ns | 2.85 ns | −1.0 ns |
| quic frame parse | 8.63 ns | 2.93 ns | −5.7 ns |
| http3 frame header | 2.94 ns | 2.62 ns | −0.3 ns |
| packet seal (aes-128-gcm) | 389.3 ns | 386.9 ns | within noise |
| packet seal+open | 941.0 ns | 937.3 ns | within noise |

A packet costs ~390 ns to seal and carries many frames; the assertions save a
few nanoseconds per frame against that. So the argument that carried in h2 —
"decode is new mandatory cost on zrk's hot path" — does not obviously carry
here, and turning the checks off in a stack that manages nonces wants a better
reason than habit. **Recommendation: zrk inherits the default (on) until a
profile of a real run says otherwise.** This is a change from what zrk does with
h2, and it should be a deliberate one.

**How much of RFC 9002 is policy?** NewReno is the RFC's own algorithm and
belongs here. CUBIC and BBR are not in RFC 9002 at all, and a load generator and
a proxy may reasonably want different ones. The likely shape is a
comptime-selected controller behind a small interface, with NewReno as the only
one shipped — but that is a decision for slice 3, informed by what the pluggable
seam actually costs.

## 8. Threat model

The same as h2's, for the same reason: **write every parser for zoxy's threat
model**, which is the open internet, on the assumption that the peer is trying
to make this code allocate, loop, or read out of bounds. zrk's inputs are
friendlier, but a stack with two threat models is a stack with one threat model
and a bug.

QUIC adds two surfaces h2 did not have, and they are worth naming because they
are not parser bugs:

- **Amplification.** An unvalidated address must not receive more than three
  times what it sent (RFC 9000 §8.1), or the server is a DDoS reflector for
  anyone who can spoof a source address. This is connection state, not parsing,
  which is part of why §2 puts the connection in this package.
- **Key commitment.** RFC 9001 §6.6 sets confidentiality and integrity limits
  per key — a count of packets sealed, and a count of failed authentications
  tolerated. Exceeding either is a connection error. They are counters that no
  parser test would catch and that a consumer would not think to write.
