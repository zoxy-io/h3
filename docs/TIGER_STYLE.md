# h3 style — adopted from h2's, which adopted zoxy's

h3 adopts [h2's TIGER_STYLE](https://github.com/zoxy-io/h2/blob/main/docs/TIGER_STYLE.md),
which adopts [zoxy's](https://github.com/zoxy-io/zoxy/blob/main/docs/TIGER_STYLE.md),
which adopts [TigerBeetle's](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
Those are the source of truth. This file records only the **deltas** that owning
a transport, rather than a codec, forces.

> Design goals, in priority order: **safety, performance, developer experience.**

Read h2's file first — it is short, and its deltas section is the part that
governs. Everything in it applies here unless listed below.

---

## What h2's rules mean here

### No allocator

Unchanged as a rule, harder as a practice. h2's only genuinely stateful
structure is HPACK's dynamic table; a QUIC connection has sent-packet records,
stream buffers, an ACK range set, a connection identifier set and a QPACK
dynamic table, all of them open-ended in principle.

The answer is **comptime-parameterised limits**: `Connection(config)` produces a
type whose every buffer is a fixed array sized from constants the consumer
picked, so a connection's footprint is a closed-form function a consumer can
print at startup. See [DESIGN.md §5](DESIGN.md#5-no-allocator-with-a-quic-sized-asterisk).

The corollary is a rule of its own: **a limit that is not comptime is a bug**.
A runtime-sized buffer inside a `Connection` defeats the whole arrangement, and
it will be reached for the first time someone wants a peer's transport parameter
to size something. It cannot: a peer's parameter is checked *against* our limit,
never used as one.

### No I/O types in the seam

Unchanged, and the temptation is much stronger. A frame codec merely *wants* to
be `readFrame(reader)`; a QUIC stack wants to own the socket outright, because
`recvmmsg`, GSO, ECN and the pacing timer are all socket-level and doing them
well is most of what makes a fast QUIC implementation fast.

It still cannot. The two consumers do not share a runtime. What the package does
instead is make those things *expressible* by the consumer: `send` fills a
caller buffer and says how many datagrams of what size are in it, so a consumer
with GSO can hand the whole thing to one `sendmsg` and a consumer without it can
loop.

### Put a limit on everything

More load-bearing than in h2, and for a structural reason. An HTTP/2 frame
carries its length; a QUIC frame does not. A packet payload is a run of frames
that ends when the payload does, so "consume until the buffer is done" is the
natural shape of nearly every loop in this package — and therefore the natural
shape of nearly every bug in it.

Every such loop must have a bound a reader can see. For a frame loop the bound
is structural — each frame consumes at least one octet — and the *assertion
saying so* is what makes it a checked claim rather than a comment. `zig build
lint` refuses a bare `while (true)` without one.

### Explicitly-sized integers

Here it is the wire format, again more so than in h2. A packet number is 62
bits, truncated to 1-4 octets on the wire; a connection identifier length is 8
bits with a maximum of 20; a variable-length integer is 6, 14, 30 or 62 usable
bits; a stream identifier's low two bits are a type tag. A `usize` in this
codebase is almost always a bug, and a `u64` that should have been bounded to
`varint.max` is the specific bug that produces an unencodable value three layers
later.

## What is new

### `now_ns` is a parameter

Nothing here reads a clock. Every function whose behaviour depends on time takes
`now_ns: u64`, and the connection answers `timeout()` with the absolute time it
must next be woken at. This is not only the sans-I/O rule restated: it is what
makes loss recovery testable, because a PTO that fires after a real second is a
test nobody runs, and it is what lets zoxy's deterministic simulator drive a
connection on a virtual clock.

### Randomness is a parameter

Connection identifiers, PATH_CHALLENGE payloads, stateless reset tokens and a
client's initial packet number all need unpredictable bytes, and this package
draws none of them. Same rule as zssl, same payoff: a seeded simulation replays
a connection byte for byte.

The cost is real and belongs in a review: a caller that passes predictable bytes
gets a connection an off-path attacker can interfere with, and nothing in this
package can detect that.

### Cryptographic state is not ordinary state

Three rules that have no analogue in h2, because h2 holds no keys.

- **A nonce is used once.** The packet number is the nonce (RFC 9001 §5.3), so a
  packet number reused under one key is a confidentiality failure, not a
  protocol error. Any code path that could produce the same number twice in one
  space is a defect regardless of whether a test catches it.
- **A failed authentication is not an error to report.** RFC 9001 §5.4: discard
  the packet. An off-path attacker can inject packets at will, so tearing down a
  connection on one is the attack rather than the defence. The distinction
  between "discard" and "connection error" is stated at every error value in
  `crypto/protect.zig` for this reason.
- **Key limits are counters someone must keep.** RFC 9001 §6.6 caps how many
  packets a key may seal and how many forgeries it may survive. Nothing about
  parsing enforces them, so they are the connection's, and they are the kind of
  requirement that is quietly skipped and never noticed.

### An assertion may not be the only guard on a `catch unreachable`

Inherited from h2, restated because the stakes moved. h2's fallout from
violating it once was a livelock. Here an `unreachable` behind a removed
assertion sits in code that manages nonces and buffer offsets into a packet.
Every `catch unreachable` and every `=> unreachable` in this package carries a
comment naming the *returned error or exhaustive switch* that makes it
unreachable — never an assertion.

## What does not apply

### h2's "the slow resource is CPU and memory bandwidth"

Half-true here. QPACK and the frame codecs are CPU-bound the way HPACK is, but
the packet path is dominated by two things h2 has neither of: **the AEAD**, and
**syscalls per datagram**. The second is the consumer's to amortise (GSO,
`sendmmsg`), and the seam is shaped to let it. The first is `std.crypto`'s, and
the honest position is that this package's contribution to it is the framing
around the primitive, not the primitive — which is exactly what `zig build
bench`'s two protection rows measure.

The back-of-the-envelope discipline still applies, against those resources.

## Threat model

zoxy's, which is the stricter one, unchanged from h2 — plus the two surfaces
[DESIGN.md §8](DESIGN.md#8-threat-model) names that are not parser bugs:
amplification, and the key limits of RFC 9001 §6.6.

## Gates this package adds

- **Every RFC test vector that exists ships as a test.** RFC 9000 appendix A,
  RFC 9001 appendix A, RFC 7541 appendix C for the QPACK integer. A derivation
  verified only against itself is a derivation verified against nothing, and the
  QUIC key schedule is the clearest case: the labels, the salt and the HKDF
  structure are all independently guessable-wrong, and only a published vector
  catches all three at once.
- **Every parsing change ships with its fuzz coverage.** `fuzz/` holds the
  targets; a decode path without one is not done.
- **Interoperability, before the connection slice.** RFC 9001 appendix A's
  complete packets, and encodings captured from other implementations. See
  [DESIGN.md §6](DESIGN.md#6-what-is-built-and-what-is-next).
