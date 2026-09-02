# h3

![GitHub License](https://img.shields.io/github/license/zoxy-io/h3?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-x86_64-linux.yml?label=x86_64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-aarch64-linux.yml?label=aarch64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-x86_64-windows.yml?label=x86_64-windows)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-macos.yml?label=macos)

QUIC and HTTP/3 in Zig. A library, not a program: it is built to be consumed by
[zoxy](https://github.com/zoxy-io/zoxy) (reverse proxy, libxev completion
callbacks) and [zrk](https://github.com/zoxy-io/zrk) (load generator, zio green
threads through `std.Io`), which is why it owns no socket, no clock and no TLS
engine.

**Status: in progress, and it works end to end.** A handshake completes,
survives a dropped datagram, and an HTTP/3 request crosses a QUIC stream and
validates at the far end. What is left is depth rather than reach — QPACK's
dynamic table, the HTTP/3 control stream and SETTINGS exchange, migration, and
a corpus from other implementations. See
[docs/DESIGN.md §6](docs/DESIGN.md#6-what-is-built-and-what-is-next).
[docs/DESIGN.md §6](docs/DESIGN.md#6-what-is-built-and-what-is-next) is the
ledger — read it before depending on this.

## Scope

* **RFC 9000 — QUIC transport.** Variable-length integers, packet headers,
  packet numbers, the twenty frame types, transport parameters, stream
  identifiers, error codes, the connection state machine, streams, and both
  levels of flow control.
* **RFC 9001 — packet protection.** Initial secrets, AEAD packet protection,
  header protection, the Retry integrity tag, key update.
* **RFC 9002 — loss detection and congestion control.** RTT estimation, both
  loss thresholds, the PTO, and NewReno, including per-packet window growth and
  persistent congestion. ECN is parsed and not yet acted on, and there is no
  pacer; both are tracked in docs/DESIGN.md §6 rather than implied away here.
* **RFC 9204 — QPACK.** The static table and section 4.5's field line
  representations, both directions. The prefixed integer and the Huffman code
  come from [hpack](https://github.com/zoxy-io/hpack), which holds the RFC 7541
  originals QPACK adopts unchanged. The dynamic table is planned — an endpoint
  advertising `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` does not need it, and
  that is the choice zrk already makes for HPACK.
* **RFC 9114 — HTTP/3.** The frame layer, the unidirectional stream types, the
  settings, and sections 4.2 and 4.3's message validation — the octet rules and
  the pseudo-header rules that between them guard against request smuggling
  through an HTTP/1.1 downgrade, including RFC 9220's extended CONNECT, the
  `:authority`/`Host` agreement section 4.3.1 requires, and `content-length`'s
  own syntax. The control stream and SETTINGS exchange are planned.

RFC 9001 and RFC 9002 were not in the original ask and are not optional
additions: RFC 9000 describes packets whose payloads are always encrypted, so a
package without RFC 9001 cannot parse one, and a sender without RFC 9002 stalls
at the first lost datagram.
[docs/DESIGN.md §1](docs/DESIGN.md#1-the-scope-is-five-rfcs-not-three) has the
argument.

Out of scope, permanently: **the UDP socket, the clock, randomness, and the TLS
handshake.** Each of those is a place where the two consumers differ, and a
package that chose for them would be unusable by one of them.
[docs/DESIGN.md §3](docs/DESIGN.md#3-the-seam-datagrams-in-datagrams-and-events-out)
and [§4](docs/DESIGN.md#4-where-tls-attaches).

## Properties

* Never allocates — no `std.mem.Allocator` in the public API. A connection is
  comptime-parameterised by its limits, so its footprint is a closed-form
  function a consumer can print at startup.
* Never copies where a slice will do. A CRYPTO frame's data, a STREAM frame's
  data and an ACK's ranges all borrow from the caller's datagram.
* Caller-owned, caller-sized buffers. Packet protection works in place, in the
  buffer the datagram arrived in.
* One dependency, [hpack](https://github.com/zoxy-io/hpack), which has none of
  its own — it carries RFC 7541, of which QPACK adopts the Huffman code and the
  prefixed integer unchanged. The rule is **no dependency outside the
  organisation, and none that pulls in a runtime or a libcrypto**. Packet
  protection is the one thing that would normally reach for libcrypto, and
  `std.crypto` covers all of it: AES-GCM, ChaCha20-Poly1305, a raw AES block for
  header protection, and HKDF-SHA256/384.
* Assertions ship by default, in every optimize mode. `-Dassertions=false`
  removes them for a consumer that has made that argument — see
  [`src/assert.zig`](src/assert.zig) for why this is not `std.debug.assert`.
* Datagrams in, events out — no socket, no reader, no writer and no `std.Io` in
  the seam. `now` is an argument; randomness is an argument; TLS handshake bytes
  are arguments in both directions. `zig build lint` enforces the first.

## Verified against the RFCs' own vectors

The key schedule is the part of QUIC where three independent things can each be
subtly wrong — the salt, the HKDF-Expand-Label structure, and the labels — and
where a mistake in any of them produces keys that look fine and decrypt nothing.
So it is checked against RFC 9001 appendix A's published values rather than
against itself:

| Vector | Source |
|---|---|
| Client and server Initial secrets | RFC 9001 §A.1 |
| Client key, IV and header-protection key | RFC 9001 §A.1 |
| Server key, IV and header-protection key | RFC 9001 §A.1 |
| Variable-length integer encodings | RFC 9000 §A.1 |
| Packet number encoding and decoding | RFC 9000 §A.2, §A.3 |
| Prefixed integers | RFC 7541 §C.1, via RFC 9204 §4.1.1 (in hpack) |

## Usage

One client Initial packet, built and read back — every layer in the order a real
client uses them:

```zig
const h3 = @import("h3");
const quic = h3.quic;

// RFC 9001 section 5.2: the Initial keys come from the destination connection
// identifier of this very packet.
const keys: quic.crypto.Keys = .initial(destination.bytes(), .client);

// The payload is a run of frames. Here, one CRYPTO frame holding whatever the
// consumer's TLS engine produced — this package never builds a ClientHello.
const crypto_octets = try quic.frame.encode(&payload, .{
    .crypto = .{ .offset = 0, .data = client_hello },
});

// The header. `writeLong` returns exactly the two offsets `seal` asks for,
// which is the join this package exists to make.
const written = try quic.packet.writeLong(&datagram, .{
    .long_type = .initial,
    .destination = destination,
    .source = source,
    .payload_octets = payload_octets,
    .number = 0,
    .number_octets = 4,
});
const total = try keys.seal(
    &datagram,
    written.packet_number_offset,
    written.header_octets,
    payload_octets,
    0,
);

// --- and on the way back in ---

// Phase one: everything legible before the keys are involved. It cannot read
// the packet number, because the bits saying how long that is are encrypted —
// what it finds is where the number *begins*.
const parsed = try quic.packet.parse(datagram[0..total], 0);
const offset = parsed.header.packetNumberOffset().?;

// Phase two: header protection off, number reconstructed, payload decrypted,
// all in the same buffer.
const opened = try keys.open(datagram[0..total], offset, null);

var frames: quic.frame.Iterator = .init(opened.payload);
while (try frames.next()) |frame| switch (frame) {
    .crypto => |value| { /* hand value.data to the TLS engine */ },
    .padding, .ping => {},
    else => {},
};
```

[`example/initial.zig`](example/initial.zig) is the whole thing, padded to the
1200 octets RFC 9000 §14.1 requires. It is a compiled, run program rather than a
snippet — `zig build example`, and `zig build ci` runs it — so a usage example
that stopped building fails the build instead of greeting the next reader.

Nothing above allocates, and nothing above touches a socket: `datagram` is the
caller's buffer, and what to do with it is the caller's business.

## Gates

```sh
zig build ci      # format check, tests, the lint's own tests, fuzz corpus, boundary lint
zig build ci -Doptimize=ReleaseFast                     # zoxy's build
zig build ci -Doptimize=ReleaseFast -Dassertions=false  # zrk's build
zig build bench   # packet protection and codec microbenchmarks (ReleaseFast)
zig build fuzz    # replay the fuzz corpus; --fuzz to actually fuzz
zig build fmt-fix # reformat in place
zig build example # build and run the usage example above
```

## Reading order

* [docs/DESIGN.md](docs/DESIGN.md) — the scope, the seam, where TLS attaches,
  what is built and what is next, and the decisions still open.
* [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — the enforced coding rules: h2's,
  plus the deltas that owning a transport rather than a codec forces.
