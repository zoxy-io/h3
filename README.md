# h3

![GitHub License](https://img.shields.io/github/license/zoxy-io/h3?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-x86_64-linux.yml?label=x86_64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-aarch64-linux.yml?label=aarch64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-x86_64-windows.yml?label=x86_64-windows)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h3/test-macos.yml?label=macos)

QUIC, QPACK and HTTP/3 for Zig 0.16.

h3 is a sans-I/O protocol library. It parses and builds QUIC datagrams,
runs the connection state machine, loss recovery and congestion control,
and encodes and validates HTTP/3 messages. It does not open sockets, read a
clock, generate randomness or perform the TLS handshake; the caller supplies
all four. The library never allocates: a connection is a fixed-size value
whose limits are chosen at compile time.

## Status

Pre-release. The transport works end to end in tests: a handshake completes
through all three encryption levels, survives packet loss, carries streams
under flow control, updates keys, and an HTTP/3 request crosses a stream and
validates on the far side.

Not implemented yet:

- QPACK dynamic table, encoder and decoder streams
- HTTP/3 control stream, SETTINGS exchange, GOAWAY
- Connection migration, stateless reset, 0-RTT
- ECN (parsed, not acted on) and pacing
- Interoperability testing against other implementations

The full ledger is in [docs/DESIGN.md §6](docs/DESIGN.md#6-what-is-built-and-what-is-next).

## What is implemented

| RFC | Coverage |
|---|---|
| [9000](https://www.rfc-editor.org/rfc/rfc9000) QUIC transport | Variable-length integers, long and short headers, version negotiation, packet numbers, all twenty frame types, transport parameters, stream identifiers, error codes, the connection state machine, streams, stream- and connection-level flow control, address validation and the amplification limit |
| [9001](https://www.rfc-editor.org/rfc/rfc9001) QUIC TLS | Initial secrets, AEAD packet protection, header protection, Retry integrity tag, key update, AEAD confidentiality and integrity limits. AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 via `std.crypto` |
| [9002](https://www.rfc-editor.org/rfc/rfc9002) Loss detection | RTT estimation, packet- and time-threshold loss detection, probe timeout with backoff, NewReno with persistent congestion |
| [9204](https://www.rfc-editor.org/rfc/rfc9204) QPACK | Static table, field line representations in both directions. Prefixed integers and Huffman coding come from [hpack](https://github.com/zoxy-io/hpack) |
| [9114](https://www.rfc-editor.org/rfc/rfc9114) HTTP/3 | Frame layer, unidirectional stream types, settings, request and response validation per §4.2 and §4.3, including RFC 9220 extended CONNECT and RFC 9110 `content-length` syntax |

Key derivation, packet protection and packet number coding are checked
against the test vectors in RFC 9000 appendix A and RFC 9001 appendix A,
including the complete worked packets in `corpus/`.

## Installation

```sh
zig fetch --save git+https://github.com/zoxy-io/h3
```

```zig
// build.zig
const h3 = b.dependency("h3", .{
    .target = target,
    .optimize = optimize,
    // Optional. Assertions are on in every optimize mode unless disabled here.
    // .assertions = false,
});
exe.root_module.addImport("h3", h3.module("h3"));
```

h3 depends on [hpack](https://github.com/zoxy-io/hpack) and nothing else.

## Usage

A connection is a type instantiated with its limits. Every buffer inside it
is sized from these at compile time, and `footprint_octets` reports the
result.

```zig
const h3 = @import("h3");

const Connection = h3.quic.Connection(.{
    .streams_max = 16,
    .stream_receive_octets = 64 * 1024,
    .stream_send_octets = 16 * 1024,
});

var connection: Connection = .init(.{
    .side = .client,
    .original_destination = destination, // drawn at random by the caller
    .source = source,
});
```

The TLS handshake is exchanged as bytes. The caller runs its own TLS 1.3
engine and moves handshake messages and traffic secrets across:

```zig
// ClientHello from the TLS engine, framed into CRYPTO frames and sent.
try connection.cryptoIn(.initial, client_hello);

// Handshake bytes the peer sent, reassembled in order, for the TLS engine.
const from_peer = connection.cryptoOut(.initial);
connection.cryptoConsumed(.initial, from_peer.len);

// Traffic secrets the TLS engine derived, one per level and direction.
try connection.installSecret(.handshake, .send, &send_secret, .aes_128_gcm_sha256);
try connection.installSecret(.handshake, .receive, &receive_secret, .aes_128_gcm_sha256);
```

Datagrams move through caller-owned buffers, and time is passed in:

```zig
var buffer: [Connection.datagram_octets]u8 = undefined;

// Outbound. Each call fills at most one datagram.
while (connection.wantsSend()) {
    const octets = try connection.send(&buffer, now_ns);
    if (octets == 0) break;
    try socket.sendTo(buffer[0..octets], peer_address);
}

// Inbound. Decrypted in place; the datagram buffer is reused.
try connection.receive(datagram, now_ns);

// Timers. The caller arms its own timer and calls back at the deadline.
if (connection.timeout()) |deadline_ns| {
    // ... at deadline_ns:
    connection.onTimeout(deadline_ns);
}
```

Streams are addressed by identifier:

```zig
_ = try connection.write(0, request_bytes, true); // fin = true
const response = connection.readable(0);
try connection.consume(0, response.len);
```

[`example/initial.zig`](example/initial.zig) is a complete program at the
packet level: it builds a client Initial, seals it under the Initial keys,
then parses and opens it again. It is compiled and run as part of
`zig build ci`.

## Design constraints

- **No allocator.** `std.mem.Allocator` does not appear in the public API or
  under `src/`. Limits are comptime parameters; a peer's transport parameters
  are checked against them, never used to size anything.
- **No I/O.** No `std.Io`, `std.posix`, `std.net` or `std.fs` under `src/`.
  The build's lint step enforces this.
- **No clock, no entropy.** Every time-dependent function takes `now_ns`;
  connection identifiers and other random values are arguments. A connection
  can be replayed deterministically.
- **No TLS engine.** Handshake messages and secrets cross the API as data.
  Packet protection is inside the library, using `std.crypto` only.
- **Assertions are a build option.** They are on by default in every
  optimize mode and removed with `-Dassertions=false`. See
  [`src/assert.zig`](src/assert.zig).

The reasoning behind each is in [docs/DESIGN.md](docs/DESIGN.md).

## Building and testing

```sh
zig build ci                                             # fmt, unit tests, fuzz corpus, RFC corpus, example, lint, requirements
zig build ci -Doptimize=ReleaseFast                      # release, assertions on
zig build ci -Doptimize=ReleaseFast -Dassertions=false   # release, assertions off
zig build fuzz --fuzz                                    # coverage-guided fuzzing
zig build requirements                                   # RFC citations against the vendored specs in specs/
zig build sim -- --seeds 4096                            # seeded network simulation; --seed N replays one
zig build bench                                          # packet protection and codec microbenchmarks
zig build fmt-fix                                        # reformat
```

CI runs the three `ci` invocations above on x86_64 and aarch64 Linux,
Windows and macOS.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): scope, the I/O boundary, where TLS
  attaches, what is built and what is next.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md): the coding rules the lint and
  the review enforce.
- [docs/VERIFICATION.md](docs/VERIFICATION.md): the testing gaps, how other
  QUIC implementations test, and the plan.

## License

[MIT](LICENSE)
