# h3

![GitHub License](https://img.shields.io/github/license/zoxy-io/h3?color=orange)

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
| [9114](https://www.rfc-editor.org/rfc/rfc9114) HTTP/3 | Frame layer, unidirectional stream types, the connection layer — control stream, SETTINGS exchange, GOAWAY and §4.1's frame sequence — and request and response validation per §4.2 and §4.3, including RFC 9220 extended CONNECT and RFC 9110 `content-length` syntax. No server push and no QPACK dynamic table |

Key derivation, packet protection and packet number coding are checked
against the test vectors in RFC 9000 appendix A and RFC 9001 appendix A,
including the complete worked packets in `corpus/`.

Evidence that does not come from this package: `corpus/qifs.zig` decodes 144
QPACK field sections produced by four other implementations, and `interop/` is
a [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
client that completes a real handshake, Retry, and HTTP/3 transfer against
quic-go, ngtcp2 and aioquic — and a server that passes all 49 of
[h3spec](https://github.com/kazu-yamamoto/h3spec)'s conformance cases. Between
them they found eleven defects; they are in the table in
[docs/VERIFICATION.md](docs/VERIFICATION.md) §1, the shims are §5.5, and
[interop/README.md](interop/README.md) is how to run them.

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
zig build ci                                             # fmt, unit tests, fuzz targets, RFC corpus, example, lint, requirements, sim
zig build ci -Doptimize=ReleaseFast                      # release, assertions on
zig build ci -Doptimize=ReleaseFast -Dassertions=false   # release, assertions off
zig build fuzz --fuzz                                    # coverage-guided fuzzing
zig build requirements                                   # RFC citations against the vendored specs in specs/
zig build sim -- --seeds 4096                            # seeded network simulation; --seed N replays one
zig build bench                                          # packet protection and codec microbenchmarks
zig build fmt-fix                                        # reformat
```

### The gates

One workflow per gate, because a single job that ran everything could only
ever say "something broke". Each badge below is that gate's own verdict, and
the row beside it says what a green one means:

| Gate | What it proves | Builds |
| --- | --- | --- |
| [![test](https://github.com/zoxy-io/h3/actions/workflows/test.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/test.yml) [`test`](.github/workflows/test.yml) | The unit tests, and everything `zig build test` depends on: the lint's own tests, the ledger's, the simulator's, the RFC corpus, the fuzz targets, the README example, the negative fixture and the interop shims | all three |
| [![sim](https://github.com/zoxy-io/h3/actions/workflows/sim.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/sim.yml) [`sim`](.github/workflows/sim.yml) | 256 seeds of the seeded network simulation, its oracles, and a coverage census that fails the run when a behaviour no seed reached would otherwise pass quietly | all three |
| [![fuzz](https://github.com/zoxy-io/h3/actions/workflows/fuzz.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/fuzz.yml) [`fuzz`](.github/workflows/fuzz.yml) | The 16 fuzz targets, each run once as a regression with a deterministic draw — their oracles hold and their accept paths still compile. Under the builds that ship, not only under Debug | all three |
| [![corpus](https://github.com/zoxy-io/h3/actions/workflows/corpus.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/corpus.yml) [`corpus`](.github/workflows/corpus.yml) | RFC 9001 appendix A's worked packets octet for octet, and qifs's QPACK field sections from four other implementations | all three |
| [![requirements](https://github.com/zoxy-io/h3/actions/workflows/requirements.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/requirements.yml) [`requirements`](.github/workflows/requirements.yml) | Every `//=` citation quotes the RFC section it names, verbatim, and every exception states a reason | source scan |
| [![lint](https://github.com/zoxy-io/h3/actions/workflows/lint.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/lint.yml) [`lint`](.github/workflows/lint.yml) | No I/O types, no allocator, no unbounded loops and no `std.debug.assert` under `src/` | source scan |
| [![checks](https://github.com/zoxy-io/h3/actions/workflows/checks.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/checks.yml) [`checks`](.github/workflows/checks.yml) | `checks/` holds a fixture that must *fail* to compile — a `comptime` assertion still fires with `-Dassertions=false` | Debug on, ReleaseFast off |
| [![example](https://github.com/zoxy-io/h3/actions/workflows/example.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/example.yml) [`example`](.github/workflows/example.yml) | The usage example above compiles and runs | Debug |
| [![interop](https://github.com/zoxy-io/h3/actions/workflows/interop.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/interop.yml) [`interop`](.github/workflows/interop.yml) | The interop shims build, natively and statically for the endpoint image | ReleaseFast |
| [![bench](https://github.com/zoxy-io/h3/actions/workflows/bench.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/bench.yml) [`bench`](.github/workflows/bench.yml) | The benchmark still compiles and runs. **Not a measurement**: a shared runner cannot produce a band worth comparing, so the numbers it prints mean nothing | ReleaseFast |
| [![fmt](https://github.com/zoxy-io/h3/actions/workflows/fmt.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/fmt.yml) [`fmt`](.github/workflows/fmt.yml) | Formatting, over the path list that lives in `build.zig` and nowhere else | — |

"All three" is Debug, ReleaseFast, and ReleaseFast with `-Dassertions=false`.
The last is the one that matters most and the one a local Debug run cannot
substitute for: `-Dassertions=false` in Debug removes the `if (!ok)` and
nothing else, so only a release mode tests the elision — and only a release
mode reaches the undefined behaviour that a `catch unreachable` guarded by a
removed assertion becomes.

Not a per-change gate, and so not in the table:
[![nightly-sim](https://github.com/zoxy-io/h3/actions/workflows/nightly-sim.yml/badge.svg)](https://github.com/zoxy-io/h3/actions/workflows/nightly-sim.yml) [`nightly-sim`](.github/workflows/nightly-sim.yml)
sweeps 4096 seeds under all three builds every night, from a range no earlier
night has run.

There is no per-operating-system matrix. This library opens no sockets, reads
no clock and calls into no platform API, so what a second operating system
exercised was the Zig toolchain rather than this package — and it cost four
copies of every gate to say so.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): scope, the I/O boundary, where TLS
  attaches, what is built and what is next.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md): the coding rules the lint and
  the review enforce.
- [docs/VERIFICATION.md](docs/VERIFICATION.md): what each gate proves and what
  it cannot, the fifty-odd defects they found, and how other QUIC stacks test.

## License

[MIT](LICENSE)
