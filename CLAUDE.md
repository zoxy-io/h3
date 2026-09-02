# h3

QUIC (RFC 9000, 9001, 9002), QPACK (RFC 9204) and HTTP/3 (RFC 9114) in Zig 0.16.
A library, not a program: it is consumed by
[zoxy](https://github.com/zoxy-io/zoxy) (reverse proxy, libxev completion
callbacks) and [zrk](https://github.com/zoxy-io/zrk) (load generator, zio green
threads through `std.Io`). Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — **read this first.** The scope, the seam,
  where TLS attaches, and the ledger of what is built against what is next. The
  boundary here is deliberately *not* h2's, and §2 is why.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — enforced coding rules. h2's,
  plus the deltas owning a transport forces; the deltas are the part to read.
- [README.md](README.md) — scope, and what is permanently out of it.

## Gates — run before every commit

- `zig build ci` — the format check, unit tests, the lint's own tests, the fuzz
  corpus, the usage example and the boundary lint. This is exactly what CI runs,
  on each target natively.
- `zig build ci -Doptimize=ReleaseFast` and
  `zig build ci -Doptimize=ReleaseFast -Dassertions=false` — the two builds that
  ship, zoxy's and zrk's. Not optional, and the Debug run above does *not*
  substitute: `-Dassertions=false` in Debug removes the `if (!ok)` and nothing
  else, so only a release mode tests that the checks are gone, and only a
  release mode reaches the undefined behaviour a `catch unreachable` guarded by
  a removed assertion becomes. CI runs all three legs.
- `zig build bench` — the performance gate. **Not optional for a change that
  touches a protection or codec path.** Compare bands across runs, never single
  numbers: a 3% move between two runs on a laptop is noise, and reporting it as
  a regression trains everyone to ignore the gate.
- The format gate is part of `zig build ci`, and `zig build fmt-fix` rewrites.
  The list of formatted paths lives in build.zig and nowhere else, so CI cannot
  check a different set than you do. A PostToolUse hook auto-formats files as
  they are edited.

## Review — required before every commit

Run the `tiger-style-reviewer` agent on the diff before committing a slice. The
automated gates cover formatting, the boundaries, and behavior; the agent covers
the rules only a reader can check — assertion density, function length, bounded
loops, explicitly-sized integers, and whether a new limit is a named constant.

This is not a formality here. The two consumers point this code at different
threat models, and the stricter one — zoxy's, which is the open internet — is
not represented by any test that runs on a laptop.

## Policies

- **No dependencies.** `build.zig.zon` has an empty `dependencies` table.
  `@cImport` is lint-forbidden. Packet protection is the one place that would
  otherwise reach for libcrypto, and `std.crypto` covers it. Note
  [docs/DESIGN.md §7](docs/DESIGN.md#7-open-decisions) has an open question
  about sharing Huffman with h2, which is the one thing that might change this.
- **No allocator, anywhere.** `std.mem.Allocator` does not appear in `src/`, and
  `zig build lint` enforces it. Every buffer is caller-owned and caller-sized. A
  connection's state is comptime-parameterised by its limits, so **a limit that
  is not comptime is a bug** — a peer's transport parameter is checked *against*
  our limit, never used as one.
- **No I/O types in the seam.** No `std.Io`, `std.posix`, `std.os`, `std.net`,
  `std.fs` under `src/`, lint-enforced. The temptation is specific and stronger
  than it was in h2: a QUIC stack wants to own a UDP socket, because `recvmmsg`,
  GSO and ECN are socket-level. It cannot — the two consumers do not share a
  runtime. Datagrams in, datagrams and events out.
- **`now` and randomness are parameters.** Nothing here reads a clock or draws
  entropy. That is what makes loss recovery testable and what lets zoxy's
  simulator replay a connection.
- **TLS is the consumer's.** zoxy has ztls, zrk has zssl; this package takes
  handshake bytes and secrets as data and never links either. Packet protection
  is the opposite call and lives here — see docs/DESIGN.md §4 for why the two
  halves land on different sides.
- **An assertion may not be the only guard on a `catch unreachable`.** Every one
  in this package carries a comment naming the returned error or the exhaustive
  switch that makes it unreachable. h2 violated this once and the fallout was an
  uninterruptible spin; here the same mistake sits in code that manages nonces.
- **Assertions are a build option, not a consequence of the optimize mode.**
  `std.debug.assert` is lint-forbidden under `src/`. Use
  `@import("../assert.zig").assert`.
- **Every bound is a named constant** with a comptime assert relating it to its
  neighbours. A QUIC frame carries no length, so "consume until the buffer ends"
  is the shape of nearly every loop here and therefore of nearly every bug.
- **Every RFC test vector that exists ships as a test.** A derivation verified
  only against itself is verified against nothing. RFC 9001 appendix A's key
  schedule is the clearest case and is already in `crypto/`.
- **Every parsing change ships with its fuzz coverage.** `fuzz/` holds the
  targets; a decode path without one is not done. Zig 0.16 hands the target a
  `*std.testing.Smith`, so inputs are *drawn* rather than cast out of a buffer.
- **Write to zoxy's threat model**, which is the stricter one. Plus the two
  surfaces that are not parser bugs: the amplification limit (RFC 9000 §8.1) and
  the AEAD key limits (RFC 9001 §6.6).
- **Workflow:** small slices, one commit per slice, descriptive commit messages.
  Push and open PRs only when asked.
