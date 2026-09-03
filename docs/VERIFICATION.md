# h3 — verification

Why the review keeps finding what the gates do not, what the other QUIC stacks
run that this package does not, and the order in which to close the gap.
Written 2026-09-02 against commit `07684e1`. [DESIGN.md](DESIGN.md) is the
argument for the code; this is the argument for the evidence.

---

## 1. The signal

The last eight commits fixed roughly twenty defects. Every one of them was found
by an agent reading the code, and not one by `zig build ci`. That is the signal
this document exists to explain, and the explanation is not "there are no
tests". There are 252 unit tests, 16 fuzz targets, and RFC 9001 appendix A's
four packets checked octet for octet. What there is none of is the three kinds
of evidence that would have caught this particular list.

Each finding, with the gate that would have caught it first:

| Finding | Commit | Gate that would have caught it |
|---|---|---|
| The congestion window was computed, halved, floored and unit-tested, and `sendPacket` never consulted it | `5d1897b` | A requirement ledger (§4.1), or a simulator invariant that in-flight octets never exceed the window |
| `stream_id.sendable` and `kindOf` existed and nothing called them | `014e7ca` | The ledger, plus a coverage report over the unit test run: a MUST implemented by an uncovered function is a finding |
| Absent entirely: the AEAD limits of RFC 9001 §6.6, persistent congestion, the receive half of the 1200-octet floor, five of RFC 9114 §4's rules | `19cf6fb`, `5d1897b`, `014e7ca`, `11d4587` | The ledger |
| A FIN was re-framed into every packet forever, and `wantsSend` never answered false again | `7c17728` | A simulator liveness oracle: the pair must go quiet within bounded virtual time |
| `writePayload` committed ACK debt, cursors and a probe before `seal` was known to succeed | `7c17728` | Simulator fault injection: a send buffer that is sometimes too small |
| A server re-adopted the client's source connection identifier from any Initial it could open | `014e7ca` | A simulator adversary node that seals Initial-keyed packets |
| ACK range eviction defeated duplicate suppression; a RESET_STREAM moved a final size a FIN had fixed; reset credit was never released | `a3ce1c9`, `014e7ca` | Model-based property tests: `AckRanges` against a bitset, `Streams` against a flow-control ledger |
| Three overflows on peer-chosen 62-bit values | `3e5a7ae` | Fuzz targets that draw the field at its wire width. The recovery target draws `delay` as a `u16`, so the overflow at 2^62 was unreachable by construction |
| Seven `catch unreachable` and subtractions guarded only by an assertion | `d23c798` | Fuzz and simulation run under `-Doptimize=ReleaseFast -Dassertions=false`. Today the fuzz corpus replays in Debug with assertions on, so the build that ships is never the build that is fuzzed |
| A comptime "proof" that set 256 flags and checked 256 flags | `6f46be7` | Nothing automated short of mutation testing; noted for honesty |
| Two fuzz targets could not reach the paths their comments claimed: the connection target never padded to 1200 and drew the packet number twice, so no packet it built ever authenticated; the recovery target pinned `range_count = 0`, so the ACK range walk was unreachable | `b9c796d` | A coverage report over a fuzz run. Both targets passed for years of CPU time because "discarded" is a legal outcome, and neither a corpus replay nor a crash-free `--fuzz` run can tell covering a path from never reaching it |

Three patterns in that table are worth more than the rows.

**Half the findings are a MUST that was never implemented, or was implemented
and never wired in.** No quantity of unit tests finds a requirement nobody wrote
down as missing. That needs a list of requirements derived from the RFC text,
not from the code.

**A target that cannot reach a path still passes.** This is the fuzz-shaped
version of the row below it, and it is worse, because a fuzz target reports
CPU-hours rather than a verdict a reader can check. Both defects were in the
*generator*, not the code, and both were invisible to every gate: the corpus
replayed, `--fuzz` found nothing, and the reason was that the input was refused
at the door. Any target whose accept path is not itself asserted by a
deterministic test is a target that may be proving nothing — which is why
`b9c796d` adds four such tests rather than only fixing the draws.

**The `AckRanges` tests asserted the bug.** `expect(!set.contains(0))` after an
eviction was the violation, written down as the design. A test written by the
author of the code shares the author's reading of the RFC, and passes for the
same reason the code is wrong. Only evidence from outside escapes that: the
RFC's own vectors, encodings other implementations produced, a live peer, or a
requirement list extracted from the specification.

There is a third signal, and it is structural. zoxy's
[DESIGN.md §9](https://github.com/zoxy-io/zoxy/blob/main/docs/DESIGN.md) states
"a feature without its gate is not done" and runs a deterministic simulator on
every change: 4096 seeds, a coverage census, a nightly sweep of millions of
seeds, replay by seed. This package's seam — no clock, no randomness, no I/O, no
TLS engine — was designed so that simulator could drive a connection. The
simulator never crossed over. The whole pair harness here is one function that
moves a datagram from one `Connection` to another.

## 2. What the gates are today

| Gate | What it proves | What it cannot prove |
|---|---|---|
| 252 `test` blocks | Each function does what its author meant | That the author read the RFC correctly, or that anything calls the function |
| 16 fuzz targets, Debug, assertions on | Decoders reject or parse with no third outcome | Anything about the shipping builds; anything a `u16` draw cannot reach; and — until `b9c796d` — whether a target reaches its accept path at all, which two of them did not |
| `corpus/`, RFC 9001 appendix A | The key schedule, AEAD, nonce, sampling offset and mask are right at once | Anything after the first flight |
| `zig build lint` | No I/O, no allocator, no unbounded loop | Nothing about behaviour |
| The `tiger-style-reviewer` agent | Assertion density, function length, named bounds | It is a reader, not a gate: it found the twenty above, and it will not find the same class twice at the same cost |
| `zig build requirements` | That every RFC quote in the source is really in the section it cites, and that every exception states a reason | Coverage — the sentence extraction is a heuristic, so `7 cited / 571 mandatory` is a trend to move, not a threshold to pass |

Missing outright: a seeded simulator, an interop image, a QPACK
cross-implementation corpus, qlog output, and any run of the fuzz targets in a
release mode. The requirement ledger of §5.1 now exists; §5.2's simulator is
the next item, and it is the one the ledger's oracles feed.

## 3. What the other stacks do

Verified against the repositories on 2026-09-02. Counts are `grep` and
approximate.

| Stack | In-memory pair | Network model | Fuzz | Traceability or formal | Interop runner |
|---|---|---|---|---|---|
| [quinn](https://github.com/quinn-rs/quinn) | `Pair` with a simulated clock, `step()` advances to the next wakeup | Tests hand-edit the queues: `pair.client.inbound.clear()` | 4 cargo-fuzz targets | none; no RFC 9001 vectors either | yes |
| [quiche](https://github.com/cloudflare/quiche) | `Pipe`, manual `now` | Tests hand-drop flights | 5 libFuzzer targets, corpus checked in | RFC 9001 appendix A in `packet.rs`; qlog parsed back in tests | yes |
| [neqo](https://github.com/mozilla/neqo) | `test-fixture` | Seeded discrete-event simulator: `Delay`, `Drop`, `TailDrop` with DSL presets, MTU, `SIMULATION_SEED` | 12 targets | RFC 9001 vectors fed to a server | every PR, against its own baseline image |
| [s2n-quic](https://github.com/aws/s2n-quic) | `io::testing::Model` with `set_drop_rate`, `set_jitter`, `set_corrupt_rate` | Monte-Carlo `s2n-quic-sim` over TOML plans, published plots | bolero at 186 sites, `quic-attack` | 102 Kani proofs; duvet with 1393 RFC citations and a published report | yes, published |
| [picoquic](https://github.com/private-octopus/picoquic) | `sim_link.c`: virtual time, rate, latency, tail-drop queue | 64-bit rotating loss mask, AQM, Wi-Fi jitter, link suspend; 570 scenario tests | in-suite fuzz and stress modes | golden qlog and trace diffs | yes |
| [ngtcp2](https://github.com/ngtcp2/ngtcp2) | `ngtcp2_tpe` encodes hand-built frames into a conn under test | new `examples/sim` with seeded loss and a goodput bound | 5 targets, ClusterFuzzLite every six hours | none | yes; nghttp3 checks QPACK against qifs |
| [msquic](https://github.com/microsoft/msquic) | loopback sockets | datapath loss hook by percentage | `spinquic` random API driver, OSS-Fuzz | none | own interop client |
| [quic-go](https://github.com/quic-go/quic-go) | `simnet` under Go `synctest` | a `Drop func(Packet) bool` router | 8 native targets, OSS-Fuzz | none | yes |

Three things stand out.

**Every serious stack runs client and server in one process on a virtual
clock.** This package already can; that is what `installBoth` and `deliver` in
`Connection.zig`'s tests are. The difference is what sits between the two
endpoints: a hand-written call in quinn and quiche, a seeded link model in neqo,
picoquic and s2n-quic.

**The two stacks with the fewest surprises added a randomized network model and
a spec-derived requirement list.** picoquic's 570 scenarios are the reason it
is the reference implementation the formal-methods papers test against.
s2n-quic's duvet report is the only public artifact that answers "which MUSTs
in RFC 9000 does this code cite, test, or excuse", per section, per requirement.

**Every one of them ships an interop image.** A shared misreading of the RFC
survives every test its author writes. The
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
has 17 participants and 24 columns, and among them are exactly the surfaces
this package got wrong on its own: `keyupdate`, `amplificationlimit`,
`handshakeloss`, `transferloss`, `retry`, `chacha20`, `goodput`.

### The harness shapes, for reference

neqo, the closest to this package's seam:

```rust
simulate!(transfer_taildrop, [
    Node::default_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
    TailDrop::dsl_downlink(),          // 1 MB/s, 32 KiB buffer, 50 ms
    Node::default_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
    TailDrop::dsl_uplink(),
]);
```

picoquic, the deterministic loss mask:

```c
/* one bit per packet, rotating, so every seed is a replayable schedule */
loss_bit = *loss_mask & 1; *loss_mask >>= 1; *loss_mask |= loss_bit << 63;
```

s2n-quic, the requirement citation the ledger of §4.1 adopts:

```rust
//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
//# In order to assist loss detection at the sender, an endpoint SHOULD
//# generate and send an ACK frame without delay when it receives an ack-
//# eliciting packet either:
should_activate |= !is_largest;
```

## 4. Cross-implementation tooling

- **[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)**
  — active, results at [interop.seemann.io](https://interop.seemann.io/). Three
  containers: an ns-3
  [network simulator](https://github.com/quic-interop/quic-network-simulator)
  with `simple-p2p`, `drop-rate`, `corrupt-rate`, `droplist`, `blackhole`,
  `rebind` and cross-traffic scenarios, a server, a client. An endpoint image
  reads `ROLE`, `TESTCASE`, `REQUESTS`, writes `SSLKEYLOGFILE` and `QLOGDIR`,
  serves `/www`, exits 127 for a test case it does not support. Verdicts are
  byte-exact file comparison plus pcap analysis with the key log.
- **[h3spec](https://github.com/kazu-yamamoto/h3spec)** — active, 50 negative
  cases against a listening server: 34 transport and TLS, 16 HTTP/3 and QPACK.
  Each mutates a frame, a transport parameter or a TLS extension and expects a
  specific error code. Its case list is the closest thing to a public MUST
  catalogue for the surfaces `fields.zig` and the connection guard.
- **[qifs](https://github.com/qpackers/qifs)** — QPACK field sections encoded by
  ten implementations, in the
  [offline interop format](https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop):
  `[stream id u64][length u32][bytes]`, stream 0 the encoder stream, table
  capacity and blocked-stream count in the filename. Last touched 2021 and
  still what nghttp3 and ls-qpack check against. The capacity-zero encodings
  are decodable by this package's static-only decoder today.
- **[duvet](https://github.com/awslabs/duvet)** — extracts every MUST, SHOULD
  and MAY sentence from an RFC, matches `//=` and `//#` citations in source,
  reports per section: cited, implemented, tested, exception, todo. Zig and
  Rust share line comments, so the tool may run on this tree unchanged; if not,
  the format is small enough for a script in `scripts/`.
- **[qlog](https://github.com/quicwg/qlog)** — still Internet-Drafts at
  version 14 of the main schema; `qvis` renders it. No stack keeps golden qlog
  fixtures except picoquic. aioquic and quic-go assert on individual events.
- **quic-tracker** — dead at draft-29; not worth targeting.
- **Formal** — McMillan and Zuck's Ivy model (SIGCOMM 2019) and its draft-29
  extension found real bugs in seven stacks, including client-sent NEW_TOKEN
  and errors at the wrong encryption level.
  [PANTHER](https://github.com/ElNiak/PANTHER) is the active successor and is
  research tooling; usable, not a gate.

## 5. The shape of the fix

In the order that each one unblocks or cheapens the next, with a cost that is
an estimate rather than a promise.

### 5.1 A requirement ledger — first, days — **started**

Vendor the five RFC texts under `specs/`; `corpus/extract.py` already parses
RFC 9001's. Adopt duvet's convention in `src/` and in tests: a `//=` line naming
`rfcNNNN#section-X.Y`, `//#` lines quoting the requirement, and
`//= type=test`, `type=exception` with a `reason=`, or `type=todo`. A script
lists every MUST, MUST NOT and SHOULD as cited, tested, excepted, or missing,
and `zig build ci` fails on a missing MUST that no exception names.

This is the gate that would have listed §6.6's limits, §7.6's persistent
congestion, §14.1's receive half and RFC 9114 §4.3.1 as absent before any
reviewer did. It also turns "canSend has no callers" into a mechanical finding:
a requirement whose only citation is in a function the tests never enter. It
comes before the simulator because a simulator finds only what an oracle
states, and the ledger is where the oracles come from.

**Status.** `specs/` holds RFC 9000, 9001, 9002, 9110, 9112, 9114 and 9204.
`scripts/requirements.zig` runs as `zig build requirements` and is part of
`zig build ci`. It reads 849 sections across seven RFCs and finds **1206
normative sentences, 849 of them mandatory**.

**Every mandatory requirement in the five documents this package implements is
cited: 566 of 566.** RFC 9110 and RFC 9112 are *referenced* rather than
implemented and are cited only where a rule is borrowed — see specs/SCOPE.md,
and note that the aggregate hid this distinction until the report was split per
RFC.

`--uncited` lists what is left rather than counting it, which is what finished
the sweep: the last twenty-four were invisible in a total, and three of them
turned out to be RFC 8174's keyword boilerplate — a sentence that names every
keyword while defining its own vocabulary. That is a defect in the extractor
rather than a gap in the code, and it is excluded there. Ten more were RFC
9000 section 22, which instructs IANA and the authors of future extensions and
has no counterpart in an implementation.

**"Cited" is not "correct".** 566 of 566 means every mandatory sentence has
something in the tree pointing at it and quoting it accurately; 124 of those
carry a test, 343 an exception with a stated reason, and the rest are an
implementation a reader can check. The ledger's value is that the third
category is now visible and finite.

The SHOULD-level sweep followed the mandatory one and reached the same place in
four of the five documents: RFC 9001, 9002, 9114 and 9204 have no uncited
SHOULD left, and RFC 9000 has four, all IANA registry policy.

**The ratio is the finding.** RFC 9114's fifty-eight SHOULDs produced one
implementation and fifty-seven exceptions. That is the correct answer, not a
shortfall: a SHOULD is the specification saying a reasonable implementation
might do otherwise, and the agents were told not to manufacture agreement. What
the sweep produced is a list of every place this package knowingly declines
advice, each with the mechanism that would have to change first.

Of those citations, 129 carry a test and 452 an exception with a stated reason.
**The exceptions are the product as much as the citations are**: migration,
0-RTT, version negotiation, Retry, stateless reset, address-validation tokens,
preferred address, PMTU discovery, server push, the QPACK dynamic table, ECN
and pacing are each now marked out of scope with a mechanism named. Before this
work every one of them was indistinguishable from an oversight.

The annotation was done by three agents working on disjoint files, and the
method is worth keeping. Every one of them generated its `//#` blocks by
slicing the vendored text with a script rather than typing them, and between
them they produced **292 citations with zero quote failures**. The two quote
failures in this pass were both mine, both hand-typed, and both the same
mistake: copying a requirement out of my own terminal output, which had wrapped
`ack-eliciting` across a line the RFC does not wrap. The gate caught both. If
you take one working rule from this document, it is *extract the quote, never
retype it*.

The exceptions are the product here as much as the citations. 60 requirements
are now marked deliberately-out-of-scope with a reason naming the mechanism —
migration, 0-RTT, version negotiation, stateless reset, NEW_TOKEN issuance,
server push, the QPACK dynamic table and encoder streams, the HTTP/3 control
stream, ECN and pacing. Before this pass, every one of those was
indistinguishable from an oversight.

Two of its checks are gates and the rest is a report, which is a deliberate
split:

- **A quote must appear in the section it cites.** This one has already earned
  its place: the first `//#` block written for RFC 9002 §7.6.2 was paraphrased
  from memory rather than copied, and the gate rejected it. A citation that
  misquotes an RFC is worse than no citation, because it is a claim of
  diligence a reader will believe.
- **An exception must carry a `reason=`.** Without one, "deliberately not
  done" and "forgotten" are the same string.
- **Coverage is a report.** Extracting "the requirements" from prose is a
  heuristic — `splitSentences` breaks on a full stop before a capital, with a
  short abbreviation list — and a gate resting on a heuristic teaches everyone
  to work around the heuristic rather than to cite the RFC. The number to watch
  is the trend, and the honest reading of `7 / 571` is that this has started
  rather than that it is done.

The work left is the annotation, and it is the bulk of it: 564 mandatory
requirements with nothing said about them. Not all are in scope — migration,
0-RTT, the QPACK dynamic table and version negotiation are all out, and each
wants a `type=exception` naming that rather than silence. Distinguishing "out
of scope" from "nobody looked" is the whole product of this exercise, and it is
what makes the next 57-finding review smaller than the last.

### 5.2 A `sim/` in this package — one to two weeks — **started**

Cheaper than zoxy's, because there is no I/O layer to virtualize: the seam
already takes datagrams and `now_ns`. A seed derives a topology and a schedule.

- **Nodes.** Two or more `Connection`s, the constant-secret fake TLS the tests
  already use, a scripted application on each side, and an adversary that
  replays, reorders, truncates, seals Initial-keyed packets with a different
  source identifier, and spoofs a source address.
- **Link.** Delay, jitter, a rotating loss mask, reorder, duplication, MTU, a
  token-bucket queue with tail drop. picoquic's `sim_link.c` is 462 lines and
  is the model to copy.
- **Invariants after every step.** The pair goes quiet within bounded virtual
  time. In-flight octets never exceed the window except for an ACK-only packet
  and a PTO probe. Sent never exceeds three times received while unvalidated.
  No packet number repeats under one key. Delivered bytes equal written bytes,
  in order, per stream. Every buffer drains to zero at close. `timeout()` is
  never in the past while `wantsSend()` is false.
- **Coverage census**, as zoxy's: across a sweep, a PTO must fire, a key update
  must happen, persistent congestion must collapse a window, a FIN must be
  retransmitted, a Retry must be honoured. A counter no seed moves is a finding.
- **Fault injection.** A send buffer that is sometimes too small, which is the
  `writePayload` bug; a seal that fails; a `now_ns` that jumps.
- **Cadence.** 4096 seeds per change under all three build legs, a nightly
  range, replay by seed, a quarter of seeds clean so the oracles tighten from
  prefix-legality to exact outcomes.

A test in this harness is a scenario, not a function: "handshake under 30%
loss both ways completes within N round trips", "a blackhole of five seconds
collapses the window and the transfer resumes".

**Status.** `sim/Link.zig` and `sim/main.zig` exist and run as `zig build sim`.
The link has delay, jitter, a rotating loss mask, reordering, duplication, MTU
and a token-bucket queue with tail drop. Four oracles are live and the census
counts thirteen behaviours.

It is part of `zig build ci`. It was held out while the census reported
behaviours no seed reached, because a gate that passes while saying so would be
the same lie the fuzz targets were telling in §1's table.

It has already paid for itself. Two defects in its first working sweep, both of
the class this document predicted and neither reachable by a test of a
function:

- **The server never sent HANDSHAKE_DONE.** RFC 9001 §4.1.2 makes it a MUST.
  The frame was handled on receipt and generated nowhere, so a client talking
  to this server stayed in `handshaking` for the life of the connection — and
  RFC 9002 §6.2.1 then declines to arm an application-data probe timeout, so
  its 1-RTT packets were never retransmitted either. Every unit test missed it
  because every unit test injects the frame by hand.
- **A probe carrying data never spent its credit.** `probes_pending` was
  decremented on the PING path alone, so a probe that carried CRYPTO — the case
  §6.2.4 prefers — left the credit standing, and a non-zero credit is what
  exempts a packet from the congestion window. The window stopped binding for
  the rest of the connection. Three seeds reproduced it with the same excess.

Fixing the second surfaced a third, which is the one worth reading: the
ACK-only exemption was **accidental rather than real**. A sender with a full
window framed its stream data *and* its ACK, had the whole packet refused for
being ack-eliciting, and so never sent the acknowledgement that would have
opened the window. `writePayload` now takes the window's verdict and stops
before the first ack-eliciting frame.

Three of the four oracles had to be restated, and how is worth recording,
because it is the failure mode of oracle-writing:

- "In-flight never exceeds the window by more than one datagram" fired on a
  legitimate second probe. Widened to two — §6.2.4's number — it fired on two
  legitimate probe *rounds*. The RFC puts no bound on that, so any number here
  is invented and would be loosened each time it fired. It is now stated where
  it is exact: with `pto_count` at zero, no exemption applies and the window
  binds absolutely.
- "`timeout()` is never in the past while `wantsSend()` is false", taken
  literally, fires on every timer for the instant between coming due and being
  serviced. The property that matters is that servicing *converges*, which is
  what the harness now checks.
- The packet-number oracle shared one array between both endpoints, so the
  server's lower numbers read as the client's going backwards. It fired on
  every seed before a single packet had been sent.

Transfers now complete and the delivered-equals-written oracle runs. Over 256
seeds the census reaches every behaviour it requires — handshakes, transfers,
halved and collapsed windows, loss, reordering, and the amplification limit
binding — so `sim` is part of `zig build ci`. It costs seconds in either build.

Three more fidelity gaps had to be closed before any of that was true, and each
one had the census reporting a behaviour unreached rather than a run passing
with nothing in it:

- Both endpoints were given the **same source connection identifier**, so the
  client addressed its 1-RTT packets to something the server did not answer to
  and every one was discarded as a forgery. Silently, because section 5.4
  requires exactly that — which is the shape a simulator exists to catch.
- The **client never sent a Handshake flight**, so the server never saw a
  Handshake packet, never treated the address as validated under section 8.1,
  and stayed throttled to three times what it received for the whole
  connection.
- The **server's first flight was 38 octets**. A real one is a certificate
  chain of a few kilobytes against a single 1200-octet client Initial, which is
  when the three-times limit actually binds. With a token-sized flight the
  amplification counter never moved, and it was right not to.

Still to come: the adversary node, fault injection, the `poll` of §5.3, and the
4096-seed nightly cadence under all three build legs. One census row stays at
zero on purpose — "packets declared lost" — because `Recovery` reports losses
per acknowledgement and keeps no lifetime total, so nothing outside the library
can count them. That is what §5.3 is for, and until then the halved-window
count is the signal that loss was reached.

### 5.3 Events out — with 5.2

Add a `poll` that yields an event alongside the accessors that exist:
handshake done, stream readable, stream finished, stream reset, stream stopped,
key updated, closed. The simulator's oracle becomes a trace; a qlog writer
outside `src/` becomes a consumer of that trace; picoquic-style golden trace
diffs become possible between seeds and between versions.

### 5.4 Fuzz where it ships — days

Run `zig build fuzz` under `-Doptimize=ReleaseFast` with and without
`-Dassertions`, on every change. Draw peer-chosen fields at their wire width:
a `u62` where the wire carries one. Add model-based targets: `AckRanges`
against a bitset, `Reassembler` against a byte array, `Streams` against a
flow-control ledger. Each of the three data-structure findings in §1 is a
model disagreeing with the structure.

Pair every target with a deterministic test that its *accepted* input really is
accepted. `b9c796d` is the argument for it: two targets spent every run being
refused at the door, and nothing in the gate output distinguished that from
coverage.

### 5.5 An interop shim — one to two weeks, needs TLS glue

A binary under `interop/`, outside the lint, with a UDP loop and one of the
organisation's TLS engines, honouring the runner's environment contract. Start
with `hq-interop`: `handshake`, `transfer`, `retry`, `keyupdate`,
`amplificationlimit`, `chacha20`, `handshakeloss`, `transferloss`. Add `http3`
once the control stream lands, then point h3spec at the same binary. This is
the only gate that catches a shared misreading, and it is why the corpus
README's "second corpus" line has stayed open.

Cheap and immediate: decode qifs's capacity-zero encodings from every
contributor and diff against the source `.qif`. That is the QPACK half of the
second corpus, and it needs nothing this package does not have.

### 5.6 Structure — only if rewriting anyway

`Connection.zig` is 2469 lines carrying 43 tests. Both send-path findings were
about the order in which state is committed, so a rewrite would separate the
send scheduler from the packet builder, and pull address validation and the
amplification budget into a struct with its own invariant check the simulator
calls after every datagram. Neither is needed for §5.1 through §5.5.

## 6. The rewrite question

The seam is right. It is the same shape as quinn-proto, quiche, neqo and
s2n-quic-core, and it is exactly what makes §5.2 cheap. Rewriting the code
without the gates first would reproduce the same list, because the list is a
property of how the evidence was gathered rather than of how the code was
written.

If a rewrite happens anyway, its first commit is `sim/` with the fake TLS and
two connections that cannot yet handshake, and the handshake grows inside it.
That inverts the order this package was built in, where every component was
finished and unit-tested alone and integrated late, which is how a congestion
controller and a stream-direction check each came to exist with no callers.

## 7. What none of this catches

zoxy shipped two bugs its simulator was exhaustive within and blind to: a
phantom log line and a probe that idled out its whole timeout. Each had to be
known before an oracle could look for it. A simulator's reach is the sum of its
oracles, and the ledger and the interop shim exist to supply oracles the
authors did not think of. Keep the reviewer agent; make it the fourth line of
evidence rather than the first.
