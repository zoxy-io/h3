# h3 — verification

Why the review keeps finding what the gates do not, what the other QUIC stacks
run that this package does not, and the order in which to close the gap.
Written 2026-09-02, revised 2026-09-03 against commit `8e77c63`. [DESIGN.md](DESIGN.md) is the
argument for the code; this is the argument for the evidence.

---

## 1. The signal

Roughly twenty defects were fixed in the eight commits that prompted this
document. Every one was found by an agent reading the code, and not one by
`zig build ci`. That is the signal this document exists to explain, and the
explanation is not "there are no tests": there were 252 of them, 16 fuzz
targets, and RFC 9001 appendix A's four packets checked octet for octet. What
there was none of is the three kinds of evidence that would have caught that
particular list.

**Since then the two new gates have found about twenty-five more**, which is
the part worth reading. §5.1's ledger and §5.2's simulator were built to catch
the classes in the table below; they did, and they also caught classes nobody
had written down. The second table records those, because a gate's real yield
is only knowable after it runs.

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

### What the new gates then found

| Finding | Found by | Why nothing else would have |
|---|---|---|
| The server never sent HANDSHAKE_DONE, so a client never confirmed the handshake and never armed an application-data probe timeout | simulator, first working sweep | Every unit test injects the frame by hand |
| A probe carrying CRYPTO never spent its credit, so a non-zero `probes_pending` exempted the sender from the congestion window for the rest of the connection | simulator, three seeds with the same excess | Correct in isolation at every step; only a connection over time diverges |
| The ACK-only exemption was accidental: a full window refused the whole packet, so the acknowledgement that would have opened it never went out | fixing the above | A mutual deadlock — each side is individually correct |
| `transport_parameters.validate` was tested and called from nowhere; a client could send a `stateless_reset_token` and a server would keep it | ledger | The third instance of "implemented and never wired in"; the tests passed because they called it directly |
| STOP_SENDING and MAX_STREAM_DATA each *created* the stream they named, so a peer could fill the table with identifiers this endpoint never opened | ledger | Two rules with one shape, both looking correct beside their own code |
| A repeated `Host` with no `:authority`, and `content-length` accepted in a trailer section, both feeding a downgraded HTTP/1.1 request line | ledger | `transfer-encoding` was guarded, so the other two looked like they must be |
| A client's anti-deadlock PTO was never armed with nothing in flight, so a client and a server could both wait forever | ledger | Neither endpoint is wrong alone |
| Two RFC 9001 §9.5 timing channels: the reserved-bits check ran before the AEAD, and the header mask's trip count was the packet number length | ledger | Not a behavioural property; no assertion over output can see it |
| The §9.5 fix then reached only the send path, because the receive path inlines its own copy of the loop | ledger, second pass | The fixed half is the half nobody can measure |
| A CONNECTION_CLOSE reached one encryption level; and a closing endpoint's `wantsSend` disagreed with its `send`, so an event loop polling the pair never sleeps | ledger, and writing the test for it | The close *worked* against a peer that could read that level |
| `Recovery` reported losses to `Streams` and acknowledgements to nobody, so RFC 9000 §3.1's terminal send states were unreachable and the simulator's loss census was permanently zero | `poll`, section 5.3 | Both halves look complete from inside; nothing asked the connection what had *changed* |
| A client discarded its Initial keys on *installing* Handshake keys rather than on *sending* a Handshake packet, losing the ACK it owed — the peer then retransmits into §8.1's amplification limit and both endpoints wait | interop shim, first real connection | The rule was quoted verbatim two lines above the code that broke it, and both endpoints are individually correct |
| The server half of the same rule was absent entirely | interop shim | Nothing tested a server's Initial keys after the handshake moved on |
| §14.1's padding asked whether the client *had* Initial keys rather than whether the datagram *carried* an Initial packet — a proxy that held only because of the bug above, and that corrupted every 1-RTT packet once it was fixed | interop shim, immediately after fixing the first | One bug was holding another one up; and reverting this fix broke no test until one was written for it |
| The peer's four flow control limits were parsed and applied to nothing, so a stream opened with a send limit of zero and the first request could never be written | interop shim | `sim/` sends explicit MAX_DATA and MAX_STREAM_DATA, which is what a peer sends *after* the initial limit rather than instead of it |
| Five of `Event`'s eight variants — `handshake_confirmed`, `stream_reset`, `stream_stopped`, `key_updated`, `closed` — were declared, documented, and emitted by nothing | the interop shim needing a close code | The tests called `emit` directly, so they proved the queue worked and never that anything filled it |
| MAX_STREAM_DATA was offered for every stream in the table, including this endpoint's own send-only ones, which RFC 9000 section 19.10 makes a connection error at the peer | interop shim, first HTTP/3 connection | `hq-interop` never opens a unidirectional stream, so for the life of the package the loop was only ever asked about bidirectional ones |
| The HTTP/3 layer buffered a whole DATA frame before delivering any of it, and a one-megabyte frame is larger than a stream's receive window — which only moves when octets are consumed | interop shim, against ngtcp2 | quic-go and aioquic chunk their DATA frames, so two implementations out of three hid it |
| A server marked the connection `established` and the handshake confirmed on installing its 1-RTT *send* keys — one flight before the client's Finished was verified | h3spec | Both endpoints are individually correct, and a client that speaks first never notices |
| A packet whose reserved bits survived protection was counted as a forgery and discarded, so RFC 9000 §17.2's violation was both unreported and charged against the AEAD integrity limit | h3spec | Only a peer holding the keys can produce one, so no fuzz input and no simulator seed can |
| A STREAM frame naming a stream in *this* endpoint's number space that it never opened created that stream and accepted the data | h3spec | `Streams.open` creates whatever identifier it is handed, and every test handed it one the peer was entitled to |
| The QPACK encoder and decoder streams were read and thrown away, so an instruction no zero-capacity endpoint can honour was accepted in silence | h3spec | A stream read by nobody looks exactly like a stream with nothing wrong on it |
| A stream could send `stream_send_octets` in *total*: the send buffer was never reclaimed, so it filled once and refused every write after | the interop server, serving a file larger than one buffer | Nothing here had ever sent more than a request line, and a buffer that fills silently looks like a peer that stopped reading |
| "Acknowledged implies framed" — false, because RFC 9002's loss detection is a heuristic and a packet declared lost can be acknowledged anyway | the simulator, first sweep after reclamation landed | It needs a spurious loss, which is a property of a connection over time and of nothing smaller |
| No Version Negotiation packet was ever written, so a server answered an unknown version with silence | the interop runner's network simulator, which will not start a test until the server answers exactly that probe | It is a rule about a packet this package had decided not to send, which is indistinguishable from a rule it had decided not to obey |
| The interop client resolved host names with `IpAddress.resolve`, which parses a literal and then goes to DNS — never `/etc/hosts`, which is where the runner puts every name | the interop runner | Every test until then used an address literal, so the resolver was never asked a question it could get wrong |

Two things about that table.

**Each gate found what the others could not, and no gate found what another
did.** The simulator finds properties of a connection over time; the ledger
finds requirements nobody implemented and claims nobody checked; `poll` found
the transitions no accessor reports; the interop shim and h3spec found the
things only a peer written by somebody else can see — and then the simulator
found the bug the shim's own fix introduced, which is the argument for keeping
all of them. A defect is usually visible
to exactly one of them, which is the argument against ever calling any one of
them sufficient.

**Six of these were introduced by the same session that fixed the rest**, and
four were mine. Two stale `type=todo` comments described gaps that had moved,
which is worse than no comment: a todo reads as a known gap and so hides that
the gap is now somewhere else.

### The failure mode that kept recurring

Six times in one session a check turned out to be ignoring its input rather
than answering wrongly:

- `parseUrl` accepted only `#section-`, so six RFC 9002 appendix citations were
  dropped without a word. Three of them were misattributed, and the gate found
  all three within a second of being allowed to see them.
- A revert-check reported "not caught" four separate times when the revert had
  broken the build — a compile error and a passing test look identical through
  a grep for a failing one.
- A gate piped through `tail` returned the pipe's exit status, and a broken
  commit went out.
- A comptime assertion read `x <= y - n + n`, so it asserted `16 <= 20` and
  said nothing about the offset it was named for.

Every one presented as *silence*. None presented as a wrong answer. The
practical rule: a check that produces no output has not passed, it has not run,
and the two must be made to look different.

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
| 348 `test` blocks | Each function does what its author meant | That the author read the RFC correctly, or that anything calls the function |
| 16 fuzz targets, replayed in all three build legs | Decoders reject or parse with no third outcome | Anything a `u16` draw cannot reach; and — until `b9c796d` — whether a target reaches its accept path at all, which two of them did not |
| `corpus/`, RFC 9001 appendix A | The key schedule, AEAD, nonce, sampling offset and mask are right at once | Anything after the first flight |
| `zig build lint` | No I/O, no allocator, no unbounded loop | Nothing about behaviour |
| The `tiger-style-reviewer` agent | Assertion density, function length, named bounds | It is a reader, not a gate: it found the twenty above, and it will not find the same class twice at the same cost |
| `zig build requirements` | That every RFC quote in the source is in the section it cites, that every exception states a reason, and that no `//=` URL is silently unreadable | Coverage — the sentence extraction is a heuristic, so the count is a trend rather than a threshold. And "cited" is not "correct": a citation says someone looked, not that they were right |
| `zig build sim` | 256 seeded runs of two connections over a modelled link, five oracles, a census that fails the sweep when a behaviour goes unreached | Anything no oracle states. It is deterministic and cross-platform — the same seeds pass on four targets — but its reach is exactly the sum of its oracles |

Missing outright: an interop image, a QPACK cross-implementation corpus, qlog
output, and the event seam of §5.3 that the last two want. The requirement
ledger of §5.1 and the simulator of §5.2 both exist and are both in `ci`.

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
- **[h3spec](https://github.com/kazu-yamamoto/h3spec)** — **run, and passing
  49 of 49** against `interop/server.zig`; see §5.5. Forty-nine negative cases
  against a listening server: 33 transport and TLS, 16 HTTP/3 and QPACK. Each
  mutates a frame, a transport parameter or a TLS extension and expects a
  specific error code. Its case list is the closest thing to a public MUST
  catalogue for the surfaces `fields.zig` and the connection guard, and it
  found four defects in `src/` that nothing else here could reach.
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

The annotation was done by agents working on disjoint files, and the method is
the most transferable thing here. Every one of them generated its `//#` blocks
by slicing the vendored text with a script rather than typing them, and between
them they produced roughly **850 citations with zero quote failures**. Every
quote failure in this project was mine, and every one was hand-typed: a
requirement copied out of my own terminal output that had wrapped
`ack-eliciting` across a line the RFC does not wrap, and three RFC 9002
appendix citations that named the wrong appendix. If you take one working rule
from this document, it is *extract the quote, never retype it*.

Two of its checks are gates and the rest is a report, which is a deliberate
split:

- **A quote must appear in the section it cites.** This has earned its place
  repeatedly. The first `//#` block written for RFC 9002 §7.6.2 was paraphrased
  from memory and rejected within minutes of the gate existing; three appendix
  citations were caught the moment the parser was taught to read `#appendix-`
  anchors. A citation that misquotes an RFC is worse than no citation, because
  it is a claim of diligence a reader will believe.
- **An exception must carry a `reason=`, and a `//=` URL the tool cannot read
  is a violation.** Without the first, "deliberately not done" and "forgotten"
  are the same string. The second was added after `parseUrl` was found silently
  dropping six citations: a checker that ignores its input reports success
  either way, which is worse than having no checker.
- **Coverage is a report.** Extracting "the requirements" from prose is a
  heuristic — `splitSentences` breaks on a full stop before a capital, with a
  short abbreviation list, and RFC 8174's keyword boilerplate had to be excluded
  by name. A gate resting on a heuristic teaches everyone to work around the
  heuristic rather than to cite the RFC.

What is left in the ledger: four SHOULD-level requirements in RFC 9000, all
IANA registry policy. The mandatory sweep is complete.

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

### 5.3 Events out — **done**

`Connection.poll` yields an `Event` alongside the accessors: handshake
confirmed, stream readable, stream delivered, stream reset, stream stopped, key
updated, packets lost, closed — and `overflowed`, which is the queue saying it
dropped something rather than dropping it quietly.

Three gaps were waiting on this and did not look related:

- **The simulator's census had a permanently-zero row.** `Recovery` reports
  losses per acknowledgement and keeps no total, so nothing outside the library
  could count them; the census printed an apology instead of a number. It now
  counts 321 declared losses over 256 seeds, and the row is a *required*
  behaviour rather than a footnote.
- **RFC 9000 §3.1's terminal states are entered on acknowledgement**, and
  `Recovery` reported losses to `Streams` and acknowledgements to nobody. So
  `SendState` had no "Data Recvd": a stream could be written, sent, fully
  acknowledged, and sit in "Data Sent" for the life of the connection. Fixing it
  meant `AckedPacket` carrying the same `Context` a lost packet always had.
- **A qlog writer** needs a trace rather than a poll of accessors, and so does
  any consumer that wants to know about a *transition* without keeping its own
  shadow copy of every answer.

One design note worth keeping. The queue is fixed, like everything else here,
and a full one **counts the drop and reports it as an event**. The alternative —
overwrite the oldest, say nothing — is the failure this package met six times in
other guises and is catalogued in §1: a component that ignores its input reports
success either way.

The bug found while wiring it is the one to remember. The census row stayed at
zero after `poll` existed, because the sweep was accumulating a `lost_declared`
field that had been added when the count was unobtainable and then never
written. Two independent reasons for one symptom, and the second outlived the
fix for the first — which is only visible because the census fails a sweep that
leaves a required behaviour unreached.

### 5.4 Fuzz where it ships — partly done

**Already true, and this document said otherwise for a day.** `ci_step`
depends on `test_step`, which depends on `fuzz_run`, so all three build legs
replay the corpus — including `-Doptimize=ReleaseFast -Dassertions=false`. §1's
table claimed "the build that ships is never the build that is fuzzed"; it was
wrong when written or fixed shortly after, and nobody noticed because a plan
listing finished work as pending reads exactly like a plan.

What is left: Draw peer-chosen fields at their wire width: a
`u62` where the wire carries one. Add model-based targets: `AckRanges`
against a bitset, `Reassembler` against a byte array, `Streams` against a
flow-control ledger. Each of the three data-structure findings in §1 is a
model disagreeing with the structure.

Pair every target with a deterministic test that its *accepted* input really is
accepted. `b9c796d` is the argument for it: two targets spent every run being
refused at the door, and nothing in the gate output distinguished that from
coverage.

### 5.5 An interop shim — **done**

`interop/` is the QUIC Interop Runner client: a UDP loop, a TLS 1.3 client
written for this purpose, and the runner's environment contract. It covers
`handshake`, `transfer`, `chacha20`, `keyupdate`, `multiconnect`,
`handshakeloss` and `transferloss` over `hq-interop`, and exits 127 — the
runner's "unsupported" — for `retry` and `http3`, which are gaps rather than
failures. `interop/README.md` has the docker recipe that reproduces all of it
without the network simulator.

**It found four defects on the first connection it completed**, and the shape
of them is the argument for the whole directory. Every one had passed the unit
tests, the fuzz corpus and 256 simulator seeds, because every one of those is
fed by this package.

1. **The client discarded its Initial keys one event too early.** RFC 9001
   §4.9.1 retires them when a client *sends* a Handshake packet;
   `installSecret` retired them when Handshake keys were *installed*. One
   datagram of difference, and it deadlocks: a client that has just been handed
   Handshake keys still owes an ACK for the Initial that carried the
   ServerHello, and the space it would go out in is gone. The server
   retransmits an Initial nobody acknowledges, reaches §8.1's three-times
   amplification limit, and stops. Both endpoints then wait. The rule was
   quoted verbatim two lines above the code that broke it.
2. **The server half of the same rule was missing** — a server is supposed to
   discard Initial keys when it first successfully processes a Handshake
   packet, and nothing did.
3. **The padding condition was a proxy that only held because of (1).** §14.1's
   1200-octet floor applies to a datagram *carrying an Initial packet*; the
   code asked whether the client still *had* Initial keys. Correcting (1) made
   the proxy false, and a client began padding datagrams that carried nothing
   but a 1-RTT packet. A short header runs to the end of the datagram, so the
   padding landed inside the AEAD's ciphertext and every one of those packets
   failed to open at the peer — silently, because a packet that does not
   authenticate is indistinguishable from one that was never sent. One bug was
   holding another one up.
4. **The peer's transport parameters were parsed and not applied.**
   `transportParametersIn` read all four of §4.1's flow control limits and used
   none of them. A stream therefore opened with a send limit of zero and stayed
   there: no `MAX_STREAM_DATA` is coming for credit the peer believes it
   already granted in its extension. The first request on a real connection
   could not be written.

A fifth is not a defect and is worth as much. `Connection.canUpdateKeys`
answers §6.1's "has the current phase been acknowledged" and **cannot** answer
§6.5's "wait three times the PTO", because it reads no clock. Spacing key
updates in time is therefore the consumer's, and `interop/` learned it by
being wrong: over loopback the octet threshold alone fired a second update
about one round trip after the first. quic-go and aioquic both accepted it;
ngtcp2 stopped answering. **Two implementations agreeing with us was not
evidence that we were right** — which is this section's whole thesis, arriving
as a bug in the thing built to test the thesis.

Why `sim/` could not have found any of the four: its handshake installs both
sides' secrets in the same step, so the ACK a client owes is never the only
thing keeping the peer alive; and its endpoints exchange explicit `MAX_DATA`
and `MAX_STREAM_DATA`, which is what a peer sends *after* the initial limit
rather than instead of it. A simulator built from the same reading as the
library simulates the reading, not the protocol.

One of the four also shows why a fix needs its own revert-check. Three of the
four failed a test the moment their fix was reverted; **(3) did not**, and
nothing in the tree noticed. The test that catches it had to be written
afterwards, and it is the one that asserts a datagram carrying no Initial
packet stays under 1200 octets.

Verified against three independent implementations — quic-go, ngtcp2 and
aioquic — at seven test cases each, including HTTP/3 proper, twice over: once against servers in their
normal mode and once against servers configured to answer every connection with
a Retry, so that all six run the Retry path as well. A megabyte byte for byte
each time, with all four TLS secrets matching each server's own key log
exactly.

**`http3` is covered**, which needed the connection layer `frame.zig` and
`stream.zig` had been waiting for: `src/Http3.zig` opens the control stream,
exchanges SETTINGS, sequences HEADERS and DATA under RFC 9114 section 4.1,
refuses a push stream, and holds GOAWAY in both directions. Thirty-three
exception reasons across `frame.zig`, `stream.zig` and `qpack.zig` had said
"the HTTP/3 connection layer, which docs/DESIGN.md section 6 lists as next
rather than built" — every one was rewritten, because a reason describing a gap
that has closed is worse than no reason at all.

It found three more defects, and the first two are the same shape as everything
above:

1. **Five of `Connection.Event`'s eight variants were emitted by nothing.**
   `handshake_confirmed`, `stream_reset`, `stream_stopped`, `key_updated` and
   `closed` were declared, documented and dead. The commit that added them said
   they were wired; three of seven were. The tests called `emit` directly, so
   they proved the queue worked and never that anything filled it — section 1's
   recurring failure mode, arriving inside the code written to answer section
   1's recurring failure mode. Found because a server closed the HTTP/3
   connection and the shim could not say with what code.
2. **MAX_STREAM_DATA was offered for every stream in the table**, this
   endpoint's own send-only ones included, which RFC 9000 section 19.10 makes a
   connection error at the peer. `hq-interop` never opens a unidirectional
   stream, so the loop had only ever been asked about bidirectional ones.
   quic-go named it exactly: "invalid frame for send stream 2".
3. **A whole DATA frame was buffered before any of it was delivered.** ngtcp2
   sends a megabyte body as one DATA frame; a stream's receive window is
   smaller than that, and the window only moves when octets are consumed. Both
   endpoints correct, neither able to proceed. quic-go and aioquic chunk their
   DATA frames, so **two implementations out of three hid it** — the same
   lesson the key-update spacing taught, in a different place.

**`retry` is now covered too**, and closing it was the first thing the shim's
existence paid for a second time. RFC 9000 section 17.2.5 was nine `type=todo`
and `type=exception` citations in `packet.zig` saying Retry was out of scope;
it is now `Connection.receiveRetry`, and with it section 7.3's connection-ID
authentication — which had been four `type=todo`s of its own, and which is the
rule that stops an attacker who can inject a packet during the handshake from
choosing either endpoint's connection identifier.

Twelve reverts of that work were checked and twelve failed a test. One of them
failed for the wrong reason first: the test for "a Retry arriving after the
server's Initial is discarded" reused the server's Source Connection ID, which
by that point is the identifier the client is already addressing — so section
17.2.5.1's identical-identifier rule refused the packet before the rule under
test was ever consulted. It passed, it proved nothing, and only the revert
showed it.

**h3spec passes 49 of 49**, which needed the server role: h3spec is a
conformance tester for HTTP/3 *servers*, so it tests the one half `interop/`
did not have. `interop/server.zig` is that half — `tls.Server` signs a
transcript with a P-256 key, and `Connection.closeApplication` sends the `H3_*`
codes h3spec asserts on.

The score went 48 failures → 27 → 25 → 19 → 8 → 2 → 0, and almost every step
was a defect rather than a missing feature:

1. **The CertificateVerify signature covered the wrong transcript.** The three
   handshake messages were hashed as a batch *after* being built, so the
   signature was over `ClientHello .. ServerHello` instead of
   `ClientHello .. Certificate`. The peer says "cannot verify
   CertificateVerify" and nothing about why. 48 → 27.
2. **A server confirmed the handshake a flight early.** RFC 9001 §4.1.1: the
   handshake completes when the TLS stack has *both* sent its Finished and
   verified the peer's. `installSecret` had done it on the first alone — so a
   server marked the connection `established` before the client was
   authenticated, and, because `recovery.handshake_confirmed` was set with it,
   sent every CONNECTION_CLOSE at 1-RTT to a peer holding no 1-RTT keys. Eight
   transport-parameter rules that *were* implemented and tested looked
   unimplemented from the outside. 27 → 19.
3. **Closed connections were never retired from the server's table.** Sixteen
   slots, 49 test cases, and a connection this endpoint closed stayed `live`:
   after sixteen cases the server answered nothing, which to h3spec is
   indistinguishable from failing to detect the error under test. Every one of
   those cases passed when run alone. 19 → 8.
4. **Reserved bits, and a STREAM frame for a stream this endpoint never
   opened.** Both real, both in `src/`, both invisible to a fuzzer: the first
   because only a peer holding the keys can produce one, the second because
   every test handed `Streams` an identifier the peer was entitled to. 8 → 2.
5. **The QPACK encoder and decoder streams were read and discarded.** A
   zero-capacity endpoint makes those rules short rather than absent: no
   capacity above zero, no insert, and nothing acknowledged that was never
   sent. 2 → 0.

Two changes made while chasing these turned out to be **redundant**, and the
revert-check is what said so: a second send-only test in the STREAM arm that
`Streams.peerMaySend` already made, and an explicit close-level choice that
became unnecessary once confirmation started discarding Handshake keys on both
sides. Both were removed. A fix no test can distinguish is a claim, and this
document has enough of those in its history.

What is left here:

**The interop runner's server role is done too.** `ROLE=server` runs under the
runner's contract — port 443, `/www` for the files, `/certs` for the key — and
answers `hq-interop` as well as `h3`. RFC 9000 §8.1.2's address validation came
with it: `packet.writeRetry` builds the packet, and the token is
`odcid || HMAC(key, odcid || address)`, which is what lets a server recover the
identifier §7.3 has it repeat after the packet stops carrying it.

Two more defects, and the first is the largest single limitation this document
has recorded:

1. **A stream could send `stream_send_octets` in total.** `send_offset` existed,
   was added to every STREAM frame's Offset field, and was never advanced — so
   the buffer filled once and every write after it returned zero, for the life
   of the connection. Nothing here had ever sent more than a request line. The
   server met it the first time it served a file larger than one buffer: the
   transfer stopped at 64 KiB with both endpoints idle and neither of them
   wrong.
2. **"Acknowledged implies framed" is false**, and reclamation asserted it. RFC
   9002's loss detection is a heuristic: a packet declared lost — which rewinds
   the framing watermark behind it — can be acknowledged afterwards, because it
   was only late. The simulator found it on the first sweep after reclamation
   landed, which is the case it exists for and the one no unit test reached.

A third was the shim's own and worth the same attention. **The server matched
connections only by the identifier it had chosen**, so a client whose first
flight spans several datagrams — a ClientHello past 1200 octets does — looked
like a new connection on the second one and got a *different* Source Connection
ID. quic-go's client said exactly what was wrong: "expected
initial_source_connection_id to equal 82864cea7e23bd49, is fe5493141d0ef85f".
Our own client sends its first flight in one datagram, so nothing here could
have found it.

Verified with **third-party clients against our server**: quic-go and aioquic
complete `handshake`, `transfer`, `chacha20`, `multiconnect`, `http3` and
`retry`, a megabyte byte for byte each time. ngtcp2's *client* image does not
run outside the runner's simulator network, which is its scaffolding rather
than a result.
- **Server push and QPACK's dynamic table**, which `Http3.zig` refuses and
  declines rather than implements — correctly, and they are the two places its
  module comment says it stops.
#### The real runner, inside the network simulator — **attempted, and two more defects**

The runner drives both endpoints through ns-3 with `simple-p2p --delay=15ms
--bandwidth=10Mbps --queue=25`, which is a path nothing on a loopback
resembles. `interop/README.md` has the whole recipe: the endpoint image, the
runner's Python environment, `tshark` and `openssl` from nix, and the entry to
add to `implementations_quic.json`.

Two defects fell out of getting that far, and neither could have been found any
other way:

1. **No Version Negotiation packet was ever written.** RFC 9000 §6.1 makes it a
   server's answer to a version it does not implement, and this package had it
   as an exception: "no Version Negotiation packet is written here". The
   simulator does not care about the rule — it *depends* on it. Its readiness
   probe is a long header carrying version `0x57414954` ("WAIT"), and it will
   not start a test until the server answers with a packet whose version field
   is zero. A server that ignores it fails every case before the first
   handshake. `packet.writeVersionNegotiation` is now the writer, with the two
   crossed-over identifier rules that are the whole reason it is a function.
2. **The client could not resolve a host name.** It used
   `IpAddress.resolve`, which parses an address literal and otherwise goes
   straight to DNS. The runner puts every name — `server4`, `server6` — in
   `/etc/hosts`, written by docker from the compose file's `extra_hosts`, and
   `HostName.lookup` is the call that reads it. Every test until then had used
   an address literal, so the resolver had never been asked a question it could
   get wrong.

**The end-to-end run is blocked by the host, not by this package.** On the
machine this was attempted on, ns-3's re-emitted frames are filtered away
before they reach the far endpoint: `bridge-nf-call-iptables` is 1, so bridged
frames traverse iptables and meet docker's `DOCKER` chain, which ends in DROP.
A narrow `DOCKER-USER` accept for the runner's `193.167.0.0/16` was tried and
is hit — 26 packets — and is not sufficient.

The control is the part worth keeping: **quic-go against quic-go fails
identically**, with the same "timeout: no recent network activity". Recording
that is the difference between "the runner does not pass" and "the runner does
not run here", and only the control tells them apart. Nothing about the result
is a claim about this package, and the two defects above are real whatever the
host does.

What is left here:

- **Finishing the runner on a host whose bridge filtering allows it**, which is
  a machine question rather than a code one. Everything else is in place: the
  endpoint image builds, `run.py` drives it, and the server answers the
  simulator's probe.

#### The other outside evidence: `corpus/qifs.zig` — **done**

The cheap half, and it landed first. It decodes qifs's capacity-zero
encodings from four other implementations and diffs the result against the
source `.qif`. It needed nothing this package does not have — a static-only
decoder is exactly what those files exercise.

The result corrects the argument that justified it. It was proposed on the
strength of a defect it does **not** catch: `field_line.iterate` refused a
section whose Required Insert Count was zero and whose Base was not, and the
reasoning was that other encoders produce shapes this package's own never does.
They do — but not that one. All four emit a prefix of `00 00` at capacity zero,
because a zero Delta Base is what RFC 9204 §4.5.1.2 calls "one of the most
efficient encodings". Reverting the fix leaves the corpus green.

What it does prove: 144 field sections from four implementations decode to
exactly the fields those implementations were handed, and all eight vendored
files differ octet for octet from what `field_line.encode` emits for the same
input. Indexed against literal, which names get Huffman coding, where a
static-table reference is preferred — those choices are theirs, and the decoder
handles them.

The general lesson, which the interop shim above then demonstrated at a larger
scale: **a corpus disagrees with you only where its producers had a reason to
differ.** Capacity-zero QPACK leaves an encoder very little room, so it is
strong evidence about representation and none at all about the prefix. Choosing
external evidence means choosing which disagreements are possible.

### 5.6 Structure — only if rewriting anyway

`Connection.zig` is 5977 lines, roughly half of them RFC citations. Both send-path findings were
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
