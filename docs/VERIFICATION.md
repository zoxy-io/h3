# h3 — verification

Why a reading agent kept finding what the gates did not, what the other QUIC
stacks run, and what was built here to close the gap. Written 2026-09-02 as a
plan; §5 is now a description, and what is still open is at the end of it.
Revised 2026-09-05 against commit `273be5d`. [DESIGN.md](DESIGN.md) is the
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

**Since then the new gates have found what the second table holds**, which is
the part worth reading. The ledger, the simulator, the event queue, the interop
shim and h3spec were built to catch the eleven classes in the first table; they
did, and they also caught classes nobody had written down. The second table is
fifty-seven rows against the first table's eleven, because a gate's real yield
is only knowable after it runs.

Each finding, with the gate that would have caught it first:

| Finding | Commit | Gate that would have caught it |
|---|---|---|
| The congestion window was computed, halved, floored and unit-tested, and `sendPacket` never consulted it | `5d1897b` | A requirement ledger (§5.1), or a simulator invariant that in-flight octets never exceed the window |
| `stream_id.sendable` and `kindOf` existed and nothing called them | `014e7ca` | The ledger, plus a coverage report over the unit test run: a MUST implemented by an uncovered function is a finding |
| Absent entirely: the AEAD limits of RFC 9001 §6.6, persistent congestion, the receive half of the 1200-octet floor, five of RFC 9114 §4's rules | `19cf6fb`, `5d1897b`, `014e7ca`, `11d4587` | The ledger |
| A FIN was re-framed into every packet forever, and `wantsSend` never answered false again | `7c17728` | A simulator liveness oracle: the pair must go quiet within bounded virtual time |
| `writePayload` committed ACK debt, cursors and a probe before `seal` was known to succeed | `7c17728` | Simulator fault injection: a send buffer that is sometimes too small — **and this one turned out to be wrong**. No caller can produce that buffer, so no harness can inject it; see §5.2. This finding still has no gate |
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
| A request stream tolerated eight disjoint received ranges, on the reasoning that "a real path reorders within a few packets" — the runner's ordinary path makes more, and a receiver out of spans closes with INTERNAL_ERROR | the runner, on a 5 MiB transfer | `sim/` reorders, but not the way a 10 Mbps link with a 25-packet queue does |
| A probe owed by a discarded packet number space was never cleared, so a stalled connection reported probes outstanding on two spaces that no longer existed | reading a stall the runner produced | Nothing acts on the count, so nothing could notice it was wrong — it cost an hour of looking at the wrong thing |
| The server refilled its send buffer only when a datagram arrived, so a client waiting for a download and a server waiting for a datagram waited for each other | the runner, `transfer` against quic-go's client | Every earlier test had a peer that kept talking |
| The server truncated any response over two megabytes and served the prefix as if it were the file | the runner, which compares byte for byte | A cap chosen for memory that was never about memory: the body is streamed in scratch-sized pieces |
| Reclamation advanced the send buffer only on a range that began exactly where the acknowledged prefix ended, so the first acknowledgement that arrived out of order stopped it permanently | the runner, `transfer` against quic-go's client | The rule is right for a path that never reorders, and every test path was one |
| Reclaiming past the framing watermark dropped octets a spurious loss had put back, so the stream carried a hole and the far end answered FLOW_CONTROL_ERROR | the runner, once reclamation kept up | Two correct-looking rules — release what is acknowledged, re-frame what is lost — that contradict each other only when both fire on the same octets |
| `wantsSend` did not consider flow control, so an endpoint that owed a MAX_STREAM_DATA reported it had nothing to send, and a consumer that sends when told to never sent it | three streams at once, in a unit test written after the runner stalled | The accessor and the writer disagreed, and each is right on its own |
| No DATA_BLOCKED or STREAM_DATA_BLOCKED frame was ever sent, so a lost window update deadlocked the connection with no way for either endpoint to learn why | the same stall | RFC 9000 section 4.1 reads like a courtesy; it is the only thing that breaks the tie |
| A lost MAX_DATA or MAX_STREAM_DATA was never sent again: the limit is recorded when the frame is *written*, so the threshold that decides the next one had already moved past it | the same stall | Loss detection needs later packets to declare the loss, and a deadlocked connection has none |
| A packet whose payload came to fewer than four octets could not be sealed — RFC 9001 section 5.4.2's sample — and `send` turned that into "nothing to send". A lone HANDSHAKE_DONE is one octet; so is a lone PING probe | fixing the flow control above, which removed the MAX_DATA that had been padding the first 1-RTT packet by accident | One bug was holding another one up, for the second time in this document |
| No MAX_STREAMS frame was generated anywhere, and `Streams.open` never freed a slot — so `streams_max` bounded a connection's *lifetime* rather than its concurrency, and a peer that closed a stream never got it back | the runner's `multiplexing` case, which is 1999 files on one connection | The comment above the constant argued it was sound because the limit is comptime and never rises. The limit never rising is the defect |
| The interop shim's own list of readable streams was append-only and bounded by the stream table, so the twenty-fifth request on a connection was silently never answered | the same case, one layer up | The same defect as the one below it — a fixed array nobody gives back — and it was hidden by the one below it until that was fixed |
| The interop client refused more requests than it had stream identifiers for, rather than issuing them as earlier ones finished | the same case, as a client | `error.TooManyRequests` reads like a guard and was a limitation |
| A stream the peer abandoned could never retire, and the retirement watermark is contiguous — so one RESET_STREAM, which is an ordinary thing for a peer to send, froze the stream credit for its whole kind for the rest of the connection | reading the retirement code that had just been written | Every interop case completes its streams cleanly, so no gate here has a peer that gives up |
| The interop client lost a response's FIN when the stream retired in the same pass that consumed the last of its body, and waited for a response it already had | the runner's `http3` case, on the second run | It depends on where a DATA frame's last octet falls relative to the FIN, so it fails on one run and passes on the next |
| Only the named stream was created, so RFC 9000 §3.2's lower-numbered ones were not — a peer whose third request arrived first had three streams and this endpoint had one, and the two disagreed about which streams existed and how much of the limit had been spent | reading §3.2 against the retirement code | Each endpoint is internally consistent, and every peer this package has met allocates identifiers in order |
| No RESET_STREAM was ever framed, so a peer's STOP_SENDING moved a state here and was never answered — the final size the two endpoints have to agree on was never communicated, and a consumer had no way to cancel a stream at all | the requirement ledger, which had it as a `type=todo` beside the state it moved | Nothing in the interop matrix cancels a stream, and h3spec resets *its* streams rather than asking this endpoint to |
| `writeStream` read no send state, so a peer that sent STOP_SENDING got the rest of the buffer anyway. `wantsSend` refusing is not `send` refusing: an owed acknowledgement is enough to build a packet, and the stream writer then filled it | writing the test for the rule above | The test that should have caught it could not — an acknowledgement reclaims the buffer, so a stream that *was* framed and one that never was both end at zero |
| Skipping section 3.3's terminal states in the stream writer stalled a transfer, because "Data Recvd" is entered when the packet carrying the FIN is acknowledged rather than when every packet is — and an earlier packet can be declared lost afterwards | the runner's `http3` case, one build later | It needs a spurious loss on a stream that has already sent its FIN, which is a property of a path rather than of a state machine |
| STOP_SENDING was received and never sent, so a consumer could abandon what it wrote and not what it read — the peer went on sending into a buffer the application had walked away from | the ledger, which had section 3.5's SHOULD as a `type=todo` | Nothing in either suite asks a peer to stop; h3spec resets its own streams and the runner's cases all read what they asked for |
| A PTO probe was pointed at the earliest *recorded* packet rather than the earliest one in flight, and an acknowledgement-only packet carries nothing a retransmission can make progress with — so the probe rewound nothing and went out as an ACK and some padding | the runner's `handshakeloss` case, read packet by packet | Every unit test's probe had data as its oldest packet, because nothing had sent an acknowledgement first |
| RFC 9001 §5.7's "a server MUST NOT process incoming 1-RTT packets before the handshake is complete" was recorded as satisfied by construction — a 1-RTT key exists only when the handshake is complete — which is true of a client and false of a server | the same case | The argument is written next to the rule and reads as a proof; a TLS 1.3 server holds application keys one flight before it verifies the client |
| The interop client's `Session` carried its completion counter across connections, so every connection after the first returned at once having done nothing — and reported success | the runner counting handshakes in the capture | The shim said "1 of 1 requests" fifty times and exited zero; only an independent count of what reached the wire disagreed |
| The interop server retired a peer after five seconds of silence while advertising no idle timeout at all, so it dropped connections whose peer was still probing | the same case | Five seconds is longer than anything a working path needs and shorter than a probe timeout that has backed off twice |
| Section 14.1's 1200-octet floor was met by zeroing the datagram *after* the last packet, which is neither of the two ways the sentence names — a peer parses the zeroes as one more packet and throws it away | reading quic-go's log while chasing `handshakeloss` | Every peer accepts it, so nothing fails; what it costs is a slot in the peer's undecryptable queue and half of every padded datagram |
| Moving that padding into the *first* packet then stopped the coalescing, so a server's flight went out as two datagrams instead of one — sixty per cent more octets against section 8.1's budget, and two datagrams that both have to survive | `handshakeloss`, which went from two runs in three to none in four | The unit tests only ask whether the datagram reaches 1200; which packet holds the padding is invisible to them |
| A PTO probed only the space whose timer expired, so a handshake — which is two spaces at once — repaired one flight per timeout while the other space's timer went on backing off in parallel | the ledger, which had RFC 9002 §6.2.4's coalescing as a `type=todo`, and the padding fallback that kept firing because of it | The rule is a SHOULD about an optimisation, and what it optimises is the case where both spaces are lost together — which is the ordinary case under 30% loss and never happens on a clean path |
| An endpoint that initiated a key update could not read anything the peer had sent under the old generation, so it stopped hearing acknowledgements at the instant it updated — RFC 9001 §6.1's retention rule, broken by the AEAD's own failure path | the simulator, the first sweep in which any seed updated its keys | `std.crypto.aead` scrubs its output buffer on a tag mismatch, deliberately, and the output buffer is the packet: the first speculative key destroys the ciphertext the second needs. The interop `keyupdate` case passes because there the peer follows promptly and the *other* branch is the one that runs |
| The census merged into the sweep total through a hand-written list of fields, so a counter nobody remembered to add read as a behaviour no seed reached | adding two counters and watching both report zero while the sweep reached one of them eleven thousand times | It is the same shape as the defect the file already recorded — a row that is zero because the accumulator is wrong rather than because the behaviour is absent — and the second instance arrived four months after the comment about the first |
| `src/qlog.zig`'s tests never ran. `src/root.zig` has a `test` block that names each module, and a module nobody names is a module whose tests Zig does not compile — so the file was written, wired into both roles and passing for an hour, and the first test to actually execute failed | naming the module | Nothing reports a test that was never compiled. The gate output is identical to the gate output for a module whose tests all pass |
| What that was hiding: two `Record` variants wrote their first field with the raw text writer, which does not do the comma bookkeeping, and emitted two fields with nothing between them — balanced braces, and not JSON | the first run of those tests | The test that caught it parses each record with `std.json.validate`. The one it replaced counted braces, and counting braces would have passed |

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
TLS engine — was designed so that simulator could drive a connection, and for
the eight commits this document opens with it never did: the whole pair harness
was one function moving a datagram from one `Connection` to another. `sim/` is
that crossing, and §5.2 is what it became.

## 2. What the gates are today

| Gate | What it proves | What it cannot prove |
|---|---|---|
| 371 `test` blocks | Each function does what its author meant | That the author read the RFC correctly, or that anything calls the function |
| 16 fuzz targets, run in all three build legs | Decoders reject or parse with no third outcome | Anything a `u16` draw cannot reach; and — until `b9c796d` — whether a target reaches its accept path at all, which two of them did not |
| `zig build lint` | No I/O, no allocator, no unbounded loop | Nothing about behaviour |
| The `tiger-style-reviewer` agent | Assertion density, function length, named bounds | It is a reader, not a gate: it found the twenty above, and it will not find the same class twice at the same cost |
| `zig build requirements` | That every RFC quote in the source is in the section it cites, that every exception states a reason, and that no `//=` URL is silently unreadable | Coverage — the sentence extraction is a heuristic, so the count is a trend rather than a threshold. And "cited" is not "correct": a citation says someone looked, not that they were right |
| `zig build sim` | 256 seeded runs of two connections over a modelled link — loss, reordering, duplication, MTU changes, clock jumps, a late reader, key updates, and on a third of seeds an adversary that replays, truncates and corrupts — with seven oracles and a 24-row census that fails the sweep when a required behaviour goes unreached | Anything no oracle states, and any fault that lives *inside* the library: a `seal` that fails and a send buffer that is too small are not things a harness can inject, because no caller can produce them. It also enters the state the flow-control deadlock lived in and does not reproduce it — removing both fixes leaves 256 of 256 seeds passing |
| The interop shim, against quic-go: 9 of 9 as a client, 8 of 8 as a server | That two independent implementations of the same RFCs agree over a lossy link, on the cases the runner has | Only what the runner tests — nine named scenarios, not a specification. And it is run by hand: `interop.yml` builds the shims and stops |
| h3spec, 49 of 49 | That 49 specific violations are answered with the specific error code the RFC names | The positive path — every case is a negative one. Run by hand, like the interop matrix |
| `zig build corpus` | RFC 9001 appendix A's worked packets octet for octet — key schedule, AEAD, nonce, sampling offset and mask, right at once — and QPACK field sections four other encoders produced | Anything after the first flight; and only the capacity-zero QPACK encodings, because the decoder is static-table-only |
| `src/qlog.zig` | Nothing. It is not a gate — it writes a trace a person can read after a failure | Everything. It is evidence for a human, and §5.7 says exactly which events it does not carry |

No gate this document planned is missing outright any more. What is missing is
narrower and is listed at the end of §5 — most of it fuzz accept-path tests,
two faults no harness can inject, and two census rows.

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

s2n-quic, the requirement citation the ledger of §5.1 adopts:

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
  byte-exact file comparison plus pcap analysis with the key log. **Built and
  run**, as `interop/`; see §5.5 for the results.
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
  are the ones this package's static-table-only decoder can read, and those are
  **vendored and gated**; see §5.5.
- **[duvet](https://github.com/awslabs/duvet)** — extracts every MUST, SHOULD
  and MAY sentence from an RFC, matches `//=` and `//#` citations in source,
  reports per section: cited, implemented, tested, exception, todo. Zig and
  Rust share line comments. The convention was adopted and the checker written
  here rather than vendored, as `zig build requirements`; see §5.1.
- **[qlog](https://github.com/quicwg/qlog)** — still Internet-Drafts at
  version 14 of the main schema; `qvis` renders it. No stack keeps golden qlog
  fixtures except picoquic. aioquic and quic-go assert on individual events.
  **Written**, as `src/qlog.zig` and `interop/qlog_file.zig`; see §5.7. Note
  what it is *not* for: nothing in the interop runner reads a qlog. It sets
  `QLOGDIR` and keeps whatever is written there, and the value is a trace a
  person or `qvis` can read afterwards — not a measurement the runner takes.
- **quic-tracker** — dead at draft-29; not worth targeting.
- **Formal** — McMillan and Zuck's Ivy model (SIGCOMM 2019) and its draft-29
  extension found real bugs in seven stacks, including client-sent NEW_TOKEN
  and errors at the wrong encryption level.
  [PANTHER](https://github.com/ElNiak/PANTHER) is the active successor and is
  research tooling; usable, not a gate.

## 5. What was built

Everything this section planned exists in some form, and four items of it do
not. Each gate below is in `zig build ci` or in a workflow of its own, except
the interop matrix and h3spec, which are run by hand, and the qlog writer,
which is not a gate at all. What each one *found* is the second table in §1,
which is the part worth re-reading; what follows is only what the gates are
now, and what is still open is at the end.

### 5.1 A requirement ledger — `zig build requirements`

The five RFC texts are vendored under `specs/`. A citation is a `//=` line
naming `rfcNNNN#section-X.Y`, `//#` lines quoting the requirement, and a
`//= type=` line saying `test`, `exception` with a `reason=`, or `todo`. The
gate checks that every quote appears **verbatim** in the section it cites, and
fails on an exception with no reason or a URL it cannot read. It exists in that
shape because the first citation written for this package was paraphrased from
memory and was wrong.

783 requirements are cited, 184 with a test, 425 with an exception, 34 with a
todo; all 566 mandatory sentences in the five documents are cited.

Two limits, unchanged. The sentence extraction is a heuristic, so the counts
are a trend and not a threshold. And "cited" is not "correct": a citation says
someone looked, not that they were right — three of the six misattributed
citations this gate found had been sitting beside code that satisfied a
*different* rule.

### 5.2 A simulator — `zig build sim`

`sim/` drives two `Connection`s over a modelled link with a fake TLS, a virtual
clock and a seeded PRNG. `sim/Link.zig` delays, jitters, loses on a rotating
mask, reorders, duplicates, drops over MTU and drops on a full token bucket.
The clock jumps, the reader is sometimes late, half the seeds update keys, and
a third of them draw an adversary that replays, truncates and corrupts what it
forwards — corruption is the adversary's, not the link's.

**Two of the three faults originally planned turned out not to be expressible,
and that is worth stating rather than quietly dropping.** "A `seal` that fails"
and "a send buffer that is sometimes too small" are faults *inside* the
library: every send here declares its own `[Link.datagram_octets_max]u8`, and
`sendPacket` rejects anything shorter than `config.datagram_octets` before it
starts, so no caller can produce either. Injecting them needs a
fault-injecting build of `src/`, not a harness. What a harness can inject is
what a caller can do wrong — a clock that jumps and a reader that is late are
what replaced them. So §1's `writePayload` finding, which committed ACK debt
and cursors before `seal` was known to succeed, still has no gate.

256 seeds run on every change under all three build legs.
`.github/workflows/nightly-sim.yml` runs 4096 from a range derived from the run
number, so no two nights sweep the same one. `--seed N` replays a failure;
`--from N` chooses a range.

The census is the half that keeps the sweep honest: 24 rows counting behaviours
the seeds reached, merged by an `inline for` over the census's own fields so a
new counter cannot be forgotten, and a required row at zero **fails** the
sweep. Which rows are required is declared in `sim/`'s census and nowhere else,
including here: a list in a document drifts from the one the sweep enforces,
and only one of the two can fail a build.

That is not a formality. The two most recent counters both read zero on their
first run while the sweep was reaching one of them eleven thousand times, and a
row that is zero because the accumulator is wrong looks exactly like a
behaviour the seeds never reached.

Seven oracles, numbered here because `sim/main.zig`'s comments cite them by
number:

1. Once the application has nothing left to do, the pair goes quiet within
   bounded virtual time.
2. In-flight octets never exceed the congestion window, except for an ACK-only
   packet and a PTO probe.
3. An unvalidated server never sends more than three times what it received.
4. A packet number never repeats under one key.
5. Delivered octets equal written octets, in order, per stream.
6. `timeout()` is never in the past while `wantsSend()` is false.
7. A datagram is the packets in it and nothing else.

Two of them are deliberately *not* in `checkInvariants`, and the comments there
are the record of why.

**Two** cannot be stated from outside the library without a number RFC 9002
does not give: a congestion event halves the window under data already on the
wire and the RFC does not retract it, and a number invented to make a run pass
gets loosened the next time it fires. It is asserted inside `sendPacket`
instead, where `canSend` has just been consulted with that packet's own size —
exact, needing no slack, and strictly stronger than anything the harness could
write.

**Six**, taken literally, fires on any timer that has merely come due and not
yet been serviced, which is every timer for the instant between the clock
reaching it and the caller firing it. What matters is that servicing
*converges*, so `serviceTimers` checks that instead: a timer that re-arms in
the past without sending anything is the spin the oracle was written for.

The adversary has found nothing, over 4096 seeds and about seven thousand
injections. That is worth recording as plainly as a finding would be: the gate
that pays out is not the same as the gate that was worth building.

### 5.3 Events out — `Connection.poll`

`poll` yields an `Event` alongside the accessors: handshake confirmed, stream
readable, stream delivered, stream reset, stream stopped, key updated, packets
lost, closed — and `overflowed`, which is the queue saying it dropped something
rather than dropping it quietly.

The queue is fixed, like everything else here, and a full one **counts the drop
and reports it**. The alternative — overwrite the oldest, say nothing — is the
failure mode §1 catalogues six times in other guises: a component that ignores
its input reports success either way.

### 5.4 Fuzz where it ships

16 targets in `fuzz/`, run in all three build legs rather than in Debug alone,
which is what makes a `catch unreachable` guarded by an elided assertion
reachable. Fields are drawn at their wire width — the recovery target used to
draw a 62-bit `delay` as a `u16`, so the overflow in it was unreachable by
construction.

No corpus is checked in. Zig's fuzzer keeps one under `.zig-cache`, so
`zig build fuzz` on a clean checkout is one deterministic pass per target, and
`--fuzz` is the coverage-guided run.

### 5.5 An interop shim — `interop/`

`interop/client.zig` and `interop/server.zig` build the endpoint image the QUIC
Interop Runner expects: `ROLE`, `TESTCASE`, `REQUESTS`, `SSLKEYLOGFILE`,
`QLOGDIR`, `/www`, and exit 127 for a case they do not support. TLS is ztls,
which is the consumer's side of the seam and therefore not in `src/`.

**As a client against quic-go's server: nine of nine. As a server against
quic-go's client: eight of eight** — `handshake`, `transfer`, `chacha20`,
`retry`, `http3`, `transferloss`, `multiplexing`, `handshakeloss`, with
`keyupdate` on the client side as well. `handshakeloss` is the one to read the
small print on: fifty connections through 30% loss, and a `multiconnect` client
abandons the run on the first one it loses, so it is the case most able to fail
for nobody's reason. Three runs of three in both roles on the last measurement.

**h3spec passes 49 of 49** against `interop/server.zig`: 33 transport and TLS
cases, 16 HTTP/3 and QPACK. Its case list is the closest thing to a public MUST
catalogue for the surfaces `fields.zig` and the connection guard cover, and it
found four defects in `src/` that nothing else here could reach.

**qifs** is vendored under `corpus/qifs/` and gated by `zig build corpus`:
QPACK field sections encoded by four other implementations, decoded against the
same header list. Only the capacity-zero encodings are in scope, because the
decoder is static-table-only and stays that way — the dynamic table is out of
scope for this package, not behind it.

### 5.6 Structure — only if rewriting anyway

`Connection.zig` is 9420 lines, 5262 of them comments and 2408 of those RFC
citations. Both
send-path findings in §1 were about the order in which state is committed, so a
rewrite would separate the send scheduler from the packet builder, and pull
address validation and the amplification budget into a struct with its own
invariant check the simulator calls after every datagram. Nothing above needed
it, and nothing below does either.

### 5.7 A qlog trace — written, and partial on purpose

`src/qlog.zig` turns a record into octets and stops; `interop/qlog_file.zig`
opens `$QLOGDIR/<odcid>.sqlog` and writes them. The split is the seam's, for
the seam's reason: the library holds no file and no clock. Both roles name the
trace for the *original* Destination Connection ID, the one value both
endpoints agree on before either has chosen anything, so a client's trace and a
server's of the same connection sit side by side under one name. A 5 MiB
transfer produces about 22,000 records, all of them valid JSON-SEQ.

**There are no packet events, and that is the honest shape of this trace.**
`transport:packet_sent` and `packet_received` are most of what a qvis timeline
is made of, and this seam does not expose them: `poll` is a queue of things a
consumer must *act* on, bounded at `events_max`, and a packet-per-event stream
would overflow it on every connection that did any work. Reporting packets
needs a sink rather than a queue — a change to the shape of the seam, not to
the writer. What a trace carries instead is the metrics after every flush, the
loss counts, the key updates, the close, the stream terminations, and the
datagram counts the *consumer* knows because it holds the socket.

And what it is not for, because the obvious guess is wrong: **nothing in the
interop runner reads a qlog.** It sets `QLOGDIR`, keeps what is written there,
and that is all. The value is a trace a person or `qvis` can read after a
failure, not a measurement anything takes.

### What is left

- **Accept-path tests for fourteen of the sixteen fuzz targets.** §5.4 planned
  a deterministic test per target proving its *accepted* input really is
  accepted; two exist, for the connection and recovery targets. §1's third
  pattern is the argument that the other fourteen may be proving nothing, and
  it is the largest open item here.
- **A `seal` that fails, and a send buffer that is too small** — the two faults
  §5.2 records as not expressible from a harness. They need a fault-injecting
  build of `src/`, and until one exists §1's `writePayload` finding has no
  gate.
- **Two census rows planned and not built**: a FIN must be retransmitted, and a
  Retry must be honoured. Neither is among the 24.
- **An adversary that forges an Initial** and spoofs a source address.
  `sim/main.zig` says outright that it does not model this, and §1's
  connection-identifier finding is the one it was named for.
- **34 requirements marked `type=todo`** — 49 citation blocks in `src/`, which
  resolve to 34 of the sentences the extractor found. Each is quoted and not
  yet satisfied, and the number is the ledger working: before it existed the
  same requirements were absent *and* unrecorded.
- **Packet-level qlog**, which needs the sink of §5.7 rather than the queue.
- **§5.6**, above, and only if a rewrite happens for another reason.
- **Oracles nobody has written**, which is the standing item and the subject of
  §7. The census turns "an oracle we did not think of" into a visible zero only
  for behaviours somebody thought to count.

Not on that list, because it is scope rather than debt: the dynamic-table qifs
files stay undecoded for as long as the package has no QPACK dynamic table,
which README states as permanent.


## 6. The rewrite question

The seam is right. It is the same shape as quinn-proto, quiche, neqo and
s2n-quic-core, and it is exactly what makes §5.2 cheap. Rewriting the code
before the gates existed would have reproduced the same list, because the list
is a property of how the evidence was gathered rather than of how the code was
written. The gates exist now, which is what makes the question answerable at
all rather than a matter of taste.

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
authors did not think of. The reviewer agent stays, and it now runs on every
slice before the commit rather than on a session's worth of them at the end —
which is the correction the last such review earned: three of the defects it
found had already gone through a green CI.
