# h3 — verification

Why the review keeps finding what the gates do not, what the other QUIC stacks
run that this package does not, and the order in which to close the gap.
Written 2026-09-02, revised 2026-09-05 against commit `7411c7a`. [DESIGN.md](DESIGN.md) is the
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
and a token-bucket queue with tail drop. Five oracles are live and the census
counts twenty-four behaviours, seventeen of them required. A third of seeds
are watched by an off-path attacker and a third read slowly.

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

**The cadence and three more census rows.** `.github/workflows/nightly-sim.yml`
sweeps 4096 seeds under all three build legs every night, from a range derived
from the run number so that no two nights run the same one — a sample taken
from the same 256 seeds every time proves the same thing every time. `--from`
exists for that: `--seed` pins the count to one, which is right for replaying a
failure and wrong for choosing a range.

Three rows were added, and each of them found something.

- **"datagrams accounted for by their packets"**, with its counterpart
  "datagrams with loose padding". A datagram is the packets in it and nothing
  else; what a walk of it does not reach is padding no packet claims, which
  §14.1 does not name and every peer nonetheless throws away. This is the
  measurement that had been taken by hand out of quic-go's log, and it belongs
  where every seed takes it. It reads 0 of 181,855 over a 4096-seed sweep;
  removing the padding fix takes it to 317 of 11,096 in a 256-seed one.
- **"probes carrying data"**, against "probes carrying a bare PING". The
  difference is whether the timeout rewound a framing watermark, which is
  exactly what the probe defect above got wrong, and it was invisible from
  outside the library. Removing that fix moves the bare-PING row from 38 to
  255.
- **"key updates"**, which §5.2 lists as required and which sat at zero because
  nothing in the harness initiated one. Making half the seeds update took the
  row to 132 — **and took transfers completed from 256 to 197**. See below.

**A defect the moment the row moved.** RFC 9001 §6.1 requires an endpoint to
retain old keys until it has unprotected a packet under the new ones, because
everything already in flight when it updates arrives under the old generation.
This package tried the next generation first and the previous second, and the
second could never work: `std.crypto.aead`'s decrypt does `@memset(m,
undefined)` on a tag mismatch — deliberately, so a caller cannot read a
plaintext that was never authenticated — and the output buffer *is* the packet.
The first speculative key scrubbed the ciphertext the second one needed. So an
endpoint stopped hearing acknowledgements at the instant it initiated an update,
which is why every seed that updated stalled. The fix is a copy of the octets
the AEAD will touch, restored between attempts.

It is worth being precise about why nothing else caught it. The interop runner's
`keyupdate` case passes, and passed throughout: there the peer follows the
update promptly, so the *first* branch is the one that runs. The branch that had
never worked is the one that only matters while the peer has not caught up —
which is a window of one round trip, and a window every packet already in flight
falls into.

**The merge was a hand-written list**, and both new counters read zero on the
first run while the sweep was reaching one of them eleven thousand times. That
is the same shape as the defect this file already records — a row that is zero
because the accumulator is wrong rather than because the behaviour is absent —
so the merge is now a `inline for` over the census's own fields and a new
counter cannot be forgotten.

**The adversary node**, which §5.2 asked for and which is the last of the
harness's own gaps but one. A third of seeds are watched by an off-path
attacker: it sees everything that crosses the link, holds no key, and can
therefore do exactly three things — send a datagram again, send part of one, or
send one with a bit changed. That is not a small threat model. A replay is the
only one of the three that authenticates, so it is the only one an endpoint has
to *decide* about rather than discard, and the other two are the only routine
source of packets that fail authentication.

The oracle is the transfer completing, because an endpoint a stranger can stall
is an endpoint anyone on the path can stall. Over 4096 seeds and about seven
thousand injections, every handshake and every transfer completed and no
endpoint reported an error. It found nothing, which is worth recording as
plainly as a finding would be: the gate that pays out is not the same as the
gate that was worth building, and this one is cheap to keep.

**The oracle that would have caught the key update**, and did not exist. A run
could end by reaching the virtual-time deadline without finishing, and that exit
was silent — which is how a defect that stalled fifty-nine transfers in a sweep
showed up as a census row going *down* rather than as a failure with a seed
attached. A run that stops with the transfer unfinished and neither endpoint
reporting anything is now a failure. Reverting the key fix turns it back into
four named seeds in the first ten.

Not modelled: forging an Initial packet. Its keys are derived from a connection
identifier that travels in the clear, so an attacker who saw the first flight
can seal one — and the defect that reached review by that route, a server
adopting the Source Connection ID from any Initial it could open, is covered by
a test in `Connection` instead.

**Fault injection — done, and two of §5.2's three items were not expressible.**
"A seal that fails" and "a send buffer that is sometimes too small" are both
faults *inside* the library: `send` refuses a buffer below `datagram_octets`, so
a caller cannot pass a small one, and nothing outside can make an AEAD fail.
Writing them down as pending for as long as they were pending was the mistake —
they need a fault-injecting build of `src/`, not a harness. What a harness can
inject is what a caller can do wrong, and there are two of those:

- **A clock that jumps.** A process descheduled for a few milliseconds services
  every timer that came due while it was away, all at once and all late. One
  step in sixteen now advances past the next event, and a sweep of 4096 seeds
  takes about twenty thousand of them.
- **A reader that is late.** A third of seeds drain the stream every few steps
  instead of the instant anything arrives. This is the one that mattered: the
  receive window is what closes when nobody reads, and every window-update
  defect this package has had lived on the other side of that.

Reaching that state needed two changes beyond the reader. The payload
distribution now goes past the connection's own windows — a transfer that fits
inside a receive window is one flow control never has to pace — and the receive
window is deliberately *smaller* than the send buffer, because with it the other
way round every short write was this endpoint filling up rather than the peer's
window closing. Writes refused by flow control went from zero to about 292,000
in a 4096-seed sweep.

One honest limit, and it is now closed from the other end. The sweep enters the
state the window-update deadlock lived in and does **not** reproduce the
deadlock: removing both §4.1's blocked frames and §13.3's re-owing leaves 256 of
256 seeds passing. The escape is that the receiver keeps consuming, so its
window keeps moving, so the next threshold crossing sends a fresh
MAX_STREAM_DATA even though the lost one was never repaired. That deadlock needs
a receiver which has *stopped* owing updates while the sender is blocked, which
is a narrower schedule than a random sweep finds.

So it is a scenario rather than a seed: "a window update lost on the wire does
not deadlock" drives a sender at its limit, a receiver reading slowly, and a
*targeted* drop of the one datagram carrying the update — then asserts the
transfer finishes. It is the first test of these two fixes that loses a frame at
all. The two that existed report a loss through `onPacketsLost` with a context
made up by hand and check what is owed afterwards, which is the mechanism and
not the situation.

Its revert-check says exactly one thing, and the test says so in its own
comment: removing §4.1's blocked frames fails it, and removing §13.3's
re-advertisement does not. They are independent ways out of the same state — one
asks the receiver, the other repairs the loss once later traffic reveals it —
and 13.3's has a test of its own. A scenario that claimed both would be claiming
coverage it does not have.

It also cost one harness defect, of the kind this file keeps recording. A run
ended when the network went quiet — and with a late reader, everything can be
delivered and acknowledged while the application still has octets buffered.
Nothing owed, no timer armed, and the loop ended with the transfer short and
both endpoints blameless. Four seeds in the first 256.

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
  shadow copy of every answer. `src/qlog.zig` is now written against what the
  poll *can* say, and §5.7 records exactly what that leaves out.

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

What is left here:

- **Server push and QPACK's dynamic table**, which `Http3.zig` refuses and
  declines rather than implements — correctly, and they are the two places its
  module comment says it stops.

#### The real runner, inside the network simulator — **run, and green but for loss**

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

**Getting the simulator to pass packets at all was a host question**, and the
control is what settled it. ns-3 re-emits frames with raw sockets; with
`bridge-nf-call-iptables=1` those bridged frames traverse iptables and meet
docker's `DOCKER` chain, which ends in DROP. **quic-go against quic-go failed
identically** until `net.bridge.bridge-nf-call-iptables` was set to 0. A narrow
`DOCKER-USER` accept for `193.167.0.0/16` is *hit* and is not sufficient, which
is worth knowing before spending an evening on it. The runner's own Python
needs an interpreter older than 3.14, because pyshark still calls
`asyncio.set_child_watcher`.

Run the control first, always. A red matrix that is really a host problem is
the most expensive wrong answer this document can produce, and one command
tells them apart.

### The result

**As a client, against quic-go's server: nine of nine**, and as a **server
against quic-go's client: eight of eight** — `handshake`, `transfer`,
`chacha20`, `retry`, `http3`, `transferloss`, `multiplexing` and
`handshakeloss`, with `keyupdate` on the client side as well.

`handshakeloss` is the one to read the small print on: it is fifty connections
through 30% loss and a `multiconnect` client abandons the run on the first one
it loses, so it is the case most able to fail for reasons that are nobody's
fault. Three runs of three in both roles on the last measurement. Every other
case has passed on every run since the work that fixed it.

Four defects fell out of the attempt, all in the table in §1: the eight-span
reassembly limit, a probe count that outlived its space, a server that refilled
its send buffer only on inbound datagrams, and a server that truncated
responses over two megabytes and served the prefix.

##### The multi-stream stall — **fixed, and six defects deep**

`transfer` failed as a server on three simultaneous streams carrying several
megabytes: both endpoints idle, neither of them wrong. It took six fixes, and
the chain is the interesting part, because each one uncovered the next.

1. **The send buffer was never reclaimed** — found earlier, and the reason the
   file stopped at 64 KiB.
2. **Reclamation by exact contiguity**: only a range beginning exactly where
   the acknowledged prefix ended advanced the buffer, so the first
   acknowledgement to arrive out of order stopped it for good. What replaced it
   asks a different question — how much of this stream is still in any
   unacknowledged packet — and releases everything below that.
3. **Releasing past the framing watermark.** A loss rewinds framing to the
   start of the lost range, so those octets are back in the buffer waiting; and
   they can sit *below* the highest offset the peer has acknowledged, because
   acknowledgements do not arrive in order. Releasing them put a hole in the
   stream, and the far end reported it as FLOW_CONTROL_ERROR — a name three
   removes from the cause.
4. **`wantsSend` did not consider flow control**, so an endpoint owing a
   MAX_STREAM_DATA said it had nothing to send.
5. **The deadlock underneath all of it: a lost window update.** The limit is
   recorded when the frame is *written*, so a lost MAX_STREAM_DATA is never
   re-sent, and the threshold deciding when to send the next one has already
   moved past it. Loss detection cannot break the tie either — it needs later
   packets to declare the loss, and a deadlocked connection has none. Two fixes
   close it: RFC 9000 §4.1's DATA_BLOCKED and STREAM_DATA_BLOCKED, which are
   the only thing that tells a receiver its update never landed, and §13.3's
   re-advertisement of the current limit when the packet carrying it is lost.
6. **RFC 9001 §5.4.2's padding**, which fell out of fixing (5). Starting
   `max_data_sent` at the limit the transport parameters had already carried —
   rather than at zero, which made every connection owe a MAX_DATA from its
   first packet — took away the frame that had been padding the first 1-RTT
   packet by accident. Four tests failed at once: a payload under four octets
   cannot be sealed, and `send` reported that as "nothing to send". A lone
   HANDSHAKE_DONE is one octet. So is a lone PING probe.

Five of the six are invisible to a peer that neither reorders nor loses
anything, which is every test path this package had.

##### `multiplexing`, and a limit nobody had noticed was one — **fixed**

`multiplexing` is 1999 files on a single connection, and the runner's own
description says what it is for: "server increased stream limits to accommodate
client requests". This package generated no MAX_STREAMS frame anywhere, and the
comment above the constant argued that it did not need to — the limit is
comptime, so it never rises and there is nothing to re-advertise. The limit
never rising *is* the defect. `Streams.open` never freed a slot either, so
`streams_max` bounded how many streams a connection could carry in its
*lifetime* rather than how many it could carry at once.

Closing it needed three things:

1. **Retirement.** A stream whose halves have both reached a terminal state
   gives its slot back. The watermark that records this is contiguous per kind,
   which is not an optimisation: a hole in it cannot tell a retired identifier
   from one that was never opened, and the two need opposite answers — a frame
   for the first is a retransmission to discard, and a frame for the second
   opens a stream. `open` is the one place that knows, and it says so with
   `error.Retired`; each caller decides, and for a frame from the peer the
   decision is to ignore it.
2. **The credit, and telling the peer.** The advertised limit rises as
   peer-initiated streams retire, and a MAX_STREAMS carries it. Any credit at
   all is worth a frame rather than a fraction of the window, because this
   endpoint sends no STREAMS_BLOCKED: with no way for a peer to ask, a threshold
   is a deadlock whenever the credit owed stops one short of it. A lost
   MAX_STREAMS is re-owed like a lost MAX_DATA, and an incoming STREAMS_BLOCKED
   is answered with the current limit.
3. **Two fixed arrays in the shim, for the same reason.** Its own list of
   readable streams was append-only and bounded by the stream table, so the
   twenty-fifth request on a connection was never answered — the library defect
   had been hiding it. And the client refused more requests than it had
   identifiers for, with an `error.TooManyRequests` that read like a guard and
   was a limitation; it now issues them as earlier ones finish.

§3.2's implicit creation went with it, and the reason it is worth recording is
that the argument for doing it was **wrong**. It looked like a live hazard:
`retireOne` reads the identifier at the contiguous watermark and stops when it
is missing, so an identifier that was never created seemed to freeze the stream
credit for the rest of the connection. The revert-check said otherwise. An
implicitly created stream that nobody uses is *unfinished*, and it blocks the
watermark exactly as a missing one does — which is also the right answer, since
§3.2 means the peer has spent that identifier and is holding it. The rule is a
MUST and is now implemented with a test behind it, and what it actually buys is
the sentence the RFC gives for it: the two endpoints agree on which streams
exist. It was written down here as a credit freeze first, and the test that
could not tell the two versions apart is what corrected it.

It also has a cost that a consumer has to size for, so it is stated where the
sizing happens: an identifier at index N means N+1 streams of that kind exist,
so whatever an endpoint advertises is a claim the peer can make on the table all
at once. A table smaller than that answers a conforming peer with
STREAM_LIMIT_ERROR — this endpoint's sizing mistake, reported as the peer's
protocol error. Both shims now state their advertised limits to the stream layer
instead of letting it enforce the table's size, which was larger than what they
had offered.

Retirement then had two consequences worth naming, because both are the kind a
green matrix hides. The first was found by reading the code that had just been
written: an abandoned half never reaches a *clean* terminal state, so a stream
the peer reset could never retire — and with a contiguous watermark, one
RESET_STREAM freezes the credit for that whole kind for the life of the
connection. Every interop case completes its streams cleanly, so nothing here
would have caught it. The second the runner did catch, on the second run rather
than the first: the client read "this stream is not in the table" as "not yet"
rather than "finished", and lost a response's FIN whenever the last of a body
and the end of the stream landed in the same pass. It depends on where a DATA
frame's last octet falls, so it fails on one run and passes on the next — which
is the argument for running the matrix twice.

##### RESET_STREAM — **framed at last**

The largest remaining protocol gap, and it had been recorded as one: two of
section 3.5's MUSTs sat in the ledger as `type=todo` beside the state they moved.
`Connection` put a stream in "Reset Sent" on receiving STOP_SENDING and then
never told the peer, so the final size the two endpoints are supposed to agree
on was never communicated — and a consumer had no way to cancel a stream at all.

`Streams.resetSend` is the one door. It fixes the frame's content on the way in,
which section 13.3 requires: the final size is recorded rather than recomputed,
because the buffer it would be recomputed from moves as the peer acknowledges.
The final size is everything the application handed over, including octets that
will now never be sent — `write` charged them against both windows when it took
them, and section 4.5 makes the final size what the receiver counts, so anything
smaller leaves the two endpoints disagreeing about what this stream spent.
"Reset Sent" is no longer terminal for retirement: a stream that still owes the
frame keeps its slot, because retiring it would drop what the peer is waiting
for.

Two defects came out of writing it, and the second is the more interesting:

1. **`writeStream` read no send state at all**, so a peer that sent
   STOP_SENDING got the rest of the buffer anyway. `wantsSend` refusing is not
   `send` refusing — an owed acknowledgement is enough to build a packet, and
   the stream writer then filled it. The first test written for this could not
   tell the two cases apart: an acknowledgement reclaims the send buffer, so a
   stream that *was* framed and one that never was both end with `framed` at
   zero. Checking `send_len` alongside it is what made the test discriminate.
2. **Skipping section 3.3's terminal states there stalled a transfer.** "Data
   Recvd" is entered when the packet carrying the FIN is acknowledged rather
   than when every packet is, and RFC 9002's loss detection is a heuristic — an
   earlier packet can be declared lost afterwards, which puts its octets back in
   front of the cursor. A sender that refuses to frame them because the state
   says "terminal" stalls the stream with data the peer never received. The
   runner's `http3` case found it one build later, and the honest fix is a
   `type=todo` on section 3.1's precision rather than a guard that reads a state
   this package sets early.

##### STOP_SENDING — **the other half**

Cancelling a bidirectional stream is two frames, and the second one closed the
same week as the first. `resetStream` abandons what this endpoint sends;
`stopSending` abandons what it receives, and neither implies the other — a
consumer cancelling a request wants both.

Its ending is the part worth reading, because it is not the one RESET_STREAM
has. Section 13.3 keeps a STOP_SENDING going *until the peer answers* rather
than until the packet carrying it is acknowledged, and the two are different: an
acknowledged request the peer has not acted on is still outstanding. So it is
re-owed on loss like the others and cleared by either of section 13.3's two
endings — the peer's RESET_STREAM, or the whole stream arriving and being read.
Both of those needed a test that could see the difference, and the first two
could not: they asserted "nothing is owed" at a moment when the frame had
already been framed, which is true whether or not the ending works. Reporting
the packet lost first is what made them discriminate.

##### `handshakeloss` — **two defects, two shim mistakes, and it passes**

The last failing case, and the one this document had explained away. It was
recorded as a performance property — "not a rule broken, a recovery slower than
quic-go's" — on the strength of a measurement that predated most of the work
above. It was four separate things, and only one of them was slow.

**In the package.** A PTO probe is supposed to carry unacknowledged data, and
`Recovery.earliestContext` handed back the earliest *recorded* packet in the
space. Every packet is recorded, acknowledgement-only ones included, and an
acknowledgement carries nothing a retransmission can make progress with — so
whenever an endpoint had sent an ACK before its own flight, every probe rewound
nothing and went out as an ACK and some padding while the peer waited for the
handshake bytes that probe was for. `pto_count` doubles each time it is not
answered, so by the fourth attempt the period is four seconds.

The second is the more interesting, because it was *argued*. RFC 9001 §5.7 says
a server MUST NOT process incoming 1-RTT packets before its handshake is
complete, and the comment beside the rule explained that it held by
construction: a 1-RTT read key only exists once the handshake is complete. That
is true of a client and false of a server — a TLS 1.3 server derives the
application traffic secrets when it *sends* its Finished, one flight before it
has verified the client's. So this server acknowledged a client's first request
while still waiting for that Finished; quic-go read the acknowledgement as
"everything arrived", dropped its Handshake keys, and could no longer
retransmit the Finished that had been lost. Both endpoints then waited, one
probing at Initial and Handshake for thirty seconds and the other counting down
an idle timer.

**In the shim**, two mistakes of its own, and the first is the one worth
remembering. The client's `Session` is reused across connections and carried
its completion counter forward, so from the second connection on `complete()`
answered true before anything had been sent: the loop broke on its first pass,
`run` returned success, and the shim printed "1 of 1 requests in 0ms" fifty
times and exited zero. Nothing in the shim could see it. What saw it was the
runner counting handshakes in the packet capture — eighteen where fifty were
expected — which is exactly the kind of oracle §5.5 exists to buy. The second:
the server retired a peer after five seconds of silence while advertising no
idle timeout at all, which is longer than a working path needs and shorter than
a probe timeout that has backed off twice. It now evicts the least recently
heard from when the table is full, which is pressure-driven and cannot kill a
live handshake, and it advertises the timeout it actually applies.

**The result**, and it is not a clean one: the client passes three runs of
three; the server passes two of three. The run that failed lost one connection
in about thirteen to a bad enough loss streak that quic-go's own handshake
timeout ended it, and a `multiconnect` client abandons the whole run on the
first connection it loses. So `handshakeloss` is a case this package passes and
does not pass reliably, which is worth more written down than a number that
looks like a verdict.

##### The padding, and which packet holds it — **fixed, after getting it wrong once**

§14.1's floor was met by zeroing the datagram after the last packet. The
sentence names two ways to reach 1200 octets — PADDING frames in the Initial
packet, or coalescing — and trailing zeroes are neither. Every peer accepts
them, which is why it had never failed anything: quic-go parses them as one more
packet, cannot unprotect it, and either discards it or spends a slot in its
undecryptable queue on it.

The first attempt put the padding in the Initial packet, which is what §14.1
literally says, and it made things worse: an Initial padded to 1200 leaves no
room to coalesce anything behind it, so a server's flight went out as an Initial
datagram *and* a Handshake datagram — sixty per cent more octets against §8.1's
three-times budget, and two datagrams that both have to survive instead of one.
`handshakeloss` went from two runs in three to none in four. The unit tests
could not see it: they ask whether the datagram reaches 1200, and which packet
holds the padding is invisible to that question. The runner asked a different
one.

What works is padding the *last* packet, and "last" is answered by the keys —
levels are written oldest first, so the last one that can write is the newest
this endpoint holds send keys for. A client's first flight pads its Initial; a
server's flight coalesces Initial and Handshake and pads the Handshake. Both
roles now pass `handshakeloss` three runs of three, and a client's datagrams
carry no trailing zeroes at all: twelve "not a QUIC packet" in a run before,
none after.

##### Probe coalescing — **and the padding fallback stopped firing**

RFC 9002 §6.2.4 asks a sender to probe the *other* packet number spaces that
have data in flight, coalescing them, and this package probed only the space
whose timer expired. A handshake is two spaces at once: a server whose Initial
and Handshake packets were both lost repaired one of them per timeout while the
other space's timer backed off in parallel. The comment beside the rule said the
coalescing "cannot be driven from this answer", which was true of `Recovery`
alone and not of `Recovery` plus the caller — `Connection.onTimeout` now walks
the other spaces, asks `earliestContext` which of them have anything in flight,
and probes those too.

The two changes turned out to be the same change seen twice. A probe carrying
only Initial data has nothing behind it, so §14.1's floor had no later packet to
live in and fell back to trailing zeroes; the fallback fired on eleven of
fifteen padded server datagrams. With coalescing it fires on none — but only
after two corrections to *which* packet is expected to be last, both of which
the runner had to point out:

1. The newest level this endpoint holds send keys for is not the last one to
   write. A server installs 1-RTT send keys when it sends its Finished, so from
   that moment the newest level has nothing to say on a handshake datagram.
   Sixty-four of a hundred and eleven datagrams fell back.
2. Nor is the newest level that has *keys and something owed* the same as the
   newest with keys. Adding the second half — unframed CRYPTO, a pending probe,
   or an owed acknowledgement — took it from twenty-four in a hundred and twenty
   to zero.

A guess that is wrong here costs trailing zeroes and never a short datagram,
which is why guessing is acceptable at all: the fallback is what makes §14.1's
MUST independent of the heuristic above it. It is still there, and now unused on
every path the runner exercises.

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

`Connection.zig` is 8127 lines, roughly half of them RFC citations. Both send-path findings were
about the order in which state is committed, so a rewrite would separate the
send scheduler from the packet builder, and pull address validation and the
amplification budget into a struct with its own invariant check the simulator
calls after every datagram. Neither is needed for §5.1 through §5.5.

### 5.7 A qlog trace — **written, and partial on purpose**

`src/qlog.zig` turns a record into octets and stops; `interop/qlog_file.zig`
opens `$QLOGDIR/<odcid>.sqlog` and writes them. The split is the seam's, for the
seam's reason: the library holds no file and no clock. Both roles write one
trace per connection, named for the *original* Destination Connection ID, which
is the one value both endpoints agree on before either has chosen anything — so
a client's trace and a server's of the same connection sit side by side under
one name.

**There are no packet events, and that is the honest shape of this trace.**
`transport:packet_sent` and `packet_received` are most of what a qvis timeline
is made of, and this seam does not expose them: `poll` is a queue of things a
consumer must *act* on, bounded at `events_max`, and a packet-per-event stream
would overflow it on every connection that did any work. Reporting packets needs
a sink rather than a queue — a change to the shape of the seam, not to the
writer. What a trace carries instead is the metrics after every flush, the loss
counts, the key updates, the close, the stream terminations, and the datagram
counts the *consumer* knows because it holds the socket. A 5 MiB transfer
produces about 22,000 records, all of them valid JSON-SEQ.

It is worth being clear about what this is for, because the obvious guess is
wrong: **nothing in the interop runner reads a qlog.** It sets `QLOGDIR`, keeps
what is written there, and that is all. The value is a trace a person or `qvis`
can read after a failure, not a measurement anything takes.

Two defects, both in the new code and both of one kind:

- **`src/qlog.zig`'s tests never ran.** `src/root.zig` has a `test` block that
  names each module, and a module nobody names is a module whose tests Zig does
  not compile. The file was written, wired into both roles, and passing for an
  hour — and the first test to actually execute failed.
- **What it was hiding**: two variants wrote their first field with the raw
  text writer, which does not do the comma bookkeeping, and emitted two fields
  with nothing between them. Balanced braces, and not JSON. The test that caught
  it parses each record with `std.json.validate`; the one it replaced counted
  braces, and counting braces would have passed.

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
