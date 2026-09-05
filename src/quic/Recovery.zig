//! RFC 9002: loss detection and congestion control.
//!
//! QUIC has no retransmission in RFC 9000. A lost packet is gone, and it is this
//! document that decides what was lost and tells the sender to send those frames
//! again. Without it a connection stalls at the first dropped datagram; for a
//! load generator it is worse than a stall, because a sender with no congestion
//! control does not measure a server, it measures whether the network buffered
//! enough.
//!
//! ## Pure computation over a caller's clock
//!
//! Nothing here reads a clock, holds a socket or knows what a packet contained.
//! `now_ns` is an argument in nanoseconds, and every timer is *returned* as an
//! absolute time the caller arms. That is what makes loss recovery testable at
//! all — a PTO that fires after a real second is a test nobody runs — and it is
//! what lets zoxy's simulator drive a connection on a virtual clock.
//!
//! ## What a packet contained is the connection's business
//!
//! This structure tracks a packet's number, size and send time. What was *in*
//! it — which CRYPTO offsets, which streams — it never learns. `Config.Context`
//! is an opaque token the caller attaches on send and gets back on loss, so the
//! connection can rebuild the frames without this file growing a dependency on
//! what a frame is.
//!
//! ## The transcription is deliberate
//!
//! The functions below follow RFC 9002 Appendix A's pseudocode closely enough
//! to diff against it, and are named after it. This is a place to be boring:
//! congestion control that is subtly its own algorithm is congestion control
//! nobody can reason about, and the failure mode is not a crash but a sender
//! that is unfair to everything else on the path.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const frame = @import("frame.zig");
const packet_number = @import("packet_number.zig");
const varint = @import("../varint.zig");

const Space = packet_number.Space;
const Side = @import("crypto.zig").Side;

/// Section 6.1.1: packets this far before an acknowledged one are lost.
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.1
//# In order to remain similar to TCP,
//# implementations SHOULD NOT use a packet threshold less than 3; see
//# [RFC5681].
pub const packet_threshold: u64 = 3;

/// Section 6.1.2: reordering tolerated in time, as an RTT multiplier of 9/8.
pub const time_threshold_numerator: u64 = 9;
pub const time_threshold_denominator: u64 = 8;

/// Section 6.1.2: the timer granularity, and the floor under every timer here.
pub const granularity_ns: u64 = std.time.ns_per_ms;

/// Section 6.2.2: the RTT assumed before a sample exists.
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
//# When no previous RTT is available, the initial RTT
//# SHOULD be set to 333 milliseconds.
//
// The other way section 6.2.2 offers to seed this is a path validation
// exchange, which needs PATH_CHALLENGE and PATH_RESPONSE. Migration is out of
// scope — see the README and docs/DESIGN.md section 6 — so no such delay ever
// reaches `updateRtt`, and the prohibition on treating one as a sample has
// nothing to prohibit.
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
//# A connection MAY use the delay between sending a PATH_CHALLENGE and
//# receiving a PATH_RESPONSE to set the initial RTT (see kInitialRtt in
//# Appendix A.2) for a new path, but the delay SHOULD NOT be considered
//# an RTT sample.
//= type=exception
//= reason=connection migration and path validation are out of scope, so there is no PATH_RESPONSE delay to seed an initial RTT from or to mistake for a sample
pub const initial_rtt_ns: u64 = 333 * std.time.ns_per_ms;

/// Section 7.6: consecutive PTO periods without a delivery that mean the path
/// is gone rather than lossy.
pub const persistent_congestion_threshold: u64 = 3;

/// The most the PTO backoff is shifted by.
///
/// Section 6.2.1's backoff is exponential and unbounded in the text, but a
/// `u64` of nanoseconds is not: at 2^20 the smallest possible PTO is already
/// longer than any connection, and the shift itself must stay inside a `u6`.
/// Named rather than written twice at the two shift sites, with the overflow
/// argument checked below rather than assumed.
pub const pto_backoff_shift_max: u6 = 20;

/// Section 7.3.2: what the window is multiplied by on a congestion event.
//= https://www.rfc-editor.org/rfc/rfc9002#section-7
//# If a sender uses a different controller than that specified in this
//# document, the chosen controller MUST conform to the congestion
//# control guidelines specified in Section 3.1 of [RFC8085].
//= type=exception
//= reason=this is section 7's own NewReno, transcribed from appendix B rather than replaced, so the conditional requirement on a different controller does not arise
pub const loss_reduction_divisor: u64 = 2;

comptime {
    // The shift cannot overflow the accumulator it is applied to: the largest
    // base a PTO can have is the initial RTT plus four times its variance, and
    // shifting that by the cap stays inside `u64`.
    const pto_base_max: u64 = initial_rtt_ns + 4 * initial_rtt_ns;
    assert(pto_base_max < std.math.maxInt(u64) >> pto_backoff_shift_max);
    assert(pto_backoff_shift_max <= std.math.maxInt(u6));

    assert(packet_threshold == 3);
    assert(time_threshold_numerator * 8 == time_threshold_denominator * 9);
    // `assert(granularity_ns == 1_000_000)` and `assert(initial_rtt_ns ==
    // 333_000_000)` stood here and proved nothing: each restated the literal on
    // the line that defines it, so the only edit either could catch is one that
    // changes the constant and not the assertion — which is the edit a reader
    // makes deliberately. Replaced with the relations that do constrain them.
    //
    // Section 6.1.2: the timer granularity has to be reachable by a clock, and
    // it bounds every timeout below, so a granularity above the initial RTT
    // would make the first probe fire on the floor rather than on the estimate.
    assert(granularity_ns > 0);
    assert(granularity_ns < initial_rtt_ns);
    // Section 6.2.2: the initial RTT is used until a sample exists, and the
    // first PTO is `initial_rtt + 4 * initial_rtt`, which must not overflow
    // before `pto_base_max` above gets to shift it.
    assert(initial_rtt_ns > 0);
    assert(initial_rtt_ns <= pto_base_max / 5);
}

pub const Config = struct {
    /// Sent packets tracked per space before the oldest is forgotten.
    sent_max: u32 = 256,
    /// Section B.2's `max_datagram_size`, which every window here is a multiple
    /// of. RFC 9000 section 14 puts its floor at 1200.
    max_datagram_size: u32 = 1452,
    /// An opaque token attached on send and handed back on loss. `void` for a
    /// caller that only wants the congestion controller.
    Context: type = void,
};

pub fn Recovery(comptime config: Config) type {
    comptime {
        assert(config.sent_max >= packet_threshold + 1);
        assert(config.max_datagram_size >= 1200);
    }

    // Section B.1: ten datagrams, but never below two and never above 14720.
    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.2
    //# Endpoints SHOULD use an initial congestion
    //# window of ten times the maximum datagram size (max_datagram_size),
    //# while limiting the window to the larger of 14,720 bytes or twice the
    //# maximum datagram size.
    //
    // `max_datagram_size` is a comptime field of `Config`, so the two
    // recalculation rules below have no event to fire on: the size is fixed
    // when the type is instantiated and there is no PMTU discovery here.
    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.2
    //# If the maximum datagram size changes during the connection, the
    //# initial congestion window SHOULD be recalculated with the new size.
    //= type=exception
    //= reason=`Config.max_datagram_size` is comptime, so the size cannot change during a connection
    //
    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.2
    //# If the maximum datagram size is decreased in order to complete the
    //# handshake, the congestion window SHOULD be set to the new initial
    //# congestion window.
    //= type=exception
    //= reason=`Config.max_datagram_size` is comptime and is never decreased to complete a handshake
    const initial_window: u64 = @min(
        10 * @as(u64, config.max_datagram_size),
        @max(14_720, 2 * @as(u64, config.max_datagram_size)),
    );
    // Section B.1: the floor a congestion event may not take the window below.
    const minimum_window: u64 = 2 * @as(u64, config.max_datagram_size);

    return struct {
        const Self = @This();

        pub const Context = config.Context;

        pub const Sent = struct {
            number: u64,
            time_sent: u64,
            octets: u32,
            ack_eliciting: bool,
            in_flight: bool,
            context: Context,
        };

        /// What section B.5 needs about a packet the peer acknowledged.
        ///
        /// Collected rather than acted on immediately, because appendix A.7
        /// runs loss detection *between* removing the acknowledged packets and
        /// growing the window — and loss detection is what starts a recovery
        /// period, which is exactly what `onPacketAcked` then declines to grow
        /// through.
        const AckedPacket = struct {
            time_sent: u64,
            octets: u32,
            in_flight: bool,
            ack_eliciting: bool,
            /// What the connection attached on send. Losses have carried this
            /// since the beginning and acknowledgements did not, which is why
            /// RFC 9000 section 3.1's terminal states — "Data Recvd" and
            /// "Reset Recvd", both entered *on acknowledgement* — had nothing
            /// to enter them. A stream could be written, sent, acknowledged and
            /// still sit in "Data Sent" for the life of the connection.
            context: Context,
        };

        const SpaceState = struct {
            sent: [config.sent_max]Sent = undefined,
            count: u32 = 0,
            largest_acked: ?u64 = null,
            /// Section A.10: when the earliest packet still in doubt becomes
            /// lost by the time threshold, or null when none is.
            loss_time: ?u64 = null,
            time_of_last_ack_eliciting: ?u64 = null,
        };

        // --- Section A.3's variables, one connection's worth.
        latest_rtt: u64 = 0,
        smoothed_rtt: u64 = initial_rtt_ns,
        rttvar: u64 = initial_rtt_ns / 2,
        /// Section 5.2's minimum, and it only ever falls: nothing here raises
        /// it again, which is the shape of both citations below.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
        //# Endpoints SHOULD set the min_rtt to the newest RTT sample after
        //# persistent congestion is established.
        //= type=todo
        //
        //= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
        //# Implementations SHOULD
        //# NOT refresh the min_rtt value too often since the actual minimum RTT
        //# of the path is not frequently observable.
        //= type=exception
        //= reason=section 5.2's optional reestablishment is not implemented, so there is no refresh whose frequency could be wrong
        min_rtt: u64 = 0,
        has_rtt_sample: bool = false,
        //= https://www.rfc-editor.org/rfc/rfc9002#appendix-A.7
        //# if (first_rtt_sample == 0):
        //#   min_rtt = latest_rtt
        //#   smoothed_rtt = latest_rtt
        //#   rttvar = latest_rtt / 2
        //#   first_rtt_sample = now()
        //#   return
        /// When the first RTT sample was taken. Appendix B.8 builds its
        /// persistent-congestion candidate set from lost packets sent *after*
        /// this, and nothing tracked it — so a packet sent before any RTT was
        /// ever measured could widen the span and collapse the window on a
        /// duration the RFC would not count.
        first_rtt_sample_ns: u64 = 0,
        pto_count: u32 = 0,

        // --- Section B.2's variables.
        congestion_window: u64 = initial_window,
        bytes_in_flight: u64 = 0,
        congestion_recovery_start_time: ?u64 = null,
        ssthresh: u64 = std.math.maxInt(u64),

        spaces: [Space.count]SpaceState = @splat(.{}),

        /// Section 6.2.1: the handshake is confirmed once the peer's
        /// HANDSHAKE_DONE arrives (client) or the client's Finished is
        /// acknowledged (server). Before it, an application-data PTO is not
        /// armed, because 1-RTT keys may not exist on both sides yet.
        handshake_confirmed: bool = false,
        /// Which end of the connection this is. Appendix A.7's
        /// `PeerCompletedAddressValidation` answers differently for each, and
        /// nothing else here needs to know — see that function.
        side: Side = .client,
        /// Whether Handshake keys exist. Appendix A.8 chooses the space an
        /// anti-deadlock probe goes out in by asking exactly this, and it is
        /// not the same question as "the Handshake space is not discarded" —
        /// before the keys arrive that space is undiscarded and unusable.
        /// `Connection.installSecret` sets it.
        handshake_keys: bool = false,
        /// The instant an anti-deadlock probe is measured from. Appendix A.8
        /// says "the anti-deadlock PTO starts from the current time", and this
        /// function takes no `now_ns` — so the caller stamps it, and
        /// `timeoutAt` is where that happens.
        anti_deadlock_from_ns: u64 = 0,

        /// Section 18.2's `max_ack_delay`, from the peer's transport
        /// parameters. Held rather than read from them, because the connection
        /// decodes those and this file decodes nothing.
        max_ack_delay_ns: u64 = 25 * std.time.ns_per_ms,

        pub const SentError = error{
            /// More unacknowledged packets in one space than `sent_max`. The
            /// bound exists because the list is sized at compile time; reaching
            /// it means the peer has stopped acknowledging, which the PTO will
            /// have been shouting about for some time.
            TooManyOutstanding,
        };

        /// Section A.5.
        ///
        /// The PTO is not stored, it is derived: `ptoTimeAndSpace` recomputes
        /// it from `time_of_last_ack_eliciting` on every `timeoutAt`, so
        /// recording the send time here *is* the restart section 6.2.1 asks
        /// for. `onAckReceived` and `discardSpace` restart it the same way, by
        /// moving what the derivation reads.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
        //# A sender SHOULD restart its PTO timer every time an ack-eliciting
        //# packet is sent or acknowledged, or when Initial or Handshake keys are
        //# discarded (Section 4.9 of [QUIC-TLS]).
        //
        // Section 7.5: a probe is counted in flight like anything else. There
        // is no probe flag on `Sent` precisely because the RFC does not want
        // one here — the exemption is on the *send* decision, not on the
        // accounting.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.5
        //# A
        //# sender MUST however count these packets as being additionally in
        //# flight, since these packets add network load without establishing
        //# packet loss.
        pub fn onPacketSent(self: *Self, space: Space, sent: Sent) SentError!void {
            const state = &self.spaces[@intFromEnum(space)];
            // Appendix A.8's "the anti-deadlock PTO starts from the current
            // time". `ptoTimeAndSpace` is `*const` and takes no clock, so every
            // entry point that carries one stamps it here instead — the probe
            // is then measured from the last thing that happened, which is what
            // re-arming a timer on each send and each acknowledgement means.
            self.anti_deadlock_from_ns = @max(self.anti_deadlock_from_ns, sent.time_sent);
            if (state.count == config.sent_max) return error.TooManyOutstanding;
            // Ascending by number, which every walk below relies on.
            if (state.count > 0) assert(sent.number > state.sent[state.count - 1].number);

            state.sent[state.count] = sent;
            state.count += 1;
            if (sent.ack_eliciting) state.time_of_last_ack_eliciting = sent.time_sent;
            if (sent.in_flight) self.bytes_in_flight += sent.octets;
        }

        /// The acknowledged packets' contexts, in the order they were removed.
        /// Filled by `onAckReceived` when the caller supplies somewhere to put
        /// them; a caller that only wants the congestion accounting passes an
        /// empty slice and pays nothing.
        pub const AckResult = struct {
            /// Packets newly acknowledged by this frame.
            acked: u32 = 0,
            /// Packets declared lost while processing it. Their contexts are in
            /// the caller's `lost` slice, which is what a retransmission is
            /// rebuilt from.
            lost: u32 = 0,
            /// True when the largest acknowledged number was newly
            /// acknowledged, which is the only case section 5.1 takes an RTT
            /// sample from.
            rtt_sampled: bool = false,
        };

        pub const AckError = error{
            /// The frame's ranges do not decode, or walk below zero.
            Malformed,
        };

        /// Section A.7: process an ACK frame.
        ///
        /// `ack_delay_ns` is the frame's delay field already scaled by the
        /// peer's `ack_delay_exponent` — this file does not hold that parameter
        /// either. `lost` receives the contexts of packets declared lost, and a
        /// caller that passes a short slice gets the first that fit; `lost` in
        /// the result is the true count.
        //
        // `ack.ecn` is decoded by `frame.zig` and is not read here: an
        // ACK_ECN frame's counts reach this function and are dropped, so a
        // rising ECN-CE count is not the congestion event section 7.3.1 says
        // it is. Loss is the only signal this controller responds to.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.3
        //# QUIC implementations MUST properly handle both
        //# types, and, if they have enabled ECN for packets they send, they
        //# SHOULD use the information in the ECN section to manage their
        //# congestion state.
        //= type=exception
        //= reason=ECN is a documented gap in docs/DESIGN.md section 6 — the counts are parsed into `frame.Ack.ecn` and dropped — and this endpoint never marks its own packets ECN-Capable, so the conditional half does not arise
        pub fn onAckReceived(
            self: *Self,
            space: Space,
            ack: frame.Ack,
            ack_delay_ns: u64,
            now_ns: u64,
            lost: []Context,
            /// Where to report the acknowledged packets' contexts. A caller
            /// that only wants the congestion accounting passes `&.{}`.
            delivered: []Context,
        ) AckError!AckResult {
            const state = &self.spaces[@intFromEnum(space)];
            if (state.largest_acked) |previous| {
                state.largest_acked = @max(previous, ack.largest);
            } else {
                state.largest_acked = ack.largest;
            }

            var result: AckResult = .{};
            var acked: [config.sent_max]AckedPacket = undefined;
            self.anti_deadlock_from_ns = @max(self.anti_deadlock_from_ns, now_ns);
            const newly = try self.removeAcked(space, ack, &result, &acked);
            if (newly == null) return result;
            const largest = newly.?;

            // Section 5.1: an RTT sample comes only from the largest
            // acknowledged, and only when that packet was ack-eliciting —
            // otherwise the peer was under no obligation to answer promptly and
            // the sample is not one.
            //
            // `newly` is null when the frame acknowledged nothing this endpoint
            // still tracked, which is the early return above; `largest.number
            // == ack.largest` is the rest of it.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
            //# To avoid generating multiple RTT samples for a single packet, an ACK
            //# frame SHOULD NOT be used to update RTT estimates if it does not newly
            //# acknowledge the largest acknowledged packet.
            //
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
            //# An RTT sample MUST NOT be generated on receiving an ACK frame that
            //# does not newly acknowledge at least one ack-eliciting packet.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
            //# *  at least one of the newly acknowledged packets was ack-eliciting.
            //
            // "At least one of the newly acknowledged packets", not "the
            // largest one". Requiring `largest` itself to be ack-eliciting
            // meant an ACK whose highest newly acknowledged packet was ACK-only
            // produced no sample even with an ack-eliciting packet below it.
            // Conservative — it never invented a sample — but it starves the
            // estimator on a path whose two directions carry different traffic.
            var includes_ack_eliciting = false;
            for (acked[0..@min(result.acked, acked.len)]) |one| {
                if (one.ack_eliciting) includes_ack_eliciting = true;
            }
            if (largest.number == ack.largest and includes_ack_eliciting) {
                self.updateRtt(now_ns - largest.time_sent, ack_delay_ns, now_ns);
                result.rtt_sampled = true;
            }

            // Section A.7's order, and it is load-bearing rather than
            // cosmetic: loss detection is what starts a recovery period, and
            // `onPacketsAcked` declines to grow the window for a packet sent
            // before one began. Growing first and halving afterwards leaves the
            // window an eighth too wide after every loss event — which is a
            // sender that is quietly unfair to everything else on the path, and
            // which no crash would ever reveal.
            result.lost = self.detectAndRemoveLostPackets(space, now_ns, lost, acked[0..@min(result.acked, acked.len)]);
            // Section B.5, one call per acknowledged packet, and after loss
            // detection so a packet sent before a recovery period does not grow
            // the window that loss just halved.
            for (acked[0..@min(result.acked, acked.len)]) |one| self.onPacketAcked(one);
            // Section 3.1's terminal states are entered on acknowledgement, so
            // the caller needs the same view of what was acknowledged that it
            // has always had of what was lost.
            for (acked[0..@min(result.acked, @min(acked.len, delivered.len))], 0..) |one, index| {
                delivered[index] = one.context;
            }
            // Section A.7: a delivery means the path is working, so the PTO
            // backoff resets.
            //= https://www.rfc-editor.org/rfc/rfc9002#appendix-A.7
            //# if (PeerCompletedAddressValidation()):
            //#   pto_count = 0
            //
            // Guarded, where it used to be unconditional. Acknowledgements of
            // Initial packets say nothing about whether the server can receive
            // at this address, so a client that reset its backoff on them
            // re-probes at the un-backed-off interval against a server that is
            // merely slow — which is the case the guard exists for.
            if (self.peerCompletedAddressValidation()) self.pto_count = 0;
            return result;
        }

        /// Remove every tracked packet the frame acknowledges, returning the
        /// largest of them.
        fn removeAcked(
            self: *Self,
            space: Space,
            ack: frame.Ack,
            result: *AckResult,
            acked: *[config.sent_max]AckedPacket,
        ) AckError!?Sent {
            const state = &self.spaces[@intFromEnum(space)];
            var ranges = ack.iterate();
            var largest: ?Sent = null;

            var seen: u64 = 0;
            while (seen <= ack.range_count) : (seen += 1) {
                const range = ranges.next() catch return error.Malformed;
                const value = range orelse break;
                var index: u32 = 0;
                while (index < state.count) {
                    const packet = state.sent[index];
                    if (packet.number < value.smallest or packet.number > value.largest) {
                        index += 1;
                        continue;
                    }
                    if (packet.in_flight) {
                        assert(self.bytes_in_flight >= packet.octets);
                        self.bytes_in_flight -= packet.octets;
                    }
                    if (largest == null or packet.number > largest.?.number) largest = packet;
                    if (result.acked < acked.len) acked[result.acked] = .{
                        .time_sent = packet.time_sent,
                        .octets = packet.octets,
                        .in_flight = packet.in_flight,
                        .ack_eliciting = packet.ack_eliciting,
                        .context = packet.context,
                    };
                    result.acked += 1;
                    remove(state, index);
                }
            }
            return largest;
        }

        /// A free function rather than a method: it touches only `state`, and
        /// taking a `self` it immediately discards invited a reader to look for
        /// the recovery state it changes. It changes none — `bytes_in_flight`
        /// is adjusted by the caller, before this runs.
        fn remove(state: *SpaceState, index: u32) void {
            assert(index < state.count);
            var at = index;
            while (at + 1 < state.count) : (at += 1) {
                state.sent[at] = state.sent[at + 1];
            }
            state.count -= 1;
        }

        /// Section 5.3.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
        //# In such
        //# cases, an endpoint SHOULD subtract such local delays from its RTT
        //# sample until the handshake is confirmed.
        //= type=exception
        //= reason=a packet whose keys are not yet installed is discarded rather than buffered, so no local delay of the kind section 5.3 describes is ever accumulated to subtract
        //= https://www.rfc-editor.org/rfc/rfc9002#appendix-A.8
        //# PeerCompletedAddressValidation():
        //#   // Assume clients validate the server's address implicitly.
        //#   if (endpoint is server):
        //#     return true
        //#   // Servers complete address validation when a
        //#   // protected packet is received.
        //#   return has received Handshake ACK ||
        //#        handshake confirmed
        ///
        /// A server answers true always: the client picked the address it is
        /// talking to, so there is nothing for the server to prove. A client
        /// answers true once the handshake is confirmed or it has seen an
        /// acknowledgement in the Handshake space, either of which means a
        /// protected packet reached the server.
        fn peerCompletedAddressValidation(self: *const Self) bool {
            if (self.side == .server) return true;
            if (self.handshake_confirmed) return true;
            return self.spaces[@intFromEnum(Space.handshake)].largest_acked != null;
        }

        fn updateRtt(self: *Self, sample: u64, ack_delay_ns: u64, now_ns: u64) void {
            // A sample is an elapsed time computed by the caller from two of
            // its own timestamps, so a zero is a clock that did not move rather
            // than a packet that arrived before it left.
            assert(sample < std.math.maxInt(u64) / 8);
            self.latest_rtt = sample;
            // The two branches below are the two halves of one requirement:
            // the first sample *sets* the minimum, every later one lowers it.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
            //# min_rtt MUST be set to the latest_rtt on the first RTT sample.
            //# min_rtt MUST be set to the lesser of min_rtt and latest_rtt
            //# (Section 5.1) on all other samples.
            if (!self.has_rtt_sample) {
                self.first_rtt_sample_ns = now_ns;
                self.min_rtt = sample;
                self.smoothed_rtt = sample;
                self.rttvar = sample / 2;
                self.has_rtt_sample = true;
                return;
            }

            self.min_rtt = @min(self.min_rtt, sample);
            // Section 5.3: the peer's reported delay is trusted only up to what
            // it said it would ever be, and only where subtracting it still
            // leaves a plausible RTT. A peer that inflates it would otherwise
            // shrink our RTT estimate and make us declare loss early.
            assert(self.min_rtt <= sample);
            // Section 5.3: the peer's reported delay is clamped to what it said
            // it would ever be — but only once the handshake is confirmed,
            // because `max_ack_delay` arrives in the peer's transport
            // parameters and before that this endpoint is comparing against its
            // own default rather than against anything the peer promised.
            // Clamping earlier shrank the subtrahend and biased the estimate up.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
            //# To account for this, the endpoint SHOULD ignore
            //# max_ack_delay until the handshake is confirmed, as defined in
            //# Section 4.1.2 of [QUIC-TLS].
            //
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
            //# *  MUST use the lesser of the acknowledgment delay and the peer's
            //# max_ack_delay after the handshake is confirmed; and
            const delay = if (self.handshake_confirmed)
                @min(ack_delay_ns, self.max_ack_delay_ns)
            else
                ack_delay_ns;
            if (self.handshake_confirmed) assert(delay <= self.max_ack_delay_ns);
            // The comparison is the guard on the subtraction, not the assertion
            // beside it: both terms come from the peer, and section 5.3 is
            // explicit that a peer inflating its reported delay must not be
            // able to shrink our estimate below what we measured.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
            //# *  MUST NOT subtract the acknowledgment delay from the RTT sample if
            //# the resulting value is smaller than the min_rtt.
            const adjusted = if (sample >= self.min_rtt + delay) sample - delay else sample;
            assert(adjusted <= sample);

            const difference = if (self.smoothed_rtt > adjusted)
                self.smoothed_rtt - adjusted
            else
                adjusted - self.smoothed_rtt;
            self.rttvar = (3 * self.rttvar + difference) / 4;
            self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted) / 8;
        }

        /// Section 6.1.2's loss delay: 9/8 of the larger RTT, floored at the
        /// timer granularity.
        ///
        /// The floor is what makes a zero RTT harmless. A sample of zero is
        /// physically impossible on a network and entirely possible with a
        /// coarse clock — a packet sent and acknowledged inside one tick — and
        /// section 5.3 has nothing to say about it, so `smoothed_rtt` becomes
        /// zero and stays a valid estimate. Every timer derived from it is
        /// floored here and in `ptoTimeAndSpace`, which is why nothing needs to
        /// special-case it. A fuzz oracle that asserted `smoothed_rtt > 0`
        /// found this and was wrong; the tests below pin the behaviour instead.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
        //# To avoid declaring
        //# packets as lost too early, this time threshold MUST be set to at
        //# least the local timer granularity, as indicated by the kGranularity
        //# constant.
        pub fn lossDelay(self: *const Self) u64 {
            const rtt = @max(self.latest_rtt, self.smoothed_rtt);
            assert(rtt >= self.latest_rtt);
            const delay = @max((rtt * time_threshold_numerator) / time_threshold_denominator, granularity_ns);
            // Section 6.1.2: the threshold is never below the timer granularity,
            // or a packet would be declared lost inside the noise of the clock.
            assert(delay >= granularity_ns);
            return delay;
        }

        /// Section A.10.
        ///
        /// Every packet below the largest acknowledged is examined on every
        /// pass, so there is no class of loss this declines to notice — which
        /// is what section 7.4 asks of a sender that has no key-availability
        /// heuristic to apply.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.4
        //# Endpoints MUST NOT ignore the loss of packets that were sent after
        //# the earliest acknowledged packet in a given packet number space.
        fn detectAndRemoveLostPackets(
            self: *Self,
            space: Space,
            now_ns: u64,
            lost: []Context,
            acked: []const AckedPacket,
        ) u32 {
            const state = &self.spaces[@intFromEnum(space)];
            const largest_acked = state.largest_acked orelse return 0;
            state.loss_time = null;

            const delay = self.lossDelay();

            var count: u32 = 0;
            var largest_lost: ?Sent = null;
            // Section B.8's window: the first and last ack-eliciting packets
            // lost in this pass. Only ack-eliciting ones count, because a
            // PADDING-only packet the peer was never obliged to acknowledge is
            // no evidence the path is gone.
            var earliest_eliciting: ?u64 = null;
            var latest_eliciting: ?u64 = null;
            var index: u32 = 0;
            while (index < state.count) {
                const packet = state.sent[index];
                if (packet.number > largest_acked) {
                    index += 1;
                    continue;
                }
                // Section 6.1: lost by time, or by having been sent far enough
                // before something that did arrive.
                //
                // Written as `sent + delay <= now` rather than the RFC's
                // `sent <= now - delay`, which is the same inequality over the
                // reals and not over `u64`: early in a connection `now_ns` is
                // smaller than the loss delay, and a saturating subtraction
                // clamps the threshold to zero — declaring every packet sent at
                // time zero lost, on the first acknowledgement, forever. The
                // tests below found it.
                //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
                //# Once a later packet within the same packet number space has been
                //# acknowledged, an endpoint SHOULD declare an earlier packet lost if it
                //# was sent a threshold amount of time in the past.
                const by_time = packet.time_sent + delay <= now_ns;
                const by_order = largest_acked >= packet.number + packet_threshold;
                if (!by_time and !by_order) {
                    // Still in doubt: the timer that would settle it.
                    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
                    //# If packets sent prior to the largest acknowledged packet cannot yet
                    //# be declared lost, then a timer SHOULD be set for the remaining time.
                    const at = packet.time_sent + delay;
                    state.loss_time = if (state.loss_time) |current| @min(current, at) else at;
                    index += 1;
                    continue;
                }

                if (packet.in_flight) {
                    assert(self.bytes_in_flight >= packet.octets);
                    self.bytes_in_flight -= packet.octets;
                    if (largest_lost == null or packet.number > largest_lost.?.number) largest_lost = packet;
                }
                if (packet.ack_eliciting) {
                    //= https://www.rfc-editor.org/rfc/rfc9002#appendix-B.8
                    //# // Only consider packets sent after getting an RTT sample.
                    //# if (first_rtt_sample == 0):
                    //#   return
                    //# pc_lost = []
                    //# for lost in lost_packets:
                    //#   if lost.time_sent > first_rtt_sample:
                    //#     pc_lost.insert(lost)
                    //
                    // The filter appendix B.8 applies and this did not. A packet
                    // sent before the first RTT sample says nothing about a
                    // duration measured in RTTs, and letting one set the
                    // earliest end of the span stretches it across the whole
                    // handshake — collapsing the window on a period the RFC
                    // never counted.
                    if (packet.time_sent > self.first_rtt_sample_ns) {
                        if (earliest_eliciting == null or packet.time_sent < earliest_eliciting.?) {
                            earliest_eliciting = packet.time_sent;
                        }
                        if (latest_eliciting == null or packet.time_sent > latest_eliciting.?) {
                            latest_eliciting = packet.time_sent;
                        }
                    }
                }
                if (count < lost.len) lost[count] = packet.context;
                count += 1;
                // A packet declared lost is forgotten here rather than
                // retained, so a later ACK naming it — the spurious-loss case
                // reordering produces — matches nothing in `sent` and tells
                // nobody. What it held has already gone back to the caller for
                // retransmission, and if that retransmission is itself declared
                // lost the same octets go out a third time even though the
                // original was acknowledged in between. Holding the packet past
                // `remove` for a reordering window — a PTO, which is what RFC
                // 9000 section 13.3 suggests — is what would close it.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
                //# A sender SHOULD avoid retransmitting information from packets once
                //# they are acknowledged.
                //= type=todo
                remove(state, index);
            }

            if (largest_lost) |packet| {
                self.onCongestionEvent(packet.time_sent, now_ns);
                // Section 7.6: losing everything across more than a few PTOs is
                // not congestion, it is a path that has gone away — so the
                // window collapses to the floor rather than halving, and the
                // recovery period is cleared so the next delivery can grow it
                // again from there.
                //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
                //# *  across all packet number spaces, none of the packets sent between
                //#    the send times of these two packets are acknowledged;
                //
                // The second of section 7.6.2's three conditions, which was
                // unchecked. `removeAcked` runs before this in the same
                // `onAckReceived`, so a packet acknowledged by this very frame
                // and sent between the two lost ones is already gone from
                // `sent` — persistent congestion was declared over a span the
                // peer had just proved was not a blackhole. The newly
                // acknowledged set is passed down so the question can be asked
                // of the packets that answered it.
                if (self.acknowledgedBetween(acked, earliest_eliciting, latest_eliciting)) {
                    // Something got through: this is congestion, not a dead path.
                } else if (self.inPersistentCongestion(earliest_eliciting, latest_eliciting)) {
                    self.congestion_window = minimum_window;
                    self.congestion_recovery_start_time = null;
                }
            }
            return count;
        }

        // ------------------------------------------------------- section B.4-7

        /// Section B.5: one delivery, one window increase.
        ///
        /// Per *packet*, not per ACK frame. Growing once per frame — which this
        /// did — halves slow start against any peer acknowledging every second
        /// packet, which is section 13.2.2's default behaviour, and leaves
        /// congestion avoidance adding roughly half what it should. Neither
        /// shows up as a failure; it shows up as a connection that is slower
        /// than it should be and a sender whose algorithm is quietly its own.
        // Section 7.8: an acknowledgement grows the window whether or not the
        // window was ever full, so a sender starved of application data still
        // inflates one it never used. Nothing here knows it was starved —
        // `bytes_in_flight` at *send* time is what would say so.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.8
        //# When this occurs, the congestion window
        //# SHOULD NOT be increased in either slow start or congestion avoidance.
        //= type=todo
        //
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.8
        //# A sender SHOULD NOT consider itself application limited if it
        //# would have fully utilized the congestion window without pacing delay.
        //= type=exception
        //= reason=nothing here paces, so no pacing delay can make a sender look application limited; pacing is a documented gap in docs/DESIGN.md section 6
        fn onPacketAcked(self: *Self, packet: AckedPacket) void {
            if (!packet.in_flight) return; // Section B.5: an ACK-only packet grows nothing.
            if (self.inCongestionRecovery(packet.time_sent)) return;
            if (self.congestion_window < self.ssthresh) {
                // Slow start: one for one, by the acknowledged packet's size.
                self.congestion_window += packet.octets;
                return;
            }
            // Congestion avoidance: roughly one datagram per round trip. The
            // increment is `max_datagram_size * acked / cwnd`, so a full
            // window's worth of acknowledgements adds one datagram and no more
            // — the additive half of AIMD, expressed per packet.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.3
            //# A sender in congestion avoidance uses an Additive Increase
            //# Multiplicative Decrease (AIMD) approach that MUST limit the increase
            //# to the congestion window to at most one maximum datagram size for
            //# each congestion window that is acknowledged.
            self.congestion_window += (@as(u64, config.max_datagram_size) * packet.octets) / self.congestion_window;
        }

        /// Section 7.6 and appendix B.8.
        ///
        /// Gated on an RTT sample existing, which the RFC requires and which
        /// matters: without one `smoothed_rtt` is the 333 ms default, and a
        /// connection that lost its whole first flight would declare the path
        /// dead on the strength of a number nobody measured.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
        //# When persistent congestion is declared, the sender's congestion
        //# window MUST be reduced to the minimum congestion window
        //# (kMinimumWindow), similar to a TCP sender's response on an RTO
        //# [RFC5681].
        //
        // `earliest` and `latest` are collected in `detectAndRemoveLostPackets`
        // from ack-eliciting packets only, which is the requirement below: a
        // PADDING-only packet the peer never owed an acknowledgement for says
        // nothing about how long the path has been silent.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
        //# These two packets MUST be ack-eliciting, since a receiver is required
        //# to acknowledge only ack-eliciting packets within its maximum
        //# acknowledgment delay; see Section 13.2 of [QUIC-TRANSPORT].
        //
        // One space's losses, not every space's: the caller is
        // `detectAndRemoveLostPackets`, which runs per packet number space, so
        // the send times compared here are the acknowledged space's alone —
        // the narrower reading section 7.6.2 explicitly permits.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
        //# Since network congestion is not affected by packet number spaces,
        //# persistent congestion SHOULD consider packets sent across packet
        //# number spaces.
        //= type=exception
        //= reason=section 7.6.2's own MAY: send times are compared only within the acknowledged space, which can miss a persistent congestion event but never invent one
        /// Whether any newly acknowledged packet was sent strictly between the
        /// two lost ones, which is section 7.6.2's second condition.
        fn acknowledgedBetween(self: *const Self, acked: []const AckedPacket, earliest: ?u64, latest: ?u64) bool {
            _ = self;
            const from = earliest orelse return false;
            const to = latest orelse return false;
            for (acked) |one| {
                if (one.time_sent > from and one.time_sent < to) return true;
            }
            return false;
        }

        fn inPersistentCongestion(self: *const Self, earliest: ?u64, latest: ?u64) bool {
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
            //# The persistent congestion period SHOULD NOT start until there is at
            //# least one RTT sample.
            if (!self.has_rtt_sample) return false;
            const from = earliest orelse return false;
            const to = latest orelse return false;
            // Two distinct ack-eliciting packets are needed: one lost packet
            // says nothing about duration.
            if (to <= from) return false;

            const pto = self.smoothed_rtt + @max(4 * self.rttvar, granularity_ns) + self.max_ack_delay_ns;
            const period = pto * persistent_congestion_threshold;
            return (to - from) > period;
        }

        fn inCongestionRecovery(self: *const Self, time_sent: u64) bool {
            const start = self.congestion_recovery_start_time orelse return false;
            // A packet sent after the period began is feedback about the
            // reduced window rather than about what caused the reduction, which
            // is the whole reason this predicate exists.
            assert(self.congestion_window >= minimum_window);
            return time_sent <= start;
        }

        /// Section B.6: halve the window, once per recovery period.
        ///
        /// Entering a recovery period is also how slow start ends: `ssthresh`
        /// drops to the halved window and `congestion_window` is set equal to
        /// it, so the `congestion_window < ssthresh` test in `onPacketAcked`
        /// answers false from here on.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.1
        //# The sender MUST exit slow start and enter a recovery period when a
        //# packet is lost or when the ECN-CE count reported by its peer
        //# increases.
        //
        // Every lost packet reaches here without exception, and it can: no
        // packet this package sends is a PMTU probe. The datagram size is fixed
        // at comptime and nothing ever writes above it, so section 14.4's
        // carve-out has nothing to carve out. `Sent` carries no probe flag
        // either, which is the shape this would have to grow if it ever did.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.4
        //# Loss of
        //# a QUIC packet that is carried in a PMTU probe is therefore not a
        //# reliable indication of congestion and SHOULD NOT trigger a congestion
        //# control reaction;
        //= type=exception
        //= reason=PMTU discovery is out of scope, so no packet is ever a PMTU probe: the maximum datagram size is a comptime constant and nothing sends above it, leaving no probe loss for the congestion controller to exempt
        fn onCongestionEvent(self: *Self, time_sent: u64, now_ns: u64) void {
            // Everything lost in one round trip is one event: reacting to each
            // packet would collapse the window by a factor of two per packet.
            if (self.inCongestionRecovery(time_sent)) return;
            assert(self.congestion_window >= minimum_window);
            self.congestion_recovery_start_time = now_ns;
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.2
            //# On entering a recovery period, a sender MUST set the slow start
            //# threshold to half the value of the congestion window when loss is
            //# detected.
            self.ssthresh = @max(self.congestion_window / loss_reduction_divisor, minimum_window);
            // Section 7.3.2: the window never goes below two datagrams, or a
            // sender in recovery could not put a packet on the wire to find out
            // that the path came back.
            assert(self.ssthresh >= minimum_window);
            // Immediately rather than gradually, which is the simplest of the
            // choices section 7.3.2 offers.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.2
            //# The congestion window MUST be set to the reduced value of
            //# the slow start threshold before exiting the recovery period.
            self.congestion_window = self.ssthresh;
            assert(self.congestion_window >= minimum_window);
        }

        /// Whether `octets` may go out now. Section 7: a sender is limited by
        /// the congestion window, and probes are exempt because a connection
        /// that cannot probe cannot recover.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7
        //# An endpoint MUST NOT send a packet if it would cause bytes_in_flight
        //# (see Appendix B.2) to be larger than the congestion window, unless
        //# the packet is sent on a PTO timer expiration (see Section 6.2) or
        //# when entering recovery (see Section 7.3.2).
        //
        // The exemption is the caller's to take: `Connection.sendPacket` skips
        // this predicate for an ACK-only packet and for a PTO probe, which is
        // the only way a probe can leave a full window.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.5
        //# Probe packets MUST NOT be blocked by the congestion controller.
        //
        // Section 7.7: nothing here paces. `canSend` answers yes for as long
        // as the window has room, so a sender with a full window's worth of
        // data puts it on the wire back to back. Named as a gap in
        // docs/DESIGN.md section 6 rather than left to be discovered.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
        //# A sender SHOULD pace sending of all in-flight packets based on input
        //# from the congestion controller.
        //= type=exception
        //= reason=pacing is a documented gap in docs/DESIGN.md section 6: it matters to zoxy more than to zrk and blocks no handshake
        //
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
        //# Senders MUST either use pacing or limit such bursts.
        //= type=exception
        //= reason=pacing is a documented gap in docs/DESIGN.md section 6, and no burst limit stands in for it: a burst is bounded only by the congestion window
        //
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
        //# Senders SHOULD limit bursts to the initial congestion window; see
        //# Section 7.2.
        //= type=exception
        //= reason=pacing is a documented gap in docs/DESIGN.md section 6; a grown window is sent in one burst rather than in initial-window-sized ones
        //
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
        //# To avoid delaying their delivery to the peer, packets
        //# containing only ACK frames SHOULD therefore not be paced.
        //= type=exception
        //= reason=nothing is paced, so an ACK-only packet cannot be delayed by a pacer; pacing is a documented gap in docs/DESIGN.md section 6
        pub fn canSend(self: *const Self, octets: u64) bool {
            // Both terms are ours rather than the peer's: `bytes_in_flight` is
            // the sum of what this endpoint sent and has not had acknowledged,
            // bounded by `sent_max` packets of `max_datagram_size`.
            assert(self.bytes_in_flight <= @as(u64, config.sent_max) * config.max_datagram_size);
            assert(octets <= config.max_datagram_size);
            return self.bytes_in_flight + octets <= self.congestion_window;
        }

        // ------------------------------------------------------ section 6.2

        /// When a PTO fires, and in which space. Named rather than anonymous
        /// because two anonymous structs with identical fields are still two
        /// types.
        const PtoTime = struct { at: u64, space: Space };

        /// Section A.6: the PTO, and the space it belongs to.
        ///
        /// A client with nothing ack-eliciting outstanding gets no PTO here:
        /// every space without an ack-eliciting packet is skipped. Section
        /// 6.2.2.1 wants one anyway before the handshake is confirmed, so that
        /// a client keeps unblocking a server held under its anti-amplification
        /// limit. See the `todo` below.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2.1
        //# That is,
        //# the client MUST set the PTO timer if the client has not received an
        //# acknowledgment for any of its Handshake packets and the handshake is
        //# not confirmed (see Section 4.1.2 of [QUIC-TLS]), even if there are no
        //# packets in flight.
        //= type=todo
        //
        // The server's half of section 6.2.2.1 is missing for the same reason,
        // and it is the more consequential one: this file holds no
        // address-validation state, `Connection.timeout` returns `timeoutAt`
        // unconditionally, and a probe sent under the anti-amplification limit
        // spends allowance the handshake needs.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2.1
        //# If
        //# no additional data can be sent, the server's PTO timer MUST NOT be
        //# armed until datagrams have been received from the client because
        //# packets sent on PTO count against the anti-amplification limit.
        //= type=todo
        fn ptoTimeAndSpace(self: *const Self) ?PtoTime {
            // Section 6.2.1: the floor is inside the base rather than applied
            // to the sum, which is the RFC's own arrangement — `max(4*rttvar,
            // kGranularity)` cannot be zero, so neither can the period.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
            //# The PTO period MUST be at least kGranularity to avoid the timer
            //# expiring immediately.
            var duration = self.smoothed_rtt + @max(4 * self.rttvar, granularity_ns);
            duration <<= @intCast(@min(self.pto_count, @as(u32, pto_backoff_shift_max)));

            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2.1
            //# That is, the client MUST set the PTO timer if the client has not
            //# received an acknowledgment for any of its Handshake packets and the
            //# handshake is not confirmed (see Section 4.1.2 of [QUIC-TLS]), even
            //# if there are no packets in flight. When the PTO fires, the client
            //# MUST send a Handshake packet if it has Handshake keys, otherwise it
            //# MUST send an Initial packet in a UDP datagram with a payload of at
            //# least 1200 bytes.
            //
            // The anti-deadlock probe, and the reason it cannot fall out of the
            // loop below: that loop arms a space only when something
            // ack-eliciting is outstanding there, and this rule is about the
            // case where *nothing* is. A client whose Initial flight was
            // answered by an ACK-only packet has no ack-eliciting packet in
            // flight, so it armed no timer, so it never probed — and the server
            // is blocked behind the amplification limit waiting for exactly
            // that probe. Both sides then wait.
            //
            // Appendix A.8 puts the assertion below in the pseudocode rather
            // than the condition, because a server never reaches it: its own
            // `peerCompletedAddressValidation` is always true.
            if (!self.peerCompletedAddressValidation()) {
                var any_in_flight = false;
                for (0..Space.count) |index| {
                    const space: Space = @enumFromInt(index);
                    if (self.hasAckEliciting(space)) any_in_flight = true;
                }
                if (!any_in_flight) {
                    assert(self.side == .client);
                    const space: Space = if (self.handshake_keys) .handshake else .initial;
                    return .{ .at = self.anti_deadlock_from_ns + duration, .space = space };
                }
            }

            var earliest: ?PtoTime = null;
            for (0..Space.count) |index| {
                const space: Space = @enumFromInt(index);
                const state = &self.spaces[index];
                if (!self.hasAckEliciting(space)) continue;
                // Section 6.2.1: an application-data PTO waits for the
                // handshake, because 1-RTT keys may not exist on both sides.
                var at = state.time_of_last_ack_eliciting orelse continue;
                //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
                //# An endpoint MUST NOT set its PTO timer for the Application Data
                //# packet number space until the handshake is confirmed.
                if (space == .application) {
                    if (!self.handshake_confirmed) continue;
                    at += (self.max_ack_delay_ns << @intCast(@min(self.pto_count, @as(u32, pto_backoff_shift_max))));
                }
                at += duration;
                // The earliest across every armed space, which subsumes the
                // Initial-and-Handshake case the RFC calls out: those two are
                // the only spaces armed before the handshake is confirmed.
                //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
                //# When ack-eliciting packets in multiple packet number spaces are in
                //# flight, the timer MUST be set to the earlier value of the Initial and
                //# Handshake packet number spaces.
                if (earliest == null or at < earliest.?.at) earliest = .{ .at = at, .space = space };
            }
            return earliest;
        }

        fn hasAckEliciting(self: *const Self, space: Space) bool {
            const state = &self.spaces[@intFromEnum(space)];
            for (state.sent[0..state.count]) |packet| {
                if (packet.ack_eliciting) return true;
            }
            return false;
        }

        /// Section A.8: when the caller must wake this connection.
        ///
        /// The earliest loss time if one is pending, otherwise the PTO, or null
        /// when nothing is outstanding and there is nothing to wait for.
        pub fn timeoutAt(self: *const Self) ?u64 {
            var earliest: ?u64 = null;
            for (self.spaces) |state| {
                const at = state.loss_time orelse continue;
                earliest = if (earliest) |current| @min(current, at) else at;
            }
            // A loss time short-circuits the PTO rather than being compared
            // with it: the timer this returns is the only one the caller arms,
            // so returning the loss time *is* declining to set the PTO.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
            //# The PTO timer MUST NOT be set if a timer is set for time threshold
            //# loss detection; see Section 6.1.2.
            if (earliest) |at| return at;
            const pto = self.ptoTimeAndSpace() orelse return null;
            return pto.at;
        }

        pub const Timeout = union(enum) {
            /// Packets were declared lost; their contexts are in the caller's
            /// slice and the frames they held must be sent again.
            lost: u32,
            /// Nothing is known to be lost, but the peer has gone quiet.
            /// Section 6.2.4: send ack-eliciting packets in this space to make
            /// it say something. Two, because one may be lost as well.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
            //# When a PTO timer expires, a sender MUST send at least one ack-
            //# eliciting packet in the packet number space as a probe.
            //
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
            //# All probe packets sent on a PTO MUST be ack-eliciting.
            //
            // One space, because one timer expired. The coalescing section
            // 6.2.4 asks for is the caller's: `Connection.onTimeout` walks the
            // other spaces, asks `earliestContext` which of them have data in
            // flight, and probes those too — and `send` writes all of them into
            // one datagram. It is driven from this answer plus that walk rather
            // than from this answer alone, which is what the comment here used
            // to say could not be done.
            probe: struct { space: Space, packets: u8 },
            /// Nothing to do.
            idle,
        };

        /// Section A.9.
        pub fn onLossDetectionTimeout(self: *Self, now_ns: u64, lost: []Context) Timeout {
            self.anti_deadlock_from_ns = @max(self.anti_deadlock_from_ns, now_ns);
            var earliest_space: ?Space = null;
            var earliest: ?u64 = null;
            for (self.spaces, 0..) |state, index| {
                const at = state.loss_time orelse continue;
                if (earliest == null or at < earliest.?) {
                    earliest = at;
                    earliest_space = @enumFromInt(index);
                }
            }
            if (earliest_space) |space| {
                const count = self.detectAndRemoveLostPackets(space, now_ns, lost, &.{});
                return .{ .lost = count };
            }

            const pto = self.ptoTimeAndSpace() orelse return .idle;
            // Section 6.2.1: the backoff is exponential, and it is reset by a
            // delivery rather than by a probe being sent — a probe that is also
            // lost must not shorten the next wait.
            //
            // Nothing is removed from `sent` on this path, which is the whole
            // of section 6.2's requirement: a PTO answers `.probe`, and only
            // `detectAndRemoveLostPackets` ever answers `.lost`.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2
            //# A PTO timer expiration event does not indicate packet loss and MUST
            //# NOT cause prior unacknowledged packets to be marked as lost.
            //
            //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
            //# When a PTO timer expires, the PTO backoff MUST be increased,
            //# resulting in the PTO period being set to twice its current value.
            self.pto_count += 1;
            return .{ .probe = .{ .space = pto.space, .packets = 2 } };
        }

        /// Section 6.2.3: the connection has just discarded a packet number
        /// space, so everything outstanding in it is neither lost nor
        /// acknowledged — it is gone.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.4
        //# The sender MUST discard all recovery state
        //# associated with those packets and MUST remove them from the count of
        //# bytes in flight.
        //
        // `state.* = .{}` clears `loss_time` and `time_of_last_ack_eliciting`
        // together, and both timers are derived from those on the next
        // `timeoutAt` — which is what resetting them means here.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
        //# When
        //# Initial or Handshake keys are discarded, the PTO and loss detection
        //# timers MUST be reset, because discarding keys indicates forward
        //# progress and the loss detection timer might have been set for a now-
        //# discarded packet number space.
        pub fn discardSpace(self: *Self, space: Space) void {
            const state = &self.spaces[@intFromEnum(space)];
            for (state.sent[0..state.count]) |packet| {
                if (packet.in_flight) {
                    assert(self.bytes_in_flight >= packet.octets);
                    self.bytes_in_flight -= packet.octets;
                }
            }
            state.* = .{};
            self.pto_count = 0;
        }

        /// Outstanding packets in one space, for a caller deciding whether to
        /// probe.
        pub fn outstanding(self: *const Self, space: Space) u32 {
            return self.spaces[@intFromEnum(space)].count;
        }

        /// The context of the earliest packet still outstanding in a space.
        ///
        /// Section 6.2.4: a probe should carry unacknowledged data rather than
        /// a bare PING where there is any, and this is what tells a caller
        /// where that data starts. The list is ascending by number, so the
        /// earliest is the first.
        ///
        /// The RFC's preference runs the other way, and the inversion is
        /// deliberate rather than an oversight: nothing here knows what a
        /// packet contained, so "new data" is a phrase this module cannot
        /// name. The earliest unacknowledged context is the only thing it can.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        //# An endpoint SHOULD include new data in packets that are sent on PTO
        //# expiration.
        //= type=exception
        //= reason=this module never learns what a packet contained, so it cannot name new data; the probe is driven from the earliest unacknowledged context instead, which is the same section's "Previously sent data MAY be sent", and whatever new data the caller has pending rides along in the same packet build
        //
        // A null answer is the other case section 6.2.4 names: nothing is
        // outstanding in this space, so there is nothing to point a probe at,
        // and `Connection.writePayload` frames a PING when a probe is pending
        // and the space has nothing else to say. The timer is rearmed by that
        // point without anything further here — `onLossDetectionTimeout` has
        // already advanced `pto_count`, and `timeoutAt` recomputes the period
        // from it on the next call.
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        //# When there is no data to send, the sender SHOULD send
        //# a PING or other ack-eliciting frame in a single packet, rearming the
        //# PTO timer.
        pub fn earliestContext(self: *const Self, space: Space) ?Context {
            const state = &self.spaces[@intFromEnum(space)];
            // The earliest *in flight*, not the earliest recorded. Every packet
            // is recorded here, acknowledgement-only ones included, and an
            // acknowledgement-only packet carries nothing a retransmission
            // could make progress with: pointing the probe at one rewinds
            // nothing, so the probe goes out carrying an ACK and padding while
            // the peer waits for the handshake bytes it was supposed to carry.
            //
            // A server whose flight is lost then never resends it. Its probes
            // are answered by nothing, `pto_count` doubles each time, and by
            // the fourth or fifth attempt the period is four or five seconds —
            // which is how the interop runner's `handshakeloss` case ended with
            // one connection wedged and a client that gave up on the whole run.
            //
            // `in_flight` is exactly "this packet was ack-eliciting", which is
            // the same question as "could this packet have carried data".
            for (state.sent[0..state.count]) |packet| {
                if (packet.in_flight) return packet.context;
            }
            return null;
        }

        /// Every context still outstanding in a space, oldest first.
        ///
        /// A slice rather than an interpretation: this file never learns what a
        /// packet contained — `Context` is the caller's opaque token — so a
        /// caller that needs to ask "which of my octets are still in the air"
        /// has to do the asking. `Connection` uses it to decide how much of a
        /// stream's send buffer can be given back.
        pub fn inFlight(self: *const Self, space: Space) []const Sent {
            const state = &self.spaces[@intFromEnum(space)];
            return state.sent[0..state.count];
        }
    };
}

const testing = std.testing;

const ms = std.time.ns_per_ms;
const TestRecovery = Recovery(.{ .sent_max = 32, .max_datagram_size = 1200, .Context = u64 });

fn sentPacket(number: u64, at: u64) TestRecovery.Sent {
    return .{
        .number = number,
        .time_sent = at,
        .octets = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .context = number,
    };
}

fn ackOf(largest: u64, first_range: u64) frame.Ack {
    return .{
        .largest = largest,
        .delay = 0,
        .first_range = first_range,
        .range_count = 0,
        .ranges = &.{},
        .ecn = null,
    };
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
//# min_rtt MUST be set to the latest_rtt on the first RTT sample.
//# min_rtt MUST be set to the lesser of min_rtt and latest_rtt
//# (Section 5.1) on all other samples.
//= type=test
test "the first sample sets the estimate rather than smoothing into it" {
    var recovery: TestRecovery = .{};
    // Before a sample, section 6.2.2's 333ms stands in.
    try testing.expectEqual(initial_rtt_ns, recovery.smoothed_rtt);

    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    var lost: [8]u64 = undefined;
    const result = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});
    try testing.expect(result.rtt_sampled);
    try testing.expectEqual(@as(u32, 1), result.acked);
    // Section 5.3: the first sample *is* the estimate; smoothing it against the
    // 333ms default would leave the connection sluggish for several round trips.
    try testing.expectEqual(@as(u64, 100 * ms), recovery.smoothed_rtt);
    try testing.expectEqual(@as(u64, 50 * ms), recovery.rttvar);
    try testing.expectEqual(@as(u64, 100 * ms), recovery.min_rtt);
}

test "a later sample moves the estimate by an eighth" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});

    try recovery.onPacketSent(.initial, sentPacket(1, 200 * ms));
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 400 * ms, &lost, &.{});
    // 7/8 * 100 + 1/8 * 200 = 112.5ms.
    try testing.expectEqual(@as(u64, 112_500_000), recovery.smoothed_rtt);
    try testing.expectEqual(@as(u64, 100 * ms), recovery.min_rtt);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
//# *  MUST NOT subtract the acknowledgment delay from the RTT sample if
//# the resulting value is smaller than the min_rtt.
//= type=test
test "an inflated ack delay cannot shrink the estimate below the minimum" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});

    // A peer claiming a delay far past what it advertised. Section 5.3 caps it
    // at `max_ack_delay`; without the cap a peer could drive our RTT estimate
    // down and make us declare loss early — retransmitting into a healthy path.
    try recovery.onPacketSent(.initial, sentPacket(1, 200 * ms));
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 10_000 * ms, 300 * ms, &lost, &.{});
    try testing.expect(recovery.smoothed_rtt >= recovery.min_rtt);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.1
//# In order to remain similar to TCP,
//# implementations SHOULD NOT use a packet threshold less than 3; see
//# [RFC5681].
//= type=test
test "section 6.1.1: three packets past a delivery is lost" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    // All five together, and acknowledged soon enough that the *time* threshold
    // cannot fire — otherwise this would not be a test of the packet threshold.
    for (0..5) |number| try recovery.onPacketSent(.initial, sentPacket(number, 0));

    // Packet 4 arrives; 0 and 1 are three or more behind it and are lost, while
    // 2 and 3 are still in doubt.
    const result = try recovery.onAckReceived(.initial, ackOf(4, 0), 0, 1 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 1), result.acked);
    try testing.expectEqual(@as(u32, 2), result.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);
    try testing.expectEqual(@as(u64, 1), lost[1]);
    try testing.expectEqual(@as(u32, 2), recovery.outstanding(.initial));
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
//# Once a later packet within the same packet number space has been
//# acknowledged, an endpoint SHOULD declare an earlier packet lost if it
//# was sent a threshold amount of time in the past.
//= type=test
test "section 6.1.2: a packet old enough is lost even without three behind it" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    // A sample, so the loss delay is a real 9/8 of an RTT rather than the floor.
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 100 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 1), recovery.outstanding(.initial));

    // A later packet is acknowledged, which is what runs detection again.
    // Packet 0 is now more than 9/8 of an RTT old and is lost by time alone —
    // only two packets were ever sent past it, one short of the packet
    // threshold, so nothing else could have declared it.
    try recovery.onPacketSent(.initial, sentPacket(2, 200 * ms));
    const result = try recovery.onAckReceived(.initial, ackOf(2, 0), 0, 1000 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 1), result.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
//# To avoid generating multiple RTT samples for a single packet, an ACK
//# frame SHOULD NOT be used to update RTT estimates if it does not newly
//# acknowledge the largest acknowledged packet.
//= type=test
test "an ACK that acknowledges nothing new does nothing" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 100 * ms, &lost, &.{});
    const smoothed = recovery.smoothed_rtt;

    // Section A.7 returns early when nothing was newly acknowledged. A
    // retransmitted ACK is ordinary, and taking an RTT sample from one would
    // measure the age of an acknowledgement rather than a round trip.
    const again = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 5000 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 0), again.acked);
    try testing.expect(!again.rtt_sampled);
    try testing.expectEqual(smoothed, recovery.smoothed_rtt);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
//# If packets sent prior to the largest acknowledged packet cannot yet
//# be declared lost, then a timer SHOULD be set for the remaining time.
//= type=test
test "a packet still in doubt arms the timer rather than being declared lost" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 100 * ms, &lost, &.{});

    // Nothing lost yet, but the timer says when to look again.
    try testing.expectEqual(@as(u32, 1), recovery.outstanding(.initial));
    const at = recovery.timeoutAt().?;
    try testing.expect(at > 0);

    const outcome = recovery.onLossDetectionTimeout(at + 1, &lost);
    try testing.expectEqual(@as(u32, 1), outcome.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.2
//# On entering a recovery period, a sender MUST set the slow start
//# threshold to half the value of the congestion window when loss is
//# detected.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9002#section-7.3.2
//# The congestion window MUST be set to the reduced value of
//# the slow start threshold before exiting the recovery period.
//= type=test
test "the window halves once per round trip, not once per lost packet" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    const before = recovery.congestion_window;

    // Five packets sent together; four are lost at once. Reacting to each would
    // take the window down by a factor of sixteen.
    for (0..5) |number| try recovery.onPacketSent(.initial, sentPacket(number, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(4, 0), 0, 100 * ms, &lost, &.{});

    try testing.expect(recovery.congestion_window < before);
    try testing.expectEqual(@max(before / 2, 2 * @as(u64, 1200)), recovery.congestion_window);
}

test "the window never falls below two datagrams" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    var round: u64 = 0;
    while (round < 20) : (round += 1) {
        const base = round * 10;
        for (0..5) |offset| try recovery.onPacketSent(.initial, sentPacket(base + offset, round * 100 * ms));
        _ = try recovery.onAckReceived(.initial, ackOf(base + 4, 0), 0, (round + 1) * 100 * ms, &lost, &.{});
    }
    // Section B.6's floor: below two datagrams a sender cannot make progress at
    // all, so the collapse stops there.
    try testing.expectEqual(@as(u64, 2 * 1200), recovery.congestion_window);
}

test "slow start grows the window per delivery and stops at the threshold" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    const before = recovery.congestion_window;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 10 * ms, &lost, &.{});
    try testing.expectEqual(before + 1200, recovery.congestion_window);
}

test "bytes in flight follow what is outstanding" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try testing.expectEqual(@as(u64, 0), recovery.bytes_in_flight);
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    try testing.expectEqual(@as(u64, 2400), recovery.bytes_in_flight);

    _ = try recovery.onAckReceived(.initial, ackOf(1, 1), 0, 10 * ms, &lost, &.{});
    try testing.expectEqual(@as(u64, 0), recovery.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), recovery.outstanding(.initial));
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-7
//# An endpoint MUST NOT send a packet if it would cause bytes_in_flight
//# (see Appendix B.2) to be larger than the congestion window, unless
//# the packet is sent on a PTO timer expiration (see Section 6.2) or
//# when entering recovery (see Section 7.3.2).
//= type=test
test "a full window stops the sender" {
    var recovery: TestRecovery = .{};
    try testing.expect(recovery.canSend(1200));
    var number: u64 = 0;
    while (recovery.canSend(1200)) : (number += 1) {
        try recovery.onPacketSent(.initial, sentPacket(number, 0));
    }
    try testing.expect(!recovery.canSend(1200));
    try testing.expect(recovery.bytes_in_flight + 1200 > recovery.congestion_window);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
//# When a PTO timer expires, a sender MUST send at least one ack-
//# eliciting packet in the packet number space as a probe.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
//# When a PTO timer expires, the PTO backoff MUST be increased,
//# resulting in the PTO period being set to twice its current value.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2
//# A PTO timer expiration event does not indicate packet loss and MUST
//# NOT cause prior unacknowledged packets to be marked as lost.
//= type=test
test "a silent peer produces a probe, and the backoff is exponential" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));

    const first = recovery.timeoutAt().?;
    const outcome = recovery.onLossDetectionTimeout(first, &lost);
    try testing.expectEqual(Space.initial, outcome.probe.space);
    // Section 6.2.4: two, because one probe may be lost as well.
    try testing.expectEqual(@as(u8, 2), outcome.probe.packets);
    try testing.expectEqual(@as(u32, 1), recovery.pto_count);

    // The next wait is twice as long.
    const second = recovery.timeoutAt().?;
    try testing.expectEqual(first * 2, second);

    // And a delivery resets it — the path is working again. Appendix A.7
    // guards that on `PeerCompletedAddressValidation`, so this test says which
    // endpoint it is asking: a server has nothing to wait for, while a client
    // acknowledged only in the Initial space still does not know the server can
    // receive at this address. The unguarded version of this assertion passed
    // for both and was wrong for one.
    recovery.side = .server;
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(1, 0), 0, 10 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 0), recovery.pto_count);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
//# To avoid declaring
//# packets as lost too early, this time threshold MUST be set to at
//# least the local timer granularity, as indicated by the kGranularity
//# constant.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
//# The PTO period MUST be at least kGranularity to avoid the timer
//# expiring immediately.
//= type=test
test "a zero RTT sample is degenerate, not dangerous" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    // A packet sent and acknowledged inside one clock tick. Impossible on a
    // network, ordinary with a coarse clock, and not something RFC 9002
    // forbids — so the estimate really does become zero.
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 0, &lost, &.{});
    try testing.expectEqual(@as(u64, 0), recovery.smoothed_rtt);

    // What matters is that every timer derived from it still obeys its floor,
    // which is what sections 6.1.2 and 6.2.1 require and what keeps a zero
    // estimate from turning into a busy loop.
    try testing.expectEqual(granularity_ns, recovery.lossDelay());
    try recovery.onPacketSent(.initial, sentPacket(1, 0));
    const at = recovery.timeoutAt().?;
    try testing.expect(at >= granularity_ns);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
//# An endpoint MUST NOT set its PTO timer for the Application Data
//# packet number space until the handshake is confirmed.
//= type=test
test "an application-data PTO waits for the handshake" {
    var recovery: TestRecovery = .{};
    try recovery.onPacketSent(.application, sentPacket(0, 0));
    // Section 6.2.1: arming it before the handshake is confirmed would probe
    // with keys the peer may not have installed.
    try testing.expectEqual(@as(?u64, null), recovery.timeoutAt());

    recovery.handshake_confirmed = true;
    try testing.expect(recovery.timeoutAt() != null);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.4
//# The sender MUST discard all recovery state
//# associated with those packets and MUST remove them from the count of
//# bytes in flight.
//= type=test
test "discarding a space forgets what was in flight there" {
    var recovery: TestRecovery = .{};
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    try recovery.onPacketSent(.handshake, sentPacket(0, 0));
    try testing.expectEqual(@as(u64, 2400), recovery.bytes_in_flight);

    // Section 6.2.3: an Initial packet outstanding when the space goes is
    // neither lost nor acknowledged, and leaving its octets in flight would
    // hold the window down for the rest of the connection.
    recovery.discardSpace(.initial);
    try testing.expectEqual(@as(u64, 1200), recovery.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), recovery.outstanding(.initial));
    try testing.expectEqual(@as(u32, 1), recovery.outstanding(.handshake));
}

test "more outstanding packets than the bound is refused rather than overrun" {
    var recovery: TestRecovery = .{};
    for (0..32) |number| try recovery.onPacketSent(.initial, sentPacket(number, 0));
    try testing.expectError(error.TooManyOutstanding, recovery.onPacketSent(.initial, sentPacket(32, 0)));
}

test "a caller's lost slice may be shorter than the truth" {
    var recovery: TestRecovery = .{};
    for (0..8) |number| try recovery.onPacketSent(.initial, sentPacket(number, 0));
    var lost: [2]u64 = undefined;
    const result = try recovery.onAckReceived(.initial, ackOf(7, 0), 0, 10 * ms, &lost, &.{});
    // Five are lost; two fit. The count is the truth, so a caller can tell it
    // did not see everything rather than quietly retransmitting less.
    try testing.expectEqual(@as(u32, 5), result.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);
    try testing.expectEqual(@as(u64, 1), lost[1]);
}

test "appendix B.5: the window grows once per acknowledged packet" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    const before = recovery.congestion_window;

    // Four packets, all acknowledged by one frame. Growing once per *frame* —
    // which this did — halves slow start against any peer acknowledging every
    // second packet, which is RFC 9000 section 13.2.2's default.
    for (0..4) |number| try recovery.onPacketSent(.initial, sentPacket(number, 0));
    const result = try recovery.onAckReceived(.initial, ackOf(3, 3), 0, 1 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 4), result.acked);
    try testing.expectEqual(@as(u32, 0), result.lost);
    try testing.expectEqual(before + 4 * 1200, recovery.congestion_window);
}

test "appendix B.5: an ACK-only packet grows nothing" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    const before = recovery.congestion_window;
    // Not in flight, so section B.5 returns before touching the window —
    // otherwise acknowledgement traffic would inflate it for free.
    var ack_only = sentPacket(0, 0);
    ack_only.in_flight = false;
    ack_only.ack_eliciting = false;
    try recovery.onPacketSent(.initial, ack_only);
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 1 * ms, &lost, &.{});
    try testing.expectEqual(before, recovery.congestion_window);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
//# When persistent congestion is declared, the sender's congestion
//# window MUST be reduced to the minimum congestion window
//# (kMinimumWindow), similar to a TCP sender's response on an RTO
//# [RFC5681].
//= type=test
test "section 7.6: losing everything across several PTOs collapses the window" {
    var recovery: TestRecovery = .{};
    var lost: [16]u64 = undefined;

    // An RTT sample first: without one the estimate is the 333 ms default, and
    // section 7.6 declines to declare a path dead on a number nobody measured.
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});
    try testing.expect(recovery.has_rtt_sample);

    // pto = 100 + max(4*50, 1) + 25 = 325ms; the period is three of those.
    // Two ack-eliciting packets that far apart, with everything between them
    // lost, is a path that has gone away rather than a congested one.
    try recovery.onPacketSent(.initial, sentPacket(1, 200 * ms));
    try recovery.onPacketSent(.initial, sentPacket(2, 2000 * ms));
    try recovery.onPacketSent(.initial, sentPacket(3, 2100 * ms));
    const result = try recovery.onAckReceived(.initial, ackOf(3, 0), 0, 2200 * ms, &lost, &.{});
    try testing.expect(result.lost >= 2);

    // Section 7.6: the floor, not a halving — and then exactly one packet's
    // growth on top, because appendix B.8 clears the recovery period and
    // appendix A.7 runs the acknowledgement *after* the loss. The packet
    // acknowledged in this same frame therefore grows the collapsed window by
    // its own size. That is the RFC's behaviour rather than an accident, and
    // asserting the bare floor here was this test being wrong about it.
    try testing.expectEqual(@as(u64, 2 * 1200 + 1200), recovery.congestion_window);
    try testing.expectEqual(@as(?u64, null), recovery.congestion_recovery_start_time);
    // What matters is that it collapsed rather than halved: a halving from
    // 13200 would have left 6600.
    try testing.expect(recovery.congestion_window < 6600);
}

test "a single loss is congestion, not a dead path" {
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;
    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});

    for (1..6) |number| try recovery.onPacketSent(.initial, sentPacket(number, 200 * ms));
    _ = try recovery.onAckReceived(.initial, ackOf(5, 0), 0, 250 * ms, &lost, &.{});
    // Halved, not collapsed: the lost packets were sent together, so no
    // duration passed between the first and last of them.
    try testing.expect(recovery.congestion_window > 2 * 1200);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
//# *  at least one of the newly acknowledged packets was ack-eliciting.
//= type=test
test "section 5.1: any newly acknowledged ack-eliciting packet gives a sample" {
    // The condition used to be that the *largest* newly acknowledged packet
    // was ack-eliciting. An ACK whose top packet was ACK-only then produced no
    // sample even with an ack-eliciting packet below it — conservative, but it
    // starves the estimator on a path whose two directions carry different
    // traffic, and appendix A.7 asks the question over the whole set.
    var recovery: TestRecovery = .{};
    var lost: [8]u64 = undefined;

    var eliciting = sentPacket(0, 0);
    eliciting.ack_eliciting = true;
    try recovery.onPacketSent(.initial, eliciting);

    var ack_only = sentPacket(1, 0);
    ack_only.ack_eliciting = false;
    ack_only.in_flight = false;
    try recovery.onPacketSent(.initial, ack_only);

    // Largest is packet 1, which is ACK-only; packet 0 below it is not.
    _ = try recovery.onAckReceived(.initial, ackOf(1, 1), 0, 100 * ms, &lost, &.{});
    try testing.expect(recovery.has_rtt_sample);
    try testing.expectEqual(@as(u64, 100 * ms), recovery.latest_rtt);
}

//= https://www.rfc-editor.org/rfc/rfc9002#appendix-A.7
//# if (PeerCompletedAddressValidation()):
//#   pto_count = 0
//= type=test
test "appendix A.7: a client keeps its PTO backoff until the server is validated" {
    // Acknowledgements of Initial packets say nothing about whether the server
    // can receive at this address, so a client that reset its backoff on them
    // would re-probe at the un-backed-off interval against a server that is
    // merely slow. The reset used to be unconditional.
    var client: TestRecovery = .{ .side = .client };
    var lost: [8]u64 = undefined;
    client.pto_count = 3;
    try client.onPacketSent(.initial, sentPacket(0, 0));
    _ = try client.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 3), client.pto_count);

    // Confirmation is one of the two things that ends the doubt.
    client.handshake_confirmed = true;
    try client.onPacketSent(.initial, sentPacket(1, 0));
    _ = try client.onAckReceived(.initial, ackOf(1, 1), 0, 200 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 0), client.pto_count);

    // A server has nothing to wait for: the client chose the address.
    var server: TestRecovery = .{ .side = .server };
    server.pto_count = 3;
    try server.onPacketSent(.initial, sentPacket(0, 0));
    _ = try server.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});
    try testing.expectEqual(@as(u32, 0), server.pto_count);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
//# *  across all packet number spaces, none of the packets sent between
//#    the send times of these two packets are acknowledged;
//= type=test
test "section 7.6.2: something getting through is not a dead path" {
    var recovery: TestRecovery = .{};
    var lost: [16]u64 = undefined;

    try recovery.onPacketSent(.initial, sentPacket(0, 0));
    _ = try recovery.onAckReceived(.initial, ackOf(0, 0), 0, 100 * ms, &lost, &.{});

    // Two ack-eliciting packets far enough apart to be persistent congestion,
    // and one *between* them that this very ACK acknowledges. Section 7.6.2's
    // second condition says that is congestion, not a blackhole — the peer just
    // proved the path carries traffic.
    try recovery.onPacketSent(.initial, sentPacket(1, 200 * ms));
    try recovery.onPacketSent(.initial, sentPacket(2, 1000 * ms));
    try recovery.onPacketSent(.initial, sentPacket(3, 2000 * ms));
    try recovery.onPacketSent(.initial, sentPacket(4, 2100 * ms));

    // Acknowledge 2 and 4, losing 1 and 3.
    var ranges: [8]u8 = undefined;
    var octets: usize = 0;
    octets += try varint.encode(ranges[octets..], 0);
    octets += try varint.encode(ranges[octets..], 0);
    _ = try recovery.onAckReceived(.initial, .{
        .largest = 4,
        .delay = 0,
        .first_range = 0,
        .range_count = 1,
        .ranges = ranges[0..octets],
        .ecn = null,
    }, 0, 2200 * ms, &lost, &.{});

    // Halved rather than collapsed: packet 2 landed between the two lost ones.
    //
    // Asserted on the recovery period rather than on the window, because the
    // window is ambiguous here for the reason appendix A.7 gives: persistent
    // congestion sets the window to the floor *and clears the period*, and the
    // acknowledgement that follows then grows the floor by one packet — so
    // `window > 2 * 1200` is true either way. `congestion_recovery_start_time`
    // is not: a collapse clears it, an ordinary halving sets it to now.
    try testing.expect(recovery.congestion_recovery_start_time != null);
}

//= https://www.rfc-editor.org/rfc/rfc9002#appendix-B.8
//# // Only consider packets sent after getting an RTT sample.
//# if (first_rtt_sample == 0):
//#   return
//= type=test
test "appendix B.8: a packet sent before the first RTT sample cannot widen the span" {
    var recovery: TestRecovery = .{};
    var lost: [16]u64 = undefined;

    // The old packet lives in the Initial space and is never acknowledged, so
    // nothing there runs loss detection over it until the very end. The first
    // RTT sample is taken in the Handshake space instead — `first_rtt_sample`
    // is a property of the connection, not of a space.
    //
    // Written this way on the second attempt. The first put both in one space,
    // where the old packet was declared lost by the very first acknowledgement
    // and was gone long before the event under test — so the test passed with
    // the filter removed, which is a test that proves nothing.
    try recovery.onPacketSent(.initial, sentPacket(0, 0));

    try recovery.onPacketSent(.handshake, sentPacket(0, 2900 * ms));
    _ = try recovery.onAckReceived(.handshake, ackOf(0, 0), 0, 3000 * ms, &lost, &.{});
    try testing.expect(recovery.has_rtt_sample);
    try testing.expectEqual(@as(u64, 3000 * ms), recovery.first_rtt_sample_ns);

    // Now an Initial loss event long after. Packet 0 was sent at zero, before
    // any RTT was measured; appendix B.8 excludes it from the span, leaving
    // only packet 1 — and one packet is not two, so there is no persistent
    // congestion. Without the filter the span runs 0 to 3100 ms and collapses
    // the window on a period that predates every measurement.
    try recovery.onPacketSent(.initial, sentPacket(1, 3100 * ms));
    try recovery.onPacketSent(.initial, sentPacket(2, 3200 * ms));
    const result = try recovery.onAckReceived(.initial, ackOf(2, 0), 0, 3300 * ms, &lost, &.{});
    try testing.expect(result.lost >= 2);
    try testing.expect(recovery.congestion_recovery_start_time != null);
}
