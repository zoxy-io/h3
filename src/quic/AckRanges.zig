//! The set of packet numbers received in one packet number space, and the ACK
//! frames generated from it (RFC 9000 sections 13.2 and 19.3).
//!
//! Three of these per connection — Initial, Handshake, application — because
//! the spaces are separate and an acknowledgement in one says nothing about
//! another (section 12.3). This structure is deliberately *not* an array of
//! three: which spaces are alive changes over a connection's life, and a
//! discarded space's set should be gone rather than idle.
//!
//! It holds no `packet_number.Space` and takes none. An earlier version of this
//! comment claimed the type "exists so a caller cannot pass the wrong one by
//! accident", which is a property `Recovery` has — it is keyed by space and
//! takes one on every call — and this file does not. Keeping the right set
//! beside the right space is the connection's job, and `Connection.spaces`
//! indexes both from the same enum, which is where that safety actually comes
//! from.
//!
//! ## The bound is the whole design problem
//!
//! A received-packet set is a set of ranges, and the number of ranges is chosen
//! by the peer: sending every other packet number produces one range per
//! packet. Unbounded, that is a structure an attacker sizes. Bounded, something
//! has to be dropped, and *which* end is dropped is the decision.
//!
//! The low end goes. Section 13.2.3 permits an endpoint to limit what it
//! acknowledges, and the cost of forgetting a low range is that the peer may
//! retransmit data we already have — wasteful, and handled, because
//! `Reassembler` treats a duplicate as free. The cost of forgetting a *high*
//! range would be acknowledging a packet number below one already sent in an
//! earlier ACK, and section 19.3 forbids that outright: "QUIC acknowledgments
//! are irrevocable. Once acknowledged, a packet remains acknowledged, even if
//! it does not appear in a future ACK frame."
//!
//! ## Forgetting a range obliges us to refuse it
//!
//! Section 13.2.3 attaches a condition to that permission, and it is the whole
//! of `minimum` below: "A receiver MUST retain an ACK Range unless it can
//! ensure that it will not subsequently accept packets with numbers in that
//! range. Maintaining a minimum packet number that increases as ranges are
//! discarded is one way to achieve this with minimal state."
//!
//! Without it, dropping a range makes `contains` answer false for every number
//! in it, so a replay of one of those packets is recorded as new and its frames
//! are processed a second time. That is the duplicate-suppression the whole
//! structure exists to provide, defeated by the eviction that keeps it bounded.
//!
//! ## What it does not do
//!
//! No decision about *when* to send an ACK. Section 13.2.1's rules — every
//! second ack-eliciting packet, and within `max_ack_delay` otherwise — are the
//! connection's, because they need a timer and a peer's transport parameter.
//! This structure knows what has arrived and can render it.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const frame = @import("frame.zig");
const packet_number = @import("packet_number.zig");
const varint = @import("../varint.zig");

/// One acknowledged run, inclusive at both ends, as section 19.3 describes them.
pub const Range = struct {
    largest: u64,
    smallest: u64,

    pub fn contains(range: Range, number: u64) bool {
        return number >= range.smallest and number <= range.largest;
    }

    pub fn count(range: Range) u64 {
        assert(range.largest >= range.smallest);
        return range.largest - range.smallest + 1;
    }
};

pub const Config = struct {
    /// Ranges tracked before the lowest is forgotten.
    ///
    /// Thirty-two is well past what loss produces on a real path and far short
    /// of what a peer can manufacture. RFC 9000 section 13.2.4 is explicit that
    /// limiting this is allowed, and section 19.3 bounds an ACK frame's size in
    /// the same breath — a frame has to fit a packet, and every range costs two
    /// variable-length integers.
    //
    // A fixed bound is the whole of the eviction policy: nothing here watches
    // for an ACK *of* an ACK, so a range survives until the count is full and
    // the low end is pushed out, rather than until the peer confirms it saw
    // it. That is section 13.2.4's algorithm, and it needs state this
    // structure does not keep — which Largest Acknowledged each sent ACK
    // frame carried, and which of those packets were acknowledged.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    //# After receiving
    //# acknowledgments for an ACK frame, the receiver SHOULD stop tracking
    //# those acknowledged ACK Ranges.
    //= type=todo
    ranges_max: u32 = 32,
};

pub fn AckRanges(comptime config: Config) type {
    comptime {
        assert(config.ranges_max >= 1);
    }

    return struct {
        const Self = @This();

        // One of these per packet number space, and it holds nothing that
        // names its own. What keeps an ACK in the right packet is the pairing
        // at the far end: `Connection.writePayload` takes the set from
        // `spaces[level.space()]` and writes it into a packet at `level`, so
        // the numbers in an ACK frame and the keys protecting the packet
        // carrying it always come from the same space. There is no path that
        // reaches one space's set from another space's packet.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        //# ACK frames MUST only be carried in a packet that has the same packet
        //# number space as the packet being acknowledged; see Section 12.1.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        //# For instance, packets that are protected with 1-RTT keys MUST be
        //# acknowledged in packets that are also protected with 1-RTT keys.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        //# Packets that a client sends with 0-RTT packet protection MUST be
        //# acknowledged by the server in packets protected by 1-RTT keys.
        //= type=exception
        //= reason=0-RTT is out of scope: nothing here installs an early-data key or accepts a 0-RTT packet, so there is no 0-RTT packet to acknowledge. See docs/DESIGN.md section 6.
        pub const ranges_max: u32 = config.ranges_max;

        /// Descending by `largest`, non-overlapping, and separated by at least
        /// one packet number. `record` maintains all three, which is what makes
        /// `write` a walk rather than a sort.
        ranges: [ranges_max]Range = @splat(.{ .largest = 0, .smallest = 0 }),
        count: u32 = 0,
        /// When the largest packet number was received, for section 13.2.5's
        /// ACK delay. Nanoseconds on the caller's clock; this structure never
        /// reads one.
        largest_received_at: u64 = 0,
        /// Whether anything ack-eliciting has arrived since the last ACK was
        /// written. Section 13.2.1: an ACK frame is owed only for those.
        //
        // The debt, not the deadline: this flag says an ACK is owed and
        // `write` clears it. Whether the connection pays it inside
        // `max_ack_delay` is the connection's, because that needs a timer and
        // the transport parameter this structure does not hold.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# Every packet SHOULD be acknowledged at least once, and ack-eliciting
        //# packets MUST be acknowledged at least once within the maximum delay
        //# an endpoint communicated using the max_ack_delay transport parameter;
        //# see Section 18.2.
        //
        // Section 13.2.1 also wants a CE-marked packet acknowledged at once.
        // The codepoint is in the IP header, and this package's seam takes a
        // datagram without one — see docs/DESIGN.md section 3 for why no
        // socket-level information crosses it, and section 6 for ECN as a
        // named gap.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# Similarly, packets marked with the ECN Congestion Experienced (CE)
        //# codepoint in the IP header SHOULD be acknowledged immediately, to
        //# reduce the peer's response time to congestion events.
        //= type=exception
        //= reason=the seam takes datagrams without their IP-level ECN codepoints, so a CE mark is not observable here; ECN is a documented gap in docs/DESIGN.md section 6
        //
        // There is no delay to bound, which is how the deadline is met without
        // a timer: `Connection.writePayload` writes the ACK into the first
        // packet it builds after this goes true, and `Connection.wantsSend`
        // reports true while it is set, so the debt is paid at the next send
        // opportunity at every level. "Within max_ack_delay" and "immediately"
        // are the same behaviour here, and the two SHOULDs below are met by
        // the same fact rather than by a policy that distinguishes them.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        //# packets immediately and all ack-eliciting 0-RTT and 1-RTT packets
        //# within its advertised max_ack_delay, with the following exception.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# In order to assist loss detection at the sender, an endpoint SHOULD
        //# generate and send an ACK frame without delay when it receives an ack-
        //# eliciting packet either:
        //
        // And an ACK after one ack-eliciting packet satisfies "after at least
        // two" a fortiori. Acknowledging sooner than the peer's loss detection
        // requires costs packets, which is what section 13.2.2 is trading
        // against; it is a trade this package has not made, not one it made
        // and lost.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.2
        //# A receiver SHOULD send an ACK frame after receiving at least two ack-
        //# eliciting packets.
        //
        // The ACK is written first into a payload the rest of the packet is
        // then built into, so it travels with whatever else was owed rather
        // than in a packet of its own whenever anything else is waiting.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# An endpoint SHOULD send an ACK frame with other frames when there are
        //# new ack-eliciting packets to acknowledge.
        //
        // What is not done is the other half: a packet built for some other
        // reason carries an ACK only when this flag is set, so a set holding
        // ranges that have already been sent once adds nothing to an outgoing
        // packet. Nothing tracks when an ACK was last sent, which is what
        // "recently" would need.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2
        //# When sending a packet for any reason, an endpoint SHOULD attempt to
        //# include an ACK frame if one has not been sent recently.
        //= type=todo
        //
        // PADDING is the one frame that sets nothing here, which is what
        // section 13.2.7's deadlock is made of. It does not arise: the only
        // PADDING this package emits is what `Connection` adds to reach
        // section 14.1's 1200-octet Initial minimum, in the same packet as the
        // CRYPTO frame that made the packet worth sending.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.7
        //# To avoid a deadlock, a sender SHOULD ensure that other frames are sent
        //# periodically in addition to PADDING frames to elicit acknowledgments
        //# from the receiver.
        //= type=exception
        //= reason=this package emits PADDING only to reach section 14.1's 1200-octet Initial minimum, always in the same packet as the CRYPTO frame it pads, so it never sends the PADDING-only packet this deadlock needs
        ack_eliciting_pending: bool = false,
        /// Section 13.2.3's minimum packet number: everything below this is
        /// treated as already seen, whether or not a range still records it.
        /// Rises when eviction forgets a range, and never falls.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        //# A receiver MUST retain an ACK Range unless it can ensure that it will
        //# not subsequently accept packets with numbers in that range.
        minimum: u64 = 0,

        /// Note that `number` arrived at `now_ns`.
        ///
        /// Idempotent: a duplicate changes nothing, which matters because a
        /// duplicate is exactly what a retransmitted packet looks like.
        //
        // Recording a number is what makes it acknowledgeable, so the ordering
        // below is a requirement rather than a convenience.
        // `Connection.receivePacket` calls this only after `openPacket` has
        // removed the protection and `receiveFrames` has returned — a frame
        // that fails to process closes the connection instead of landing here.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.1
        //# A packet MUST NOT be acknowledged until packet protection has been
        //# successfully removed and all frames contained in the packet have been
        //# processed.
        //
        // A packet that is not ack-eliciting is recorded and owes nothing:
        // the flag is the only thing `Connection.wantsSend` consults about
        // this set, so an ACK-only packet arriving — with or without gaps
        // before it — produces no packet in reply and no infinite exchange of
        // acknowledgements between two endpoints that have nothing to say.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# An endpoint MUST NOT send a non-ack-eliciting packet in response to a
        //# non-ack-eliciting packet, even if there are packet gaps that precede
        //# the received packet.
        //
        // The mirror of it on the send side, and the reason it holds is that
        // the optional behaviour the rule constrains is not performed at all:
        // nothing here or in `Connection.writePayload` adds a PING to a packet
        // that would otherwise carry only an ACK.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# In that case, an endpoint MUST NOT send an ack-eliciting frame in all
        //# packets that would otherwise be non-ack-eliciting, to avoid an
        //# infinite feedback loop of acknowledgments.
        pub fn record(self: *Self, number: u64, now_ns: u64, ack_eliciting: bool) void {
            assert(number <= packet_number.max);
            if (ack_eliciting) self.ack_eliciting_pending = true;
            if (self.contains(number)) return;

            if (self.count == 0 or number > self.ranges[0].largest) {
                self.largest_received_at = now_ns;
            }
            self.insert(number);
            self.assertInvariants();
        }

        pub fn contains(self: *const Self, number: u64) bool {
            // Section 13.2.3: a number below the floor is one this endpoint has
            // undertaken never to accept again, which is what makes forgetting
            // its range legal. Answered before the walk, because the range that
            // would have said so is exactly the one that is gone.
            if (number < self.minimum) return true;
            for (self.ranges[0..self.count]) |range| {
                if (range.contains(number)) return true;
                // Descending, so once a range sits entirely below `number`
                // nothing further can hold it.
                if (range.largest < number) return false;
            }
            return false;
        }

        pub fn largest(self: *const Self) ?u64 {
            if (self.count == 0) return null;
            return self.ranges[0].largest;
        }

        /// Extend an adjacent range, merge two that a new number joins, or open
        /// a new one — dropping the lowest if there is no room.
        fn insert(self: *Self, number: u64) void {
            assert(!self.contains(number));

            var index: u32 = 0;
            while (index < self.count and self.ranges[index].largest > number) : (index += 1) {}

            // Adjacent above: `number` extends the range below it downward.
            const extends_below = index > 0 and self.ranges[index - 1].smallest == number + 1;
            // Adjacent below: `number` extends the range at `index` upward.
            const extends_above = index < self.count and self.ranges[index].largest + 1 == number;

            if (extends_below and extends_above) {
                // The number closed a one-packet gap: two ranges become one.
                self.ranges[index - 1].smallest = self.ranges[index].smallest;
                self.remove(index);
                return;
            }
            if (extends_below) {
                self.ranges[index - 1].smallest = number;
                return;
            }
            if (extends_above) {
                self.ranges[index].largest = number;
                return;
            }
            self.open(index, number);
        }

        /// Open a new range at `index`, shifting the rest down and forgetting
        /// the lowest if the set is full. See the module comment for why the
        /// low end is the end that goes, and why forgetting one obliges this to
        /// raise `minimum`.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        //# A receiver MUST retain an ACK Range unless it can ensure that it will
        //# not subsequently accept packets with numbers in that range.
        //
        // Eviction takes `ranges[count - 1]`, the lowest, and index 0 holds
        // the largest — so the number section 13.2.3 requires be kept is the
        // one this can never drop.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        //# Receivers can discard all ACK Ranges, but they MUST retain the
        //# largest packet number that has been successfully processed, as that
        //# is used to recover packet numbers from subsequent packets; see
        //# Section 17.1.
        fn open(self: *Self, index: u32, number: u64) void {
            assert(index <= self.count);
            const floor_before = self.minimum;
            if (self.count == ranges_max) {
                if (index == ranges_max) {
                    // Lower than everything held, and no room to hold it. It is
                    // never recorded, so it must never be accepted either.
                    self.minimum = @max(self.minimum, number + 1);
                    assert(self.minimum >= floor_before);
                    return;
                }
                // The lowest range is about to go; undertake never to accept a
                // number in it again.
                const dropped = self.ranges[self.count - 1];
                self.minimum = @max(self.minimum, dropped.largest + 1);
                self.count -= 1;
            }
            assert(self.minimum >= floor_before);
            var at = self.count;
            while (at > index) : (at -= 1) {
                self.ranges[at] = self.ranges[at - 1];
            }
            self.ranges[index] = .{ .largest = number, .smallest = number };
            self.count += 1;
            assert(self.count <= ranges_max);
        }

        fn remove(self: *Self, index: u32) void {
            assert(index < self.count);
            var at = index;
            while (at + 1 < self.count) : (at += 1) {
                self.ranges[at] = self.ranges[at + 1];
            }
            self.count -= 1;
        }

        pub const WriteError = error{
            /// Nothing has been received, so there is nothing to acknowledge.
            Empty,
            /// `target` cannot hold even the frame's fixed fields.
            OutputTooLong,
            /// A packet number past what a variable-length integer can carry.
            /// Returned rather than asserted: `record` is public and takes a
            /// `u64`, so the 62-bit bound is a caller's to break.
            ValueTooLarge,
        };

        pub const Written = struct {
            octets: usize,
            /// Ranges the frame carried. Fewer than the set holds when the
            /// target ran out of room, which is legal — section 13.2.1 requires
            /// the *largest* to be acknowledged, not all of them.
            ranges: u32,
        };

        /// Render an ACK frame into `target`.
        ///
        /// `now_ns` and `ack_delay_exponent` come from the caller: the delay is
        /// measured against a clock this structure does not read, and scaled by
        /// a transport parameter it does not hold.
        //
        // `ranges[0]` is the largest received and is always written first, and
        // `writeRanges` drops from the low end when the target runs out — so
        // the two requirements below hold no matter how little room the caller
        // gives this.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        //# ACK frames SHOULD always acknowledge the most recently received
        //# packets, and the more out of order the packets are, the more
        //# important it is to send an updated ACK frame quickly, to prevent the
        //# peer from declaring a packet as lost and spuriously retransmitting
        //# the frames it contains.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        //# A receiver SHOULD include an ACK Range containing the largest
        //# received packet number in every ACK frame.
        //
        // The last line of this function clears `ack_eliciting_pending`, and
        // that clearing is the whole of the rule below: the debt an arriving
        // ack-eliciting packet created is settled by the first ACK written for
        // it, so a second packet built before anything else arrives finds
        // nothing owed and `Connection.wantsSend` answers false. Without it,
        // one ack-eliciting packet would keep producing ACK-only packets that
        // no congestion controller is holding back.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        //# Since packets containing only ACK frames are not congestion
        //# controlled, an endpoint MUST NOT send more than one such packet in
        //# response to receiving an ack-eliciting packet.
        pub fn write(self: *Self, target: []u8, now_ns: u64, ack_delay_exponent: u6) WriteError!Written {
            if (self.count == 0) return error.Empty;
            self.assertInvariants();

            // Section 13.2.5: the delay is in microseconds, scaled down by the
            // exponent the peer advertised.
            //
            // Saturating, and the assertion states why rather than enforcing
            // it. `now_ns` is a parameter by policy, so a caller that reads its
            // clock once per batch rather than once per packet passes a value
            // below the receive time — and with assertions compiled out a bare
            // subtraction there is unsigned overflow. A stale `now_ns` producing a
            // zero delay is a correct answer; undefined behaviour is not.
            //
            // Both terms are the caller's clock: `largest_received_at` was
            // stamped in `record` and `now_ns` is passed here, so the interval
            // is the one this endpoint held the acknowledgement for and
            // nothing else. It is reported whatever its size, with no clamp to
            // `max_ack_delay` — the peer is told what happened.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
            //# An endpoint MUST NOT include delays that it
            //# does not control when populating the ACK Delay field in an ACK frame.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
            //# When the measured acknowledgment delay is larger than its
            //# max_ack_delay, an endpoint SHOULD report the measured delay.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
            //# However, endpoints SHOULD include buffering delays caused by
            //# unavailability of decryption keys, since these delays can be large
            //# and are likely to be non-repeating.
            //= type=exception
            //= reason=a packet arriving before its keys is discarded rather than buffered, so no key-unavailability delay is ever accumulated to report
            assert(now_ns >= self.largest_received_at);
            const delay_us = (now_ns -| self.largest_received_at) / std.time.ns_per_us;
            const delay = delay_us >> ack_delay_exponent;

            var writer: Writer = .{ .target = target };
            try writer.writeVarint(@intFromEnum(frame.Type.ack));
            try writer.writeVarint(self.ranges[0].largest);
            try writer.writeVarint(@min(delay, varint.max));
            // The range count is written before the ranges are known to fit, so
            // it is reserved at its widest and back-filled. The alternative is
            // serializing the ranges twice to find out how many there are.
            const count_at = writer.offset;
            try writer.reserve(varint.octets_max);
            try writer.writeVarint(self.ranges[0].count() - 1);

            const emitted = try self.writeRanges(&writer);
            varint.encodeIn(target[count_at..][0..varint.octets_max], emitted, varint.octets_max) catch unreachable; // The space was reserved above and `emitted` is at most `ranges_max`.

            self.ack_eliciting_pending = false;
            return .{ .octets = writer.offset, .ranges = emitted };
        }

        /// The `[Gap, ACK Range Length]` pairs after the first range, stopping
        /// when the target runs out rather than failing.
        fn writeRanges(self: *const Self, writer: *Writer) WriteError!u32 {
            var emitted: u32 = 0;
            var previous = self.ranges[0].smallest;
            var index: u32 = 1;
            while (index < self.count) : (index += 1) {
                const range = self.ranges[index];
                assert(previous > range.largest);
                // Section 19.3.1: the gap is the count of unacknowledged packets
                // between the ranges, less one.
                // Section 19.3.1's gap needs two clear numbers between the
                // ranges. The separation invariant guarantees it, and this
                // checks it rather than trusting it: with assertions compiled
                // out, a broken invariant would underflow here and encode a
                // gap that acknowledges packets never received.
                if (previous < range.largest + 2) break;
                const gap = previous - range.largest - 2;
                const saved = writer.offset;
                writer.writeVarint(gap) catch {
                    writer.offset = saved;
                    break;
                };
                writer.writeVarint(range.count() - 1) catch {
                    writer.offset = saved;
                    break;
                };
                previous = range.smallest;
                emitted += 1;
            }
            return emitted;
        }

        fn assertInvariants(self: *const Self) void {
            assert(self.count <= ranges_max);
            var index: u32 = 0;
            while (index < self.count) : (index += 1) {
                const range = self.ranges[index];
                assert(range.largest >= range.smallest);
                assert(range.largest <= packet_number.max);
                // Nothing held may sit below the floor, or `contains` would
                // answer true for a number a range still records — two sources
                // of truth disagreeing.
                assert(range.smallest >= self.minimum);
                // Descending, and separated by at least one number: a gap of
                // zero would mean the merge failed to run.
                if (index > 0) assert(self.ranges[index - 1].smallest > range.largest + 1);
            }
        }
    };
}

const Writer = struct {
    target: []u8,
    offset: usize = 0,

    /// Named `writeVarint` rather than `varint` so it does not shadow the
    /// module import — which is why this used to spell `@import("../varint.zig")`
    /// inline at every use.
    fn writeVarint(self: *Writer, value: u64) error{ OutputTooLong, ValueTooLarge }!void {
        // Returned, not asserted. `varint.encode` has two failure modes and
        // `reserve` only rules out one of them; the other is a value past 62
        // bits, whose only previous guard was an assertion in `record` — and an
        // assertion is not a guard in the build that removes it.
        if (value > varint.max) return error.ValueTooLarge;
        const length = varint.encodedLength(value);
        try self.reserve(length);
        _ = varint.encode(self.target[self.offset - length ..][0..length], value) catch unreachable; // `reserve` sized the slice from `encodedLength` and the range check above bounded the value.
    }

    fn reserve(self: *Writer, octets: u8) error{OutputTooLong}!void {
        const end = self.offset + octets;
        if (end > self.target.len) return error.OutputTooLong;
        self.offset = end;
    }
};

const testing = std.testing;

const Set = AckRanges(.{ .ranges_max = 4 });

test "consecutive numbers collapse into one range" {
    var set: Set = .{};
    for (0..8) |number| set.record(number, 0, true);
    try testing.expectEqual(@as(u32, 1), set.count);
    try testing.expectEqual(@as(u64, 7), set.largest().?);
    try testing.expectEqual(@as(u64, 0), set.ranges[0].smallest);
}

test "arrival order does not change the set" {
    var forward: Set = .{};
    for ([_]u64{ 0, 1, 2, 5, 6 }) |number| forward.record(number, 0, true);
    var backward: Set = .{};
    for ([_]u64{ 6, 5, 2, 1, 0 }) |number| backward.record(number, 0, true);

    try testing.expectEqual(forward.count, backward.count);
    try testing.expectEqual(@as(u32, 2), backward.count);
    for (0..forward.count) |index| {
        try testing.expectEqual(forward.ranges[index].largest, backward.ranges[index].largest);
        try testing.expectEqual(forward.ranges[index].smallest, backward.ranges[index].smallest);
    }
}

test "a number closing a one-packet gap merges two ranges" {
    var set: Set = .{};
    set.record(0, 0, true);
    set.record(2, 0, true);
    try testing.expectEqual(@as(u32, 2), set.count);
    set.record(1, 0, true);
    try testing.expectEqual(@as(u32, 1), set.count);
    try testing.expectEqual(@as(u64, 2), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 0), set.ranges[0].smallest);
}

test "a duplicate changes nothing" {
    var set: Set = .{};
    set.record(4, 100, true);
    const before = set.ranges[0];
    set.record(4, 200, true);
    try testing.expectEqual(@as(u32, 1), set.count);
    try testing.expectEqual(before.largest, set.ranges[0].largest);
    // And the receive time did not move: it belongs to the largest number, and
    // a retransmission of an old packet is not news about the newest one.
    try testing.expectEqual(@as(u64, 100), set.largest_received_at);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
//# Receivers can discard all ACK Ranges, but they MUST retain the
//# largest packet number that has been successfully processed, as that
//# is used to recover packet numbers from subsequent packets; see
//# Section 17.1.
//= type=test
test "the lowest range is what a full set forgets" {
    var set: Set = .{};
    // Every other number: one range each, which is the shape a peer chooses
    // when it wants this structure to grow.
    for ([_]u64{ 0, 2, 4, 6 }) |number| set.record(number, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    try testing.expect(set.contains(0));

    set.record(8, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    // The high end survives, because section 19.3 makes an acknowledgement
    // irrevocable; the low end is merely a retransmission.
    try testing.expectEqual(@as(u64, 8), set.largest().?);
    try testing.expect(set.contains(2));

    // The *range* holding 0 is gone, but 0 is still refused — section 13.2.3
    // only permits forgetting a range if the numbers in it will not be accepted
    // again. This assertion used to read `!set.contains(0)`, which asserted the
    // violation as though it were the design.
    try testing.expect(set.contains(0));
    try testing.expect(set.minimum > 0);
}

test "a number below a full set is dropped rather than displacing a higher one" {
    var set: Set = .{};
    for ([_]u64{ 10, 12, 14, 16 }) |number| set.record(number, 0, true);
    set.record(2, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    try testing.expectEqual(@as(u64, 10), set.ranges[3].largest);
    // Not recorded, and therefore refused: an untracked number that could still
    // be accepted is a replay window. This too used to assert the opposite.
    try testing.expect(set.contains(2));
}

test "a written ACK frame parses back to the ranges that went in" {
    var set: Set = .{};
    for ([_]u64{ 100, 99, 98, 95, 94, 90 }) |number| set.record(number, 0, true);
    try testing.expectEqual(@as(u32, 3), set.count);

    var target: [64]u8 = @splat(0);
    const written = try set.write(&target, 0, 3);
    try testing.expectEqual(@as(u32, 2), written.ranges);

    const parsed = try frame.parse(target[0..written.octets]);
    const ack = parsed.frame.ack;
    try testing.expectEqual(@as(u64, 100), ack.largest);
    try testing.expectEqual(@as(u64, 2), ack.range_count);

    var iterator = ack.iterate();
    const first = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 100), first.largest);
    try testing.expectEqual(@as(u64, 98), first.smallest);
    const second = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 95), second.largest);
    try testing.expectEqual(@as(u64, 94), second.smallest);
    const third = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 90), third.largest);
    try testing.expectEqual(@as(u64, 90), third.smallest);
    try testing.expectEqual(@as(?frame.Range, null), try iterator.next());
}

test "the delay is scaled by the exponent the peer advertised" {
    var set: Set = .{};
    set.record(1, 0, true);
    var target: [64]u8 = @splat(0);
    // 8192 microseconds, with the default exponent of 3, is 1024.
    const written = try set.write(&target, 8192 * std.time.ns_per_us, 3);
    const ack = (try frame.parse(target[0..written.octets])).frame.ack;
    try testing.expectEqual(@as(u64, 1024), ack.delay);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
//# A receiver SHOULD include an ACK Range containing the largest
//# received packet number in every ACK frame.
//= type=test
test "a target too small carries the largest and drops the rest" {
    var set: Set = .{};
    for ([_]u64{ 100, 98, 96, 94 }) |number| set.record(number, 0, true);

    // Room for the fixed fields and nothing more. Section 13.2.1 requires the
    // largest to be acknowledged, not every range, so this is a shorter frame
    // rather than a failure.
    var target: [16]u8 = @splat(0);
    const written = try set.write(&target, 0, 3);
    try testing.expect(written.ranges < 3);
    const ack = (try frame.parse(target[0..written.octets])).frame.ack;
    try testing.expectEqual(@as(u64, 100), ack.largest);
    try testing.expectEqual(@as(u64, written.ranges), ack.range_count);

    // Whatever it did carry has to be walkable, not truncated mid-pair.
    var iterator = ack.iterate();
    var seen: u32 = 0;
    while (try iterator.next()) |_| seen += 1;
    try testing.expectEqual(written.ranges + 1, seen);
}

test "an empty set has nothing to say" {
    var set: Set = .{};
    var target: [64]u8 = @splat(0);
    try testing.expectError(error.Empty, set.write(&target, 0, 3));
    try testing.expectEqual(@as(?u64, null), set.largest());
    try testing.expect(!set.contains(0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
//# Every packet SHOULD be acknowledged at least once, and ack-eliciting
//# packets MUST be acknowledged at least once within the maximum delay
//# an endpoint communicated using the max_ack_delay transport parameter;
//# see Section 18.2.
//= type=test
//
// The first two lines are the second rule and the last two are the third: a
// packet that is not ack-eliciting leaves nothing owed, and one ACK settles
// what an ack-eliciting packet owed.
//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
//# An endpoint MUST NOT send a non-ack-eliciting packet in response to a
//# non-ack-eliciting packet, even if there are packet gaps that precede
//# the received packet.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
//# Since packets containing only ACK frames are not congestion
//# controlled, an endpoint MUST NOT send more than one such packet in
//# response to receiving an ack-eliciting packet.
//= type=test
test "writing an ACK clears the debt an ack-eliciting packet created" {
    var set: Set = .{};
    set.record(1, 0, false);
    try testing.expect(!set.ack_eliciting_pending);
    set.record(2, 0, true);
    try testing.expect(set.ack_eliciting_pending);

    var target: [64]u8 = @splat(0);
    _ = try set.write(&target, 0, 3);
    try testing.expect(!set.ack_eliciting_pending);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
//# A receiver MUST retain an ACK Range unless it can ensure that it will
//# not subsequently accept packets with numbers in that range.
//= type=test
test "section 13.2.3: forgetting a range means refusing it forever" {
    var set: Set = .{};
    // Every other number, which is the shape that costs one range each.
    for ([_]u64{ 0, 2, 4, 6 }) |number| set.record(number, 0, true);
    try testing.expect(set.contains(0));

    set.record(8, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    // The range holding 0 is gone — and section 13.2.3 requires that dropping
    // it come with an undertaking never to accept those numbers again.
    // Otherwise a replay is recorded as new and its frames are processed twice,
    // which is the duplicate suppression this structure exists to provide.
    try testing.expect(set.contains(0));
    try testing.expectEqual(@as(u64, 1), set.minimum);

    // A replay changes nothing: no new range, no new acknowledgement.
    const before = set.count;
    set.record(0, 0, true);
    try testing.expectEqual(before, set.count);
}

test "the floor rises with eviction and never falls" {
    var set: Set = .{};
    var number: u64 = 0;
    while (number < 40) : (number += 2) set.record(number, 0, true);
    const floor = set.minimum;
    try testing.expect(floor > 0);

    // A number below the floor is refused rather than recorded.
    set.record(0, 0, true);
    try testing.expectEqual(floor, set.minimum);
    try testing.expect(set.contains(0));
    // And the floor never moves backwards.
    set.record(1000, 0, true);
    try testing.expect(set.minimum >= floor);
}

test "a number too low to hold when full is refused rather than dropped" {
    var set: Set = .{};
    for ([_]u64{ 10, 12, 14, 16 }) |n| set.record(n, 0, true);
    // Lower than everything held, and there is no room. It cannot be recorded,
    // so it must not be acceptable either — otherwise it is a replay window.
    set.record(2, 0, true);
    try testing.expect(set.contains(2));
    try testing.expectEqual(@as(u32, 4), set.count);
}
