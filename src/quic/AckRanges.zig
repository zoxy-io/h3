//! The set of packet numbers received in one packet number space, and the ACK
//! frames generated from it (RFC 9000 sections 13.2 and 19.3).
//!
//! Three of these per connection — Initial, Handshake, application — because
//! the spaces are separate and an acknowledgement in one says nothing about
//! another (section 12.3). `packet_number.Space` exists so a caller cannot pass
//! the wrong one by accident, and this structure is deliberately *not* an array
//! of three: which spaces are alive changes over a connection's life, and a
//! discarded space's set should be gone rather than idle.
//!
//! ## The bound is the whole design problem
//!
//! A received-packet set is a set of ranges, and the number of ranges is chosen
//! by the peer: sending every other packet number produces one range per
//! packet. Unbounded, that is a structure an attacker sizes. Bounded, something
//! has to be dropped, and *which* end is dropped is the decision.
//!
//! The low end goes. Section 13.2.4 permits an endpoint to limit what it
//! acknowledges, and the cost of forgetting a low range is that the peer may
//! retransmit data we already have — wasteful, and handled, because
//! `Reassembler` treats a duplicate as free. The cost of forgetting a *high*
//! range would be acknowledging a packet number below one already sent in an
//! earlier ACK, which section 13.2.1 forbids outright: an ACK frame's ranges
//! must be descending and an endpoint must not renege on what it acknowledged.
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
    ranges_max: u32 = 32,
};

pub fn AckRanges(comptime config: Config) type {
    comptime {
        assert(config.ranges_max >= 1);
    }

    return struct {
        const Self = @This();

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
        ack_eliciting_pending: bool = false,

        /// Note that `number` arrived at `now`.
        ///
        /// Idempotent: a duplicate changes nothing, which matters because a
        /// duplicate is exactly what a retransmitted packet looks like.
        pub fn record(self: *Self, number: u64, now: u64, ack_eliciting: bool) void {
            assert(number <= packet_number.max);
            if (ack_eliciting) self.ack_eliciting_pending = true;
            if (self.contains(number)) return;

            if (self.count == 0 or number > self.ranges[0].largest) {
                self.largest_received_at = now;
            }
            self.insert(number);
            self.assertInvariants();
        }

        pub fn contains(self: *const Self, number: u64) bool {
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
        /// low end is the end that goes.
        fn open(self: *Self, index: u32, number: u64) void {
            assert(index <= self.count);
            if (self.count == ranges_max) {
                if (index == ranges_max) return; // Lower than everything held.
                self.count -= 1;
            }
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
        /// `now` and `ack_delay_exponent` come from the caller: the delay is
        /// measured against a clock this structure does not read, and scaled by
        /// a transport parameter it does not hold.
        pub fn write(self: *Self, target: []u8, now: u64, ack_delay_exponent: u6) WriteError!Written {
            if (self.count == 0) return error.Empty;
            assert(now >= self.largest_received_at);

            // Section 13.2.5: the delay is in microseconds, scaled down by the
            // exponent the peer advertised.
            const delay_us = (now - self.largest_received_at) / std.time.ns_per_us;
            const delay = delay_us >> ack_delay_exponent;

            var writer: Writer = .{ .target = target };
            try writer.varint(@intFromEnum(frame.Type.ack));
            try writer.varint(self.ranges[0].largest);
            try writer.varint(@min(delay, varint.max));
            // The range count is written before the ranges are known to fit, so
            // it is reserved at its widest and back-filled. The alternative is
            // serializing the ranges twice to find out how many there are.
            const count_at = writer.offset;
            try writer.reserve(varint.octets_max);
            try writer.varint(self.ranges[0].count() - 1);

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
                const gap = previous - range.largest - 2;
                const saved = writer.offset;
                writer.varint(gap) catch {
                    writer.offset = saved;
                    break;
                };
                writer.varint(range.count() - 1) catch {
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

    fn varint(self: *Writer, value: u64) error{OutputTooLong}!void {
        const length = @import("../varint.zig").encodedLength(value);
        try self.reserve(length);
        _ = @import("../varint.zig").encode(self.target[self.offset - length ..][0..length], value) catch unreachable; // `reserve` sized the slice from `encodedLength`.
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

test "the lowest range is what a full set forgets" {
    var set: Set = .{};
    // Every other number: one range each, which is the shape a peer chooses
    // when it wants this structure to grow.
    for ([_]u64{ 0, 2, 4, 6 }) |number| set.record(number, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    try testing.expect(set.contains(0));

    set.record(8, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    // The high end survives, because section 13.2.1 forbids reneging on an
    // acknowledgement already sent; the low end is merely a retransmission.
    try testing.expectEqual(@as(u64, 8), set.largest().?);
    try testing.expect(!set.contains(0));
    try testing.expect(set.contains(2));
}

test "a number below a full set is dropped rather than displacing a higher one" {
    var set: Set = .{};
    for ([_]u64{ 10, 12, 14, 16 }) |number| set.record(number, 0, true);
    set.record(2, 0, true);
    try testing.expectEqual(@as(u32, 4), set.count);
    try testing.expect(!set.contains(2));
    try testing.expectEqual(@as(u64, 10), set.ranges[3].largest);
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
