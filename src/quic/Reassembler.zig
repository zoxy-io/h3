//! Ordered byte reassembly for a QUIC stream.
//!
//! Chunks arrive as `(offset, data)` — out of order, duplicated, overlapping,
//! and with gaps — and a reader wants the contiguous prefix. That is what
//! `push` and `readable` are. One implementation serves two callers that look
//! unrelated and are not: the CRYPTO stream carries the TLS handshake at each
//! encryption level (RFC 9000 section 19.6), and every request and response
//! body is a stream (section 2.2). Both are byte streams with offsets, both are
//! fed by a lossy network, and writing the second one separately would be
//! writing the first one's bugs again.
//!
//! ## The capacity is the flow control window
//!
//! The buffer is comptime-sized and the peer may not write past its end. That
//! is not a limitation working around the no-allocator rule — it *is* QUIC's
//! flow control, stated once instead of twice. `MAX_STREAM_DATA` is derived
//! from this capacity (`limit`), and a peer that exceeds it has committed a
//! `FLOW_CONTROL_ERROR` rather than overrun a buffer. A design where the window
//! and the buffer were separate numbers is a design where they can disagree,
//! and the direction they disagree in is a heap overflow.
//!
//! ## Data at an offset never changes
//!
//! RFC 9000 section 2.2 is explicit: an endpoint MUST NOT send data at a given
//! offset with different content, and a receiver that detects it MAY treat it
//! as a `PROTOCOL_VIOLATION`. This detects it. The cost is a comparison over
//! the overlap, paid only when a chunk actually overlaps something already
//! held, and the reason to pay it is that the alternative is a stream whose
//! contents depend on packet arrival order — which is a request-smuggling
//! primitive wherever two intermediaries reassemble differently.
//!
//! ## What it does not do
//!
//! No timers, no acknowledgement, no retransmission — those are the
//! connection's, over `AckRanges` and RFC 9002. This structure knows only which
//! octets it holds.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const varint = @import("../varint.zig");

/// A half-open span of buffer-relative offsets. Internal: the public API speaks
/// absolute stream offsets, because that is what the wire carries.
const Span = struct {
    start: u32,
    end: u32,

    fn length(span: Span) u32 {
        assert(span.end >= span.start);
        return span.end - span.start;
    }
};

pub const Config = struct {
    /// Octets held at once. This is the stream's flow control window.
    ///
    /// It is also the interface below, for the one caller that is a
    /// cryptographic protocol: `Connection.crypto_octets` builds one of these
    /// per encryption level, so the consumer whose TLS engine does the
    /// buffering states the limit at comptime and this window is derived from
    /// it. There is one number rather than a buffer and a limit that can drift
    /// apart — see the module comment for why that direction of drift is a
    /// heap overflow.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4
    //# To avoid excessive buffering at multiple layers, QUIC implementations
    //# SHOULD provide an interface for the cryptographic protocol
    //# implementation to communicate its buffering limits.
    capacity: u32,
    /// Distinct received spans tolerated before a peer is refused.
    ///
    /// A gap costs a span, and a peer can manufacture gaps at will by sending
    /// every other octet in its own packet. Without a bound that is an
    /// unbounded structure driven by an attacker; with one it is a
    /// `TooFragmented` error the connection turns into a close. Sixteen is
    /// generous for loss and stingy for malice — a real path reorders within a
    /// few packets, not within a few hundred.
    spans_max: u32 = 16,
};

pub fn Reassembler(comptime config: Config) type {
    comptime {
        assert(config.capacity >= 1);
        assert(config.spans_max >= 1);
        // A span needs two offsets into the buffer, so the buffer has to be
        // addressable by the type those offsets use.
        assert(config.capacity <= std.math.maxInt(u32));
        // And the stream offset space has to be able to hold the window.
        assert(config.capacity <= varint.max);
    }

    return struct {
        const Self = @This();

        /// Octets held at once, and the stream's flow control window.
        pub const capacity: u32 = config.capacity;
        pub const spans_max: u32 = config.spans_max;

        storage: [capacity]u8 = @splat(0),
        /// The stream offset of `storage[0]`: everything below it has been
        /// consumed and is gone.
        base: u64 = 0,
        /// Received spans, ascending, non-overlapping and non-adjacent. The
        /// merge on insert is what keeps that invariant, and it is what makes
        /// `readable` a single lookup.
        spans: [spans_max]Span = @splat(.{ .start = 0, .end = 0 }),
        span_count: u32 = 0,
        /// Section 4.5's final size, once a FIN or a RESET_STREAM has named it.
        final_size: ?u64 = null,

        pub const PushError = error{
            /// The chunk reaches past the flow control window.
            /// `FLOW_CONTROL_ERROR`.
            BeyondWindow,
            /// More distinct spans than `spans_max`. Not a protocol error in
            /// the RFC's vocabulary — the connection decides, and closing with
            /// `INTERNAL_ERROR` is the honest answer, because the peer is
            /// within its rights and this endpoint is out of room.
            TooFragmented,
            /// Section 2.2: data at an offset already held, with different
            /// content. `PROTOCOL_VIOLATION`.
            Inconsistent,
            /// Section 4.5: data past a final size already established, or a
            /// final size that contradicts data already held.
            /// `FINAL_SIZE_ERROR`.
            FinalSizeViolated,
        };

        /// Take a chunk of stream data.
        ///
        /// Chunks below `base` are already consumed; the part of one that is
        /// still relevant is kept and the rest dropped, because a retransmission
        /// covering consumed data is ordinary rather than an error.
        pub fn push(self: *Self, offset: u64, data: []const u8) PushError!void {
            // Checked rather than asserted: `push` is public, so the 62-bit
            // bound is a precondition a consumer can break, and the addition
            // below overflows `u64` in the build that has no assertions.
            if (offset > varint.max) return error.BeyondWindow;
            if (data.len > varint.max - offset) return error.BeyondWindow;
            const end = offset + data.len;
            // "Even after a stream is closed" is the part that costs something:
            // `final_size` is kept for the life of the reassembler rather than
            // dropped once everything has been read, which is the state
            // commitment section 4.5 warns about and the reason this is a
            // SHOULD. It is paid here, because the alternative is that a peer
            // can extend a stream it already ended.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
            //# A receiver SHOULD treat receipt of data at or beyond the final size as
            //# an error of type FINAL_SIZE_ERROR, even after a stream is closed.
            if (self.final_size) |final| {
                if (end > final) return error.FinalSizeViolated;
            }
            if (end <= self.base) return; // Entirely consumed already.

            // Trim what has been consumed; the remainder starts at `base`.
            const from = @max(offset, self.base);
            const trimmed = data[@intCast(from - offset)..];
            if (trimmed.len == 0) return;

            const start_relative = from - self.base;
            if (start_relative + trimmed.len > capacity) return error.BeyondWindow;
            const span: Span = .{
                .start = @intCast(start_relative),
                .end = @intCast(start_relative + trimmed.len),
            };

            try self.checkConsistent(span, trimmed);
            try self.insert(span);
            @memcpy(self.storage[span.start..span.end], trimmed);
        }

        /// Section 2.2: whatever this chunk overlaps must already say the same
        /// thing. Checked before anything is written, so a rejected chunk
        /// leaves the buffer as it was.
        ///
        /// The MAY is taken: `error.Inconsistent` becomes `PROTOCOL_VIOLATION`
        /// rather than a silently preferred copy, because the alternative is a
        /// stream whose contents depend on arrival order — see the module
        /// comment for why that is a smuggling primitive and not a curiosity.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        //# The data at a given offset MUST NOT change if it is sent multiple
        //# times; an endpoint MAY treat receipt of different data at the same
        //# offset within a stream as a connection error of type
        //# PROTOCOL_VIOLATION.
        fn checkConsistent(self: *const Self, span: Span, data: []const u8) PushError!void {
            assert(data.len == span.length());
            for (self.spans[0..self.span_count]) |held| {
                const start = @max(span.start, held.start);
                const end = @min(span.end, held.end);
                if (start >= end) continue;
                const offered = data[start - span.start .. end - span.start];
                if (!std.mem.eql(u8, self.storage[start..end], offered)) {
                    return error.Inconsistent;
                }
            }
        }

        /// Insert `span`, merging with everything it touches or adjoins.
        ///
        /// Adjacency merges as well as overlap, which is what keeps two halves
        /// of a contiguous run from costing two spans forever.
        fn insert(self: *Self, span: Span) PushError!void {
            var merged = span;
            var kept: u32 = 0;
            for (self.spans[0..self.span_count]) |held| {
                if (held.end < merged.start or held.start > merged.end) {
                    // Disjoint and not adjacent: it survives as it is.
                    self.spans[kept] = held;
                    kept += 1;
                    continue;
                }
                merged = .{ .start = @min(merged.start, held.start), .end = @max(merged.end, held.end) };
            }
            if (kept == spans_max) return error.TooFragmented;

            // Insert in ascending order, which the loop above preserved for the
            // survivors: they were ascending and none was dropped out of turn.
            var index = kept;
            while (index > 0 and self.spans[index - 1].start > merged.start) : (index -= 1) {
                self.spans[index] = self.spans[index - 1];
            }
            self.spans[index] = merged;
            self.span_count = kept + 1;
            assert(self.span_count <= spans_max);
            self.assertInvariants();
        }

        /// The contiguous run available from `base`, in order.
        ///
        /// Borrows from the reassembler, so a caller holding it across a `push`
        /// is holding a slice into a buffer that may have been written.
        ///
        /// The whole of the ordering guarantee is the two lines below: the run
        /// starts at `base` or it is empty, so an octet behind a gap is held
        /// and never handed out. A structure that returned what it had would
        /// deliver the stream in arrival order, which is what QUIC's
        /// reassembly exists to prevent.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        //# Endpoints MUST be able to deliver stream data to an application as an
        //# ordered byte stream.
        pub fn readable(self: *const Self) []const u8 {
            if (self.span_count == 0) return &.{};
            const first = self.spans[0];
            if (first.start != 0) return &.{};
            return self.storage[0..first.end];
        }

        /// The stream offset the next unread octet has.
        pub fn readOffset(self: *const Self) u64 {
            return self.base;
        }

        /// Drop `octets` from the front, freeing that much window.
        pub fn consume(self: *Self, octets: usize) void {
            // The assertion states the precondition; the clamp is what enforces
            // it. `-Dassertions=false` is one of the two builds that ship, and
            // without the clamp an over-reported count reaches `@intCast`,
            // `spans[span_count - 1]` with no spans, and `held - shift` — an
            // illegal cast, an out-of-bounds read and an underflow, none of
            // them checked.
            assert(octets <= self.readable().len);
            const shift: u32 = @intCast(@min(octets, self.readable().len));
            if (shift == 0) return;

            // The move is over the octets still *held*, not over the capacity:
            // a caller that drains everything readable moves nothing, which is
            // the common case and the one worth being fast.
            const held = self.spans[self.span_count - 1].end;
            assert(held >= shift);
            std.mem.copyForwards(u8, self.storage[0 .. held - shift], self.storage[shift..held]);

            var kept: u32 = 0;
            for (self.spans[0..self.span_count]) |span| {
                if (span.end <= shift) continue;
                self.spans[kept] = .{
                    .start = if (span.start > shift) span.start - shift else 0,
                    .end = span.end - shift,
                };
                kept += 1;
            }
            self.span_count = kept;
            self.base += shift;
            self.assertInvariants();
        }

        /// The largest stream offset the peer may write, for `MAX_STREAM_DATA`.
        /// Derived from the capacity rather than tracked beside it, so the
        /// window and the buffer cannot disagree.
        ///
        /// This is the number the requirement below is measured against, and
        /// `push` returns `BeyondWindow` for anything past it — which
        /// `Streams.receive` turns into `error.FlowControl` and the connection
        /// into `FLOW_CONTROL_ERROR`. Refusing rather than growing is the whole
        /// reason the window is the buffer.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        //# A receiver MUST close the connection with an error of type
        //# FLOW_CONTROL_ERROR if the sender violates the advertised connection or
        //# stream data limits; see Section 11 for details on error handling.
        pub fn limit(self: *const Self) u64 {
            return self.base + capacity;
        }

        /// Section 4.5: name the stream's final size, from a FIN or a
        /// RESET_STREAM. Idempotent, and a second, different answer is an error.
        ///
        /// Both halves of "it cannot change" are here: a second, different size
        /// is refused, and so is one below what has already been received. The
        /// second is the one worth stating, because a size that retracts data
        /// the peer itself delivered would give back flow control credit that
        /// `Streams` has already charged.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        //# If a RESET_STREAM or STREAM frame is received indicating a change in
        //# the final size for the stream, an endpoint SHOULD respond with an
        //# error of type FINAL_SIZE_ERROR; see Section 11 for details on error
        //# handling.
        pub fn finish(self: *Self, size: u64) PushError!void {
            assert(size <= varint.max);
            if (self.final_size) |final| {
                if (final != size) return error.FinalSizeViolated;
                return;
            }
            // A final size below what has already been *received* contradicts
            // data the peer itself sent. `base` counts what has been consumed
            // and is gone, so it belongs in the comparison: without it, a
            // stream drained to empty had no spans left and the check was
            // skipped entirely, and `finish` below what was already read
            // succeeded.
            const received_end = self.base + if (self.span_count > 0) self.spans[self.span_count - 1].end else 0;
            if (received_end > size) return error.FinalSizeViolated;
            self.final_size = size;
        }

        /// True when every octet up to the final size has *arrived*, whether or
        /// not the caller has read it. The cue that a request body or a CRYPTO
        /// stream is whole.
        ///
        /// The doc comment said "arrived and been consumed", which the code has
        /// never checked: `readable()` is what is held and unread, so this goes
        /// true the moment the last octet lands and stays true until it is
        /// taken. A caller that read this as "nothing left to do" would drop
        /// data still sitting in the buffer. `Streams.settle` asks both
        /// questions — this one and `readable().len == 0` — which is what the
        /// comment was describing.
        pub fn isComplete(self: *const Self) bool {
            const final = self.final_size orelse return false;
            return self.base + self.readable().len >= final;
        }

        fn assertInvariants(self: *const Self) void {
            assert(self.span_count <= spans_max);
            var index: u32 = 0;
            while (index < self.span_count) : (index += 1) {
                const span = self.spans[index];
                assert(span.start < span.end);
                assert(span.end <= capacity);
                // Ascending, and separated by at least one octet: a gap of zero
                // would mean the merge failed to run.
                if (index > 0) assert(span.start > self.spans[index - 1].end);
            }
        }
    };
}

const testing = std.testing;

const Small = Reassembler(.{ .capacity = 64, .spans_max = 4 });

test "in-order chunks read back as one run" {
    var stream: Small = .{};
    try stream.push(0, "hello ");
    try stream.push(6, "world");
    try testing.expectEqualStrings("hello world", stream.readable());
    try testing.expectEqual(@as(u64, 0), stream.readOffset());

    stream.consume(6);
    try testing.expectEqualStrings("world", stream.readable());
    try testing.expectEqual(@as(u64, 6), stream.readOffset());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
//# Endpoints MUST be able to deliver stream data to an application as an
//# ordered byte stream.
//= type=test
test "a gap holds everything after it back" {
    var stream: Small = .{};
    try stream.push(6, "world");
    // Nothing is readable: the run must start at the read offset.
    try testing.expectEqualStrings("", stream.readable());
    try stream.push(0, "hello ");
    try testing.expectEqualStrings("hello world", stream.readable());
}

test "out-of-order arrival converges on the same bytes" {
    var forward: Small = .{};
    try forward.push(0, "abc");
    try forward.push(3, "def");
    try forward.push(6, "ghi");

    var backward: Small = .{};
    try backward.push(6, "ghi");
    try backward.push(0, "abc");
    try backward.push(3, "def");

    try testing.expectEqualStrings(forward.readable(), backward.readable());
    try testing.expectEqualStrings("abcdefghi", backward.readable());
    // And both converged to one span rather than three: adjacency merges.
    try testing.expectEqual(@as(u32, 1), backward.span_count);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
//# The data at a given offset MUST NOT change if it is sent multiple
//# times; an endpoint MAY treat receipt of different data at the same
//# offset within a stream as a connection error of type
//# PROTOCOL_VIOLATION.
//= type=test
test "a duplicate is free, and a contradiction is a protocol violation" {
    var stream: Small = .{};
    try stream.push(0, "hello");
    // Section 2.2: the same octets at the same offset is ordinary
    // retransmission and costs nothing.
    try stream.push(0, "hello");
    try stream.push(2, "ll");
    try testing.expectEqualStrings("hello", stream.readable());

    // Different octets at an offset already held is the smuggling primitive.
    try testing.expectError(error.Inconsistent, stream.push(0, "HELLO"));
    try testing.expectError(error.Inconsistent, stream.push(4, "O!"));
    // And a rejected chunk left the buffer as it was.
    try testing.expectEqualStrings("hello", stream.readable());
}

test "a partial overlap is checked only where it overlaps" {
    var stream: Small = .{};
    try stream.push(4, "45678");
    // Overlaps at 4..9 with the same content, and extends both ways.
    try stream.push(0, "0123456789");
    try testing.expectEqualStrings("0123456789", stream.readable());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
//# A receiver MUST close the connection with an error of type
//# FLOW_CONTROL_ERROR if the sender violates the advertised connection or
//# stream data limits; see Section 11 for details on error handling.
//= type=test
test "the window is the buffer, and a peer may not write past it" {
    var stream: Small = .{};
    try testing.expectEqual(@as(u64, Small.capacity), stream.limit());

    const oversized: [Small.capacity + 1]u8 = @splat('x');
    try testing.expectError(error.BeyondWindow, stream.push(0, &oversized));
    // Exactly to the edge is fine.
    const exact: [Small.capacity]u8 = @splat('x');
    try stream.push(0, &exact);

    // And consuming moves the window forward by what was freed.
    stream.consume(Small.capacity);
    try testing.expectEqual(@as(u64, Small.capacity * 2), stream.limit());
}

test "consumed data is not re-admitted, and a retransmission over it is not an error" {
    var stream: Small = .{};
    try stream.push(0, "abcdef");
    stream.consume(6);
    try testing.expectEqualStrings("", stream.readable());

    // The peer retransmits what we already consumed: ordinary, and dropped.
    try stream.push(0, "abcdef");
    try testing.expectEqualStrings("", stream.readable());
    try testing.expectEqual(@as(u64, 6), stream.readOffset());

    // A chunk straddling the boundary keeps only its live tail.
    try stream.push(3, "defghi");
    try testing.expectEqualStrings("ghi", stream.readable());
}

test "too many gaps is refused rather than grown into" {
    var stream: Small = .{};
    // Four disjoint spans fit; a fifth does not. A peer can manufacture gaps at
    // will, so the bound is what stops an attacker sizing this structure.
    try stream.push(0, "a");
    try stream.push(2, "b");
    try stream.push(4, "c");
    try stream.push(6, "d");
    try testing.expectEqual(@as(u32, 4), stream.span_count);
    try testing.expectError(error.TooFragmented, stream.push(8, "e"));

    // Filling a gap merges and makes room again.
    try stream.push(1, "x");
    try testing.expectEqual(@as(u32, 3), stream.span_count);
    try stream.push(8, "e");
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# If a RESET_STREAM or STREAM frame is received indicating a change in
//# the final size for the stream, an endpoint SHOULD respond with an
//# error of type FINAL_SIZE_ERROR; see Section 11 for details on error
//# handling.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# A receiver SHOULD treat receipt of data at or beyond the final size as
//# an error of type FINAL_SIZE_ERROR, even after a stream is closed.
//= type=test
test "section 4.5's final size" {
    var stream: Small = .{};
    try stream.push(0, "abc");
    try stream.finish(5);
    try testing.expect(!stream.isComplete());

    // Data past the final size the peer itself named.
    try testing.expectError(error.FinalSizeViolated, stream.push(5, "zz"));
    // A second, different final size.
    try testing.expectError(error.FinalSizeViolated, stream.finish(6));
    // The same one again is idempotent, because a FIN can be retransmitted.
    try stream.finish(5);

    try stream.push(3, "de");
    try testing.expect(stream.isComplete());
    try testing.expectEqualStrings("abcde", stream.readable());
}

test "a final size below what is already held is refused" {
    var stream: Small = .{};
    try stream.push(0, "abcdef");
    try testing.expectError(error.FinalSizeViolated, stream.finish(3));
}

test "a long stream drains through a small window" {
    // The shape a response body has: more bytes than the window, consumed as
    // they arrive. This is also the case where `consume` moves nothing, because
    // the reader drains everything readable each time.
    var stream: Reassembler(.{ .capacity = 8, .spans_max = 4 }) = .{};
    var written: u64 = 0;
    var seen: [64]u8 = undefined;
    var seen_len: usize = 0;

    while (written < 64) {
        const chunk = "01234567";
        const take = @min(@as(u64, 4), 64 - written);
        try stream.push(written, chunk[0..@intCast(take)]);
        written += take;
        const ready = stream.readable();
        @memcpy(seen[seen_len..][0..ready.len], ready);
        seen_len += ready.len;
        stream.consume(ready.len);
    }
    try testing.expectEqual(@as(usize, 64), seen_len);
    try testing.expectEqual(@as(u64, 64), stream.readOffset());
    try testing.expectEqualStrings("0123", seen[0..4]);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# A receiver SHOULD treat receipt of data at or beyond the final size as
//# an error of type FINAL_SIZE_ERROR, even after a stream is closed.
//= type=test
test "a final size below what was already consumed is refused" {
    // Section 4.5: data at or beyond the final size is an error "even after a
    // stream is closed". Once everything is drained there are no spans left, so
    // the check that looked only at spans was skipped entirely and a peer could
    // claim a final size below octets it had already delivered — leaving
    // `isComplete` true for a stream that never was, and every honest
    // retransmission rejected afterwards.
    var stream: Small = .{};
    try stream.push(0, "abcdef");
    stream.consume(6);
    try testing.expectEqual(@as(u32, 0), stream.span_count);
    try testing.expectError(error.FinalSizeViolated, stream.finish(3));
    // The true size is still accepted.
    try stream.finish(6);
    try testing.expect(stream.isComplete());
}

test "consume clamps rather than trusting its caller" {
    // Only meaningful in the build that ships without assertions. With them on,
    // an over-reported count is a caller bug and the assertion is *supposed* to
    // fire — that is the contract. What this checks is the other half: that the
    // same call in the `-Dassertions=false` leg clamps instead of reaching an
    // illegal cast, an out-of-bounds read and an underflow.
    if (@import("../assert.zig").enabled) return error.SkipZigTest;

    var stream: Small = .{};
    try stream.push(0, "abc");
    stream.consume(99);
    try testing.expectEqual(@as(u64, 3), stream.readOffset());
    try testing.expectEqualStrings("", stream.readable());
    // And on an empty reassembler, where the old code indexed span_count - 1.
    var empty: Small = .{};
    empty.consume(5);
    try testing.expectEqual(@as(u64, 0), empty.readOffset());
}

test "an offset past the encoding's range is refused, not wrapped" {
    var stream: Small = .{};
    try testing.expectError(error.BeyondWindow, stream.push(varint.max, "x"));
    try testing.expectError(error.BeyondWindow, stream.push(varint.max - 1, "abc"));
}
