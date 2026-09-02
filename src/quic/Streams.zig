//! RFC 9000 sections 2, 3 and 4: streams, their states, and flow control.
//!
//! A bounded set of streams, each with a receive half built on `Reassembler`
//! and a send half that buffers until acknowledged, plus the two levels of flow
//! control that decide how much a peer may send.
//!
//! ## Two levels, and the second one is the reason the first is not enough
//!
//! Section 4.1 gives every stream a limit and the connection a limit over all of
//! them. Only the second bounds memory: without it a peer opens as many streams
//! as it is allowed and fills each one's window, so the memory a connection can
//! be made to hold is the per-stream window times the stream limit. With it, the
//! connection window is the answer regardless of how the peer divides it.
//!
//! Both are enforced here rather than advertised and hoped for. A peer that
//! exceeds either has committed a `FLOW_CONTROL_ERROR`, and this refuses the
//! data instead of growing to fit it.
//!
//! ## A closed stream's accounting does not go away
//!
//! Section 4.1 counts the connection's flow control against the *highest offset
//! received* on every stream, and a stream that is reset or finished keeps
//! counting. Forgetting it would let a peer open a stream, fill its window,
//! reset it, and open another — consuming the connection window over and over
//! while never appearing to hold anything. `received_total` therefore only ever
//! rises, and it is credit consumed rather than memory held.
//!
//! ## Sized at compile time
//!
//! `Streams(config)` produces a type whose every buffer is a fixed array. The
//! peer's `initial_max_streams` and `initial_max_stream_data` are checked
//! *against* these numbers and never used as them — a limit that is not
//! comptime is a limit a peer can choose.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const error_code = @import("error_code.zig");
const stream_id = @import("stream_id.zig");
const varint = @import("../varint.zig");

const Reassembler = @import("Reassembler.zig").Reassembler;
const Side = @import("crypto.zig").Side;

/// Section 3.2: what has happened to a stream's receive half.
pub const ReceiveState = enum {
    /// Data is arriving.
    receiving,
    /// A FIN named the final size; earlier data may still be missing.
    size_known,
    /// Everything up to the final size has been read by the application.
    data_read,
    /// The peer abandoned it with RESET_STREAM.
    reset,
};

/// Section 3.1: what has happened to a stream's send half.
pub const SendState = enum {
    /// Accepting writes.
    sending,
    /// A FIN was queued; no more writes are accepted.
    data_sent,
    /// This endpoint abandoned it with RESET_STREAM.
    reset,
};

pub const Config = struct {
    /// Concurrent streams tracked. A peer's `initial_max_streams` is checked
    /// against this, never used as it.
    streams_max: u32 = 64,
    /// The receive window offered on each stream.
    receive_octets: u32 = 64 * 1024,
    /// Bytes buffered on each stream's send half. They stay until acknowledged,
    /// because they are what a retransmission is rebuilt from.
    send_octets: u32 = 16 * 1024,
    /// The connection's own receive window, over all streams at once. This is
    /// the number that actually bounds memory; see the module comment.
    connection_receive_octets: u64 = 1 << 20,
};

pub fn Streams(comptime config: Config) type {
    comptime {
        assert(config.streams_max >= 1);
        assert(config.receive_octets >= 1);
        assert(config.send_octets >= 1);
        // The connection window has to be able to hold at least one stream's
        // worth, or a single stream could never fill its own.
        assert(config.connection_receive_octets >= config.receive_octets);
        assert(config.streams_max <= stream_id.count_max);
    }

    const Receive = Reassembler(.{ .capacity = config.receive_octets, .spans_max = 8 });

    return struct {
        const Self = @This();

        pub const streams_max: u32 = config.streams_max;
        pub const receive_octets: u32 = config.receive_octets;
        pub const connection_receive_octets: u64 = config.connection_receive_octets;

        pub const Stream = struct {
            id: u64,
            receive_state: ReceiveState = .receiving,
            send_state: SendState = .sending,

            received: Receive = .{},
            /// The highest offset seen on this stream, which is what section
            /// 4.1 counts against both limits — not what has arrived in order,
            /// and not what has been read.
            received_highest: u64 = 0,
            /// Octets the application has taken, which is what the advertised
            /// limit is measured forward from.
            consumed: u64 = 0,

            /// Bytes waiting to go out, and how far they have been framed. The
            /// same arrangement the CRYPTO stream uses, for the same reason:
            /// what a retransmission needs is held here, and what decides to
            /// send it is RFC 9002.
            send: [config.send_octets]u8 = @splat(0),
            send_len: u32 = 0,
            framed: u32 = 0,
            send_offset: u64 = 0,
            send_fin: bool = false,
            /// The peer's `MAX_STREAM_DATA` for this stream.
            send_limit: u64 = 0,

            /// The error code a RESET_STREAM carried, in either direction.
            reset_code: u64 = 0,
            /// The `MAX_STREAM_DATA` last advertised, so a new one goes out
            /// only when the window has moved enough to be worth a frame.
            max_data_sent: u64 = 0,

            /// Bytes readable in order.
            pub fn readable(self: *const Stream) []const u8 {
                return self.received.readable();
            }

            /// Whether everything the peer will ever send has been read.
            pub fn isComplete(self: *const Stream) bool {
                return self.receive_state == .data_read;
            }

            /// Section 4.1: the limit to advertise, measured forward from what
            /// the application has taken rather than from what has arrived.
            /// Advertising from arrival would let a peer that sends faster than
            /// we read push the window ahead of the buffer.
            pub fn receiveLimit(self: *const Stream) u64 {
                return self.consumed + config.receive_octets;
            }

            /// Whether this endpoint may still write to it.
            pub fn writable(self: *const Stream) bool {
                return self.send_state == .sending;
            }
        };

        streams: [streams_max]Stream = undefined,
        count: u32 = 0,

        /// Section 4.1's connection-level accounting: octets of *credit* the
        /// peer has consumed across every stream that ever existed, and octets
        /// the application has taken.
        received_total: u64 = 0,
        consumed_total: u64 = 0,
        /// The peer's `MAX_DATA` for this connection.
        send_limit: u64 = 0,
        /// Octets this endpoint has queued across all streams, against that.
        sent_total: u64 = 0,

        pub const Error = error{
            /// More streams than `streams_max`. Section 4.6's
            /// `STREAM_LIMIT_ERROR` when the peer opened it, and a caller's own
            /// problem when this endpoint did.
            TooManyStreams,
            /// Data past a stream's limit or the connection's.
            /// `FLOW_CONTROL_ERROR`.
            FlowControl,
            /// Section 4.5: data past a final size, a second and different
            /// final size, or a final size below what has already arrived.
            /// `FINAL_SIZE_ERROR`.
            FinalSize,
            /// Section 2.2's rule that data at an offset never changes, or a
            /// write to a stream that cannot take one. `PROTOCOL_VIOLATION`.
            Protocol,
            /// The stream is not open.
            NotFound,
        };

        pub fn find(self: *Self, id: u64) ?*Stream {
            for (self.streams[0..self.count]) |*stream| {
                if (stream.id == id) return stream;
            }
            return null;
        }

        /// Open a stream, or return the one already open.
        pub fn open(self: *Self, id: u64) Error!*Stream {
            assert(id <= varint.max);
            if (self.find(id)) |stream| return stream;
            if (self.count == streams_max) return error.TooManyStreams;
            self.streams[self.count] = .{ .id = id };
            self.count += 1;
            return &self.streams[self.count - 1];
        }

        /// Take a STREAM frame.
        pub fn receive(self: *Self, id: u64, offset: u64, data: []const u8, fin: bool) Error!void {
            const end = offset + data.len;
            if (end > varint.max) return error.FinalSize;

            const stream = try self.open(id);
            if (stream.receive_state == .reset) return; // Section 3.2: discard.

            try self.admit(stream, end);
            stream.received.push(offset, data) catch |err| return switch (err) {
                error.BeyondWindow, error.TooFragmented => error.FlowControl,
                error.Inconsistent => error.Protocol,
                error.FinalSizeViolated => error.FinalSize,
            };
            if (fin) {
                stream.received.finish(end) catch return error.FinalSize;
                stream.receive_state = .size_known;
            }
            self.settle(stream);
        }

        /// Section 4.1: check both limits, and charge the connection for what
        /// this stream newly consumed.
        ///
        /// The charge is the *delta* of the stream's highest offset, so a
        /// retransmission of data already counted costs nothing and a peer
        /// cannot consume the connection window twice with the same octets.
        fn admit(self: *Self, stream: *Stream, end: u64) Error!void {
            if (end <= stream.received_highest) return;
            if (end > stream.receiveLimit()) return error.FlowControl;

            const charge = end - stream.received_highest;
            if (self.received_total + charge > self.receiveLimit()) return error.FlowControl;
            self.received_total += charge;
            stream.received_highest = end;
        }

        /// Section 4.1: the connection's limit, measured forward from what the
        /// application has taken across all streams.
        pub fn receiveLimit(self: *const Self) u64 {
            return self.consumed_total + config.connection_receive_octets;
        }

        /// Release bytes the application has read.
        pub fn consume(self: *Self, id: u64, octets: usize) Error!void {
            const stream = self.find(id) orelse return error.NotFound;
            assert(octets <= stream.readable().len);
            stream.received.consume(octets);
            stream.consumed += octets;
            self.consumed_total += octets;
            self.settle(stream);
        }

        /// Move a stream to `data_read` once everything has arrived and been
        /// taken. Separate from `consume` because a zero-length FIN completes a
        /// stream without anything being read.
        fn settle(self: *Self, stream: *Stream) void {
            _ = self;
            if (stream.receive_state != .size_known) return;
            if (stream.received.isComplete() and stream.readable().len == 0) {
                stream.receive_state = .data_read;
            }
        }

        /// Section 19.4: the peer abandoned a stream.
        pub fn reset(self: *Self, id: u64, code: u64, final_size: u64) Error!void {
            const stream = try self.open(id);
            if (stream.receive_state == .reset) return;
            // Section 4.5: a reset names the final size, and it must agree with
            // everything already seen — otherwise a peer could retract data it
            // already charged to the connection's window.
            if (final_size < stream.received_highest) return error.FinalSize;
            try self.admit(stream, final_size);
            stream.receive_state = .reset;
            stream.reset_code = code;
        }

        /// Queue bytes for sending, returning how many were taken.
        ///
        /// A short write is ordinary: the buffer is finite and the peer's flow
        /// control limit is not ours to exceed. A caller loops, or waits for
        /// `MAX_STREAM_DATA`.
        pub fn write(self: *Self, id: u64, data: []const u8, fin: bool) Error!usize {
            const stream = try self.open(id);
            if (!stream.writable()) return error.Protocol;

            const room = @min(
                config.send_octets - stream.send_len,
                sendRoom(stream.send_limit, stream.send_offset + stream.send_len),
            );
            const connection_room = sendRoom(self.send_limit, self.sent_total);
            const take = @min(data.len, @min(room, connection_room));

            @memcpy(stream.send[stream.send_len..][0..take], data[0..take]);
            stream.send_len += @intCast(take);
            self.sent_total += take;
            if (fin and take == data.len) {
                stream.send_fin = true;
                stream.send_state = .data_sent;
            }
            return take;
        }

        fn sendRoom(limit: u64, at: u64) u64 {
            return if (limit > at) limit - at else 0;
        }

        /// Section 19.10 and 19.9: raise a peer's limits.
        pub fn setSendLimit(self: *Self, id: u64, limit: u64) Error!void {
            const stream = try self.open(id);
            // Limits only ever rise; a peer lowering one is ignored rather than
            // an error, which is what section 4.1 says to do.
            stream.send_limit = @max(stream.send_limit, limit);
        }

        pub fn setConnectionSendLimit(self: *Self, limit: u64) void {
            self.send_limit = @max(self.send_limit, limit);
        }

        /// Streams with data waiting to be framed.
        pub fn wantsSend(self: *const Self) bool {
            for (self.streams[0..self.count]) |*stream| {
                if (stream.framed < stream.send_len) return true;
                if (stream.send_fin and stream.framed == stream.send_len and stream.send_state != .reset) return true;
            }
            return false;
        }

        /// Undo the framing of a lost range, so it is sent again.
        pub fn rewind(self: *Self, id: u64, from: u32) void {
            const stream = self.find(id) orelse return;
            stream.framed = @min(stream.framed, from);
        }
    };
}

const testing = std.testing;

const Set = Streams(.{
    .streams_max = 4,
    .receive_octets = 64,
    .send_octets = 32,
    .connection_receive_octets = 128,
});

test "data arrives, is read, and the window moves forward with the reader" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", false);
    const stream = set.find(0).?;
    try testing.expectEqualStrings("hello", stream.readable());
    // Section 4.1: the limit is measured from what the application took, not
    // from what arrived — otherwise a peer that outruns the reader pushes the
    // window past the buffer.
    try testing.expectEqual(@as(u64, Set.receive_octets), stream.receiveLimit());

    try set.consume(0, 5);
    try testing.expectEqual(@as(u64, 5 + Set.receive_octets), stream.receiveLimit());
    try testing.expectEqual(@as(u64, 5), set.consumed_total);
}

test "a peer may not send past a stream's limit" {
    var set: Set = .{};
    const oversized: [Set.receive_octets + 1]u8 = @splat('x');
    try testing.expectError(error.FlowControl, set.receive(0, 0, &oversized, false));

    // Exactly to the edge is fine.
    const exact: [Set.receive_octets]u8 = @splat('x');
    try set.receive(0, 0, &exact, false);
    // And one octet past it, on a second frame, is not.
    try testing.expectError(error.FlowControl, set.receive(0, Set.receive_octets, "y", false));
}

test "the connection limit binds across streams, which is what bounds memory" {
    var set: Set = .{};
    // Two streams' worth fits the connection window; a third does not, even
    // though each is within its own stream limit. Without this a peer's memory
    // budget is the per-stream window times the stream count.
    const chunk: [Set.receive_octets]u8 = @splat('x');
    try set.receive(0, 0, &chunk, false);
    try set.receive(4, 0, &chunk, false);
    try testing.expectEqual(Set.connection_receive_octets, set.received_total);
    try testing.expectError(error.FlowControl, set.receive(8, 0, "z", false));

    // Reading frees connection credit, and the third stream fits.
    try set.consume(0, 32);
    try set.receive(8, 0, "z", false);
}

test "a retransmission does not consume the window twice" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
    // The same octets again: ordinary retransmission. Charging for them would
    // let a lossy path exhaust a connection's window without sending anything
    // new.
    try set.receive(0, 0, "hello", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
    // And an overlapping frame charges only for what is past the high mark.
    try set.receive(0, 3, "lo there", false);
    try testing.expectEqual(@as(u64, 11), set.received_total);
}

test "a reset stream keeps its accounting" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", false);
    try set.reset(0, 7, 5);
    try testing.expectEqual(ReceiveState.reset, set.find(0).?.receive_state);
    // Section 4.1: the credit stays consumed. Forgetting it would let a peer
    // fill a window, reset, and repeat — holding nothing and consuming
    // everything.
    try testing.expectEqual(@as(u64, 5), set.received_total);

    // Data after a reset is discarded rather than an error: it was in flight
    // when the reset was sent.
    try set.receive(0, 5, "more", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
}

test "a reset that retracts data already charged is refused" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", false);
    // Section 4.5: a final size below what has arrived contradicts the peer's
    // own earlier frames, and accepting it would give back window credit.
    try testing.expectError(error.FinalSize, set.reset(0, 0, 3));
    // A final size above it charges the difference, as section 4.5 requires.
    try set.reset(0, 0, 9);
    try testing.expectEqual(@as(u64, 9), set.received_total);
}

test "a FIN completes a stream once everything has been read" {
    var set: Set = .{};
    try set.receive(0, 0, "hel", false);
    try set.receive(0, 3, "lo", true);
    const stream = set.find(0).?;
    try testing.expectEqual(ReceiveState.size_known, stream.receive_state);
    try testing.expect(!stream.isComplete());

    try set.consume(0, 5);
    try testing.expect(stream.isComplete());
}

test "an empty FIN completes a stream with nothing to read" {
    var set: Set = .{};
    try set.receive(0, 0, "", true);
    try testing.expect(set.find(0).?.isComplete());
}

test "section 4.5: the final size may not move" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", true);
    try testing.expectError(error.FinalSize, set.receive(0, 5, "more", false));
    // A different final size on a second FIN.
    try testing.expectError(error.FinalSize, set.receive(0, 0, "hel", true));
}

test "section 2.2: data at an offset never changes" {
    var set: Set = .{};
    try set.receive(0, 0, "hello", false);
    try testing.expectError(error.Protocol, set.receive(0, 0, "HELLO", false));
}

test "writes are bounded by the peer's limits, in both levels" {
    var set: Set = .{};
    // No limits yet: the peer has offered nothing, so nothing may go out.
    try testing.expectEqual(@as(usize, 0), try set.write(0, "hello", false));

    try set.setSendLimit(0, 3);
    set.setConnectionSendLimit(1000);
    try testing.expectEqual(@as(usize, 3), try set.write(0, "hello", false));
}

test "the connection's send limit binds independently of a stream's" {
    // A fresh set, because a limit never falls — lowering the connection's to
    // observe it would be observing nothing.
    var set: Set = .{};
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(2);
    // The stream would take all five; the connection allows two.
    try testing.expectEqual(@as(usize, 2), try set.write(0, "hello", false));
    try testing.expectEqual(@as(u64, 2), set.sent_total);

    // Raising it lets the rest through.
    set.setConnectionSendLimit(1000);
    try testing.expectEqual(@as(usize, 3), try set.write(0, "llo", false));
}

test "a limit never falls" {
    var set: Set = .{};
    try set.setSendLimit(0, 100);
    try set.setSendLimit(0, 10);
    // Section 4.1: a smaller limit is ignored rather than an error. A reordered
    // MAX_STREAM_DATA is ordinary.
    try testing.expectEqual(@as(u64, 100), set.find(0).?.send_limit);

    set.setConnectionSendLimit(100);
    set.setConnectionSendLimit(10);
    try testing.expectEqual(@as(u64, 100), set.send_limit);
}

test "a FIN closes the send half to further writes" {
    var set: Set = .{};
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(1000);
    _ = try set.write(0, "hello", true);
    try testing.expectEqual(SendState.data_sent, set.find(0).?.send_state);
    try testing.expectError(error.Protocol, set.write(0, "more", false));
}

test "a partial write does not carry the FIN" {
    var set: Set = .{};
    try set.setSendLimit(0, 2);
    set.setConnectionSendLimit(1000);
    // Only two octets fit, so the stream is not finished — a FIN at the wrong
    // offset would tell the peer the stream ended early.
    try testing.expectEqual(@as(usize, 2), try set.write(0, "hello", true));
    try testing.expect(!set.find(0).?.send_fin);
    try testing.expectEqual(SendState.sending, set.find(0).?.send_state);
}

test "more streams than the bound is refused rather than grown into" {
    var set: Set = .{};
    for (0..Set.streams_max) |index| _ = try set.open(@as(u64, index) * 4);
    try testing.expectError(error.TooManyStreams, set.open(1000));
    // An already-open stream is found rather than opened again.
    const again = try set.open(0);
    try testing.expectEqual(@as(u64, 0), again.id);
}

test "rewinding re-frames a lost range" {
    var set: Set = .{};
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(1000);
    _ = try set.write(0, "hello", false);
    const stream = set.find(0).?;
    stream.framed = 5;
    try testing.expect(!set.wantsSend());

    set.rewind(0, 2);
    try testing.expectEqual(@as(u32, 2), stream.framed);
    try testing.expect(set.wantsSend());
}
