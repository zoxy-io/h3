//! RFC 9000 section 2.1: what a stream identifier's low two bits mean.
//!
//! A stream identifier is a variable-length integer whose low bit says who
//! opened the stream and whose next bit says whether it is bidirectional. That
//! is the whole of the addressing scheme, and it is why the *count* of streams
//! of a kind tops out at 2^60 rather than 2^62 (section 19.11).
//!
//! HTTP/3 rests on this directly: RFC 9114 section 6.1 puts requests on
//! client-initiated bidirectional streams and the control, push, and two QPACK
//! streams on unidirectional ones, so "which kind is this?" is asked on every
//! new stream.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const varint = @import("../varint.zig");

const Side = @import("crypto.zig").Side;

/// Section 2.1's four kinds, in the encoding the low two bits use.
pub const Kind = enum(u2) {
    client_bidirectional = 0x0,
    server_bidirectional = 0x1,
    client_unidirectional = 0x2,
    server_unidirectional = 0x3,

    pub fn initiator(kind: Kind) Side {
        return switch (kind) {
            .client_bidirectional, .client_unidirectional => .client,
            .server_bidirectional, .server_unidirectional => .server,
        };
    }

    pub fn bidirectional(kind: Kind) bool {
        return switch (kind) {
            .client_bidirectional, .server_bidirectional => true,
            .client_unidirectional, .server_unidirectional => false,
        };
    }
};

/// The largest number of streams of one kind. Section 19.11: a limit above this
/// is a `FRAME_ENCODING_ERROR`, because the identifier it implies would not fit
/// a variable-length integer.
pub const count_max: u64 = 1 << 60;

comptime {
    assert(count_max * 4 == varint.max + 1);
}

pub fn kindOf(id: u64) Kind {
    assert(id <= varint.max);
    return @enumFromInt(@as(u2, @truncate(id)));
}

/// The position of this stream among those of its kind, counting from zero.
/// This is what a `MAX_STREAMS` limit is measured in — not the identifier —
/// and conflating the two overshoots the limit by a factor of four.
pub fn index(id: u64) u64 {
    assert(id <= varint.max);
    return id >> 2;
}

/// The identifier of the `position`-th stream of `stream_kind`.
pub fn make(stream_kind: Kind, position: u64) u64 {
    assert(position < count_max);
    const id = (position << 2) | @intFromEnum(stream_kind);
    assert(id <= varint.max);
    assert(index(id) == position);
    assert(kindOf(id) == stream_kind);
    return id;
}

/// True when `side` is allowed to send on this stream: either it opened it, or
/// the stream is bidirectional.
pub fn sendable(id: u64, side: Side) bool {
    const stream_kind = kindOf(id);
    return stream_kind.bidirectional() or stream_kind.initiator() == side;
}

const testing = std.testing;

test "the low two bits are the whole addressing scheme" {
    try testing.expectEqual(Kind.client_bidirectional, kindOf(0));
    try testing.expectEqual(Kind.server_bidirectional, kindOf(1));
    try testing.expectEqual(Kind.client_unidirectional, kindOf(2));
    try testing.expectEqual(Kind.server_unidirectional, kindOf(3));
    // RFC 9114 section 6.1: the first request of a connection is stream 0, and
    // the second is stream 4 — not stream 1.
    try testing.expectEqual(@as(u64, 0), make(.client_bidirectional, 0));
    try testing.expectEqual(@as(u64, 4), make(.client_bidirectional, 1));
    try testing.expectEqual(@as(u64, 1), index(4));
}

test "an index is not an identifier" {
    // The distinction MAX_STREAMS is counted in. A limit of 100 permits
    // identifiers up to 396, and reading it as an identifier limit would allow
    // a quarter of the streams the peer offered.
    try testing.expectEqual(@as(u64, 396), make(.client_bidirectional, 99));
    try testing.expectEqual(@as(u64, 99), index(396));
}

test "who may send on a stream" {
    try testing.expect(sendable(make(.client_unidirectional, 0), .client));
    try testing.expect(!sendable(make(.client_unidirectional, 0), .server));
    try testing.expect(sendable(make(.client_bidirectional, 0), .server));
    try testing.expect(sendable(make(.server_unidirectional, 0), .server));
}

test "every kind round-trips through make and kindOf" {
    for ([_]Kind{ .client_bidirectional, .server_bidirectional, .client_unidirectional, .server_unidirectional }) |stream_kind| {
        var position: u64 = 0;
        while (position < 8) : (position += 1) {
            const id = make(stream_kind, position);
            try testing.expectEqual(stream_kind, kindOf(id));
            try testing.expectEqual(position, index(id));
        }
    }
}
