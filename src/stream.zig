//! RFC 9114 section 6.2: what the first octets of a unidirectional stream mean.
//!
//! HTTP/3 has no connection-level framing. Everything that is not a request
//! lives on its own unidirectional QUIC stream, and the only way to tell those
//! streams apart is a variable-length integer at the front of each — sent once,
//! before anything else, and never repeated. That single integer decides
//! whether the octets after it are control frames, a QPACK encoder's
//! instructions, or a server push.
//!
//! ## Why the type can arrive one octet at a time
//!
//! The type is a variable-length integer on a stream, so a peer may send its
//! first octet in one QUIC packet and the rest in another. `parse` therefore
//! answers `Incomplete` rather than an error, and the caller retries when more
//! arrives. A parser that treated a partial type as malformed would kill
//! conforming connections under packet loss, which is the failure mode a load
//! generator would find and a laptop test never would.
//!
//! ## An unknown type is abandoned, not refused
//!
//! Section 6.2 requires an endpoint to either stop reading an unknown stream
//! type or discard its contents, and section 6.2.3 reserves the same
//! `0x1f * N + 0x21` family the frame types use so that this path is exercised.
//! Neither is a connection error. What *is* a connection error is a second
//! control stream, or a control stream that closes — `H3_STREAM_CREATION_ERROR`
//! and `H3_CLOSED_CRITICAL_STREAM` — and both are the consumer's to detect,
//! because they are facts about a connection rather than about a stream.

const std = @import("std");

const assert = @import("assert.zig").assert;
const varint = @import("varint.zig");

/// RFC 9114 section 11.2.4's stream type registry, plus RFC 9204 section 4.2's
/// two QPACK streams.
pub const Type = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,

    pub fn known(stream_type: Type) bool {
        return switch (stream_type) {
            .control, .push, .qpack_encoder, .qpack_decoder => true,
            _ => false,
        };
    }

    /// Section 6.2.3: `0x1f * N + 0x21`.
    pub fn isReserved(stream_type: Type) bool {
        const value = @intFromEnum(stream_type);
        if (value < 0x21) return false;
        return (value - 0x21) % 0x1f == 0;
    }

    /// Sections 6.2.1 and 6.2.2, and RFC 9204 section 4.2: exactly one of each
    /// of these may exist per direction, and closing one is
    /// `H3_CLOSED_CRITICAL_STREAM`. A second is `H3_STREAM_CREATION_ERROR`.
    pub fn critical(stream_type: Type) bool {
        return switch (stream_type) {
            .control, .qpack_encoder, .qpack_decoder => true,
            .push => false,
            _ => false,
        };
    }
};

pub const ParseError = error{
    /// The type's octets have not all arrived. Ordinary on a stream.
    Incomplete,
    /// A type encoded longer than it needs. Stricter than section 6.2 requires,
    /// for the reason `frame.zig` gives about a `switch` with four ways past it.
    NotMinimal,
};

pub const Parsed = struct {
    stream_type: Type,
    /// Octets the type occupied. Everything after them belongs to the stream's
    /// own format.
    octets: u8,
};

pub fn parse(source: []const u8) ParseError!Parsed {
    const decoded = varint.decodeMinimal(source) catch |err| return switch (err) {
        error.Incomplete => error.Incomplete,
        error.NotMinimal => error.NotMinimal,
    };
    assert(decoded.octets >= 1);
    assert(decoded.octets <= varint.octets_max);
    return .{ .stream_type = @enumFromInt(decoded.value), .octets = decoded.octets };
}

pub const WriteError = error{
    /// `target` cannot hold the type.
    OutputTooLong,
};

pub fn write(target: []u8, stream_type: Type) WriteError!u8 {
    return varint.encode(target, @intFromEnum(stream_type)) catch |err| switch (err) {
        error.OutputTooLong => error.OutputTooLong,
        // A `Type` is a `u64` and the enum's own values are all far below the
        // 62-bit ceiling, but a caller can build one from any integer. Mapping
        // it here rather than asserting keeps a caller-supplied value from
        // becoming a panic.
        error.ValueTooLarge => error.OutputTooLong,
    };
}

const testing = std.testing;

test "the four stream types RFC 9114 and RFC 9204 define" {
    try testing.expectEqual(Type.control, (try parse(&.{0x00})).stream_type);
    try testing.expectEqual(Type.push, (try parse(&.{0x01})).stream_type);
    try testing.expectEqual(Type.qpack_encoder, (try parse(&.{0x02})).stream_type);
    try testing.expectEqual(Type.qpack_decoder, (try parse(&.{0x03})).stream_type);
}

test "a type split across packets is incomplete, not malformed" {
    try testing.expectError(error.Incomplete, parse(&.{}));
    try testing.expectError(error.Incomplete, parse(&.{0x40}));
    // And the same octets, once the rest arrives, are a type. 0x005f is
    // `0x1f * 2 + 0x21` = 95, which genuinely needs two octets — a reserved
    // value below 64 encoded in two would be `NotMinimal` instead.
    const parsed = try parse(&.{ 0x40, 0x5f });
    try testing.expect(parsed.stream_type.isReserved());
    try testing.expectEqual(@as(u8, 2), parsed.octets);
}

test "the reserved family is unknown but not an error" {
    var n: u64 = 0;
    while (n < 8) : (n += 1) {
        const stream_type: Type = @enumFromInt(0x1f * n + 0x21);
        try testing.expect(stream_type.isReserved());
        try testing.expect(!stream_type.known());
        try testing.expect(!stream_type.critical());
    }
}

test "the critical streams are the ones that may exist exactly once" {
    try testing.expect(Type.control.critical());
    try testing.expect(Type.qpack_encoder.critical());
    try testing.expect(Type.qpack_decoder.critical());
    // A push stream is per-push, so there is nothing singular about it.
    try testing.expect(!Type.push.critical());
}

test "a written type parses back" {
    var target: [8]u8 = @splat(0);
    for ([_]Type{ .control, .push, .qpack_encoder, .qpack_decoder }) |stream_type| {
        const octets = try write(&target, stream_type);
        const parsed = try parse(target[0..octets]);
        try testing.expectEqual(stream_type, parsed.stream_type);
        try testing.expectEqual(octets, parsed.octets);
    }
}

test "a non-minimal type is refused" {
    // 0x4000 decodes to 0, which is the control stream, in two octets. A second
    // spelling of the control stream is a second control stream to anything
    // that counts them.
    try testing.expectError(error.NotMinimal, parse(&.{ 0x40, 0x00 }));
}
