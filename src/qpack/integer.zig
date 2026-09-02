//! RFC 9204 section 4.1.1: integers with an N-bit prefix.
//!
//! QPACK keeps HPACK's integer encoding (RFC 7541 section 5.1) rather than
//! adopting QUIC's variable-length one, and the reason is the reason this file
//! exists separately from `varint.zig`: a QPACK integer shares its first octet
//! with the type tag above it. A field line representation is one to four tag
//! bits followed by an index in the remaining bits, and a variable-length
//! integer has no room for a tag.
//!
//! So this package has two integer encodings, in two files, and every call site
//! has to know which layer it is on. QUIC frames and HTTP/3 frames use
//! `varint.zig`; anything inside a field section uses this one.
//!
//! ## The bound is this file's, not the RFC's
//!
//! Section 4.1.1 sets no limit on how many continuation octets an encoder may
//! send, and an unbounded run of octets with the high bit set is legal-looking
//! input a trusting decoder follows forever. Every QPACK integer — an index, a
//! string length, an insert count — flows through here, so the bound belongs at
//! the primitive rather than at each of a dozen call sites, one of which will
//! forget it.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const varint = @import("../varint.zig");

/// The most continuation octets a value may use.
///
/// Nine 7-bit groups carry 63 bits, one more than the 62 a QPACK value can
/// need: every length and index in HTTP/3 is ultimately bounded by a QUIC
/// stream offset, which is 62 bits. A tenth octet cannot describe a
/// representable value, so accepting one only buys an attacker a longer walk.
pub const continuation_octets_max: u32 = 9;

/// The widest prefix the representations use. A prefix is the low bits of an
/// octet whose high bits carry a type tag; the widest, seven, belongs to the
/// string lengths and to the encoder stream's capacity update.
pub const prefix_bits_max: u4 = 8;

/// The largest value this decodes. Shared with `varint.max` deliberately: a
/// QPACK integer that could exceed a QUIC varint would be an index into
/// something QUIC cannot address.
pub const value_max: u64 = varint.max;

comptime {
    assert(continuation_octets_max * 7 >= 62);
    assert(continuation_octets_max * 7 <= std.math.maxInt(u6));
    assert(prefix_bits_max >= 1);
    assert(value_max == varint.max);
}

pub const DecodeError = error{
    /// The encoding continues past the end of the input. On a QPACK stream this
    /// may simply be data that has not arrived; inside a field section, which
    /// arrives whole, it is malformed.
    Incomplete,
    /// More continuation octets than `continuation_octets_max`, or a value past
    /// `value_max`.
    TooLarge,
};

pub const Decoded = struct {
    value: u64,
    /// Octets consumed, including the prefix octet. Always at least one.
    octets: u32,
};

/// Decode the integer beginning at `source[0]`, whose prefix occupies the low
/// `prefix_bits` bits of that octet. Bits above the prefix are the caller's
/// type tag and are ignored here.
pub fn decode(source: []const u8, prefix_bits: u4) DecodeError!Decoded {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    if (source.len == 0) return error.Incomplete;

    const prefix_max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    const prefix: u64 = source[0] & prefix_max;
    if (prefix < prefix_max) {
        return .{ .value = prefix, .octets = 1 };
    }

    var value: u64 = prefix_max;
    var shift: u6 = 0;
    var continuation_octets: u32 = 0;
    while (continuation_octets < continuation_octets_max) {
        const index = continuation_octets + 1;
        if (index >= source.len) return error.Incomplete;
        const octet = source[index];
        continuation_octets += 1;

        // Overflow is checked before it happens rather than after: `value`
        // is already at its maximum width, so a wrap would lose the evidence
        // that anything went wrong.
        const addend = @as(u64, octet & 0x7f);
        const shifted = std.math.shlExact(u64, addend, shift) catch return error.TooLarge;
        value = std.math.add(u64, value, shifted) catch return error.TooLarge;

        if (octet & 0x80 == 0) {
            if (value > value_max) return error.TooLarge;
            const decoded: Decoded = .{ .value = value, .octets = continuation_octets + 1 };
            assert(decoded.octets <= continuation_octets_max + 1);
            return decoded;
        }
        shift += 7;
    }
    assert(continuation_octets == continuation_octets_max);
    return error.TooLarge;
}

pub const EncodeError = error{
    /// `target` cannot hold the encoding.
    OutputTooLong,
    /// The value is past `value_max`.
    ValueTooLarge,
};

/// Write `value` into `target` with a `prefix_bits`-bit prefix, keeping the tag
/// bits `tag` supplies above that prefix.
///
/// The caller passes the tag rather than setting `target[0]` first, because the
/// tag is what decides `prefix_bits` and splitting them across two steps
/// invites a pair that disagrees.
pub fn encode(target: []u8, value: u64, prefix_bits: u4, tag: u8) EncodeError!u32 {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    if (prefix_bits < prefix_bits_max) {
        // The tag must not reach into the prefix, or it would be read back as
        // part of the value.
        assert((tag & ((@as(u16, 1) << prefix_bits) - 1)) == 0);
    }
    if (value > value_max) return error.ValueTooLarge;

    // Checked once, up front, so this either writes the whole encoding or
    // touches nothing — a caller writing a length followed by a string composes
    // exactly the two, and one of them leaving a half-written prefix behind
    // would be a trap set for whoever writes that caller.
    const length = encodedLength(value, prefix_bits);
    if (length > target.len) return error.OutputTooLong;

    const prefix_max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < prefix_max) {
        target[0] = tag | @as(u8, @intCast(value));
        assert(length == 1);
        return 1;
    }

    target[0] = tag | @as(u8, @intCast(prefix_max));
    var remaining = value - prefix_max;
    var index: u32 = 1;
    while (remaining >= 0x80) {
        assert(index <= continuation_octets_max);
        target[index] = @as(u8, @truncate(remaining)) | 0x80;
        remaining >>= 7;
        index += 1;
    }
    target[index] = @intCast(remaining);
    index += 1;
    assert(index == length);
    return index;
}

/// Octets `value` needs with this prefix.
pub fn encodedLength(value: u64, prefix_bits: u4) u32 {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    const prefix_max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < prefix_max) return 1;

    var remaining = value - prefix_max;
    var octets: u32 = 2;
    while (remaining >= 0x80) : (octets += 1) {
        assert(octets <= continuation_octets_max + 1);
        remaining >>= 7;
    }
    assert(octets <= continuation_octets_max + 1);
    return octets;
}

const testing = std.testing;

test "RFC 7541 appendix C.1: the examples QPACK inherits" {
    // C.1.1: 10 with a five-bit prefix fits the prefix.
    try testing.expectEqual(@as(u64, 10), (try decode(&.{0x0a}, 5)).value);
    // C.1.2: 1337 with a five-bit prefix spills into two continuation octets.
    const spilled = try decode(&.{ 0x1f, 0x9a, 0x0a }, 5);
    try testing.expectEqual(@as(u64, 1337), spilled.value);
    try testing.expectEqual(@as(u32, 3), spilled.octets);
    // C.1.3: 42 with an eight-bit prefix, starting at an octet boundary.
    try testing.expectEqual(@as(u64, 42), (try decode(&.{0x2a}, 8)).value);
}

test "the tag bits above the prefix are ignored on the way in and kept on the way out" {
    // A 6-bit prefix under a `01` tag: the same value under two tags decodes
    // the same, and encoding puts the tag back.
    try testing.expectEqual(@as(u64, 5), (try decode(&.{0x45}, 6)).value);
    try testing.expectEqual(@as(u64, 5), (try decode(&.{0x05}, 6)).value);
    var target: [16]u8 = @splat(0);
    const written = try encode(&target, 5, 6, 0x40);
    try testing.expectEqual(@as(u32, 1), written);
    try testing.expectEqual(@as(u8, 0x45), target[0]);
}

test "every prefix width round-trips across the boundary its prefix sets" {
    var prefix_bits: u4 = 1;
    while (prefix_bits <= prefix_bits_max) : (prefix_bits += 1) {
        const prefix_max: u64 = (@as(u64, 1) << prefix_bits) - 1;
        const values = [_]u64{ 0, 1, prefix_max - 1, prefix_max, prefix_max + 1, 127, 128, 16_383, 16_384, value_max };
        for (values) |value| {
            var target: [16]u8 = @splat(0);
            const written = try encode(&target, value, prefix_bits, 0);
            try testing.expectEqual(written, encodedLength(value, prefix_bits));
            const decoded = try decode(target[0..written], prefix_bits);
            try testing.expectEqual(value, decoded.value);
            try testing.expectEqual(written, decoded.octets);
        }
        if (prefix_bits == prefix_bits_max) break;
    }
}

test "an unbounded run of continuation octets terminates" {
    // The attack this file's bound exists for: legal-looking octets that never
    // end. Without the bound a decoder walks until it runs out of input, and on
    // a stream it never does.
    const forever: [64]u8 = @splat(0xff);
    try testing.expectError(error.TooLarge, decode(&forever, 5));
}

test "an encoding cut short is incomplete" {
    try testing.expectError(error.Incomplete, decode(&.{}, 5));
    try testing.expectError(error.Incomplete, decode(&.{0x1f}, 5));
    try testing.expectError(error.Incomplete, decode(&.{ 0x1f, 0x9a }, 5));
}

test "a value past 62 bits is refused rather than truncated" {
    var target: [16]u8 = @splat(0);
    try testing.expectError(error.ValueTooLarge, encode(&target, value_max + 1, 5, 0));
    // And on the way in: 2^62 encoded with a five-bit prefix.
    var wide: [16]u8 = @splat(0);
    const written = try encode(&wide, value_max, 5, 0);
    wide[written - 1] += 1; // One past the ceiling.
    try testing.expectError(error.TooLarge, decode(wide[0..written], 5));
}

test "encode writes nothing when the target is too small" {
    var target: [1]u8 = .{0xaa};
    try testing.expectError(error.OutputTooLong, encode(&target, 1337, 5, 0));
    try testing.expectEqual(@as(u8, 0xaa), target[0]);
}
