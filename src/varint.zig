//! RFC 9000 section 16: variable-length integers.
//!
//! The two most significant bits of the first octet say how long the encoding
//! is; the remaining 62 bits are the value, in network byte order.
//!
//!     +======+========+=============+=======================+
//!     | 2MSB | Length | Usable Bits | Range                 |
//!     +======+========+=============+=======================+
//!     | 00   | 1      | 6           | 0-63                  |
//!     | 01   | 2      | 14          | 0-16383               |
//!     | 10   | 4      | 30          | 0-1073741823          |
//!     | 11   | 8      | 62          | 0-4611686018427387903 |
//!     +------+--------+-------------+-----------------------+
//!
//! This is the primitive everything in the package is built out of: QUIC frame
//! types and their fields (RFC 9000 section 19), transport parameters (section
//! 18), HTTP/3 frame types and lengths (RFC 9114 section 7.1), and HTTP/3
//! settings identifiers. It is not QPACK's integer — RFC 9204 section 4.1.1
//! keeps HPACK's N-bit prefix encoding, which comes from zoxy-io/hpack and is
//! re-exported as `qpack.integer`.
//!
//! ## Non-minimal encodings are legal, and that is a trap
//!
//! Section 16 permits a value to be encoded in any length that can hold it:
//! `0x4025` and `0x25` both mean 37. An encoder may exploit that to reserve
//! space it will fill in later — this package does, when it writes an ACK
//! frame's length before knowing how many ranges fit — so a decoder that
//! insisted on minimality would reject conforming peers.
//!
//! Section 12.4 then carves out the one exception that matters: a *frame type*
//! encoded longer than necessary MAY be a `PROTOCOL_VIOLATION`. That is a
//! genuine attack surface, because it multiplies every frame type into four
//! spellings, and a switch that dispatches on the decoded value will happily
//! treat `0x4000` as PADDING. So the choice is made explicit at the call site:
//! `decode` accepts what section 16 accepts, `decodeMinimal` accepts only the
//! shortest spelling, and every frame-type read in this package uses the
//! second. A decoder with two answers for the same octets is a decoder with a
//! request-smuggling bug waiting for a name.

const std = @import("std");

const assert = @import("assert.zig").assert;

/// The largest value the encoding can carry: 62 usable bits.
pub const max: u64 = (1 << 62) - 1;

/// The longest encoding, and the shortest. Both are named because sizing a
/// buffer against "8" leaves the next reader to rediscover why.
pub const octets_max: u8 = 8;
pub const octets_min: u8 = 1;

comptime {
    assert(max == 4_611_686_018_427_387_903);
    assert(octets_max * 8 - 2 == 62);
    assert(octets_min == 1);
}

pub const DecodeError = error{
    /// The encoding continues past the end of the input.
    ///
    /// Whether that is malformed or merely early is the caller's to decide: a
    /// frame arriving inside a packet payload has all its octets already, so
    /// this is a protocol error there, while a stream reassembly buffer may
    /// simply not have the rest yet.
    Incomplete,
    /// The value is encoded in more octets than it needs. Only `decodeMinimal`
    /// returns this; see the note on section 12.4 above.
    NotMinimal,
};

pub const Decoded = struct {
    value: u64,
    /// Octets consumed. One of 1, 2, 4 or 8.
    octets: u8,
};

/// Decode the variable-length integer beginning at `source[0]`.
///
/// Accepts non-minimal encodings, which section 16 permits. Use
/// `decodeMinimal` where section 12.4's rule applies.
pub fn decode(source: []const u8) DecodeError!Decoded {
    if (source.len == 0) return error.Incomplete;

    const octets = octetsFor(source[0]);
    assert(octets == 1 or octets == 2 or octets == 4 or octets == 8);
    if (source.len < octets) return error.Incomplete;

    // The two length bits are not part of the value, so they are masked off the
    // first octet and the rest is a plain big-endian read.
    var value: u64 = source[0] & 0x3f;
    for (source[1..octets]) |byte| {
        value = (value << 8) | byte;
    }

    assert(value <= max);
    assert(value <= valueMaxFor(octets));
    return .{ .value = value, .octets = octets };
}

/// Decode, and reject an encoding longer than the value needs.
///
/// This is what reads a frame type (RFC 9000 section 12.4, RFC 9114 section
/// 7.1) and a transport parameter identifier: those are dispatched on, and a
/// type with four legal spellings is four ways past a `switch`.
pub fn decodeMinimal(source: []const u8) DecodeError!Decoded {
    const decoded = try decode(source);
    if (decoded.octets != encodedLength(decoded.value)) return error.NotMinimal;
    assert(decoded.octets == encodedLength(decoded.value));
    return decoded;
}

pub const EncodeError = error{
    /// `target` cannot hold the encoding.
    OutputTooLong,
    /// The value needs more than 62 bits. Not a wire-format condition — it is a
    /// caller that computed a length or an identifier the format cannot carry,
    /// and returning it rather than asserting is what keeps a peer-derived
    /// number from becoming a panic.
    ValueTooLarge,
};

/// Write `value` into `target` in the fewest octets that hold it, returning how
/// many that was.
///
/// Writes nothing on failure. A caller composing a frame out of several of
/// these would otherwise have to unwind a half-written field.
pub fn encode(target: []u8, value: u64) EncodeError!u8 {
    if (value > max) return error.ValueTooLarge;
    const octets = encodedLength(value);
    assert(octets <= octets_max);
    if (target.len < octets) return error.OutputTooLong;
    encodeAssumeCapacity(target[0..octets], value, octets);
    return octets;
}

/// Write `value` into exactly `octets` octets, whether or not it needs them.
///
/// The deliberate non-minimal encoding of section 16, for the one thing it is
/// for: reserving a length field before the length is known. An ACK frame's
/// range count and an HTTP/3 frame's payload length are both written before
/// their bodies are, and reserving eight octets and back-filling beats
/// serializing the body twice to find out how long it is.
pub fn encodeIn(target: []u8, value: u64, octets: u8) EncodeError!void {
    assert(octets == 1 or octets == 2 or octets == 4 or octets == 8);
    if (value > valueMaxFor(octets)) return error.ValueTooLarge;
    if (target.len < octets) return error.OutputTooLong;
    encodeAssumeCapacity(target[0..octets], value, octets);
}

/// The shared tail of `encode` and `encodeIn`, entered with every check made.
fn encodeAssumeCapacity(target: []u8, value: u64, octets: u8) void {
    assert(target.len == octets);
    assert(value <= valueMaxFor(octets));

    var remaining = value;
    var index: u8 = octets;
    // Bounded by `octets`, which is one of four constants.
    while (index > 0) {
        index -= 1;
        target[index] = @truncate(remaining);
        remaining >>= 8;
    }
    assert(remaining == 0);

    // The length bits sit above the value's own, which the range check above
    // guaranteed there is room for.
    target[0] |= lengthBitsFor(octets);
    assert(octetsFor(target[0]) == octets);
}

/// How many octets `value` needs. Answers 8 for a value the format cannot
/// carry, so a caller sizing a buffer never under-counts; `encode` is what
/// refuses it.
pub fn encodedLength(value: u64) u8 {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    return 8;
}

/// How many octets the encoding beginning with `first` occupies. Total, not
/// remaining: the octet carrying the length bits is one of them.
pub fn octetsFor(first: u8) u8 {
    return @as(u8, 1) << @intCast(first >> 6);
}

/// The largest value an `octets`-long encoding can carry.
pub fn valueMaxFor(octets: u8) u64 {
    assert(octets == 1 or octets == 2 or octets == 4 or octets == 8);
    const bits: u6 = @intCast(octets * 8 - 2);
    return (@as(u64, 1) << bits) - 1;
}

/// The two-bit length tag, positioned for the first octet.
fn lengthBitsFor(octets: u8) u8 {
    return switch (octets) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        else => unreachable, // Guarded by the callers' `assert` on the same four values, and by `octetsFor`, whose only outputs these are.
    };
}

comptime {
    // The table in the module comment, checked rather than trusted. Each row's
    // boundary is the first value that needs the next length up.
    assert(encodedLength(63) == 1);
    assert(encodedLength(64) == 2);
    assert(encodedLength(16_383) == 2);
    assert(encodedLength(16_384) == 4);
    assert(encodedLength(1_073_741_823) == 4);
    assert(encodedLength(1_073_741_824) == 8);
    assert(encodedLength(max) == 8);
    // And the two directions agree: a length's tag decodes back to the length.
    assert(octetsFor(lengthBitsFor(1)) == 1);
    assert(octetsFor(lengthBitsFor(2)) == 2);
    assert(octetsFor(lengthBitsFor(4)) == 4);
    assert(octetsFor(lengthBitsFor(8)) == 8);
    assert(valueMaxFor(8) == max);
}

test "RFC 9000 appendix A.1: the sample encodings" {
    // Transcribed from the appendix, which is the only reason to prefer these
    // four numbers to any others: they are what an interop partner tested with.
    const cases = [_]struct { wire: []const u8, value: u64, octets: u8 }{
        .{ .wire = &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, .value = 151_288_809_941_952_652, .octets = 8 },
        .{ .wire = &.{ 0x9d, 0x7f, 0x3e, 0x7d }, .value = 494_878_333, .octets = 4 },
        .{ .wire = &.{ 0x7b, 0xbd }, .value = 15_293, .octets = 2 },
        .{ .wire = &.{0x25}, .value = 37, .octets = 1 },
    };
    for (cases) |case| {
        const decoded = try decode(case.wire);
        try std.testing.expectEqual(case.value, decoded.value);
        try std.testing.expectEqual(case.octets, decoded.octets);

        var target: [octets_max]u8 = undefined;
        const written = try encode(&target, case.value);
        try std.testing.expectEqual(case.octets, written);
        try std.testing.expectEqualSlices(u8, case.wire, target[0..written]);
    }
}

test "RFC 9000 appendix A.1: 0x4025 is also 37" {
    // The appendix's fifth case, and the whole reason `decodeMinimal` exists.
    const decoded = try decode(&.{ 0x40, 0x25 });
    try std.testing.expectEqual(@as(u64, 37), decoded.value);
    try std.testing.expectEqual(@as(u8, 2), decoded.octets);
    try std.testing.expectError(error.NotMinimal, decodeMinimal(&.{ 0x40, 0x25 }));
    // The one-octet spelling of the same value is what a frame type must use.
    try std.testing.expectEqual(@as(u64, 37), (try decodeMinimal(&.{0x25})).value);
}

test "an encoding cut short is incomplete, not a short value" {
    try std.testing.expectError(error.Incomplete, decode(&.{}));
    try std.testing.expectError(error.Incomplete, decode(&.{0x40}));
    try std.testing.expectError(error.Incomplete, decode(&.{ 0x80, 0x00 }));
    try std.testing.expectError(error.Incomplete, decode(&.{ 0xc0, 0x00, 0x00, 0x00 }));
}

test "every boundary round-trips at the length it claims" {
    const boundaries = [_]u64{ 0, 1, 62, 63, 64, 16_382, 16_383, 16_384, 1_073_741_822, 1_073_741_823, 1_073_741_824, max - 1, max };
    for (boundaries) |value| {
        var target: [octets_max]u8 = undefined;
        const written = try encode(&target, value);
        const decoded = try decodeMinimal(target[0..written]);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(written, decoded.octets);
    }
}

test "a value past 62 bits is refused rather than truncated" {
    var target: [octets_max]u8 = undefined;
    try std.testing.expectError(error.ValueTooLarge, encode(&target, max + 1));
    try std.testing.expectError(error.ValueTooLarge, encode(&target, std.math.maxInt(u64)));
    // And a reservation too small for its value is refused the same way, which
    // is what stops a back-filled length from silently wrapping.
    try std.testing.expectError(error.ValueTooLarge, encodeIn(&target, 64, 1));
    try std.testing.expectError(error.ValueTooLarge, encodeIn(&target, 16_384, 2));
}

test "encode writes nothing when the target is too small" {
    var target: [1]u8 = .{0xaa};
    try std.testing.expectError(error.OutputTooLong, encode(&target, 64));
    try std.testing.expectEqual(@as(u8, 0xaa), target[0]);
}

test "a reserved length carries a value that did not need it" {
    // What an ACK frame's back-filled length looks like on the wire.
    var target: [octets_max]u8 = undefined;
    try encodeIn(&target, 37, 8);
    const decoded = try decode(&target);
    try std.testing.expectEqual(@as(u64, 37), decoded.value);
    try std.testing.expectEqual(@as(u8, 8), decoded.octets);
    try std.testing.expectError(error.NotMinimal, decodeMinimal(&target));
}
