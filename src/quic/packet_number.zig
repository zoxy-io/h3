//! RFC 9000 section 17.1 and appendix A: packet number encoding.
//!
//! A packet number is a 62-bit counter, and sending 62 bits of it on every
//! packet would be absurd. What travels instead is the low 1-4 octets, and the
//! receiver reconstructs the rest from the largest number it has already
//! processed *in the same packet number space*. The encoding is therefore
//! ambiguous by construction, and stays unambiguous only while the sender obeys
//! section 17.1's rule: encode enough octets to cover twice the range of
//! outstanding packets.
//!
//! ## Why this is more delicate than it looks
//!
//! Three things ride on getting it right, and none of them fail loudly.
//!
//! 1. **The number is the AEAD nonce.** Section 19 of RFC 9001 builds the
//!    nonce by XORing the reconstructed number into the write IV. A number
//!    reconstructed one window off decrypts to garbage, which looks exactly
//!    like a corrupted packet.
//! 2. **The number is authenticated, not encrypted.** It is part of the
//!    associated data, so a receiver cannot recover from a wrong guess by
//!    trying the next one — the tag check fails and the packet is discarded.
//!    That is the intended behaviour (section 12.3 of RFC 9000), and it means
//!    an off-by-one here presents as unexplained loss.
//! 3. **The spaces are separate.** Initial, Handshake and application data each
//!    have their own counter starting at zero, and mixing them reconstructs
//!    against the wrong `largest_acked`. `Space` exists so a caller cannot pass
//!    "the largest packet number" without saying which one.
//!
//! Both functions here are transcriptions of the pseudocode in appendix A.2 and
//! A.3, kept in that shape on purpose: this is a place to be boring.

const std = @import("std");

const assert = @import("../assert.zig").assert;

/// Section 17.1: a packet number is at most 62 bits, so that it fits the
/// variable-length integer encoding used for it in ACK frames.
pub const max: u64 = (1 << 62) - 1;

/// The 2-bit length field in a protected header carries 1-4 octets.
pub const octets_max: u8 = 4;
pub const octets_min: u8 = 1;

comptime {
    assert(octets_max == 4);
    assert(octets_min == 1);
    assert(max == (1 << 62) - 1);
}

/// RFC 9000 section 12.3: the three packet number spaces.
///
/// A separate type rather than a `u2`, because every function that reconstructs
/// a number needs the largest one seen *in that space*, and a bare integer
/// argument is how the Initial space's counter ends up reconstructing an
/// application packet.
pub const Space = enum(u2) {
    initial,
    handshake,
    application,

    /// The number of spaces, for a caller sizing a per-space array. Named here
    /// so the array and the enum cannot drift.
    pub const count: usize = 3;
};

comptime {
    assert(Space.count == @typeInfo(Space).@"enum".fields.len);
}

/// Appendix A.2: how many octets `full` needs, given the largest number the
/// peer has acknowledged in this space.
///
/// `largest_acked` is null before anything in the space has been acknowledged,
/// which section 17.1 handles by requiring the full range to be covered — the
/// appendix writes that as a range of `full + 1`.
pub fn encodedLength(full: u64, largest_acked: ?u64) u8 {
    assert(full <= max);
    if (largest_acked) |acked| assert(acked <= full);

    // The number of packets that could be in flight, doubled: section 17.1
    // requires the encoding to be unambiguous across twice the outstanding
    // range, because that is the window a reordered acknowledgement can move
    // `largest_acked` within.
    const range: u64 = if (largest_acked) |acked| (full - acked) * 2 else (full + 1) * 2;

    // A `u64` is compared against, rather than the appendix's arbitrary
    // precision, so the boundaries are stated as constants a reader can check.
    if (range < (1 << 8)) return 1;
    if (range < (1 << 16)) return 2;
    if (range < (1 << 24)) return 3;
    // Four octets is the ceiling the wire format offers. Section 17.1 does not
    // define what happens when even that is ambiguous, because it cannot be:
    // reaching it needs 2^31 packets outstanding, which no flow control window
    // this package will accept can reach. The assertion says so.
    assert(range < (@as(u64, 1) << 33));
    return 4;
}

/// Appendix A.3: reconstruct the full packet number.
///
/// `largest` is the largest number *successfully processed* in this space —
/// which is not the same as the largest acknowledged, and the difference is the
/// bug this parameter name exists to prevent. `truncated` is the value read out
/// of the header, `octets` its width.
pub fn decode(largest: ?u64, truncated: u32, octets: u8) u64 {
    assert(octets >= octets_min);
    assert(octets <= octets_max);

    const bits: u6 = @intCast(octets * 8);
    assert(bits <= 32);
    // The window the truncated value ranges over, and the candidate that sits
    // in the window containing `expected`.
    const window: u64 = @as(u64, 1) << bits;
    assert(truncated < window);

    // Before anything has been processed the expected number is zero, which is
    // the appendix's `expected_pn = largest_pn + 1` with `largest_pn = -1`.
    const expected: u64 = if (largest) |value| value + 1 else 0;
    const half_window: u64 = window / 2;
    assert(half_window >= 1 << 7);

    const candidate: u64 = (expected & ~(window - 1)) | truncated;

    // The appendix picks the candidate nearest `expected`, which for the two
    // neighbours either side is a pair of range checks rather than a subtraction
    // that could underflow. The upper guard is `max`, not overflow: section 17.1
    // caps a packet number at 62 bits, so a candidate above that is a peer
    // sending a number this connection can never have reached.
    if (candidate + half_window <= expected and candidate + window <= max) {
        return candidate + window;
    }
    if (candidate > expected + half_window and candidate >= window) {
        return candidate - window;
    }
    assert(candidate <= max);
    return candidate;
}

/// Write the low `octets` octets of `full`, big-endian, into `target`.
///
/// The caller has already decided `octets` — normally with `encodedLength` —
/// because the same number is written into the header's length bits, and
/// deriving it twice is how the two disagree.
pub fn encode(target: []u8, full: u64, octets: u8) void {
    assert(octets >= octets_min);
    assert(octets <= octets_max);
    assert(target.len == octets);
    assert(full <= max);

    var index: u8 = octets;
    var remaining = full;
    // Bounded by `octets`, at most four.
    while (index > 0) {
        index -= 1;
        target[index] = @truncate(remaining);
        remaining >>= 8;
    }
    assert(index == 0);
}

/// Read `octets` big-endian octets as a truncated packet number.
pub fn read(source: []const u8) u32 {
    assert(source.len >= octets_min);
    assert(source.len <= octets_max);
    var value: u32 = 0;
    for (source) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

test "RFC 9000 appendix A.3: the worked example" {
    // largest processed 0xa82f30ea, two octets on the wire reading 0x9b32.
    try std.testing.expectEqual(@as(u64, 0xa82f_9b32), decode(0xa82f_30ea, 0x9b32, 2));
}

test "RFC 9000 appendix A.2: the length covers twice the outstanding range" {
    // The appendix's own example: 0xac5c02 with 0xabe8b3 acknowledged needs two
    // octets, and one more outstanding packet tips it to three.
    try std.testing.expectEqual(@as(u8, 2), encodedLength(0xac5c02, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 3), encodedLength(0xace8fe, 0xabe8b3));
}

test "before the first acknowledgement the whole number is covered" {
    try std.testing.expectEqual(@as(u8, 1), encodedLength(0, null));
    // The boundary: the range covered is `(full + 1) * 2`, so one octet lasts
    // until 126 rather than until 127, which is exactly the kind of off-by-one
    // this test exists to pin.
    try std.testing.expectEqual(@as(u8, 1), encodedLength(126, null));
    try std.testing.expectEqual(@as(u8, 2), encodedLength(127, null));
    // And the first packet of a connection reconstructs from nothing at all.
    try std.testing.expectEqual(@as(u64, 0), decode(null, 0, 1));
    try std.testing.expectEqual(@as(u64, 7), decode(null, 7, 1));
}

test "encode and decode agree across a window boundary" {
    // The property that matters: for any number, encoding it at the length
    // section 17.1 requires and reconstructing it against the largest processed
    // must give the number back. Walked across a 256-boundary, where an
    // off-by-one in the window arithmetic shows up.
    var largest: u64 = 250;
    var full: u64 = 251;
    while (full < 520) : (full += 1) {
        const octets = encodedLength(full, largest);
        var target: [octets_max]u8 = undefined;
        encode(target[0..octets], full, octets);
        const truncated = read(target[0..octets]);
        try std.testing.expectEqual(full, decode(largest, truncated, octets));
        largest = full;
    }
}

test "a candidate above the window resolves downward" {
    // `expected` just past a boundary, with a truncated value that belongs to
    // the window below it.
    try std.testing.expectEqual(@as(u64, 0x00ff), decode(0x0100, 0xff, 1));
    // And one that belongs to the window above.
    try std.testing.expectEqual(@as(u64, 0x0201), decode(0x0180, 0x01, 1));
}

test "reconstruction never exceeds the 62-bit ceiling" {
    // A peer near the top of the space cannot make us produce a number the
    // format has no room for; that would be a nonce this connection can never
    // legitimately reach.
    const near_max = max - 4;
    const decoded = decode(near_max, 0xff, 1);
    try std.testing.expect(decoded <= max);
}
