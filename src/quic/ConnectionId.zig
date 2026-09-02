//! RFC 9000 section 5.1: a connection identifier.
//!
//! An opaque label a peer puts in the destination field of every packet it
//! sends us, so that the packet can be routed to a connection without depending
//! on the four-tuple. That indirection is the whole point — it is what lets a
//! connection survive a NAT rebinding or a change of network — and it is also
//! what makes the length field a wire-format hazard: a long header carries the
//! length, and a short header does not.
//!
//! ## The asymmetry that decides this type's shape
//!
//! In a long header both identifiers are length-prefixed, so a parser can read
//! them out of the packet alone (section 17.2). In a short header there is no
//! length: the destination identifier is however many octets *the receiver*
//! chose to issue, and a parser that does not already know that number cannot
//! find the packet number, let alone the payload (section 17.3).
//!
//! So parsing a short header takes the local identifier length as an argument,
//! and this package never guesses it. A stack that guessed would be one where a
//! peer picks the framing of our packets.
//!
//! ## The bound
//!
//! Section 17.2 caps an identifier at 20 octets, and versions after 1 may not
//! exceed it either — the field is 8 bits wide but values above 20 are a
//! `PROTOCOL_VIOLATION` rather than a longer identifier. Storage is therefore a
//! fixed 20-octet array, which is what keeps a connection identifier copyable,
//! comparable, and free of an allocator.

const std = @import("std");

const ConnectionId = @This();

const assert = @import("../assert.zig").assert;

/// Section 17.2: the longest identifier a QUIC version 1 endpoint may use, and
/// the reason the storage below is a fixed array.
pub const octets_max: u8 = 20;

/// Section 5.1.1: an endpoint that issues a zero-length identifier is saying it
/// will route by four-tuple alone. Legal, and a real deployment choice — but it
/// forfeits migration, so the two are worth being able to name apart.
pub const octets_min: u8 = 0;

comptime {
    assert(octets_max == 20);
    assert(octets_min == 0);
}

/// Fixed storage, of which the first `length` octets are the identifier. The
/// tail is not zeroed and must never be read: `bytes()` is the only way in.
storage: [octets_max]u8 = @splat(0),
length: u8 = 0,

pub const Error = error{
    /// More than `octets_max` octets. A connection error of type
    /// `PROTOCOL_VIOLATION` when it arrives from a peer.
    TooLong,
};

/// Copy `source` into a new identifier.
pub fn init(source: []const u8) Error!ConnectionId {
    if (source.len > octets_max) return error.TooLong;
    var id: ConnectionId = .{ .length = @intCast(source.len) };
    @memcpy(id.storage[0..source.len], source);
    assert(id.length <= octets_max);
    assert(std.mem.eql(u8, id.bytes(), source));
    return id;
}

/// The identifier's octets. Borrows from `self`, so a caller holding the slice
/// across a move of the struct is holding a dangling pointer — take a copy of
/// the `ConnectionId`, which is cheap and has no interior pointers.
pub fn bytes(self: *const ConnectionId) []const u8 {
    assert(self.length <= octets_max);
    return self.storage[0..self.length];
}

/// True when this is section 5.1.1's zero-length identifier.
pub fn isEmpty(self: *const ConnectionId) bool {
    assert(self.length <= octets_max);
    return self.length == 0;
}

/// Constant-time-ish equality is deliberately *not* offered: a connection
/// identifier is not a secret, it is a routing label a peer chose and sends in
/// the clear on every packet. The secret that travels beside one is the
/// stateless reset token, and that comparison belongs with the token.
pub fn eql(self: *const ConnectionId, other: *const ConnectionId) bool {
    assert(self.length <= octets_max);
    assert(other.length <= octets_max);
    return std.mem.eql(u8, self.bytes(), other.bytes());
}

test "an identifier round-trips through its storage" {
    const id = try init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    try std.testing.expectEqual(@as(u8, 8), id.length);
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, id.bytes());
    try std.testing.expect(!id.isEmpty());
}

test "the empty identifier is a choice, not an error" {
    const id = try init(&.{});
    try std.testing.expect(id.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), id.bytes().len);
}

test "twenty octets fit and twenty-one do not" {
    const twenty: [octets_max]u8 = @splat(0xab);
    const id = try init(&twenty);
    try std.testing.expectEqual(octets_max, id.length);
    const twenty_one: [octets_max + 1]u8 = @splat(0xab);
    try std.testing.expectError(error.TooLong, init(&twenty_one));
}

test "equality is over the octets, not the storage behind them" {
    // The tail of `storage` is untouched by `init`, so two identifiers that
    // differ only past `length` must still compare equal.
    var a = try init(&.{ 1, 2, 3 });
    var b = try init(&.{ 1, 2, 3 });
    a.storage[octets_max - 1] = 0xff;
    try std.testing.expect(a.eql(&b));
    try std.testing.expect(!a.eql(&try init(&.{ 1, 2 })));
}
