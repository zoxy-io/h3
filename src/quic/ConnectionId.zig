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
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# In QUIC version 1, this value MUST NOT exceed 20 bytes. Endpoints
//# that receive a version 1 long header with a value larger than 20
//# MUST drop the packet.
pub const octets_max: u8 = 20;

/// Section 5.1.1: an endpoint that issues a zero-length identifier is saying it
/// will route by four-tuple alone. Legal, and a real deployment choice — but it
/// forfeits migration, so the two are worth being able to name apart.
///
/// The rules below are what an endpoint that *issues* identifiers owes its
/// peer. This package issues exactly one — the `Options.source` its consumer
/// hands it — and never a second, so each of them is an exception naming that
/// rather than a gap.
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
//# Connection IDs MUST NOT contain any information that can be used by
//# an external observer (that is, one that does not cooperate with the
//# issuer) to correlate them with other connection IDs for the same
//# connection.
//= type=exception
//= reason=this package chooses no connection identifier; it draws no randomness at all, so the one identifier it uses is the octets its consumer supplied. See docs/DESIGN.md section 3 for why entropy stays outside the seam, and section 2 for what this package owns.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
//# As a trivial example, this means the same connection ID MUST NOT be
//# issued more than once on the same connection.
//= type=exception
//= reason=only one identifier is ever issued, so there is no second issuance to collide with; issuing more belongs to migration, which is out of scope per docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
//# An endpoint MUST NOT use the same IP address and port for multiple
//# concurrent connections with zero-length connection IDs, unless it is
//# certain that those protocol features are not in use.
//= type=exception
//= reason=nothing here sees an address or a port; the seam of docs/DESIGN.md section 3 takes a datagram rather than a socket, so demultiplexing connections onto a four-tuple is the consumer's table and not this type's.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# The sequence number on each newly issued connection ID MUST increase
//# by 1.
//= type=exception
//= reason=no connection identifier is ever issued after the first, which carries sequence number zero by definition, so no sequence number is ever assigned. NEW_CONNECTION_ID belongs to migration; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# An endpoint MUST NOT provide more connection IDs than the peer's
//# limit.
//= type=exception
//= reason=this endpoint provides none beyond the first, so the peer's active_connection_id_limit can never be exceeded. See docs/DESIGN.md section 2 and section 6 for migration's place on the not-built list.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# After processing a NEW_CONNECTION_ID frame and adding and retiring
//# active connection IDs, if the number of active connection IDs
//# exceeds the value advertised in its active_connection_id_limit
//# transport parameter, an endpoint MUST close the connection with an
//# error of type CONNECTION_ID_LIMIT_ERROR.
//= type=exception
//= reason=NEW_CONNECTION_ID frames are parsed and ignored rather than tracked, because migration is out of scope and this endpoint keeps no set of active identifiers to overflow. See docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# Upon receipt of an increased Retire Prior To field, the peer MUST
//# stop using the corresponding connection IDs and retire them with
//# RETIRE_CONNECTION_ID frames before adding the newly provided
//# connection ID to the set of active connection IDs.
//= type=exception
//= reason=retirement is migration's bookkeeping and is out of scope; this endpoint uses one destination identifier for the life of the connection and never rotates it. See docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# An endpoint MUST NOT forget a connection ID without retiring it,
//# though it MAY choose to treat having connection IDs in need of
//# retirement that exceed this limit as a connection error of type
//# CONNECTION_ID_LIMIT_ERROR.
//= type=exception
//= reason=no identifier is ever forgotten because none is ever stored beyond the single one in use; the retirement bookkeeping this rule governs belongs to migration, which docs/DESIGN.md section 2 and section 6 place out of scope.
//
// The eight rules above are what an issuer owes its peer at the level of a
// MUST; the eight below are the same shape at the level of a SHOULD, and they
// are excused by the same fact — the pool of connection identifiers this
// endpoint offers has one member and never grows or shrinks.
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# An endpoint SHOULD ensure that its peer has a sufficient number of
//# available and unused connection IDs.
//= type=exception
//= reason=the peer is given one connection identifier and needs no more, because it never migrates: migration is out of scope per docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# An endpoint SHOULD supply a new connection ID when the peer retires
//# a connection ID.
//= type=exception
//= reason=a RETIRE_CONNECTION_ID from the peer is parsed and ignored, and no replacement identifier is issued, because issuing a second one is migration's business. See docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
//# An endpoint that initiates migration and requires non-zero-length
//# connection IDs SHOULD ensure that the pool of connection IDs
//# available to its peer allows the peer to use a new connection ID on
//# migration, as the peer will be unable to respond if the pool is
//# exhausted.
//= type=exception
//= reason=this endpoint initiates no migration, so it never puts its peer in the position this rule guards against; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# Endpoints SHOULD retire connection IDs when they are no longer
//# actively using either the local or destination address for which the
//# connection ID was used.
//= type=exception
//= reason=the one destination identifier in use stays in use for the life of the connection, because the address it was chosen for never changes; nothing here sees an address at all, per docs/DESIGN.md section 3. Migration is out of scope per docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# The endpoint SHOULD continue to accept the previously issued
//# connection IDs until they are retired by the peer.
//= type=exception
//= reason=there is exactly one previously issued identifier and it is accepted for the whole connection, so there is no set to age out; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# An endpoint SHOULD limit the number of connection IDs it has retired
//# locally for which RETIRE_CONNECTION_ID frames have not yet been
//# acknowledged.
//= type=exception
//= reason=no RETIRE_CONNECTION_ID frame is ever sent, so the unacknowledged count is zero by construction; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# An endpoint SHOULD allow for sending and tracking a number of
//# RETIRE_CONNECTION_ID frames of at least twice the value of the
//# active_connection_id_limit transport parameter.
//= type=exception
//= reason=none is sent and none is tracked, because no identifier of the peer's is ever adopted and so none is ever retired; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
//# Endpoints SHOULD NOT issue updates of the Retire Prior To field
//# before receiving RETIRE_CONNECTION_ID frames that retire all
//# connection IDs indicated by the previous Retire Prior To value.
//= type=exception
//= reason=no NEW_CONNECTION_ID frame is sent, so no Retire Prior To field of ours is ever issued or updated; see docs/DESIGN.md section 2 and section 6.
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

//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# In QUIC version 1, this value MUST NOT exceed 20 bytes. Endpoints
//# that receive a version 1 long header with a value larger than 20
//# MUST drop the packet.
//= type=test
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
