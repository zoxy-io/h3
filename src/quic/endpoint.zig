//! What a server does with a datagram before there is a connection for it.
//!
//! `Connection` begins once a consumer has decided a datagram is the start of
//! one. Everything before that decision is per-endpoint rather than
//! per-connection, and every server writes it: read the Destination Connection
//! ID out of a datagram that no connection has opened, decide from RFC 9000's
//! rules whether it may start a connection, belongs to one, needs a Version
//! Negotiation packet, or is to be dropped, and build the two stateless answers
//! — Version Negotiation and Retry — plus the third, a Stateless Reset, for a
//! datagram addressed to a connection this endpoint no longer has.
//!
//! `interop/server.zig` wrote all of it by hand, and a second server would have
//! copied it. The rules are this package's to state: the 1200-octet floor that
//! decides whether an Initial or an unknown version may be answered at all is
//! RFC 9000 section 14.1's, the identifiers a Version Negotiation packet and a
//! Retry carry are crossed over in a way that is easy to get backwards, and a
//! Stateless Reset that is not smaller than its trigger is a loop.
//!
//! ## What stays the consumer's
//!
//! The connection table, the token and its key, the reset key and the entropy.
//! A server routes by `Datagram.destination` through whatever table it keeps —
//! this package has none, because a table of connections is a table of
//! `Connection(config)`s sized by the consumer — and it decides *when* to send
//! a Retry, how its token is minted and checked, and how a reset token is
//! derived from a connection identifier (RFC 9000 section 10.3.2 suggests
//! `HMAC(static_key, connection_id)`). The seam of docs/DESIGN.md section 3
//! keeps all of that outside: it needs a key, a clock and randomness.
//!
//! ## The server loop this is the first step of
//!
//!     const datagram = endpoint.classify(bytes, local_connection_id_octets);
//!     switch (datagram.action) {
//!         .route => table.find(datagram.destination) orelse drop-or-reset,
//!         .initial => table.find(datagram.destination) orelse
//!             if (datagram.mayStart()) start one else drop,
//!         .version_negotiation => send(endpoint.writeVersionNegotiation(...)),
//!         .drop => {},
//!     }

const std = @import("std");

const assert = @import("../assert.zig").assert;
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");

const ConnectionId = @import("ConnectionId.zig");

/// RFC 9000 section 14.1's floor, the size a datagram must reach before a
/// server will answer it with anything that costs more than nothing.
pub const initial_datagram_min: usize = 1200;

/// The versions this package speaks, in the order a Version Negotiation packet
/// lists them.
pub const supported_versions = [_]u32{packet.version_1};

//= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
//# This Destination Connection ID MUST be at least 8 bytes in length.
/// The shortest Destination Connection ID a client's first Initial may carry.
pub const initial_destination_octets_min: u8 = 8;

/// Section 18.2's token length, which is also what a Stateless Reset ends in.
pub const stateless_reset_token_octets: usize = @import("transport_parameters.zig").stateless_reset_token_octets;

/// RFC 9000 section 10.3: two fixed bits and at least 38 unpredictable ones,
/// then the 16-octet token. Anything shorter is not a valid QUIC packet, so a
/// peer could not take it for one.
pub const stateless_reset_octets_min: usize = 5 + stateless_reset_token_octets;

comptime {
    assert(initial_datagram_min == @import("Connection.zig").initial_datagram_min);
    assert(stateless_reset_token_octets == 16);
    assert(stateless_reset_octets_min == 21);
    assert(initial_destination_octets_min <= ConnectionId.octets_max);
}

/// What a server does with a datagram nothing has routed yet.
pub const Action = enum {
    /// Route by `destination` to the connection that answers to it. If none
    /// does, the datagram is dropped — or, for a short header, it may be
    /// answered with `writeStatelessReset` by an endpoint that sends those.
    route,
    /// An Initial in a datagram of at least 1200 octets. Route it by
    /// `destination` if a connection answers to that identifier — a client's
    /// first flight can span several datagrams, every one of them addressed to
    /// the identifier it drew, and its later Initials are addressed to the one
    /// this server chose — and otherwise start a connection from it if
    /// `Datagram.mayStart` says it may.
    initial,
    /// A long header in a version this endpoint does not speak, in a datagram
    /// large enough to start a connection in one it does: answer with
    /// `writeVersionNegotiation`.
    version_negotiation,
    /// Nothing to answer and nothing to route.
    drop,
};

/// One datagram, as far as a server can read it without a connection.
pub const Datagram = struct {
    action: Action,
    /// The first packet's Destination Connection ID, which is what a server
    /// routes by. Empty for a datagram that is dropped before it is readable.
    destination: ConnectionId = .{},
    /// A long header's Source Connection ID; empty for a short header. A Retry
    /// and a Version Negotiation packet are addressed to it.
    source: ConnectionId = .{},
    /// A long header's version; null for a short header.
    version: ?u32 = null,
    /// A long header's two identifiers as RFC 8999 states them, borrowed from
    /// the datagram: up to 255 octets each in a version other than 1, which is
    /// more than `ConnectionId` holds. What a Version Negotiation packet
    /// echoes, so that a version's own rules about its identifiers cannot
    /// decide whether it is answered.
    long_destination: []const u8 = &.{},
    long_source: []const u8 = &.{},
    /// An Initial's token, borrowed from the datagram, or empty. What a server
    /// that sent a Retry validates before it starts the connection.
    token: []const u8 = &.{},
    /// The whole datagram's length, which is section 8.1's unit of account
    /// and section 10.3's bound on a Stateless Reset.
    octets: usize = 0,

    /// Whether an Initial that named no connection may start one.
    ///
    /// Section 7.2's eight-octet floor binds a client's *first* Initial only:
    /// after the server's first Initial or a Retry, the client addresses the
    /// identifier the server chose, which may be shorter. So the floor cannot
    /// decide routing, only creation — a short identifier that finds a
    /// connection is that connection's, and one that finds none is a first
    /// Initial breaking the rule. Dropped rather than refused, because an
    /// Initial authenticates nobody.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    //# This Destination Connection ID MUST be at least 8 bytes in length.
    //= type=test
    pub fn mayStart(self: *const Datagram) bool {
        if (self.action != .initial) return false;
        assert(self.octets >= initial_datagram_min);
        assert(self.version.? == packet.version_1);
        return self.destination.length >= initial_destination_octets_min;
    }
};

/// Read a datagram's first packet header and decide what a server does with it.
///
/// `local_connection_id_octets` is the length of every connection identifier
/// this server issues, which is the only way a short header's Destination
/// Connection ID can be found: a short header does not carry its length, so a
/// server that issues identifiers of more than one length cannot route by them
/// (RFC 9000 section 10.3.2 makes the same demand of a server that resets).
///
/// Never an error. A datagram this endpoint cannot read is one it drops, and
/// section 5.2.2 says so for every case not listed.
pub fn classify(datagram: []const u8, local_connection_id_octets: u8) Datagram {
    assert(local_connection_id_octets <= ConnectionId.octets_max);
    // Any version but 1 is read by RFC 8999's rules, before version 1's parser
    // can apply version 1's: its 20-octet identifier cap and its fixed bit are
    // both version-specific, and neither may decide whether a Version
    // Negotiation packet is sent.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# Version- specific rules for the connection ID therefore MUST NOT
    //# influence a decision about whether to send a Version Negotiation
    //# packet.
    //= type=test
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    //# In order to properly form a Version Negotiation packet, servers
    //# SHOULD be able to read longer connection IDs from other QUIC
    //# versions.
    //= type=test
    if (invariant(datagram)) |long| {
        if (long.version != packet.version_1 and long.version != packet.version_negotiation) {
            return classifyUnsupported(datagram, long);
        }
    }
    const parsed = packet.parse(datagram, local_connection_id_octets) catch return .{
        .action = .drop,
        .octets = datagram.len,
    };
    assert(parsed.octets <= datagram.len);
    return switch (parsed.header) {
        .short => |short| .{ .action = .route, .destination = short.destination, .octets = datagram.len },
        .initial => |initial| classifyInitial(datagram, initial),
        .zero_rtt, .handshake => |long| .{
            .action = .route,
            .destination = long.destination,
            .source = long.source,
            .version = packet.version_1,
            .octets = datagram.len,
        },
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
        //# A client MUST accept and process at most one Retry packet for each
        //# connection attempt.
        //= type=exception
        //= reason=a rule on the client; a server is the endpoint that sends a Retry and never acts on one, so `classify` drops it, and `Connection.receiveRetry` is the client half.
        .retry => .{ .action = .drop, .octets = datagram.len },
        //= https://www.rfc-editor.org/rfc/rfc9000#section-6.1
        //# An endpoint MUST NOT send a Version Negotiation packet in response
        //# to receiving a Version Negotiation packet.
        //= type=test
        .version_negotiation => .{ .action = .drop, .octets = datagram.len },
        // Read above, by RFC 8999's rules, before the parser was reached.
        .unsupported_version => .{ .action = .drop, .octets = datagram.len },
    };
}

/// RFC 8999 section 5.1: the long header every QUIC version shares — a first
/// octet with its high bit set, a version, and two identifiers of up to 255
/// octets each, length-prefixed.
const Invariant = struct {
    version: u32,
    destination: []const u8,
    source: []const u8,
};

fn invariant(datagram: []const u8) ?Invariant {
    // The first octet, the version, and the two length octets.
    const fixed_octets: usize = 1 + 4 + 1 + 1;
    if (datagram.len < fixed_octets) return null;
    if (datagram[0] & packet.header_form_long == 0) return null;
    const version = std.mem.readInt(u32, datagram[1..5], .big);
    const destination_octets: usize = datagram[5];
    const source_at = 6 + destination_octets;
    if (source_at >= datagram.len) return null;
    const source_octets: usize = datagram[source_at];
    if (source_at + 1 + source_octets > datagram.len) return null;
    // RFC 8999's identifiers are one length octet each, so neither can pass
    // 255 and the two together fit in the 1 + 4 + 2 + 510 octets checked.
    assert(destination_octets <= std.math.maxInt(u8));
    assert(source_octets <= std.math.maxInt(u8));
    return .{
        .version = version,
        .destination = datagram[6..][0..destination_octets],
        .source = datagram[source_at + 1 ..][0..source_octets],
    };
}

fn classifyInitial(datagram: []const u8, initial: @FieldType(packet.Header, "initial")) Datagram {
    assert(datagram.len >= 1);
    const result: Datagram = .{
        .action = .initial,
        .destination = initial.destination,
        .source = initial.source,
        .version = packet.version_1,
        .token = initial.token,
        .octets = datagram.len,
    };
    // The floor applies to the datagram, not to the packet: a padded Initial
    // and an Initial coalesced with others both reach it, and both count.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
    //# A server MUST discard an Initial packet that is carried in a UDP
    //# datagram with a payload that is smaller than the smallest allowed
    //# maximum datagram size of 1200 bytes.
    //= type=test
    if (datagram.len < initial_datagram_min) return .{ .action = .drop, .octets = datagram.len };
    assert(result.destination.length == initial.destination.length);
    assert(result.token.len == initial.token.len);
    return result;
}

fn classifyUnsupported(datagram: []const u8, unsupported: Invariant) Datagram {
    assert(unsupported.version != packet.version_1);
    assert(unsupported.version != packet.version_negotiation);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    //# Servers MUST drop smaller packets that specify unsupported versions.
    //= type=test
    if (datagram.len < initial_datagram_min) return .{ .action = .drop, .octets = datagram.len };
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    //# If a server receives a packet that indicates an unsupported version
    //# and if the packet is large enough to initiate a new connection for
    //# any supported version, the server SHOULD send a Version Negotiation
    //# packet as described in Section 6.1.
    //= type=test
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    //# Servers SHOULD respond with a Version Negotiation packet, provided
    //# that the datagram is sufficiently long.
    //= type=test
    return .{
        .action = .version_negotiation,
        // Kept as identifiers too when they fit, so a server that routes on
        // them need not re-read the octets; past 20 only the octets exist.
        .destination = ConnectionId.init(unsupported.destination) catch .{},
        .source = ConnectionId.init(unsupported.source) catch .{},
        .version = unsupported.version,
        .long_destination = unsupported.destination,
        .long_source = unsupported.source,
        .octets = datagram.len,
    };
}

/// The Version Negotiation packet that answers `datagram`, with the
/// identifiers crossed over as section 17.2.1 requires: the client's Source
/// Connection ID becomes this packet's destination and its Destination
/// Connection ID this packet's source.
///
/// Smaller than the datagram it answers by construction — a header and four
/// octets of versions against a datagram of at least 1200 — which is what
/// makes it safe to send to an address nobody has validated.
pub fn writeVersionNegotiation(target: []u8, datagram: *const Datagram) packet.WriteError!usize {
    assert(datagram.action == .version_negotiation);
    assert(datagram.octets >= initial_datagram_min);
    const written = try packet.writeVersionNegotiationOctets(
        target,
        datagram.long_source,
        datagram.long_destination,
        &supported_versions,
    );
    assert(written < datagram.octets);
    return written;
}

pub const RetryError = packet.RetryError || error{
    /// The identifier chosen for the Retry is the one the client addressed.
    /// Section 17.2.5.1 forbids it, and a client discards such a Retry.
    SourceUnchanged,
};

/// The Retry that answers `datagram`'s Initial, its integrity tag computed by
/// `Backend` — the backend the consumer's `Connection` is configured with.
///
/// `source` is the identifier the server wants the client to address it as
/// from now on; the client's next Initial carries it as its Destination
/// Connection ID, which is what the Initial keys then derive from and what
/// `retry_source_connection_id` must repeat. `token` is opaque here: what is in
/// it, and how it is checked when it returns, is the consumer's.
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
//# This value MUST NOT be equal to the Destination Connection ID field
//# of the packet sent by the client.
//= type=test
pub fn writeRetry(
    comptime Backend: type,
    target: []u8,
    scratch: []u8,
    datagram: *const Datagram,
    source: ConnectionId,
    token: []const u8,
) RetryError!usize {
    assert(datagram.action == .initial);
    assert(datagram.octets >= initial_datagram_min);
    if (source.eql(&datagram.destination)) return error.SourceUnchanged;
    const written = try packet.writeRetryWith(Backend, target, scratch, .{
        .destination = datagram.source,
        .source = source,
        .token = token,
        .original_destination = datagram.destination,
    });
    assert(written >= crypto.tag_octets);
    return written;
}

pub const StatelessResetError = error{
    /// The trigger is too short for a reset smaller than it to be a valid
    /// packet: section 10.3.3's loop guard and section 10.3's 21-octet floor
    /// cannot both be met, so nothing is sent.
    TriggerTooSmall,
    /// `target` or `unpredictable` leaves no room for the 21-octet minimum.
    OutputTooSmall,
};

/// A Stateless Reset answering a `trigger_octets`-octet datagram that named no
/// connection this endpoint holds, ending in `token`.
///
/// Its length is the smallest of: one octet less than the trigger, the
/// target's length, and `unpredictable.len` plus the token. So the consumer
/// chooses the size by how much it hands over — RFC 9000 section 10.3.3 notes
/// that a reset under 41 octets may be identifiable as one, so a slice of 41 to
/// 64 is a reasonable choice — and this function holds the rules: at least 21
/// octets, always shorter than its trigger, and so never three times it.
///
/// `unpredictable` is the consumer's entropy, and it is copied rather than
/// drawn: this package draws none. Its first octet supplies the six random
/// bits of the first byte.
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# The remainder of the first byte and an arbitrary number of bytes
//# following it are set to values that SHOULD be indistinguishable from
//# random.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# An endpoint MUST NOT send a Stateless Reset that is three times or
//# more larger than the packet it receives to avoid being used for
//# amplification.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
//# An endpoint MUST ensure that every Stateless Reset that it sends is
//# smaller than the packet that triggered it, unless it maintains state
//# sufficient to prevent looping.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# An endpoint that sends a Stateless Reset in response to a packet that is
//# 43 bytes or shorter SHOULD send a Stateless Reset that is one byte
//# shorter than the packet it responds to.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# Endpoints MUST send Stateless Resets formatted as a packet with a
//# short header.
//= type=test
pub fn writeStatelessReset(
    target: []u8,
    token: *const [stateless_reset_token_octets]u8,
    trigger_octets: usize,
    unpredictable: []const u8,
) StatelessResetError!usize {
    if (trigger_octets <= stateless_reset_octets_min) return error.TriggerTooSmall;
    const octets = @min(@min(trigger_octets - 1, target.len), unpredictable.len + stateless_reset_token_octets);
    if (octets < stateless_reset_octets_min) return error.OutputTooSmall;
    // Shorter than the trigger is what section 10.3.3 asks, and it is also the
    // whole of section 10.3's three-times rule: a reset that is smaller than
    // its trigger is certainly not three times it.
    assert(octets < trigger_octets);
    assert(octets >= stateless_reset_octets_min);

    const prefix = octets - stateless_reset_token_octets;
    @memcpy(target[0..prefix], unpredictable[0..prefix]);
    // The short header's form bit is zero and its fixed bit one; the other six
    // bits are the consumer's random ones.
    target[0] = packet.fixed_bit | (unpredictable[0] & 0x3f);
    @memcpy(target[prefix..][0..stateless_reset_token_octets], token);
    assert(target[0] & packet.header_form_long == 0);
    return octets;
}

const testing = std.testing;

/// For tests and fuzzing: a long-header packet of `long_type` whose Length runs
/// to the end of a `total`-octet datagram, which is the shape `classify` reads.
/// Not protected — classification happens before any key, which is its point.
pub fn testLongDatagram(
    target: []u8,
    long_type: packet.LongType,
    version: u32,
    destination: []const u8,
    token: []const u8,
    total: usize,
) !usize {
    const options: packet.LongOptions = .{
        .long_type = long_type,
        .version = version,
        .destination = try ConnectionId.init(destination),
        .source = try ConnectionId.init(&.{ 1, 2, 3, 4 }),
        .token = token,
        .length_octets = 2,
        .payload_octets = 0,
        .number = 0,
        .number_octets = 1,
    };
    // The pinned Length makes the header's width independent of the payload,
    // so it can be measured once and the payload sized from it.
    const probe = try packet.writeLong(target, options);
    if (total < probe.header_octets + crypto.tag_octets) return error.OutputTooLong;
    var sized = options;
    sized.payload_octets = total - probe.header_octets - crypto.tag_octets;
    const written = try packet.writeLong(target, sized);
    assert(written.header_octets == probe.header_octets);
    @memset(target[written.header_octets..total], 0);
    return total;
}

const client_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "a client Initial of at least 1200 octets may start a connection" {
    var buffer: [1500]u8 = undefined;
    const octets = try testLongDatagram(&buffer, .initial, packet.version_1, &client_dcid, "a token", 1200);
    const datagram = classify(buffer[0..octets], 8);
    try testing.expectEqual(Action.initial, datagram.action);
    try testing.expectEqualSlices(u8, &client_dcid, datagram.destination.bytes());
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, datagram.source.bytes());
    try testing.expectEqualStrings("a token", datagram.token);
    try testing.expectEqual(@as(?u32, packet.version_1), datagram.version);
    try testing.expectEqual(@as(usize, 1200), datagram.octets);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
//# A server MUST discard an Initial packet that is carried in a UDP
//# datagram with a payload that is smaller than the smallest allowed
//# maximum datagram size of 1200 bytes.
//= type=test
test "an Initial under 1200 octets is dropped, and buys nothing" {
    var buffer: [1500]u8 = undefined;
    const octets = try testLongDatagram(&buffer, .initial, packet.version_1, &client_dcid, "", 1199);
    try testing.expectEqual(Action.drop, classify(buffer[0..octets], 8).action);
}

test "an Initial padded past its packet still counts the whole datagram" {
    // Section 14.1's floor is the datagram's, so an Initial followed by
    // anything — padding the client put after the packet, or a coalesced
    // Handshake packet — classifies by the total.
    var buffer: [1500]u8 = undefined;
    const first = try testLongDatagram(&buffer, .initial, packet.version_1, &client_dcid, "", 600);
    @memset(buffer[first..1200], 0);
    const datagram = classify(buffer[0..1200], 8);
    try testing.expectEqual(Action.initial, datagram.action);
    try testing.expectEqual(@as(usize, 1200), datagram.octets);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
//# This Destination Connection ID MUST be at least 8 bytes in length.
//= type=test
test "a short Destination Connection ID routes an Initial and cannot start one" {
    // After a Retry or the server's first Initial, a client addresses the
    // identifier the server chose, and a server issuing four-octet identifiers
    // gets four-octet Initials back. Those must still route.
    var buffer: [1500]u8 = undefined;
    const octets = try testLongDatagram(&buffer, .initial, packet.version_1, client_dcid[0..4], "", 1200);
    const datagram = classify(buffer[0..octets], 4);
    try testing.expectEqual(Action.initial, datagram.action);
    try testing.expect(!datagram.mayStart());

    const long = try testLongDatagram(&buffer, .initial, packet.version_1, &client_dcid, "", 1200);
    try testing.expect(classify(buffer[0..long], 4).mayStart());
}

test "a short header is routed by the identifier length this server issues" {
    var buffer: [64]u8 = @splat(0xaa);
    const written = try packet.writeShort(&buffer, .{
        .destination = try ConnectionId.init(&client_dcid),
        .number = 1,
        .number_octets = 2,
    });
    _ = written;
    const datagram = classify(&buffer, 8);
    try testing.expectEqual(Action.route, datagram.action);
    try testing.expectEqualSlices(u8, &client_dcid, datagram.destination.bytes());
    try testing.expect(datagram.source.isEmpty());
    try testing.expectEqual(@as(?u32, null), datagram.version);
}

test "Handshake and 0-RTT packets are routed, never started from" {
    var buffer: [256]u8 = undefined;
    for ([_]packet.LongType{ .handshake, .zero_rtt }) |long_type| {
        const octets = try testLongDatagram(&buffer, long_type, packet.version_1, &client_dcid, "", 100);
        const datagram = classify(buffer[0..octets], 8);
        try testing.expectEqual(Action.route, datagram.action);
        try testing.expectEqualSlices(u8, &client_dcid, datagram.destination.bytes());
    }
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-6.1
//# An endpoint MUST NOT send a Version Negotiation packet in response
//# to receiving a Version Negotiation packet.
//= type=test
test "a Version Negotiation packet and a Retry are dropped by a server" {
    var buffer: [1300]u8 = @splat(0);
    const negotiation = try packet.writeVersionNegotiation(
        &buffer,
        try ConnectionId.init(&.{ 1, 2, 3, 4 }),
        try ConnectionId.init(&client_dcid),
        &.{0x1a2a3a4a},
    );
    try testing.expectEqual(Action.drop, classify(buffer[0..@max(negotiation, 1200)], 8).action);

    var scratch: [256]u8 = undefined;
    const retry = try packet.writeRetry(&buffer, &scratch, .{
        .destination = try ConnectionId.init(&.{ 1, 2, 3, 4 }),
        .source = try ConnectionId.init(&.{ 9, 9, 9, 9, 9, 9, 9, 9 }),
        .token = "token",
        .original_destination = try ConnectionId.init(&client_dcid),
    });
    try testing.expectEqual(Action.drop, classify(buffer[0..retry], 8).action);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
//# Servers MUST drop smaller packets that specify unsupported versions.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
//# If a server receives a packet that indicates an unsupported version
//# and if the packet is large enough to initiate a new connection for
//# any supported version, the server SHOULD send a Version Negotiation
//# packet as described in Section 6.1.
//= type=test
test "an unknown version is answered at 1200 octets and dropped below" {
    var buffer: [1500]u8 = @splat(0);
    buffer[0] = packet.header_form_long | packet.fixed_bit;
    std.mem.writeInt(u32, buffer[1..5], 0xff00_001d, .big);
    buffer[5] = client_dcid.len;
    @memcpy(buffer[6..][0..client_dcid.len], &client_dcid);
    buffer[6 + client_dcid.len] = 4;
    @memcpy(buffer[7 + client_dcid.len ..][0..4], &[_]u8{ 1, 2, 3, 4 });

    try testing.expectEqual(Action.drop, classify(buffer[0..1199], 8).action);
    const datagram = classify(buffer[0..1200], 8);
    try testing.expectEqual(Action.version_negotiation, datagram.action);
    try testing.expectEqual(@as(?u32, 0xff00_001d), datagram.version);

    // The answer crosses the identifiers over and is smaller than the probe.
    var answer: [256]u8 = undefined;
    const written = try writeVersionNegotiation(&answer, &datagram);
    try testing.expect(written < datagram.octets);
    const parsed = try packet.parse(answer[0..written], 0);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, parsed.header.version_negotiation.destination.bytes());
    try testing.expectEqualSlices(u8, &client_dcid, parsed.header.version_negotiation.source.bytes());
    try testing.expectEqual(@as(?u32, packet.version_1), packet.versionAt(parsed.header.version_negotiation.versions, 0));
}

test "an unknown version's identifiers are read by RFC 8999, past version 1's limits" {
    // Thirty-octet identifiers and a clear fixed bit: both legal in a version
    // this package does not speak, and both refused by version 1's parser.
    var buffer: [1300]u8 = @splat(0);
    const long_id: [30]u8 = @splat(0x5c);
    buffer[0] = packet.header_form_long;
    std.mem.writeInt(u32, buffer[1..5], 0x5a6a7a8a, .big);
    buffer[5] = long_id.len;
    @memcpy(buffer[6..][0..long_id.len], &long_id);
    buffer[6 + long_id.len] = 3;
    @memcpy(buffer[7 + long_id.len ..][0..3], &[_]u8{ 7, 8, 9 });

    const datagram = classify(buffer[0..1200], 8);
    try testing.expectEqual(Action.version_negotiation, datagram.action);
    try testing.expectEqualSlices(u8, &long_id, datagram.long_destination);
    var answer: [256]u8 = undefined;
    const written = try writeVersionNegotiation(&answer, &datagram);
    // The answer's source is the thirty octets the client addressed.
    try testing.expectEqual(@as(u8, 3), answer[5]);
    try testing.expectEqual(@as(u8, long_id.len), answer[5 + 1 + 3]);
    try testing.expectEqualSlices(u8, &long_id, answer[5 + 1 + 3 + 1 ..][0..long_id.len]);
    try testing.expect(written < datagram.octets);
}

test "garbage is dropped, never an error" {
    try testing.expectEqual(Action.drop, classify(&.{}, 8).action);
    // A short header with its fixed bit clear is not QUIC (section 17.3.1).
    try testing.expectEqual(Action.drop, classify(&([_]u8{0x00} ++ @as([40]u8, @splat(7))), 8).action);
    // A short header too short to hold the identifier this server issues.
    try testing.expectEqual(Action.drop, classify(&.{ 0x40, 1, 2, 3 }, 8).action);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
//# This value MUST NOT be equal to the Destination Connection ID field
//# of the packet sent by the client.
//= type=test
test "a Retry this endpoint writes is one a client accepts, under a new identifier" {
    var buffer: [1500]u8 = undefined;
    const octets = try testLongDatagram(&buffer, .initial, packet.version_1, &client_dcid, "", 1200);
    const datagram = classify(buffer[0..octets], 8);

    var retry: [256]u8 = undefined;
    var scratch: [512]u8 = undefined;
    try testing.expectError(error.SourceUnchanged, writeRetry(crypto.backend.Std, &retry, &scratch, &datagram, datagram.destination, "t"));

    const source = try ConnectionId.init(&.{ 9, 8, 7, 6, 5, 4, 3, 2 });
    const written = try writeRetry(crypto.backend.Std, &retry, &scratch, &datagram, source, "a token");
    const parsed = try packet.parse(retry[0..written], 0);
    try testing.expectEqualSlices(u8, datagram.source.bytes(), parsed.header.retry.destination.bytes());
    try testing.expectEqualSlices(u8, source.bytes(), parsed.header.retry.source.bytes());
    try testing.expectEqualStrings("a token", parsed.header.retry.token);
    // Section 5.8: the tag binds the identifier the client used first.
    try crypto.retry.verify(&scratch, &client_dcid, retry[0..written]);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
//# An endpoint MUST ensure that every Stateless Reset that it sends is
//# smaller than the packet that triggered it, unless it maintains state
//# sufficient to prevent looping.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# An endpoint MUST NOT send a Stateless Reset that is three times or
//# more larger than the packet it receives to avoid being used for
//# amplification.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
//# Endpoints MUST send Stateless Resets formatted as a packet with a
//# short header.
//= type=test
test "a stateless reset is shorter than its trigger and ends in the token" {
    const token: [16]u8 = @splat(0xab);
    var unpredictable: [48]u8 = undefined;
    for (&unpredictable, 0..) |*octet, index| octet.* = @truncate(index *% 37 +% 11);
    var target: [128]u8 = undefined;

    // A small trigger: one octet shorter, which is section 10.3's SHOULD.
    const small = try writeStatelessReset(&target, &token, 30, &unpredictable);
    try testing.expectEqual(@as(usize, 29), small);
    try testing.expectEqual(@as(u8, 0), target[0] & packet.header_form_long);
    try testing.expect(target[0] & packet.fixed_bit != 0);
    try testing.expectEqualSlices(u8, &token, target[small - 16 .. small]);

    // A large one: as long as the consumer's entropy allows, and no longer.
    const large = try writeStatelessReset(&target, &token, 1200, &unpredictable);
    try testing.expectEqual(unpredictable.len + 16, large);
    try testing.expect(large < 1200);

    // Too small to answer at all, and too little room to.
    try testing.expectError(error.TriggerTooSmall, writeStatelessReset(&target, &token, 21, &unpredictable));
    try testing.expectError(error.OutputTooSmall, writeStatelessReset(target[0..20], &token, 100, &unpredictable));
    try testing.expectError(error.OutputTooSmall, writeStatelessReset(&target, &token, 100, unpredictable[0..4]));
}
