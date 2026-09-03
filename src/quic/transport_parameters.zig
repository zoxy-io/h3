//! RFC 9000 section 18: transport parameters.
//!
//! The connection's entire configuration, exchanged once, inside the TLS
//! handshake rather than in a QUIC frame — which is what makes it
//! authenticated: a parameter cannot be tampered with by the path, because it
//! is covered by the handshake transcript. This package neither builds nor
//! reads the TLS extension that carries them; it encodes and decodes the
//! extension's *contents*, and the consumer hands those to its TLS engine as
//! opaque octets. That is the same seam as everywhere else here, and it is what
//! lets zoxy use ztls and zrk use zssl for the same wire format.
//!
//! ## Defaults are not zero
//!
//! Six parameters have non-zero defaults, and each of them is a limit that
//! applies *whether or not the peer sent it*. `active_connection_id_limit`
//! defaults to 2 and may not be sent below 2; `ack_delay_exponent` defaults to
//! 3, and reading an ACK's delay field with the wrong exponent silently
//! misestimates the RTT by a factor of eight. So `Parameters` is a struct with
//! defaults rather than a set of optionals, and a parameter that was absent is
//! indistinguishable from one sent at its default — which is what section 18.2
//! says they mean.
//!
//! The four that genuinely are optional — the three connection identifiers and
//! the stateless reset token — stay optional, because "absent" and "empty" are
//! different answers for those.
//!
//! ## Unknown parameters are ignored, and that is a requirement
//!
//! Section 18.1 requires an unrecognised identifier to be ignored, and section
//! 22.3 reserves a GREASE family to make sure implementations actually do. A
//! decoder that rejected one would fail against half the deployed servers.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const varint = @import("../varint.zig");

const ConnectionId = @import("ConnectionId.zig");

/// Section 18.2's identifiers. Non-exhaustive: the registry is extensible and
/// unknown values must be ignored rather than refused.
pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// The defaults section 18.2 assigns, named so that a reader can tell a default
/// from a number someone liked.
pub const max_udp_payload_size_default: u64 = 65_527;
pub const max_udp_payload_size_min: u64 = 1_200;
pub const ack_delay_exponent_default: u64 = 3;
pub const ack_delay_exponent_max: u64 = 20;
pub const max_ack_delay_default: u64 = 25;
pub const max_ack_delay_max: u64 = (1 << 14) - 1;
pub const active_connection_id_limit_default: u64 = 2;
pub const active_connection_id_limit_min: u64 = 2;

/// Section 18.2: a streams limit above this cannot be a stream identifier.
pub const streams_max: u64 = 1 << 60;

/// Section 19.15 and 18.2: the stateless reset token's fixed length.
pub const stateless_reset_token_octets: usize = 16;

comptime {
    assert(max_udp_payload_size_min == 1_200);
    assert(active_connection_id_limit_min == active_connection_id_limit_default);
    assert(max_ack_delay_max == 16_383);
    // The floor exists because section 14.1 requires an Initial packet to be
    // padded to 1200 octets: a peer advertising less could not receive one.
    assert(max_udp_payload_size_min <= max_udp_payload_size_default);
}

// Section 18.2's preferred address is decoded and encoded so that a consumer
// can see what a server offered, and nothing here acts on one: moving to a
// preferred address is migration, and migration is out of scope. The three
// rules that constrain the field are that decision.
//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# A server that chooses a zero-length connection ID MUST NOT provide a
//# preferred address.
//= type=exception
//= reason=this package never composes a preferred address of its own, because a server here has one address and never moves; see docs/DESIGN.md section 2 for what this package owns and section 6 for migration's place on the not-built list.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# Similarly, a server MUST NOT include a zero- length connection ID in
//# this transport parameter.
//= type=exception
//= reason=no preferred address is ever sent, so no connection identifier of ours is ever put in one; see docs/DESIGN.md section 2 and section 6.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# A client MUST treat a violation of these requirements as a
//# connection error of type TRANSPORT_PARAMETER_ERROR.
//= type=exception
//= reason=a received preferred address is decoded and then ignored rather than checked, because a client here never migrates to one; see docs/DESIGN.md section 2 and section 6.

/// Section 18.2's `preferred_address`.
///
/// Addresses are octets and ports are integers, deliberately: `std.net` is
/// lint-forbidden here, and it would be the wrong type anyway — the two
/// consumers hand these to two different socket layers, and a package that
/// picked one of their address types would exclude the other.
pub const PreferredAddress = struct {
    ipv4: [4]u8,
    ipv4_port: u16,
    ipv6: [16]u8,
    ipv6_port: u16,
    connection_id: ConnectionId,
    stateless_reset_token: [stateless_reset_token_octets]u8,

    /// Section 18.2: an all-zero address means the server offers nothing for
    /// that family, which is not the same as offering port 0 on 0.0.0.0.
    pub fn hasIpv4(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ipv4, 0);
    }

    pub fn hasIpv6(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ipv6, 0);
    }
};

/// Everything section 18.2 defines, with the defaults it assigns.
pub const Parameters = struct {
    original_destination_connection_id: ?ConnectionId = null,
    max_idle_timeout_ms: u64 = 0,
    /// Section 18.2's `stateless_reset_token`. Optional rather than defaulted,
    /// because absent and empty are different answers — and `validate` is what
    /// refuses one from a client.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    //# This transport parameter MUST NOT be sent by a client but MAY be
    //# sent by a server.
    stateless_reset_token: ?[stateless_reset_token_octets]u8 = null,
    max_udp_payload_size: u64 = max_udp_payload_size_default,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = ack_delay_exponent_default,
    /// Section 18.2's `max_ack_delay`, in milliseconds. What to put in it is
    /// the consumer's call, because the alarm that would be late is the
    /// consumer's timer: nothing here reads a clock.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    //# This value SHOULD include the receiver's expected delays in alarms
    //# firing.
    //= type=exception
    //= reason=this package neither owns a timer nor knows how late its consumer's fires; `now_ns` arrives as a parameter per docs/DESIGN.md section 3, so the margin a receiver should add is the consumer's to choose and this type only carries it.
    max_ack_delay_ms: u64 = max_ack_delay_default,
    /// Section 18.2's `disable_active_migration`, carried so that a consumer
    /// can honour it. Honouring it costs nothing here.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    //# An endpoint that receives this transport parameter MUST NOT use a
    //# new local address when sending to the address that the peer used
    //# during the handshake.
    //= type=exception
    //= reason=nothing here chooses a local address, or sees one: the seam of docs/DESIGN.md section 3 takes datagrams rather than sockets, so this endpoint never migrates whether or not the peer forbids it. Migration is out of scope per docs/DESIGN.md section 2 and section 6.
    disable_active_migration: bool = false,
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = active_connection_id_limit_default,
    initial_source_connection_id: ?ConnectionId = null,
    retry_source_connection_id: ?ConnectionId = null,
};

pub const ParseError = error{
    /// A parameter runs past the end of the extension, or a length field does
    /// not decode. A `TRANSPORT_PARAMETER_ERROR`.
    Truncated,
    /// A value outside the range section 18.2 gives it, a fixed-length
    /// parameter at the wrong length, or a duplicate identifier. All
    /// `TRANSPORT_PARAMETER_ERROR`.
    Malformed,
};

/// Decode the contents of the `quic_transport_parameters` TLS extension.
///
/// Duplicates are refused rather than last-one-wins: section 18 makes a
/// repeated identifier a `TRANSPORT_PARAMETER_ERROR`, and the alternative is
/// two implementations disagreeing about which copy counts.
pub fn parse(source: []const u8) ParseError!Parameters {
    var parameters: Parameters = .{};
    var seen: std.EnumSet(Known) = .initEmpty();
    var offset: usize = 0;

    // Bounded: every parameter costs at least two octets — an identifier and a
    // length — so this runs at most `source.len / 2` times.
    while (offset < source.len) {
        const id_decoded = varint.decode(source[offset..]) catch return error.Truncated;
        offset += id_decoded.octets;
        const length_decoded = varint.decode(source[offset..]) catch return error.Truncated;
        offset += length_decoded.octets;

        const length = std.math.cast(usize, length_decoded.value) orelse return error.Truncated;
        if (source.len - offset < length) return error.Truncated;
        const value = source[offset..][0..length];
        offset += length;
        assert(offset <= source.len);

        const known = toKnown(id_decoded.value) orelse continue;
        if (seen.contains(known)) return error.Malformed;
        seen.insert(known);
        try apply(&parameters, known, value);
    }
    assert(offset == source.len);
    return parameters;
}

/// The subset of `Id` this package understands, as a dense enum so that
/// duplicate detection is a bit set rather than a search.
const Known = enum {
    original_destination_connection_id,
    max_idle_timeout,
    stateless_reset_token,
    max_udp_payload_size,
    initial_max_data,
    initial_max_stream_data_bidi_local,
    initial_max_stream_data_bidi_remote,
    initial_max_stream_data_uni,
    initial_max_streams_bidi,
    initial_max_streams_uni,
    ack_delay_exponent,
    max_ack_delay,
    disable_active_migration,
    preferred_address,
    active_connection_id_limit,
    initial_source_connection_id,
    retry_source_connection_id,
};

comptime {
    // The two enums have to stay in step, or an identifier would be understood
    // by one and ignored by the other.
    assert(@typeInfo(Known).@"enum".fields.len == @typeInfo(Id).@"enum".fields.len);
}

fn toKnown(value: u64) ?Known {
    if (value > 0x10) return null;
    return @enumFromInt(@as(u5, @intCast(value)));
}

fn apply(parameters: *Parameters, known: Known, value: []const u8) ParseError!void {
    switch (known) {
        .original_destination_connection_id => parameters.original_destination_connection_id = try connectionId(value),
        .initial_source_connection_id => parameters.initial_source_connection_id = try connectionId(value),
        .retry_source_connection_id => parameters.retry_source_connection_id = try connectionId(value),
        .stateless_reset_token => {
            if (value.len != stateless_reset_token_octets) return error.Malformed;
            parameters.stateless_reset_token = value[0..stateless_reset_token_octets].*;
        },
        .max_idle_timeout => parameters.max_idle_timeout_ms = try integer(value, varint.max),
        .max_udp_payload_size => {
            const size = try integer(value, varint.max);
            // Below 1200 a peer could not receive the Initial packet section
            // 14.1 requires to be padded to that length, so the connection
            // could never start.
            if (size < max_udp_payload_size_min) return error.Malformed;
            parameters.max_udp_payload_size = size;
        },
        .initial_max_data => parameters.initial_max_data = try integer(value, varint.max),
        .initial_max_stream_data_bidi_local => parameters.initial_max_stream_data_bidi_local = try integer(value, varint.max),
        .initial_max_stream_data_bidi_remote => parameters.initial_max_stream_data_bidi_remote = try integer(value, varint.max),
        .initial_max_stream_data_uni => parameters.initial_max_stream_data_uni = try integer(value, varint.max),
        .initial_max_streams_bidi => parameters.initial_max_streams_bidi = try integer(value, streams_max),
        .initial_max_streams_uni => parameters.initial_max_streams_uni = try integer(value, streams_max),
        .ack_delay_exponent => parameters.ack_delay_exponent = try integer(value, ack_delay_exponent_max),
        .max_ack_delay => parameters.max_ack_delay_ms = try integer(value, max_ack_delay_max),
        .disable_active_migration => {
            if (value.len != 0) return error.Malformed;
            parameters.disable_active_migration = true;
        },
        .active_connection_id_limit => {
            const limit = try integer(value, varint.max);
            //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
            //# The value of the active_connection_id_limit parameter MUST be at
            //# least 2. An endpoint that receives a value less than 2 MUST close
            //# the connection with an error of type TRANSPORT_PARAMETER_ERROR.
            if (limit < active_connection_id_limit_min) return error.Malformed;
            parameters.active_connection_id_limit = limit;
        },
        .preferred_address => parameters.preferred_address = try preferredAddress(value),
    }
}

fn integer(value: []const u8, maximum: u64) ParseError!u64 {
    const decoded = varint.decode(value) catch return error.Malformed;
    // The whole parameter must be the integer: trailing octets mean the length
    // and the value disagree, which is a `TRANSPORT_PARAMETER_ERROR` rather
    // than something to skip past.
    if (decoded.octets != value.len) return error.Malformed;
    if (decoded.value > maximum) return error.Malformed;
    return decoded.value;
}

fn connectionId(value: []const u8) ParseError!ConnectionId {
    return ConnectionId.init(value) catch error.Malformed;
}

fn preferredAddress(value: []const u8) ParseError!PreferredAddress {
    // Section 18.2's fixed prefix: two addresses with their ports, then a
    // length-prefixed connection identifier and a token.
    const prefix = 4 + 2 + 16 + 2 + 1;
    if (value.len < prefix) return error.Malformed;
    const id_length = value[prefix - 1];
    if (id_length > ConnectionId.octets_max) return error.Malformed;
    const total = prefix + @as(usize, id_length) + stateless_reset_token_octets;
    if (value.len != total) return error.Malformed;

    return .{
        .ipv4 = value[0..4].*,
        .ipv4_port = std.mem.readInt(u16, value[4..6], .big),
        .ipv6 = value[6..22].*,
        .ipv6_port = std.mem.readInt(u16, value[22..24], .big),
        .connection_id = try connectionId(value[prefix..][0..id_length]),
        .stateless_reset_token = value[prefix + id_length ..][0..stateless_reset_token_octets].*,
    };
}

pub const ValidateError = error{
    /// Section 18.2: four parameters are the server's alone. A client that
    /// sends one is a `TRANSPORT_PARAMETER_ERROR`, and accepting it would let a
    /// client hand us a stateless reset token for a connection it does not own.
    ServerOnlyParameter,
    /// Section 7.3: both endpoints must send `initial_source_connection_id`,
    /// and a server that sent a Retry must send `retry_source_connection_id`.
    /// Their absence is what an endpoint checks to detect a tampered handshake.
    MissingConnectionId,
};

/// Check the rules that depend on *who sent* the parameters.
///
/// Separate from `parse` because the same octets are legal from one side and
/// not from the other, and a decoder that took a side would be two decoders.
pub fn validate(parameters: *const Parameters, sender: @import("crypto.zig").Side) ValidateError!void {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    //# A client MUST NOT include any server-only transport parameter:
    //# original_destination_connection_id, preferred_address,
    //# retry_source_connection_id, or stateless_reset_token.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    //# A server MUST treat receipt of any of these transport parameters as
    //# a connection error of type TRANSPORT_PARAMETER_ERROR.
    if (sender == .client) {
        if (parameters.original_destination_connection_id != null) return error.ServerOnlyParameter;
        if (parameters.stateless_reset_token != null) return error.ServerOnlyParameter;
        if (parameters.preferred_address != null) return error.ServerOnlyParameter;
        if (parameters.retry_source_connection_id != null) return error.ServerOnlyParameter;
    }
    if (parameters.initial_source_connection_id == null) return error.MissingConnectionId;
    if (sender == .server and parameters.original_destination_connection_id == null) {
        return error.MissingConnectionId;
    }
}

pub const EncodeError = error{
    /// `target` cannot hold the parameters.
    OutputTooLong,
    /// A value outside the range its parameter allows.
    ValueTooLarge,
};

/// Encode the parameters that differ from their defaults.
///
/// Omitting a default is not an optimisation — a parameter sent at its default
/// and a parameter omitted mean the same thing (section 18.2) — but it keeps
/// the extension small, which matters because the ClientHello it rides in
/// should fit one packet.
pub fn encode(target: []u8, parameters: *const Parameters) EncodeError!usize {
    var writer: Writer = .{ .target = target };
    try writer.optionalId(.original_destination_connection_id, parameters.original_destination_connection_id);
    try writer.optionalId(.initial_source_connection_id, parameters.initial_source_connection_id);
    try writer.optionalId(.retry_source_connection_id, parameters.retry_source_connection_id);
    if (parameters.stateless_reset_token) |token| try writer.octets(.stateless_reset_token, &token);

    try writer.integerIfNot(.max_idle_timeout, parameters.max_idle_timeout_ms, 0);
    try writer.integerIfNot(.max_udp_payload_size, parameters.max_udp_payload_size, max_udp_payload_size_default);
    try writer.integerIfNot(.initial_max_data, parameters.initial_max_data, 0);
    try writer.integerIfNot(.initial_max_stream_data_bidi_local, parameters.initial_max_stream_data_bidi_local, 0);
    try writer.integerIfNot(.initial_max_stream_data_bidi_remote, parameters.initial_max_stream_data_bidi_remote, 0);
    try writer.integerIfNot(.initial_max_stream_data_uni, parameters.initial_max_stream_data_uni, 0);
    try writer.integerIfNot(.initial_max_streams_bidi, parameters.initial_max_streams_bidi, 0);
    try writer.integerIfNot(.initial_max_streams_uni, parameters.initial_max_streams_uni, 0);
    try writer.integerIfNot(.ack_delay_exponent, parameters.ack_delay_exponent, ack_delay_exponent_default);
    try writer.integerIfNot(.max_ack_delay, parameters.max_ack_delay_ms, max_ack_delay_default);
    try writer.integerIfNot(.active_connection_id_limit, parameters.active_connection_id_limit, active_connection_id_limit_default);
    if (parameters.disable_active_migration) try writer.octets(.disable_active_migration, &.{});
    if (parameters.preferred_address) |address| try writePreferredAddress(&writer, address);

    return writer.offset;
}

fn writePreferredAddress(writer: *Writer, address: PreferredAddress) EncodeError!void {
    var body: [4 + 2 + 16 + 2 + 1 + ConnectionId.octets_max + stateless_reset_token_octets]u8 = undefined;
    @memcpy(body[0..4], &address.ipv4);
    std.mem.writeInt(u16, body[4..6], address.ipv4_port, .big);
    @memcpy(body[6..22], &address.ipv6);
    std.mem.writeInt(u16, body[22..24], address.ipv6_port, .big);
    body[24] = address.connection_id.length;
    @memcpy(body[25..][0..address.connection_id.length], address.connection_id.bytes());
    const token_at = 25 + @as(usize, address.connection_id.length);
    @memcpy(body[token_at..][0..stateless_reset_token_octets], &address.stateless_reset_token);
    try writer.octets(.preferred_address, body[0 .. token_at + stateless_reset_token_octets]);
}

const Writer = struct {
    target: []u8,
    offset: usize = 0,

    fn room(self: *Writer, count: usize) EncodeError![]u8 {
        const end = std.math.add(usize, self.offset, count) catch return error.ValueTooLarge;
        if (end > self.target.len) return error.OutputTooLong;
        const slice = self.target[self.offset..end];
        self.offset = end;
        return slice;
    }

    fn varintValue(self: *Writer, value: u64) EncodeError!void {
        if (value > varint.max) return error.ValueTooLarge;
        const slice = try self.room(varint.encodedLength(value));
        _ = varint.encode(slice, value) catch unreachable; // `room` sized the slice from `encodedLength`, and the range check above bounded the value.
    }

    fn octets(self: *Writer, id: Id, value: []const u8) EncodeError!void {
        try self.varintValue(@intFromEnum(id));
        try self.varintValue(value.len);
        const slice = try self.room(value.len);
        @memcpy(slice, value);
    }

    fn integerIfNot(self: *Writer, id: Id, value: u64, default: u64) EncodeError!void {
        if (value == default) return;
        if (value > varint.max) return error.ValueTooLarge;
        try self.varintValue(@intFromEnum(id));
        try self.varintValue(varint.encodedLength(value));
        try self.varintValue(value);
    }

    fn optionalId(self: *Writer, id: Id, value: ?ConnectionId) EncodeError!void {
        if (value) |present| try self.octets(id, present.bytes());
    }
};

const testing = std.testing;

test "an absent parameter is its default, not zero" {
    const parameters = try parse(&.{});
    try testing.expectEqual(max_udp_payload_size_default, parameters.max_udp_payload_size);
    try testing.expectEqual(ack_delay_exponent_default, parameters.ack_delay_exponent);
    try testing.expectEqual(max_ack_delay_default, parameters.max_ack_delay_ms);
    try testing.expectEqual(active_connection_id_limit_default, parameters.active_connection_id_limit);
    try testing.expectEqual(@as(u64, 0), parameters.initial_max_data);
    try testing.expect(!parameters.disable_active_migration);
}

test "an unknown identifier is skipped by its length" {
    // A GREASE parameter (section 22.3) between two real ones. Refusing it
    // would fail against most deployed servers.
    const wire = [_]u8{
        0x04, 0x04, 0x80, 0x01, 0x00, 0x00, // initial_max_data = 65536
        0x1b, 0x02, 0xaa, 0xbb, //             0x1f * 0 + 0x1b: a GREASE identifier
        0x0e, 0x01, 0x08, //                   active_connection_id_limit = 8
    };
    const parameters = try parse(&wire);
    try testing.expectEqual(@as(u64, 65_536), parameters.initial_max_data);
    try testing.expectEqual(@as(u64, 8), parameters.active_connection_id_limit);
}

test "a duplicate identifier is refused rather than resolved" {
    const wire = [_]u8{ 0x04, 0x01, 0x0a, 0x04, 0x01, 0x0b };
    try testing.expectError(error.Malformed, parse(&wire));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# The value of the active_connection_id_limit parameter MUST be at
//# least 2. An endpoint that receives a value less than 2 MUST close
//# the connection with an error of type TRANSPORT_PARAMETER_ERROR.
//= type=test
test "the ranges section 18.2 states are enforced" {
    // ack_delay_exponent above 20.
    try testing.expectError(error.Malformed, parse(&.{ 0x0a, 0x01, 0x15 }));
    // max_ack_delay at 2^14.
    try testing.expectError(error.Malformed, parse(&.{ 0x0b, 0x04, 0x80, 0x00, 0x40, 0x00 }));
    // max_udp_payload_size below 1200: the peer could not receive a padded
    // Initial packet.
    try testing.expectError(error.Malformed, parse(&.{ 0x03, 0x02, 0x44, 0xaf })); // 1199
    // And 1200 exactly is the floor, not below it.
    try testing.expectEqual(@as(u64, 1_200), (try parse(&.{ 0x03, 0x02, 0x44, 0xb0 })).max_udp_payload_size);
    // active_connection_id_limit below 2.
    try testing.expectError(error.Malformed, parse(&.{ 0x0e, 0x01, 0x01 }));
    // A stateless reset token of the wrong length.
    try testing.expectError(error.Malformed, parse(&.{ 0x02, 0x02, 0xaa, 0xbb }));
    // disable_active_migration with a body.
    try testing.expectError(error.Malformed, parse(&.{ 0x0c, 0x01, 0x00 }));
    // An integer parameter with octets left over.
    try testing.expectError(error.Malformed, parse(&.{ 0x04, 0x02, 0x0a, 0x0b }));
}

test "a length past the end of the extension is truncation" {
    try testing.expectError(error.Truncated, parse(&.{ 0x04, 0x08, 0x00 }));
    try testing.expectError(error.Truncated, parse(&.{0x04}));
}

test "parameters round-trip through encode and parse" {
    const original: Parameters = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 3,
        .max_idle_timeout_ms = 30_000,
        .ack_delay_exponent = 3,
        .max_ack_delay_ms = 25,
        .active_connection_id_limit = 4,
        .disable_active_migration = true,
        .initial_source_connection_id = try ConnectionId.init(&.{ 1, 2, 3, 4 }),
    };

    var target: [256]u8 = @splat(0);
    const written = try encode(&target, &original);
    const decoded = try parse(target[0..written]);

    try testing.expectEqual(original.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(original.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expectEqual(original.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
    try testing.expectEqual(original.active_connection_id_limit, decoded.active_connection_id_limit);
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, decoded.initial_source_connection_id.?.bytes());
    // The defaults were not written, which is what keeps the extension small.
    try testing.expectEqual(max_ack_delay_default, decoded.max_ack_delay_ms);
    try testing.expectEqual(ack_delay_exponent_default, decoded.ack_delay_exponent);
}

test "a preferred address round-trips with both families" {
    const original: Parameters = .{
        .initial_source_connection_id = try ConnectionId.init(&.{0x01}),
        .preferred_address = .{
            .ipv4 = .{ 192, 0, 2, 1 },
            .ipv4_port = 4433,
            .ipv6 = @splat(0),
            .ipv6_port = 0,
            .connection_id = try ConnectionId.init(&.{ 9, 8, 7 }),
            .stateless_reset_token = @splat(0x5a),
        },
    };
    var target: [256]u8 = @splat(0);
    const written = try encode(&target, &original);
    const decoded = try parse(target[0..written]);
    const address = decoded.preferred_address.?;
    try testing.expectEqual(@as(u16, 4433), address.ipv4_port);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &address.ipv4);
    try testing.expect(address.hasIpv4());
    try testing.expect(!address.hasIpv6());
    try testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, address.connection_id.bytes());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# A client MUST NOT include any server-only transport parameter:
//# original_destination_connection_id, preferred_address,
//# retry_source_connection_id, or stateless_reset_token.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
//# A server MUST treat receipt of any of these transport parameters as
//# a connection error of type TRANSPORT_PARAMETER_ERROR.
//= type=test
test "the server-only parameters are refused from a client" {
    var parameters: Parameters = .{ .initial_source_connection_id = try ConnectionId.init(&.{1}) };
    parameters.stateless_reset_token = @splat(0);
    try testing.expectError(error.ServerOnlyParameter, validate(&parameters, .client));
    parameters.stateless_reset_token = null;
    parameters.original_destination_connection_id = try ConnectionId.init(&.{1});
    try testing.expectError(error.ServerOnlyParameter, validate(&parameters, .client));
    // From a server the same parameter is required, not forbidden.
    try validate(&parameters, .server);
}

test "section 7.3's identifiers are required in both directions" {
    const empty: Parameters = .{};
    try testing.expectError(error.MissingConnectionId, validate(&empty, .client));
    const client: Parameters = .{ .initial_source_connection_id = try ConnectionId.init(&.{1}) };
    try validate(&client, .client);
    // A server must also echo the identifier the client first addressed.
    try testing.expectError(error.MissingConnectionId, validate(&client, .server));
}
