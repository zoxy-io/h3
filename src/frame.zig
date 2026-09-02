//! RFC 9114 section 7: the HTTP/3 frame layer.
//!
//! Type, Length, Payload — all three variable-length integers or octets, on top
//! of a QUIC stream rather than a connection. Two consequences follow, and they
//! are what make this codec look different from h2's.
//!
//! ## A frame can be larger than any buffer
//!
//! A DATA frame's length is a 62-bit integer and its payload arrives in
//! whatever pieces QUIC delivers. So there is no `parse(frame) -> Frame`
//! here: `parseHeader` reads the type and the length, and the payload is the
//! caller's to consume as it arrives. A codec that insisted on a whole frame
//! would need a buffer the size of the largest response body anyone might send,
//! which is the memory bug the design exists to avoid.
//!
//! ## An unknown frame type is skippable, and must be skipped
//!
//! Unlike QUIC frames, which carry no length and therefore cannot be skipped
//! (RFC 9000 section 12.4), an HTTP/3 frame always states its length. Section
//! 9 requires an unknown type to be *ignored*, and section 7.2.8 reserves a
//! whole family of them for the purpose. `Type.reserved` names that family, and
//! `Type.known` is what a `switch` asks.
//!
//! The exception is the four types RFC 9114 section 11.2.1 marks reserved to
//! keep HTTP/2's numbering from being reused: 0x02, 0x06, 0x08 and 0x09 were
//! PRIORITY, PING, WINDOW_UPDATE and CONTINUATION in HTTP/2, and receiving one
//! is `H3_FRAME_UNEXPECTED` rather than something to skip. That rule exists so
//! that a proxy translating between the two versions cannot pass a frame
//! through unchanged and have it mean something else.

const std = @import("std");

const assert = @import("assert.zig").assert;
const varint = @import("varint.zig");

/// RFC 9114 section 11.2.1's frame type registry.
pub const Type = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,

    /// Section 11.2.1: the four values HTTP/2 used for frames HTTP/3 does not
    /// have. Receiving one is a connection error of type `H3_FRAME_UNEXPECTED`,
    /// not an unknown type to ignore.
    pub fn isHttp2Reserved(frame_type: Type) bool {
        return switch (@intFromEnum(frame_type)) {
            0x02, 0x06, 0x08, 0x09 => true,
            else => false,
        };
    }

    /// Section 7.2.8: `0x1f * N + 0x21`, the family an endpoint may send to
    /// check that its peer really does ignore what it does not know.
    pub fn isReserved(frame_type: Type) bool {
        const value = @intFromEnum(frame_type);
        if (value < 0x21) return false;
        return (value - 0x21) % 0x1f == 0;
    }

    pub fn known(frame_type: Type) bool {
        return switch (frame_type) {
            .data, .headers, .cancel_push, .settings, .push_promise, .goaway, .max_push_id => true,
            _ => false,
        };
    }

    /// Section 6.2.1: which frames may appear on the control stream, and which
    /// may not appear anywhere else. Getting this wrong is how a SETTINGS frame
    /// on a request stream becomes an accepted reconfiguration mid-request.
    pub fn allowedOnControlStream(frame_type: Type) bool {
        return switch (frame_type) {
            .cancel_push, .settings, .goaway, .max_push_id => true,
            .data, .headers, .push_promise => false,
            _ => true, // Unknown types are ignored wherever they appear.
        };
    }

    pub fn allowedOnRequestStream(frame_type: Type) bool {
        return switch (frame_type) {
            .data, .headers, .push_promise => true,
            .cancel_push, .settings, .goaway, .max_push_id => false,
            _ => true,
        };
    }
};

/// A frame's type and length, and how many octets the two of them took.
pub const Header = struct {
    frame_type: Type,
    /// Octets of payload following this header.
    length: u64,
    /// Octets the type and length fields occupied, 2 to 16.
    octets: u8,
};

pub const ParseError = error{
    /// The header is not all here yet. On a stream this is ordinary — more
    /// octets are coming — which is why it is a separate error from the two
    /// below rather than a malformed frame.
    Incomplete,
    /// A type or length encoded in more octets than it needs. Section 7.1 does
    /// not require minimal encodings the way RFC 9000 section 12.4 does, so
    /// this is stricter than the letter of the specification and deliberately
    /// so: a type with four spellings is four ways past a `switch`, and every
    /// implementation in the wild writes the short one.
    NotMinimal,
    /// One of section 11.2.1's HTTP/2 carry-overs. `H3_FRAME_UNEXPECTED`.
    Http2Reserved,
};

/// Read a frame's type and length off the front of `source`.
pub fn parseHeader(source: []const u8) ParseError!Header {
    const type_decoded = varint.decodeMinimal(source) catch |err| return switch (err) {
        error.Incomplete => error.Incomplete,
        error.NotMinimal => error.NotMinimal,
    };
    const frame_type: Type = @enumFromInt(type_decoded.value);
    if (frame_type.isHttp2Reserved()) return error.Http2Reserved;

    const length_decoded = varint.decodeMinimal(source[type_decoded.octets..]) catch |err| return switch (err) {
        error.Incomplete => error.Incomplete,
        error.NotMinimal => error.NotMinimal,
    };

    const octets = type_decoded.octets + length_decoded.octets;
    assert(octets >= 2);
    assert(octets <= 2 * varint.octets_max);
    return .{ .frame_type = frame_type, .length = length_decoded.value, .octets = octets };
}

pub const EncodeError = error{
    /// `target` cannot hold the header.
    OutputTooLong,
    /// A length past what a variable-length integer can carry.
    ValueTooLarge,
};

/// Write a frame header. The payload is the caller's to write after it, which
/// is what lets a DATA frame's body be streamed rather than buffered.
pub fn writeHeader(target: []u8, frame_type: Type, length: u64) EncodeError!u8 {
    if (length > varint.max) return error.ValueTooLarge;
    const type_value = @intFromEnum(frame_type);
    if (type_value > varint.max) return error.ValueTooLarge;

    const octets = varint.encodedLength(type_value) + varint.encodedLength(length);
    if (target.len < octets) return error.OutputTooLong;
    const written_type = varint.encode(target, type_value) catch unreachable; // Bounded by the two checks above.
    const written_length = varint.encode(target[written_type..], length) catch unreachable; // Same.
    assert(written_type + written_length == octets);
    return octets;
}

/// RFC 9114 section 7.2.4.1's settings identifiers, plus RFC 9220's.
pub const Setting = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    /// RFC 9220: extended CONNECT.
    enable_connect_protocol = 0x08,
    _,

    /// Section 11.2.2: the identifiers HTTP/2 used for settings HTTP/3 does not
    /// have. Receiving one is `H3_SETTINGS_ERROR`, for the same reason the
    /// reserved frame types are an error — so that a translating proxy cannot
    /// pass one through and have it mean something else.
    pub fn isHttp2Reserved(setting: Setting) bool {
        return switch (@intFromEnum(setting)) {
            0x02, 0x03, 0x04, 0x05 => true,
            else => false,
        };
    }

    /// Section 7.2.4.1: the same `0x1f * N + 0x21` family as the frame types.
    pub fn isReserved(setting: Setting) bool {
        const value = @intFromEnum(setting);
        if (value < 0x21) return false;
        return (value - 0x21) % 0x1f == 0;
    }
};

pub const SettingsError = error{
    /// A field runs past the end of the payload.
    Truncated,
    /// One of section 11.2.2's HTTP/2 carry-overs, or a repeated identifier.
    /// Both are `H3_SETTINGS_ERROR`.
    Invalid,
};

pub const SettingPair = struct {
    identifier: Setting,
    value: u64,
};

/// Walks a SETTINGS frame's payload.
///
/// An iterator rather than a struct of known settings, for the same reason h2's
/// header fields are an iterator: the payload may carry identifiers this
/// package has never heard of, and a consumer may care about ones it does not.
/// Duplicate detection is the consumer's, because "which duplicates matter" is
/// a policy question — section 7.2.4 makes any repeat an error, but a proxy
/// forwarding settings and a client reading them do different things about it.
pub const SettingsIterator = struct {
    payload: []const u8,
    offset: usize = 0,

    pub fn init(payload: []const u8) SettingsIterator {
        return .{ .payload = payload };
    }

    pub fn next(self: *SettingsIterator) SettingsError!?SettingPair {
        assert(self.offset <= self.payload.len);
        if (self.offset == self.payload.len) return null;

        const identifier = try self.varint();
        const value = try self.varint();
        const setting: Setting = @enumFromInt(identifier);
        if (setting.isHttp2Reserved()) return error.Invalid;
        return .{ .identifier = setting, .value = value };
    }

    fn varint(self: *SettingsIterator) SettingsError!u64 {
        const decoded = varint_module.decode(self.payload[self.offset..]) catch return error.Truncated;
        self.offset += decoded.octets;
        assert(self.offset <= self.payload.len);
        return decoded.value;
    }

    const varint_module = @import("varint.zig");
};

/// Write one setting into a SETTINGS payload, returning its length.
pub fn writeSetting(target: []u8, setting: Setting, value: u64) EncodeError!u8 {
    return writeHeader(target, @enumFromInt(@intFromEnum(setting)), value);
}

/// The payload of a frame whose whole body is one variable-length integer:
/// CANCEL_PUSH (section 7.2.3), MAX_PUSH_ID (7.2.7), and GOAWAY (7.2.6).
///
/// GOAWAY's single field is a stream identifier from a server and a push
/// identifier from a client, which is a distinction the caller makes and this
/// function cannot.
pub fn parseSingleVarint(payload: []const u8) SettingsError!u64 {
    const decoded = varint.decode(payload) catch return error.Truncated;
    // Section 7.2.3, 7.2.6 and 7.2.7 all make a payload of any other length a
    // frame error, and the check is here rather than at three call sites.
    if (decoded.octets != payload.len) return error.Invalid;
    return decoded.value;
}

const testing = std.testing;

test "a frame header is a type and a length" {
    const header = try parseHeader(&.{ 0x01, 0x40, 0x80 });
    try testing.expectEqual(Type.headers, header.frame_type);
    try testing.expectEqual(@as(u64, 128), header.length);
    try testing.expectEqual(@as(u8, 3), header.octets);
}

test "a header that has not all arrived is incomplete, not malformed" {
    // The distinction the stream layer depends on: more octets are coming.
    try testing.expectError(error.Incomplete, parseHeader(&.{}));
    try testing.expectError(error.Incomplete, parseHeader(&.{0x01}));
    try testing.expectError(error.Incomplete, parseHeader(&.{ 0x01, 0x40 }));
}

test "HTTP/2's leftover frame types are an error, not an unknown type" {
    // Section 11.2.1: 0x02 was PRIORITY, 0x06 PING, 0x08 WINDOW_UPDATE, 0x09
    // CONTINUATION. Skipping one would let a translating proxy pass a frame
    // through that means something else on the other side.
    for ([_]u8{ 0x02, 0x06, 0x08, 0x09 }) |value| {
        try testing.expectError(error.Http2Reserved, parseHeader(&.{ value, 0x00 }));
    }
}

test "an unknown type is skippable because it carries its length" {
    const header = try parseHeader(&.{ 0x21, 0x04, 0xde, 0xad, 0xbe, 0xef });
    try testing.expect(!header.frame_type.known());
    try testing.expect(header.frame_type.isReserved());
    try testing.expectEqual(@as(u64, 4), header.length);
    // Which is the whole difference from a QUIC frame: there is a length to
    // skip by.
    try testing.expectEqual(@as(usize, 6), header.octets + header.length);
}

test "the reserved family is what section 7.2.8 describes" {
    var n: u64 = 0;
    while (n < 8) : (n += 1) {
        const frame_type: Type = @enumFromInt(0x1f * n + 0x21);
        try testing.expect(frame_type.isReserved());
        try testing.expect(!frame_type.known());
    }
    try testing.expect(!Type.data.isReserved());
    try testing.expect(!Type.max_push_id.isReserved());
}

test "a non-minimal type or length is refused" {
    try testing.expectError(error.NotMinimal, parseHeader(&.{ 0x40, 0x01, 0x00 }));
    try testing.expectError(error.NotMinimal, parseHeader(&.{ 0x01, 0x40, 0x01 }));
}

test "where a frame is allowed depends on the stream it arrived on" {
    // A SETTINGS frame on a request stream would be a reconfiguration in the
    // middle of a request; a DATA frame on the control stream would be a body
    // for no request.
    try testing.expect(Type.settings.allowedOnControlStream());
    try testing.expect(!Type.settings.allowedOnRequestStream());
    try testing.expect(Type.data.allowedOnRequestStream());
    try testing.expect(!Type.data.allowedOnControlStream());
    try testing.expect(Type.headers.allowedOnRequestStream());
    try testing.expect(!Type.goaway.allowedOnRequestStream());
    // An unknown type is ignored wherever it lands.
    const unknown: Type = @enumFromInt(0x21);
    try testing.expect(unknown.allowedOnControlStream());
    try testing.expect(unknown.allowedOnRequestStream());
}

test "a written header parses back" {
    var target: [16]u8 = @splat(0);
    const octets = try writeHeader(&target, .data, 1_000_000);
    const header = try parseHeader(target[0..octets]);
    try testing.expectEqual(Type.data, header.frame_type);
    try testing.expectEqual(@as(u64, 1_000_000), header.length);
    try testing.expectEqual(octets, header.octets);
}

test "a SETTINGS payload walks as pairs" {
    var target: [32]u8 = @splat(0);
    var offset: usize = 0;
    offset += try writeSetting(target[offset..], .qpack_max_table_capacity, 4096);
    offset += try writeSetting(target[offset..], .max_field_section_size, 65_536);
    offset += try writeSetting(target[offset..], .qpack_blocked_streams, 16);

    var iterator: SettingsIterator = .init(target[0..offset]);
    const first = (try iterator.next()).?;
    try testing.expectEqual(Setting.qpack_max_table_capacity, first.identifier);
    try testing.expectEqual(@as(u64, 4096), first.value);
    const second = (try iterator.next()).?;
    try testing.expectEqual(Setting.max_field_section_size, second.identifier);
    try testing.expectEqual(@as(u64, 65_536), second.value);
    const third = (try iterator.next()).?;
    try testing.expectEqual(Setting.qpack_blocked_streams, third.identifier);
    try testing.expectEqual(@as(?SettingPair, null), try iterator.next());
}

test "HTTP/2's leftover settings identifiers are a settings error" {
    for ([_]u8{ 0x02, 0x03, 0x04, 0x05 }) |value| {
        var iterator: SettingsIterator = .init(&.{ value, 0x01 });
        try testing.expectError(error.Invalid, iterator.next());
    }
}

test "a SETTINGS payload cut mid-pair is truncated" {
    var iterator: SettingsIterator = .init(&.{0x01});
    try testing.expectError(error.Truncated, iterator.next());
}

test "the single-integer frames refuse a payload of any other length" {
    try testing.expectEqual(@as(u64, 7), try parseSingleVarint(&.{0x07}));
    try testing.expectError(error.Invalid, parseSingleVarint(&.{ 0x07, 0x00 }));
    try testing.expectError(error.Truncated, parseSingleVarint(&.{}));
}
