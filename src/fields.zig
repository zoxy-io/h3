//! RFC 9114 sections 4.2 and 4.3: what makes a field section a message.
//!
//! Two layers of rule. Section 4.2 is about octets — which bytes may appear in
//! a field name and value, and which fields may not appear at all. Section 4.3
//! is about the section as a whole — which pseudo-headers a request or response
//! must carry, that they come first, and that none repeats.
//!
//! Between them they are the guard against request smuggling. HTTP/3 is
//! routinely translated to HTTP/1.1 at the far end of a proxy, and a field name
//! containing a colon or a value containing CRLF becomes two messages there.
//! The rules exist because the translation cannot be made safe downstream.
//!
//! ## A check, never an enforcement
//!
//! What to do about a malformed message is the consumer's decision, and the two
//! consumers answer differently: zoxy is a proxy and must reject, zrk is
//! measuring a server and may want to record what it got. So this reports and
//! never acts — the same arrangement h2's `fields` has, for the same reason.
//!
//! ## What HTTP/3 changed from HTTP/2, and what it did not
//!
//! The octet rules are RFC 9110's and are the same in both, which is why this
//! file and h2's `fields/syntax.zig` say the same thing twice — a candidate for
//! the same treatment RFC 7541's primitives got, and noted in docs/DESIGN.md
//! rather than done here.
//!
//! What did change: HTTP/3 has no HTTP/2 `:protocol` special case in the base
//! spec, and section 4.2 makes an uppercase field name malformed outright
//! rather than a "SHOULD". That is the one rule most likely to be got wrong by
//! a port of an HTTP/2 validator, so it is checked first.

const std = @import("std");

const assert = @import("assert.zig").assert;

const Field = @import("qpack.zig").Field;

pub const Error = error{
    /// An octet section 4.2 does not permit in a field name, an uppercase
    /// letter among them.
    NameInvalid,
    /// An octet section 4.2 does not permit in a field value, or leading or
    /// trailing whitespace.
    ValueInvalid,
    /// Section 4.2: a connection-specific field. `H3_MESSAGE_ERROR`.
    ConnectionSpecific,
    /// Section 4.3: a pseudo-header this message may not carry, one that
    /// repeats, or one after an ordinary field.
    PseudoInvalid,
    /// Section 4.3.1 or 4.3.2: a required pseudo-header is missing.
    PseudoMissing,
};

/// Section 4.2, via RFC 9110's `token`: the octets a field name may contain.
/// Uppercase is deliberately absent — HTTP/3 field names are lowercase, and a
/// validator that tolerated uppercase would let `Content-Length` and
/// `content-length` be two different fields to whatever it feeds.
fn nameOctetValid(octet: u8) bool {
    return switch (octet) {
        'a'...'z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// RFC 9110's `field-value`: visible characters, spaces and tabs, and obs-text.
/// Notably *not* CR, LF or NUL, which are the octets that split a message when
/// it is written out as HTTP/1.1.
fn valueOctetValid(octet: u8) bool {
    return switch (octet) {
        0x21...0x7e => true, // VCHAR
        ' ', '\t' => true,
        0x80...0xff => true, // obs-text
        else => false,
    };
}

comptime {
    // The octets that make smuggling possible, named so that a change to the
    // ranges above cannot quietly admit one.
    assert(!valueOctetValid('\r'));
    assert(!valueOctetValid('\n'));
    assert(!valueOctetValid(0));
    assert(!nameOctetValid(':'));
    assert(!nameOctetValid('A'));
    assert(!nameOctetValid(' '));
    // And the ones that must stay legal.
    assert(nameOctetValid('a'));
    assert(nameOctetValid('-'));
    assert(valueOctetValid(' '));
    assert(valueOctetValid(0x80));
}

/// Check a field name. A leading colon is the caller's business — `pseudo`
/// tells them apart — so this validates the name past it.
pub fn validateName(name: []const u8) Error!void {
    if (name.len == 0) return error.NameInvalid;
    const body = if (name[0] == ':') name[1..] else name;
    if (body.len == 0) return error.NameInvalid;
    for (body) |octet| {
        if (!nameOctetValid(octet)) return error.NameInvalid;
    }
}

/// Check a field value.
pub fn validateValue(value: []const u8) Error!void {
    for (value) |octet| {
        if (!valueOctetValid(octet)) return error.ValueInvalid;
    }
    // RFC 9110 section 5.5: a field value has no leading or trailing
    // whitespace. Sending one is how a value acquires a different meaning after
    // an intermediary trims it.
    if (value.len == 0) return;
    if (value[0] == ' ' or value[0] == '\t') return error.ValueInvalid;
    if (value[value.len - 1] == ' ' or value[value.len - 1] == '\t') return error.ValueInvalid;
}

/// True when the field is a pseudo-header.
pub fn pseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == ':';
}

/// Section 4.2: fields that exist to describe a single hop and cannot cross
/// one. `Transfer-Encoding` is the sharpest — it is HTTP/1.1's framing, and a
/// message carrying both it and a length is the classic smuggling pair.
fn connectionSpecific(name: []const u8) bool {
    const forbidden = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    };
    for (forbidden) |one| {
        if (std.mem.eql(u8, name, one)) return true;
    }
    return false;
}

/// The pseudo-headers RFC 9114 sections 4.3.1 and 4.3.2 define.
const Pseudo = enum {
    method,
    scheme,
    authority,
    path,
    status,
    /// RFC 9220's extended CONNECT.
    protocol,

    fn parse(name: []const u8) ?Pseudo {
        const table = [_]struct { text: []const u8, value: Pseudo }{
            .{ .text = ":method", .value = .method },
            .{ .text = ":scheme", .value = .scheme },
            .{ .text = ":authority", .value = .authority },
            .{ .text = ":path", .value = .path },
            .{ .text = ":status", .value = .status },
            .{ .text = ":protocol", .value = .protocol },
        };
        for (table) |entry| {
            if (std.mem.eql(u8, name, entry.text)) return entry.value;
        }
        return null;
    }
};

pub const Kind = enum { request, response };

/// Walks a field section once, checking section 4.3's rules as it goes.
///
/// Fed one field at a time rather than a list, because a decoded field's name
/// and value borrow from a buffer the next field reuses — the same constraint
/// `qpack.field_line.Iterator` imposes, and the reason both are iterators.
pub const MessageValidator = struct {
    kind: Kind,
    seen: std.EnumSet(Pseudo) = .initEmpty(),
    ordinary_seen: bool = false,
    /// A CONNECT request is the one shape with different required
    /// pseudo-headers (section 4.4), so the method is remembered.
    is_connect: bool = false,

    pub fn init(kind: Kind) MessageValidator {
        return .{ .kind = kind };
    }

    pub fn field(self: *MessageValidator, one: *const Field) Error!void {
        try validateName(one.name);
        try validateValue(one.value);

        if (!pseudo(one.name)) {
            // Section 4.2's TE exception: it may appear, and only with the one
            // value that means something in HTTP/3.
            if (std.mem.eql(u8, one.name, "te")) {
                if (!std.mem.eql(u8, one.value, "trailers")) return error.ConnectionSpecific;
            } else if (connectionSpecific(one.name)) {
                return error.ConnectionSpecific;
            }
            self.ordinary_seen = true;
            return;
        }

        // Section 4.3: all pseudo-headers precede every ordinary field, so a
        // receiver can decide what kind of message it has without buffering.
        if (self.ordinary_seen) return error.PseudoInvalid;

        const which = Pseudo.parse(one.name) orelse return error.PseudoInvalid;
        if (self.seen.contains(which)) return error.PseudoInvalid;
        self.seen.insert(which);

        // A pseudo-header belonging to the other kind of message.
        switch (which) {
            .status => if (self.kind != .response) return error.PseudoInvalid,
            .method, .scheme, .authority, .path, .protocol => {
                if (self.kind != .request) return error.PseudoInvalid;
            },
        }
        if (which == .method and std.mem.eql(u8, one.value, "CONNECT")) self.is_connect = true;
        // Section 4.3.1: an empty `:path` is not a path.
        if (which == .path and one.value.len == 0) return error.PseudoInvalid;
    }

    /// Check what the section as a whole had to carry.
    pub fn finish(self: *const MessageValidator) Error!void {
        switch (self.kind) {
            .response => {
                if (!self.seen.contains(.status)) return error.PseudoMissing;
            },
            .request => {
                if (!self.seen.contains(.method)) return error.PseudoMissing;
                // Section 4.4: a CONNECT request carries `:authority` and
                // neither `:scheme` nor `:path`, because it names a tunnel
                // rather than a resource.
                if (self.is_connect) {
                    if (!self.seen.contains(.authority)) return error.PseudoMissing;
                    if (self.seen.contains(.scheme) or self.seen.contains(.path)) {
                        return error.PseudoInvalid;
                    }
                    return;
                }
                if (!self.seen.contains(.scheme)) return error.PseudoMissing;
                if (!self.seen.contains(.path)) return error.PseudoMissing;
            },
        }
    }
};

const testing = std.testing;

fn validate(kind: Kind, fields: []const Field) Error!void {
    var validator: MessageValidator = .init(kind);
    for (fields) |one| try validator.field(&one);
    try validator.finish();
}

test "a well-formed request and response" {
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "zrk" },
    });
    try validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
    });
}

test "section 4.2: an uppercase field name is malformed" {
    // The rule most likely to be lost in a port of an HTTP/2 validator, where
    // it was softer. Without it `Content-Length` and `content-length` are two
    // fields to whatever this feeds.
    try testing.expectError(error.NameInvalid, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "Content-Length", .value = "0" },
    }));
}

test "the octets that would split a message downstream are refused" {
    // A field value carrying CRLF becomes two messages when written out as
    // HTTP/1.1, which is the whole reason these rules exist.
    try testing.expectError(error.ValueInvalid, validateValue("one\r\nsmuggled: yes"));
    try testing.expectError(error.ValueInvalid, validateValue("has\x00nul"));
    try testing.expectError(error.NameInvalid, validateName("has:colon"));
    try testing.expectError(error.NameInvalid, validateName("has space"));
    // And obs-text stays legal, because RFC 9110 says so.
    try validateValue("caf\xc3\xa9");
}

test "a value may not begin or end in whitespace" {
    try testing.expectError(error.ValueInvalid, validateValue(" leading"));
    try testing.expectError(error.ValueInvalid, validateValue("trailing "));
    try testing.expectError(error.ValueInvalid, validateValue("\ttab"));
    try validateValue("in the middle is fine");
    try validateValue("");
}

test "section 4.2: connection-specific fields may not cross a hop" {
    for ([_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" }) |name| {
        try testing.expectError(error.ConnectionSpecific, validate(.response, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = name, .value = "x" },
        }));
    }
    // TE is the exception, and only with the one value HTTP/3 gives meaning.
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "trailers" },
    });
    try testing.expectError(error.ConnectionSpecific, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "gzip" },
    }));
}

test "section 4.3: pseudo-headers come first, once each, and belong to a kind" {
    // After an ordinary field.
    try testing.expectError(error.PseudoInvalid, validate(.response, &.{
        .{ .name = "server", .value = "x" },
        .{ .name = ":status", .value = "200" },
    }));
    // Twice.
    try testing.expectError(error.PseudoInvalid, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "404" },
    }));
    // A response's pseudo-header in a request.
    try testing.expectError(error.PseudoInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":status", .value = "200" },
    }));
    // One nobody has heard of.
    try testing.expectError(error.PseudoInvalid, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":invented", .value = "x" },
    }));
}

test "section 4.3: what a message must carry" {
    try testing.expectError(error.PseudoMissing, validate(.response, &.{
        .{ .name = "server", .value = "x" },
    }));
    try testing.expectError(error.PseudoMissing, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    }));
    try testing.expectError(error.PseudoInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "" },
    }));
}

test "section 4.4: CONNECT names a tunnel rather than a resource" {
    try validate(.request, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    });
    // A CONNECT with a scheme or a path is describing something it cannot.
    try testing.expectError(error.PseudoInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.PseudoMissing, validate(.request, &.{
        .{ .name = ":method", .value = "CONNECT" },
    }));
}

test "a decoded section validates field by field" {
    // The shape a consumer actually uses: decode and validate in one pass,
    // because a field's name and value borrow from a buffer the next one reuses.
    const qpack = @import("qpack.zig");
    var wire: [256]u8 = undefined;
    const written = try qpack.field_line.encode(&wire, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    });

    var buffer: [256]u8 = undefined;
    var iterator = try qpack.field_line.iterate(wire[0..written], &buffer, 1 << 16);
    var validator: MessageValidator = .init(.response);
    while (try iterator.next()) |one| try validator.field(&one);
    try validator.finish();
}
