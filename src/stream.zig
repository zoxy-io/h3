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

//= https://www.rfc-editor.org/rfc/rfc9114#section-2.2
//# The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
//# "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
//# "OPTIONAL" in this document are to be interpreted as described in
//# BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
//# capitals, as shown here.
//= type=exception
//= reason=RFC 8174's boilerplate: it says how the keywords in the rest of the document are to be read and requires no behaviour of an implementation. It is here because the ledger's sentence-splitter counts any sentence carrying a keyword, and an uncited line in the report should mean a rule nobody looked at

// RFC 9114 section 3: everything that has to be true before a stream type
// means anything. None of it is this package's — the TLS handshake, the ALPN
// and SNI it carries, and the certificate that decides whether a server is
// authoritative for an origin all sit on the consumer's side of the seam, per
// docs/DESIGN.md sections 3 and 4.
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.1
//# Upon receiving a
//# server certificate in the TLS handshake, the client MUST verify that
//# the certificate is an acceptable match for the URI's origin server
//# using the process described in Section 4.3.4 of [HTTP].  If the
//# certificate cannot be verified with respect to the URI's origin
//# server, the client MUST NOT consider the server authoritative for
//# that origin.
//= type=exception
//= reason=a certificate never crosses this package's seam: docs/DESIGN.md section 4 puts the TLS engine in the consumer, so nothing here sees a certificate, an origin, or the URI a request was made for
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.1.2
//# Prior to making requests for an origin whose scheme is not "https",
//# the client MUST ensure the server is willing to serve that scheme.
//= type=exception
//= reason=which schemes a server is willing to serve is learned from an Alt-Svc field or from a prior response, neither of which this package reads; it validates a field section and makes no request. See docs/DESIGN.md section 3
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
//# HTTP/3 clients MUST support a mechanism to indicate the
//# target host to the server during the TLS handshake.  If the server is
//# identified by a domain name ([DNS-TERMS]), clients MUST send the
//# Server Name Indication (SNI; [RFC6066]) TLS extension unless an
//# alternative mechanism to indicate the target host is used.
//= type=exception
//= reason=SNI is a TLS extension and docs/DESIGN.md section 4 puts the TLS engine on the consumer's side of the seam; this package hands the handshake no bytes of its own
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
//# To use an existing connection for a new origin, clients MUST validate
//# the certificate presented by the server for the new origin server
//# using the process described in Section 4.3.4 of [HTTP].  This implies
//# that clients will need to retain the server certificate and any
//# additional information needed to verify that certificate; clients
//# that do not do so will be unable to reuse the connection for
//# additional origins.
//# If the certificate is not acceptable with regard to the new origin
//# for any reason, the connection MUST NOT be reused and a new
//# connection SHOULD be established for the new origin.
//= type=exception
//= reason=choosing which connection carries a request for which origin is the consumer's, and the certificate that decision rests on never crosses the seam of docs/DESIGN.md section 4

const std = @import("std");

const assert = @import("assert.zig").assert;
const varint = @import("varint.zig");

/// RFC 9114 section 11.2.4's stream type registry, plus RFC 9204 section 4.2's
/// two QPACK streams.
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//# Clients MUST treat
//# receipt of a server-initiated bidirectional stream as a connection
//# error of type H3_STREAM_CREATION_ERROR unless such an extension has
//# been negotiated.
//= type=exception
//= reason=which endpoint opened a stream, and whether this one is the client, are facts about a connection; the HTTP/3 connection layer that would hold them is docs/DESIGN.md section 6's next slice, and this file reads the first octets of a stream it is handed
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# Therefore, the transport parameters sent by both clients
//# and servers MUST allow the peer to create at least three
//# unidirectional streams.
//= type=exception
//= reason=QUIC transport parameters are the consumer's to advertise, per docs/DESIGN.md section 3's seam; this file classifies a stream type and opens no stream
//= https://www.rfc-editor.org/rfc/rfc9114#section-11.2.4
//# In addition to common fields as described in Section 11.2, permanent
//# registrations in this registry MUST include the following fields:
//# Stream Type:  A name or label for the stream type.
//= type=exception
//= reason=an instruction to IANA and to the author of a registration rather than to an implementation; Type transcribes the registry's contents, which is all an implementation can do with it
//= https://www.rfc-editor.org/rfc/rfc9114#section-11.2.4
//# Specifications for permanent registrations MUST include a description
//# of the stream type, including the layout and semantics of the stream
//# contents.
//= type=exception
//= reason=a requirement on the specification that registers a stream type, not on code; this package implements the two types Table 5 registers and names the two RFC 9204 section 4.2 adds
pub const Type = enum(u64) {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# A control stream is indicated by a stream type of 0x00.  Data on this
    //# stream consists of HTTP/3 frames, as defined in Section 7.2.
    //# Each side MUST initiate a single control stream at the beginning of
    //# the connection and send its SETTINGS frame as the first frame on this
    //# stream.  If the first frame of the control stream is any other frame
    //# type, this MUST be treated as a connection error of type
    //# H3_MISSING_SETTINGS.
    //= type=exception
    //= reason=initiating the control stream and sequencing SETTINGS onto it is the HTTP/3 connection layer's, which docs/DESIGN.md section 6 lists as next rather than built; Type.control is the number it will write first
    control = 0x00,
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
    //# Only servers can push; if a server receives a client-initiated push
    //# stream, this MUST be treated as a connection error of type
    //# H3_STREAM_CREATION_ERROR.
    //= type=exception
    //= reason=server push is not implemented and is not on docs/DESIGN.md section 6's list; the type is named so an unknown-stream path can be told apart from a push one when it is
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
    //# Each push ID MUST only be used once in a push stream header.  If a
    //# client detects that a push stream header includes a push ID that was
    //# used in another push stream header, the client MUST treat this as a
    //# connection error of type H3_ID_ERROR.
    //= type=exception
    //= reason=server push is not implemented and remembering which push IDs have been seen is connection state; docs/DESIGN.md section 6 does not list push at all, and Type.push exists so an unknown stream can be told apart from a push one
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# A client MUST treat receipt of a push stream as a connection
    //# error of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or
    //# when the stream references a push ID that is greater than the maximum
    //# push ID.
    //= type=exception
    //= reason=server push is not implemented; the maximum push ID this endpoint sent is connection state the HTTP/3 layer docs/DESIGN.md section 6 lists as next would hold
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# When the
    //# same push ID is promised on multiple request streams, the
    //# decompressed request field sections MUST contain the same fields in
    //# the same order, and both the name and the value in each field MUST be
    //# identical.
    //= type=exception
    //= reason=server push is not implemented, and comparing two field sections would mean retaining one; fields.zig validates a section as it streams past and keeps no field, per its own header
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# The server MUST include a value in the :authority pseudo-header field
    //# for which the server is authoritative.
    //= type=exception
    //= reason=server push is not implemented, and which origins a server is authoritative for is the consumer's knowledge: it holds the certificate, per docs/DESIGN.md section 4
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# If the client has not yet
    //# validated the connection for the origin indicated by the pushed
    //# request, it MUST perform the same verification process it would do
    //# before sending a request for that origin on the connection; see
    //# Section 3.3.  If this verification fails, the client MUST NOT
    //# consider the server authoritative for that origin.
    //= type=exception
    //= reason=server push is not implemented, and the verification named here is section 3.3's certificate check, which docs/DESIGN.md section 4 leaves to the consumer's TLS engine
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# Any
    //# corresponding responses MUST NOT be used or cached.
    //= type=exception
    //= reason=server push is not implemented and this package has no cache; storing a response is the consumer's, per docs/DESIGN.md section 3
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# Pushed responses that are not cacheable MUST NOT be stored by any
    //# HTTP cache.
    //= type=exception
    //= reason=server push is not implemented and this package has no cache; cacheability is decided from response fields by the consumer that would store them
    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.4
    //# Where multiple tenants share space on the same server, that server
    //# MUST ensure that tenants are not able to push representations of
    //# resources that they do not have authority over.
    //= type=exception
    //= reason=server push is not implemented, so this package pushes nothing on any tenant's behalf; which resources a tenant has authority over is a deployment's question rather than a codec's
    push = 0x01,
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    //# Each endpoint
    //# MUST initiate, at most, one encoder stream and, at most, one decoder
    //# stream.  Receipt of a second instance of either stream type MUST be
    //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
    //= type=exception
    //= reason=the QPACK encoder and decoder streams carry dynamic table instructions, which this package does not have: it advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 and decodes static-only, per docs/DESIGN.md section 6
    qpack_encoder = 0x02,
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    //# The sender MUST NOT close either of these streams, and the receiver
    //# MUST NOT request that the sender close either of these streams.
    //# Closure of either unidirectional stream type MUST be treated as a
    //# connection error of type H3_CLOSED_CRITICAL_STREAM.
    //= type=exception
    //= reason=the QPACK encoder and decoder streams are not built, per docs/DESIGN.md section 6; Type.critical names them so the connection layer can raise H3_CLOSED_CRITICAL_STREAM when it exists
    qpack_decoder = 0x03,
    _,

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    //# Recipients of unknown stream types MUST
    //# either abort reading of the stream or discard incoming data without
    //# further processing.
    //= type=exception
    //= reason=aborting a read or discarding a stream's data is an action on a QUIC stream, which docs/DESIGN.md section 3 puts on the consumer's side of the seam; Type.known is what tells it which streams those are
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    //# The recipient MUST NOT consider unknown stream types
    //# to be a connection error of any kind.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-9
    //# Implementations MUST discard data or
    //# abort reading on unidirectional streams that have unknown or
    //# unsupported types.
    //= type=exception
    //= reason=discarding a stream's data or aborting its read is an action on a QUIC stream, which docs/DESIGN.md section 3 puts on the consumer's side of the seam; Type.known is the classification it asks
    pub fn known(stream_type: Type) bool {
        return switch (stream_type) {
            .control, .push, .qpack_encoder, .qpack_decoder => true,
            _ => false,
        };
    }

    /// Section 6.2.3: `0x1f * N + 0x21`.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
    //# Stream types of the format 0x1f * N + 0x21 for non-negative integer
    //# values of N are reserved to exercise the requirement that unknown
    //# types be ignored.  These streams have no semantics, and they can be
    //# sent when application-layer padding is desired.  They MAY also be
    //# sent on connections where no data is currently being transferred.
    //# Endpoints MUST NOT consider these streams to have any meaning upon
    //# receipt.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-11.2.4
    //# Each code of the format 0x1f * N + 0x21 for non-negative integer
    //# values of N (that is, 0x21, 0x40, ..., through 0x3ffffffffffffffe)
    //# MUST NOT be assigned by IANA and MUST NOT appear in the listing of
    //# assigned values.
    //= type=exception
    //= reason=an instruction to IANA rather than to an implementation; isReserved is what this package does with the family IANA is told to leave unassigned, and the test below walks it
    pub fn isReserved(stream_type: Type) bool {
        const value = @intFromEnum(stream_type);
        if (value < 0x21) return false;
        return (value - 0x21) % 0x1f == 0;
    }

    /// Sections 6.2.1 and 6.2.2, and RFC 9204 section 4.2: exactly one of each
    /// of these may exist per direction, and closing one is
    /// `H3_CLOSED_CRITICAL_STREAM`. A second is `H3_STREAM_CREATION_ERROR`.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# Only one control stream per peer is permitted;
    //# receipt of a second stream claiming to be a control stream MUST be
    //# treated as a connection error of type H3_STREAM_CREATION_ERROR.  The
    //# sender MUST NOT close the control stream, and the receiver MUST NOT
    //# request that the sender close the control stream.  If either control
    //# stream is closed at any point, this MUST be treated as a connection
    //# error of type H3_CLOSED_CRITICAL_STREAM.
    //= type=exception
    //= reason=counting control streams and noticing one close are facts about a connection, and the HTTP/3 connection layer that would hold them is next rather than built (docs/DESIGN.md section 6); critical() is the classification it will ask
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# A receiver MUST tolerate unidirectional streams being
//# closed or reset prior to the reception of the unidirectional stream
//# header.
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# However, stream types that could modify the state or
//# semantics of existing protocol components, including QPACK or other
//# extensions, MUST NOT be sent until the peer is known to support them.
//= type=exception
//= reason=knowing whether a peer supports a stream type needs its SETTINGS, which the connection layer docs/DESIGN.md section 6 lists as next holds; write() encodes a type and decides nothing about when to send it
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# A receiver MUST tolerate unidirectional streams being
//# closed or reset prior to the reception of the unidirectional stream
//# header.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
//# Stream types of the format 0x1f * N + 0x21 for non-negative integer
//# values of N are reserved to exercise the requirement that unknown
//# types be ignored.  These streams have no semantics, and they can be
//# sent when application-layer padding is desired.  They MAY also be
//# sent on connections where no data is currently being transferred.
//# Endpoints MUST NOT consider these streams to have any meaning upon
//# receipt.
//= type=test
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# The recipient MUST NOT consider unknown stream types
//# to be a connection error of any kind.
//= type=test
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
