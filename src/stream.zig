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
//# Connectivity problems (e.g., blocking UDP) can result in a failure to
//# establish a QUIC connection; clients SHOULD attempt to use TCP-based
//# versions of HTTP in this case.
//= type=exception
//= reason=falling back to a TCP-based HTTP version means opening a TCP connection and speaking HTTP/1.1 or HTTP/2, neither of which exists here: docs/DESIGN.md section 3's seam takes datagrams and the no-I/O rule forbids a socket outright. The consumer is the party that chose QUIC and is the only one that can choose otherwise
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
//# If the reason the certificate cannot be verified might apply to other
//# origins already associated with the connection, the client SHOULD
//# revalidate the server certificate for those origins.
//= type=exception
//= reason=revalidating a certificate is the TLS engine's, and this package links neither of the two consumers use: docs/DESIGN.md section 4 puts the engine on their side of the seam, so no certificate and no list of associated origins exists here to revalidate
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
//# Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
//# address and UDP port, where the IP address and port might be derived
//# from a URI, a selected alternative service ([ALTSVC]), a configured
//# proxy, or name resolution of any of these.
//= type=exception
//= reason=this package opens no connection and knows no address: docs/DESIGN.md section 3's seam takes datagrams a consumer has already read off a socket, and the no-I/O rule keeps std.net out of src/ entirely. Pooling one connection per address is the consumer's bookkeeping
//= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
//# A client MAY open multiple HTTP/3 connections to the same IP address
//# and UDP port using different transport or TLS configurations but
//# SHOULD avoid creating multiple connections with the same
//# configuration.
//= type=exception
//= reason=the transport and TLS configurations this rule compares are the consumer's — quic/Connection is parameterised with its limits and its TLS engine is its own, per docs/DESIGN.md sections 4 and 5 — so nothing here can tell one configuration from another, or open a second connection under either

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
//= reason=which endpoint opened a stream, and whether this one is the client, are facts about a connection; the connection layer that holds them is `Http3.zig`, and this file reads the first octets of a stream it is handed
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# Therefore, the transport parameters sent by both clients
//# and servers MUST allow the peer to create at least three
//# unidirectional streams.
//= type=exception
//= reason=the value advertised for initial_max_streams_uni comes from the limits a consumer parameterises quic/Connection with (docs/DESIGN.md section 5), and quic/transport_parameters.zig is what encodes it; this file classifies the type on a stream that already exists and opens none
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//# In order to permit these streams to open, an HTTP/3 server SHOULD
//# configure non- zero minimum values for the number of permitted streams
//# and the initial stream flow-control window.
//= type=exception
//= reason=a limit that is not comptime is a bug here (docs/DESIGN.md section 5): quic/Connection is parameterised by the consumer's limits, so what a server configures is chosen one level up and encoded by quic/transport_parameters.zig. This file opens no stream and advertises nothing
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//# So as to not unnecessarily limit parallelism, at least 100 request
//# streams SHOULD be permitted at a time.
//= type=exception
//= reason=initial_max_streams_bidi is one of the comptime limits a consumer parameterises quic/Connection with, per docs/DESIGN.md section 5; a hundred is a deployment's number rather than a codec's, and this file neither holds it nor counts streams against it
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# These transport parameters SHOULD also provide at least 1,024 bytes of
//# flow-control credit to each unidirectional stream.
//= type=exception
//= reason=initial_max_stream_data_uni is a comptime limit the consumer parameterises quic/Connection with (docs/DESIGN.md section 5) and quic/transport_parameters.zig encodes; this file reads the first octets of a stream and grants no credit
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# Endpoints SHOULD create the HTTP control stream as well as the
//# unidirectional streams required by mandatory extensions (such as the
//# QPACK encoder and decoder streams) first, and then create additional
//# streams as allowed by their peer.
//= type=exception
//= reason=the control stream and the two QPACK streams are not built — docs/DESIGN.md section 6 lists the control stream as next and the QPACK dynamic table with it — so there is no ordering here to get right; write() encodes a type into a caller's buffer and opens nothing
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
//= reason=a requirement on the specification that registers a stream type, not on code; Type names the two types Table 5 registers and the two RFC 9204 section 4.2 adds, which is what an implementation has to say about a registry
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
    //= reason=initiating the control stream and sequencing SETTINGS onto it is `Http3.zig`'s; Type.control is the number it will write first
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# Because the contents of the control stream are used to manage the
    //# behavior of other streams, endpoints SHOULD provide enough flow-
    //# control credit to keep the peer's control stream from becoming
    //# blocked.
    //= type=exception
    //= reason=flow-control credit for a stream is granted by quic/Connection out of a comptime limit the consumer parameterises it with (docs/DESIGN.md section 5), and the control stream that needs it is opened by the consumer on `Http3.zig`'s behalf. Type.control is the number by which the connection layer will recognise the stream to credit
    control = 0x00,
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
    //# Only servers can push; if a server receives a client-initiated push
    //# stream, this MUST be treated as a connection error of type
    //# H3_STREAM_CREATION_ERROR.
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
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
    //# A client SHOULD NOT abort reading on a push stream prior to reading
    //# the push stream header, as this could lead to disagreement between
    //# client and server on which push IDs have already been consumed.
    //= type=exception
    //= reason=server push is not implemented, so no push stream header is ever read and no push ID is ever consumed; aborting a read is the consumer's action on a QUIC stream in any case, per docs/DESIGN.md section 3
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    //# Clients SHOULD abort reading and discard data already read from push
    //# streams if no corresponding PUSH_PROMISE frame is processed in a
    //# reasonable amount of time.
    //= type=exception
    //= reason=server push is not implemented, and pairing a push stream with the PUSH_PROMISE that announced it is connection state nothing here holds; "a reasonable amount of time" would also need a clock, and docs/DESIGN.md's seam takes now_ns as a parameter rather than reading one
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
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    //# The recipient MUST NOT consider unknown stream types
    //# to be a connection error of any kind.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-9
    //# Implementations MUST discard data or
    //# abort reading on unidirectional streams that have unknown or
    //# unsupported types.
    //= type=exception
    //= reason=discarding a stream's data or aborting its read is an action on a QUIC stream, which docs/DESIGN.md section 3 puts on the consumer's side of the seam; Type.known is the classification it asks
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    //# If reading is aborted, the recipient SHOULD use the
    //# H3_STREAM_CREATION_ERROR error code or a reserved error code (Section
    //# 8.1).
    //= type=exception
    //= reason=aborting a read is a QUIC STOP_SENDING and choosing the code on it is that frame's field, both of which are the consumer's per docs/DESIGN.md section 3; this file answers which types are unknown and never resets anything
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
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
    //# When resetting the stream, either the H3_NO_ERROR error code or a
    //# reserved error code (Section 8.1) SHOULD be used.
    //= type=exception
    //= reason=resetting a stream is a QUIC RESET_STREAM and the code on it is that frame's field, both the consumer's per docs/DESIGN.md section 3; isReserved is what tells it that the stream it is resetting is one of the reserved family this sentence is about
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
//# As certain stream types can affect connection state, a recipient
//# SHOULD NOT discard data from incoming unidirectional streams prior to
//# reading the stream type.
//= type=exception
//= reason=discarding a stream's data is the recipient's action and docs/DESIGN.md section 3 puts the QUIC stream on the consumer's side of the seam. What this file owes that recipient is the reason it need not discard early, and parse gives it: a type split across packets answers Incomplete rather than an error, so a caller that follows the contract keeps the octets and retries
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
//= reason=knowing whether a peer supports a stream type needs its SETTINGS, which `Http3.zig` holds; write() encodes a type and decides nothing about when to send it
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
