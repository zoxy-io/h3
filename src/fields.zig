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
//! What did change: section 4.2 makes an uppercase field name malformed
//! outright rather than a "SHOULD". That is the one rule most likely to be lost
//! in a port of an HTTP/2 validator, so it is checked first.
//!
//! What did *not* change, though this file once said otherwise: `:protocol`.
//! RFC 9220 section 3 gives HTTP/3 RFC 8441's extended CONNECT with "semantics
//! ... identical to those in HTTP/2", so the same three-shape request rule
//! applies here — and reading section 4.4's tunnel restrictions before RFC
//! 9220's, as this did, rejects every legal WebSocket-over-HTTP/3 request while
//! accepting a bare CONNECT that carries a `:protocol` it has no `:scheme` or
//! `:path` for.
//!
//! ## What is checked here and what is not
//!
//! Checked: everything section 4.3 decides from the field section alone, plus
//! `content-length`'s own syntax (RFC 9110 section 8.6) and the `:authority`
//! and `Host` agreement section 4.3.1 requires.
//!
//! Not checked, because a field section cannot decide it: whether a
//! `content-length` equals the DATA frames that follow (section 4.1.2 — see
//! `MessageValidator.contentLength`, which hands a consumer the number to
//! compare), whether an `:authority` carries the deprecated userinfo
//! subcomponent, whether two spellings of an authority name the same origin,
//! and whether a method or status is one that exists.

const std = @import("std");

const assert = @import("assert.zig").assert;

const Field = @import("qpack.zig").Field;

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
//# Intermediaries that process HTTP requests or responses (i.e., any
//# intermediary not acting as a tunnel) MUST NOT forward a malformed
//# request or response.  Malformed requests or responses that are
//# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
//= type=exception
//= reason=fields.zig reports a malformed message and never acts on one; whether to forward it or to raise H3_MESSAGE_ERROR belongs to the consumer, per this file's header and docs/DESIGN.md section 3's seam
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
    /// Section 4.1.2's "invalid values for pseudo-header fields": a `:status`
    /// that is not three digits, an empty `:method`, an empty `:path` under a
    /// scheme that forbids one.
    PseudoValueInvalid,
    /// Section 4.3.1: a `Host` that is empty, or that disagrees with the
    /// `:authority` beside it. The pair a downstream HTTP/1.1 request line is
    /// built from, so a disagreement is a smuggling primitive rather than an
    /// inconsistency.
    AuthorityMismatch,
    /// RFC 9110 section 8.6: a `content-length` that is not `1*DIGIT`, or two
    /// that disagree.
    ContentLengthInvalid,
};

/// Section 4.2, via RFC 9110's `token`: the octets a field name may contain.
/// Uppercase is deliberately absent — HTTP/3 field names are lowercase, and a
/// validator that tolerated uppercase would let `Content-Length` and
/// `content-length` be two different fields to whatever it feeds.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# Characters in field names MUST be
//# converted to lowercase prior to their encoding.  A request or
//# response containing uppercase characters in field names MUST be
//# treated as malformed.
//= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
//# Requests or responses containing invalid field names MUST be treated
//# as malformed.
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
//# Any request or response that contains a
//# character not permitted in a field value MUST be treated as
//# malformed.
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# An intermediary transforming an HTTP/1.x message to HTTP/3 MUST
//# remove connection-specific header fields as discussed in
//# Section 7.6.1 of [HTTP], or their messages will be treated by other
//# HTTP/3 endpoints as malformed.
//= type=exception
//= reason=this package validates a field section and never transforms one; docs/DESIGN.md section 3 puts message translation in the consumer, which is the only party holding the HTTP/1.x side
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# An endpoint MUST NOT generate
//# an HTTP/3 field section containing connection-specific fields; any
//# message containing connection-specific fields MUST be treated as
//# malformed.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# Transfer codings (see Section 7 of [HTTP/1.1]) are not defined for
//# HTTP/3; the Transfer-Encoding header field MUST NOT be used.
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

/// The pseudo-headers RFC 9114 sections 4.3.1 and 4.3.2 define, plus the one
/// RFC 9220 adds.
const Pseudo = enum {
    method,
    scheme,
    authority,
    path,
    status,
    /// RFC 9220 section 3: extended CONNECT, whose semantics "are identical to
    /// those in HTTP/2 as defined in [RFC8441]". It exists only where the
    /// server sent `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08), which is
    /// connection state this file does not hold — so `Options` takes it as a
    /// parameter and the decision stays with the consumer.
    protocol,

    /// Whether this one is defined for requests. Section 4.3: "Pseudo-header
    /// fields defined for requests MUST NOT appear in responses; pseudo-header
    /// fields defined for responses MUST NOT appear in requests."
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Pseudo-header fields defined for requests MUST NOT appear
    //# in responses; pseudo-header fields defined for responses MUST NOT
    //# appear in requests.
    fn forRequest(which: Pseudo) bool {
        return which != .status;
    }

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

pub const Kind = enum {
    request,
    response,
    /// A trailer section. Section 4.3: "Pseudo-header fields MUST NOT appear in
    /// trailer sections" — so every one of them is misplaced here, in either
    /// direction, and there is nothing a trailer section is required to carry.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Pseudo-header fields MUST NOT appear in trailer
    //# sections.
    trailer,
};

//= https://www.rfc-editor.org/rfc/rfc9114#section-9
//# If a setting is used for extension negotiation, the default
//# value MUST be defined in such a fashion that the extension is
//# disabled if the setting is omitted.
pub const Options = struct {
    kind: Kind,
    /// Whether `SETTINGS_ENABLE_CONNECT_PROTOCOL` is in force (RFC 9220
    /// section 3). False makes `:protocol` an undefined pseudo-header, which
    /// section 4.3 requires of one that was never negotiated.
    extended_connect: bool = false,
};

/// RFC 9110 section 9.1: "the method token is case-sensitive", so `connect` is
/// a different method rather than a sloppy spelling of this one.
const connect_method = "CONNECT";

/// The schemes section 4.3.1's authority rule names explicitly: "a scheme that
/// has a mandatory authority component (including 'http' and 'https')". Only
/// these two are recognised, because deciding it for an arbitrary scheme needs
/// that scheme's definition and this file has no registry.
///
/// Compared without regard to case: RFC 3986 section 3.1 makes schemes
/// case-insensitive and asks implementations to accept `HTTP` as `http`. A
/// case-sensitive comparison would let `HTTPS` with an empty `:path` through,
/// which is the accept-a-malformed-message direction.
const authority_bearing_schemes = [_][]const u8{ "http", "https" };

const te_field_name = "te";
/// The one value section 4.2 permits in a `te`, and the one kind of section it
/// permits the field in.
const te_permitted_value = "trailers";

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# To ensure that the HTTP/1.1 request line can be reproduced
//# accurately, this pseudo-header field MUST be omitted when
//# translating from an HTTP/1.1 request that has a request target in
//# a method-specific form; see Section 7.1 of [HTTP].
//= type=exception
//= reason=this package never translates a message; docs/DESIGN.md section 3 leaves the HTTP/1.1 side to the consumer, and only a party holding the original request target can know it was in method-specific form
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# Clients that
//# generate HTTP/3 requests directly SHOULD use the :authority
//# pseudo-header field instead of the Host header field.
//= type=exception
//= reason=generating a request is the consumer's, per docs/DESIGN.md section 3; fields.zig checks a field section it is handed and writes none
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# An
//# intermediary that converts an HTTP/3 request to HTTP/1.1 MUST
//# create a Host field if one is not present in a request by copying
//# the value of the :authority pseudo-header field.
//= type=exception
//= reason=this package never converts a message, so it creates no Host field; docs/DESIGN.md section 3 leaves the HTTP/1.1 side to the consumer, and checkHost is how this side refuses a pair that would make the conversion ambiguous
const host_field_name = "host";
const content_length_field_name = "content-length";

/// RFC 9112 section 4: `status-code = 3DIGIT`. Not "parses as a number" —
/// `7`, `0200` and `1000` are all malformed, and a validator that accepted
/// them would hand a downstream HTTP/1.1 writer a status line it cannot form.
const status_octets = 3;

/// `u64` holds 20 decimal digits, so a longer run cannot be represented and is
/// refused rather than truncated. RFC 9110 section 8.6 asks a recipient to
/// "prevent parsing errors due to integer conversion overflows"; it also says
/// any value at or above zero is valid, so this bound is a deliberate and
/// documented departure at a size no real message reaches.
const content_length_digits_max = 20;

/// How much of an `:authority` is kept so that a later `Host` can be compared
/// against it. Section 4.3.1 requires the two to "contain the same value", and
/// checking that means holding one of them.
///
/// Generous on purpose: RFC 1035 caps a domain name at 253 octets and a port
/// adds at most six, so a real authority never approaches this. An `:authority`
/// past the bound is not rejected on its own — it is only unverifiable, and
/// `authority_truncated` records that so a `Host` arriving later fails closed
/// rather than being waved through.
const authority_octets_max = 512;

comptime {
    assert(authority_octets_max > 253 + ":65535".len);
    assert(content_length_digits_max == std.fmt.count("{d}", .{std.math.maxInt(u64)}));
    assert(status_octets == 3);
}

/// Walks a field section once, checking sections 4.2 and 4.3 as it goes.
///
/// Fed one field at a time rather than a list, because a decoded field's name
/// and value borrow from a buffer the next field reuses — the same constraint
/// `qpack.field_line.Iterator` imposes, and the reason both are iterators.
/// Nothing here retains a caller's slice: where a later rule needs an earlier
/// field's value, either a bit is derived while the value is in hand, or the
/// octets are copied into this struct's own storage.
///
/// Section 4.1's "begin processing partial HTTP messages" is why it is an
/// iterator rather than a function over a list: a field section can be checked
/// as it streams past, so a consumer never has to hold a whole one.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# Because some messages are large or unbounded, endpoints SHOULD begin
//# processing partial HTTP messages once enough of the message has been
//# received to make progress.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# A
//# client MUST send only a single request on a given stream.
//= type=exception
//= reason=one stream carries one request, and this validator is handed one field section at a time by a consumer that owns the stream; docs/DESIGN.md section 3 puts the QUIC stream on the consumer's side of the seam
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# On a given stream, receipt of multiple requests or receipt of an
//# additional HTTP response following a final HTTP response MUST be
//# treated as malformed.
//= type=exception
//= reason=counting the messages that have crossed one stream is per-stream state, and MessageValidator is constructed per field section and keeps none of the last one; the request/response state machine is the consumer's, per docs/DESIGN.md section 3
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# After sending a request, a client MUST
//# close the stream for sending.  Unless using the CONNECT method (see
//# Section 4.4), clients MUST NOT make stream closure dependent on
//# receiving a response to their request.  After sending a final
//# response, the server MUST close the stream for sending.
//= type=exception
//= reason=closing a QUIC stream for sending is an action on a stream, which docs/DESIGN.md section 3 leaves to the consumer; nothing here sends a message, ends one, or decides which response is final
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# Clients MUST NOT discard complete responses as a
//# result of having their request terminated abruptly, though clients
//# can always discard responses at their discretion for other reasons.
//= type=exception
//= reason=what to do with a response that arrived is the consumer's decision, as this file's header says: zoxy must reject a malformed one and zrk may want to record what it got, and neither is a rule about a field section
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# If a client-initiated stream terminates without enough of the HTTP
//# message to provide a complete response, the server SHOULD abort its
//# response stream with the error code H3_REQUEST_INCOMPLETE.
//= type=exception
//= reason=aborting a response stream is an action on a QUIC stream, which docs/DESIGN.md section 3 puts on the consumer's side of the seam; nothing here sees a stream end, so "terminates without enough of the message" is not a fact a field-section validator can observe
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# The error code H3_NO_ERROR SHOULD be used when requesting that the
//# client stop sending on the request stream.
//= type=exception
//= reason=requesting that a peer stop sending is a QUIC STOP_SENDING frame, which this package never sends on any consumer's behalf; docs/DESIGN.md section 3 leaves the stream and its error code to the consumer
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//# If the server sends a partial or complete response but does not abort
//# reading the request, clients SHOULD continue sending the content of
//# the request and close the stream normally.
//= type=exception
//= reason=this package sends no content and closes no stream; whether a server aborted reading is per-stream state the consumer holds, per docs/DESIGN.md section 3
// RFC 9114 section 4.1.1: how a request is cancelled and what may be done
// afterwards. None of it is a rule about a field section — every one names an
// action on a QUIC stream, or a decision about a request this package does not
// hold. The error codes themselves are named in frame.zig's section 8 block.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# Implementations SHOULD cancel requests by abruptly terminating any
//# directions of a stream that are still open.
//= type=exception
//= reason=abruptly terminating a direction of a stream is a QUIC RESET_STREAM or STOP_SENDING, and docs/DESIGN.md section 3 puts the stream on the consumer's side of the seam; this validator is handed a decoded field section and cancels nothing
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# The server SHOULD abort its response stream with the error code
//# H3_REQUEST_REJECTED.
//= type=exception
//= reason=this package resets no stream, so it chooses no error code for one; the matching MUST NOT — that H3_REQUEST_REJECTED not be used for a request that was processed — is cited in frame.zig for the same reason
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# When a server abandons a response after partial processing, it SHOULD
//# abort its response stream with the error code H3_REQUEST_CANCELLED.
//= type=exception
//= reason=whether a response was abandoned after partial processing is the consumer's knowledge — it is what runs the request — and aborting the stream is its action, per docs/DESIGN.md section 3
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# Client SHOULD use the error code H3_REQUEST_CANCELLED to cancel
//# requests.
//= type=exception
//= reason=this package issues no request and therefore cancels none; docs/DESIGN.md section 3 leaves the request/response state machine and the stream it rides on to the consumer
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# However, if a stream is cancelled after receiving a partial response,
//# the response SHOULD NOT be used.
//= type=exception
//= reason=using a response is the consumer's decision, as this file's header says: it reports and never acts, and it retains no field of any message it has checked
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# Only idempotent actions such as GET, PUT, or DELETE can be safely
//# retried; a client SHOULD NOT automatically retry a request with a
//# non-idempotent method unless it has some means to know that the
//# request semantics are idempotent independent of the method or some
//# means to detect that the original request was never applied.
//= type=exception
//= reason=retrying a request is the consumer's, and this package deliberately knows nothing about method semantics: its header says whether a method is one that exists is not checked here, so idempotence is not a property it could read
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.1
//# If a decompressed field
//# section contains multiple cookie field lines, these MUST be
//# concatenated into a single byte string using the two-byte delimiter
//# of "; " (ASCII 0x3b, 0x20) before being passed into a context other
//# than HTTP/2 or HTTP/3, such as an HTTP/1.1 connection, or a generic
//# HTTP server application.
//= type=exception
//= reason=joining cookie field lines happens on the way into another context, and this package never translates a message: docs/DESIGN.md section 3 leaves the HTTP/1.1 side to the consumer, which is the party holding the joined string's destination
pub const MessageValidator = struct {
    kind: Kind,
    extended_connect: bool,
    seen: std.EnumSet(Pseudo) = .initEmpty(),
    ordinary_seen: bool = false,
    /// Derived from values while they were in hand, never from a kept slice.
    method_is_connect: bool = false,
    scheme_bears_authority: bool = false,
    path_is_empty: bool = false,
    host_seen: bool = false,
    /// The `:authority` value, copied because a `Host` field arriving later has
    /// to be compared against it. Section 4.3's ordering rule guarantees the
    /// order — every pseudo-header precedes every ordinary field — so one
    /// buffer suffices and `Host` never needs keeping.
    authority_storage: [authority_octets_max]u8 = @splat(0),
    authority_octets: u16 = 0,
    authority_truncated: bool = false,
    content_length: u64 = 0,
    content_length_seen: bool = false,

    pub fn init(options: Options) MessageValidator {
        return .{ .kind = options.kind, .extended_connect = options.extended_connect };
    }

    fn authority(self: *const MessageValidator) []const u8 {
        assert(self.authority_octets <= authority_octets_max);
        return self.authority_storage[0..self.authority_octets];
    }

    pub fn field(self: *MessageValidator, one: *const Field) Error!void {
        // Section 4.2 first. Every name comparison below is against a lowercase
        // literal with no case folding, which is sound only because this
        // rejects every uppercase octet — an ordering dependency, not a
        // preference.
        try validateName(one.name);
        try validateValue(one.value);
        assert(one.name.len >= 1);

        if (!pseudo(one.name)) return self.regularField(one);
        return self.pseudoField(one);
    }

    fn pseudoField(self: *MessageValidator, one: *const Field) Error!void {
        assert(one.name[0] == ':');

        // Section 4.3: all pseudo-headers precede every ordinary field, so a
        // receiver can decide what kind of message it has without buffering.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.  Any request or response that contains a
        //# pseudo-header field that appears in a header section after a regular
        //# header field MUST be treated as malformed.
        if (self.ordinary_seen) return error.PseudoInvalid;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# Endpoints MUST NOT
        //# generate pseudo-header fields other than those defined in this
        //# document.
        const which = Pseudo.parse(one.name) orelse return error.PseudoInvalid;
        // RFC 9220 defines `:protocol` only where it was negotiated; anywhere
        // else section 4.3 makes it an undefined pseudo-header.
        if (which == .protocol and !self.extended_connect) return error.PseudoInvalid;

        switch (self.kind) {
            .trailer => return error.PseudoInvalid,
            .request => if (!which.forRequest()) return error.PseudoInvalid,
            .response => if (which.forRequest()) return error.PseudoInvalid,
        }

        if (self.seen.contains(which)) return error.PseudoInvalid;
        self.seen.insert(which);
        assert(!self.ordinary_seen);

        try self.pseudoValue(which, one.value);
    }

    /// Section 4.1.2 lists "invalid values for pseudo-header fields" as its own
    /// way to be malformed, distinct from a missing or misplaced one. Before
    /// this existed, every value here was accepted unread: a `:status` of
    /// `banana`, an `:authority` of nothing at all.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Endpoints MUST treat a request or response that contains
    //# undefined or invalid pseudo-header fields as malformed.
    fn pseudoValue(self: *MessageValidator, which: Pseudo, value: []const u8) Error!void {
        assert(self.seen.contains(which));

        // Section 4.3.1 requires "exactly one value" for the mandatory
        // pseudo-headers, and no value is not one. `:path` is exempt because
        // whether an empty one is legal depends on the scheme, which may not
        // have arrived yet — `checkPath` asks that question at the end.
        if (which != .path and value.len == 0) return error.PseudoValueInvalid;

        switch (which) {
            .method => self.method_is_connect = std.mem.eql(u8, value, connect_method),
            .scheme => self.scheme_bears_authority = bearsAuthority(value),
            .path => self.path_is_empty = value.len == 0,
            .status => try checkStatus(value),
            .authority => self.rememberAuthority(value),
            .protocol => {},
        }
    }

    /// RFC 9112 section 4's `status-code = 3DIGIT`, checked as octets rather
    /// than by parsing, so that `+20`, ` 20` and `2e2` are all refused.
    fn checkStatus(value: []const u8) Error!void {
        if (value.len != status_octets) return error.PseudoValueInvalid;
        for (value) |octet| {
            if (octet < '0' or octet > '9') return error.PseudoValueInvalid;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
    //# The authority MUST NOT include the
    //# deprecated userinfo subcomponent for URIs of scheme "http" or
    //# "https".
    //= type=todo
    fn rememberAuthority(self: *MessageValidator, value: []const u8) void {
        if (value.len > authority_octets_max) {
            // Kept unverifiable rather than rejected: a long `:authority` on
            // its own breaks no rule, and only a `Host` to compare it against
            // turns this into a refusal.
            self.authority_truncated = true;
            self.authority_octets = 0;
            return;
        }
        @memcpy(self.authority_storage[0..value.len], value);
        self.authority_octets = @intCast(value.len);
        assert(std.mem.eql(u8, self.authority(), value));
    }

    fn regularField(self: *MessageValidator, one: *const Field) Error!void {
        assert(one.name[0] != ':');

        // Section 4.2's TE exception, which is narrower than it was read as
        // being: "the TE header field, which MAY be present in an HTTP/3
        // request; when it is, it MUST NOT contain any value other than
        // 'trailers'". A request, and that one value — a `te` in a response was
        // being waved through here, and a trailer section is not a request's
        // header section either. Transfer-coding negotiation after the content
        // has been sent means nothing in any case.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //# The only exception to this is the TE header field, which MAY be
        //# present in an HTTP/3 request header; when it is, it MUST NOT contain
        //# any value other than "trailers".
        if (std.mem.eql(u8, one.name, te_field_name)) {
            if (self.kind != .request) return error.ConnectionSpecific;
            // Case-insensitively: RFC 9110 section 10.1.4 defines the value
            // through ABNF, and RFC 5234 section 2.3 makes ABNF string literals
            // case-insensitive, so `TRAILERS` is a conforming spelling this
            // package has no business refusing.
            if (!std.ascii.eqlIgnoreCase(one.value, te_permitted_value)) return error.ConnectionSpecific;
        }
        if (!std.mem.eql(u8, one.name, te_field_name)) {
            if (connectionSpecific(one.name)) return error.ConnectionSpecific;
        }

        //= https://www.rfc-editor.org/rfc/rfc9110#section-6.5.1
        //# A recipient MUST NOT merge a trailer field into a header
        //# section unless the recipient understands the corresponding header
        //# field definition and that definition explicitly permits and defines
        //# how trailer field values can be safely merged.
        //
        // `content-length` and `host` are message framing and routing, and
        // section 6.5.1 opens by naming exactly that class: "Many fields cannot
        // be processed outside the header section because their evaluation is
        // necessary prior to receiving the content". Neither definition permits
        // a trailer, so neither may be read from one.
        //
        // Both checks used to run whatever the `Kind` was, so a
        // `content-length` in a trailer section was accepted *and* handed to a
        // consumer through `contentLength()` — indistinguishable there from one
        // in the header section. For zoxy's threat model that is the vector this
        // file exists to close: an intermediary that merges a trailer into the
        // header section on the way to HTTP/1.1 emits a second, later
        // `Content-Length`. `transfer-encoding` was already caught by
        // `connectionSpecific`, which is what made the gap easy to miss.
        if (self.kind == .trailer) {
            if (std.mem.eql(u8, one.name, host_field_name)) return error.ConnectionSpecific;
            if (std.mem.eql(u8, one.name, content_length_field_name)) return error.ConnectionSpecific;
        } else {
            if (std.mem.eql(u8, one.name, host_field_name)) try self.checkHost(one.value);
            if (std.mem.eql(u8, one.name, content_length_field_name)) try self.checkContentLength(one.value);
        }

        // Set last, so a field this function refused cannot make a later
        // pseudo-header look out of order.
        self.ordinary_seen = true;
    }

    /// Section 4.3.1: "If these fields are present, they MUST NOT be empty. If
    /// both fields are present, they MUST contain the same value."
    ///
    /// Compared literally, which is what that sentence asks for — it says the
    /// same *value*, not an equivalent authority. Whether two spellings name
    /// the same origin needs a URI parser and stays with the consumer.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
    //# If these fields are present, they MUST NOT be
    //# empty.  If both fields are present, they MUST contain the same value.
    fn checkHost(self: *MessageValidator, value: []const u8) Error!void {
        assert(!self.host_seen or self.ordinary_seen);
        //= https://www.rfc-editor.org/rfc/rfc9112#section-3.2
        //# A server MUST respond with a 400 (Bad Request) status code to any
        //# HTTP/1.1 request message that lacks a Host header field and to any
        //# request message that contains more than one Host header field line or
        //# a Host header field with an invalid field value.
        //
        // A second `Host` was accepted here whenever no `:authority` stood
        // beside it: with one, each `Host` is compared against it and two
        // disagreeing values cannot both pass, but with none there was nothing
        // to compare against and `{host: example.com, host: evil.example}` was
        // a well-formed request. RFC 9114 section 4.3.1 does not cover it —
        // it speaks only to `:authority` versus `Host` — which is why the
        // existing check was literally correct and still left the hole.
        //
        // The rule that closes it is HTTP/1.1's, and that is the point: this
        // package is written to zoxy's threat model, and zoxy is a proxy that
        // may translate this request into an HTTP/1.1 one, where two `Host`
        // lines are a 400. Refusing it here is refusing to build a message
        // whose meaning depends on which hop reads it.
        if (self.host_seen) return error.AuthorityMismatch;
        self.host_seen = true;
        if (value.len == 0) return error.AuthorityMismatch;
        if (!self.seen.contains(.authority)) return;
        // An `:authority` too long to keep cannot be compared, and a pair this
        // cannot verify is refused rather than assumed to agree: the whole
        // point of the rule is that a proxy about to write one of these into an
        // HTTP/1.1 request line knows which value it is writing.
        if (self.authority_truncated) return error.AuthorityMismatch;
        if (!std.mem.eql(u8, self.authority(), value)) return error.AuthorityMismatch;
    }

    /// RFC 9110 section 8.6: `Content-Length = 1*DIGIT`. A second field line
    /// with a different value is the response-splitting pair — whichever the next
    /// hop believes, the other half of the stream is a message it did not see
    /// coming — and that is what this refuses.
    ///
    /// Two field lines carrying the *same* value are accepted. Section 8.6 offers
    /// both answers for that case ("MAY either reject the message as invalid or
    /// replace that invalid field value with a single instance"), and taking the
    /// second is conformant. What is refused is the comma-joined spelling
    /// `10, 10`, which fails the ABNF outright.
    ///
    /// This comment used to claim the repeated-identical form was refused too,
    /// "which this does" — it does not, and the test below states the real rule.
    fn checkContentLength(self: *MessageValidator, value: []const u8) Error!void {
        const length = parseContentLength(value) orelse return error.ContentLengthInvalid;
        if (self.content_length_seen and self.content_length != length) {
            return error.ContentLengthInvalid;
        }
        self.content_length_seen = true;
        self.content_length = length;
    }

    /// The `content-length` a well-formed section carried, for a consumer that
    /// has to compare it against the DATA frames it goes on to read. Section
    /// 4.1.2 makes that comparison a malformed-message check, and it is not one
    /// a field section can make on its own.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
    //# A request or response that is defined as having content when it
    //# contains a Content-Length header field (Section 8.6 of [HTTP]) is
    //# malformed if the value of the Content-Length header field does not
    //# equal the sum of the DATA frame lengths received.
    pub fn contentLength(self: *const MessageValidator) ?u64 {
        if (!self.content_length_seen) return null;
        return self.content_length;
    }

    /// Check what only the end of a section can decide: which pseudo-headers
    /// had to be there, and which had to not be. Separate from `field` because
    /// pseudo-headers may appear in any order among themselves, so a CONNECT
    /// request's `:method` can arrive after the `:path` its presence forbids.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
    //# Clients MUST NOT
    //# accept a malformed response.
    //= type=exception
    //= reason=accepting or refusing is the consumer's decision, as this file's header says: zoxy must reject and zrk may want to record what it got, so finish() reports and never acts
    pub fn finish(self: *const MessageValidator) Error!void {
        if (self.kind == .trailer) assert(self.seen.count() == 0);
        if (self.method_is_connect) assert(self.kind == .request);

        switch (self.kind) {
            .trailer => return,
            .request => return self.finishRequest(),
            // Section 4.3.2: `:status` "MUST be included in all responses".
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
            //# This pseudo-
            //# header field MUST be included in all responses; otherwise, the
            //# response is malformed (see Section 4.1.2).
            .response => if (!self.seen.contains(.status)) return error.PseudoMissing,
        }
    }

    fn finishRequest(self: *const MessageValidator) Error!void {
        assert(self.kind == .request);

        // Which of the three shapes applies is decided by `:protocol` first.
        // RFC 9220 *modifies* section 4.4 for a request carrying one, so
        // reading section 4.4's rules first — as this did — applies the tunnel
        // restrictions to an extended CONNECT and rejects every legal
        // WebSocket-over-HTTP/3 request.
        if (self.seen.contains(.protocol)) return self.finishExtendedConnect();
        if (self.method_is_connect) return self.finishConnect();
        return self.finishOrdinary();
    }

    /// RFC 8441 section 4, adopted unchanged by RFC 9220 section 3: CONNECT
    /// with a `:protocol`.
    fn finishExtendedConnect(self: *const MessageValidator) Error!void {
        assert(self.extended_connect);
        assert(self.seen.contains(.protocol));

        // `:protocol` names the protocol to speak "on the tunnel created by
        // CONNECT", so there has to be a CONNECT for it to modify. Without this
        // a bare `GET` carrying a `:protocol` was accepted.
        if (!self.method_is_connect) return error.PseudoInvalid;
        assert(self.seen.contains(.method));

        // "On requests that contain the :protocol pseudo-header field, the
        // :scheme and :path pseudo-header fields of the target URI MUST also be
        // included." The exact inverse of section 4.4, which is why it is asked
        // before section 4.4 rather than after.
        if (!self.seen.contains(.scheme)) return error.PseudoMissing;
        if (!self.seen.contains(.path)) return error.PseudoMissing;
        return self.checkAuthority();
    }

    /// Section 4.4: CONNECT without a `:protocol`, which is a tunnel rather
    /// than a request for a resource.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# A CONNECT request MUST be constructed as follows:
    //# *  The :method pseudo-header field is set to "CONNECT"
    //# *  The :scheme and :path pseudo-header fields are omitted
    //# *  The :authority pseudo-header field contains the host and port to
    //# connect to (equivalent to the authority-form of the request-target
    //# of CONNECT requests; see Section 7.1 of [HTTP]).
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# Correspondingly, if a proxy detects an error with the stream or the
    //# QUIC connection, it MUST close the TCP connection.  If the proxy
    //# detects that the client has reset the stream or aborted reading from
    //# the stream, it MUST close the TCP connection.
    //= type=exception
    //= reason=the TCP connection a CONNECT tunnel carries is the proxy's, and this package opens no socket at all: docs/DESIGN.md section 3's seam takes datagrams, so finishConnect checks the request's shape and owns nothing to close
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# TCP connections that remain half closed in a single direction are not
    //# invalid, but are often handled poorly by servers, so clients SHOULD
    //# NOT close a stream for sending while they still expect to receive data
    //# from the target of the CONNECT.
    //= type=exception
    //= reason=closing a stream for sending is an action on a QUIC stream, which docs/DESIGN.md section 3 puts on the consumer's side of the seam; finishConnect decides whether a CONNECT request is well-formed and never drives the tunnel it opens
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# If the stream is reset or reading is aborted by the client, a proxy
    //# SHOULD perform the same operation on the other direction in order to
    //# ensure that both directions of the stream are cancelled.
    //= type=exception
    //= reason=this package is not a proxy: it holds neither the QUIC stream nor the TCP connection a tunnel joins, so there is no other direction for it to mirror a reset onto. zoxy is the proxy, per docs/DESIGN.md section 3
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# In all these cases, if the underlying TCP implementation permits it,
    //# the proxy SHOULD send a TCP segment with the RST bit set.
    //= type=exception
    //= reason=there is no underlying TCP implementation here — the package's no-I/O rule forbids std.posix and std.net outright, per docs/DESIGN.md section 3 — so no segment of any kind is this file's to send
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# Since CONNECT creates a tunnel to an arbitrary server, proxies that
    //# support CONNECT SHOULD restrict its use to a set of known ports or a
    //# list of safe request targets; see Section 9.3.6 of [HTTP] for more
    //# details.
    //= type=exception
    //= reason=which destinations a deployment permits is policy rather than syntax, and it belongs where the socket is: zoxy holds the port allowlist. finishConnect gives that policy the shape it needs — an :authority that is present, non-empty and unaccompanied by :scheme or :path — and the consumer already holds the value, because it is the party feeding each decoded field in
    fn finishConnect(self: *const MessageValidator) Error!void {
        assert(self.method_is_connect);
        assert(!self.seen.contains(.protocol));

        // "The :scheme and :path pseudo-header fields are omitted."
        if (self.seen.contains(.scheme)) return error.PseudoInvalid;
        if (self.seen.contains(.path)) return error.PseudoInvalid;
        // "The :authority pseudo-header field contains the host and port to
        // connect to." A CONNECT without one names no destination, and
        // `pseudoValue` has already refused an empty one.
        if (!self.seen.contains(.authority)) return error.PseudoMissing;
    }

    /// Section 4.3.1: everything that is not a CONNECT of either kind.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
    //# All HTTP/3 requests MUST include exactly one value for the :method,
    //# :scheme, and :path pseudo-header fields, unless the request is a
    //# CONNECT request; see Section 4.4.
    fn finishOrdinary(self: *const MessageValidator) Error!void {
        assert(!self.method_is_connect);
        assert(!self.seen.contains(.protocol));

        // "All HTTP/3 requests MUST include exactly one value for the :method,
        // :scheme, and :path pseudo-header fields." Duplicates and empty values
        // are already refused, so what is left here is presence.
        if (!self.seen.contains(.method)) return error.PseudoMissing;
        if (!self.seen.contains(.scheme)) return error.PseudoMissing;
        if (!self.seen.contains(.path)) return error.PseudoMissing;
        return self.checkAuthority();
    }

    /// Section 4.3.1's two rules that need the whole section: the authority has
    /// to be there under a scheme that mandates one, and a `:path` under `http`
    /// or `https` may not be empty.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
    //# If the :scheme pseudo-header field identifies a scheme that has a
    //# mandatory authority component (including "http" and "https"), the
    //# request MUST contain either an :authority pseudo-header field or a
    //# Host header field.
    fn checkAuthority(self: *const MessageValidator) Error!void {
        assert(self.kind == .request);

        // "If the :scheme pseudo-header field identifies a scheme that has a
        // mandatory authority component (including 'http' and 'https'), the
        // request MUST contain either an :authority pseudo-header field or a
        // Host header field." Neither one leaves a proxy nothing to write into
        // the request line it forwards.
        if (self.scheme_bears_authority) {
            if (!self.seen.contains(.authority) and !self.host_seen) return error.PseudoMissing;
        }
        // ":path" "MUST NOT be empty for 'http' or 'https' URIs". Restricted to
        // those two because the section is: `:scheme` "is not restricted to
        // URIs with scheme 'http' and 'https'", and refusing an empty path
        // under some other scheme — as this did — rejects a conforming
        // translated request.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        if (self.scheme_bears_authority and self.path_is_empty) return error.PseudoValueInvalid;
    }
};

/// Whether a scheme is one section 4.3.1 names as mandating an authority.
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# If the scheme does not have a mandatory authority component and none
//# is provided in the request target, the request MUST NOT contain the
//# :authority pseudo-header or Host header fields.
//= type=todo
fn bearsAuthority(scheme: []const u8) bool {
    for (authority_bearing_schemes) |candidate| {
        if (std.ascii.eqlIgnoreCase(scheme, candidate)) return true;
    }
    return false;
}

/// RFC 9110 section 8.6's `1*DIGIT`, with the overflow that section asks a
/// recipient to prevent. Null is "not a content-length", never a silent zero.
fn parseContentLength(value: []const u8) ?u64 {
    if (value.len == 0) return null;
    if (value.len > content_length_digits_max) return null;
    var total: u64 = 0;
    for (value) |octet| {
        if (octet < '0' or octet > '9') return null;
        total = std.math.mul(u64, total, 10) catch return null;
        total = std.math.add(u64, total, octet - '0') catch return null;
    }
    return total;
}

const testing = std.testing;

fn validate(kind: Kind, fields: []const Field) Error!void {
    return check(.{ .kind = kind }, fields);
}

fn check(options: Options, fields: []const Field) Error!void {
    var validator: MessageValidator = .init(options);
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# Characters in field names MUST be
//# converted to lowercase prior to their encoding.  A request or
//# response containing uppercase characters in field names MUST be
//# treated as malformed.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# An endpoint MUST NOT generate
//# an HTTP/3 field section containing connection-specific fields; any
//# message containing connection-specific fields MUST be treated as
//# malformed.
//= type=test
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
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "trailers" },
    });
    try testing.expectError(error.ConnectionSpecific, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "gzip" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
//# All pseudo-header fields MUST appear in the header section before
//# regular header fields.  Any request or response that contains a
//# pseudo-header field that appears in a header section after a regular
//# header field MUST be treated as malformed.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# All HTTP/3 requests MUST include exactly one value for the :method,
//# :scheme, and :path pseudo-header fields, unless the request is a
//# CONNECT request; see Section 4.4.
//= type=test
test "section 4.3: what a message must carry" {
    try testing.expectError(error.PseudoMissing, validate(.response, &.{
        .{ .name = "server", .value = "x" },
    }));
    try testing.expectError(error.PseudoMissing, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    }));
    try testing.expectError(error.PseudoValueInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
//# A CONNECT request MUST be constructed as follows:
//# *  The :method pseudo-header field is set to "CONNECT"
//# *  The :scheme and :path pseudo-header fields are omitted
//# *  The :authority pseudo-header field contains the host and port to
//# connect to (equivalent to the authority-form of the request-target
//# of CONNECT requests; see Section 7.1 of [HTTP]).
//= type=test
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
    var validator: MessageValidator = .init(.{ .kind = .response });
    while (try iterator.next()) |one| try validator.field(&one);
    try validator.finish();
}

const extended: Options = .{ .kind = .request, .extended_connect = true };

test "RFC 9220: an extended CONNECT is a request, not a tunnel" {
    // The whole point of the extension, and it was rejected outright before:
    // section 4.4's "the :scheme and :path pseudo-header fields are omitted"
    // was read first, so every conforming WebSocket-over-HTTP/3 request was
    // called malformed for carrying the two RFC 8441 section 4 requires.
    try check(extended, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
    });
}

test "RFC 9220: :protocol without the scheme and path it requires" {
    // The inverse error, and the one that was *accepted*: section 4.4's shape
    // plus a `:protocol`, which RFC 8441 section 4 forbids — "the :scheme and
    // :path pseudo-header fields of the target URI MUST also be included".
    try testing.expectError(error.PseudoMissing, check(extended, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":authority", .value = "example.com:443" },
    }));
}

test "RFC 9220: :protocol needs a CONNECT to modify, and a negotiation" {
    // "included on request HEADERS indicating the desired protocol to be spoken
    // on the tunnel created by CONNECT" — there has to be a CONNECT.
    try testing.expectError(error.PseudoInvalid, check(extended, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
    }));
    // And without `SETTINGS_ENABLE_CONNECT_PROTOCOL` it is a pseudo-header
    // nobody defined, which section 4.3 makes malformed on sight.
    try testing.expectError(error.PseudoInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
    }));
}

test "section 4.4: a plain CONNECT still names a tunnel" {
    // The extension must not have loosened the original shape.
    try testing.expectError(error.PseudoInvalid, check(extended, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":scheme", .value = "https" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
//# Endpoints MUST treat a request or response that contains
//# undefined or invalid pseudo-header fields as malformed.
//= type=test
test "section 4.1.2: a pseudo-header value is read, not just counted" {
    // Every one of these was accepted before, because nothing looked at a
    // pseudo-header's value at all.
    for ([_][]const u8{ "20", "2000", "abc", "20a", "+20", "" }) |bad| {
        try testing.expectError(error.PseudoValueInvalid, validate(.response, &.{
            .{ .name = ":status", .value = bad },
        }));
    }
    for ([_][]const u8{ "100", "200", "599", "999" }) |good| {
        try validate(.response, &.{.{ .name = ":status", .value = good }});
    }
    // A leading space is refused a layer earlier, by section 4.2's rule on
    // values rather than by section 4.3.2's on this one.
    try testing.expectError(error.ValueInvalid, validate(.response, &.{
        .{ .name = ":status", .value = " 200" },
    }));
    // An empty `:method`, `:scheme` or `:authority` is not "exactly one value".
    try testing.expectError(error.PseudoValueInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "" },
    }));
    try testing.expectError(error.PseudoValueInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# This pseudo-header field MUST NOT be empty for "http" or "https"
//# URIs; "http" or "https" URIs that do not contain a path component
//# MUST include a value of / (ASCII 0x2f).
//= type=test
test "section 4.3.1: an empty path is the scheme's question, not a blanket rule" {
    // `:scheme` "is not restricted to URIs with scheme 'http' and 'https'", and
    // the empty-path rule is written only for those two. Refusing it everywhere
    // — as this did — rejects a conforming translated request.
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "ftp" },
        .{ .name = ":path", .value = "" },
    });
    // Case-insensitively, or `HTTPS` would be a way around the rule.
    try testing.expectError(error.PseudoValueInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "HTTPS" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# If the :scheme pseudo-header field identifies a scheme that has a
//# mandatory authority component (including "http" and "https"), the
//# request MUST contain either an :authority pseudo-header field or a
//# Host header field.
//= type=test
test "section 4.3.1: an http request names an authority somehow" {
    // "the request MUST contain either an :authority pseudo-header field or a
    // Host header field". Neither leaves a proxy nothing to write into the
    // HTTP/1.1 request line it forwards.
    try testing.expectError(error.PseudoMissing, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    }));
    // Host alone is enough.
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
    });
    // A scheme with no mandatory authority needs neither.
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "ftp" },
        .{ .name = ":path", .value = "/x" },
    });
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# If these fields are present, they MUST NOT be
//# empty.  If both fields are present, they MUST contain the same value.
//= type=test
test "section 4.3.1: :authority and Host must agree" {
    // The smuggling pair. One value routes the request and the other is written
    // into the forwarded request line; a proxy that accepts a disagreement lets
    // the peer choose which.
    try testing.expectError(error.AuthorityMismatch, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "evil.example" },
    }));
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
    });
    // "If these fields are present, they MUST NOT be empty."
    try testing.expectError(error.AuthorityMismatch, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "" },
    }));
}

test "an authority too long to keep fails closed against a Host" {
    var long: [authority_octets_max + 1]u8 = @splat('a');
    var validator: MessageValidator = .init(.{ .kind = .request });
    try validator.field(&.{ .name = ":method", .value = "GET" });
    try validator.field(&.{ .name = ":scheme", .value = "https" });
    try validator.field(&.{ .name = ":authority", .value = &long });
    try validator.field(&.{ .name = ":path", .value = "/" });
    // Unverifiable is refused rather than assumed to agree.
    try testing.expectError(
        error.AuthorityMismatch,
        validator.field(&.{ .name = "host", .value = "example.com" }),
    );

    // On its own it breaks no rule, so it is not rejected on its own.
    var alone: MessageValidator = .init(.{ .kind = .request });
    try alone.field(&.{ .name = ":method", .value = "GET" });
    try alone.field(&.{ .name = ":scheme", .value = "https" });
    try alone.field(&.{ .name = ":authority", .value = &long });
    try alone.field(&.{ .name = ":path", .value = "/" });
    try alone.finish();
}

test "RFC 9110 section 8.6: content-length is 1*DIGIT and agrees with itself" {
    // Two lengths that disagree is the response-splitting pair: whichever the
    // next hop believes, the other half of the stream is a message it did not
    // see coming.
    try testing.expectError(error.ContentLengthInvalid, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "10" },
        .{ .name = "content-length", .value = "20" },
    }));
    // Repeated identical is permitted to be refused by section 8.6, and is,
    // only when it arrives as the comma-joined form that fails the ABNF.
    try validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "10" },
        .{ .name = "content-length", .value = "10" },
    });
    try testing.expectError(error.ContentLengthInvalid, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "10, 10" },
    }));
    for ([_][]const u8{ "", "-1", "+1", "0x10", "1 0", "12a", "99999999999999999999" }) |bad| {
        try testing.expectError(error.ContentLengthInvalid, validate(.response, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = bad },
        }));
    }
    // Leading zeros match `1*DIGIT` and mean what they say, so `007` and `7`
    // are the same length rather than a disagreement.
    try validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "007" },
        .{ .name = "content-length", .value = "7" },
    });
}

test "the content-length is handed to the consumer that can finish the check" {
    // Section 4.1.2's real rule compares it against the DATA frames, which a
    // field section cannot see.
    var validator: MessageValidator = .init(.{ .kind = .response });
    try validator.field(&.{ .name = ":status", .value = "204" });
    try testing.expectEqual(@as(?u64, null), validator.contentLength());
    try validator.field(&.{ .name = "content-length", .value = "4096" });
    try validator.finish();
    try testing.expectEqual(@as(?u64, 4096), validator.contentLength());
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
//# Pseudo-header fields MUST NOT appear in trailer
//# sections.
//= type=test
test "section 4.3: a trailer section carries no pseudo-header at all" {
    try validate(.trailer, &.{
        .{ .name = "grpc-status", .value = "0" },
    });
    // Both directions: the rule is about pseudo-headers, not about which kind
    // of message they belong to.
    try testing.expectError(error.PseudoInvalid, validate(.trailer, &.{
        .{ .name = ":status", .value = "200" },
    }));
    try testing.expectError(error.PseudoInvalid, validate(.trailer, &.{
        .{ .name = ":method", .value = "GET" },
    }));
    // And nothing is required of one.
    try validate(.trailer, &.{});
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
//# The only exception to this is the TE header field, which MAY be
//# present in an HTTP/3 request header; when it is, it MUST NOT contain
//# any value other than "trailers".
//= type=test
test "section 4.2: te belongs to a request, and only with one value" {
    // "the TE header field, which MAY be present in an HTTP/3 *request*". A
    // response carrying one was accepted before, which is the connection-
    // specific field the exception exists to carve out of.
    try testing.expectError(error.ConnectionSpecific, validate(.response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "te", .value = "trailers" },
    }));
    try testing.expectError(error.ConnectionSpecific, validate(.trailer, &.{
        .{ .name = "te", .value = "trailers" },
    }));
    // RFC 5234 section 2.3: an ABNF string literal is case-insensitive, so
    // these are conforming spellings rather than evasions.
    for ([_][]const u8{ "trailers", "TRAILERS", "Trailers" }) |value| {
        try validate(.request, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "te", .value = value },
        });
    }
}

//= https://www.rfc-editor.org/rfc/rfc9112#section-3.2
//# A server MUST respond with a 400 (Bad Request) status code to any
//# HTTP/1.1 request message that lacks a Host header field and to any
//# request message that contains more than one Host header field line or
//# a Host header field with an invalid field value.
//= type=test
test "a second Host is refused even with no :authority to compare it against" {
    // Found by the annotation pass. With an `:authority` present each `Host`
    // is compared against it, so two disagreeing values could not both pass —
    // and that made the hole invisible: it only opened when the pair a proxy
    // would build its request line from was the only thing present.
    try testing.expectError(error.AuthorityMismatch, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
        .{ .name = "host", .value = "evil.example" },
    }));
    // Two identical ones are refused too. RFC 9112 section 3.2 counts field
    // lines rather than values, and a proxy writing them out produces two
    // `Host` lines whatever they say.
    try testing.expectError(error.AuthorityMismatch, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
        .{ .name = "host", .value = "example.com" },
    }));
    // One is still fine.
    try validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
    });
}

//= https://www.rfc-editor.org/rfc/rfc9110#section-6.5.1
//# A recipient MUST NOT merge a trailer field into a header
//# section unless the recipient understands the corresponding header
//# field definition and that definition explicitly permits and defines
//# how trailer field values can be safely merged.
//= type=test
test "section 6.5.1: framing and routing fields may not arrive in a trailer" {
    // `content-length` in a trailer used to pass *and* be handed to a consumer
    // through `contentLength()`, indistinguishable there from one in the header
    // section. An intermediary merging that trailer on the way to HTTP/1.1
    // emits a second, later `Content-Length` — the smuggling pair this file
    // exists to prevent.
    try testing.expectError(error.ConnectionSpecific, validate(.trailer, &.{
        .{ .name = "content-length", .value = "10" },
    }));
    try testing.expectError(error.ConnectionSpecific, validate(.trailer, &.{
        .{ .name = "host", .value = "example.com" },
    }));
    // A trailer field whose definition does permit one is still fine.
    try validate(.trailer, &.{.{ .name = "grpc-status", .value = "0" }});
}
