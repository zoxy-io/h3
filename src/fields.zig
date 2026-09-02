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
    trailer,
};

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
        if (self.ordinary_seen) return error.PseudoInvalid;

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

        if (std.mem.eql(u8, one.name, host_field_name)) try self.checkHost(one.value);
        if (std.mem.eql(u8, one.name, content_length_field_name)) try self.checkContentLength(one.value);

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
    fn checkHost(self: *MessageValidator, value: []const u8) Error!void {
        assert(!self.host_seen or self.ordinary_seen);
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
    /// with a different value is the response-splitting pair, and section 8.6
    /// permits refusing even the repeated-identical form — which this does,
    /// because "a sender MUST NOT forward a message with a Content-Length
    /// header field value that does not match the ABNF above".
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
    pub fn contentLength(self: *const MessageValidator) ?u64 {
        if (!self.content_length_seen) return null;
        return self.content_length;
    }

    /// Check what only the end of a section can decide: which pseudo-headers
    /// had to be there, and which had to not be. Separate from `field` because
    /// pseudo-headers may appear in any order among themselves, so a CONNECT
    /// request's `:method` can arrive after the `:path` its presence forbids.
    pub fn finish(self: *const MessageValidator) Error!void {
        if (self.kind == .trailer) assert(self.seen.count() == 0);
        if (self.method_is_connect) assert(self.kind == .request);

        switch (self.kind) {
            .trailer => return,
            .request => return self.finishRequest(),
            // Section 4.3.2: `:status` "MUST be included in all responses".
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
        if (self.scheme_bears_authority and self.path_is_empty) return error.PseudoValueInvalid;
    }
};

/// Whether a scheme is one section 4.3.1 names as mandating an authority.
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
    try testing.expectError(error.PseudoValueInvalid, validate(.request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
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
