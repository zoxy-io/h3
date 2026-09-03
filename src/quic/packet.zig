//! RFC 9000 section 17: packet headers.
//!
//! ## The two-phase parse, and why the API cannot hide it
//!
//! A QUIC header cannot be parsed in one pass. The bits that say how long the
//! packet number is live in the first octet, and RFC 9001 section 5.4 encrypts
//! them; the mask that decrypts them is sampled from a fixed offset past the
//! *start* of the packet number. So the only thing a parser can do before
//! touching keys is find where the packet number begins — and that is exactly
//! what this module returns.
//!
//! Phase 1, here: everything up to `packet_number_offset`, plus how many octets
//! of the datagram this packet occupies.
//! Phase 2, in `crypto/protect.zig`: remove header protection, learn the packet
//! number's length, and decrypt.
//!
//! A design that returned a fully-parsed header would have to hold keys, and
//! then every consumer's key management would be this package's problem.
//!
//! ## Short headers do not carry their own length
//!
//! In a long header both connection identifiers are length-prefixed. In a short
//! header there is no length at all: the Destination Connection ID is however
//! many octets *this endpoint* chose to issue, and a parser that does not
//! already know that number cannot find the packet number. `parse` therefore
//! takes it as an argument, and this package never guesses. A stack that
//! guessed would let a peer pick the framing of packets addressed to us.
//!
//! ## Unknown versions are an answer, not an error
//!
//! RFC 8999 fixes the first five octets and the two connection identifiers
//! across every QUIC version, precisely so that an endpoint can read them out
//! of a packet whose version it does not implement — and then reply with a
//! Version Negotiation packet naming the ones it does. So an unrecognised
//! version parses to `.unsupported_version` with both identifiers intact,
//! rather than to an error. Returning an error here would make a conformant
//! server silently unable to negotiate.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const crypto = @import("crypto.zig");
const packet_number = @import("packet_number.zig");
const varint = @import("../varint.zig");

const ConnectionId = @import("ConnectionId.zig");

/// The QUIC version this package implements (RFC 9000 section 15).
pub const version_1: u32 = 0x0000_0001;

/// Section 17.2.1: the version field of a Version Negotiation packet is zero,
/// which is not a version and can never be one.
pub const version_negotiation: u32 = 0x0000_0000;

/// Section 17.2: the high bit of the first octet distinguishes the two forms.
pub const header_form_long: u8 = 0x80;

/// Sections 17.2 and 17.3: the second bit is 1 in every valid packet of this
/// version. A zero there is how QUIC is told apart from other UDP protocols
/// sharing a port, so a packet without it is discarded rather than refused —
/// it was probably never ours.
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# Packets containing a zero value for this bit are not valid packets
//# in this version and MUST be discarded.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
//# Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
//# containing a zero value for this bit are not valid packets in this
//# version and MUST be discarded.
pub const fixed_bit: u8 = 0x40;

/// Section 17.2: bits 5 and 4 of a long header's first octet.
const long_type_mask: u8 = 0x30;
const long_type_shift: u3 = 4;

/// Section 17.3.1: the spin bit, which header protection deliberately leaves
/// exposed so that a path can measure latency with it.
const spin_bit: u8 = 0x20;

/// Section 17.2: a QUIC version 1 long packet type.
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,

    /// The encryption level packets of this type are protected at.
    pub fn level(long_type: LongType) crypto.Level {
        return switch (long_type) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            // A Retry is not protected at all; it carries an integrity tag
            // under a published key instead (RFC 9001 section 5.8). The
            // caller must not reach here, and `Header` gives it no way to.
            .retry => unreachable,
        };
    }
};

pub const Kind = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    unsupported_version,
    short,
};

/// The fields common to every long header that carries a protected payload.
pub const Protected = struct {
    destination: ConnectionId,
    source: ConnectionId,
    /// Where the packet number begins, relative to the start of the datagram.
    /// This is what `crypto.Keys.open` samples its header protection mask from.
    packet_number_offset: usize,
};

pub const Header = union(Kind) {
    /// Section 17.2.2. Carries a token, which is empty unless the client is
    /// answering a Retry or replaying a NEW_TOKEN.
    initial: struct {
        destination: ConnectionId,
        source: ConnectionId,
        token: []const u8,
        packet_number_offset: usize,
    },
    /// A 0-RTT packet parses, and none is ever written: the level exists in
    /// `crypto.Level` so that a received one can be named and discarded.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
    //# A client SHOULD attempt to resend data in 0-RTT packets after it
    //# sends a new Initial packet.
    //= type=exception
    //= reason=0-RTT is out of scope, so there is no early data to resend and no 0-RTT packet is ever written; see docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
    //# New packet numbers MUST be used for any new packets that are sent;
    //# as described in Section 17.2.5.3, reusing packet numbers could
    //# compromise packet protection.
    //= type=exception
    //= reason=this rule governs the 0-RTT data a client resends after a Retry, and 0-RTT is out of scope, so there is no early data to re-send under a new number. The general no-reuse property is `Connection`'s monotonic per-space counter, which `receiveRetry` deliberately does not rewind. See docs/DESIGN.md section 2 and section 6.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
    //# A server SHOULD treat a violation of remembered limits (Section
    //# 7.4.1) as a connection error of an appropriate type (for instance, a
    //# FLOW_CONTROL_ERROR for exceeding stream data limits).
    //= type=exception
    //= reason=no transport parameters are ever remembered across connections, because 0-RTT is out of scope and this package holds no session cache; there is therefore no remembered limit to violate. See docs/DESIGN.md section 2 and section 6.
    /// Section 17.2.3.
    zero_rtt: Protected,
    /// Section 17.2.4.
    handshake: Protected,
    /// A Retry packet parses to its fields here and is acted on in
    /// `Connection.receiveRetry`, which is where every client-side rule of
    /// section 17.2.5 now lives: the integrity tag check, the one-per-attempt
    /// rule, the new Destination Connection ID, the new Initial keys and the
    /// token that goes into every subsequent Initial.
    ///
    /// What stays out of scope is the *sending* half. A server here issues no
    /// Retry, because issuing one needs a token, which needs randomness and a
    /// clock that docs/DESIGN.md section 3 keeps outside the seam.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    //# This value MUST NOT be equal to the Destination Connection ID field
    //# of the packet sent by the client.
    //= type=exception
    //= reason=a rule on the server that writes a Retry packet, and this package writes none: issuing one needs a token, which needs the randomness and the clock docs/DESIGN.md section 3 keeps outside the seam. The client's half of the same rule — discarding such a Retry — is implemented and tested in `Connection.receiveRetry`.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    //# A server MUST NOT send more than one Retry packet in response to a
    //# single UDP datagram.
    //= type=exception
    //= reason=a server here sends no Retry packet at all; issuing one needs a token, which needs randomness and a clock that docs/DESIGN.md section 3 keeps outside the seam. See docs/DESIGN.md section 2 and section 6.
    //
    /// Section 17.2.5. No packet number and no length: the rest of the datagram
    /// is the token followed by the 16-octet integrity tag.
    retry: struct {
        destination: ConnectionId,
        source: ConnectionId,
        token: []const u8,
        integrity_tag: *const [crypto.tag_octets]u8,
    },
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# Where QUIC might be multiplexed with other protocols (see
    //# [RFC7983]), servers SHOULD set the most significant bit of this
    //# field (0x40) to 1 so that Version Negotiation packets appear to have
    //# the Fixed Bit field.
    //= type=exception
    //= reason=no Version Negotiation packet is written here, so there is no unused field of ours to set; version negotiation is out of scope per docs/DESIGN.md section 2 and section 6.
    /// A Version Negotiation packet is parsed, so that a client can see one and
    /// a consumer can act on it. Sending one is a server's answer to a version
    /// it does not implement, and building that answer is out of scope here —
    /// which is what the four rules below say.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# The Version field of a Version Negotiation packet MUST be set to
    //# 0x00000000. The server MUST include the value from the Source
    //# Connection ID field of the packet it receives in the Destination
    //# Connection ID field.
    //= type=exception
    //= reason=version negotiation is out of scope; nothing here writes a Version Negotiation packet, because a connection in this package speaks one version. See docs/DESIGN.md section 2, which leaves the packet types that begin a *different* connection to the consumer, and section 6.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# The value for Source Connection ID MUST be copied from the
    //# Destination Connection ID of the received packet, which is initially
    //# randomly selected by a client.
    //= type=exception
    //= reason=no Version Negotiation packet is ever written, so there is no Source Connection ID of ours to copy into one; see docs/DESIGN.md section 2 and section 6.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# Version- specific rules for the connection ID therefore MUST NOT
    //# influence a decision about whether to send a Version Negotiation
    //# packet.
    //= type=exception
    //= reason=this package makes no decision about whether to send a Version Negotiation packet, because it never sends one; see docs/DESIGN.md section 2 and section 6.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# A server MUST NOT send more than one Version Negotiation packet in
    //# response to a single UDP datagram.
    //= type=exception
    //= reason=none is sent at all, so none can be sent twice; version negotiation is out of scope per docs/DESIGN.md section 2 and section 6.
    /// Section 17.2.1. The versions are left as raw octets rather than decoded
    /// into a slice of `u32`, because decoding them would need somewhere to put
    /// them and this package has no allocator. `versionAt` reads one.
    version_negotiation: struct {
        destination: ConnectionId,
        source: ConnectionId,
        versions: []const u8,
    },
    /// A long header in a version this package does not implement. Its
    /// identifiers are still readable — that is RFC 8999's whole point — so a
    /// server can answer with a Version Negotiation packet.
    unsupported_version: struct {
        destination: ConnectionId,
        source: ConnectionId,
        version: u32,
    },
    /// Section 17.3.1. Always the last packet in its datagram: it has no length
    /// field, so it runs to the end.
    short: struct {
        destination: ConnectionId,
        spin: bool,
        packet_number_offset: usize,
    },

    /// Where the packet number starts, for the kinds that have one.
    pub fn packetNumberOffset(header: Header) ?usize {
        return switch (header) {
            .initial => |value| value.packet_number_offset,
            .zero_rtt, .handshake => |value| value.packet_number_offset,
            .short => |value| value.packet_number_offset,
            .retry, .version_negotiation, .unsupported_version => null,
        };
    }

    /// The encryption level this packet is protected at, for the kinds that are.
    pub fn level(header: Header) ?crypto.Level {
        return switch (header) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            .short => .one_rtt,
            .retry, .version_negotiation, .unsupported_version => null,
        };
    }

    pub fn destination(header: Header) ConnectionId {
        return switch (header) {
            inline else => |value| value.destination,
        };
    }
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-4
//# When packets of different types need to be sent, endpoints SHOULD use
//# coalesced packets to send them in the same UDP datagram.
// The Length field is the whole of what makes coalescing possible, and it is
// read in both directions: a receiver steps by `octets` to reach the next
// packet, and a sender writes each level's header knowing where the one
// before it ended. `Connection` does the sending half, oldest encryption
// level first, which is what puts an Initial and a Handshake packet in one
// datagram rather than two.
/// One packet, and how much of the datagram it took.
///
/// `octets` is what advances a caller to the next packet of a coalesced
/// datagram (section 12.2). For a short header it is the whole remainder,
/// because a short header has no length field and therefore must be last.
pub const Parsed = struct {
    header: Header,
    octets: usize,
};

pub const ParseError = error{
    /// The packet claims more octets than the datagram holds, or ends inside a
    /// field. Section 12.2: discard the rest of the datagram, but keep whatever
    /// earlier packets in it already parsed.
    Truncated,
    /// The second bit of the first octet was zero. Section 17.2: not a valid
    /// packet of this version, so it is discarded rather than treated as an
    /// error against the connection.
    FixedBitUnset,
    /// A connection identifier longer than section 17.2's 20-octet limit. A
    /// connection error of type `PROTOCOL_VIOLATION`.
    ConnectionIdTooLong,
    /// A Length or Token Length field the datagram cannot satisfy, or a varint
    /// that does not decode.
    LengthMalformed,
};

/// Parse the packet beginning at `datagram[0]`.
///
/// `local_connection_id_octets` is the length of the connection identifiers
/// *this endpoint issued*, which is the only way a short header's Destination
/// Connection ID can be found. It is ignored for long headers, which carry
/// their own lengths.
pub fn parse(datagram: []const u8, local_connection_id_octets: u8) ParseError!Parsed {
    assert(local_connection_id_octets <= ConnectionId.octets_max);
    if (datagram.len < 1) return error.Truncated;

    if (datagram[0] & header_form_long != 0) return parseLong(datagram);
    return parseShort(datagram, local_connection_id_octets);
}

/// Section 17.3.1. There is nothing to check but the fixed bit: everything else
/// in a short header's first octet is under header protection.
fn parseShort(datagram: []const u8, local_connection_id_octets: u8) ParseError!Parsed {
    assert(datagram.len >= 1);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    //# Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
    //# containing a zero value for this bit are not valid packets in this
    //# version and MUST be discarded.
    if (datagram[0] & fixed_bit == 0) return error.FixedBitUnset;

    const offset = 1 + @as(usize, local_connection_id_octets);
    // Strictly greater, not `>=`: a datagram that ends exactly where the packet
    // number begins has no packet number, and every packet has one (section
    // 17.3.1). Accepting it would answer a `packet_number_offset` equal to the
    // packet's own length — an offset one past the end, which a caller is
    // entitled to slice at.
    //
    // Found by the fuzz target, which asserts that a parsed offset lies inside
    // the packet it came from. Nothing downstream would have been unsafe —
    // `crypto.Keys.open` refuses anything without room for a sample — but a
    // parser that answers a nonsense offset is a parser whose next caller has
    // to know that.
    if (datagram.len <= offset) return error.Truncated;
    const destination = ConnectionId.init(datagram[1..offset]) catch return error.ConnectionIdTooLong;

    assert(offset <= datagram.len);
    return .{
        .octets = datagram.len,
        .header = .{
            .short = .{
                .destination = destination,
                // Read before header protection comes off, which is legitimate:
                // section 17.4 exempts the spin bit from protection precisely so
                // that an observer can see it.
                .spin = datagram[0] & spin_bit != 0,
                .packet_number_offset = offset,
            },
        },
    };
}

/// Section 17.2, down to the version-specific split.
fn parseLong(datagram: []const u8) ParseError!Parsed {
    assert(datagram[0] & header_form_long != 0);
    // Five octets: the first, and the version. RFC 8999 guarantees this much of
    // any QUIC packet, in any version.
    if (datagram.len < 5) return error.Truncated;
    const version = std.mem.readInt(u32, datagram[1..5], .big);

    var cursor: usize = 5;
    const destination = try readConnectionId(datagram, &cursor);
    const source = try readConnectionId(datagram, &cursor);

    // Order matters: a Version Negotiation packet has no fixed bit requirement
    // (section 17.2.1 lets a server set the unused bits to anything), so the
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    //# Clients MUST ignore the value of this field.
    // fixed-bit check has to come after this branch rather than before it.
    if (version == version_negotiation) {
        return .{
            .octets = datagram.len,
            .header = .{ .version_negotiation = .{
                .destination = destination,
                .source = source,
                .versions = datagram[cursor..],
            } },
        };
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    //# Packets containing a zero value for this bit are not valid packets
    //# in this version and MUST be discarded.
    if (datagram[0] & fixed_bit == 0) return error.FixedBitUnset;
    if (version != version_1) {
        return .{
            .octets = datagram.len,
            .header = .{ .unsupported_version = .{
                .destination = destination,
                .source = source,
                .version = version,
            } },
        };
    }

    const long_type: LongType = @enumFromInt((datagram[0] & long_type_mask) >> long_type_shift);
    return switch (long_type) {
        .initial => parseInitial(datagram, cursor, destination, source),
        .zero_rtt, .handshake => parseLengthPrefixed(datagram, cursor, destination, source, long_type),
        .retry => parseRetry(datagram, cursor, destination, source),
    };
}

/// Section 17.2.2: a token, then the same length-prefixed body as the others.
fn parseInitial(
    datagram: []const u8,
    start: usize,
    destination: ConnectionId,
    source: ConnectionId,
) ParseError!Parsed {
    assert(start <= datagram.len);
    var cursor = start;
    const token_length = try readVarint(datagram, &cursor);
    const token_end = std.math.add(usize, cursor, std.math.cast(usize, token_length) orelse
        return error.LengthMalformed) catch return error.LengthMalformed;
    if (token_end > datagram.len) return error.Truncated;
    const token = datagram[cursor..token_end];
    // A token is read at both roles and at any length, because the role is not
    // known here. The rule is enforced one layer up, in
    // `Connection.receivePacket`, which discards an Initial carrying a token
    // when this endpoint is the client; this comment said "neither this parser
    // nor `Connection` does" for as long as that was true and no longer is.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.2
    //# Initial packets sent by the server MUST set the Token Length field
    //# to 0; clients that receive an Initial packet with a non-zero Token
    //# Length field MUST either discard the packet or generate a connection
    //# error of type PROTOCOL_VIOLATION.
    //
    //= https://www.rfc-editor.org/rfc/rfc9001#section-7
    //# Implementations SHOULD use caution in relying on any data that is
    //# contained in Initial packets that is not otherwise authenticated.
    // The token is the one field of an Initial packet whose contents an
    // attacker chooses and the AEAD does not vouch for -- Initial keys come
    // from a connection identifier anyone on the path has seen, so an Initial
    // packet authenticates nobody. The caution this package takes is total:
    // the token is borrowed out of the caller's datagram and never parsed,
    // compared or acted on, here or downstream. Nothing in the tree reads an
    // octet of it.
    cursor = token_end;

    const body = try readBody(datagram, &cursor);
    return .{
        .octets = body,
        .header = .{ .initial = .{
            .destination = destination,
            .source = source,
            .token = token,
            .packet_number_offset = cursor,
        } },
    };
}

/// Sections 17.2.3 and 17.2.4: a Length, a packet number, a payload.
fn parseLengthPrefixed(
    datagram: []const u8,
    start: usize,
    destination: ConnectionId,
    source: ConnectionId,
    long_type: LongType,
) ParseError!Parsed {
    assert(long_type == .zero_rtt or long_type == .handshake);
    var cursor = start;
    const body = try readBody(datagram, &cursor);
    const protected: Protected = .{
        .destination = destination,
        .source = source,
        .packet_number_offset = cursor,
    };
    return .{
        .octets = body,
        .header = if (long_type == .zero_rtt)
            .{ .zero_rtt = protected }
        else
            .{ .handshake = protected },
    };
}

/// Section 17.2.5: no length and no packet number — the rest of the datagram is
/// the token and then a 16-octet integrity tag.
fn parseRetry(
    datagram: []const u8,
    start: usize,
    destination: ConnectionId,
    source: ConnectionId,
) ParseError!Parsed {
    assert(start <= datagram.len);
    // Nothing reads the low four bits of the first octet, which is the whole of
    // this rule: they are the server's to choose and a client's to ignore.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5
    //# The value in the Unused field is set to an arbitrary value by the
    //# server; a client MUST ignore these bits.
    if (datagram.len < start + crypto.tag_octets) return error.Truncated;
    const token_end = datagram.len - crypto.tag_octets;
    assert(token_end >= start);
    return .{
        .octets = datagram.len,
        .header = .{ .retry = .{
            .destination = destination,
            .source = source,
            .token = datagram[start..token_end],
            .integrity_tag = datagram[token_end..][0..crypto.tag_octets],
        } },
    };
}

/// Read the Length field and return where this packet ends in the datagram,
/// leaving `cursor` at the packet number.
fn readBody(datagram: []const u8, cursor: *usize) ParseError!usize {
    const length = try readVarint(datagram, cursor);
    const octets = std.math.cast(usize, length) orelse return error.LengthMalformed;
    // The Length counts the packet number and the payload, so the packet ends
    // that far past where the number begins. A packet claiming more than the
    // datagram holds is truncated; section 12.2 makes the rest of the datagram
    // undecodable, which is the caller's cue to stop rather than to skip.
    const end = std.math.add(usize, cursor.*, octets) catch return error.LengthMalformed;
    if (end > datagram.len) return error.Truncated;
    // A Length that cannot even cover a one-octet packet number is malformed
    // rather than truncated: no amount of further data would fix it.
    if (octets < packet_number.octets_min) return error.LengthMalformed;
    return end;
}

fn readVarint(datagram: []const u8, cursor: *usize) ParseError!u64 {
    assert(cursor.* <= datagram.len);
    const decoded = varint.decode(datagram[cursor.*..]) catch return error.Truncated;
    cursor.* += decoded.octets;
    assert(cursor.* <= datagram.len);
    return decoded.value;
}

fn readConnectionId(datagram: []const u8, cursor: *usize) ParseError!ConnectionId {
    if (cursor.* >= datagram.len) return error.Truncated;
    const length = datagram[cursor.*];
    cursor.* += 1;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    //# In QUIC version 1, this value MUST NOT exceed 20 bytes. Endpoints
    //# that receive a version 1 long header with a value larger than 20
    //# MUST drop the packet.
    //
    // The cap is applied before the version is looked at, which costs the
    // SHOULD below: a long header in another QUIC version carrying a 21-octet
    // identifier is refused here rather than parsed into `.unsupported_version`
    // for a server to answer with.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    //# In order to properly form a Version Negotiation packet, servers
    //# SHOULD be able to read longer connection IDs from other QUIC
    //# versions.
    //= type=exception
    //= reason=writing a Version Negotiation packet is out of scope, so the only reader that would need the longer identifier does not exist here; a version 1 endpoint is otherwise required to refuse it. See docs/DESIGN.md section 2 and section 6.
    if (length > ConnectionId.octets_max) return error.ConnectionIdTooLong;
    const end = cursor.* + length;
    if (end > datagram.len) return error.Truncated;
    const id = ConnectionId.init(datagram[cursor.*..end]) catch return error.ConnectionIdTooLong;
    cursor.* = end;
    return id;
}

/// Read the `index`-th version out of a Version Negotiation packet's list, or
/// null when there are no more. An iterator rather than a decoded slice,
/// because a decoded slice needs storage this package does not have.
pub fn versionAt(versions: []const u8, index: usize) ?u32 {
    const at = index * 4;
    // A list whose length is not a multiple of four is malformed; section
    // 17.2.1 says to discard the packet, and answering null for the partial
    // tail is what makes that the caller's single check.
    if (at + 4 > versions.len) return null;
    return std.mem.readInt(u32, versions[at..][0..4], .big);
}

/// What `write` produced, in the shape `crypto.Keys.seal` asks for.
pub const Written = struct {
    packet_number_offset: usize,
    header_octets: usize,
};

pub const WriteError = error{
    /// `target` cannot hold the header.
    OutputTooLong,
    /// A field the format cannot carry: a token or a payload longer than a
    /// variable-length integer can describe.
    ValueTooLarge,
};

pub const LongOptions = struct {
    long_type: LongType,
    version: u32 = version_1,
    destination: ConnectionId,
    source: ConnectionId,
    /// Initial packets only; ignored for the others, which have no token field.
    token: []const u8 = &.{},
    /// Octets of plaintext the payload will hold. The Length field covers the
    /// packet number, this, and the AEAD tag.
    payload_octets: usize,
    /// Pin the Length field to this many octets rather than the fewest that
    /// hold it.
    ///
    /// Section 16 permits a variable-length integer to be encoded in any length
    /// that can hold it, and this is the one thing that permission is for: a
    /// sender that does not yet know how long its payload will be reserves the
    /// field at a width it is sure of, builds the payload, and writes the real
    /// length back into the same octets. Without it a header has to be written
    /// twice, and the second write can change the header's own length and move
    /// everything after it.
    ///
    /// `Written.packet_number_offset` minus this is where the field starts.
    length_octets: ?u8 = null,
    number: u64,
    number_octets: u8,
};

/// Write a long header, leaving the packet number in place and the first octet
/// unprotected — which is exactly the state `crypto.Keys.seal` expects.
pub fn writeLong(target: []u8, options: LongOptions) WriteError!Written {
    assert(options.number_octets >= packet_number.octets_min);
    assert(options.number_octets <= packet_number.octets_max);
    assert(options.long_type != .retry); // A Retry has no packet number; `retry.zig` builds one.

    var cursor: usize = 0;
    try put(target, &cursor, 1);
    // The two reserved bits (0x0c) are absent from this expression, which is
    // how they are set to zero: header protection then masks them, and a peer
    // that finds them non-zero after unmasking has found a violation.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    //# The value included prior to protection MUST be set to 0.
    target[0] = header_form_long | fixed_bit |
        (@as(u8, @intFromEnum(options.long_type)) << long_type_shift) |
        (options.number_octets - 1);
    try put(target, &cursor, 4);
    std.mem.writeInt(u32, target[1..5], options.version, .big);

    try writeConnectionId(target, &cursor, options.destination);
    try writeConnectionId(target, &cursor, options.source);

    if (options.long_type == .initial) {
        try writeVarint(target, &cursor, options.token.len);
        try put(target, &cursor, options.token.len);
        @memcpy(target[cursor - options.token.len ..][0..options.token.len], options.token);
    }

    // Section 17.2: the Length covers the packet number, the payload and the
    // tag. Computed here rather than asked for, because a caller that got it
    // wrong would produce a packet the peer discards without saying why.
    const length = @as(u64, options.number_octets) + options.payload_octets + crypto.tag_octets;
    if (options.length_octets) |octets| {
        const at = cursor;
        try put(target, &cursor, octets);
        varint.encodeIn(target[at..cursor], length, octets) catch |err| return switch (err) {
            error.OutputTooLong => error.OutputTooLong,
            error.ValueTooLarge => error.ValueTooLarge,
        };
    } else {
        try writeVarint(target, &cursor, length);
    }

    const packet_number_offset = cursor;
    try put(target, &cursor, options.number_octets);
    packet_number.encode(target[packet_number_offset..cursor], options.number, options.number_octets);

    assert(cursor == packet_number_offset + options.number_octets);
    return .{ .packet_number_offset = packet_number_offset, .header_octets = cursor };
}

pub const ShortOptions = struct {
    destination: ConnectionId,
    number: u64,
    number_octets: u8,
    /// RFC 9001 section 6: which generation of 1-RTT keys sealed this packet.
    key_phase: bool = false,
    /// RFC 9000 section 17.3.1. A client that does not participate should send
    /// a random value on each connection rather than a constant, which is the
    /// caller's business: this package draws no randomness.
    ///
    /// Defaulting to false is section 17.4's "disabled": nothing here derives a
    /// spin value from the packets it has seen, so the feature is off unless a
    /// caller turns it on per packet, and no incoming value is ever acted on.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
    //# An endpoint that does not support this feature MUST disable it, as
    //# defined below.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
    //# Implementations MUST allow administrators of clients and servers to
    //# disable the spin bit either globally or on a per-connection basis.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
    //# When the spin bit is disabled, endpoints MAY set the spin bit to any
    //# value and MUST ignore any incoming value.
    //
    // The one in sixteen below is the half this package cannot do: choosing a
    // random subset of paths needs entropy, and the seam keeps entropy out.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
    //# Even when the spin bit is not disabled by the administrator,
    //# endpoints MUST disable their use of the spin bit for a random
    //# selection of at least one in every 16 network paths, or for one in
    //# every 16 connection IDs, in order to ensure that QUIC connections
    //# that disable the spin bit are commonly observed on the network.
    //= type=exception
    //= reason=the spin bit is off by default and never set by this package, so the sixteenth connection is as disabled as the other fifteen; drawing the random selection would need entropy, which docs/DESIGN.md section 3 keeps outside the seam.
    spin: bool = false,
};

/// Write a short header. The Destination Connection ID's length is implied by
/// the identifier itself, which is why nothing here needs telling.
pub fn writeShort(target: []u8, options: ShortOptions) WriteError!Written {
    assert(options.number_octets >= packet_number.octets_min);
    assert(options.number_octets <= packet_number.octets_max);

    var cursor: usize = 0;
    try put(target, &cursor, 1);
    // A short header's reserved bits are 0x18, and the same reasoning applies:
    // they are left out of the expression rather than cleared afterwards.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    //# The value included prior to protection MUST be set to 0.
    target[0] = fixed_bit | (options.number_octets - 1);
    if (options.key_phase) target[0] |= 0x04;
    if (options.spin) target[0] |= spin_bit;

    try writeConnectionIdBare(target, &cursor, options.destination);
    const packet_number_offset = cursor;
    try put(target, &cursor, options.number_octets);
    packet_number.encode(target[packet_number_offset..cursor], options.number, options.number_octets);

    assert(target[0] & header_form_long == 0);
    return .{ .packet_number_offset = packet_number_offset, .header_octets = cursor };
}

/// Advance `cursor` by `octets`, or refuse. One helper rather than a bounds
/// check per field, so that a field added later cannot forget one.
fn put(target: []const u8, cursor: *usize, octets: usize) WriteError!void {
    const end = std.math.add(usize, cursor.*, octets) catch return error.ValueTooLarge;
    if (end > target.len) return error.OutputTooLong;
    cursor.* = end;
}

fn writeVarint(target: []u8, cursor: *usize, value: u64) WriteError!void {
    if (value > varint.max) return error.ValueTooLarge;
    const start = cursor.*;
    try put(target, cursor, varint.encodedLength(value));
    _ = varint.encode(target[start..cursor.*], value) catch unreachable; // The two checks above are the guard; `put` bounded the slice and the range check bounded the value.
}

fn writeConnectionId(target: []u8, cursor: *usize, id: ConnectionId) WriteError!void {
    const at = cursor.*;
    try put(target, cursor, 1);
    target[at] = id.length;
    try writeConnectionIdBare(target, cursor, id);
}

fn writeConnectionIdBare(target: []u8, cursor: *usize, id: ConnectionId) WriteError!void {
    const at = cursor.*;
    try put(target, cursor, id.length);
    @memcpy(target[at..cursor.*], id.bytes());
}

const testing = std.testing;

test "an Initial header parses to the offset header protection samples from" {
    // 0xc3 long/fixed/Initial/4-octet number, version 1, 4-octet DCID, empty
    // SCID, empty token, Length = 20.
    const datagram = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0x00, 0x00, 0x14,
    } ++ [_]u8{0} ** 20;

    const parsed = try parse(&datagram, 0);
    try testing.expectEqual(Kind.initial, @as(Kind, parsed.header));
    const initial = parsed.header.initial;
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, initial.destination.bytes());
    try testing.expect(initial.source.isEmpty());
    try testing.expectEqual(@as(usize, 0), initial.token.len);
    try testing.expectEqual(@as(usize, 13), initial.packet_number_offset);
    // Length 20 counts the packet number and the payload, from offset 13.
    try testing.expectEqual(@as(usize, 33), parsed.octets);
    try testing.expectEqual(crypto.Level.initial, parsed.header.level().?);
}

test "a short header needs the local identifier length to find its number" {
    const datagram = [_]u8{ 0x40, 0x11, 0x22, 0x33, 0x44 } ++ [_]u8{0xee} ** 40;
    const parsed = try parse(&datagram, 4);
    const short = parsed.header.short;
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33, 0x44 }, short.destination.bytes());
    try testing.expectEqual(@as(usize, 5), short.packet_number_offset);
    try testing.expect(!short.spin);
    // No length field: a short header owns the rest of the datagram.
    try testing.expectEqual(datagram.len, parsed.octets);

    // The same octets read with a different local length are a different
    // packet. That is not a bug to be defended against here — it is why the
    // argument exists.
    const other = try parse(&datagram, 0);
    try testing.expectEqual(@as(usize, 1), other.header.short.packet_number_offset);
}

test "a Version Negotiation packet is readable without a supported version" {
    const datagram = [_]u8{
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x01, 0x02, 0x01, 0x0a,
        0x00, 0x00, 0x00, 0x01, 0xaa,
        0xaa, 0xaa, 0xaa,
    };
    const parsed = try parse(&datagram, 0);
    const negotiation = parsed.header.version_negotiation;
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, negotiation.destination.bytes());
    try testing.expectEqualSlices(u8, &.{0x0a}, negotiation.source.bytes());
    try testing.expectEqual(@as(u32, version_1), versionAt(negotiation.versions, 0).?);
    try testing.expectEqual(@as(u32, 0xaaaa_aaaa), versionAt(negotiation.versions, 1).?);
    try testing.expectEqual(@as(?u32, null), versionAt(negotiation.versions, 2));
    try testing.expectEqual(@as(?usize, null), parsed.header.packetNumberOffset());
}

test "an unknown version keeps its identifiers so a server can answer" {
    const datagram = [_]u8{
        0xc0, 0xff, 0x00, 0x00, 0x21,
        0x02, 0x01, 0x02, 0x00,
    } ++ [_]u8{0} ** 8;
    const parsed = try parse(&datagram, 0);
    const unsupported = parsed.header.unsupported_version;
    try testing.expectEqual(@as(u32, 0xff00_0021), unsupported.version);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, unsupported.destination.bytes());
    try testing.expectEqual(@as(?crypto.Level, null), parsed.header.level());
}

test "a Retry ends in its integrity tag" {
    const datagram = [_]u8{ 0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 } ++
        [_]u8{ 0x74, 0x6f, 0x6b } ++ [_]u8{0x5a} ** crypto.tag_octets;
    const parsed = try parse(&datagram, 0);
    const retry = parsed.header.retry;
    try testing.expectEqualStrings("tok", retry.token);
    try testing.expectEqual(@as(u8, 0x5a), retry.integrity_tag[0]);
    try testing.expectEqual(datagram.len, parsed.octets);
}

test "a short header with no room for a packet number is truncated" {
    // The datagram ends exactly where the packet number would begin.
    const exact = [_]u8{ 0x40, 0x11, 0x22, 0x33, 0x44 };
    try testing.expectError(error.Truncated, parse(&exact, 4));
    // One more octet, and there is a packet number to point at.
    const enough = [_]u8{ 0x40, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const parsed = try parse(&enough, 4);
    try testing.expectEqual(@as(usize, 5), parsed.header.short.packet_number_offset);
    try testing.expect(parsed.header.short.packet_number_offset < parsed.octets);

    // And the zero-length connection identifier case, which is the one a
    // minimal short header uses.
    try testing.expectError(error.Truncated, parse(&.{0x40}, 0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# Packets containing a zero value for this bit are not valid packets
//# in this version and MUST be discarded.
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
//# Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
//# containing a zero value for this bit are not valid packets in this
//# version and MUST be discarded.
//= type=test
test "the fixed bit is what tells QUIC from anything else on the port" {
    const long = [_]u8{ 0x80 | 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04 } ++ [_]u8{0} ** 4;
    try testing.expectError(error.FixedBitUnset, parse(&long, 0));
    const short = [_]u8{0x00} ++ [_]u8{0} ** 40;
    try testing.expectError(error.FixedBitUnset, parse(&short, 0));
}

test "a length past the end of the datagram is truncation, not a short read" {
    const datagram = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x44, 0x00,
    } ++ [_]u8{0} ** 4;
    try testing.expectError(error.Truncated, parse(&datagram, 0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# In QUIC version 1, this value MUST NOT exceed 20 bytes. Endpoints
//# that receive a version 1 long header with a value larger than 20
//# MUST drop the packet.
//= type=test
test "a connection identifier past twenty octets is a protocol violation" {
    const datagram = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01, 21 } ++ [_]u8{0xaa} ** 32;
    try testing.expectError(error.ConnectionIdTooLong, parse(&datagram, 0));
}

test "a written long header parses back to what was written" {
    var target: [128]u8 = @splat(0);
    const written = try writeLong(&target, .{
        .long_type = .handshake,
        .destination = try ConnectionId.init(&.{ 1, 2, 3, 4, 5 }),
        .source = try ConnectionId.init(&.{ 9, 9 }),
        .payload_octets = 30,
        .number = 0x1234,
        .number_octets = 2,
    });
    try testing.expectEqual(written.packet_number_offset + 2, written.header_octets);

    const parsed = try parse(target[0 .. written.header_octets + 30 + crypto.tag_octets], 0);
    const handshake = parsed.header.handshake;
    try testing.expectEqual(written.packet_number_offset, handshake.packet_number_offset);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, handshake.destination.bytes());
    try testing.expectEqualSlices(u8, &.{ 9, 9 }, handshake.source.bytes());
    try testing.expectEqual(written.header_octets + 30 + crypto.tag_octets, parsed.octets);
}

test "a written Initial carries its token back" {
    var target: [128]u8 = @splat(0);
    const written = try writeLong(&target, .{
        .long_type = .initial,
        .destination = try ConnectionId.init(&.{0xab}),
        .source = try ConnectionId.init(&.{}),
        .token = "a-retry-token",
        .payload_octets = 8,
        .number = 1,
        .number_octets = 1,
    });
    const parsed = try parse(target[0 .. written.header_octets + 8 + crypto.tag_octets], 0);
    try testing.expectEqualStrings("a-retry-token", parsed.header.initial.token);
}

test "a written short header parses back at the length it was given" {
    var target: [64]u8 = @splat(0);
    const written = try writeShort(&target, .{
        .destination = try ConnectionId.init(&.{ 7, 7, 7 }),
        .number = 9,
        .number_octets = 1,
        .spin = true,
    });
    try testing.expectEqual(@as(usize, 4), written.packet_number_offset);
    try testing.expectEqual(@as(usize, 5), written.header_octets);
    const parsed = try parse(target[0..40], 3);
    try testing.expect(parsed.header.short.spin);
    try testing.expectEqual(@as(usize, 4), parsed.header.short.packet_number_offset);
}

test "a pinned Length field is a reservation to write back into" {
    var target: [256]u8 = @splat(0);
    const written = try writeLong(&target, .{
        .long_type = .handshake,
        .destination = try ConnectionId.init(&.{ 1, 2 }),
        .source = try ConnectionId.init(&.{}),
        .payload_octets = 0,
        .number = 0,
        .number_octets = 1,
        .length_octets = 4,
    });
    // The field sits directly before the packet number, which is what lets a
    // caller find it again without being told where it is.
    const at = written.packet_number_offset - 4;

    // Back-fill it the way a sender does once the payload is built.
    const length: u64 = 1 + 120 + crypto.tag_octets;
    try varint.encodeIn(target[at..][0..4], length, 4);

    const parsed = try parse(target[0 .. written.header_octets + 120 + crypto.tag_octets], 0);
    try testing.expectEqual(written.packet_number_offset, parsed.header.handshake.packet_number_offset);
    try testing.expectEqual(written.header_octets + 120 + crypto.tag_octets, parsed.octets);

    // And a pinned width does not change with the value, which is the property
    // the reservation depends on.
    const narrow = try writeLong(&target, .{
        .long_type = .handshake,
        .destination = try ConnectionId.init(&.{ 1, 2 }),
        .source = try ConnectionId.init(&.{}),
        .payload_octets = 3,
        .number = 0,
        .number_octets = 1,
        .length_octets = 4,
    });
    try testing.expectEqual(written.header_octets, narrow.header_octets);
}

test "a header longer than the target is refused rather than truncated" {
    var target: [4]u8 = @splat(0);
    try testing.expectError(error.OutputTooLong, writeLong(&target, .{
        .long_type = .handshake,
        .destination = try ConnectionId.init(&.{ 1, 2, 3, 4 }),
        .source = try ConnectionId.init(&.{}),
        .payload_octets = 0,
        .number = 0,
        .number_octets = 1,
    }));
}

test "write and seal compose into a packet that opens" {
    // The join this package exists to make: `packet.writeLong` produces exactly
    // the two offsets `crypto.Keys.seal` asks for, and `packet.parse` recovers
    // the first of them from the wire.
    const dcid = try ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const keys: crypto.Keys = .initial(dcid.bytes(), .client);

    var datagram: [256]u8 = @splat(0);
    const payload = "the CRYPTO frames of a ClientHello would go here";
    const written = try writeLong(&datagram, .{
        .long_type = .initial,
        .destination = dcid,
        .source = try ConnectionId.init(&.{ 0x01, 0x02 }),
        .payload_octets = payload.len,
        .number = 0,
        .number_octets = 4,
    });
    @memcpy(datagram[written.header_octets..][0..payload.len], payload);
    const total = try keys.seal(&datagram, written.packet_number_offset, written.header_octets, payload.len, 0);

    const parsed = try parse(datagram[0..total], 0);
    try testing.expectEqual(total, parsed.octets);
    const offset = parsed.header.packetNumberOffset().?;
    try testing.expectEqual(written.packet_number_offset, offset);

    const opened = try keys.open(datagram[0..total], offset, null);
    try testing.expectEqual(@as(u64, 0), opened.number);
    try testing.expectEqualStrings(payload, opened.payload);
}

test "a coalesced datagram advances by each packet's octets" {
    // Section 12.2: several packets in one datagram, the short one last.
    var datagram: [512]u8 = @splat(0);
    var cursor: usize = 0;

    const first = try writeLong(datagram[cursor..], .{
        .long_type = .initial,
        .destination = try ConnectionId.init(&.{0x01}),
        .source = try ConnectionId.init(&.{}),
        .payload_octets = 4,
        .number = 0,
        .number_octets = 1,
    });
    cursor += first.header_octets + 4 + crypto.tag_octets;

    const second = try writeShort(datagram[cursor..], .{
        .destination = try ConnectionId.init(&.{0x01}),
        .number = 0,
        .number_octets = 1,
    });
    const end = cursor + second.header_octets + 4 + crypto.tag_octets;

    const one = try parse(datagram[0..end], 1);
    try testing.expectEqual(Kind.initial, @as(Kind, one.header));
    try testing.expectEqual(cursor, one.octets);
    const two = try parse(datagram[one.octets..end], 1);
    try testing.expectEqual(Kind.short, @as(Kind, two.header));
    try testing.expectEqual(end - cursor, two.octets);
}
