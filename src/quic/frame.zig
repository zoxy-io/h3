//! RFC 9000 section 19: the frames a packet payload is made of.
//!
//! A payload is a run of frames with no count and no separator — each frame's
//! type says how long it is, and the run ends when the payload does. That shape
//! is why `Iterator` exists and why every length in this file is checked
//! against the remaining slice rather than trusted: a frame that lies about its
//! length is a frame that reads into the next one, and there is no framing
//! layer underneath to catch it. RFC 9001's AEAD guarantees the octets came
//! from the peer, not that the peer is honest.
//!
//! ## Where a frame may appear is part of the frame's definition
//!
//! Section 12.4's Table 3 says which packet types each frame is allowed in, and
//! it is not a formality: a STREAM frame in an Initial packet would be
//! application data accepted before the handshake authenticated anybody, and a
//! HANDSHAKE_DONE from a client is a client telling a server the handshake
//! finished. Both are `PROTOCOL_VIOLATION`, and `Type.allowedIn` is where that
//! table lives so that no consumer has to transcribe it.
//!
//! ## What is decoded, and what is borrowed
//!
//! Numbers are decoded; octets are borrowed. A CRYPTO frame's data, a STREAM
//! frame's data, a CONNECTION_CLOSE's reason phrase and an ACK's ranges are all
//! slices into the caller's packet buffer, valid exactly as long as it is. That
//! is the no-allocator rule doing its job: an ACK frame can name a quarter of a
//! million packets, and materializing its ranges would need somewhere to put
//! them. `Ack.ranges` iterates the wire bytes instead.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const error_code = @import("error_code.zig");
const packet_number = @import("packet_number.zig");
const varint = @import("../varint.zig");

const ConnectionId = @import("ConnectionId.zig");

/// Section 19: the frame type registry.
///
/// Non-exhaustive because the registry is extensible and section 22.4 reserves
/// a GREASE family. An unknown type is a `FRAME_ENCODING_ERROR` — unlike
/// HTTP/2, QUIC gives a frame no length prefix, so an unknown one cannot be
/// skipped and there is nothing to do but close the connection.
pub const Type = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    /// 0x08 through 0x0f: the low three bits are OFF, LEN and FIN.
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidirectional = 0x12,
    max_streams_unidirectional = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidirectional = 0x16,
    streams_blocked_unidirectional = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close_transport = 0x1c,
    connection_close_application = 0x1d,
    handshake_done = 0x1e,
    _,

    /// Section 19.8: STREAM occupies eight type values, whose low bits are
    /// flags rather than a different frame.
    pub const stream_first: u64 = 0x08;
    pub const stream_last: u64 = 0x0f;
    pub const stream_offset_bit: u64 = 0x04;
    pub const stream_length_bit: u64 = 0x02;
    pub const stream_fin_bit: u64 = 0x01;

    /// The type with STREAM's flag bits cleared, so a `switch` has one arm for
    /// the eight spellings of one frame.
    pub fn canonical(frame_type: Type) Type {
        const value = @intFromEnum(frame_type);
        if (value >= stream_first and value <= stream_last) return .stream;
        return frame_type;
    }

    /// Section 13.2.1: a frame that obliges the peer to acknowledge the packet
    /// carrying it. Everything but ACK, PADDING and CONNECTION_CLOSE.
    pub fn ackEliciting(frame_type: Type) bool {
        return switch (frame_type.canonical()) {
            .padding, .ack, .ack_ecn, .connection_close_transport, .connection_close_application => false,
            else => true,
        };
    }

    /// Section 9.1: a frame that may be sent on a path not yet validated,
    /// because it cannot be used to send application data to an address the
    /// peer has not proven it owns.
    pub fn probing(frame_type: Type) bool {
        return switch (frame_type.canonical()) {
            .path_challenge, .path_response, .new_connection_id, .padding => true,
            else => false,
        };
    }

    /// Section 12.4, Table 3: whether this frame may appear at this encryption
    /// level.
    pub fn allowedIn(frame_type: Type, level: @import("crypto.zig").Level) bool {
        const initial_or_handshake = level == .initial or level == .handshake;
        return switch (frame_type.canonical()) {
            .padding, .ping, .connection_close_transport => true,
            .ack, .ack_ecn, .crypto => level != .zero_rtt,
            .new_token, .path_response, .handshake_done => level == .one_rtt,
            .reset_stream,
            .stop_sending,
            .stream,
            .max_data,
            .max_stream_data,
            .max_streams_bidirectional,
            .max_streams_unidirectional,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidirectional,
            .streams_blocked_unidirectional,
            .new_connection_id,
            .retire_connection_id,
            .path_challenge,
            .connection_close_application,
            => !initial_or_handshake,
            // An unknown type is refused everywhere; `parse` rejects it before
            // this is asked, and answering false keeps the two consistent.
            else => false,
        };
    }
};

/// Section 19.15: the token that travels with a new connection identifier.
pub const stateless_reset_token_octets: usize = 16;

/// Section 19.17 and 19.18: PATH_CHALLENGE and PATH_RESPONSE carry exactly
/// eight octets of unpredictable data.
pub const path_data_octets: usize = 8;

/// Section 19.11: a streams limit above this cannot be encoded as a stream
/// identifier, so a frame carrying one is a `FRAME_ENCODING_ERROR`.
pub const streams_max: u64 = 1 << 60;

comptime {
    assert(stateless_reset_token_octets == 16);
    assert(path_data_octets == 8);
    // A stream identifier is a varint whose low two bits are the type, so the
    // count of streams of one type tops out two bits below the varint's range.
    assert(streams_max == (varint.max + 1) / 4);
}

pub const ParseError = error{
    /// A field runs past the end of the payload.
    Truncated,
    /// A frame type this version does not define. Section 12.4: a frame has no
    /// length prefix, so there is no way to skip one — `FRAME_ENCODING_ERROR`.
    UnknownType,
    /// A field the frame's own rules forbid: a `retire_prior_to` above the
    /// sequence number it arrived with, a stream offset that would put the
    /// final size past 2^62-1, a streams limit above 2^60, a connection
    /// identifier of the wrong length. All `FRAME_ENCODING_ERROR`.
    Malformed,
};

pub const Ecn = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// Section 19.3. The ranges are left as wire octets; `iterate` walks them.
/// Section 19.6. Named rather than anonymous so that a receiver can take one
/// as an argument; `Ack` beside it always could.
pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

pub const Ack = struct {
    largest: u64,
    /// The raw delay field. Scaling it by the peer's `ack_delay_exponent`
    /// transport parameter is the connection's business, not this codec's —
    /// applying it here would mean this module holding connection state.
    delay: u64,
    /// How many packets below `largest` are acknowledged contiguously.
    first_range: u64,
    range_count: u64,
    /// The `[Gap, ACK Range Length]` pairs, unparsed.
    ranges: []const u8,
    /// Present only in an ACK frame of type 0x03.
    ecn: ?Ecn,

    /// The lowest packet number the first range covers.
    pub fn smallest(ack: Ack) ParseError!u64 {
        if (ack.first_range > ack.largest) return error.Malformed;
        return ack.largest - ack.first_range;
    }

    pub fn iterate(ack: Ack) RangeIterator {
        return .{ .ack = ack, .next_largest = ack.largest, .cursor = .{ .source = ack.ranges } };
    }
};

/// One acknowledged run, inclusive at both ends.
pub const Range = struct {
    largest: u64,
    smallest: u64,
};

/// Walks an ACK frame's ranges from the highest packet number downward, which
/// is the order the wire format is in.
///
/// Bounded by `range_count`, which is itself bounded by the payload: each range
/// costs at least two octets, so a frame cannot claim more ranges than it has
/// room for. That is checked at parse time, not here, so this iterator cannot
/// be handed a count the bytes do not support.
pub const RangeIterator = struct {
    ack: Ack,
    next_largest: u64,
    emitted: u64 = 0,
    cursor: Cursor,
    first_done: bool = false,

    pub fn next(self: *RangeIterator) ParseError!?Range {
        if (!self.first_done) {
            self.first_done = true;
            const smallest = try self.ack.smallest();
            self.next_largest = smallest;
            return .{ .largest = self.ack.largest, .smallest = smallest };
        }
        if (self.emitted == self.ack.range_count) return null;
        self.emitted += 1;
        assert(self.emitted <= self.ack.range_count);

        const gap = try self.cursor.varint();
        const length = try self.cursor.varint();
        // Section 19.3.1: the next range's largest is
        // `previous_smallest - gap - 2`, and both subtractions can underflow on
        // a hostile frame. Written as two guarded steps rather than one
        // expression so that the error names which one failed to hold.
        if (self.next_largest < gap + 2) return error.Malformed;
        const largest = self.next_largest - gap - 2;
        if (length > largest) return error.Malformed;
        const smallest = largest - length;
        self.next_largest = smallest;
        return .{ .largest = largest, .smallest = smallest };
    }
};

pub const Frame = union(enum) {
    /// Section 19.1. A run of PADDING octets is reported as one frame, because
    /// an Initial packet is padded to 1200 octets and reporting 1150 separate
    /// frames would make the iterator the bottleneck.
    padding: struct { octets: usize },
    ping,
    ack: Ack,
    reset_stream: struct { stream: u64, code: error_code.Application, final_size: u64 },
    stop_sending: struct { stream: u64, code: error_code.Application },
    crypto: Crypto,
    new_token: struct { token: []const u8 },
    stream: struct { stream: u64, offset: u64, data: []const u8, fin: bool },
    max_data: struct { maximum: u64 },
    max_stream_data: struct { stream: u64, maximum: u64 },
    max_streams: struct { bidirectional: bool, maximum: u64 },
    data_blocked: struct { limit: u64 },
    stream_data_blocked: struct { stream: u64, limit: u64 },
    streams_blocked: struct { bidirectional: bool, limit: u64 },
    new_connection_id: struct {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: *const [stateless_reset_token_octets]u8,
    },
    retire_connection_id: struct { sequence: u64 },
    path_challenge: struct { data: *const [path_data_octets]u8 },
    path_response: struct { data: *const [path_data_octets]u8 },
    connection_close: struct {
        /// True for a type 0x1d frame, whose code comes from the *application*
        /// registry and which carries no triggering frame type.
        application: bool,
        code: u64,
        /// Section 19.19: the frame type that triggered the close, present only
        /// on a transport close.
        triggered_by: ?u64,
        reason: []const u8,
    },
    handshake_done,

    pub fn frameType(frame: Frame) Type {
        return switch (frame) {
            .padding => .padding,
            .ping => .ping,
            .ack => |value| if (value.ecn == null) .ack else .ack_ecn,
            .reset_stream => .reset_stream,
            .stop_sending => .stop_sending,
            .crypto => .crypto,
            .new_token => .new_token,
            .stream => .stream,
            .max_data => .max_data,
            .max_stream_data => .max_stream_data,
            .max_streams => |value| if (value.bidirectional) .max_streams_bidirectional else .max_streams_unidirectional,
            .data_blocked => .data_blocked,
            .stream_data_blocked => .stream_data_blocked,
            .streams_blocked => |value| if (value.bidirectional) .streams_blocked_bidirectional else .streams_blocked_unidirectional,
            .new_connection_id => .new_connection_id,
            .retire_connection_id => .retire_connection_id,
            .path_challenge => .path_challenge,
            .path_response => .path_response,
            .connection_close => |value| if (value.application) .connection_close_application else .connection_close_transport,
            .handshake_done => .handshake_done,
        };
    }

    pub fn ackEliciting(frame: Frame) bool {
        return frame.frameType().ackEliciting();
    }
};

pub const Parsed = struct {
    frame: Frame,
    octets: usize,
};

/// A bounded cursor over a payload. Not an I/O reader — there is nothing to
/// read from, only a slice to walk — and named so that it cannot be mistaken
/// for one, which `zig build lint` would refuse anyway.
const Cursor = struct {
    source: []const u8,
    offset: usize = 0,

    fn remaining(self: *const Cursor) usize {
        assert(self.offset <= self.source.len);
        return self.source.len - self.offset;
    }

    fn varint(self: *Cursor) ParseError!u64 {
        const decoded = @import("../varint.zig").decode(self.source[self.offset..]) catch return error.Truncated;
        self.offset += decoded.octets;
        assert(self.offset <= self.source.len);
        return decoded.value;
    }

    fn byte(self: *Cursor) ParseError!u8 {
        if (self.remaining() < 1) return error.Truncated;
        const value = self.source[self.offset];
        self.offset += 1;
        return value;
    }

    fn take(self: *Cursor, octets: u64) ParseError![]const u8 {
        const wanted = std.math.cast(usize, octets) orelse return error.Truncated;
        if (self.remaining() < wanted) return error.Truncated;
        const slice = self.source[self.offset..][0..wanted];
        self.offset += wanted;
        assert(self.offset <= self.source.len);
        return slice;
    }

    fn takeArray(self: *Cursor, comptime octets: usize) ParseError!*const [octets]u8 {
        const slice = try self.take(octets);
        assert(slice.len == octets);
        return slice[0..octets];
    }
};

/// Parse the frame beginning at `payload[0]`.
pub fn parse(payload: []const u8) ParseError!Parsed {
    if (payload.len == 0) return error.Truncated;
    var cursor: Cursor = .{ .source = payload };
    // Section 12.4: a frame type MUST use the shortest variable-length integer
    // encoding, so a longer spelling is refused rather than decoded. Without
    // this every frame type has four names and a `switch` has four ways to be
    // surprised.
    const decoded = varint.decodeMinimal(payload) catch |err| return switch (err) {
        error.Incomplete => error.Truncated,
        error.NotMinimal => error.UnknownType,
    };
    cursor.offset = decoded.octets;
    const frame_type: Type = @enumFromInt(decoded.value);

    const frame = try parseBody(&cursor, frame_type, payload);
    assert(cursor.offset <= payload.len);
    assert(cursor.offset >= 1);
    return .{ .frame = frame, .octets = cursor.offset };
}

fn parseBody(cursor: *Cursor, frame_type: Type, payload: []const u8) ParseError!Frame {
    return switch (frame_type.canonical()) {
        // The one frame whose length is not implied by its fields: the run is
        // measured and the cursor moved to its end, because `parse` reports
        // consumption from the cursor and a run reported without being consumed
        // would be re-parsed one octet later, forever.
        .padding => padding: {
            const octets = paddingRun(payload);
            assert(octets >= cursor.offset);
            cursor.offset = octets;
            break :padding .{ .padding = .{ .octets = octets } };
        },
        .ping => .ping,
        .ack, .ack_ecn => .{ .ack = try parseAck(cursor, frame_type == .ack_ecn) },
        .reset_stream => .{ .reset_stream = .{
            .stream = try cursor.varint(),
            .code = @enumFromInt(try cursor.varint()),
            .final_size = try cursor.varint(),
        } },
        .stop_sending => .{ .stop_sending = .{
            .stream = try cursor.varint(),
            .code = @enumFromInt(try cursor.varint()),
        } },
        .crypto => try parseCrypto(cursor),
        .new_token => .{ .new_token = .{ .token = try takeLengthPrefixed(cursor) } },
        .stream => try parseStream(cursor, frame_type),
        .max_data => .{ .max_data = .{ .maximum = try cursor.varint() } },
        .max_stream_data => .{ .max_stream_data = .{
            .stream = try cursor.varint(),
            .maximum = try cursor.varint(),
        } },
        .max_streams_bidirectional, .max_streams_unidirectional => .{ .max_streams = .{
            .bidirectional = frame_type == .max_streams_bidirectional,
            .maximum = try streamsLimit(cursor),
        } },
        .data_blocked => .{ .data_blocked = .{ .limit = try cursor.varint() } },
        .stream_data_blocked => .{ .stream_data_blocked = .{
            .stream = try cursor.varint(),
            .limit = try cursor.varint(),
        } },
        .streams_blocked_bidirectional, .streams_blocked_unidirectional => .{ .streams_blocked = .{
            .bidirectional = frame_type == .streams_blocked_bidirectional,
            .limit = try streamsLimit(cursor),
        } },
        .new_connection_id => try parseNewConnectionId(cursor),
        .retire_connection_id => .{ .retire_connection_id = .{ .sequence = try cursor.varint() } },
        .path_challenge => .{ .path_challenge = .{ .data = try cursor.takeArray(path_data_octets) } },
        .path_response => .{ .path_response = .{ .data = try cursor.takeArray(path_data_octets) } },
        .connection_close_transport, .connection_close_application => try parseConnectionClose(cursor, frame_type),
        .handshake_done => .handshake_done,
        else => error.UnknownType,
    };
}

/// Section 19.1: how many PADDING octets start here. Coalesced rather than
/// reported one at a time, because a padded Initial packet is over a thousand
/// of them and a per-octet iterator would dominate the receive path.
fn paddingRun(payload: []const u8) usize {
    assert(payload.len >= 1);
    assert(payload[0] == 0x00);
    var octets: usize = 0;
    while (octets < payload.len and payload[octets] == 0x00) {
        octets += 1;
    }
    assert(octets >= 1);
    assert(octets <= payload.len);
    return octets;
}

fn parseAck(cursor: *Cursor, ecn: bool) ParseError!Ack {
    const largest = try cursor.varint();
    const delay = try cursor.varint();
    const range_count = try cursor.varint();
    const first_range = try cursor.varint();
    if (first_range > largest) return error.Malformed;

    // Each range is two variable-length integers, so it costs at least two
    // octets. A count larger than the payload could hold is refused here rather
    // than discovered halfway through the iterator, so that `RangeIterator` can
    // treat its count as trustworthy.
    if (range_count > cursor.remaining() / 2) return error.Truncated;

    const ranges_start = cursor.offset;
    var index: u64 = 0;
    while (index < range_count) : (index += 1) {
        assert(index <= range_count);
        _ = try cursor.varint();
        _ = try cursor.varint();
    }
    const ranges = cursor.source[ranges_start..cursor.offset];

    return .{
        .largest = largest,
        .delay = delay,
        .first_range = first_range,
        .range_count = range_count,
        .ranges = ranges,
        .ecn = if (ecn) .{
            .ect0 = try cursor.varint(),
            .ect1 = try cursor.varint(),
            .ce = try cursor.varint(),
        } else null,
    };
}

fn parseCrypto(cursor: *Cursor) ParseError!Frame {
    const offset = try cursor.varint();
    const data = try takeLengthPrefixed(cursor);
    // Section 19.6: the end of the data must fit the offset space, or the
    // stream's final size would be unrepresentable.
    if (offset + data.len > varint.max) return error.Malformed;
    return .{ .crypto = .{ .offset = offset, .data = data } };
}

fn parseStream(cursor: *Cursor, frame_type: Type) ParseError!Frame {
    const bits = @intFromEnum(frame_type);
    assert(bits >= Type.stream_first);
    assert(bits <= Type.stream_last);

    const stream = try cursor.varint();
    const offset: u64 = if (bits & Type.stream_offset_bit != 0) try cursor.varint() else 0;
    // Section 19.8: without the LEN bit the frame runs to the end of the
    // packet, which is what makes a STREAM frame free of a length field when it
    // is the last thing in a packet.
    const data = if (bits & Type.stream_length_bit != 0)
        try takeLengthPrefixed(cursor)
    else
        try cursor.take(cursor.remaining());
    if (offset + data.len > varint.max) return error.Malformed;
    return .{ .stream = .{
        .stream = stream,
        .offset = offset,
        .data = data,
        .fin = bits & Type.stream_fin_bit != 0,
    } };
}

fn parseNewConnectionId(cursor: *Cursor) ParseError!Frame {
    const sequence = try cursor.varint();
    const retire_prior_to = try cursor.varint();
    // Section 19.15: retiring more than has been issued is a
    // `FRAME_ENCODING_ERROR`, and it matters — a peer that could would force us
    // to retire identifiers we are still using.
    if (retire_prior_to > sequence) return error.Malformed;
    const length = try cursor.byte();
    if (length < 1 or length > ConnectionId.octets_max) return error.Malformed;
    const bytes = try cursor.take(length);
    const connection_id = ConnectionId.init(bytes) catch return error.Malformed;
    return .{ .new_connection_id = .{
        .sequence = sequence,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .stateless_reset_token = try cursor.takeArray(stateless_reset_token_octets),
    } };
}

fn parseConnectionClose(cursor: *Cursor, frame_type: Type) ParseError!Frame {
    const application = frame_type == .connection_close_application;
    const code = try cursor.varint();
    // Section 19.19: only the transport form names the frame that triggered
    // the close. Reading one from an application close would consume the
    // reason phrase's length as a frame type.
    const triggered_by: ?u64 = if (application) null else try cursor.varint();
    return .{ .connection_close = .{
        .application = application,
        .code = code,
        .triggered_by = triggered_by,
        .reason = try takeLengthPrefixed(cursor),
    } };
}

fn streamsLimit(cursor: *Cursor) ParseError!u64 {
    const maximum = try cursor.varint();
    if (maximum > streams_max) return error.Malformed;
    return maximum;
}

fn takeLengthPrefixed(cursor: *Cursor) ParseError![]const u8 {
    const length = try cursor.varint();
    return cursor.take(length);
}

/// Walks the frames of one packet payload.
///
/// Bounded structurally: every frame consumes at least one octet, so the loop
/// runs at most `payload.len` times. The assertion in `next` is what makes that
/// a checked claim rather than a comment.
pub const Iterator = struct {
    payload: []const u8,
    offset: usize = 0,

    pub fn init(payload: []const u8) Iterator {
        return .{ .payload = payload };
    }

    pub fn next(self: *Iterator) ParseError!?Frame {
        assert(self.offset <= self.payload.len);
        if (self.offset == self.payload.len) return null;
        const parsed = try parse(self.payload[self.offset..]);
        assert(parsed.octets >= 1);
        self.offset += parsed.octets;
        assert(self.offset <= self.payload.len);
        return parsed.frame;
    }
};

pub const EncodeError = error{
    /// `target` cannot hold the frame.
    OutputTooLong,
    /// A field the wire format cannot carry.
    ValueTooLarge,
};

/// Write `frame` into `target`, returning its length.
///
/// Writes nothing on failure, so a caller filling a packet can try a frame,
/// find it does not fit, and move on to the next packet without unwinding.
pub fn encode(target: []u8, frame: Frame) EncodeError!usize {
    var writer: Writer = .{ .target = target };
    try writer.varint(@intFromEnum(frame.frameType()));
    switch (frame) {
        .padding => |value| try writer.zeroes(value.octets - 1),
        .ping, .handshake_done => {},
        .ack => |value| try encodeAck(&writer, value),
        .reset_stream => |value| {
            try writer.varint(value.stream);
            try writer.varint(@intFromEnum(value.code));
            try writer.varint(value.final_size);
        },
        .stop_sending => |value| {
            try writer.varint(value.stream);
            try writer.varint(@intFromEnum(value.code));
        },
        .crypto => |value| {
            try writer.varint(value.offset);
            try writer.lengthPrefixed(value.data);
        },
        .new_token => |value| try writer.lengthPrefixed(value.token),
        .stream => |value| try encodeStream(&writer, value.stream, value.offset, value.data, value.fin),
        .max_data => |value| try writer.varint(value.maximum),
        .max_stream_data => |value| {
            try writer.varint(value.stream);
            try writer.varint(value.maximum);
        },
        .max_streams => |value| try writer.varint(value.maximum),
        .data_blocked => |value| try writer.varint(value.limit),
        .stream_data_blocked => |value| {
            try writer.varint(value.stream);
            try writer.varint(value.limit);
        },
        .streams_blocked => |value| try writer.varint(value.limit),
        .new_connection_id => |value| {
            try writer.varint(value.sequence);
            try writer.varint(value.retire_prior_to);
            try writer.byte(value.connection_id.length);
            try writer.bytes(value.connection_id.bytes());
            try writer.bytes(value.stateless_reset_token);
        },
        .retire_connection_id => |value| try writer.varint(value.sequence),
        // Two arms rather than one: the payloads are structurally identical
        // but nominally distinct types, and a shared capture cannot name both.
        .path_challenge => |value| try writer.bytes(value.data),
        .path_response => |value| try writer.bytes(value.data),
        .connection_close => |value| {
            try writer.varint(value.code);
            if (value.triggered_by) |triggering| try writer.varint(triggering);
            try writer.lengthPrefixed(value.reason);
        },
    }
    assert(writer.offset >= 1);
    return writer.offset;
}

fn encodeAck(writer: *Writer, ack: Ack) EncodeError!void {
    try writer.varint(ack.largest);
    try writer.varint(ack.delay);
    try writer.varint(ack.range_count);
    try writer.varint(ack.first_range);
    // The ranges go back out exactly as they came in. Re-deriving them would
    // mean holding them, and holding them would mean an allocator.
    try writer.bytes(ack.ranges);
    if (ack.ecn) |counts| {
        try writer.varint(counts.ect0);
        try writer.varint(counts.ect1);
        try writer.varint(counts.ce);
    }
}

fn encodeStream(writer: *Writer, stream: u64, offset: u64, data: []const u8, fin: bool) EncodeError!void {
    // The type octet is already written, and the flag bits belong to it, so it
    // is patched rather than written twice — the alternative is deciding the
    // flags before knowing whether the fields fit.
    assert(writer.offset >= 1);
    var bits: u8 = @intCast(Type.stream_first);
    if (offset != 0) bits |= @intCast(Type.stream_offset_bit);
    bits |= @intCast(Type.stream_length_bit);
    if (fin) bits |= @intCast(Type.stream_fin_bit);
    writer.target[0] = bits;

    try writer.varint(stream);
    if (offset != 0) try writer.varint(offset);
    try writer.lengthPrefixed(data);
}

const Writer = struct {
    target: []u8,
    offset: usize = 0,

    fn room(self: *Writer, octets: usize) EncodeError![]u8 {
        const end = std.math.add(usize, self.offset, octets) catch return error.ValueTooLarge;
        if (end > self.target.len) return error.OutputTooLong;
        const slice = self.target[self.offset..end];
        self.offset = end;
        return slice;
    }

    fn varint(self: *Writer, value: u64) EncodeError!void {
        if (value > @import("../varint.zig").max) return error.ValueTooLarge;
        const slice = try self.room(@import("../varint.zig").encodedLength(value));
        _ = @import("../varint.zig").encode(slice, value) catch unreachable; // `room` sized the slice from `encodedLength` and the range check above bounded the value.
    }

    fn byte(self: *Writer, value: u8) EncodeError!void {
        const slice = try self.room(1);
        slice[0] = value;
    }

    fn bytes(self: *Writer, source: []const u8) EncodeError!void {
        const slice = try self.room(source.len);
        @memcpy(slice, source);
    }

    fn zeroes(self: *Writer, octets: usize) EncodeError!void {
        const slice = try self.room(octets);
        @memset(slice, 0);
    }

    fn lengthPrefixed(self: *Writer, source: []const u8) EncodeError!void {
        try self.varint(source.len);
        try self.bytes(source);
    }
};

const testing = std.testing;

test "a padded packet reports one PADDING frame, not a thousand" {
    var payload: [1200]u8 = @splat(0);
    payload[1199] = 0x01; // A PING at the end, so the run is bounded by content.
    var iterator: Iterator = .init(&payload);
    const padding = (try iterator.next()).?;
    try testing.expectEqual(@as(usize, 1199), padding.padding.octets);
    try testing.expectEqual(Frame.ping, (try iterator.next()).?);
    try testing.expectEqual(@as(?Frame, null), try iterator.next());
}

test "a STREAM frame's flag bits are three optional fields" {
    // 0x0f: OFF, LEN and FIN all set. Stream 4, offset 8, two octets of data.
    const with_all = [_]u8{ 0x0f, 0x04, 0x08, 0x02, 0xaa, 0xbb };
    const parsed = try parse(&with_all);
    try testing.expectEqual(@as(u64, 4), parsed.frame.stream.stream);
    try testing.expectEqual(@as(u64, 8), parsed.frame.stream.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, parsed.frame.stream.data);
    try testing.expect(parsed.frame.stream.fin);
    try testing.expectEqual(with_all.len, parsed.octets);

    // 0x08: no offset, no length, no FIN — the data runs to the end.
    const bare = [_]u8{ 0x08, 0x04, 0xaa, 0xbb, 0xcc };
    const rest = try parse(&bare);
    try testing.expectEqual(@as(u64, 0), rest.frame.stream.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, rest.frame.stream.data);
    try testing.expect(!rest.frame.stream.fin);
}

test "an ACK frame's ranges walk downward without materializing" {
    // Largest 100, delay 0, two ranges, first range 10 (so 90..100),
    // then gap 1 length 2 (so 86..88 -- 90 - 1 - 2 = 87? see below),
    // then gap 0 length 0.
    const wire = [_]u8{ 0x02, 0x40, 0x64, 0x00, 0x02, 0x0a, 0x01, 0x02, 0x00, 0x00 };
    const parsed = try parse(&wire);
    const ack = parsed.frame.ack;
    try testing.expectEqual(@as(u64, 100), ack.largest);
    try testing.expectEqual(@as(u64, 2), ack.range_count);
    try testing.expectEqual(@as(u64, 90), try ack.smallest());

    var iterator = ack.iterate();
    const first = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 100), first.largest);
    try testing.expectEqual(@as(u64, 90), first.smallest);
    // Section 19.3.1: largest = previous smallest - gap - 2 = 90 - 1 - 2 = 87.
    const second = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 87), second.largest);
    try testing.expectEqual(@as(u64, 85), second.smallest);
    const third = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 83), third.largest);
    try testing.expectEqual(@as(u64, 83), third.smallest);
    try testing.expectEqual(@as(?Range, null), try iterator.next());
}

test "an ACK whose ranges would go below zero is malformed" {
    // Largest 5, first range 10: the range starts below packet number zero.
    const under = [_]u8{ 0x02, 0x05, 0x00, 0x00, 0x0a };
    try testing.expectError(error.Malformed, parse(&under));

    // A gap that walks past zero on the second range.
    const walked = [_]u8{ 0x02, 0x05, 0x00, 0x01, 0x00, 0x0a, 0x00 };
    const parsed = try parse(&walked);
    var iterator = parsed.frame.ack.iterate();
    _ = try iterator.next();
    try testing.expectError(error.Malformed, iterator.next());
}

test "an ACK claiming more ranges than the payload holds is truncated" {
    // Range count 0x3f = 63, with nothing following it.
    const wire = [_]u8{ 0x02, 0x05, 0x00, 0x3f, 0x00 };
    try testing.expectError(error.Truncated, parse(&wire));
}

test "NEW_CONNECTION_ID refuses to retire more than it issued" {
    // Sequence 1, retire_prior_to 5.
    const wire = [_]u8{ 0x18, 0x01, 0x05, 0x02, 0xaa, 0xbb } ++ [_]u8{0x11} ** 16;
    try testing.expectError(error.Malformed, parse(&wire));

    const ok = [_]u8{ 0x18, 0x05, 0x01, 0x02, 0xaa, 0xbb } ++ [_]u8{0x11} ** 16;
    const parsed = try parse(&ok);
    const new_id = parsed.frame.new_connection_id;
    try testing.expectEqual(@as(u64, 5), new_id.sequence);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, new_id.connection_id.bytes());
    try testing.expectEqual(@as(u8, 0x11), new_id.stateless_reset_token[15]);

    // A zero-length identifier is a NEW_CONNECTION_ID that says nothing, which
    // section 19.15 forbids outright.
    const empty = [_]u8{ 0x18, 0x01, 0x00, 0x00 } ++ [_]u8{0x11} ** 16;
    try testing.expectError(error.Malformed, parse(&empty));
}

test "the two CONNECTION_CLOSE forms differ by one field" {
    // Transport: code 0x0a, triggered by frame type 0x08, reason "no".
    const transport = [_]u8{ 0x1c, 0x0a, 0x08, 0x02, 'n', 'o' };
    const parsed = try parse(&transport);
    try testing.expect(!parsed.frame.connection_close.application);
    try testing.expectEqual(@as(?u64, 0x08), parsed.frame.connection_close.triggered_by);
    try testing.expectEqualStrings("no", parsed.frame.connection_close.reason);

    // Application: no triggering frame type, so the same trailing octets mean
    // something different. Reading one from an application close would eat the
    // reason's length.
    const application = [_]u8{ 0x1d, 0x0a, 0x02, 'n', 'o' };
    const app_parsed = try parse(&application);
    try testing.expect(app_parsed.frame.connection_close.application);
    try testing.expectEqual(@as(?u64, null), app_parsed.frame.connection_close.triggered_by);
    try testing.expectEqualStrings("no", app_parsed.frame.connection_close.reason);
}

test "a streams limit above 2^60 is refused" {
    var wire: [9]u8 = undefined;
    wire[0] = 0x12;
    _ = try varint.encode(wire[1..], streams_max + 1);
    try testing.expectError(error.Malformed, parse(&wire));
}

test "a non-minimal frame type is not a frame type" {
    // 0x4001 decodes to 1, which is PING, in two octets rather than one.
    // Section 12.4 makes that a `FRAME_ENCODING_ERROR`, and accepting it would
    // give every frame four names.
    try testing.expectError(error.UnknownType, parse(&.{ 0x40, 0x01 }));
    try testing.expectEqual(Frame.ping, (try parse(&.{0x01})).frame);
}

test "an unknown frame type cannot be skipped" {
    // 0x3f is not a defined type, and a QUIC frame has no length prefix, so
    // there is nothing to skip past.
    try testing.expectError(error.UnknownType, parse(&.{0x3f}));
}

test "section 12.4 table 3: where a frame is allowed" {
    const Level = @import("crypto.zig").Level;
    // A STREAM frame in an Initial packet is application data before anyone is
    // authenticated.
    try testing.expect(!Type.stream.allowedIn(.initial));
    try testing.expect(!Type.stream.allowedIn(.handshake));
    try testing.expect(Type.stream.allowedIn(.zero_rtt));
    try testing.expect(Type.stream.allowedIn(.one_rtt));
    // CRYPTO is everywhere but 0-RTT: there is no handshake data to send in a
    // packet protected by keys the handshake produced.
    try testing.expect(Type.crypto.allowedIn(.initial));
    try testing.expect(!Type.crypto.allowedIn(.zero_rtt));
    // HANDSHAKE_DONE is 1-RTT only, and only a server may send it.
    for ([_]Level{ .initial, .zero_rtt, .handshake }) |level| {
        try testing.expect(!Type.handshake_done.allowedIn(level));
    }
    try testing.expect(Type.handshake_done.allowedIn(.one_rtt));
    // PADDING and PING go anywhere, which is what makes a PING the way to probe
    // a path at any level.
    for ([_]Level{ .initial, .zero_rtt, .handshake, .one_rtt }) |level| {
        try testing.expect(Type.padding.allowedIn(level));
        try testing.expect(Type.ping.allowedIn(level));
    }
}

test "ack-eliciting is everything but ACK, PADDING and CONNECTION_CLOSE" {
    try testing.expect(!Type.ack.ackEliciting());
    try testing.expect(!Type.ack_ecn.ackEliciting());
    try testing.expect(!Type.padding.ackEliciting());
    try testing.expect(!Type.connection_close_transport.ackEliciting());
    try testing.expect(!Type.connection_close_application.ackEliciting());
    try testing.expect(Type.ping.ackEliciting());
    try testing.expect(Type.stream.ackEliciting());
    // Every STREAM spelling, not just the canonical one.
    var bits: u64 = Type.stream_first;
    while (bits <= Type.stream_last) : (bits += 1) {
        const frame_type: Type = @enumFromInt(bits);
        try testing.expect(frame_type.ackEliciting());
        try testing.expectEqual(Type.stream, frame_type.canonical());
    }
}

test "every frame round-trips through encode and parse" {
    const token: [stateless_reset_token_octets]u8 = @splat(0x77);
    const path: [path_data_octets]u8 = @splat(0x33);
    const frames = [_]Frame{
        .ping,
        .handshake_done,
        .{ .reset_stream = .{ .stream = 4, .code = .request_cancelled, .final_size = 1024 } },
        .{ .stop_sending = .{ .stream = 8, .code = .request_rejected } },
        .{ .crypto = .{ .offset = 16, .data = "hello" } },
        .{ .new_token = .{ .token = "a token" } },
        .{ .stream = .{ .stream = 0, .offset = 0, .data = "body", .fin = true } },
        .{ .stream = .{ .stream = 12, .offset = 4096, .data = "more", .fin = false } },
        .{ .max_data = .{ .maximum = 1 << 20 } },
        .{ .max_stream_data = .{ .stream = 4, .maximum = 1 << 16 } },
        .{ .max_streams = .{ .bidirectional = true, .maximum = 100 } },
        .{ .max_streams = .{ .bidirectional = false, .maximum = 3 } },
        .{ .data_blocked = .{ .limit = 42 } },
        .{ .stream_data_blocked = .{ .stream = 4, .limit = 42 } },
        .{ .streams_blocked = .{ .bidirectional = false, .limit = 7 } },
        .{ .new_connection_id = .{
            .sequence = 2,
            .retire_prior_to = 1,
            .connection_id = try ConnectionId.init(&.{ 1, 2, 3, 4 }),
            .stateless_reset_token = &token,
        } },
        .{ .retire_connection_id = .{ .sequence = 1 } },
        .{ .path_challenge = .{ .data = &path } },
        .{ .path_response = .{ .data = &path } },
        .{ .connection_close = .{ .application = false, .code = 0x0a, .triggered_by = 0x08, .reason = "why" } },
        .{ .connection_close = .{ .application = true, .code = 0x0100, .triggered_by = null, .reason = "" } },
    };

    for (frames) |frame| {
        var target: [128]u8 = @splat(0);
        const written = try encode(&target, frame);
        const parsed = try parse(target[0..written]);
        try testing.expectEqual(written, parsed.octets);
        try testing.expectEqual(frame.frameType().canonical(), parsed.frame.frameType().canonical());
        // A structural comparison, since the union holds slices that point into
        // two different buffers.
        try testing.expectEqualStrings(@tagName(frame), @tagName(parsed.frame));
    }
}

test "an ACK re-encodes to the octets it was parsed from" {
    const wire = [_]u8{ 0x03, 0x40, 0x64, 0x00, 0x01, 0x0a, 0x01, 0x02, 0x0a, 0x0b, 0x0c };
    const parsed = try parse(&wire);
    try testing.expect(parsed.frame.ack.ecn != null);
    var target: [64]u8 = @splat(0);
    const written = try encode(&target, parsed.frame);
    try testing.expectEqualSlices(u8, &wire, target[0..written]);
}

test "encode refuses rather than truncates" {
    var target: [2]u8 = @splat(0);
    try testing.expectError(error.OutputTooLong, encode(&target, .{ .crypto = .{ .offset = 0, .data = "too long" } }));
}

test "a frame cut short is truncated, not malformed" {
    try testing.expectError(error.Truncated, parse(&.{0x06})); // CRYPTO with no offset.
    try testing.expectError(error.Truncated, parse(&.{ 0x06, 0x00, 0x05, 0xaa })); // Length 5, one octet.
    try testing.expectError(error.Truncated, parse(&.{ 0x1a, 0x01, 0x02 })); // PATH_CHALLENGE, short.
}
