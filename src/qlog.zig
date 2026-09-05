//! qlog records, serialised into a caller's buffer.
//!
//! qlog is a structured trace format for QUIC — `urn:ietf:params:qlog` — and
//! the thing that reads it is a tool like qvis rather than a person. What it
//! wants is one JSON object per event, in the JSON-SEQ framing: a record
//! separator, the object, a newline.
//!
//! ## What is here and what is not
//!
//! No file, no clock, no allocator. This module turns a record into octets and
//! stops; opening `$QLOGDIR/<id>.sqlog` and choosing when to write is the
//! consumer's, exactly as sending a datagram is. `interop/` is the consumer
//! that does it.
//!
//! **There are no packet events**, and that is the honest limitation of this
//! trace rather than an oversight. `transport:packet_sent` and
//! `packet_received` are what a qvis timeline is mostly made of, and this seam
//! does not expose them: `Connection.poll` is a queue of things a *consumer*
//! must act on, bounded at `events_max`, and a packet-per-event stream would
//! overflow it on every connection that did any work. Reporting packets needs a
//! sink rather than a queue, which is a change to the shape of the seam and not
//! to this file. What is here — the metrics, the loss counts, the key updates,
//! the close — is what the seam already says, plus what the consumer knows
//! about its own datagrams.
//!
//! ## The time field
//!
//! qlog times are milliseconds as a decimal, relative to the trace's
//! `reference_time`. The connections in this package take `now_ns` from their
//! caller and the caller's origin is the connection's start, so the two already
//! agree: `now_ns` divided out is the field. It is written to microsecond
//! precision by integer arithmetic, because a float formatter is a dependency
//! this file does not need.

const std = @import("std");

const ConnectionId = @import("quic/ConnectionId.zig");
const assert = @import("assert.zig").assert;

/// The schema this writer claims. Consumers key off it, so it is a constant
/// rather than a parameter.
pub const event_schema = "urn:ietf:params:qlog:events:quic-12";
pub const file_schema = "urn:ietf:params:qlog:file:sequential";
pub const serialization_format = "application/qlog+json-seq";

/// JSON-SEQ's framing, from RFC 7464: a record separator before each value and
/// a line feed after it.
pub const record_separator: u8 = 0x1e;

/// The longest `group_id` this writer will take: a connection identifier in
/// hex, and RFC 9000 section 17.2 caps that identifier at twenty octets.
pub const group_id_octets_max: usize = 2 * ConnectionId.octets_max;

/// And the longest `code_version`. A build identifier rather than a message, so
/// this is generous rather than arbitrary.
pub const code_version_octets_max: usize = 64;

/// The decimal width of a `u64`, which is what every integer field here is.
const digits_max: usize = 20;

comptime {
    assert(digits_max == std.fmt.count("{d}", .{std.math.maxInt(u64)}));
}

/// A millisecond's fractional part, to the microsecond.
const microsecond_digits: usize = 3;

comptime {
    assert(std.time.ns_per_ms == std.time.ns_per_us * 1000);
    assert(microsecond_digits == std.fmt.count("{d}", .{@as(u64, 999)}));
}

/// What a caller's buffer has to hold for any record this writer produces.
///
/// Derived rather than guessed, and exported rather than restated: the shim
/// that writes these had a `1024` of its own with a comment claiming it was
/// "the largest record `src/qlog.zig` produces", which this file guaranteed
/// nothing about. The two caps above are what make the claim true — without
/// them a `code_version` of any length is a record of any length.
pub const record_octets_max: usize = blk: {
    // The header is the longest thing here: three schema URNs and both caps.
    const framing = 2; // The record separator and the newline.
    const skeleton = 256; // Every literal key, brace and quote, with room over.
    break :blk framing + skeleton + file_schema.len + serialization_format.len +
        event_schema.len + group_id_octets_max + code_version_octets_max +
        // An event's own worst case: six fields, each a name and a number.
        6 * (32 + digits_max + microsecond_digits);
};

pub const Error = error{
    /// The record does not fit in the buffer the caller offered. Nothing is
    /// written: a half-written record is not a record, and a reader that meets
    /// one cannot tell truncation from corruption.
    BufferTooSmall,
    /// A string the caller supplied is longer than its cap, or holds an octet
    /// this writer will not put inside a JSON string.
    ///
    /// Refused rather than escaped, and refused rather than copied. Escaping
    /// would be the third behaviour a decoder is never allowed to have — accept
    /// something and quietly change it — and copying is how a quotation mark in
    /// a build identifier turns a trace into a file that is not JSON. Both
    /// fields this can reject are chosen by the program, not by a peer, so a
    /// refusal is a bug report to whoever chose them.
    InvalidText,
};

/// Which end of the connection this trace was taken at.
pub const VantagePoint = enum { client, server };

/// Which endpoint a record is about. A trace is taken at one end and describes
/// both, so this cannot be inferred from the vantage point — a server's trace
/// records the client's keys as well as its own.
pub const Owner = enum {
    local,
    remote,

    /// qlog spells a 1-RTT traffic secret by whose it is.
    fn keyType(owner: Owner, vantage: VantagePoint) []const u8 {
        const local_is_client = vantage == .client;
        const is_client = switch (owner) {
            .local => local_is_client,
            .remote => !local_is_client,
        };
        return if (is_client) "client_1rtt_secret" else "server_1rtt_secret";
    }
};

pub const HeaderOptions = struct {
    /// The connection's identifier, as hex. qvis groups by it, and the
    /// convention the interop runner follows is the original Destination
    /// Connection ID — the one value both endpoints agree on before either has
    /// chosen anything.
    group_id: []const u8,
    vantage_point: VantagePoint,
    /// What produced the trace. A version rather than a name so that two traces
    /// from different builds are distinguishable.
    code_version: []const u8,
};

/// The first record in the file: what the trace is and how to read it.
pub fn header(target: []u8, options: HeaderOptions) Error!usize {
    try checkText(options.group_id, group_id_octets_max);
    try checkText(options.code_version, code_version_octets_max);

    var out: Out = .{ .target = target };
    try out.byte(record_separator);
    try out.text("{\"file_schema\":\"" ++ file_schema ++ "\"");
    try out.text(",\"serialization_format\":\"" ++ serialization_format ++ "\"");
    try out.text(",\"title\":\"h3\",\"code_version\":\"");
    try out.text(options.code_version);
    try out.text("\",\"trace\":{\"event_schemas\":[\"" ++ event_schema ++ "\"]");
    try out.text(",\"vantage_point\":{\"type\":\"");
    try out.text(@tagName(options.vantage_point));
    try out.text("\"},\"common_fields\":{\"group_id\":\"");
    try out.text(options.group_id);
    try out.text("\"}}}\n");
    return framed(&out);
}

/// Whether a string may be written into a JSON string literal as it stands.
///
/// Printable ASCII, minus the two octets that would end the literal or start an
/// escape. Anything else is refused: see `Error.InvalidText`.
fn checkText(value: []const u8, cap: usize) Error!void {
    assert(cap > 0);
    if (value.len > cap) return error.InvalidText;
    for (value) |octet| {
        if (octet < 0x20 or octet > 0x7e) return error.InvalidText;
        if (octet == '"' or octet == '\\') return error.InvalidText;
    }
}

/// Section 3.1's stream states, as qlog spells them.
pub const StreamState = enum {
    opened,
    data_received,
    data_read,
    reset_received,
    reset_read,
    closed,
};

/// One event's payload. Each variant is a qlog event name and its `data`.
pub const Record = union(enum) {
    /// `recovery:metrics_updated`. Everything a congestion plot is drawn from.
    metrics: struct {
        smoothed_rtt_ns: u64,
        rtt_variance_ns: u64,
        latest_rtt_ns: u64,
        congestion_window: u64,
        bytes_in_flight: u64,
        pto_count: u32,
    },
    /// `recovery:packet_lost`, as a count. `Connection.Event` reports losses
    /// this way — per acknowledgement rather than per packet — so this is what
    /// there is to say, and saying it as one event with a count is better than
    /// inventing packet numbers that were never observed.
    packets_lost: u32,
    /// `security:key_updated`.
    ///
    /// `generation` counts updates and only rises; the key *phase* alternates
    /// 0, 1, 0, 1 and is a different fact. Emitting the phase under qlog's
    /// `generation` — which is what this did — shows a reader a generation that
    /// goes backwards on every second update.
    key_updated: struct { generation: u64, phase: u1, owner: Owner },
    /// `transport:connection_closed`. `owner` is which endpoint sent it.
    connection_closed: struct { code: u64, application: bool, owner: Owner },
    /// `transport:stream_state_updated`. Named `stream_id` on the wire and here
    /// too: an identifier is not an index, and the two differ by a factor of
    /// four in this protocol.
    stream_state: struct { stream_id: u64, state: StreamState },
    /// `transport:datagrams_sent` and `transport:datagrams_received`. The
    /// consumer's own knowledge rather than the library's: it is the one that
    /// holds the socket.
    ///
    /// One named type for both, so that the switch below can take them in a
    /// single prong: two anonymous structs with the same fields are two types.
    datagrams_sent: Datagrams,
    datagrams_received: Datagrams,

    pub const Datagrams = struct { count: u32, octets: u64 };
};

/// One event, framed and terminated. `at_ns` is the same `now_ns` the
/// connection was driven with.
pub fn event(target: []u8, vantage: VantagePoint, at_ns: u64, record: Record) Error!usize {
    var out: Out = .{ .target = target };
    try out.byte(record_separator);
    try out.text("{\"time\":");
    try out.milliseconds(at_ns);
    try out.text(",\"name\":\"");
    try out.text(name(record));
    try out.text("\",\"data\":{");
    switch (record) {
        .metrics => |value| {
            try out.field("smoothed_rtt", null);
            try out.milliseconds(value.smoothed_rtt_ns);
            try out.field("rtt_variance", null);
            try out.milliseconds(value.rtt_variance_ns);
            try out.field("latest_rtt", null);
            try out.milliseconds(value.latest_rtt_ns);
            try out.field("congestion_window", value.congestion_window);
            try out.field("bytes_in_flight", value.bytes_in_flight);
            try out.field("pto_count", value.pto_count);
        },
        .packets_lost => |count| {
            try out.field("packets_lost", count);
        },
        .key_updated => |value| {
            try out.string("key_type", value.owner.keyType(vantage));
            try out.field("generation", value.generation);
            try out.field("key_phase", value.phase);
        },
        .connection_closed => |value| {
            try out.string("owner", @tagName(value.owner));
            try out.field(if (value.application) "application_code" else "connection_code", value.code);
        },
        .stream_state => |value| {
            try out.field("stream_id", value.stream_id);
            try out.string("new", @tagName(value.state));
        },
        .datagrams_sent, .datagrams_received => |value| {
            try out.field("count", value.count);
            try out.field("raw", null);
            try out.text("{\"length\":");
            try out.integer(value.octets);
            try out.byte('}');
        },
    }
    try out.text("}}\n");
    return framed(&out);
}

/// The claim the doc comments make in prose, checked before a length is handed
/// back: what the caller is told to write is one whole framed record.
fn framed(out: *const Out) usize {
    assert(out.len >= 3);
    assert(out.len <= out.target.len);
    assert(out.target[0] == record_separator);
    assert(out.target[out.len - 1] == '\n');
    return out.len;
}

fn name(record: Record) []const u8 {
    return switch (record) {
        .metrics => "recovery:metrics_updated",
        // Not the schema's `recovery:packet_lost`, which names *one* packet and
        // carries its number. This is a count of several, because `Recovery`
        // reports losses per acknowledgement and keeps no list — so a
        // schema-defined name here would promise a reader fields that are not
        // there. An unknown name is skipped cleanly; a known name with the
        // wrong shape is not.
        .packets_lost => "h3:packets_lost",
        .key_updated => "security:key_updated",
        .connection_closed => "transport:connection_closed",
        .stream_state => "transport:stream_state_updated",
        .datagrams_sent => "transport:datagrams_sent",
        .datagrams_received => "transport:datagrams_received",
    };
}

/// A cursor over the caller's buffer that refuses to overrun it.
///
/// Every write goes through here, so `BufferTooSmall` is decided in one place
/// and a record either lands whole or does not land: `event` returns the error
/// before the caller has been told a length, and the octets already written are
/// past the length it will use.
const Out = struct {
    target: []u8,
    len: usize = 0,
    /// Whether a field has been written into the current object, which is what
    /// decides the comma.
    fields: u32 = 0,

    fn byte(self: *Out, one: u8) Error!void {
        // The invariant every other method's arithmetic rests on, asserted
        // where it is used rather than only where it is established: `text`
        // subtracts `len` from the target's length, and a broken invariant
        // makes that an underflow rather than a refusal.
        assert(self.len <= self.target.len);
        if (self.len >= self.target.len) return error.BufferTooSmall;
        self.target[self.len] = one;
        self.len += 1;
        assert(self.len <= self.target.len);
    }

    fn text(self: *Out, value: []const u8) Error!void {
        assert(self.len <= self.target.len);
        if (self.target.len - self.len < value.len) return error.BufferTooSmall;
        @memcpy(self.target[self.len..][0..value.len], value);
        self.len += value.len;
        assert(self.len <= self.target.len);
    }

    /// A named field, with its separator. `value` is written when it is there
    /// and left to the caller when it is not, which is how a field whose value
    /// is not an integer gets its name from the same place as the rest.
    fn field(self: *Out, label: []const u8, value: ?u64) Error!void {
        if (self.fields > 0) try self.byte(',');
        self.fields += 1;
        try self.byte('"');
        try self.text(label);
        try self.text("\":");
        if (value) |one| try self.integer(one);
    }

    /// A named field whose value is a string. Through `field` like every other,
    /// which is the point: a variant that wrote its first field with `text`
    /// skipped the comma bookkeeping and emitted two fields with nothing
    /// between them. Balanced braces, and not JSON — and the test that would
    /// have caught it was in a file whose tests were never run.
    fn string(self: *Out, label: []const u8, value: []const u8) Error!void {
        try self.field(label, null);
        try self.byte('"');
        try self.text(value);
        try self.byte('"');
    }

    fn integer(self: *Out, value: u64) Error!void {
        var scratch: [digits_max]u8 = undefined;
        const written = std.fmt.printInt(&scratch, value, 10, .lower, .{});
        try self.text(scratch[0..written]);
    }

    /// Nanoseconds as qlog's decimal milliseconds, to the microsecond.
    ///
    /// Integer arithmetic rather than a float: the value is exact at this
    /// precision, and a formatter that rounds would make two traces of the same
    /// connection differ in the last digit for no reason anyone can act on.
    fn milliseconds(self: *Out, at_ns: u64) Error!void {
        try self.integer(at_ns / std.time.ns_per_ms);
        try self.byte('.');
        const fraction = (at_ns / std.time.ns_per_us) % 1000;
        assert(fraction < 1000);
        // Written digit by digit rather than formatted and then padded. The
        // padding was `3 - written` on a `usize`, which is a subtraction whose
        // only guard was an assertion — and an assertion is not a guard in the
        // build that ships with `-Dassertions=false`.
        try self.byte('0' + @as(u8, @intCast(fraction / 100)));
        try self.byte('0' + @as(u8, @intCast((fraction / 10) % 10)));
        try self.byte('0' + @as(u8, @intCast(fraction % 10)));
    }
};

const testing = std.testing;

test "the header is one JSON-SEQ record naming the schema and the vantage point" {
    var buffer: [512]u8 = undefined;
    const written = try header(&buffer, .{
        .group_id = "83a4c2f1",
        .vantage_point = .server,
        .code_version = "h3-test",
    });
    const record = buffer[0..written];
    try testing.expectEqual(record_separator, record[0]);
    try testing.expectEqual(@as(u8, '\n'), record[record.len - 1]);
    try testing.expect(std.mem.indexOf(u8, record, "\"vantage_point\":{\"type\":\"server\"}") != null);
    try testing.expect(std.mem.indexOf(u8, record, "\"group_id\":\"83a4c2f1\"") != null);
    try testing.expect(std.mem.indexOf(u8, record, file_schema) != null);
}

test "an event carries its time in milliseconds to the microsecond" {
    var buffer: [512]u8 = undefined;
    // 1.5 ms exactly, and 12.000345 ms, which is the case a naive formatter
    // renders as `12.345`.
    const written = try event(&buffer, .client, 1_500_000, .{ .packets_lost = 3 });
    try testing.expect(std.mem.indexOf(u8, buffer[0..written], "\"time\":1.500") != null);
    // Not the schema's `recovery:packet_lost`; see `name`.
    try testing.expect(std.mem.indexOf(u8, buffer[0..written], "h3:packets_lost") != null);

    const second = try event(&buffer, .client, 12_000_345_000, .{ .packets_lost = 1 });
    try testing.expect(std.mem.indexOf(u8, buffer[0..second], "\"time\":12000.345") != null);

    const third = try event(&buffer, .client, 12_000_045_000, .{ .packets_lost = 1 });
    try testing.expect(std.mem.indexOf(u8, buffer[0..third], "\"time\":12000.045") != null);
}

test "metrics carry what a congestion plot is drawn from" {
    var buffer: [512]u8 = undefined;
    const written = try event(&buffer, .client, 0, .{ .metrics = .{
        .smoothed_rtt_ns = 33_000_000,
        .rtt_variance_ns = 4_000_000,
        .latest_rtt_ns = 31_000_000,
        .congestion_window = 40960,
        .bytes_in_flight = 1280,
        .pto_count = 0,
    } });
    const record = buffer[0..written];
    try testing.expect(std.mem.indexOf(u8, record, "recovery:metrics_updated") != null);
    try testing.expect(std.mem.indexOf(u8, record, "\"smoothed_rtt\":33.000") != null);
    try testing.expect(std.mem.indexOf(u8, record, "\"congestion_window\":40960") != null);
    try testing.expect(std.mem.indexOf(u8, record, "\"bytes_in_flight\":1280") != null);
}

test "a record that does not fit writes no length rather than half of one" {
    var buffer: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, event(&buffer, .client, 0, .{ .packets_lost = 3 }));
    try testing.expectError(error.BufferTooSmall, header(&buffer, .{
        .group_id = "83a4c2f1",
        .vantage_point = .client,
        .code_version = "h3-test",
    }));
}

test "every record is framed and ends with a newline" {
    var buffer: [512]u8 = undefined;
    const records = [_]Record{
        .{ .metrics = .{
            .smoothed_rtt_ns = 1,
            .rtt_variance_ns = 1,
            .latest_rtt_ns = 1,
            .congestion_window = 1,
            .bytes_in_flight = 1,
            .pto_count = 1,
        } },
        .{ .packets_lost = 1 },
        .{ .key_updated = .{ .generation = 1, .phase = 1, .owner = .local } },
        .{ .connection_closed = .{ .code = 0x100, .application = true, .owner = .remote } },
        .{ .stream_state = .{ .stream_id = 4, .state = .data_read } },
        .{ .datagrams_sent = .{ .count = 1, .octets = 1200 } },
        .{ .datagrams_received = .{ .count = 2, .octets = 2400 } },
    };
    for (records) |one| {
        const written = try event(&buffer, .client, 1_000_000, one);
        try testing.expectEqual(record_separator, buffer[0]);
        try testing.expectEqual(@as(u8, '\n'), buffer[written - 1]);
        // Parsed rather than eyeballed. A brace count would have passed the
        // first draft of two of these variants, which wrote a literal field
        // before the first `field` call and so emitted two fields with no comma
        // between them — balanced, and not JSON.
        const object = buffer[1 .. written - 1];
        try testing.expect(try std.json.validate(testing.allocator, object));
    }
}

test "the header parses as JSON" {
    var buffer: [512]u8 = undefined;
    const written = try header(&buffer, .{
        .group_id = "83a4c2f1",
        .vantage_point = .client,
        .code_version = "h3",
    });
    try testing.expect(try std.json.validate(testing.allocator, buffer[1 .. written - 1]));
}
