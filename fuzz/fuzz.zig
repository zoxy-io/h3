//! Fuzz targets. Lives outside `src/` because it needs platform surfaces that
//! `zig build lint` forbids in the library.
//!
//! Run modes:
//! * `zig build fuzz` — replays the seed corpus once (regression mode).
//! * `zig build fuzz --fuzz` — coverage-guided fuzzing via Zig's native fuzzer.
//!
//! docs/TIGER_STYLE.md makes fuzzing a gate rather than a nicety. It matters
//! more here than it did in h2 for one reason: a QUIC packet payload is a run
//! of frames with no count and no separator, so a decoder that mis-measures one
//! frame does not fail — it reinterprets everything after it. A byte-level
//! oracle is the only thing that catches that class.
//!
//! The property every target shares is **reject or parse, with no third
//! outcome**. A decoder may return a well-formed answer or an error; what it
//! may not do is panic, read out of bounds, fail to terminate, or return an
//! answer that is quietly short. Assertions are on in the Debug build this runs
//! under, so every internal invariant joins the oracle.
//!
//! Zig 0.16 hands a target a `*std.testing.Smith` rather than a byte slice, so
//! inputs are *drawn* — `smith.slice`, `smith.value` — instead of being cast
//! out of a flat buffer. That suits a packet: drawing a length and then that
//! many octets reaches valid-header/invalid-payload combinations a byte fuzzer
//! needs luck for.

const std = @import("std");

const h3 = @import("h3");

const quic = h3.quic;

/// The oracle's own assert, always on.
///
/// Deliberately not `std.debug.assert` and deliberately not the library's
/// `-Dassertions`-gated one. Every property these targets check is expressed as
/// an assertion, so an assertion the build can remove is a fuzz target the
/// build can turn into a crash-only fuzzer — and `zig build fuzz --fuzz
/// -Doptimize=ReleaseFast` is the natural way to actually fuzz.
///
/// The library's *internal* assertions are a separate matter: those follow
/// `-Dassertions`, and fuzzing with them off is legitimate — it checks that the
/// decoders reject on their own rather than on an invariant check. What must
/// not vanish is the oracle.
fn assert(ok: bool) void {
    if (!ok) @panic("fuzz: oracle assertion failed");
}

/// Inputs are capped so a failing case stays small enough to read.
const input_max = 2048;

/// The largest local connection identifier a short-header parse is offered.
const local_connection_id_octets_max = 20;

/// Frames drawn into one payload, and settings into one SETTINGS frame.
const settings_max = 16;

/// A variable-length integer either decodes or does not, and a decode is
/// canonical for the length it claimed.
///
/// Section 16 permits four spellings of a value, so the round-trip property has
/// to be stated at a *fixed length* — re-encoding minimally would disagree with
/// a legal non-minimal input. That distinction is what `encodeIn` exists for
/// and what this target pins.
fn fuzzVarint(_: void, smith: *std.testing.Smith) !void {
    var buffer: [h3.varint.octets_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const source = buffer[0..length];

    const decoded = h3.varint.decode(source) catch return;
    assert(decoded.octets >= h3.varint.octets_min);
    assert(decoded.octets <= source.len);
    assert(decoded.value <= h3.varint.max);
    assert(decoded.octets == h3.varint.octetsFor(source[0]));

    var target: [h3.varint.octets_max]u8 = undefined;
    h3.varint.encodeIn(&target, decoded.value, decoded.octets) catch unreachable; // The value came out of an encoding of exactly this length.
    assert(std.mem.eql(u8, target[0..decoded.octets], source[0..decoded.octets]));

    // The minimal decoder accepts exactly the shortest spelling, and nothing
    // else: an unknown frame type and a PING differ by this rule alone.
    if (h3.varint.decodeMinimal(source)) |minimal| {
        assert(minimal.value == decoded.value);
        assert(decoded.octets == h3.varint.encodedLength(decoded.value));
    } else |err| {
        assert(err == error.NotMinimal);
        assert(decoded.octets != h3.varint.encodedLength(decoded.value));
    }
}

test "varint: decode, re-encode at the same length, and the minimal rule" {
    try std.testing.fuzz({}, fuzzVarint, .{});
}

/// A QPACK integer terminates at every prefix width, and round-trips.
///
/// The bound is the property: section 4.1.1 sets no limit on continuation
/// octets, so an input of nothing but `0xff` is legal-looking and endless.
fn fuzzQpackInteger(_: void, smith: *std.testing.Smith) !void {
    const prefix_bits = smith.valueRangeAtMost(u4, 1, h3.qpack.integer.prefix_bits_max);
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const source = buffer[0..length];

    const decoded = h3.qpack.integer.decode(source, prefix_bits) catch return;
    assert(decoded.octets >= 1);
    assert(decoded.octets <= source.len);
    assert(decoded.octets <= h3.qpack.integer.continuation_octets_max + 1);
    assert(decoded.value <= h3.qpack.integer.value_max);
    assert(decoded.octets == h3.qpack.integer.encodedLength(decoded.value, prefix_bits));

    var target: [h3.qpack.integer.continuation_octets_max + 1]u8 = undefined;
    const prefix_mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    const tag = source[0] & ~prefix_mask;
    const written = h3.qpack.integer.encode(&target, decoded.value, prefix_bits, tag) catch unreachable; // The target holds the widest encoding, and the value came out of one.
    assert(written == decoded.octets);
    assert(std.mem.eql(u8, target[0..written], source[0..written]));
}

test "qpack integer: an unbounded continuation run still terminates" {
    try std.testing.fuzz({}, fuzzQpackInteger, .{});
}

/// A packet header parses or is refused, and never claims more of the datagram
/// than there is.
///
/// The local connection identifier length is drawn, because it is the one
/// parsing input that does not come from the wire — and a short-header parse
/// that trusted it would read the packet number out of a buffer it does not own.
fn fuzzPacketHeader(_: void, smith: *std.testing.Smith) !void {
    const local = smith.valueRangeAtMost(u8, 0, local_connection_id_octets_max);
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const datagram = buffer[0..length];

    const parsed = quic.packet.parse(datagram, local) catch return;
    assert(parsed.octets <= datagram.len);
    assert(parsed.octets >= 1);
    if (parsed.header.packetNumberOffset()) |offset| {
        assert(offset < parsed.octets);
        assert(offset <= datagram.len);
    }
    const destination = parsed.header.destination();
    assert(destination.length <= quic.ConnectionId.octets_max);
}

test "packet: a header never points past its own datagram" {
    try std.testing.fuzz({}, fuzzPacketHeader, .{});
}

/// A payload's frames consume it exactly once, and an ACK's ranges walk down
/// without underflowing or looping.
///
/// The termination argument is structural rather than a counter: every frame
/// consumes at least one octet. The assertion is what makes that a checked
/// claim, and it is the property a mis-measured frame breaks — a frame that
/// consumed zero octets would reinterpret the same payload forever.
fn fuzzPacketPayload(_: void, smith: *std.testing.Smith) !void {
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const payload = buffer[0..length];

    var iterator: quic.frame.Iterator = .init(payload);
    var count: usize = 0;
    while (count <= payload.len) : (count += 1) {
        const before = iterator.offset;
        const frame = iterator.next() catch break;
        if (frame == null) break;
        assert(iterator.offset > before);
        assert(iterator.offset <= payload.len);

        if (frame.? == .ack) {
            var ranges = frame.?.ack.iterate();
            var emitted: u64 = 0;
            while (emitted <= frame.?.ack.range_count) : (emitted += 1) {
                const range = ranges.next() catch break;
                if (range == null) break;
                assert(range.?.smallest <= range.?.largest);
            }
            assert(emitted <= frame.?.ack.range_count + 1);
        }
    }
    assert(count <= payload.len + 1);
}

test "frame: a payload's frames consume it exactly once" {
    try std.testing.fuzz({}, fuzzPacketPayload, .{});
}

/// Transport parameters decode within the ranges section 18.2 states, and
/// re-encode to something that reads back the same.
fn fuzzTransportParameters(_: void, smith: *std.testing.Smith) !void {
    const parameters_module = quic.transport_parameters;
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);

    const parameters = parameters_module.parse(buffer[0..length]) catch return;
    assert(parameters.max_udp_payload_size >= parameters_module.max_udp_payload_size_min);
    assert(parameters.ack_delay_exponent <= parameters_module.ack_delay_exponent_max);
    assert(parameters.max_ack_delay_ms <= parameters_module.max_ack_delay_max);
    assert(parameters.active_connection_id_limit >= parameters_module.active_connection_id_limit_min);
    assert(parameters.initial_max_streams_bidi <= parameters_module.streams_max);
    assert(parameters.initial_max_streams_uni <= parameters_module.streams_max);

    var target: [input_max * 2]u8 = undefined;
    const written = parameters_module.encode(&target, &parameters) catch return;
    const again = parameters_module.parse(target[0..written]) catch unreachable; // Just written by this package's own encoder.
    assert(again.initial_max_data == parameters.initial_max_data);
    assert(again.max_udp_payload_size == parameters.max_udp_payload_size);
    assert(again.active_connection_id_limit == parameters.active_connection_id_limit);
    assert(again.disable_active_migration == parameters.disable_active_migration);
}

test "transport parameters: the ranges hold and the round-trip is stable" {
    try std.testing.fuzz({}, fuzzTransportParameters, .{});
}

/// An HTTP/3 frame header states how far to skip, whatever its type.
///
/// The property that separates it from a QUIC frame, and the one a proxy
/// depends on: an unknown type is still skippable.
fn fuzzHttp3Header(_: void, smith: *std.testing.Smith) !void {
    var buffer: [2 * h3.varint.octets_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const source = buffer[0..length];

    const header = h3.frame.parseHeader(source) catch return;
    assert(header.octets >= 2);
    assert(header.octets <= source.len);
    assert(header.length <= h3.varint.max);
    assert(!header.frame_type.isHttp2Reserved());

    var target: [2 * h3.varint.octets_max]u8 = undefined;
    const written = h3.frame.writeHeader(&target, header.frame_type, header.length) catch unreachable; // Both fields came out of a parse of the same width.
    assert(written == header.octets);
    assert(std.mem.eql(u8, target[0..written], source[0..written]));
}

test "http3 frame: an unknown type still states its length" {
    try std.testing.fuzz({}, fuzzHttp3Header, .{});
}

/// A SETTINGS payload walks to its end or is refused, and never past it.
fn fuzzSettings(_: void, smith: *std.testing.Smith) !void {
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const payload = buffer[0..length];

    var iterator: h3.frame.SettingsIterator = .init(payload);
    var count: usize = 0;
    while (count <= settings_max) : (count += 1) {
        const pair = iterator.next() catch break;
        if (pair == null) break;
        assert(iterator.offset <= payload.len);
        assert(!pair.?.identifier.isHttp2Reserved());
    }
    assert(count <= settings_max + 1);
}

test "settings: a payload walks to its end or is refused" {
    try std.testing.fuzz({}, fuzzSettings, .{});
}

/// Arbitrary octets do not authenticate under a key the fuzzer never saw.
///
/// The strongest oracle in the file, and the only one whose *success* is the
/// failure: reaching the panic means a forgery. Everything else here checks
/// that a decoder does not crash; this checks that the AEAD does its job
/// through this package's framing of it — a `seal` that authenticated the wrong
/// associated data, or an `open` that skipped the tag, would show up here.
fn fuzzPacketProtection(_: void, smith: *std.testing.Smith) !void {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: quic.crypto.Keys = .initial(&dcid, .server);

    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const offset: usize = smith.valueRangeAtMost(u8, 0, 32);

    const opened = keys.open(buffer[0..length], offset, null) catch return;
    assert(opened.header.len == offset + opened.number_octets);
    @panic("fuzz: arbitrary octets authenticated under keys the fuzzer does not have");
}

test "protection: arbitrary octets do not authenticate" {
    try std.testing.fuzz({}, fuzzPacketProtection, .{});
}

/// A unidirectional stream type is a type or is incomplete, and round-trips.
fn fuzzStreamType(_: void, smith: *std.testing.Smith) !void {
    var buffer: [h3.varint.octets_max]u8 = undefined;
    const length = smith.slice(&buffer);
    const source = buffer[0..length];

    const parsed = h3.stream.parse(source) catch return;
    assert(parsed.octets >= 1);
    assert(parsed.octets <= source.len);

    var target: [h3.varint.octets_max]u8 = undefined;
    const written = h3.stream.write(&target, parsed.stream_type) catch unreachable; // A minimal parse means a minimal re-encoding fits.
    assert(written == parsed.octets);
    assert(std.mem.eql(u8, target[0..written], source[0..written]));
}

test "stream: a type parses, or more octets are coming" {
    try std.testing.fuzz({}, fuzzStreamType, .{});
}

/// A static table index resolves or is refused, and the table and its lookup
/// stay two views of one thing.
fn fuzzStaticTable(_: void, smith: *std.testing.Smith) !void {
    const table = h3.qpack.static_table;
    const index = smith.value(u64);

    const entry = table.get(index) catch {
        assert(index >= table.count);
        return;
    };
    assert(index < table.count);
    assert(entry.name.len >= 1);

    const found = table.lookup(entry.name, entry.value).?;
    const resolved = table.get(found.index) catch unreachable; // `lookup` only ever answers an index it walked.
    assert(std.mem.eql(u8, resolved.name, entry.name));
    assert(std.mem.eql(u8, resolved.value, entry.value));
}

test "static table: get and lookup agree on every index" {
    try std.testing.fuzz({}, fuzzStaticTable, .{});
}
