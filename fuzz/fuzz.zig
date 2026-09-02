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

/// Operations in one reassembler or ack-range sequence, so a failing case stays
/// short enough to read.
const reassembler_operations_max = 64;
const ack_operations_max = 128;
const connection_datagrams_max = 24;
const recovery_operations_max = 96;
const streams_operations_max = 96;

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

// The QPACK integer's fuzz target is not here. RFC 7541 section 5.1's prefixed
// integer moved to zoxy-io/hpack, and its targets went with it — including the
// one this file used to carry, which asserted that a decode re-encodes to the
// same octets. That is false by design: section 5.1 permits a non-minimal
// encoding, so `{0x1f, 0x80, 0x00}` and `{0x1f, 0x00}` are both 31 behind a
// five-bit prefix, and a coverage-guided run finds the difference in seconds.
// hpack's target asserts the *value* round-trips instead, at both widths.
//
// It stayed behind when the code moved, and a fuzzer found it. Tests belong
// with the code they cover.

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

/// The reassembler against a model of what it should hold.
///
/// The model is a filled-map and a shadow buffer, which is a different
/// implementation of the same idea — so an agreement between them is evidence
/// rather than a tautology. The properties that matter are the ones a stream
/// consumer depends on: what `readable` returns is exactly the octets pushed at
/// those offsets, and the run it returns is the *longest* contiguous one, not
/// merely a contiguous one.
fn fuzzReassembler(_: void, smith: *std.testing.Smith) !void {
    const capacity = 64;
    const Stream = quic.Reassembler(.{ .capacity = capacity, .spans_max = 8 });
    var stream: Stream = .{};

    var filled: [capacity]bool = @splat(false);
    var shadow: [capacity]u8 = @splat(0);
    var base: u64 = 0;

    var operations: u32 = 0;
    while (operations < reassembler_operations_max and !smith.eosWeightedSimple(8, 1)) : (operations += 1) {
        switch (smith.value(enum { push, consume })) {
            .push => {
                const offset = base + smith.valueRangeAtMost(u8, 0, capacity);
                var chunk: [capacity]u8 = undefined;
                const length = @min(smith.slice(&chunk), capacity);

                // The model decides what the answer should be, before the
                // structure is asked.
                const relative = offset - base;
                const fits = relative + length <= capacity;
                var contradicts = false;
                if (fits) {
                    for (chunk[0..length], 0..) |octet, index| {
                        const at = relative + index;
                        if (filled[at] and shadow[at] != octet) contradicts = true;
                    }
                }

                if (stream.push(offset, chunk[0..length])) {
                    assert(fits);
                    assert(!contradicts);
                    for (chunk[0..length], 0..) |octet, index| {
                        filled[relative + index] = true;
                        shadow[relative + index] = octet;
                    }
                } else |err| switch (err) {
                    error.BeyondWindow => assert(!fits),
                    error.Inconsistent => assert(contradicts),
                    // Running out of spans is a property of the structure's
                    // bound rather than of the model, so it is admitted
                    // without a prediction.
                    error.TooFragmented => {},
                    error.FinalSizeViolated => unreachable, // This target never calls `finish`.
                }
            },
            .consume => {
                const ready = stream.readable();
                const take = if (ready.len == 0) 0 else smith.valueRangeAtMost(u8, 0, @intCast(ready.len));
                stream.consume(take);
                if (take > 0) {
                    std.mem.copyForwards(bool, filled[0 .. capacity - take], filled[take..]);
                    std.mem.copyForwards(u8, shadow[0 .. capacity - take], shadow[take..]);
                    @memset(filled[capacity - take ..], false);
                    base += take;
                }
            },
        }

        // The contiguous run is exactly what the model says it is.
        var expected: usize = 0;
        while (expected < capacity and filled[expected]) expected += 1;
        const ready = stream.readable();
        assert(ready.len == expected);
        assert(std.mem.eql(u8, ready, shadow[0..expected]));
        assert(stream.readOffset() == base);
        assert(stream.limit() == base + capacity);
    }
}

test "reassembler: the contiguous run is what was pushed, in order" {
    try std.testing.fuzz({}, fuzzReassembler, .{});
}

/// The ack range set, against the one property whose violation breaks a peer.
///
/// **Never acknowledge a packet that did not arrive.** A spurious
/// acknowledgement tells the peer a lost packet was delivered, so it never
/// retransmits and the stream stalls forever — a liveness failure the peer
/// cannot diagnose and this endpoint cannot see. Everything else here is an
/// invariant; this is the oracle.
fn fuzzAckRanges(_: void, smith: *std.testing.Smith) !void {
    const window = 256;
    const Set = quic.AckRanges(.{ .ranges_max = 8 });
    var set: Set = .{};
    var received: [window]bool = @splat(false);

    var operations: u32 = 0;
    while (operations < ack_operations_max and !smith.eosWeightedSimple(8, 1)) : (operations += 1) {
        const number = smith.valueRangeAtMost(u8, 0, window - 1);
        set.record(number, 0, smith.value(bool));
        received[number] = true;

        // Descending, non-overlapping, separated by at least one number.
        assert(set.count <= 8);
        var index: u32 = 1;
        while (index < set.count) : (index += 1) {
            assert(set.ranges[index - 1].smallest > set.ranges[index].largest + 1);
            assert(set.ranges[index].largest >= set.ranges[index].smallest);
        }
        // Everything held was received. The set may *forget* a low range, which
        // is legal; it may never invent one.
        for (set.ranges[0..set.count]) |range| {
            var at = range.smallest;
            while (at <= range.largest) : (at += 1) assert(received[at]);
        }
    }
    if (set.count == 0) return;

    // The largest is the largest, and it is never forgotten: section 13.2.1
    // forbids reneging on an acknowledgement already sent.
    var highest: u64 = 0;
    for (received, 0..) |seen, number| if (seen) {
        highest = number;
    };
    assert(set.largest().? == highest);

    // A rendered frame acknowledges only packets that arrived.
    var target: [256]u8 = undefined;
    const written = set.write(&target, 0, 3) catch return;
    const parsed = h3.quic.frame.parse(target[0..written.octets]) catch unreachable; // Written by this package's own encoder.
    var ranges = parsed.frame.ack.iterate();
    var previous: ?u64 = null;
    while (ranges.next() catch null) |range| {
        assert(range.smallest <= range.largest);
        if (previous) |lower| assert(range.largest < lower);
        previous = range.smallest;
        var at = range.smallest;
        while (at <= range.largest) : (at += 1) assert(received[at]);
    }
}

test "ack ranges: never acknowledge a packet that did not arrive" {
    try std.testing.fuzz({}, fuzzAckRanges, .{});
}

/// Octets drawn for one connection-level datagram.
const connection_input_max = 1500;

/// Small on purpose: a connection at the default configuration is megabytes,
/// and a fuzz target builds one per input.
const FuzzConnection = quic.Connection(.{
    .crypto_octets = 4096,
    .ack_ranges_max = 8,
    .sent_max = 32,
    .streams_max = 4,
    .stream_receive_octets = 4 * 1024,
    .stream_send_octets = 4 * 1024,
    .connection_receive_octets = 16 * 1024,
});

/// Arbitrary datagrams into a connection, most of them properly sealed.
///
/// Random bytes are cheap coverage: nearly all of them fail the AEAD and never
/// reach the frame handling, which is where the interesting states are. So this
/// target draws a *payload* and seals it under the keys the connection expects,
/// which puts arbitrary frame sequences past the authentication and into the
/// state machine — the position a real peer occupies once its handshake
/// succeeds, and the only position from which a protocol bug is reachable.
///
/// The oracle is that a connection never panics and never leaves a state its
/// own invariants forbid, whatever it is told. A peer that authenticated is
/// still not trusted.
fn fuzzConnection(_: void, smith: *std.testing.Smith) !void {
    const original = quic.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }) catch unreachable; // Eight octets.
    const source = quic.ConnectionId.init(&.{ 0xaa, 0xbb }) catch unreachable; // Two octets.
    var connection: FuzzConnection = .init(.{
        .side = .server,
        .original_destination = original,
        .source = source,
    });
    // The keys a client's Initial packets arrive under.
    const keys: quic.crypto.Keys = .initial(original.bytes(), .client);

    var datagrams: u32 = 0;
    while (datagrams < connection_datagrams_max and !smith.eosWeightedSimple(6, 1)) : (datagrams += 1) {
        var buffer: [connection_input_max]u8 = @splat(0);

        const octets = switch (smith.value(enum { raw, sealed })) {
            // Straight garbage: has to be discarded rather than crash.
            .raw => blk: {
                var drawn: [connection_input_max]u8 = undefined;
                const length = smith.slice(&drawn);
                @memcpy(buffer[0..length], drawn[0..length]);
                break :blk length;
            },
            // A well-formed Initial packet whose payload is whatever was drawn.
            .sealed => blk: {
                var payload: [512]u8 = undefined;
                const payload_len = @min(smith.slice(&payload), payload.len);
                const written = quic.packet.writeLong(&buffer, .{
                    .long_type = .initial,
                    .destination = source,
                    .source = original,
                    .payload_octets = payload_len,
                    .number = smith.valueRangeAtMost(u8, 0, 8),
                    .number_octets = 4,
                }) catch break :blk 0;
                @memcpy(buffer[written.header_octets..][0..payload_len], payload[0..payload_len]);
                break :blk keys.seal(
                    &buffer,
                    written.packet_number_offset,
                    written.header_octets,
                    payload_len,
                    smith.valueRangeAtMost(u8, 0, 8),
                ) catch 0;
            },
        };
        if (octets == 0) continue;

        // Reject or accept, never a third outcome.
        // Every error is named rather than swallowed, so a new one added to the
        // connection surfaces here as a compile error and gets a decision
        // rather than a shrug.
        connection.receive(buffer[0..octets], @as(u64, datagrams) * 1000) catch |err| switch (err) {
            error.Protocol,
            error.CryptoBufferExceeded,
            error.FlowControl,
            error.FinalSize,
            error.StreamLimit,
            error.AeadLimitReached,
            error.StreamState,
            // The peer broke no rule and this endpoint ran out of span budget.
            // Still a close, so still a terminal outcome for this datagram.
            error.TooFragmented,
            => {},
        };

        // A connection that took a protocol error is finished with, but it must
        // still answer without crashing — which is what a caller does before it
        // closes.
        var out: [FuzzConnection.datagram_octets]u8 = undefined;
        const sent = connection.send(&out, @as(u64, datagrams) * 1000 + 1) catch 0;
        assert(sent <= out.len);
        // Section 8.1: a server that has not validated the address may never
        // send more than three times what it received. This is the invariant
        // whose violation makes a reflector, and nothing a peer sends may break
        // it.
        if (!connection.address_validated) {
            assert(connection.sent_octets <= connection.received_octets * quic.connection.amplification_factor);
        }
    }
}

test "connection: authenticated does not mean trusted" {
    try std.testing.fuzz({}, fuzzConnection, .{});
}

const FuzzRecovery = quic.Recovery(.{ .sent_max = 32, .max_datagram_size = 1200, .Context = u64 });

/// Loss recovery against a model of what is outstanding.
///
/// The oracle is `bytes_in_flight`, because it is the number that gates
/// sending and because both directions of drift are silent failures rather
/// than crashes: too high and the connection deadlocks against a window it
/// cannot get under, too low and congestion control has been defeated and this
/// endpoint is unfair to everything else on the path. Neither shows up as
/// anything but a bad day on someone's network.
///
/// The ACK frames are drawn rather than well-formed, because a peer chooses
/// them: an ACK claiming numbers never sent, ranges that walk below zero, or a
/// delay far past what was advertised are all things a hostile peer sends and a
/// conforming one occasionally does under reordering.
fn fuzzRecovery(_: void, smith: *std.testing.Smith) !void {
    var recovery: FuzzRecovery = .{};
    var lost: [32]u64 = undefined;

    // The model: what this target believes is outstanding and in flight.
    var outstanding: [64]?u32 = @splat(null);
    var next_number: u64 = 0;
    var now: u64 = 0;

    var operations: u32 = 0;
    while (operations < recovery_operations_max and !smith.eosWeightedSimple(6, 1)) : (operations += 1) {
        now += @as(u64, smith.valueRangeAtMost(u8, 0, 200)) * std.time.ns_per_ms;

        switch (smith.value(enum { send, ack, timeout })) {
            .send => {
                if (next_number >= outstanding.len) continue;
                const octets = smith.valueRangeAtMost(u16, 1, 1200);
                const in_flight = smith.value(bool);
                recovery.onPacketSent(.initial, .{
                    .number = next_number,
                    .time_sent = now,
                    .octets = octets,
                    .ack_eliciting = smith.value(bool),
                    .in_flight = in_flight,
                    .context = next_number,
                }) catch continue;
                if (in_flight) outstanding[next_number] = octets;
                next_number += 1;
            },
            .ack => {
                const largest = smith.valueRangeAtMost(u8, 0, @intCast(outstanding.len - 1));
                const first_range = smith.valueRangeAtMost(u8, 0, largest);
                const ack: h3.quic.frame.Ack = .{
                    .largest = largest,
                    .delay = smith.value(u16),
                    .first_range = first_range,
                    .range_count = 0,
                    .ranges = &.{},
                    .ecn = null,
                };
                const result = recovery.onAckReceived(.initial, ack, smith.value(u16), now, &lost) catch continue;
                // Everything the frame covered leaves the model, and so does
                // everything reported lost.
                var number = largest - first_range;
                while (number <= largest) : (number += 1) outstanding[number] = null;
                for (lost[0..@min(result.lost, lost.len)]) |context| outstanding[context] = null;
            },
            .timeout => {
                const at = recovery.timeoutAt() orelse continue;
                const outcome = recovery.onLossDetectionTimeout(@max(now, at), &lost);
                switch (outcome) {
                    .lost => |count| for (lost[0..@min(count, lost.len)]) |context| {
                        outstanding[context] = null;
                    },
                    .probe, .idle => {},
                }
            },
        }

        // The oracle. A short `lost` slice would make the model drift, so it is
        // sized above what the recovery can hold and the assertion is exact.
        var expected: u64 = 0;
        for (outstanding) |octets| expected += octets orelse 0;
        assert(recovery.bytes_in_flight == expected);

        // Section B.6's floor.
        assert(recovery.congestion_window >= 2 * 1200);
        // Sections 6.1.2 and 6.2.1: every timer has a floor at the granularity,
        // whatever the RTT estimate is. This is what an earlier version of this
        // target got wrong — it asserted `smoothed_rtt > 0`, which RFC 9002
        // does not guarantee: a packet sent and acknowledged inside one clock
        // tick is a zero sample, and a zero estimate is valid because
        // everything derived from it is floored. The floors are the property
        // worth asserting.
        assert(recovery.lossDelay() >= quic.recovery.granularity_ns);
        if (recovery.timeoutAt()) |at| assert(at >= quic.recovery.granularity_ns);
        // Section 5.2: the minimum is a minimum of samples, so it never exceeds
        // the newest one.
        if (recovery.has_rtt_sample) assert(recovery.min_rtt <= recovery.latest_rtt);
    }
}

test "recovery: bytes in flight are exactly what is outstanding" {
    try std.testing.fuzz({}, fuzzRecovery, .{});
}

const FuzzStreams = quic.Streams(.{
    .streams_max = 4,
    .receive_octets = 64,
    .send_octets = 32,
    .connection_receive_octets = 128,
});

/// Streams and flow control, against the invariant that actually bounds memory.
///
/// A peer chooses the stream identifiers, the offsets, the lengths and when a
/// FIN or a RESET_STREAM lands. The oracle is section 4.1's connection-level
/// accounting: `received_total` may never exceed the advertised limit, and it
/// may never *fall* — a peer that could make it fall could open a stream, fill
/// the connection's window, reset it, and repeat, holding nothing and consuming
/// everything.
fn fuzzStreams(_: void, smith: *std.testing.Smith) !void {
    var set: FuzzStreams = .{};
    var previous_total: u64 = 0;

    var operations: u32 = 0;
    while (operations < streams_operations_max and !smith.eosWeightedSimple(8, 1)) : (operations += 1) {
        const id: u64 = @as(u64, smith.valueRangeAtMost(u8, 0, 5)) * 4;

        switch (smith.value(enum { receive, consume, reset, write, limits })) {
            .receive => {
                var chunk: [96]u8 = undefined;
                const length = @min(smith.slice(&chunk), chunk.len);
                const offset = smith.valueRangeAtMost(u8, 0, 96);
                set.receive(id, offset, chunk[0..length], smith.value(bool)) catch {};
            },
            .consume => {
                const stream = set.find(id) orelse continue;
                const ready = stream.readable().len;
                if (ready == 0) continue;
                const take = smith.valueRangeAtMost(u8, 1, @intCast(@min(ready, 255)));
                set.consume(id, take) catch {};
            },
            .reset => set.reset(id, smith.value(u16), smith.valueRangeAtMost(u8, 0, 96)) catch {},
            .write => {
                var chunk: [64]u8 = undefined;
                const length = @min(smith.slice(&chunk), chunk.len);
                _ = set.write(id, chunk[0..length], smith.value(bool)) catch {};
            },
            .limits => {
                set.setConnectionSendLimit(smith.value(u16));
                set.setSendLimit(id, smith.value(u16)) catch {};
            },
        }

        // Section 4.1's connection limit, which is what bounds memory: without
        // it a peer's budget is the per-stream window times the stream count.
        assert(set.received_total <= set.receiveLimit());
        // And credit consumed never comes back.
        assert(set.received_total >= previous_total);
        previous_total = set.received_total;

        // Each stream stays inside its own limit, and what is readable is never
        // more than the window that admitted it.
        for (set.streams[0..set.count]) |*stream| {
            assert(stream.received_highest <= stream.receiveLimit());
            assert(stream.readable().len <= FuzzStreams.receive_octets);
            assert(stream.consumed <= stream.received_highest);
        }
        assert(set.count <= FuzzStreams.streams_max);
    }
}

test "streams: the connection window is never exceeded and never returned" {
    try std.testing.fuzz({}, fuzzStreams, .{});
}

/// QPACK field sections: decode never panics, and encode round-trips.
///
/// Two properties, and the second is the one that matters. A field section is
/// the most attacker-shaped input in HTTP/3 — a peer chooses every octet, the
/// lengths are its own, and a Huffman string expands. The decode side asserts
/// reject-or-parse and that the decoded strings stay inside the buffer that
/// bounds the expansion. The encode side asserts that anything this package
/// writes, it reads back identically, which is what stops the two halves of
/// section 4.5 from drifting apart into two spellings of one header.
fn fuzzFieldLine(_: void, smith: *std.testing.Smith) !void {
    var section: [512]u8 = undefined;
    const length = @min(smith.slice(&section), section.len);

    var buffer: [2048]u8 = undefined;
    if (h3.qpack.field_line.iterate(section[0..length], &buffer, 1 << 16)) |start| {
        var iterator = start;
        var count: u32 = 0;
        while (count <= length) : (count += 1) {
            const one = iterator.next() catch break;
            const field = one orelse break;
            // Whatever came out is inside what the caller lent, and inside the
            // list bound it advertised.
            assert(field.name.len + field.value.len <= buffer.len + section.len);
            assert(iterator.used <= buffer.len);
            assert(iterator.list_size <= iterator.list_size_max);
            assert(iterator.offset <= length);
        }
    } else |_| {}

    // The other direction, on drawn text rather than drawn octets.
    var names: [4][]const u8 = undefined;
    var values: [4][]const u8 = undefined;
    var storage: [4][64]u8 = undefined;
    var value_storage: [4][64]u8 = undefined;
    var fields: [4]h3.qpack.Field = undefined;
    const count = smith.valueRangeAtMost(u8, 1, 4);

    for (0..count) |index| {
        const name_len = @max(1, @min(smith.slice(&storage[index]), storage[index].len));
        const value_len = @min(smith.slice(&value_storage[index]), value_storage[index].len);
        names[index] = storage[index][0..name_len];
        values[index] = value_storage[index][0..value_len];
        fields[index] = .{ .name = names[index], .value = values[index], .never_indexed = smith.value(bool) };
    }

    var wire: [2048]u8 = undefined;
    const written = h3.qpack.field_line.encode(&wire, fields[0..count]) catch return;
    var back: [2048]u8 = undefined;
    var reader = h3.qpack.field_line.iterate(wire[0..written], &back, 1 << 20) catch unreachable; // Written by this package's own encoder.
    for (fields[0..count]) |expected| {
        const got = (reader.next() catch unreachable).?; // As above.
        assert(std.mem.eql(u8, got.name, expected.name));
        assert(std.mem.eql(u8, got.value, expected.value));
        assert(got.never_indexed == expected.never_indexed);
    }
    assert((reader.next() catch unreachable) == null); // As above.
}

test "qpack: a field section decodes safely and round-trips exactly" {
    try std.testing.fuzz({}, fuzzFieldLine, .{});
}

/// The message rules are the request-smuggling boundary, so the property is the
/// same reject-or-parse the decoders get: a section is well-formed or it is
/// refused, and there is no third outcome where a validator returns success
/// having quietly skipped a rule.
fn fuzzFields(_: void, smith: *std.testing.Smith) anyerror!void {
    const kinds = [_]h3.fields.Kind{ .request, .response, .trailer };
    const options: h3.fields.Options = .{
        .kind = kinds[smith.valueRangeAtMost(u8, 0, kinds.len - 1)],
        .extended_connect = smith.value(bool),
    };

    // Drawn from the vocabulary a real section uses rather than from arbitrary
    // octets: the interesting bugs are in which combinations of *valid* names
    // are accepted together, and random bytes reach almost none of them.
    const names = [_][]const u8{
        ":method",        ":scheme",   ":authority", ":path",
        ":status",        ":protocol", ":invented",  "host",
        "content-length", "te",        "connection", "user-agent",
    };
    const values = [_][]const u8{
        "GET", "CONNECT", "https", "ftp",                  "example.com", "evil.example",
        "/",   "",        "200",   "20",                   "websocket",   "trailers",
        "10",  "10, 10",  "007",   "99999999999999999999",
    };

    // The draw is recorded rather than consumed, so the section can be replayed
    // and the invariants below can be computed from the input independently of
    // anything the validator itself reports.
    const fields_max = 8;
    var drawn: [fields_max]h3.qpack.Field = undefined;
    const count = smith.valueRangeAtMost(u8, 0, fields_max);
    for (0..count) |index| {
        drawn[index] = .{
            .name = names[smith.valueRangeAtMost(u8, 0, names.len - 1)],
            .value = values[smith.valueRangeAtMost(u8, 0, values.len - 1)],
        };
    }
    const section = drawn[0..count];

    if (!accepts(options, section)) return;

    // Two rules restated as properties of the *input*, so that a validator
    // which lost one of them cannot also hide it. Section 4.3: "Pseudo-header
    // fields MUST NOT appear in trailer sections."
    if (options.kind == .trailer) {
        for (section) |one| assert(one.name[0] != ':');
    }
    // RFC 9220 section 3: `:protocol` exists only where it was negotiated, and
    // section 4.3 makes an undefined pseudo-header malformed.
    if (!options.extended_connect) {
        for (section) |one| assert(!std.mem.eql(u8, one.name, ":protocol"));
    }
    // A response's pseudo-header may not appear in a request, nor the reverse.
    if (options.kind == .request) {
        for (section) |one| assert(!std.mem.eql(u8, one.name, ":status"));
    }
    if (options.kind == .response) {
        for (section) |one| assert(one.name[0] != ':' or std.mem.eql(u8, one.name, ":status"));
    }

    // The verdict may not depend on state left over from a previous walk: a
    // second validator over the same section must agree with the first.
    assert(accepts(options, section));
}

/// Walk one section through a fresh validator and report only the verdict.
/// A validator is spent once it refuses — every violation in section 4.1.2 is a
/// malformed message and a malformed message is refused whole — so there is no
/// partial verdict for `finish` to add to.
fn accepts(options: h3.fields.Options, section: []const h3.qpack.Field) bool {
    var validator: h3.fields.MessageValidator = .init(options);
    for (section) |one| {
        validator.field(&one) catch return false;
    }
    validator.finish() catch return false;
    return true;
}

test "fields: a field section is a message or it is refused" {
    try std.testing.fuzz({}, fuzzFields, .{});
}
