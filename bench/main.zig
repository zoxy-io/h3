//! Microbenchmarks for the paths a consumer runs per packet.
//!
//! ## The two footguns this file exists to avoid
//!
//! **An unused result is a deleted loop.** Every workload accumulates into
//! `sink`, which `run` then hands to `doNotOptimizeAway`. The build hardcodes
//! `ReleaseFast` for the same reason in reverse: a benchmark built in Debug
//! reports numbers that mean nothing.
//!
//! **A constant input is a folded loop, and that one is not hypothetical.** The
//! first version of this file used `const` wire encodings, and the three codec
//! rows reported exactly `0.000` ns/op — `ReleaseFast` had constant-folded the
//! decode and turned the loop into a multiplication. A sink alone does not stop
//! that: the result *is* used, it is just computed once. So every workload
//! calls `doNotOptimizeAway` on its *input* inside the loop, which is what
//! makes the input opaque and the decode real.
//!
//! ## What to read out of it
//!
//! Bands across runs, never single numbers. A 3% move between two runs on a
//! laptop is noise, and reporting it as a regression trains everyone to ignore
//! the gate. The rows that matter most are the two protection ones: they are
//! per-packet costs on both consumers' hot paths, and they are the only rows
//! where `std.crypto`'s backend choice shows through.

const std = @import("std");

const h3 = @import("h3");
const options = @import("bench_options");

const quic = h3.quic;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("h3 bench — {d} runs x {d} iterations, assertions {s}\n\n", .{
        options.runs,
        options.iterations,
        if (h3.assertions.enabled) "on" else "off",
    });
    std.debug.print("{s:<32} {s:>12} {s:>12}\n", .{ "workload", "mean ns/op", "best ns/op" });
    std.debug.print("{s}\n", .{"-" ** 58});

    run(io, "varint decode", benchVarintDecode);
    run(io, "quic frame parse", benchFrameParse);
    run(io, "http3 frame header", benchHttp3Header);
    run(io, "qpack static lookup", benchStaticLookup);
    run(io, "reassemble in order", benchReassembleOrdered);
    run(io, "reassemble reordered", benchReassembleReordered);
    run(io, "ack record + write", benchAckRanges);
    run(io, "packet seal (aes-128-gcm)", benchSeal);
    run(io, "packet seal+open (aes-128-gcm)", benchOpen);
}

fn run(io: std.Io, name: []const u8, workload: fn (u64) u64) void {
    var best: u64 = std.math.maxInt(u64);
    var total: u64 = 0;
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < options.runs) : (index += 1) {
        const started = std.Io.Clock.awake.now(io).nanoseconds;
        sink +%= workload(options.iterations);
        const finished = std.Io.Clock.awake.now(io).nanoseconds;
        const elapsed: u64 = @intCast(finished - started);
        total += elapsed;
        best = @min(best, elapsed);
    }
    // The sink is printed, not discarded: an unused result is a deleted loop.
    std.mem.doNotOptimizeAway(sink);
    // Fractional, not integer. The codec rows run in well under a nanosecond,
    // and an integer division truncates every one of them to `0` — a benchmark
    // whose fastest rows all report the same number is a benchmark nobody can
    // detect a regression with.
    const mean_ns = @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(options.runs * options.iterations));
    const best_ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(options.iterations));
    std.debug.print("{s:<32} {d:>12.3} {d:>12.3}\n", .{ name, mean_ns, best_ns });
}

fn benchVarintDecode(iterations: u64) u64 {
    var wire = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&wire);
        const decoded = h3.varint.decode(&wire) catch unreachable; // A well-formed eight-octet encoding.
        sink +%= decoded.value;
    }
    return sink;
}

fn benchFrameParse(iterations: u64) u64 {
    // A STREAM frame with offset, length and FIN — the shape a response body
    // arrives in.
    var wire = [_]u8{ 0x0f, 0x04, 0x44, 0x00, 0x10 } ++ [_]u8{0xab} ** 16;
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&wire);
        const parsed = h3.quic.frame.parse(&wire) catch unreachable; // A well-formed STREAM frame.
        sink +%= parsed.octets;
    }
    return sink;
}

fn benchHttp3Header(iterations: u64) u64 {
    var wire = [_]u8{ 0x00, 0x44, 0x00 };
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&wire);
        const header = h3.frame.parseHeader(&wire) catch unreachable; // A well-formed DATA header.
        sink +%= header.length;
    }
    return sink;
}

fn benchStaticLookup(iterations: u64) u64 {
    // A miss is the expensive case — it walks all ninety-nine entries — and it
    // is the common one for a real header set, so it is what the row measures.
    // This is the number docs/DESIGN.md says has to exist before the linear
    // scan is worth replacing with h2's eight-hashes-at-a-time approach.
    var name = "x-request-id".*;
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&name);
        const found = h3.qpack.static_table.lookup(&name, "");
        sink +%= if (found) |match| match.index else 1;
    }
    return sink;
}

/// A payload sized to a common-MTU datagram: 1200 octets, less a short header
/// with an eight-octet connection identifier and a four-octet packet number,
/// less the tag. The slack above the exact header is deliberate — the row
/// should measure the AEAD over a realistic length, not the last octet of it.
const bench_payload_octets: usize = 1200 - 32 - @as(usize, quic.crypto.tag_octets);

fn benchSeal(iterations: u64) u64 {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: quic.crypto.Keys = .initial(&dcid, .client);
    var datagram: [1200]u8 = @splat(0);
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        const written = quic.packet.writeShort(&datagram, .{
            .destination = quic.ConnectionId.init(&dcid) catch unreachable, // Eight octets, well under the limit.
            .number = index,
            .number_octets = 4,
        }) catch unreachable; // A 1200-octet buffer holds a 13-octet header.
        const total = keys.seal(&datagram, written.packet_number_offset, written.header_octets, bench_payload_octets, index) catch unreachable; // Sized above.
        sink +%= total;
    }
    return sink;
}

fn benchOpen(iterations: u64) u64 {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: quic.crypto.Keys = .initial(&dcid, .client);
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        // Re-sealed each iteration because `open` decrypts in place, so the
        // row is seal+open and the seal row above is what to subtract. Stated
        // rather than hidden: a benchmark that opened the same buffer twice
        // would be measuring an authentication failure.
        var datagram: [1200]u8 = @splat(0);
        const written = quic.packet.writeShort(&datagram, .{
            .destination = quic.ConnectionId.init(&dcid) catch unreachable, // As above.
            .number = index,
            .number_octets = 4,
        }) catch unreachable; // As above.
        const total = keys.seal(&datagram, written.packet_number_offset, written.header_octets, bench_payload_octets, index) catch unreachable; // As above.
        const opened = keys.open(datagram[0..total], written.packet_number_offset, index -| 1) catch unreachable; // Just sealed with these keys.
        sink +%= opened.payload.len;
    }
    return sink;
}

/// A response body's shape: 1 KiB chunks into a 16 KiB window, drained as they
/// arrive. The drain is what makes `consume` free — it moves only the octets
/// still held, and a reader that takes everything readable leaves none.
const BenchStream = quic.Reassembler(.{ .capacity = 16 * 1024, .spans_max = 16 });
const bench_chunk_octets = 1024;

fn benchReassembleOrdered(iterations: u64) u64 {
    var chunk: [bench_chunk_octets]u8 = @splat(0xab);
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&chunk);
        var stream: BenchStream = .{};
        var offset: u64 = 0;
        while (offset < 8 * bench_chunk_octets) : (offset += bench_chunk_octets) {
            stream.push(offset, &chunk) catch unreachable; // Eight chunks into a sixteen-chunk window.
            const ready = stream.readable();
            sink +%= ready.len;
            stream.consume(ready.len);
        }
    }
    return sink;
}

/// The same bytes with every pair of chunks swapped, which is what one
/// reordering event on the path looks like. The gap holds the run back until
/// the missing chunk lands, so this measures the span bookkeeping rather than
/// the copy.
fn benchReassembleReordered(iterations: u64) u64 {
    var chunk: [bench_chunk_octets]u8 = @splat(0xab);
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        std.mem.doNotOptimizeAway(&chunk);
        var stream: BenchStream = .{};
        var pair: u64 = 0;
        while (pair < 4) : (pair += 1) {
            const first = pair * 2 * bench_chunk_octets;
            stream.push(first + bench_chunk_octets, &chunk) catch unreachable; // As above.
            stream.push(first, &chunk) catch unreachable; // As above.
            const ready = stream.readable();
            sink +%= ready.len;
            stream.consume(ready.len);
        }
    }
    return sink;
}

const BenchAck = quic.AckRanges(.{ .ranges_max = 32 });

/// Every other packet number, which is the shape that costs one range each and
/// the shape a peer would choose to make this expensive.
fn benchAckRanges(iterations: u64) u64 {
    var target: [512]u8 = undefined;
    var sink: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        var set: BenchAck = .{};
        var number: u64 = 0;
        while (number < 64) : (number += 2) {
            set.record(number, 0, true);
        }
        const written = set.write(&target, 0, 3) catch unreachable; // The target holds thirty-two ranges.
        sink +%= written.octets;
    }
    return sink;
}
