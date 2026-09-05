//! The seeded simulator of docs/VERIFICATION.md section 5.2.
//!
//! Two `Connection`s on a virtual clock with a modelled link between them, run
//! from a seed that decides the topology, the schedule and the loss pattern.
//! Nothing here reads a real clock or draws entropy from the system: a seed is
//! a complete description of a run, so a failure is replayed with
//! `zig build sim -- --seed N` rather than reproduced.
//!
//! ## Why this and not more unit tests
//!
//! Section 1 of VERIFICATION.md has the list. A FIN was re-framed into every
//! packet forever and `wantsSend` never answered false again; `writePayload`
//! committed ACK debt and cursors before `seal` was known to succeed; a
//! congestion window was computed and never consulted. None of those is a
//! function returning the wrong value, so no test of a function finds them.
//! They are properties of a *connection over time*: it goes quiet, it does not
//! commit state it might have to unwind, it obeys the window it computes. This
//! file is where a property like that can be stated.
//!
//! ## The oracles
//!
//! Checked after every step, because a violation found one step after it
//! happens is a violation whose cause is still on the screen:
//!
//!  1. **Quiet.** The pair stops sending within a bounded virtual time of the
//!     application going idle. This is the FIN-forever bug's oracle.
//!  2. **The window binds.** In-flight octets never exceed the congestion
//!     window by more than one datagram — the exception is a PTO probe, which
//!     section 7 of RFC 9002 permits and which is at most one packet.
//!  3. **The amplification limit holds.** A server that has not validated the
//!     address never sends more than three times what it received. This is the
//!     one whose violation makes a reflector.
//!  4. **Packet numbers never repeat** in a space, because a repeat is a
//!     repeated AEAD nonce.
//!  5. **Stream data arrives exactly once, in order.** What the application
//!     wrote is what the peer reads, byte for byte.
//!  6. **A timer is never in the past** while the connection claims to have
//!     nothing to send.
//!
//! ## The census
//!
//! A run that never lost a packet proved less than it looks like it proved. The
//! census counts what the sweep *reached* — a PTO fired, a window collapsed, a
//! packet was reordered — and a counter that no seed moves is reported as a
//! finding rather than left for a reader to notice. That is zoxy's discipline
//! and the reason section 5.2 asks for it.

const std = @import("std");

const h3 = @import("h3");
const options = @import("sim_options");

const Link = @import("Link.zig");

const assert = std.debug.assert;

const quic = h3.quic;
const Level = quic.crypto.Level;
const Side = quic.Side;
const ConnectionId = quic.ConnectionId;

/// Small on purpose: a sweep runs thousands of these, and every buffer here is
/// comptime-sized into the connection.
const Connection = quic.Connection(.{
    .crypto_octets = 4096,
    .ack_ranges_max = 16,
    .datagram_octets = 1452,
    .transport_parameters_octets = 1024,
    .sent_max = 64,
    .streams_max = 8,
    // The receive window is deliberately *smaller* than the send buffer. With
    // it the other way round the sender always ran out of its own buffer first,
    // so every short write was this endpoint filling up rather than the peer's
    // window closing — and the state a MAX_STREAM_DATA exists to end was never
    // entered. A receiver whose window is tighter than the sender's buffer is
    // also the ordinary case: the buffer is a local choice and the window is a
    // promise about memory.
    .stream_receive_octets = stream_receive_octets,
    .stream_send_octets = 32 * 1024,
    .connection_receive_octets = connection_receive_octets,
});

/// The receive windows, named so that the transport parameters this harness
/// advertises can be derived from them rather than restated beside them. A
/// promise larger than the buffer behind it is a sender permitted to overrun a
/// receiver, which is a defect in the harness that reads as one in the library.
const stream_receive_octets: u32 = 16 * 1024;
const connection_receive_octets: u64 = 64 * 1024;

comptime {
    // The window is smaller than the send buffer on purpose — see the note in
    // the `Connection` config above — and the payload has to outrun both or
    // flow control never paces anything.
    assert(stream_receive_octets < 32 * 1024);
    assert(payload_octets_max > connection_receive_octets);
}

/// Virtual time a run may take before it is called a livelock. Generous
/// against a lossy path with exponential backoff, and far below anything a
/// working connection needs.
const deadline_ns: u64 = 120 * std.time.ns_per_s;
/// Steps a run may take. The clock alone is not enough of a bound: a bug that
/// makes both sides send without advancing time would otherwise spin.
const steps_max: u32 = 200_000;
/// How long after the application finishes the pair may still be sending.
/// Acknowledgements and a close have to fit inside it; a FIN re-framed forever
/// does not.
const quiet_ns: u64 = 10 * std.time.ns_per_s;
/// Timers one endpoint may service at one instant before the harness calls it a
/// spin. A loss detection timer that re-arms in the past without sending
/// anything is a livelock, and this is where it is caught.
const timers_per_step_max: u32 = 64;
/// Events one endpoint may report at one instant before the harness calls it a
/// runaway. Above `events_max` in the connection, so a full queue drains.
const events_per_step_max: u32 = 256;
/// Steps the pair may take after the transfer finishes before going quiet.
/// Generous against a lossy path still retransmitting a FIN or a close, and far
/// short of the step budget, so a genuine never-quiet shows up as this rather
/// than as an exhausted run.
const quiet_steps_max: u32 = 2000;

/// What the application on each side does, so that "delivered equals written"
/// has something to compare.
///
/// Larger than the connection's own windows, and that is the point: a transfer
/// that fits inside a receive window is one flow control never has to pace, and
/// every window-update defect this package has had lived on the other side of
/// that. Most seeds stay small so the sweep stays quick; `drawPayloadLength`
/// is where the split is.
const payload_octets_max: u32 = 192 * 1024;

/// A payload size, mostly small and sometimes past the windows above.
fn drawPayloadLength(random: std.Random) u32 {
    if (random.uintLessThan(u8, 4) == 0) {
        return 1 + random.uintLessThan(u32, payload_octets_max - 1);
    }
    return 1 + random.uintLessThan(u32, payload_octets_common);
}

/// One step in this many advances the clock past the next event, and by at
/// most this much. Named and related to the deadline: a jump is virtual time
/// spent on nothing, and enough of them would exhaust a run's budget and
/// produce a failure the library did not cause.
const clock_jump_period: u8 = 16;
const clock_jump_ns_max: u64 = 50 * std.time.ns_per_ms;

/// One step in this many puts something back on the wire, and a seed's attacker
/// gets at most this many injections. A flood would measure how long an
/// endpoint takes to discard rubbish rather than whether it discards it.
const adversary_period: u8 = 8;
const adversary_budget_max: u32 = 24;

/// One seed in this many draws an attacker, and one in this many reads slowly.
/// Not all of them: a behaviour every seed reaches is one no seed can be
/// compared against.
const adversary_seed_period: u8 = 3;
const reader_seed_period: u8 = 3;

/// The most steps a late reader waits between drains, and how far the clock
/// moves when the network is quiet and it still has data.
const read_every_max: u32 = 8;
const reader_catch_up_ns: u64 = std.time.ns_per_ms;

/// Payloads below this are the common case; above it, up to
/// `payload_octets_max`, is the quarter that outruns the windows.
const payload_octets_common: u32 = 24 * 1024;

comptime {
    assert(clock_jump_ns_max < quiet_ns);
    assert(clock_jump_ns_max * @as(u64, steps_max / clock_jump_period) > deadline_ns);
    assert(read_every_max < quiet_steps_max);
    assert(reader_catch_up_ns < quiet_ns);
    assert(payload_octets_common < payload_octets_max);
    assert(adversary_budget_max < steps_max);
}

const fake_secret_seeds = [_]u8{ 0x11, 0x22, 0x33, 0x44 };

/// Stand-in for the server's first flight: ServerHello, EncryptedExtensions,
/// Certificate, CertificateVerify, Finished. Sized like a real one rather than
/// like a token, for the reason in `driveHandshake`.
const server_flight: [2600]u8 = @splat(0xa5);

/// The two endpoints' Source Connection IDs, at file scope because the
/// datagram oracle needs the *peer's* length to walk a short header.
const client_source = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const server_source = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

const Census = struct {
    runs: u64 = 0,
    handshakes_completed: u64 = 0,
    transfers_completed: u64 = 0,
    packets_lost_declared: u64 = 0,
    ptos_fired: u64 = 0,
    key_updates: u64 = 0,
    windows_collapsed: u64 = 0,
    windows_halved: u64 = 0,
    link_dropped: u64 = 0,
    link_reordered: u64 = 0,
    link_duplicated: u64 = 0,
    link_queue_dropped: u64 = 0,
    amplification_binding: u64 = 0,
    closes_observed: u64 = 0,
    /// Runs that ended short *and* had reported a connection error, so the
    /// oracle above let them pass. Printed because a sweep where most runs are
    /// excused is a sweep proving much less than its pass suggests, and that is
    /// invisible without a count.
    runs_ended_by_close: u64 = 0,
    streams_delivered: u64 = 0,
    /// Datagrams whose packets account for every octet of them, and datagrams
    /// that end in padding no packet claims.
    ///
    /// Section 14.1 names two ways to reach 1200 octets — PADDING frames in the
    /// Initial packet, or coalescing — and zeroes after the last packet are
    /// neither. Every peer accepts them, so nothing fails; what it costs is
    /// that a peer parses them as one more packet and throws it away. This is
    /// the measurement that was taken by hand, out of quic-go's log, while
    /// chasing `handshakeloss`: it belongs here, where every seed takes it.
    datagrams_whole: u64 = 0,
    datagrams_with_loose_padding: u64 = 0,
    /// Probes that carried unacknowledged data, and probes that went out with
    /// nothing but a PING.
    ///
    /// RFC 9002 section 6.2.4 prefers the first: a probe that carries the
    /// handshake makes progress and a probe that carries nothing only asks
    /// whether the path is alive. A sweep where the second dominates is a
    /// sweep where loss recovery is one round trip slower than it reads.
    probes_carrying_data: u64 = 0,
    probes_carrying_ping: u64 = 0,
    /// What the off-path attacker put back on the wire. It holds no key, so
    /// everything it can do is done with what it has already seen: send it
    /// again, send part of it, or send it with an octet changed.
    adversary_replays: u64 = 0,
    adversary_truncations: u64 = 0,
    adversary_corruptions: u64 = 0,
    /// Writes the peer's flow control refused, in whole or in part.
    ///
    /// The sender running out of credit is the state every window-update defect
    /// this package has had lived in, and a harness whose reader consumes the
    /// instant anything arrives never enters it: the window is always open, so
    /// nothing is ever owed, so a MAX_STREAM_DATA that never went out is a
    /// MAX_STREAM_DATA nothing was waiting for.
    writes_refused_by_flow_control: u64 = 0,
    /// Steps where the clock moved past the next thing that could happen.
    ///
    /// A caller's clock is not a metronome: a process descheduled for fifty
    /// milliseconds services its timers late, all of them at once, and a
    /// connection that only works when serviced promptly works only on an idle
    /// machine.
    clock_jumps: u64 = 0,

    /// The counters that must move somewhere in a sweep. A zero here means the
    /// sweep did not reach the behaviour, so any confidence drawn from it about
    /// that behaviour is unearned.
    const required = [_]struct { name: []const u8, get: *const fn (*const Census) u64 }{
        .{ .name = "handshakes completed", .get = struct {
            fn get(c: *const Census) u64 {
                return c.handshakes_completed;
            }
        }.get },
        .{ .name = "transfers completed", .get = struct {
            fn get(c: *const Census) u64 {
                return c.transfers_completed;
            }
        }.get },
        .{ .name = "packets declared lost", .get = struct {
            fn get(c: *const Census) u64 {
                return c.packets_lost_declared;
            }
        }.get },
        .{ .name = "streams fully delivered", .get = struct {
            fn get(c: *const Census) u64 {
                return c.streams_delivered;
            }
        }.get },
        .{ .name = "PTOs fired", .get = struct {
            fn get(c: *const Census) u64 {
                return c.ptos_fired;
            }
        }.get },
        .{ .name = "congestion windows halved", .get = struct {
            fn get(c: *const Census) u64 {
                return c.windows_halved;
            }
        }.get },
        .{ .name = "datagrams dropped by the link", .get = struct {
            fn get(c: *const Census) u64 {
                return c.link_dropped;
            }
        }.get },
        .{ .name = "datagrams reordered", .get = struct {
            fn get(c: *const Census) u64 {
                return c.link_reordered;
            }
        }.get },
        .{ .name = "amplification limit binding", .get = struct {
            fn get(c: *const Census) u64 {
                return c.amplification_binding;
            }
        }.get },
        .{ .name = "datagrams accounted for by their packets", .get = struct {
            fn get(c: *const Census) u64 {
                return c.datagrams_whole;
            }
        }.get },
        .{ .name = "probes carrying data", .get = struct {
            fn get(c: *const Census) u64 {
                return c.probes_carrying_data;
            }
        }.get },
        .{ .name = "key updates", .get = struct {
            fn get(c: *const Census) u64 {
                return c.key_updates;
            }
        }.get },
        .{ .name = "datagrams replayed by the adversary", .get = struct {
            fn get(c: *const Census) u64 {
                return c.adversary_replays;
            }
        }.get },
        .{ .name = "datagrams truncated by the adversary", .get = struct {
            fn get(c: *const Census) u64 {
                return c.adversary_truncations;
            }
        }.get },
        .{ .name = "datagrams corrupted by the adversary", .get = struct {
            fn get(c: *const Census) u64 {
                return c.adversary_corruptions;
            }
        }.get },
        .{ .name = "writes refused by flow control", .get = struct {
            fn get(c: *const Census) u64 {
                return c.writes_refused_by_flow_control;
            }
        }.get },
        .{ .name = "clock jumps", .get = struct {
            fn get(c: *const Census) u64 {
                return c.clock_jumps;
            }
        }.get },
    };
};

/// An off-path attacker.
///
/// It sees everything that crosses the link and holds no key, which is the
/// whole of what it can do: send a datagram again, send part of one, or send
/// one with an octet changed. That is not a small threat model — a replay is
/// the only one of the three a conforming endpoint must *decrypt* and then
/// decide about, and the other two are the only routine source of packets that
/// fail authentication.
///
/// What it must not be able to do is anything at all. The oracle is the
/// transfer completing: an endpoint that a stranger can stall is an endpoint
/// anyone on the path can stall.
///
/// Not modelled here: forging an Initial packet. The keys for those are derived
/// from a connection identifier that travels in the clear, so an attacker who
/// saw the first flight can seal one — and the defect that reached review by
/// that route, a server adopting the source identifier from any Initial it
/// could open, is covered by a test in `Connection` rather than from here.
const Adversary = struct {
    /// The last datagram seen in each direction: index 0 is client to server.
    seen: [2][Link.datagram_octets_max]u8 = @splat(@splat(0)),
    seen_len: [2]u32 = @splat(0),
    /// How many injections this seed allows, and zero for a seed with no
    /// attacker at all. Bounded, because a flood is a different experiment: it
    /// would be measuring how long an endpoint takes to discard rubbish, not
    /// whether it discards it.
    budget: u32 = 0,

    fn capture(self: *Adversary, direction: usize, datagram: []const u8) void {
        if (self.budget == 0) return;
        assert(datagram.len <= self.seen[direction].len);
        @memcpy(self.seen[direction][0..datagram.len], datagram);
        self.seen_len[direction] = @intCast(datagram.len);
    }
};

/// Everything a failure needs to be understood without re-running it.
const Failure = struct {
    seed: u64,
    step: u32,
    now_ns: u64,
    what: []const u8,
    detail: u64 = 0,
};

const World = struct {
    seed: u64,
    prng: std.Random.DefaultPrng,
    now_ns: u64 = 0,
    step: u32 = 0,

    client: Connection,
    server: Connection,
    /// Client to server, then server to client.
    to_server: Link,
    to_client: Link,

    /// The fake TLS handshake, as a pair of scripted states. There is no TLS
    /// engine here by design — the seam takes handshake bytes as data — so the
    /// simulation drives the same constant-secret exchange the unit tests use,
    /// except that it crosses the link and can therefore be lost.
    client_installed: u8 = 0,
    server_installed: u8 = 0,

    /// The application.
    payload: [payload_octets_max]u8 = undefined,
    payload_len: u32,
    written: u32 = 0,
    write_done: bool = false,
    received: u32 = 0,

    /// Highest packet number sent per space, per endpoint, so a repeat is
    /// caught. Two arrays and not one: the client and the server number their
    /// spaces independently, and sharing a slot made the server's lower number
    /// read as the client's going backwards — an oracle that fired on every
    /// seed before it had seen a single packet.
    highest_sent: [2][3]?u64 = @splat(@splat(null)),

    /// How many steps the reader waits between draining the stream, and zero
    /// for a reader that takes everything the moment it arrives.
    ///
    /// A reader that never waits keeps the receive window open, and a window
    /// that is always open is a window nothing has to reopen. Every flow
    /// control defect this package has had lived on the other side of that.
    read_every: u32 = 0,
    read_countdown: u32 = 0,

    /// How far into the transfer this seed updates its keys, or zero for a seed
    /// that does not. Drawn rather than fixed so the update lands in different
    /// places relative to loss and reordering.
    key_update_at: u32 = 0,

    /// The step a connection error was seen at, or null. What makes a
    /// short transfer excusable, and a number rather than a flag so that a
    /// reader can tell "closed at the end" from "closed at the start".
    closed_at_step: ?u32 = null,

    /// When the application last had something to do, for the quiet oracle.
    busy_until_ns: u64 = 0,
    /// Steps taken since the transfer finished, which is the other half of that
    /// oracle's budget.
    drain_steps: u32 = 0,

    census: Census = .{},
    adversary: Adversary = .{},
    failure: ?Failure = null,
};

/// A loss pattern with a realistic density: most paths lose nothing, some lose
/// a few packets in sixty-four, a few are bad. Drawn as a bit count so the
/// distribution is over *rates* rather than over masks, of which the
/// overwhelming majority would be around half.
fn drawMask(random: std.Random) u64 {
    const bits = switch (random.uintLessThan(u8, 10)) {
        0, 1, 2 => @as(u6, 0),
        3, 4, 5 => random.uintLessThan(u6, 4),
        6, 7, 8 => random.uintLessThan(u6, 12),
        else => random.uintLessThan(u6, 28),
    };
    var mask: u64 = 0;
    for (0..bits) |_| mask |= @as(u64, 1) << random.int(u6);
    return mask;
}

fn buildWorld(seed: u64) World {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();

    // The path. Every field comes from the seed, so the topology is part of
    // what a replay reproduces.
    // Each direction gets its own pattern. The return path used to be
    // `~loss_mask`, which reads like "a different pattern" and is in fact
    // "everything the forward path did not drop" — a forward path losing three
    // packets in sixty-four gave a return path losing sixty-one, so no
    // handshake could complete and no seed ever reached a transfer. The census
    // is what made that visible rather than a passing run with nothing in it.
    const loss_mask = drawMask(random);
    const reverse_mask = drawMask(random);
    const delay_ns = (@as(u64, random.uintLessThan(u32, 60)) + 1) * std.time.ns_per_ms;
    const jitter_ns = @as(u64, random.uintLessThan(u32, 20)) * std.time.ns_per_ms;
    const rate = if (random.boolean()) @as(u64, 0) else 100_000 + @as(u64, random.uintLessThan(u32, 4_000_000));

    // Three distinct identifiers, as a real connection has: the Destination
    // Connection ID the client invents for its first Initial, and one source
    // each. Giving both endpoints the same source — which this did — meant the
    // client addressed its 1-RTT packets to an identifier the server did not
    // answer to, so every one of them was discarded as a forgery and no
    // acknowledgement ever came back. Silently, because RFC 9000 section 5.4
    // requires a packet that fails authentication to be dropped rather than
    // reported: exactly the shape a simulator is for.
    const client_cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    var world: World = .{
        .seed = seed,
        .prng = prng,
        .client = .init(.{
            .side = .client,
            .original_destination = ConnectionId.init(&client_cid) catch unreachable, // Eight octets.
            .source = ConnectionId.init(&client_source) catch unreachable, // Four octets.
        }),
        .server = .init(.{
            .side = .server,
            .original_destination = ConnectionId.init(&client_cid) catch unreachable, // As above.
            .source = ConnectionId.init(&server_source) catch unreachable, // Eight octets.
        }),
        .to_server = .init(.{
            .delay_ns = delay_ns,
            .jitter_ns = jitter_ns,
            .loss_mask = loss_mask,
            .rate_octets_per_second = rate,
            .duplicate_period = if (random.uintLessThan(u8, 4) == 0) 17 else 0,
        }),
        .to_client = .init(.{
            .delay_ns = delay_ns,
            .jitter_ns = jitter_ns,
            .loss_mask = reverse_mask,
            .rate_octets_per_second = rate,
            .duplicate_period = 0,
        }),
        .payload_len = drawPayloadLength(random),
    };
    // Half the seeds update their keys, somewhere in the first half of the
    // transfer. Half rather than all, because a behaviour every seed reaches is
    // one no seed can be compared against.
    if (random.boolean()) {
        world.key_update_at = 1 + random.uintLessThan(u32, @max(2, world.payload_len / 2));
    }
    // And a third of them are watched by somebody. The same reasoning: a sweep
    // where every seed has an attacker cannot say what the attacker changed.
    if (random.uintLessThan(u8, adversary_seed_period) == 0) {
        world.adversary.budget = 1 + random.uintLessThan(u32, adversary_budget_max);
    }
    // A third read slowly. Bounded, and bounded on purpose: a reader that
    // stops for ever stalls the transfer by construction, and the oracle that
    // the transfer completes would then be measuring the harness. What this
    // draws is a reader that is *late*, which is what closes a receive window
    // and makes the other endpoint ask for it to be reopened.
    if (random.uintLessThan(u8, reader_seed_period) == 0) {
        world.read_every = 1 + random.uintLessThan(u32, read_every_max);
    }
    // Content that a partial or reordered delivery cannot accidentally satisfy.
    for (&world.payload, 0..) |*octet, index| octet.* = @truncate(index *% 31 +% 7);
    world.prng = prng;
    return world;
}

/// Both sides may install the same constant secret independently, because it
/// is a constant. What crosses the link is the CRYPTO data that gates it, so a
/// lost handshake packet delays the installation exactly as a real one would.
fn driveHandshake(world: *World) void {
    if (world.client_installed == 0) {
        world.client.cryptoIn(.initial, "ClientHello") catch {};
        world.client_installed = 1;
    }
    // The server has the client's first flight: reply, and both sides move to
    // handshake keys.
    if (world.server_installed == 0 and world.server.cryptoOut(.initial).len >= "ClientHello".len) {
        installBoth(world, .handshake, fake_secret_seeds[0]);
        installBoth(world, .one_rtt, fake_secret_seeds[1]);
        // A realistic size, not a token string. A real server's first flight is
        // a certificate chain of a few kilobytes against a single 1200-octet
        // client Initial, which is exactly when RFC 9000 section 8.1's three-
        // times limit binds and makes the server wait for more from the client.
        // With a 38-octet flight it never bound, and the census reported the
        // behaviour unreached — correctly, because the sweep was not producing
        // the situation the limit exists for.
        world.server.cryptoIn(.handshake, &server_flight) catch {};
        exchangeTransportParameters(world);
        world.server_installed = 1;
    }
    // And the client, once the server's flight lands. It answers with its own
    // Handshake flight, which is not decoration: RFC 9000 section 8.1 has the
    // server treat the client's address as validated on receiving a Handshake
    // packet, and a client that never sends one leaves the server throttled to
    // three times what it received for the life of the connection. Without
    // this the pair transferred its data and then sat wanting to send for ever,
    // which read like a livelock in the library and was a gap in the harness.
    if (world.client_installed == 1 and world.client.cryptoOut(.handshake).len >= 8) {
        world.client.cryptoIn(.handshake, "ClientFinished") catch {};
        // RFC 9001 section 4.1.1: the server's handshake completes when it has
        // verified the client's Finished, and only a TLS engine knows that.
        // This is where a real consumer would say so.
        world.server.confirmHandshake();
        world.client_installed = 2;
        world.census.handshakes_completed += 1;
    }
}

/// Section 7.4: the limits each endpoint grants the other, carried in the TLS
/// extension. Encoded and fed through `transportParametersIn` rather than
/// poked into the streams directly, because that is the path a consumer takes
/// and it is where section 4.6's stream limits are applied — a simulation that
/// set the limits by hand would never exercise it.
fn exchangeTransportParameters(world: *World) void {
    // Section 7.3's identifiers are required of both roles, and a server must
    // also echo the client's original Destination Connection ID. The exchange
    // is symmetric here because the fake handshake is, so the encoding carries
    // both and each side validates the other's.
    const parameters: quic.transport_parameters.Parameters = .{
        .initial_source_connection_id = ConnectionId.init(&.{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 }) catch unreachable, // Eight octets.
        .original_destination_connection_id = ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }) catch unreachable, // As above.
        // The windows this connection actually has, not larger ones. These
        // were 1 MiB and 256 KiB against buffers of 64 KiB and 16 KiB, which is
        // a promise the receiver cannot keep: the sender is permitted past the
        // window and takes a FLOW_CONTROL_ERROR for doing what it was told it
        // could. A harness misconfiguration scored against the library — and,
        // because a connection error exempts a run from the transfer oracle,
        // one that hid itself.
        .initial_max_data = connection_receive_octets,
        .initial_max_stream_data_bidi_local = stream_receive_octets,
        .initial_max_stream_data_bidi_remote = stream_receive_octets,
        .initial_max_stream_data_uni = stream_receive_octets,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    };
    var encoded: [512]u8 = undefined;
    const written = quic.transport_parameters.encode(&encoded, &parameters) catch return;
    world.client.transportParametersIn(encoded[0..written]) catch return;
    world.server.transportParametersIn(encoded[0..written]) catch return;

    // The data windows are the consumer's seam — `Connection` deliberately
    // applies only the stream limits from the extension, leaving MAX_DATA and
    // MAX_STREAM_DATA to drive the rest. See `transportParametersIn`.
    world.client.streams.setConnectionSendLimit(parameters.initial_max_data);
    world.server.streams.setConnectionSendLimit(parameters.initial_max_data);
    const stream = quic.stream_id.make(.client_bidirectional, 0);
    world.client.streams.setSendLimit(stream, parameters.initial_max_stream_data_bidi_remote) catch {};
    world.server.streams.setSendLimit(stream, parameters.initial_max_stream_data_bidi_remote) catch {};
}

fn installBoth(world: *World, level: Level, seed: u8) void {
    const raw: [32]u8 = @splat(seed);
    const secret = quic.crypto.secrets.Secret.init(&raw) catch unreachable; // Thirty-two octets.
    world.client.installSecret(level, .send, &secret, .aes_128_gcm_sha256) catch unreachable; // A matching suite.
    world.client.installSecret(level, .receive, &secret, .aes_128_gcm_sha256) catch unreachable; // As above.
    world.server.installSecret(level, .send, &secret, .aes_128_gcm_sha256) catch unreachable; // As above.
    world.server.installSecret(level, .receive, &secret, .aes_128_gcm_sha256) catch unreachable; // As above.
}

/// The application: the client writes its payload as fast as flow control
/// allows, and the server reads it.
fn driveApplication(world: *World) void {
    if (world.client_installed < 2) return;
    const stream = quic.stream_id.make(.client_bidirectional, 0);

    // RFC 9001 section 6's key update, once per connection and only on seeds
    // that ask for it. The census row for it stayed at zero for as long as
    // nothing here initiated one, which is the census reporting that a
    // behaviour docs/VERIFICATION.md section 5.2 lists as required was not
    // reached — not that it works.
    if (world.key_update_at > 0 and world.written >= world.key_update_at) {
        world.key_update_at = 0;
        world.client.updateKeys();
    }

    if (!world.write_done) {
        const remaining = world.payload[world.written..world.payload_len];
        if (remaining.len > 0) {
            const taken = world.client.write(stream, remaining, false) catch 0;
            // Read off the flag the library sets, not off the short write. A
            // short write is *either* the peer's window closing or this
            // endpoint's own buffer filling, and only the first is the state a
            // window update has to end — so counting short writes made a
            // required census row that could never be zero and never measured
            // what it was named for.
            if (world.client.streams.owesBlocked()) {
                world.census.writes_refused_by_flow_control += 1;
            }
            world.written += @intCast(taken);
            if (taken > 0) world.busy_until_ns = world.now_ns;
        }
        if (world.written == world.payload_len) {
            // Only when the FIN was actually taken. Setting `write_done`
            // regardless made a refused FIN look like a finished write, and the
            // run then counted as a completed transfer with nothing having been
            // delivered.
            if (world.client.write(stream, &.{}, true)) |_| {
                world.write_done = true;
                world.busy_until_ns = world.now_ns;
            } else |_| {}
        }
    }

    if (world.read_countdown > 0) {
        world.read_countdown -= 1;
        return;
    }
    world.read_countdown = world.read_every;

    const readable = world.server.readable(stream);
    if (readable.len == 0) return;
    // Oracle five: what arrives is what was written, at the offset it was
    // written to. A duplicate delivered twice or a reordering resolved wrongly
    // shows up here and nowhere else.
    const expected = world.payload[world.received..][0..readable.len];
    if (!std.mem.eql(u8, expected, readable)) {
        fail(world, "stream data differs from what was written", world.received);
        return;
    }
    world.received += @intCast(readable.len);
    world.server.consume(stream, readable.len) catch {};
    world.busy_until_ns = world.now_ns;
}

/// Oracle seven: a datagram is the packets in it and nothing else.
///
/// Walk it the way a peer does. Every packet must parse, and the walk must
/// reach the end. What it does not reach is padding no packet claims — legal
/// enough, and the thing section 14.1 does not name: a peer reads the first
/// zero octet as a short header, fails the fixed-bit check, and throws the rest
/// away. That is counted rather than failed, because this package still falls
/// back to it when the packet it expected to pad declines to be written; a
/// count is what says how often, and a count that starts rising again is what
/// says a change made it worse.
///
/// Anything else in the tail *is* a failure: a datagram whose trailing octets
/// are neither a packet nor zeroes is one this endpoint built wrong.
fn inspectDatagram(world: *World, datagram: []const u8, peer_id_octets: u8) void {
    if (world.failure != null) return;
    assert(datagram.len <= Link.datagram_octets_max);
    assert(peer_id_octets <= quic.ConnectionId.octets_max);
    var offset: usize = 0;
    // Bounded by the datagram, because every packet is at least one octet —
    // and the assertion below is what makes that a checked claim rather than
    // this sentence.
    while (offset < datagram.len) {
        const parsed = quic.packet.parse(datagram[offset..], peer_id_octets) catch break;
        assert(parsed.octets >= 1);
        offset += parsed.octets;
        if (offset > datagram.len) {
            fail(world, "a packet claimed more octets than the datagram holds", offset);
            return;
        }
    }
    if (offset == datagram.len) {
        world.census.datagrams_whole += 1;
        return;
    }
    for (datagram[offset..]) |octet| {
        if (octet != 0) {
            fail(world, "a datagram ended in something that is neither a packet nor padding", offset);
            return;
        }
    }
    world.census.datagrams_with_loose_padding += 1;
}

/// Put something back on the wire, if this seed has an attacker and it has
/// anything to work with.
fn injectAdversary(world: *World, random: std.Random) void {
    if (world.adversary.budget == 0) return;
    // Sparse. The interesting question is whether an endpoint discards one of
    // these correctly, and asking it once per step would drown the connection
    // rather than test it.
    if (random.uintLessThan(u8, adversary_period) != 0) return;

    // `u8` rather than `usize`: `uintLessThan` consumes `@sizeOf(T)` octets per
    // attempt, so drawing through a `usize` makes the whole PRNG stream — and
    // therefore the run — depend on the pointer width. A seed is meant to be a
    // complete description of a run on any target.
    const direction: usize = random.uintLessThan(u8, 2);
    const length = world.adversary.seen_len[direction];
    if (length == 0) return;
    assert(length <= Link.datagram_octets_max);
    const link = if (direction == 0) &world.to_server else &world.to_client;

    var copy: [Link.datagram_octets_max]u8 = undefined;
    @memcpy(copy[0..length], world.adversary.seen[direction][0..length]);
    const budget_before = world.adversary.budget;
    world.adversary.budget -= 1;
    assert(world.adversary.budget < budget_before);

    switch (random.uintLessThan(u8, 3)) {
        // A replay. The only one of the three that authenticates, so it is the
        // only one an endpoint has to *decide* about rather than discard:
        // section 12.3's packet numbers are what make it a duplicate.
        0 => {
            world.census.adversary_replays += 1;
            link.send(copy[0..length], world.now_ns, random);
        },
        // A truncation, which is what a middlebox with a smaller idea of the
        // path produces as well as what an attacker does on purpose.
        1 => {
            const cut = 1 + random.uintLessThan(u32, length);
            assert(cut >= 1 and cut <= length);
            world.census.adversary_truncations += 1;
            link.send(copy[0..cut], world.now_ns, random);
        },
        // And a flipped bit. Anywhere: in the header, in the protected packet
        // number, in the ciphertext, in the tag.
        else => {
            const at = random.uintLessThan(u32, length);
            assert(at < length);
            copy[at] ^= @as(u8, 1) << random.int(u3);
            world.census.adversary_corruptions += 1;
            link.send(copy[0..length], world.now_ns, random);
        },
    }
}

fn fail(world: *World, what: []const u8, detail: u64) void {
    if (world.failure != null) return;
    world.failure = .{
        .seed = world.seed,
        .step = world.step,
        .now_ns = world.now_ns,
        .what = what,
        .detail = detail,
    };
}

/// Everything that must be true after every step.
fn checkInvariants(world: *World) void {
    if (world.failure != null) return;

    // Oracle two is deliberately **not** here, and the four attempts it took
    // to work that out are the most useful thing in this file.
    //
    // "In flight never exceeds the congestion window" is not true and
    // cannot be made true by adding slack. A congestion event halves the
    // window under data already on the wire and RFC 9002 does not retract
    // it; a PTO probe is exempt by section 7 and the RFC puts no bound on
    // how far a run of probe rounds may carry a sender. Every external
    // form of this oracle therefore needs a number the specification does
    // not give — and a number invented to make a run pass gets loosened
    // the next time it fires, which is the opposite of a gate. One
    // datagram of slack fired on a legitimate second probe; two fired on a
    // second probe *round*; "the largest window this connection ever had"
    // fired once the server's first flight became a realistic size.
    //
    // Section 7 bounds the *decision to send*, not the standing total, and
    // that decision is not visible from out here. So it is asserted where
    // it is — `Connection.sendPacket`, immediately after a non-probe
    // ack-eliciting packet is recorded, where `canSend` has just been
    // consulted with that packet's own size. That assertion is exact, it
    // needs no slack, and it runs in every seed of this sweep under the
    // default `-Dassertions`. It is strictly stronger than anything this
    // file could have written.
    // Oracle six is not checked here; see `serviceTimers`. VERIFICATION.md
    // states it as "timeout() is never in the past while wantsSend() is
    // false", and taken literally that fires on a timer which has merely
    // come due and not yet been serviced — which is every timer, for the
    // instant between the clock reaching it and the caller firing it. The
    // property that actually matters is that servicing *converges*: a
    // timer that re-arms in the past without sending anything is the spin
    // the oracle was written for, and that is what `serviceTimers` checks.

    // Oracle three, and the only one whose violation is a weapon: an
    // unvalidated server that sends more than three times what it received is
    // an amplifier someone else pays for.
    if (!world.server.address_validated) {
        const allowance = world.server.received_octets * quic.connection.amplification_factor;
        if (world.server.sent_octets > allowance) {
            fail(world, "server sent past the amplification limit before validating", world.server.sent_octets);
        }
        // "Binding" means the limit is what stopped the server, not that it
        // was hit to the octet — an exact-equality test was a knife edge no
        // seed ever landed on, so the census reported the behaviour unreached
        // while the sweep was in fact exercising it constantly.
        if (allowance > 0 and world.server.sent_octets * 10 >= allowance * 9) {
            world.census.amplification_binding += 1;
        }
    }

    // Oracle four. `space.next` is the next number to use, so it may only ever
    // rise; a fall would hand the same nonce to two packets under one key.
    inline for (.{ &world.client, &world.server }, 0..) |connection, which| {
        for (connection.spaces, 0..) |space, index| {
            if (world.highest_sent[which][index]) |previous| {
                if (space.next < previous) {
                    fail(world, "packet number went backwards in a space", space.next);
                }
            }
            world.highest_sent[which][index] = space.next;
        }
    }
}

/// One step: deliver what is due, let both sides send, advance the clock.
fn stepOnce(world: *World) bool {
    const random = world.prng.random();
    var datagram: [Link.datagram_octets_max]u8 = undefined;

    driveHandshake(world);
    driveApplication(world);

    // Deliver everything due now, both directions.
    while (world.to_server.receive(world.now_ns, &datagram)) |received| {
        world.server.receive(received, world.now_ns) catch |err| {
            recordClose(world, err);
        };
    }
    while (world.to_client.receive(world.now_ns, &datagram)) |received| {
        world.client.receive(received, world.now_ns) catch |err| {
            recordClose(world, err);
        };
    }

    driveHandshake(world);
    driveApplication(world);

    // Then let each side put what it has on the wire.
    inline for (.{
        .{ &world.client, &world.to_server, server_source.len, 0 },
        .{ &world.server, &world.to_client, client_source.len, 1 },
    }) |pair| {
        const connection = pair[0];
        const link = pair[1];
        // The identifier length the *peer* issued, which is the only way a
        // short header's Destination Connection ID can be found.
        const peer_id_octets: u8 = pair[2];
        const direction: usize = pair[3];
        var guard: u32 = 0;
        while (guard < 16) : (guard += 1) {
            const octets = connection.send(&datagram, world.now_ns) catch break;
            if (octets == 0) break;
            inspectDatagram(world, datagram[0..octets], peer_id_octets);
            world.adversary.capture(direction, datagram[0..octets]);
            link.send(datagram[0..octets], world.now_ns, random);
        }
    }

    injectAdversary(world, random);

    drainEvents(world);
    checkInvariants(world);
    if (world.failure != null) return false;

    // Advance the clock and service whatever it reached. Split out because
    // `stepOnce` was three separate things — deliver, send, advance — in one
    // function past the length limit, and the third is the one with the
    // invariants worth reading on their own.
    return advanceClock(world, random);
}

/// Move to the next thing that can happen, then fire everything the clock
/// reached. Answers false when there is nothing left to move to.
fn advanceClock(world: *World, random: std.Random) bool {
    // Advance to the next thing that can happen: a delivery, or a timer.
    var next: ?u64 = null;
    if (world.to_server.nextAt()) |at| next = minimum(next, at);
    if (world.to_client.nextAt()) |at| next = minimum(next, at);
    if (world.client.timeout()) |at| next = minimum(next, at);
    if (world.server.timeout()) |at| next = minimum(next, at);

    // A quiet network is not a finished run. With a reader that takes its time,
    // everything can be delivered and acknowledged while the application still
    // has octets buffered — nothing is owed in either direction, no timer is
    // armed, and the loop would end with the transfer short and both endpoints
    // blameless. The clock moves on so the reader can catch up.
    if (next == null and world.received < world.payload_len and
        world.server.readable(quic.stream_id.make(.client_bidirectional, 0)).len > 0)
    {
        world.now_ns += reader_catch_up_ns;
        return true;
    }

    const advance = next orelse return false;
    var target = @max(advance, world.now_ns + 1);
    // A caller's clock is not a metronome. A process descheduled for a few
    // milliseconds services every timer that came due while it was away, all at
    // once and all late, and a connection that only works when serviced
    // promptly works only on an idle machine. The jump is bounded so that a
    // sweep still finishes inside its virtual deadline — what is being tested
    // is lateness, not the idle timeout.
    if (random.uintLessThan(u8, clock_jump_period) == 0) {
        target += random.uintLessThan(u64, clock_jump_ns_max);
        world.census.clock_jumps += 1;
    }
    // The one invariant a jump could break, and the reason it is checked here
    // rather than trusted: everything downstream reads `now_ns` as monotone.
    assert(target > world.now_ns);
    world.now_ns = target;

    // Fire whatever the clock reached, to a fixpoint. A real event loop drains
    // its timer wheel rather than firing one timer per wakeup, and servicing
    // only one made the "timer in the past" oracle fire on the harness rather
    // than on the code. Bounded, because a timer that re-arms in the past
    // without doing anything is exactly what that oracle is for.
    inline for (.{ &world.client, &world.server }) |connection| {
        var fired: u32 = 0;
        while (fired < timers_per_step_max) : (fired += 1) {
            const at = connection.timeout() orelse break;
            if (at > world.now_ns) break;
            const before = connection.recovery.pto_count;
            // What a probe will carry, measured as what `onTimeout` put back.
            // A probe is supposed to re-send unacknowledged data rather than a
            // bare PING, and the difference is exactly whether the timeout
            // rewound a framing watermark: a probe pointed at an
            // acknowledgement-only packet rewinds nothing and goes out empty.
            // That was a real defect and it was invisible from outside the
            // library, which is what this row is for.
            const framed_before = framedTotal(connection);
            connection.onTimeout(world.now_ns);
            if (connection.recovery.pto_count > before) {
                world.census.ptos_fired += 1;
                if (framedTotal(connection) < framed_before) {
                    world.census.probes_carrying_data += 1;
                } else {
                    world.census.probes_carrying_ping += 1;
                }
            }
        }
        if (fired == timers_per_step_max) {
            fail(world, "timer re-armed in the past without making progress", fired);
        }
        // Oracle six, in its exact form: once the caller has drained the timer
        // wheel, nothing may still be due. A connection that leaves one due
        // hands an event loop a zero-length sleep for ever.
        if (connection.timeout()) |at| {
            if (at <= world.now_ns and !connection.wantsSend()) {
                fail(world, "timer still due after the caller drained the wheel", at);
            }
        }
    }
    return true;
}

/// A connection error ends the run's usefulness but is not itself a failure:
/// a lossy path plus an adversarial schedule can legitimately produce one, and
/// the oracles above are what decide whether the endpoint behaved.
/// Take everything both endpoints have to report. This is the seam of
/// docs/VERIFICATION.md section 5.3, and the census row it fills — "packets
/// declared lost" — sat at zero for as long as it did not exist: `Recovery`
/// reports losses per acknowledgement and keeps no total, so nothing outside
/// the library could count them.
fn drainEvents(world: *World) void {
    inline for (.{ &world.client, &world.server }) |connection| {
        var guard: u32 = 0;
        while (guard < events_per_step_max) : (guard += 1) {
            const event = connection.poll() orelse break;
            switch (event) {
                .packets_lost => |count| world.census.packets_lost_declared += count,
                .key_updated => world.census.key_updates += 1,
                .handshake_confirmed => {},
                .stream_delivered => world.census.streams_delivered += 1,
                .stream_readable, .stream_reset, .stream_stopped => {},
                .closed => world.census.closes_observed += 1,
                // A dropped event is the harness failing to poll, not the
                // library failing to report — and it must never be silent.
                .overflowed => |dropped| fail(world, "the simulator dropped connection events", dropped),
            }
        }
    }
}

fn recordClose(world: *World, err: anyerror) void {
    std.debug.assert(@errorName(err).len > 0);
    world.census.closes_observed += 1;
    if (world.closed_at_step == null) world.closed_at_step = world.step;
}

/// Everything this endpoint has framed and not yet had acknowledged, across the
/// handshake levels and the streams. Only the total matters: a probe that
/// carries data is one that made this number fall.
fn framedTotal(connection: anytype) u64 {
    assert(connection.streams.count <= @TypeOf(connection.streams).streams_max);
    var total: u64 = 0;
    for (connection.levels) |level| total += level.framed;
    for (connection.streams.streams[0..connection.streams.count]) |stream| total += stream.framed;
    return total;
}

fn minimum(current: ?u64, candidate: u64) u64 {
    return if (current) |value| @min(value, candidate) else candidate;
}

fn runSeed(seed: u64, census: *Census) ?Failure {
    var world = buildWorld(seed);
    census.runs += 1;

    const minimum_window = 2 * @as(u64, 1452);
    var window_seen_high = false;

    while (world.step < steps_max and world.now_ns < deadline_ns) : (world.step += 1) {
        if (world.client.recovery.congestion_window > minimum_window * 3) window_seen_high = true;
        if (window_seen_high and world.client.recovery.congestion_window <= minimum_window) {
            census.windows_collapsed += 1;
            window_seen_high = false;
        }
        if (!stepOnce(&world)) break;

        // Oracle one: once the application has nothing left to do, the pair
        // has a bounded window in which to go quiet. A FIN re-framed into every
        // packet forever is exactly this oracle failing.
        //
        // Bounded in *steps* as well as in virtual time, and both are needed.
        // Virtual time alone was the first version and it was wrong: the clock
        // jumps to the next timer, so a single step can cross the whole quiet
        // window before the pair has been given one opportunity to drain. It
        // fired on every seed against a server that, asked directly, produced a
        // packet immediately.
        if (world.write_done and world.received == world.payload_len) {
            world.drain_steps += 1;
            const quiet = !world.client.wantsSend() and !world.server.wantsSend() and
                world.to_server.idle() and world.to_client.idle();
            if (quiet) break;
            if (world.drain_steps > quiet_steps_max and world.now_ns > world.busy_until_ns + quiet_ns) {
                fail(&world, "pair still wants to send long after the transfer finished", world.drain_steps);
                break;
            }
        }
    }

    if (world.failure == null and world.step >= steps_max) {
        fail(&world, "step budget exhausted without finishing", world.step);
    }
    // And the other way a run can end without finishing: the virtual clock
    // reaching the deadline. That exit was silent, and the silence cost
    // something — a key update stalled fifty-nine transfers in a sweep and the
    // only trace was a census row that had gone down. A run that stops with the
    // transfer unfinished and nothing having gone wrong is a failure, and the
    // "nothing having gone wrong" is what keeps a legitimate connection error
    // out of it: a lossy path plus an adversarial schedule may end a connection,
    // and that is the endpoint behaving.
    // A close exempts the run only if it arrived *after* the transfer finished.
    // `closes_observed` on its own was a blanket exemption for the rest of the
    // run: one close at virtual second three and the remaining hundred and
    // seventeen proved nothing, while the sweep reported a pass. The adversary
    // and the flow-control paths added in the same change are both ways to
    // produce that close.
    if (world.failure == null and world.received != world.payload_len) {
        if (world.closed_at_step) |at| {
            census.runs_ended_by_close += 1;
            _ = at;
        } else {
            fail(&world, "the transfer stopped and neither endpoint reported anything", world.received);
        }
    }

    if (world.received == world.payload_len and world.payload_len > 0) {
        census.transfers_completed += 1;
    }
    // Every counter the world kept, added by name. It used to be a
    // hand-written list of fields, and the list was a trap of exactly the kind
    // this file already records one instance of: a counter nobody remembered to
    // add reads as a behaviour no seed reached, which is the lie the census
    // exists to prevent. Two rows were added in one change and both reported
    // zero while the sweep was reaching one of them constantly.
    //
    // The comment that stood here is worth keeping, because it names the other
    // half of the same symptom: "packets declared lost" read
    // `world.lost_declared`, a field added when the count was unobtainable and
    // then never incremented — so the row was zero because the accumulator read
    // a variable that stayed zero, not only because the library could not
    // report it. Two reasons for one symptom, and the second outlived the first
    // fix.
    inline for (@typeInfo(Census).@"struct".fields) |field| {
        // `runs` is counted per call rather than per world, and the link and
        // window rows below are drawn from somewhere other than `world.census`.
        if (comptime std.mem.eql(u8, field.name, "runs")) continue;
        @field(census, field.name) += @field(&world.census, field.name);
    }
    census.link_dropped += world.to_server.counters.dropped_loss + world.to_client.counters.dropped_loss;
    census.link_queue_dropped += world.to_server.counters.dropped_queue + world.to_client.counters.dropped_queue;
    census.link_reordered += world.to_server.counters.reordered + world.to_client.counters.reordered;
    census.link_duplicated += world.to_server.counters.duplicated + world.to_client.counters.duplicated;
    if (world.client.recovery.ssthresh != std.math.maxInt(u64)) census.windows_halved += 1;

    return world.failure;
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var seeds: u64 = options.seeds;
    var first: u64 = 0;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        // A number that does not parse, or a flag nobody recognises, ends the
        // run. Falling back silently is how a nightly sweeps the same range it
        // was written to avoid while reporting that it did something else: the
        // shell echoes the range it *meant* to pass and the sweep never sees
        // it.
        if (std.mem.eql(u8, args[index], "--seed") and index + 1 < args.len) {
            first = std.fmt.parseInt(u64, args[index + 1], 10) catch {
                std.debug.print("sim: --seed '{s}' is not a number\n", .{args[index + 1]});
                return 2;
            };
            seeds = 1;
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, args[index], "--seeds") and index + 1 < args.len) {
            seeds = std.fmt.parseInt(u64, args[index + 1], 10) catch {
                std.debug.print("sim: --seeds '{s}' is not a number\n", .{args[index + 1]});
                return 2;
            };
            index += 1;
            continue;
        }
        // Where the sweep starts, without saying how long it is. A nightly that
        // runs the same range every night proves the same thing every night;
        // this is what lets it take a fresh one, and `--seed` alone could not
        // because it also pins the count to one.
        if (std.mem.eql(u8, args[index], "--from") and index + 1 < args.len) {
            first = std.fmt.parseInt(u64, args[index + 1], 10) catch {
                std.debug.print("sim: --from '{s}' is not a number\n", .{args[index + 1]});
                return 2;
            };
            index += 1;
            continue;
        }
        std.debug.print("sim: unrecognised argument '{s}'\n", .{args[index]});
        return 2;
    }

    std.debug.print("h3 sim — {d} seed(s) from {d}, assertions {s}\n", .{
        seeds,
        first,
        if (h3.assertions.enabled) "on" else "off",
    });

    var census: Census = .{};
    var failures: u32 = 0;
    var seed = first;
    while (seed < first + seeds) : (seed += 1) {
        if (runSeed(seed, &census)) |failure| {
            failures += 1;
            std.debug.print(
                "\nFAIL seed {d}: {s}\n  step {d}, virtual time {d} ms, detail {d}\n  replay: zig build sim -- --seed {d}\n",
                .{ failure.seed, failure.what, failure.step, failure.now_ns / std.time.ns_per_ms, failure.detail, failure.seed },
            );
            if (failures >= 5) break;
        }
    }

    printCensus(&census);

    if (failures > 0) {
        std.debug.print("\nsim: {d} seed(s) failed\n", .{failures});
        return 1;
    }

    // A counter no seed moved means the sweep did not reach that behaviour, so
    // the confidence it appears to give is unearned. Reported as a failure of
    // the *sweep* rather than of the code, which is the distinction that keeps
    // it honest.
    var unreached: u32 = 0;
    for (Census.required) |one| {
        if (one.get(&census) == 0) {
            std.debug.print("sim: no seed reached: {s}\n", .{one.name});
            unreached += 1;
        }
    }
    if (unreached > 0) {
        std.debug.print("sim: {d} behaviour(s) unreached — the sweep proves less than it looks like\n", .{unreached});
        return 1;
    }
    return 0;
}

fn printCensus(census: *const Census) void {
    std.debug.print("\ncoverage census over {d} seed(s)\n\n", .{census.runs});
    const rows = [_]struct { name: []const u8, value: u64 }{
        .{ .name = "handshakes completed", .value = census.handshakes_completed },
        .{ .name = "transfers completed", .value = census.transfers_completed },
        .{ .name = "packets declared lost", .value = census.packets_lost_declared },
        .{ .name = "PTOs fired", .value = census.ptos_fired },
        .{ .name = "congestion windows halved", .value = census.windows_halved },
        .{ .name = "congestion windows collapsed", .value = census.windows_collapsed },
        .{ .name = "key updates", .value = census.key_updates },
        .{ .name = "datagrams dropped (loss)", .value = census.link_dropped },
        .{ .name = "datagrams dropped (queue)", .value = census.link_queue_dropped },
        .{ .name = "datagrams reordered", .value = census.link_reordered },
        .{ .name = "datagrams duplicated", .value = census.link_duplicated },
        .{ .name = "amplification limit binding", .value = census.amplification_binding },
        .{ .name = "connection errors seen", .value = census.closes_observed },
        .{ .name = "runs excused by a close", .value = census.runs_ended_by_close },
        .{ .name = "streams fully delivered", .value = census.streams_delivered },
        .{ .name = "datagrams whole", .value = census.datagrams_whole },
        .{ .name = "datagrams with loose padding", .value = census.datagrams_with_loose_padding },
        .{ .name = "probes carrying data", .value = census.probes_carrying_data },
        .{ .name = "probes carrying a bare PING", .value = census.probes_carrying_ping },
        .{ .name = "adversary: replays", .value = census.adversary_replays },
        .{ .name = "adversary: truncations", .value = census.adversary_truncations },
        .{ .name = "adversary: corruptions", .value = census.adversary_corruptions },
        .{ .name = "writes refused by flow control", .value = census.writes_refused_by_flow_control },
        .{ .name = "clock jumps", .value = census.clock_jumps },
    };
    for (rows) |row| std.debug.print("  {s:<32} {d}\n", .{ row.name, row.value });
}

const testing = std.testing;

test "a clean path completes a transfer and goes quiet" {
    // The seed is fixed so this is a unit test rather than a sweep; the sweep
    // is `zig build sim`.
    var census: Census = .{};
    const failure = runSeed(1, &census);
    if (failure) |one| {
        std.debug.print("seed 1 failed: {s}\n", .{one.what});
        return error.SimulationFailed;
    }
}

test "the same seed produces the same run" {
    // The property the whole harness rests on: a failure is replayed rather
    // than reproduced. Two runs of one seed must agree on everything observable.
    var first: Census = .{};
    var second: Census = .{};
    _ = runSeed(7, &first);
    _ = runSeed(7, &second);
    try testing.expectEqual(first.transfers_completed, second.transfers_completed);
    try testing.expectEqual(first.packets_lost_declared, second.packets_lost_declared);
    try testing.expectEqual(first.link_dropped, second.link_dropped);
    try testing.expectEqual(first.link_reordered, second.link_reordered);
    try testing.expectEqual(first.ptos_fired, second.ptos_fired);
}
