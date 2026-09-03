//! One direction of a network path: what a datagram meets between `send` on
//! one `Connection` and `receive` on the other.
//!
//! Modelled on picoquic's `sim_link.c`, which docs/VERIFICATION.md section 5.2
//! names as the shape to copy. The properties that matter are that every
//! decision comes from the seed and nothing else, and that a datagram's whole
//! journey is decided when it is queued rather than when it is delivered — so
//! replaying a seed replays the path exactly, whatever the endpoints do.
//!
//! ## Why a rotating loss mask rather than a probability
//!
//! A per-datagram coin flip makes "30% loss" mean a different *pattern* every
//! time the endpoints change their sending behaviour, because the flips are
//! consumed in a different order. A 64-bit mask that rotates one bit per
//! datagram makes the pattern a property of the seed alone: the tenth datagram
//! meets the tenth bit whether it was sent early or late, and a fix that
//! changes pacing does not silently change which packets were dropped. That is
//! picoquic's reason and it is the one that matters for a regression suite.
//!
//! Loss is applied before the queue, because a packet dropped by the medium
//! never occupied the bottleneck.

const std = @import("std");

const assert = std.debug.assert;

const Link = @This();

/// Datagrams held in flight on one direction at once. A link that fills this is
/// a bottleneck the simulation is not modelling, so it is a bug rather than a
/// tail drop — the token bucket below is where deliberate drops happen.
pub const in_flight_max: u32 = 256;

/// The largest datagram this package can produce, which is what sizes the
/// storage. `Connection.datagram_octets` is the comptime bound and the link
/// never carries more.
pub const datagram_octets_max: u32 = 1500;

pub const Config = struct {
    /// One-way propagation delay.
    delay_ns: u64 = 15 * std.time.ns_per_ms,
    /// Added to the delay per datagram, drawn from the seed. Reordering falls
    /// out of this rather than being a separate switch: a datagram whose jitter
    /// exceeds the gap to the next one arrives second.
    jitter_ns: u64 = 0,
    /// One bit per datagram, rotating. A set bit drops.
    loss_mask: u64 = 0,
    /// Datagrams larger than this are dropped rather than fragmented, which is
    /// what a path MTU below the sender's assumption looks like from here.
    mtu: u32 = datagram_octets_max,
    /// Token bucket: octets per second, and the burst the queue may hold.
    /// Zero rate means an unmetered link.
    rate_octets_per_second: u64 = 0,
    queue_octets_max: u32 = 64 * 1024,
    /// One in `duplicate_period` datagrams is delivered twice. Zero disables.
    duplicate_period: u32 = 0,
};

const InFlight = struct {
    at_ns: u64,
    octets: u32,
    storage: [datagram_octets_max]u8,
};

/// Counters. A simulation whose loss counter never moves ran a clean path and
/// proved less than it looks like it proved, which is what the coverage census
/// in `main.zig` exists to catch.
pub const Counters = struct {
    queued: u64 = 0,
    delivered: u64 = 0,
    dropped_loss: u64 = 0,
    dropped_mtu: u64 = 0,
    dropped_queue: u64 = 0,
    duplicated: u64 = 0,
    reordered: u64 = 0,
};

config: Config,
/// Rotating, so the pattern belongs to the seed rather than to the ordering.
mask: u64,
in_flight: [in_flight_max]InFlight = undefined,
count: u32 = 0,
/// When the token bucket next frees up, so a burst queues rather than
/// overtaking.
busy_until_ns: u64 = 0,
sequence: u64 = 0,

counters: Counters = .{},

pub fn init(config: Config) Link {
    return .{ .config = config, .mask = config.loss_mask };
}

/// Offer a datagram to the link at `now_ns`. Returns nothing: a link that
/// refuses is indistinguishable from a link that drops, and the caller has no
/// decision to make either way.
pub fn send(link: *Link, datagram: []const u8, now_ns: u64, random: std.Random) void {
    assert(datagram.len <= datagram_octets_max);
    link.counters.queued += 1;
    link.sequence += 1;

    // The medium first: a datagram too large for the path never reaches the
    // bottleneck queue, and neither does one the mask drops.
    if (datagram.len > link.config.mtu) {
        link.counters.dropped_mtu += 1;
        return;
    }
    const lost = link.mask & 1 == 1;
    link.mask = (link.mask >> 1) | (@as(u64, @intFromBool(lost)) << 63);
    if (lost) {
        link.counters.dropped_loss += 1;
        return;
    }

    // Then the queue. A token bucket with tail drop: the datagram leaves when
    // the link has finished the ones ahead of it, and is dropped outright if
    // that backlog is already past the buffer.
    var departs_ns = now_ns;
    if (link.config.rate_octets_per_second > 0) {
        const backlog_ns = if (link.busy_until_ns > now_ns) link.busy_until_ns - now_ns else 0;
        const backlog_octets = (backlog_ns * link.config.rate_octets_per_second) / std.time.ns_per_s;
        if (backlog_octets > link.config.queue_octets_max) {
            link.counters.dropped_queue += 1;
            return;
        }
        departs_ns = @max(now_ns, link.busy_until_ns);
        const service_ns = (@as(u64, datagram.len) * std.time.ns_per_s) / link.config.rate_octets_per_second;
        link.busy_until_ns = departs_ns + service_ns;
    }

    const jitter = if (link.config.jitter_ns == 0) 0 else random.uintLessThan(u64, link.config.jitter_ns);
    const at_ns = departs_ns + link.config.delay_ns + jitter;

    link.push(datagram, at_ns);
    if (link.config.duplicate_period > 0 and link.sequence % link.config.duplicate_period == 0) {
        link.counters.duplicated += 1;
        link.push(datagram, at_ns + jitter / 2 + 1);
    }
}

fn push(link: *Link, datagram: []const u8, at_ns: u64) void {
    // Bounded, and the bound is a bug rather than a drop: see `in_flight_max`.
    assert(link.count < in_flight_max);
    // A datagram scheduled before one already queued is a reordering, counted
    // here so the census can tell a path that reordered from one that did not.
    if (link.count > 0 and at_ns < link.in_flight[link.count - 1].at_ns) {
        link.counters.reordered += 1;
    }
    var slot = &link.in_flight[link.count];
    slot.at_ns = at_ns;
    slot.octets = @intCast(datagram.len);
    @memcpy(slot.storage[0..datagram.len], datagram);
    link.count += 1;
}

/// When the next datagram is due, or null when the link is empty.
pub fn nextAt(link: *const Link) ?u64 {
    var earliest: ?u64 = null;
    for (link.in_flight[0..link.count]) |one| {
        if (earliest == null or one.at_ns < earliest.?) earliest = one.at_ns;
    }
    return earliest;
}

/// Take the datagram due at or before `now_ns`, earliest first. Null when none
/// is due, which is the caller's cue to advance the clock.
pub fn receive(link: *Link, now_ns: u64, target: []u8) ?[]u8 {
    var chosen: ?u32 = null;
    for (link.in_flight[0..link.count], 0..) |one, index| {
        if (one.at_ns > now_ns) continue;
        if (chosen == null or one.at_ns < link.in_flight[chosen.?].at_ns) chosen = @intCast(index);
    }
    const index = chosen orelse return null;
    const one = &link.in_flight[index];
    assert(one.octets <= target.len);
    @memcpy(target[0..one.octets], one.storage[0..one.octets]);
    const octets = one.octets;

    // Compact rather than shift: order in the array is not the order on the
    // wire, which `at_ns` already decides.
    link.in_flight[index] = link.in_flight[link.count - 1];
    link.count -= 1;
    link.counters.delivered += 1;
    return target[0..octets];
}

pub fn idle(link: *const Link) bool {
    return link.count == 0;
}

const testing = std.testing;

test "a clean link delivers exactly what it was given, once, after the delay" {
    var prng: std.Random.DefaultPrng = .init(1);
    var link: Link = .init(.{ .delay_ns = 10, .loss_mask = 0 });
    link.send("hello", 0, prng.random());

    var target: [datagram_octets_max]u8 = undefined;
    // Not yet: the delay has not elapsed.
    try testing.expect(link.receive(9, &target) == null);
    const got = link.receive(10, &target).?;
    try testing.expectEqualStrings("hello", got);
    try testing.expect(link.receive(1000, &target) == null);
    try testing.expect(link.idle());
}

test "the loss mask rotates, so the pattern belongs to the seed" {
    var prng: std.Random.DefaultPrng = .init(1);
    // Every other datagram, starting with the first.
    var link: Link = .init(.{ .delay_ns = 0, .loss_mask = 0b0101_0101 });
    for (0..8) |_| link.send("x", 0, prng.random());
    try testing.expectEqual(@as(u64, 4), link.counters.dropped_loss);
    try testing.expectEqual(@as(u32, 4), link.count);

    // And the mask is back where it started after 64 datagrams, which is what
    // makes it a schedule rather than a coin.
    var again: Link = .init(.{ .delay_ns = 0, .loss_mask = 0b0101_0101 });
    for (0..64) |_| again.send("x", 0, prng.random());
    try testing.expectEqual(@as(u64, 0b0101_0101), again.mask);
}

test "a datagram past the path MTU is dropped rather than fragmented" {
    var prng: std.Random.DefaultPrng = .init(1);
    var link: Link = .init(.{ .mtu = 8 });
    link.send("123456789", 0, prng.random());
    try testing.expectEqual(@as(u64, 1), link.counters.dropped_mtu);
    try testing.expect(link.idle());
    link.send("1234", 0, prng.random());
    try testing.expectEqual(@as(u32, 1), link.count);
}

test "the queue drops at its tail rather than growing without bound" {
    var prng: std.Random.DefaultPrng = .init(1);
    // A slow link with a small buffer: the first few queue, the rest are lost.
    var link: Link = .init(.{
        .delay_ns = 0,
        .rate_octets_per_second = 1000,
        .queue_octets_max = 200,
    });
    for (0..40) |_| link.send(&[_]u8{0} ** 100, 0, prng.random());
    try testing.expect(link.counters.dropped_queue > 0);
    try testing.expect(link.count > 0);
    try testing.expectEqual(
        @as(u64, 40),
        link.counters.queued,
    );
    try testing.expectEqual(
        link.counters.queued - link.counters.dropped_queue,
        @as(u64, link.count),
    );
}

test "jitter reorders, and the reordering is counted" {
    var prng: std.Random.DefaultPrng = .init(7);
    var link: Link = .init(.{ .delay_ns = 1000, .jitter_ns = 5000 });
    for (0..32) |_| link.send("x", 0, prng.random());
    // With jitter far above zero and every datagram sent at the same instant,
    // some pair must have come out of order.
    try testing.expect(link.counters.reordered > 0);
}

test "a duplicated datagram arrives twice" {
    var prng: std.Random.DefaultPrng = .init(1);
    var link: Link = .init(.{ .delay_ns = 0, .duplicate_period = 1 });
    link.send("x", 0, prng.random());
    try testing.expectEqual(@as(u64, 1), link.counters.duplicated);
    var target: [datagram_octets_max]u8 = undefined;
    try testing.expect(link.receive(10, &target) != null);
    try testing.expect(link.receive(10, &target) != null);
    try testing.expect(link.receive(10, &target) == null);
}

test "nextAt names the earliest datagram, which is what advances the clock" {
    var link: Link = .init(.{ .delay_ns = 0 });
    try testing.expect(link.nextAt() == null);
    link.push("a", 500);
    link.push("b", 100);
    link.push("c", 900);
    try testing.expectEqual(@as(?u64, 100), link.nextAt());
    var target: [datagram_octets_max]u8 = undefined;
    try testing.expectEqualStrings("b", link.receive(100, &target).?);
    try testing.expectEqual(@as(?u64, 500), link.nextAt());
}
