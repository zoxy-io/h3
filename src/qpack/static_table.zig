//! RFC 9204 appendix A: the QPACK static table.
//!
//! Ninety-nine entries, indexed from **zero** — which is the first thing to get
//! wrong, because HPACK's static table is indexed from one and the two tables
//! are otherwise similar enough to invite the confusion. Entry 0 here is
//! `:authority`; entry 1 in HPACK is `:authority` too. A decoder that carried
//! HPACK's off-by-one into QPACK would resolve every index to its neighbour and
//! produce well-formed nonsense.
//!
//! The contents are a different table from HPACK's as well, not a superset: it
//! was rebuilt from a corpus of real traffic, so it carries `:status 103`,
//! `access-control-allow-origin: *` and fifty entries HPACK has no room for,
//! and it drops some HPACK has.
//!
//! ## Why the table is data and the lookup is a linear scan
//!
//! Ninety-nine string comparisons is not free, and an encoder does one per
//! field. It is nonetheless what this slice ships, because the alternative —
//! h2's approach of comparing eight name hashes at a time — is worth doing
//! against a benchmark rather than in advance, and the table has to exist
//! before there is anything to benchmark. `zig build bench` is where that
//! decision gets made; see docs/DESIGN.md.

const std = @import("std");

const assert = @import("../assert.zig").assert;

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// Appendix A, transcribed in order. The index of an entry *is* its position
/// here, so nothing may be inserted or reordered.
pub const entries = [_]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

/// The number of entries. An index at or above this is a decoding error of
/// type `QPACK_DECOMPRESSION_FAILED`.
pub const count: u64 = entries.len;

comptime {
    // Appendix A's own count, checked against the transcription. A table one
    // entry short would shift every index past the gap and decode to a
    // neighbour, which is the failure this proof exists to prevent.
    assert(count == 99);
    // Index 0 is `:authority`, which is where QPACK and HPACK visibly differ:
    // HPACK's entry *1* is `:authority` and its entry 0 does not exist.
    assert(std.mem.eql(u8, entries[0].name, ":authority"));
    assert(std.mem.eql(u8, entries[count - 1].name, "x-frame-options"));
    // Every name is lowercase: RFC 9114 section 4.2 forbids uppercase in a
    // field name, and a static entry that broke that rule would be an
    // unrejectable violation.
    // Ninety-nine names of a dozen octets each is a few thousand comparisons,
    // which is over the default budget for a proof that costs the build nothing.
    @setEvalBranchQuota(10_000);
    for (entries) |entry| {
        assert(entry.name.len >= 1);
        for (entry.name) |octet| assert(octet < 'A' or octet > 'Z');
    }
}

pub const Error = error{
    /// An index at or above `count`. `QPACK_DECOMPRESSION_FAILED`.
    IndexOutOfRange,
};

/// The entry at `index`.
pub fn get(index: u64) Error!Entry {
    if (index >= count) return error.IndexOutOfRange;
    return entries[@intCast(index)];
}

/// What a lookup found: an entry matching both name and value, or the first
/// entry matching the name alone.
pub const Match = struct {
    index: u64,
    /// True when the entry's value matches too, which is what decides between a
    /// fully-indexed representation and a literal with an indexed name.
    value_matched: bool,
};

/// Find the best static entry for a field.
///
/// Returns the first exact match if there is one, otherwise the first
/// name-only match, otherwise null. "First" is what makes the answer
/// deterministic across encoders, which matters for a test that compares wire
/// bytes.
pub fn lookup(name: []const u8, value: []const u8) ?Match {
    var name_only: ?u64 = null;
    for (entries, 0..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (std.mem.eql(u8, entry.value, value)) {
            return .{ .index = index, .value_matched = true };
        }
        if (name_only == null) name_only = index;
    }
    if (name_only) |index| return .{ .index = index, .value_matched = false };
    return null;
}

const testing = std.testing;

test "the table is indexed from zero, unlike HPACK's" {
    const first = try get(0);
    try testing.expectEqualStrings(":authority", first.name);
    try testing.expectEqualStrings("", first.value);
    // The entry HPACK numbers 1 and QPACK numbers 0. A stack that carried
    // HPACK's offset would resolve every index to its neighbour.
    const path = try get(1);
    try testing.expectEqualStrings(":path", path.name);
    try testing.expectEqualStrings("/", path.value);
}

test "the spot checks appendix A is easiest to mistranscribe around" {
    try testing.expectEqualStrings("GET", (try get(17)).value);
    try testing.expectEqualStrings(":scheme", (try get(23)).name);
    try testing.expectEqualStrings("https", (try get(23)).value);
    try testing.expectEqualStrings("200", (try get(25)).value);
    try testing.expectEqualStrings("*", (try get(35)).value);
    try testing.expectEqualStrings("access-control-allow-origin", (try get(35)).name);
    // The boundary between the two blocks the table was assembled from.
    try testing.expectEqualStrings("x-xss-protection", (try get(62)).name);
    try testing.expectEqualStrings(":status", (try get(63)).name);
    try testing.expectEqualStrings("100", (try get(63)).value);
    try testing.expectEqualStrings("sameorigin", (try get(98)).value);
}

test "an index past the table is a decompression failure" {
    try testing.expectError(error.IndexOutOfRange, get(count));
    try testing.expectError(error.IndexOutOfRange, get(std.math.maxInt(u64)));
}

test "lookup prefers an exact match and falls back to the name" {
    const exact = lookup(":method", "GET").?;
    try testing.expectEqual(@as(u64, 17), exact.index);
    try testing.expect(exact.value_matched);

    // A method the table has no value for still gets its name indexed, at the
    // first `:method` entry.
    const name_only = lookup(":method", "PATCH").?;
    try testing.expectEqual(@as(u64, 15), name_only.index);
    try testing.expect(!name_only.value_matched);

    try testing.expectEqual(@as(?Match, null), lookup("x-not-in-the-table", ""));
}

test "every entry finds itself" {
    // The property that makes `lookup` and `get` two views of one table: for
    // every entry, looking up its own name and value must find an entry with
    // the same content — not necessarily the same index, because the table has
    // duplicates like `accept-language` with an empty value.
    for (entries, 0..) |entry, index| {
        const found = lookup(entry.name, entry.value).?;
        try testing.expect(found.value_matched);
        const resolved = try get(found.index);
        try testing.expectEqualStrings(entry.name, resolved.name);
        try testing.expectEqualStrings(entry.value, resolved.value);
        try testing.expect(found.index <= index);
    }
}
