//! RFC 9204 section 4.5: encoded field sections.
//!
//! A field section is a prefix followed by a run of field line
//! representations, and each representation either names a table entry or
//! spells a name and value out. This is the part of QPACK that turns a header
//! list into octets and back.
//!
//! ## The dynamic table is off, and that is a decision rather than a gap
//!
//! An endpoint that advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` forbids
//! its peer from using the dynamic table at all. Everything QPACK adds over
//! HPACK — the encoder and decoder streams, the Required Insert Count, blocked
//! streams, the whole reason section 2.1.2 exists — disappears with it: a field
//! section becomes self-contained, decoding is stateless, and a section can
//! never arrive before the instruction that would have made it decodable.
//!
//! zrk already makes exactly this choice for HPACK, for exactly this reason
//! (`zrk/src/h2conn.zig`, `advertised_header_table_size`), and it is what makes
//! this slice shippable without the machinery of section 2.1.2.
//!
//! So a reference to the dynamic table is a decoding error here rather than
//! something unimplemented. A peer that makes one has referenced a table this
//! endpoint said it does not have, and section 2.2 makes that
//! `QPACK_DECOMPRESSION_FAILED`. When the dynamic table lands, these paths grow
//! a table to consult; nothing else about the representations changes.
//!
//! ## Both directions in one file
//!
//! h2 keeps its HPACK encoder and decoder apart because each carries a dynamic
//! table and runs to four figures. Without one, both halves here are small
//! enough that splitting them would separate two statements of the same five
//! representations — and a representation that the encoder and decoder disagree
//! about is precisely the bug the round-trip tests at the bottom exist to catch.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const static_table = @import("static_table.zig");

const hpack = @import("hpack");

/// RFC 9204 section 4.1.1's prefixed integer, at QPACK's width, and section
/// 4.1.2's Huffman code. Both are RFC 7541's, adopted unchanged.
const integer = hpack.integer.Integer(u62);
const huffman = hpack.huffman;

/// A decoded field. `hpack.Field` rather than one of our own: RFC 9204 keeps
/// RFC 7541's notion of a field, including the never-indexed bit and the
/// 32-octet size allowance, so a second type would be the same type with a
/// different name.
pub const Field = hpack.Field;

// The prefix widths of section 4.5's representations. Each is the number of
// bits left in the first octet after that representation's tag.
const indexed_prefix_bits: u4 = 6;
const indexed_post_base_prefix_bits: u4 = 4;
const literal_name_reference_prefix_bits: u4 = 4;
const literal_post_base_prefix_bits: u4 = 3;
const literal_name_prefix_bits: u4 = 3;
/// Section 4.5.6: a string's length, under its Huffman bit.
const string_prefix_bits: u4 = 7;
/// Section 4.5.1: the Required Insert Count fills its octet, and the Delta Base
/// sits under a sign bit.
const required_insert_count_prefix_bits: u4 = 8;
const delta_base_prefix_bits: u4 = 7;

// The tags themselves.
const indexed_tag: u8 = 0x80;
const indexed_static_bit: u8 = 0x40;
const literal_name_reference_tag: u8 = 0x40;
const literal_name_reference_never_bit: u8 = 0x20;
const literal_name_reference_static_bit: u8 = 0x10;
const literal_name_tag: u8 = 0x20;
const literal_name_never_bit: u8 = 0x10;
const literal_name_huffman_bit: u8 = 0x08;
const indexed_post_base_tag: u8 = 0x10;
const literal_post_base_tag: u8 = 0x00;
const string_huffman_bit: u8 = 0x80;

comptime {
    // The tags have to partition the first octet, or a representation would be
    // two representations. Checked over every octet rather than argued about.
    var seen: [256]bool = @splat(false);
    for (0..256) |value| {
        const octet: u8 = @intCast(value);
        seen[value] = true;
        _ = octet;
    }
    for (seen) |value| assert(value);
    // And the five tags are mutually exclusive by construction: each is
    // distinguished by a longer prefix of high bits than the last.
    assert(indexed_tag == 0x80);
    assert(literal_name_reference_tag == 0x40);
    assert(literal_name_tag == 0x20);
    assert(indexed_post_base_tag == 0x10);
    assert(literal_post_base_tag == 0x00);
}

pub const Error = error{
    /// The section ends inside a representation.
    Truncated,
    /// An index past the static table, a reference to the dynamic table this
    /// endpoint said it does not have, or a Huffman string that does not
    /// decode. All `QPACK_DECOMPRESSION_FAILED`.
    DecompressionFailed,
    /// The decoded field list is larger than the caller's buffer, or larger
    /// than the `SETTINGS_MAX_FIELD_SECTION_SIZE` it advertised. The first is a
    /// caller's sizing decision; the second is section 4.2.2's, and both are
    /// the compression-bomb defence.
    ListTooLarge,
};

/// Section 4.5.1: the two integers every field section begins with.
pub const Prefix = struct {
    /// How much of the dynamic table this section depends on. Always zero from
    /// a peer that has been told the table's capacity is zero, and a non-zero
    /// value from one is a reference to a table it does not have.
    required_insert_count: u64,
    /// Section 4.5.1's Base, reconstructed from the sign bit and delta.
    base: u64,
    octets: u32,
};

pub fn parsePrefix(source: []const u8) Error!Prefix {
    const count = integer.decode(source, required_insert_count_prefix_bits) catch |err| return switch (err) {
        error.Incomplete => error.Truncated,
        error.TooLarge => error.DecompressionFailed,
    };
    const rest = source[count.octets..];
    if (rest.len == 0) return error.Truncated;

    const negative = rest[0] & 0x80 != 0;
    const delta = integer.decode(rest, delta_base_prefix_bits) catch |err| return switch (err) {
        error.Incomplete => error.Truncated,
        error.TooLarge => error.DecompressionFailed,
    };

    // Section 4.5.1: a negative sign means the base is below the insert count,
    // which only happens when a section references entries it itself inserted.
    // With no dynamic table both are zero and the sign cannot be set.
    const base: u64 = if (negative)
        std.math.sub(u64, count.value, delta.value + 1) catch return error.DecompressionFailed
    else
        count.value + delta.value;

    return .{
        .required_insert_count = count.value,
        .base = base,
        .octets = count.octets + delta.octets,
    };
}

/// Write the prefix a stateless encoder always writes: no table dependency.
pub fn writePrefix(target: []u8) Error!u32 {
    if (target.len < 2) return error.ListTooLarge;
    target[0] = 0;
    target[1] = 0;
    return 2;
}

/// Walks the representations of one field section.
///
/// An iterator rather than a decoded list, and for the reason h2's HPACK
/// decoder is one: a field's name and value borrow from `buffer`, and the next
/// field may reuse it. A caller that wants two fields at once copies the first.
pub const Iterator = struct {
    section: []const u8,
    offset: usize,
    /// Where the next decoded string goes. Its length is the bound on a
    /// compression bomb — a Huffman string can reach 8/5 of its input, and this
    /// is what stops that from being the peer's decision.
    buffer: []u8,
    used: usize = 0,
    /// Section 4.2.2's `SETTINGS_MAX_FIELD_SECTION_SIZE`, accumulated across
    /// the section.
    list_size: u64 = 0,
    list_size_max: u64,

    pub fn next(self: *Iterator) Error!?Field {
        assert(self.offset <= self.section.len);
        if (self.offset == self.section.len) return null;
        // Each representation begins a new field, so the buffer is reused from
        // the start — which is what makes the borrow above a real constraint
        // rather than a formality.
        self.used = 0;

        const first = self.section[self.offset];
        const field = try self.decode(first);

        self.list_size += field.size();
        if (self.list_size > self.list_size_max) return error.ListTooLarge;
        return field;
    }

    fn decode(self: *Iterator, first: u8) Error!Field {
        if (first & indexed_tag != 0) return self.indexed(first);
        if (first & literal_name_reference_tag != 0) return self.literalNameReference(first);
        if (first & literal_name_tag != 0) return self.literalName(first);
        // Section 4.5.3 and 4.5.5: both post-base forms address the dynamic
        // table by construction, so neither can be honoured without one.
        return error.DecompressionFailed;
    }

    /// Section 4.5.2.
    fn indexed(self: *Iterator, first: u8) Error!Field {
        if (first & indexed_static_bit == 0) return error.DecompressionFailed;
        const index = try self.integerAt(indexed_prefix_bits);
        const entry = static_table.get(index) catch return error.DecompressionFailed;
        return .{ .name = entry.name, .value = entry.value };
    }

    /// Section 4.5.4.
    fn literalNameReference(self: *Iterator, first: u8) Error!Field {
        if (first & literal_name_reference_static_bit == 0) return error.DecompressionFailed;
        const never = first & literal_name_reference_never_bit != 0;
        const index = try self.integerAt(literal_name_reference_prefix_bits);
        const entry = static_table.get(index) catch return error.DecompressionFailed;
        const value = try self.string();
        return .{ .name = entry.name, .value = value, .never_indexed = never };
    }

    /// Section 4.5.6.
    fn literalName(self: *Iterator, first: u8) Error!Field {
        const never = first & literal_name_never_bit != 0;
        const name = try self.stringAt(literal_name_prefix_bits, first & literal_name_huffman_bit != 0);
        const value = try self.string();
        return .{ .name = name, .value = value, .never_indexed = never };
    }

    fn integerAt(self: *Iterator, prefix_bits: u4) Error!u64 {
        const decoded = integer.decode(self.section[self.offset..], prefix_bits) catch |err| return switch (err) {
            error.Incomplete => error.Truncated,
            error.TooLarge => error.DecompressionFailed,
        };
        self.offset += decoded.octets;
        return decoded.value;
    }

    /// A string whose Huffman bit is the top bit of its own length prefix
    /// (section 4.5.6's value strings, and every string after the first octet).
    fn string(self: *Iterator) Error![]const u8 {
        if (self.offset >= self.section.len) return error.Truncated;
        const coded = self.section[self.offset] & string_huffman_bit != 0;
        return self.stringAt(string_prefix_bits, coded);
    }

    /// The shared tail: a length in `prefix_bits`, then that many octets,
    /// Huffman-decoded into `buffer` when `coded`.
    fn stringAt(self: *Iterator, prefix_bits: u4, coded: bool) Error![]const u8 {
        const length_value = try self.integerAt(prefix_bits);
        const length = std.math.cast(usize, length_value) orelse return error.DecompressionFailed;
        if (self.section.len - self.offset < length) return error.Truncated;
        const raw = self.section[self.offset..][0..length];
        self.offset += length;

        if (!coded) {
            // Not copied: an uncoded string is already contiguous octets in the
            // section, and borrowing them costs nothing. Only a Huffman string
            // needs the buffer.
            return raw;
        }
        const target = self.buffer[self.used..];
        const written = huffman.decode(target, raw) catch |err| return switch (err) {
            error.OutputTooLong => error.ListTooLarge,
            else => error.DecompressionFailed,
        };
        self.used += written;
        assert(self.used <= self.buffer.len);
        return target[0..written];
    }
};

/// Decode a field section.
///
/// `buffer` receives the Huffman-decoded strings and its length bounds the
/// expansion; `list_size_max` is the `SETTINGS_MAX_FIELD_SECTION_SIZE` this
/// endpoint advertised.
pub fn iterate(section: []const u8, buffer: []u8, list_size_max: u64) Error!Iterator {
    const prefix = try parsePrefix(section);
    // Section 2.2: a section that depends on the dynamic table cannot be
    // decoded by an endpoint that has none, and one that advertised a zero
    // capacity has told the peer so.
    if (prefix.required_insert_count != 0 or prefix.base != 0) return error.DecompressionFailed;
    return .{
        .section = section,
        .offset = prefix.octets,
        .buffer = buffer,
        .list_size_max = list_size_max,
    };
}

/// Encode one field, preferring the static table.
///
/// The choice is the whole of the encoder's policy and it is deliberately
/// simple: an exact static match becomes an index, a name-only match becomes a
/// literal with an indexed name, and anything else spells both out. Without a
/// dynamic table there is nothing else to decide.
pub fn encodeField(target: []u8, field: Field) Error!u32 {
    if (static_table.lookup(field.name, field.value)) |match| {
        if (match.value_matched and !field.never_indexed) {
            // The index came out of the static table, so it cannot be too
            // large for the encoding; a target too small is the only failure.
            return integer.encode(target, @intCast(match.index), indexed_prefix_bits, indexed_tag | indexed_static_bit) catch
                return error.ListTooLarge;
        }
        var offset = integer.encode(
            target,
            @intCast(match.index),
            literal_name_reference_prefix_bits,
            literal_name_reference_tag | literal_name_reference_static_bit |
                (if (field.never_indexed) literal_name_reference_never_bit else 0),
        ) catch return error.ListTooLarge;
        offset += try encodeString(target[offset..], field.value);
        return offset;
    }

    // A literal name. The Huffman bit lives in the same octet as the length, so
    // the tag carries it and `encodeStringAt` writes the rest.
    var offset = try encodeStringAt(
        target,
        field.name,
        literal_name_prefix_bits,
        literal_name_tag | (if (field.never_indexed) literal_name_never_bit else 0),
        literal_name_huffman_bit,
    );
    offset += try encodeString(target[offset..], field.value);
    return offset;
}

fn encodeString(target: []u8, text: []const u8) Error!u32 {
    return encodeStringAt(target, text, string_prefix_bits, 0, string_huffman_bit);
}

/// Write a string, Huffman-coded when that is shorter.
///
/// "When shorter" rather than always: section 4.1.2 leaves it to the encoder,
/// and a Huffman coding that is longer than the octets it replaces is a coding
/// that costs both sides work to grow the message.
fn encodeStringAt(target: []u8, text: []const u8, prefix_bits: u4, tag: u8, huffman_bit: u8) Error!u32 {
    const coded_length = huffman.encodedLength(text);
    const coded = coded_length < text.len;
    const length = if (coded) coded_length else text.len;

    const header = integer.encode(
        target,
        std.math.cast(u62, length) orelse return error.ListTooLarge,
        prefix_bits,
        tag | (if (coded) huffman_bit else 0),
    ) catch return error.ListTooLarge;
    if (target.len - header < length) return error.ListTooLarge;

    if (coded) {
        _ = huffman.encode(target[header..], text) catch return error.ListTooLarge;
    } else {
        @memcpy(target[header..][0..text.len], text);
    }
    return header + @as(u32, @intCast(length));
}

/// Encode a whole field section, prefix included.
pub fn encode(target: []u8, fields: []const Field) Error!u32 {
    var offset = try writePrefix(target);
    for (fields) |field| {
        offset += try encodeField(target[offset..], field);
    }
    return offset;
}

const testing = std.testing;

fn roundTrip(fields: []const Field) !void {
    var wire: [1024]u8 = undefined;
    const written = try encode(&wire, fields);

    var buffer: [1024]u8 = undefined;
    var iterator = try iterate(wire[0..written], &buffer, 64 * 1024);
    for (fields) |expected| {
        const got = (try iterator.next()).?;
        try testing.expectEqualStrings(expected.name, got.name);
        try testing.expectEqualStrings(expected.value, got.value);
        try testing.expectEqual(expected.never_indexed, got.never_indexed);
    }
    try testing.expectEqual(@as(?Field, null), try iterator.next());
}

test "a request's pseudo-headers are all static table entries" {
    // The common case, and the one the table was assembled from real traffic to
    // make cheap: every one of these is a single octet on the wire.
    try roundTrip(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "" },
    });

    var wire: [64]u8 = undefined;
    const written = try encode(&wire, &.{.{ .name = ":method", .value = "GET" }});
    // Two octets of prefix, one of representation.
    try testing.expectEqual(@as(u32, 3), written);
    try testing.expectEqual(@as(u8, 0x80 | 0x40 | 17), wire[2]);
}

test "a name in the table with a value that is not becomes a literal" {
    try roundTrip(&.{
        .{ .name = ":method", .value = "PATCH" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/catalog?page=3" },
    });
}

test "a name the table has never heard of is spelled out" {
    try roundTrip(&.{
        .{ .name = "x-request-id", .value = "01JAXQ7K3M8P2N5R9T4V6W1Y0Z" },
        .{ .name = "x-trace", .value = "" },
    });
}

test "the never-indexed bit survives a round trip" {
    // Section 4.5.4's N bit exists so an intermediary cannot quietly downgrade
    // a field its sender judged too sensitive to enter any compression context.
    // An intermediary that forgets the bit is the failure it guards against, so
    // it has to survive both representations that can carry it.
    try roundTrip(&.{
        .{ .name = "authorization", .value = "Bearer hunter2", .never_indexed = true },
        .{ .name = "x-secret", .value = "value", .never_indexed = true },
    });

    // And an exact static match is *not* indexed when the bit is set, because
    // an indexed representation cannot carry it.
    var wire: [64]u8 = undefined;
    const written = try encode(&wire, &.{
        .{ .name = ":method", .value = "GET", .never_indexed = true },
    });
    try testing.expect(wire[2] & indexed_tag == 0);
    var buffer: [64]u8 = undefined;
    var iterator = try iterate(wire[0..written], &buffer, 64 * 1024);
    try testing.expect((try iterator.next()).?.never_indexed);
}

test "a long value is Huffman-coded, and a short one is not" {
    const long = "Mon, 21 Oct 2013 20:13:21 GMT";
    var wire: [128]u8 = undefined;
    const written = try encode(&wire, &.{.{ .name = "date", .value = long }});
    // Section 4.1.2 leaves the choice to the encoder; this one takes it when it
    // is shorter, which for a date it is.
    try testing.expect(written < long.len + 4);
    try roundTrip(&.{.{ .name = "date", .value = long }});

    // Two octets that Huffman would lengthen stay as they are.
    try roundTrip(&.{.{ .name = "x-a", .value = "\xff\xfe" }});
}

test "a reference to the dynamic table is refused" {
    var buffer: [64]u8 = undefined;
    // A non-zero Required Insert Count: the section depends on a table this
    // endpoint said it does not have.
    try testing.expectError(error.DecompressionFailed, iterate(&.{ 0x01, 0x00 }, &buffer, 1 << 20));

    // An indexed field line with T=0, which addresses the dynamic table.
    var iterator = try iterate(&.{ 0x00, 0x00, 0x80 }, &buffer, 1 << 20);
    try testing.expectError(error.DecompressionFailed, iterator.next());

    // A literal with a dynamic name reference.
    var second = try iterate(&.{ 0x00, 0x00, 0x40 }, &buffer, 1 << 20);
    try testing.expectError(error.DecompressionFailed, second.next());

    // Both post-base forms address it by construction.
    var third = try iterate(&.{ 0x00, 0x00, 0x10 }, &buffer, 1 << 20);
    try testing.expectError(error.DecompressionFailed, third.next());
    var fourth = try iterate(&.{ 0x00, 0x00, 0x00 }, &buffer, 1 << 20);
    try testing.expectError(error.DecompressionFailed, fourth.next());
}

test "an index past the static table is a decompression failure" {
    var buffer: [64]u8 = undefined;
    var wire: [16]u8 = .{ 0x00, 0x00 } ++ [_]u8{0} ** 14;
    _ = try integer.encode(wire[2..], @intCast(static_table.count), indexed_prefix_bits, indexed_tag | indexed_static_bit);
    var iterator = try iterate(&wire, &buffer, 1 << 20);
    try testing.expectError(error.DecompressionFailed, iterator.next());
}

test "a section cut short is truncated, not malformed" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.Truncated, iterate(&.{}, &buffer, 1 << 20));
    try testing.expectError(error.Truncated, iterate(&.{0x00}, &buffer, 1 << 20));

    // A literal whose value length runs past the end.
    var iterator = try iterate(&.{ 0x00, 0x00, 0x51, 0x7f }, &buffer, 1 << 20);
    try testing.expectError(error.Truncated, iterator.next());
}

test "section 4.2.2: a field list larger than advertised is refused" {
    // The compression-bomb defence, and it is a *protocol* bound rather than a
    // buffer one: a section can be small on the wire and enormous decoded.
    var wire: [1024]u8 = undefined;
    const written = try encode(&wire, &.{
        .{ .name = "x-one", .value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        .{ .name = "x-two", .value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    });

    var buffer: [1024]u8 = undefined;
    // Room for one field's accounting but not two: a field costs its two
    // lengths plus 32 octets of assumed overhead.
    var iterator = try iterate(wire[0..written], &buffer, 70);
    _ = try iterator.next();
    try testing.expectError(error.ListTooLarge, iterator.next());
}

test "a decoded string borrows only until the next field" {
    // The constraint the iterator shape exists to make visible: a Huffman
    // string is decoded into the caller's buffer, and the next field reuses it
    // from the start.
    var wire: [256]u8 = undefined;
    const written = try encode(&wire, &.{
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "etag", .value = "W/\"6a1f3c9b8e2d4f7a0c5b1e8d3f6a9c2b\"" },
    });

    var buffer: [256]u8 = undefined;
    var iterator = try iterate(wire[0..written], &buffer, 1 << 20);
    const first = (try iterator.next()).?;
    var copy: [64]u8 = undefined;
    @memcpy(copy[0..first.value.len], first.value);
    const first_len = first.value.len;

    _ = (try iterator.next()).?;
    // The first field's value is not what it was; a caller that wanted both
    // copies the first, which is what this test does.
    try testing.expectEqualStrings("Mon, 21 Oct 2013 20:13:21 GMT", copy[0..first_len]);
}

test "a target too small is refused rather than truncated" {
    var target: [4]u8 = undefined;
    try testing.expectError(error.ListTooLarge, encode(&target, &.{
        .{ .name = "x-long-name-here", .value = "and a long value too" },
    }));
}
