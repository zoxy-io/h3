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
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.1.1
//# QPACK implementations MUST be able to decode integers up to and
//# including 62 bits long.
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
const string_huffman_bit: u8 = 0x80;

/// Section 4.5.1's field section prefix: a Required Insert Count and a Delta
/// Base. A stateless encoder writes zero for both, and zero encodes in one
/// octet at either prefix width, so the prefix this package writes is always
/// exactly this long. It was a bare `2` at the one call site.
const prefix_octets: u32 = 2;

comptime {
    // Two varints, each at their narrowest.
    assert(prefix_octets == 1 + 1);
}

/// Which representation a first octet belongs to, by section 4.5's tags.
///
/// The single source of truth for the dispatch: `Iterator.decode` walks these
/// arms in order, and the comptime block below proves the arms partition the
/// octet. Two copies of this decision — one to dispatch on and one to prove —
/// would be one copy that can go stale.
const Representation = enum {
    indexed,
    literal_name_reference,
    literal_name,
    indexed_post_base,
    literal_post_base,

    fn of(first: u8) Representation {
        if (first & indexed_tag != 0) return .indexed;
        if (first & literal_name_reference_tag != 0) return .literal_name_reference;
        if (first & literal_name_tag != 0) return .literal_name;
        if (first & indexed_post_base_tag != 0) return .indexed_post_base;
        return .literal_post_base;
    }
};

comptime {
    // The tags must partition the first octet, or a representation would be
    // two representations. Walked over all 256 rather than argued about, and
    // each octet is checked against the tag constants *independently* of the
    // dispatch that classified it — so the two have to agree, which is what
    // makes this a proof rather than a restatement.
    @setEvalBranchQuota(20_000);
    var counts = [_]u32{0} ** 5;
    for (0..256) |value| {
        const first: u8 = @intCast(value);
        const which = Representation.of(first);
        counts[@intFromEnum(which)] += 1;

        // The independent statement of each arm: exactly the octets with this
        // prefix of high bits and no higher one.
        const expected: Representation = if (first >= 0x80)
            .indexed
        else if (first >= 0x40)
            .literal_name_reference
        else if (first >= 0x20)
            .literal_name
        else if (first >= 0x10)
            .indexed_post_base
        else
            .literal_post_base;
        assert(which == expected);
    }
    // And the section's own arithmetic: each tag claims half of what the one
    // above it left, down to the last two which split the final sixteen.
    assert(counts[0] == 128); // 0x80..0xff
    assert(counts[1] == 64); //  0x40..0x7f
    assert(counts[2] == 32); //  0x20..0x3f
    assert(counts[3] == 16); //  0x10..0x1f
    assert(counts[4] == 16); //  0x00..0x0f
    assert(counts[0] + counts[1] + counts[2] + counts[3] + counts[4] == 256);
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
    ///
    /// Decoding only. This error used to cover the encoder's "your target is
    /// too small" as well, which put a remote peer's compression bomb and a
    /// local caller's undersized buffer behind one name — two different
    /// parties, two different fixes, and a consumer logging one could not tell
    /// which had happened.
    ListTooLarge,
    /// The caller's `target` cannot hold the encoding. Encoding only, and never
    /// the peer's doing: the fix is a bigger buffer.
    OutputTooSmall,
};

/// Section 4.5.1: the two integers every field section begins with.
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
//# When the decoder receives an encoded field section with a Required
//# Insert Count greater than its own Insert Count, the stream cannot be
//# processed immediately and is considered "blocked"; see Section 2.2.1.
//# The decoder specifies an upper bound on the number of streams that
//# can be blocked using the SETTINGS_QPACK_BLOCKED_STREAMS setting; see
//# Section 5.  An encoder MUST limit the number of streams that could
//# become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all
//# times.  If a decoder encounters more blocked streams than it promised
//# to support, it MUST treat this as a connection error of type
//# QPACK_DECOMPRESSION_FAILED.
//= type=exception
//= reason=blocked streams exist only where a field section may reference the dynamic table; this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, so a section is self-contained and no stream can block, per docs/DESIGN.md section 6
//= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.2
//# The
//# encoder MUST NOT cause a dynamic table entry to be evicted unless
//# that entry is evictable; see Section 2.1.1.  The new entry is then
//# added to the table.  It is an error if the encoder attempts to add an
//# entry that is larger than the dynamic table capacity; the decoder
//# MUST treat this as a connection error of type
//# QPACK_ENCODER_STREAM_ERROR.
//= type=exception
//= reason=eviction is the dynamic table's, which docs/DESIGN.md section 6 lists as next rather than built; with a capacity of zero there is no entry to evict
//= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
//# The encoder MUST NOT set a dynamic table capacity that exceeds this
//# maximum, but it can choose to use a lower dynamic table capacity; see
//# Section 4.3.1.
//= type=exception
//= reason=setting a dynamic table capacity belongs to the encoder stream, which is not built (docs/DESIGN.md section 6); this package sends no encoder instructions at all
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.1
//# If it encounters a Required Insert
//# Count smaller than expected, it MUST treat this as a connection error
//# of type QPACK_DECOMPRESSION_FAILED; see Section 2.2.3.
//= type=exception
//= reason=comparing a Required Insert Count against the expected one needs the decoder's own Insert Count, which is dynamic table state this package does not keep (docs/DESIGN.md section 6); any non-zero count is refused instead
pub const Prefix = struct {
    /// How much of the dynamic table this section depends on. Always zero from
    /// a peer that has been told the table's capacity is zero, and a non-zero
    /// value from one is a reference to a table it does not have.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
    //# If the decoder encounters a reference in a field line representation
    //# to a dynamic table entry that has already been evicted or that has an
    //# absolute index greater than or equal to the declared Required Insert
    //# Count (Section 4.5.1), it MUST treat this as a connection error of
    //# type QPACK_DECOMPRESSION_FAILED.
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

    // Widened before any arithmetic, and the annotations are load-bearing.
    // `Decoded.value` is a `u62` at this width, and Zig does not widen operands
    // to a declared result type — `count.value + delta.value` and
    // `delta.value + 1` both overflow inside `u62` for values a peer encodes in
    // nine octets, which is a panic in the safe builds and undefined behaviour
    // in the `-Dassertions=false` one. Both are reachable from the first
    // twenty-one octets of a field section, before any other check runs.
    const insert_count: u64 = count.value;
    const delta_base: u64 = delta.value;
    comptime {
        // Two 62-bit values and one cannot reach 64 bits, which is what makes
        // the addition below total once both are `u64`.
        assert(@bitSizeOf(@TypeOf(count.value)) <= 62);
        assert(@bitSizeOf(@TypeOf(delta.value)) <= 62);
    }

    // Section 4.5.1: a negative sign means the base is below the insert count,
    // which only happens when a section references entries it itself inserted.
    // With no dynamic table both are zero and the sign cannot be set.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.2
    //# If the encoder inserted entries in the dynamic table while
    //# encoding the field section and is referencing them, Required Insert
    //# Count will be greater than the Base, so the encoded difference is
    //# negative and the Sign bit is set to 1.  If the field section was not
    //# encoded using representations that reference the most recent entry in
    //# the table and did not insert any new entries, the Base will be
    //# greater than the Required Insert Count, so the encoded difference
    //# will be positive and the Sign bit is set to 0.
    //# The value of Base MUST NOT be negative.  Though the protocol might
    //# operate correctly with a negative Base using post-Base indexing, it
    //# is unnecessary and inefficient.  An endpoint MUST treat a field block
    //# with a Sign bit of 1 as invalid if the value of Required Insert Count
    //# is less than or equal to the value of Delta Base.
    const base: u64 = if (negative)
        std.math.sub(u64, insert_count, delta_base + 1) catch return error.DecompressionFailed
    else
        insert_count + delta_base;

    return .{
        .required_insert_count = count.value,
        .base = base,
        .octets = count.octets + delta.octets,
    };
}

/// Write the prefix a stateless encoder always writes: no table dependency.
pub fn writePrefix(target: []u8) Error!u32 {
    if (target.len < prefix_octets) return error.OutputTooSmall;
    target[0] = 0;
    target[1] = 0;
    return prefix_octets;
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
    //= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
    //# An implementation has to set a limit for the values it accepts for
    //# integers, as well as for the encoded length; see Section 4.1.1.  In
    //# the same way, it has to set a limit to the length it accepts for
    //# string literals; see Section 4.1.2.  These limits SHOULD be large
    //# enough to process the largest individual field the HTTP
    //# implementation can be configured to accept.
    buffer: []u8,
    used: usize = 0,
    /// Section 4.2.2's `SETTINGS_MAX_FIELD_SECTION_SIZE`, accumulated across
    /// the section.
    list_size: u64 = 0,
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
    //# The size of a field list is calculated based on the
    //# uncompressed size of fields, including the length of the name and
    //# value in bytes plus an overhead of 32 bytes for each field.
    list_size_max: u64,

    //= https://www.rfc-editor.org/rfc/rfc9204#section-2.2
    //# The decoder MUST emit field lines in the order their representations
    //# appear in the encoded field section.
    pub fn next(self: *Iterator) Error!?Field {
        // `>=` rather than `==`: with assertions compiled out the equality test
        // does not catch an offset past the end, and the read below is then out
        // of bounds. The assertion states the invariant; the comparison is what
        // holds when it is gone.
        assert(self.offset <= self.section.len);
        if (self.offset >= self.section.len) return null;
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
        return switch (Representation.of(first)) {
            .indexed => self.indexed(first),
            .literal_name_reference => self.literalNameReference(first),
            .literal_name => self.literalName(first),
            // Sections 4.5.3 and 4.5.5: both post-base forms address the
            // dynamic table by construction, so neither can be honoured
            // without one.
            //= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
            //# If the decoder encounters a reference in a field line representation
            //# to a dynamic table entry that has already been evicted or that has an
            //# absolute index greater than or equal to the declared Required Insert
            //# Count (Section 4.5.1), it MUST treat this as a connection error of
            //# type QPACK_DECOMPRESSION_FAILED.
            .indexed_post_base, .literal_post_base => error.DecompressionFailed,
        };
    }

    /// Section 4.5.2.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-3.1
    //# When the decoder encounters an invalid static table index in a field
    //# line representation, it MUST treat this as a connection error of type
    //# QPACK_DECOMPRESSION_FAILED.
    fn indexed(self: *Iterator, first: u8) Error!Field {
        if (first & indexed_static_bit == 0) return error.DecompressionFailed;
        const index = try self.integerAt(indexed_prefix_bits);
        const entry = static_table.get(index) catch return error.DecompressionFailed;
        return .{ .name = entry.name, .value = entry.value };
    }

    /// Section 4.5.4.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.4
    //# When
    //# the 'N' bit is set, the encoded field line MUST always be encoded
    //# with a literal representation.  In particular, when a peer sends a
    //# field line that it received represented as a literal field line with
    //# the 'N' bit set, it MUST use a literal representation to forward this
    //# field line.
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

    //= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
    //# If an implementation encounters a value larger than it is able to
    //# decode, this MUST be treated as a stream error of type
    //# QPACK_DECOMPRESSION_FAILED if on a request stream or a connection
    //# error of the appropriate type if on the encoder or decoder stream.
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
        // Written against the remaining slice rather than as a subtraction: if
        // `offset` were ever past the end, `len - offset` wraps to a huge
        // number, the check passes, and the slice below reads out of bounds.
        if (self.section[self.offset..].len < length) return error.Truncated;
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
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.1
//# If the decoder encounters a value
//# of EncodedInsertCount that could not have been produced by a
//# conformant encoder, it MUST treat this as a connection error of type
//# QPACK_DECOMPRESSION_FAILED.
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.2.1
//# After the decoder finishes decoding a field section encoded using
//# representations containing dynamic table references, it MUST emit a
//# Section Acknowledgment instruction (Section 4.4.1).
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; iterate refuses any section whose Required Insert Count is non-zero, so no section decoded here contains a dynamic table reference to acknowledge
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
//# If the decoder encounters a reference in an encoder instruction to a
//# dynamic table entry that has already been evicted, it MUST treat this
//# as a connection error of type QPACK_ENCODER_STREAM_ERROR.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; there is no encoder stream to read an instruction from, and the field-line half of this rule is cited on Prefix.required_insert_count
//= https://www.rfc-editor.org/rfc/rfc9204#section-3.2
//# The dynamic table can contain duplicate entries (i.e., entries with
//# the same name and same value).  Therefore, duplicate entries MUST NOT
//# be treated as an error by the decoder.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; the static table's own duplicates are handled by static_table.lookup, which returns the first matching entry rather than treating a repeat as anything
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.1
//# If an encoder receives a Section Acknowledgment instruction referring
//# to a stream on which every encoded field section with a non-zero
//# Required Insert Count has already been acknowledged, this MUST be
//# treated as a connection error of type QPACK_DECODER_STREAM_ERROR.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; the decoder stream that carries a Section Acknowledgment is not built, so this encoder receives none
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.3
//# An encoder that receives an Increment field equal to zero, or one
//# that increases the Known Received Count beyond what the encoder has
//# sent, MUST treat this as a connection error of type
//# QPACK_DECODER_STREAM_ERROR.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; the Known Received Count exists only to track dynamic table insertions, and this encoder makes none
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
//# An implementation that
//# has received this parameter SHOULD NOT send an HTTP message header
//# that exceeds the indicated size, as the peer will likely refuse to
//# process it.
//= type=exception
//= reason=encodeField holds no peer settings: SETTINGS_MAX_FIELD_SECTION_SIZE is connection state, and docs/DESIGN.md section 3 puts connection state on the consumer's side of the seam
pub fn encodeField(target: []u8, field: Field) Error!u32 {
    if (static_table.lookup(field.name, field.value)) |match| {
        //= https://www.rfc-editor.org/rfc/rfc9204#section-7.1.3
        //# An intermediary MUST NOT re-encode a value that uses a literal
        //# representation with the 'N' bit set with another representation that
        //# would index it.  If QPACK is used for re-encoding, a literal
        //# representation with the 'N' bit set MUST be used.  If HPACK is used
        //# for re-encoding, the never-indexed literal representation (see
        //# Section 6.2.3 of [RFC7541]) MUST be used.
        if (match.value_matched and !field.never_indexed) {
            // The index came out of the static table, so it cannot be too
            // large for the encoding; a target too small is the only failure.
            return integer.encode(target, @intCast(match.index), indexed_prefix_bits, indexed_tag | indexed_static_bit) catch
                return error.OutputTooSmall;
        }
        var offset = integer.encode(
            target,
            @intCast(match.index),
            literal_name_reference_prefix_bits,
            literal_name_reference_tag | literal_name_reference_static_bit |
                (if (field.never_indexed) literal_name_reference_never_bit else 0),
        ) catch return error.OutputTooSmall;
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
//= https://www.rfc-editor.org/rfc/rfc9114#section-10.6
//# Implementations communicating on a secure channel MUST NOT compress
//# content that includes both confidential and attacker-controlled data
//# unless separate compression contexts are used for each source of
//# data.  Compression MUST NOT be used if the source of data cannot be
//# reliably determined.
//= type=exception
//= reason=the attack needs a compression context shared between a secret and attacker-controlled data, and with the dynamic table advertised away there is none: every field is coded against RFC 7541 section 5.2's fixed Huffman table, which has no state to carry one field's octets into another's. The 'N' bit that stops a field entering a context is honoured, and section 7.1.3's rule about it is cited on encodeField
fn encodeStringAt(target: []u8, text: []const u8, prefix_bits: u4, tag: u8, huffman_bit: u8) Error!u32 {
    const coded_length = huffman.encodedLength(text);
    const coded = coded_length < text.len;
    const length = if (coded) coded_length else text.len;

    const header = integer.encode(
        target,
        std.math.cast(u62, length) orelse return error.OutputTooSmall,
        prefix_bits,
        tag | (if (coded) huffman_bit else 0),
    ) catch return error.OutputTooSmall;
    if (target.len - header < length) return error.OutputTooSmall;

    if (coded) {
        _ = huffman.encode(target[header..], text) catch return error.OutputTooSmall;
    } else {
        @memcpy(target[header..][0..text.len], text);
    }
    return header + @as(u32, @intCast(length));
}

/// Encode a whole field section, prefix included.
//= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
//# When the maximum table capacity is zero, the encoder MUST NOT insert
//# entries into the dynamic table and MUST NOT send any encoder
//# instructions on the encoder stream.
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.1
//# An encoder MUST emit field representations in the order
//# they appear in the input field section.
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.1.1
//# If the dynamic table does not contain enough room for a new entry
//# without evicting other entries, and the entries that would be evicted
//# are not evictable, the encoder MUST NOT insert that entry into the
//# dynamic table (including duplicates of existing entries).
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; with no table there is no insertion to refuse
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
//# The new capacity MUST be lower than or equal to the limit described
//# in Section 3.2.3.  In HTTP/3, this limit is the value of the
//# SETTINGS_QPACK_MAX_TABLE_CAPACITY parameter (Section 5) received from
//# the decoder.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; Set Dynamic Table Capacity is an encoder-stream instruction, and this encoder sends none
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
//# The decoder MUST treat a new dynamic table capacity
//# value that exceeds this limit as a connection error of type
//# QPACK_ENCODER_STREAM_ERROR.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; no capacity instruction ever arrives, because a peer told the capacity is zero may send no encoder instructions at all
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
//# Reducing the dynamic table capacity can cause entries to be evicted;
//# see Section 3.2.2.  This MUST NOT cause the eviction of entries that
//# are not evictable; see Section 2.1.1.  Changing the capacity of the
//# dynamic table is not acknowledged as this instruction does not insert
//# an entry.
//= type=exception
//= reason=the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; a capacity that is never set cannot be reduced, and there is no entry to evict
//= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
//# For clients using 0-RTT data in HTTP/3, the server's maximum table
//# capacity is the remembered value of the setting or zero if the value
//# was not previously sent.  When the client's 0-RTT value of the
//# SETTING is zero, the server MAY set it to a non-zero value in its
//# SETTINGS frame.  If the remembered value is non-zero, the server MUST
//# send the same non-zero value in its SETTINGS frame.  If it specifies
//# any other value, or omits SETTINGS_QPACK_MAX_TABLE_CAPACITY from
//# SETTINGS, the encoder must treat this as a connection error of type
//# QPACK_DECODER_STREAM_ERROR.
//= type=exception
//= reason=0-RTT is out of scope, and the dynamic table is not built: this endpoint advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0, which forbids its peer the table entirely, and docs/DESIGN.md section 6 lists the table and its two streams as next rather than built; a decoder advertising zero has nothing to remember across connections
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

//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2
//# The decoder MUST emit field lines in the order their representations
//# appear in the encoded field section.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.4
//# When
//# the 'N' bit is set, the encoded field line MUST always be encoded
//# with a literal representation.  In particular, when a peer sends a
//# field line that it received represented as a literal field line with
//# the 'N' bit set, it MUST use a literal representation to forward this
//# field line.
//= type=test
//= https://www.rfc-editor.org/rfc/rfc9204#section-7.1.3
//# An intermediary MUST NOT re-encode a value that uses a literal
//# representation with the 'N' bit set with another representation that
//# would index it.  If QPACK is used for re-encoding, a literal
//# representation with the 'N' bit set MUST be used.  If HPACK is used
//# for re-encoding, the never-indexed literal representation (see
//# Section 6.2.3 of [RFC7541]) MUST be used.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
//# If the decoder encounters a reference in a field line representation
//# to a dynamic table entry that has already been evicted or that has an
//# absolute index greater than or equal to the declared Required Insert
//# Count (Section 4.5.1), it MUST treat this as a connection error of
//# type QPACK_DECOMPRESSION_FAILED.
//= type=test
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.1
//# If the decoder encounters a value
//# of EncodedInsertCount that could not have been produced by a
//# conformant encoder, it MUST treat this as a connection error of type
//# QPACK_DECOMPRESSION_FAILED.
//= type=test
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

//= https://www.rfc-editor.org/rfc/rfc9204#section-3.1
//# When the decoder encounters an invalid static table index in a field
//# line representation, it MUST treat this as a connection error of type
//# QPACK_DECOMPRESSION_FAILED.
//= type=test
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
    try testing.expectError(error.OutputTooSmall, encode(&target, &.{
        .{ .name = "x-long-name-here", .value = "and a long value too" },
    }));
}

//= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
//# If an implementation encounters a value larger than it is able to
//# decode, this MUST be treated as a stream error of type
//# QPACK_DECOMPRESSION_FAILED if on a request stream or a connection
//# error of the appropriate type if on the encoder or decoder stream.
//= type=test
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.1.1
//# QPACK implementations MUST be able to decode integers up to and
//# including 62 bits long.
//= type=test
test "a field section prefix at the encoding's limits does not overflow" {
    // Found by review: `Decoded.value` is a `u62`, and Zig does not widen
    // operands to a declared result type, so `count.value + delta.value` and
    // `delta.value + 1` overflowed inside `u62`. Twenty-one octets of peer
    // input reach both, before any other check runs — a panic in the safe
    // builds and undefined behaviour in the one zrk ships.
    var buffer: [64]u8 = undefined;
    var wire: [32]u8 = undefined;

    // A Required Insert Count and a Delta Base both at the width's maximum,
    // with the sign bit clear and then set.
    for ([_]u8{ 0x00, 0x80 }) |sign| {
        var offset: u32 = 0;
        offset += try integer.encode(wire[offset..], std.math.maxInt(u62), required_insert_count_prefix_bits, 0);
        offset += try integer.encode(wire[offset..], std.math.maxInt(u62), delta_base_prefix_bits, sign);
        // Either answer is fine; not crashing is the point.
        _ = iterate(wire[0..offset], &buffer, 1 << 16) catch {};
    }
}
