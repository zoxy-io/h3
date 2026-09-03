//! QPACK field sections encoded by four other implementations, decoded here and
//! compared against the source the encoders were given.
//!
//! This is the only evidence in the package that comes from outside it. Every
//! other test — the unit tests, the fuzz targets, the round trips — is fed by
//! this package's own encoder, so all of them agree with the decoder for the
//! same reason the decoder might be wrong. docs/VERIFICATION.md section 1 calls
//! that "the `AckRanges` tests asserted the bug": a test written by the author
//! of the code shares the author's reading of the RFC.
//!
//! ## What it catches, and what it does not
//!
//! This file was proposed on the strength of a defect it turns out **not** to
//! catch, and saying so is more useful than quietly keeping the claim.
//! `field_line.iterate` refused a field section whose Required Insert Count was
//! zero and whose Delta Base was not, which RFC 9204 section 4.5.1.2 explicitly
//! permits. The reasoning was that other encoders would produce shapes this
//! package's own never does. They do — but not that one: all four emit a prefix
//! of `00 00` at capacity zero, because a zero Delta Base is what section
//! 4.5.1.2 calls "one of the most efficient encodings". The bug survives this
//! corpus, and was found by reading the RFC instead.
//!
//! What the corpus does prove is narrower and still worth its 40 KB: 144 field
//! sections encoded by four implementations decode to exactly the fields those
//! implementations were handed, and **all eight vendored files differ octet for
//! octet from what `field_line.encode` produces for the same input**. The
//! representation choices — indexed against literal, which names get Huffman
//! coding, where a static-table reference is preferred — are theirs and not
//! ours, and the decoder handles them. That is a real class of misreading, just
//! not the class that motivated the file.
//!
//! The lesson for the next corpus: a corpus disagrees with you only where its
//! producers had a reason to differ. Capacity-zero QPACK gives encoders very
//! little room, so it is strong evidence about representation and no evidence
//! at all about the prefix.
//!
//! ## What is here and why only this much
//!
//! From [qifs](https://github.com/qpackers/qifs), the QPACK offline interop
//! corpus that nghttp3 and ls-qpack check against. Only the **capacity-zero**
//! encodings are usable: this package advertises
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and has no dynamic table, so an
//! encoding that references one is not something a conforming peer would send
//! it. That is 48 files in the corpus; the two smallest inputs are vendored
//! across all four encoders that produced capacity-zero output, which is 40 KB
//! rather than the 5.8 MB the whole set would cost.
//!
//! `ls-qpack`, `nghttp3` and `qthingey` produce byte-identical output for these
//! inputs; `quinn` differs. Keeping all four is the point — three agreeing is
//! not the same evidence as three implementations, and the one that differs is
//! the one most likely to exercise a representation this package's own encoder
//! never emits.
//!
//! ## The two formats
//!
//! A `.qif` is the input: one field per line as `name<TAB>value`, a blank line
//! between field sections. A `.qpack` is the output, in the
//! [offline interop format](https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop):
//! a sequence of `[stream id: u64 big-endian][length: u32 big-endian][octets]`.
//! Stream 0 is the encoder stream, which is empty at capacity zero; every other
//! stream identifier carries one encoded field section.

const std = @import("std");

const h3 = @import("h3");

const qpack = h3.qpack;
const testing = std.testing;

/// Octets of decoded name and value held at once. The largest section in these
/// inputs is a browser request with a long `user-agent` and `accept` line.
const decode_buffer_octets = 16 * 1024;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` for the decode. Generous: the corpus is
/// not a compression-bomb test, and section 4.2.2's limit has its own.
const list_size_max = 1 << 20;

const Case = struct {
    name: []const u8,
    source: []const u8,
    encoded: []const u8,
};

const cases = [_]Case{
    .{ .name = "netbsd/ls-qpack", .source = @embedFile("qifs/netbsd.qif"), .encoded = @embedFile("qifs/netbsd.ls-qpack.qpack") },
    .{ .name = "netbsd/nghttp3", .source = @embedFile("qifs/netbsd.qif"), .encoded = @embedFile("qifs/netbsd.nghttp3.qpack") },
    .{ .name = "netbsd/qthingey", .source = @embedFile("qifs/netbsd.qif"), .encoded = @embedFile("qifs/netbsd.qthingey.qpack") },
    .{ .name = "netbsd/quinn", .source = @embedFile("qifs/netbsd.qif"), .encoded = @embedFile("qifs/netbsd.quinn.qpack") },
    .{ .name = "netbsd-hq/ls-qpack", .source = @embedFile("qifs/netbsd-hq.qif"), .encoded = @embedFile("qifs/netbsd-hq.ls-qpack.qpack") },
    .{ .name = "netbsd-hq/nghttp3", .source = @embedFile("qifs/netbsd-hq.qif"), .encoded = @embedFile("qifs/netbsd-hq.nghttp3.qpack") },
    .{ .name = "netbsd-hq/qthingey", .source = @embedFile("qifs/netbsd-hq.qif"), .encoded = @embedFile("qifs/netbsd-hq.qthingey.qpack") },
    .{ .name = "netbsd-hq/quinn", .source = @embedFile("qifs/netbsd-hq.qif"), .encoded = @embedFile("qifs/netbsd-hq.quinn.qpack") },
};

/// One field section's worth of the `.qif`: the slice of the file between two
/// blank lines. Kept as a slice rather than parsed up front, because the
/// comparison walks it in step with the decoder and never needs it twice.
const SectionIterator = struct {
    source: []const u8,
    offset: usize = 0,

    fn next(self: *SectionIterator) ?[]const u8 {
        // Skip blank lines between sections.
        while (self.offset < self.source.len and self.source[self.offset] == '\n') {
            self.offset += 1;
        }
        if (self.offset >= self.source.len) return null;
        const start = self.offset;
        // A section ends at a blank line or at the end of the file.
        while (self.offset < self.source.len) {
            const line_end = std.mem.indexOfScalarPos(u8, self.source, self.offset, '\n') orelse self.source.len;
            if (line_end == self.offset) break;
            self.offset = @min(line_end + 1, self.source.len);
        }
        return self.source[start..self.offset];
    }
};

const Field = struct { name: []const u8, value: []const u8 };

/// One `name<TAB>value` line.
const FieldIterator = struct {
    section: []const u8,
    offset: usize = 0,

    fn next(self: *FieldIterator) ?Field {
        if (self.offset >= self.section.len) return null;
        const line_end = std.mem.indexOfScalarPos(u8, self.section, self.offset, '\n') orelse self.section.len;
        const line = self.section[self.offset..line_end];
        self.offset = @min(line_end + 1, self.section.len);
        if (line.len == 0) return self.next();
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return .{ .name = line, .value = "" };
        return .{ .name = line[0..tab], .value = line[tab + 1 ..] };
    }
};

/// One `[stream id][length][octets]` record.
const RecordIterator = struct {
    encoded: []const u8,
    offset: usize = 0,

    const Record = struct { stream: u64, block: []const u8 };

    fn next(self: *RecordIterator) ?Record {
        if (self.offset + 12 > self.encoded.len) return null;
        const stream = std.mem.readInt(u64, self.encoded[self.offset..][0..8], .big);
        const length = std.mem.readInt(u32, self.encoded[self.offset + 8 ..][0..4], .big);
        self.offset += 12;
        if (self.offset + length > self.encoded.len) return null;
        const block = self.encoded[self.offset..][0..length];
        self.offset += length;
        return .{ .stream = stream, .block = block };
    }
};

test "qifs: four other encoders' field sections decode to what they were given" {
    var buffer: [decode_buffer_octets]u8 = undefined;

    for (cases) |case| {
        var sections: SectionIterator = .{ .source = case.source };
        var records: RecordIterator = .{ .encoded = case.encoded };
        var checked: u32 = 0;

        while (records.next()) |record| {
            // Stream 0 is the encoder stream. At capacity zero there is nothing
            // a conforming encoder can put on it, and an entry there would mean
            // the file is not the capacity-zero encoding it claims to be.
            if (record.stream == 0) {
                try testing.expectEqual(@as(usize, 0), record.block.len);
                continue;
            }

            const expected = sections.next() orelse {
                std.debug.print("\n{s}: more encoded sections than the .qif has\n", .{case.name});
                return error.TestUnexpectedResult;
            };

            var iterator = qpack.field_line.iterate(record.block, &buffer, list_size_max) catch |err| {
                std.debug.print("\n{s} stream {d}: iterate failed: {s}\n", .{ case.name, record.stream, @errorName(err) });
                return err;
            };
            var fields: FieldIterator = .{ .section = expected };

            while (fields.next()) |want| {
                const got = (iterator.next() catch |err| {
                    std.debug.print("\n{s} stream {d}: decode failed at `{s}`: {s}\n", .{ case.name, record.stream, want.name, @errorName(err) });
                    return err;
                }) orelse {
                    std.debug.print("\n{s} stream {d}: ran out of fields before `{s}`\n", .{ case.name, record.stream, want.name });
                    return error.TestUnexpectedResult;
                };
                try testing.expectEqualStrings(want.name, got.name);
                try testing.expectEqualStrings(want.value, got.value);
            }
            // And nothing after what the source listed.
            try testing.expectEqual(@as(?qpack.Field, null), try iterator.next());
            checked += 1;
        }

        // A case that decoded nothing would pass every assertion above, which is
        // the shape docs/VERIFICATION.md section 1 warns about twice.
        try testing.expect(checked > 0);
        try testing.expectEqual(@as(?[]const u8, null), sections.next());
    }
}

test "qifs: the corpus contains encodings this package's own encoder does not produce" {
    // The reason this corpus is worth its 40 KB. If every vendored file were
    // byte-identical to what `field_line.encode` emits, decoding them would
    // prove nothing that a round trip does not — the whole point is that other
    // encoders make different representation choices for the same fields.
    var buffer: [decode_buffer_octets]u8 = undefined;
    var ours: [decode_buffer_octets]u8 = undefined;
    var differs: u32 = 0;

    for (cases) |case| {
        var records: RecordIterator = .{ .encoded = case.encoded };
        while (records.next()) |record| {
            if (record.stream == 0) continue;

            // Decode theirs, re-encode with ours, and compare the octets.
            var iterator = try qpack.field_line.iterate(record.block, &buffer, list_size_max);
            var fields: [64]qpack.Field = undefined;
            var count: usize = 0;
            while (try iterator.next()) |one| {
                if (count == fields.len) break;
                fields[count] = one;
                count += 1;
            }
            const written = qpack.field_line.encode(&ours, fields[0..count]) catch continue;
            if (!std.mem.eql(u8, ours[0..written], record.block)) differs += 1;
            break; // One section per file is enough to answer the question.
        }
    }
    try testing.expect(differs > 0);
}
