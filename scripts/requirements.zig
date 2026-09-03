//! The requirement ledger of docs/VERIFICATION.md section 5.1.
//!
//! Half of the fifty-seven defects the review found were a MUST that was never
//! implemented, or one implemented and never wired in. No number of unit tests
//! finds a requirement nobody wrote down as missing, because a test is written
//! from the code and shares whatever the code's author believed. This reads the
//! RFC text instead, and asks which of its requirements this package has
//! anything to say about.
//!
//! ## The convention
//!
//! Adopted from [duvet](https://github.com/awslabs/duvet), which s2n-quic uses
//! and publishes a report from. A citation is a comment block:
//!
//!     //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.1
//!     //# A sender establishes persistent congestion after the receipt of an
//!     //# acknowledgment if two packets that are ack-eliciting are declared
//!     //# lost, and:
//!     //= type=test
//!
//! The `//=` line names the RFC and the section. The `//#` lines quote the
//! requirement **verbatim**, wrapped however the RFC wraps it. The optional
//! second `//=` gives the kind:
//!
//!   - absent — the citation is the implementation
//!   - `type=test` — this is the test that proves it
//!   - `type=exception` with `reason=...` — deliberately not done, and why
//!   - `type=todo` — known missing, tracked
//!
//! ## What is a gate and what is a report
//!
//! Two of the checks here are gates, because both are mechanical and neither
//! can be satisfied by writing something agreeable:
//!
//!  1. **A quote must appear in the section it cites.** A citation that
//!     misquotes the RFC, or that attributes a requirement to the wrong
//!     section, is worse than no citation: it is a claim of diligence that a
//!     reader will believe. This is the check that makes the rest trustworthy.
//!  2. **An exception must carry a reason.** "Deliberately not done" without a
//!     stated why is indistinguishable from "forgotten".
//!
//! The coverage numbers are a **report**, not a gate, and the reason is in
//! `splitSentences`: extracting "the requirements" from prose is a heuristic,
//! and a gate resting on a heuristic teaches everyone to work around the
//! heuristic. Coverage is ratcheted separately by `--baseline`, which fails
//! only when a previously cited requirement loses its citation — a regression,
//! which is exact, rather than a threshold, which is a guess.
//!
//! Runs as `zig build requirements`.

const std = @import("std");

const assert = std.debug.assert;

/// Bounded walk, as `lint.zig` has: a tree past this is itself the finding.
const files_max: u32 = 256;
const file_bytes_max: usize = 8 * 1024 * 1024;
/// The longest run of `//#` lines one citation may carry. A quote longer than
/// this is quoting a whole subsection rather than a requirement.
const quote_lines_max: u32 = 24;

/// The keywords RFC 2119 and RFC 8174 give normative force. `MAY` and
/// `OPTIONAL` are deliberately absent: they permit rather than require, so a
/// missing one is not a defect and counting them would bury the ones that are.
const keywords = [_][]const u8{
    "MUST NOT",
    "MUST",
    "SHALL NOT",
    "SHALL",
    "SHOULD NOT",
    "SHOULD",
    "REQUIRED",
};

/// The documents this package implements, as opposed to the ones it borrows
/// individual rules from. See specs/SCOPE.md for the argument; the short form
/// is that an uncited requirement in RFC 9112 is not a gap, because nothing
/// here is an HTTP/1.1 implementation, while an uncited requirement in RFC
/// 9000 is exactly a gap.
const implemented = [_][]const u8{ "9000", "9001", "9002", "9114", "9204" };

fn isImplemented(rfc: []const u8) bool {
    for (implemented) |one| {
        if (std.mem.eql(u8, one, rfc)) return true;
    }
    return false;
}

/// Whether a keyword's absence is a defect rather than a choice.
fn isMandatory(keyword: []const u8) bool {
    return std.mem.startsWith(u8, keyword, "MUST") or
        std.mem.startsWith(u8, keyword, "SHALL") or
        std.mem.eql(u8, keyword, "REQUIRED");
}

const Section = struct {
    /// "9000", from the filename.
    rfc: []const u8,
    /// "13.2.1", or "A.2" for an appendix.
    number: []const u8,
    title: []const u8,
    /// The section's prose, whitespace-normalized so a citation copied out of
    /// the RFC — line wrapping and all — is a plain substring of it.
    normalized: []const u8,
};

const Requirement = struct {
    section: u32,
    keyword: []const u8,
    /// The sentence, normalized like the section text it came from.
    text: []const u8,
    cited: bool = false,
    kind: Kind = .none,
};

const Kind = enum { none, implementation, test_, exception, todo };

const Citation = struct {
    path: []const u8,
    line: u32,
    rfc: []const u8,
    section: []const u8,
    quote: []const u8,
    kind: Kind,
    reason: ?[]const u8,
};

/// Collapse every whitespace run to one space and trim. Applied identically to
/// the RFC text and to a citation's quote, which is what lets a quote copied
/// with the RFC's own line breaks match the paragraph it came from.
fn normalize(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var was_space = true;
    for (text) |octet| {
        const space = octet == ' ' or octet == '\t' or octet == '\n' or octet == '\r';
        if (space) {
            if (!was_space) try out.append(arena, ' ');
            was_space = true;
            continue;
        }
        try out.append(arena, octet);
        was_space = false;
    }
    var slice = try out.toOwnedSlice(arena);
    if (slice.len > 0 and slice[slice.len - 1] == ' ') slice = slice[0 .. slice.len - 1];
    return slice;
}

/// True for a line that opens a numbered section: "13.2.1.  Generating Acks"
/// or "A.2.  Client Initial", at column zero.
fn sectionHeading(line: []const u8) ?struct { number: []const u8, title: []const u8 } {
    if (line.len == 0) return null;
    if (line[0] == ' ') return null;
    // A number, or a single appendix letter, then dot-separated parts.
    var index: usize = 0;
    var saw_digit = false;
    while (index < line.len) : (index += 1) {
        const octet = line[index];
        if (octet >= '0' and octet <= '9') {
            saw_digit = true;
            continue;
        }
        if (octet == '.') continue;
        if (index == 0 and octet >= 'A' and octet <= 'Z') continue;
        break;
    }
    if (index == 0) return null;
    if (!saw_digit and !(line[0] >= 'A' and line[0] <= 'Z')) return null;
    if (line[index - 1] != '.') return null;
    // Two spaces separate the number from the title in every RFC this reads.
    if (index + 2 > line.len) return null;
    if (line[index] != ' ') return null;
    const title = std.mem.trim(u8, line[index..], " ");
    if (title.len == 0) return null;
    return .{ .number = line[0 .. index - 1], .title = title };
}

/// Split normalized prose into sentences.
///
/// A heuristic, and the reason the coverage numbers are a report rather than a
/// gate. It breaks on ". " followed by a capital, which is wrong for "Section
/// 4.1. The" and for "e.g." — the abbreviation list below covers what these
/// five RFCs actually use, and a miss costs an over- or under-count of one
/// requirement rather than a wrong verdict about any citation.
fn splitSentences(arena: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var start: usize = 0;
    var index: usize = 0;
    while (index + 1 < text.len) : (index += 1) {
        if (text[index] != '.') continue;
        if (text[index + 1] != ' ') continue;
        if (index + 2 >= text.len) continue;
        const next = text[index + 2];
        if (!(next >= 'A' and next <= 'Z')) continue;
        if (endsWithAbbreviation(text[start .. index + 1])) continue;
        try out.append(arena, std.mem.trim(u8, text[start .. index + 1], " "));
        start = index + 2;
    }
    if (start < text.len) {
        const tail = std.mem.trim(u8, text[start..], " ");
        if (tail.len > 0) try out.append(arena, tail);
    }
    return out.toOwnedSlice(arena);
}

fn endsWithAbbreviation(text: []const u8) bool {
    const abbreviations = [_][]const u8{
        "e.g.", "i.e.", "etc.", "cf.", "Fig.", "vs.", "Sec.", "No.",
    };
    for (abbreviations) |one| {
        if (std.mem.endsWith(u8, text, one)) return true;
    }
    // "Section 4.1." and "[HTTP]." style references: a dot after a digit that
    // is part of a section number rather than a full stop.
    if (text.len >= 2) {
        const before = text[text.len - 2];
        if (before >= '0' and before <= '9') return true;
    }
    return false;
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        std.debug.print("usage: requirements <specs-dir> <source-root> [more-roots...]\n", .{});
        return 2;
    }

    var sections: std.ArrayList(Section) = .empty;
    var requirements: std.ArrayList(Requirement) = .empty;
    try loadSpecs(arena, io, args[1], &sections, &requirements);
    assert(sections.items.len > 0);
    assert(requirements.items.len > 0);

    var citations: std.ArrayList(Citation) = .empty;
    var list_uncited = false;
    for (args[2..]) |root_path| {
        // `--uncited` lists what is left rather than counting it. Counting is
        // what a gate needs; a listing is what the next person to do the work
        // needs, and hunting them by hand out of seven RFCs is how a sweep
        // stops halfway.
        if (std.mem.eql(u8, root_path, "--uncited")) {
            list_uncited = true;
            continue;
        }
        try collectCitations(arena, io, root_path, &citations);
    }

    return report(arena, sections.items, requirements.items, citations.items, list_uncited);
}

fn loadSpecs(
    arena: std.mem.Allocator,
    io: std.Io,
    specs_path: []const u8,
    sections: *std.ArrayList(Section),
    requirements: *std.ArrayList(Requirement),
) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, specs_path, .{ .iterate = true });
    defer dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".txt")) continue;
        try names.append(arena, try arena.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, lessThan);

    for (names.items) |name| {
        const rfc = name["rfc".len .. name.len - ".txt".len];
        const contents = try dir.readFileAlloc(io, name, arena, .limited(file_bytes_max));
        try parseSpec(arena, rfc, contents, sections, requirements);
    }
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn parseSpec(
    arena: std.mem.Allocator,
    rfc: []const u8,
    contents: []const u8,
    sections: *std.ArrayList(Section),
    requirements: *std.ArrayList(Requirement),
) !void {
    var body: std.ArrayList(u8) = .empty;
    var number: ?[]const u8 = null;
    var title: []const u8 = "";

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        // Page furniture: the running header and footer carry no prose, and
        // leaving them in would splice two paragraphs together across a page
        // break and break a quote that spans one.
        if (std.mem.indexOf(u8, line, "[Page ") != null) continue;
        if (line.len > 0 and line[0] == 12) continue; // form feed
        if (std.mem.startsWith(u8, line, "RFC ") and std.mem.indexOf(u8, line, "  ") != null) continue;

        if (sectionHeading(line)) |heading| {
            try flushSection(arena, rfc, number, title, body.items, sections, requirements);
            body.clearRetainingCapacity();
            number = heading.number;
            title = heading.title;
            continue;
        }
        if (number == null) continue;
        try body.appendSlice(arena, line);
        try body.append(arena, '\n');
    }
    try flushSection(arena, rfc, number, title, body.items, sections, requirements);
}

fn flushSection(
    arena: std.mem.Allocator,
    rfc: []const u8,
    number: ?[]const u8,
    title: []const u8,
    body: []const u8,
    sections: *std.ArrayList(Section),
    requirements: *std.ArrayList(Requirement),
) !void {
    const which = number orelse return;
    const normalized = try normalize(arena, body);
    if (normalized.len == 0) return;

    const index: u32 = @intCast(sections.items.len);
    try sections.append(arena, .{
        .rfc = rfc,
        .number = which,
        .title = title,
        .normalized = normalized,
    });

    for (try splitSentences(arena, normalized)) |sentence| {
        const keyword = keywordIn(sentence) orelse continue;
        // RFC 8174's boilerplate names every keyword in one sentence, so the
        // extractor sees a requirement where the document is only saying what
        // its own words mean. Three of these were the last uncited "mandatory
        // requirements" in the ledger, and citing them would have been the
        // heuristic teaching everyone to satisfy the heuristic.
        if (isKeywordBoilerplate(sentence)) continue;
        try requirements.append(arena, .{
            .section = index,
            .keyword = keyword,
            .text = sentence,
        });
    }
}

/// RFC 8174 section 2's sentence, which every one of these documents quotes
/// verbatim. Recognised by the shape rather than by section number, because the
/// section it sits in differs per RFC.
fn isKeywordBoilerplate(sentence: []const u8) bool {
    if (std.mem.indexOf(u8, sentence, "NOT RECOMMENDED") == null) return false;
    if (std.mem.indexOf(u8, sentence, "OPTIONAL") == null) return false;
    return std.mem.indexOf(u8, sentence, "BCP 14") != null or
        std.mem.indexOf(u8, sentence, "RFC2119") != null or
        std.mem.indexOf(u8, sentence, "RFC8174") != null;
}

/// The strongest keyword a sentence carries, so "MUST NOT" is not reported as
/// a "MUST" — the list is ordered longest-first for exactly that reason.
fn keywordIn(sentence: []const u8) ?[]const u8 {
    for (keywords) |keyword| {
        if (std.mem.indexOf(u8, sentence, keyword) != null) return keyword;
    }
    return null;
}

fn collectCitations(
    arena: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    citations: *std.ArrayList(Citation),
) !void {
    var root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);

    var file_count: u32 = 0;
    var walker = try root.walk(arena);
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        file_count += 1;
        assert(file_count <= files_max);
        const contents = try root.readFileAlloc(io, entry.path, arena, .limited(file_bytes_max));
        const shown = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root_path, entry.path });
        try parseCitations(arena, shown, contents, citations);
    }
}

fn parseCitations(
    arena: std.mem.Allocator,
    path: []const u8,
    contents: []const u8,
    citations: *std.ArrayList(Citation),
) !void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var number: u32 = 0;
    var open: ?Citation = null;
    var quote: std.ArrayList(u8) = .empty;
    var quote_lines: u32 = 0;

    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, std.mem.trimEnd(u8, raw, "\r"), " \t");

        if (std.mem.startsWith(u8, line, "//=")) {
            const rest = std.mem.trim(u8, line["//=".len..], " ");
            if (std.mem.startsWith(u8, rest, "https://")) {
                try close(arena, &open, &quote, &quote_lines, citations);
                open = parseUrl(path, number, rest) orelse null;
                continue;
            }
            // A `type=` line modifies the citation it follows.
            if (open) |*one| applyType(arena, one, rest);
            continue;
        }
        if (std.mem.startsWith(u8, line, "//#")) {
            if (open == null) continue;
            quote_lines += 1;
            assert(quote_lines <= quote_lines_max);
            const text = line["//#".len..];
            if (quote.items.len > 0) try quote.append(arena, ' ');
            try quote.appendSlice(arena, std.mem.trim(u8, text, " "));
            continue;
        }
        try close(arena, &open, &quote, &quote_lines, citations);
    }
    try close(arena, &open, &quote, &quote_lines, citations);
}

fn close(
    arena: std.mem.Allocator,
    open: *?Citation,
    quote: *std.ArrayList(u8),
    quote_lines: *u32,
    citations: *std.ArrayList(Citation),
) !void {
    if (open.*) |one| {
        var finished = one;
        finished.quote = try normalize(arena, quote.items);
        try citations.append(arena, finished);
    }
    open.* = null;
    quote.* = .empty;
    quote_lines.* = 0;
}

fn parseUrl(path: []const u8, line: u32, url: []const u8) ?Citation {
    const marker = "rfc-editor.org/rfc/rfc";
    const at = std.mem.indexOf(u8, url, marker) orelse return null;
    const tail = url[at + marker.len ..];
    const hash = std.mem.indexOfScalar(u8, tail, '#') orelse return null;
    const rfc = tail[0..hash];
    const anchor = tail[hash + 1 ..];
    const prefix = "section-";
    if (!std.mem.startsWith(u8, anchor, prefix)) return null;
    return .{
        .path = path,
        .line = line,
        .rfc = rfc,
        .section = anchor[prefix.len..],
        .quote = "",
        .kind = .implementation,
        .reason = null,
    };
}

fn applyType(arena: std.mem.Allocator, one: *Citation, rest: []const u8) void {
    _ = arena;
    if (std.mem.indexOf(u8, rest, "type=test") != null) one.kind = .test_;
    if (std.mem.indexOf(u8, rest, "type=todo") != null) one.kind = .todo;
    if (std.mem.indexOf(u8, rest, "type=exception") != null) one.kind = .exception;
    if (std.mem.indexOf(u8, rest, "reason=")) |at| {
        const reason = std.mem.trim(u8, rest[at + "reason=".len ..], " ");
        if (reason.len > 0) one.reason = reason;
    }
}

fn report(
    arena: std.mem.Allocator,
    sections: []const Section,
    requirements: []Requirement,
    citations: []const Citation,
    list_uncited: bool,
) !u8 {
    _ = arena;
    var violations: u32 = 0;

    for (citations) |citation| {
        const section = findSection(sections, citation.rfc, citation.section);
        if (section == null) {
            std.debug.print(
                "{s}:{d}: cites rfc{s} section {s}, which is not a section of any vendored spec\n",
                .{ citation.path, citation.line, citation.rfc, citation.section },
            );
            violations += 1;
            continue;
        }
        if (citation.quote.len == 0) {
            std.debug.print(
                "{s}:{d}: citation has no `//#` quote; a section reference alone names no requirement\n",
                .{ citation.path, citation.line },
            );
            violations += 1;
            continue;
        }
        // Gate one: the quote has to be in the section it claims.
        if (std.mem.indexOf(u8, sections[section.?].normalized, citation.quote) == null) {
            std.debug.print(
                "{s}:{d}: quote does not appear in rfc{s} section {s}:\n    {s}\n",
                .{ citation.path, citation.line, citation.rfc, citation.section, citation.quote },
            );
            violations += 1;
            continue;
        }
        // Gate two: an exception states why.
        if (citation.kind == .exception and citation.reason == null) {
            std.debug.print(
                "{s}:{d}: `type=exception` without `reason=`; deliberately-not-done and forgotten look the same without one\n",
                .{ citation.path, citation.line },
            );
            violations += 1;
        }
        markCited(sections, requirements, section.?, citation);
    }

    printCoverage(sections, requirements);
    if (list_uncited) printUncited(sections, requirements);

    if (violations > 0) {
        std.debug.print("\nrequirements: {d} violation(s)\n", .{violations});
        return 1;
    }
    return 0;
}

fn findSection(sections: []const Section, rfc: []const u8, number: []const u8) ?u32 {
    for (sections, 0..) |section, index| {
        if (!std.mem.eql(u8, section.rfc, rfc)) continue;
        if (!std.mem.eql(u8, section.number, number)) continue;
        return @intCast(index);
    }
    return null;
}

/// A requirement counts as cited when the citation's quote overlaps it in
/// either direction: a quote may be a fragment of a long requirement sentence,
/// or may span several short ones.
fn markCited(
    sections: []const Section,
    requirements: []Requirement,
    section: u32,
    citation: Citation,
) void {
    _ = sections;
    for (requirements) |*requirement| {
        if (requirement.section != section) continue;
        const overlaps = std.mem.indexOf(u8, requirement.text, citation.quote) != null or
            std.mem.indexOf(u8, citation.quote, requirement.text) != null;
        if (!overlaps) continue;
        requirement.cited = true;
        // A test citation is the strongest claim, so it wins over an
        // implementation citation on the same requirement.
        if (requirement.kind == .none or citation.kind == .test_) requirement.kind = citation.kind;
    }
}

/// Every mandatory requirement in an implemented document that nothing cites,
/// with enough of the sentence to find it.
fn printUncited(sections: []const Section, requirements: []const Requirement) void {
    std.debug.print("\nuncited mandatory requirements, implemented documents only\n\n", .{});
    var count: u32 = 0;
    for (requirements) |requirement| {
        if (requirement.cited) continue;
        if (!isMandatory(requirement.keyword)) continue;
        const section = sections[requirement.section];
        if (!isImplemented(section.rfc)) continue;
        count += 1;
        const shown = if (requirement.text.len > 150) requirement.text[0..150] else requirement.text;
        std.debug.print("  rfc{s} section {s} [{s}]\n    {s}{s}\n", .{
            section.rfc,
            section.number,
            requirement.keyword,
            shown,
            if (requirement.text.len > 150) "…" else "",
        });
    }
    std.debug.print("\n  {d} remaining\n", .{count});
}

fn printCoverage(sections: []const Section, requirements: []const Requirement) void {
    var total: u32 = 0;
    var mandatory: u32 = 0;
    var cited: u32 = 0;
    var tested: u32 = 0;
    var excepted: u32 = 0;
    var todo: u32 = 0;

    var mandatory_implemented: u32 = 0;
    var cited_implemented: u32 = 0;
    for (requirements) |requirement| {
        total += 1;
        if (isMandatory(requirement.keyword)) mandatory += 1;
        if (isMandatory(requirement.keyword) and isImplemented(sections[requirement.section].rfc)) {
            mandatory_implemented += 1;
            if (requirement.cited) cited_implemented += 1;
        }
        if (!requirement.cited) continue;
        cited += 1;
        switch (requirement.kind) {
            .test_ => tested += 1,
            .exception => excepted += 1,
            .todo => todo += 1,
            else => {},
        }
    }

    // Per-RFC, because the aggregate hides the shape of the work: a document
    // this package implements a sliver of contributes hundreds of requirements
    // that were never in scope, and a single "cited of mandatory" ratio reads
    // as neglect rather than as scope.
    std.debug.print("requirement ledger — {d} sections across the vendored specs\n\n", .{sections.len});
    std.debug.print("  {s:<10} {s:>10} {s:>10} {s:>10} {s:>10}\n", .{ "rfc", "normative", "mandatory", "cited", "uncited" });
    var seen_rfc: [16][]const u8 = undefined;
    var seen_count: usize = 0;
    for (sections) |section| {
        var known = false;
        for (seen_rfc[0..seen_count]) |one| {
            if (std.mem.eql(u8, one, section.rfc)) known = true;
        }
        if (known) continue;
        if (seen_count == seen_rfc.len) break;
        seen_rfc[seen_count] = section.rfc;
        seen_count += 1;
    }
    for (seen_rfc[0..seen_count]) |rfc| {
        var normative: u32 = 0;
        var mandatory_here: u32 = 0;
        var cited_here: u32 = 0;
        for (requirements) |one| {
            if (!std.mem.eql(u8, sections[one.section].rfc, rfc)) continue;
            normative += 1;
            if (!isMandatory(one.keyword)) continue;
            mandatory_here += 1;
            if (one.cited) cited_here += 1;
        }
        std.debug.print("  {s:<10} {d:>10} {d:>10} {d:>10} {d:>10}  {s}\n", .{
            rfc,                         normative,                                               mandatory_here, cited_here,
            mandatory_here - cited_here, if (isImplemented(rfc)) "implemented" else "referenced",
        });
    }
    std.debug.print("\n", .{});
    std.debug.print("  {d} normative sentences (MUST/SHALL/SHOULD/REQUIRED)\n", .{total});
    std.debug.print("  {d} of them mandatory (MUST/SHALL/REQUIRED)\n", .{mandatory});
    std.debug.print("  {d} cited, of which {d} carry a test, {d} an exception, {d} a todo\n", .{ cited, tested, excepted, todo });
    std.debug.print("\n  in the five documents this package implements: {d} of {d} mandatory cited,\n", .{ cited_implemented, mandatory_implemented });
    std.debug.print("  leaving {d}. RFC 9110 and 9112 are referenced rather than implemented\n", .{mandatory_implemented - cited_implemented});
    std.debug.print("  and are cited only where a rule is borrowed — see specs/SCOPE.md.\n", .{});
    std.debug.print("\nThe counts are a report: `splitSentences` is a heuristic and a gate\n", .{});
    std.debug.print("resting on one teaches everyone to work around it. The gates are that a\n", .{});
    std.debug.print("quote appears in the section it cites, and that an exception states why.\n", .{});
}

const testing = std.testing;

test "a section heading is recognised, and prose is not" {
    try testing.expect(sectionHeading("13.2.1.  Generating Acknowledgments") != null);
    try testing.expectEqualStrings("13.2.1", sectionHeading("13.2.1.  Generating Acknowledgments").?.number);
    try testing.expectEqualStrings("A.2", sectionHeading("A.2.  Client Initial").?.number);
    // Indented prose, a bare paragraph, and a numbered list item inside prose.
    try testing.expect(sectionHeading("   An endpoint MUST NOT send a packet.") == null);
    try testing.expect(sectionHeading("An endpoint MUST NOT send a packet.") == null);
    try testing.expect(sectionHeading("") == null);
}

test "normalization makes a wrapped quote a substring of its paragraph" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The RFC wraps mid-sentence; a citation copies the wrap. Both sides
    // normalize to the same string, which is the whole trick.
    const paragraph = try normalize(arena,
        \\   In order to assist loss detection at the sender, an endpoint SHOULD
        \\   generate and send an ACK frame without delay.
    );
    const quote = try normalize(arena,
        \\ In order to assist loss detection at the sender, an endpoint SHOULD
        \\ generate and send an ACK frame without delay.
    );
    try testing.expect(std.mem.indexOf(u8, paragraph, quote) != null);
}

test "the strongest keyword wins, so MUST NOT is not counted as MUST" {
    try testing.expectEqualStrings("MUST NOT", keywordIn("An endpoint MUST NOT send it.").?);
    try testing.expectEqualStrings("MUST", keywordIn("An endpoint MUST send it.").?);
    try testing.expectEqualStrings("SHOULD NOT", keywordIn("It SHOULD NOT happen.").?);
    try testing.expect(keywordIn("An endpoint may send it.") == null);
    // MAY is not counted: a permission nobody took is not a defect.
    try testing.expect(keywordIn("An endpoint MAY send it.") == null);
}

test "only mandatory keywords make an absence a defect" {
    try testing.expect(isMandatory("MUST"));
    try testing.expect(isMandatory("MUST NOT"));
    try testing.expect(isMandatory("REQUIRED"));
    try testing.expect(!isMandatory("SHOULD"));
    try testing.expect(!isMandatory("SHOULD NOT"));
}

test "a citation block parses into its url, quote and kind" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var citations: std.ArrayList(Citation) = .empty;
    try parseCitations(arena, "x.zig",
        \\//= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.1
        \\//# A sender establishes persistent congestion after the receipt of
        \\//# an acknowledgment if two packets are declared lost.
        \\//= type=test
        \\const x = 1;
    , &citations);

    try testing.expectEqual(@as(usize, 1), citations.items.len);
    const one = citations.items[0];
    try testing.expectEqualStrings("9002", one.rfc);
    try testing.expectEqualStrings("7.6.1", one.section);
    try testing.expectEqual(Kind.test_, one.kind);
    try testing.expectEqualStrings(
        "A sender establishes persistent congestion after the receipt of an acknowledgment if two packets are declared lost.",
        one.quote,
    );
}

test "an exception keeps its reason" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var citations: std.ArrayList(Citation) = .empty;
    try parseCitations(arena, "x.zig",
        \\//= https://www.rfc-editor.org/rfc/rfc9000#section-9
        \\//# An endpoint MUST validate a new path.
        \\//= type=exception
        \\//= reason=migration is out of scope; see docs/DESIGN.md section 2
    , &citations);
    try testing.expectEqual(@as(usize, 1), citations.items.len);
    try testing.expectEqual(Kind.exception, citations.items[0].kind);
    try testing.expect(citations.items[0].reason != null);
}

test "two citations in one file do not run together" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var citations: std.ArrayList(Citation) = .empty;
    try parseCitations(arena, "x.zig",
        \\//= https://www.rfc-editor.org/rfc/rfc9000#section-1
        \\//# First requirement.
        \\const a = 1;
        \\//= https://www.rfc-editor.org/rfc/rfc9000#section-2
        \\//# Second requirement.
    , &citations);
    try testing.expectEqual(@as(usize, 2), citations.items.len);
    try testing.expectEqualStrings("First requirement.", citations.items[0].quote);
    try testing.expectEqualStrings("Second requirement.", citations.items[1].quote);
}

test "sentences split on a full stop and not on a section number" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parts = try splitSentences(arena, "See Section 4.1. An endpoint MUST stop. It then closes.");
    // "Section 4.1." does not end a sentence; the other two full stops do.
    try testing.expectEqual(@as(usize, 2), parts.len);
    try testing.expectEqualStrings("See Section 4.1. An endpoint MUST stop.", parts[0]);
    try testing.expectEqualStrings("It then closes.", parts[1]);
}

test "RFC 8174's keyword boilerplate is not a requirement" {
    // It names every keyword in one sentence, so the extractor sees a MUST NOT
    // where the document is only defining its own vocabulary. Three of these
    // were the last uncited mandatory requirements in the ledger.
    try testing.expect(isKeywordBoilerplate(
        "The key words \"MUST\", \"MUST NOT\", \"REQUIRED\", \"SHALL\", \"SHALL NOT\", " ++
            "\"SHOULD\", \"SHOULD NOT\", \"RECOMMENDED\", \"NOT RECOMMENDED\", \"MAY\", and " ++
            "\"OPTIONAL\" in this document are to be interpreted as described in BCP 14 " ++
            "[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.",
    ));
    // And a real requirement that happens to mention a keyword is not.
    try testing.expect(!isKeywordBoilerplate(
        "An endpoint MUST NOT send a packet if it would cause bytes_in_flight to be larger than the congestion window.",
    ));
    try testing.expect(!isKeywordBoilerplate(
        "This is OPTIONAL and NOT RECOMMENDED for a sender.",
    ));
}
