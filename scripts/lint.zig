//! Build-time lint for the promises this package makes in its README, so that
//! none of them can be broken quietly.
//!
//! **No I/O types in the seam.** `std.Io`, `std.posix`, `std.os`, `std.net`
//! and `std.fs` may not be named anywhere under `src/`. The temptation is more
//! specific here than it was in h2, and stronger: a QUIC stack wants to own a
//! UDP socket, and once it does, its two consumers — zoxy on libxev completion
//! callbacks, zrk on zio green threads through `std.Io` — cannot both use it.
//! Datagrams in, datagrams and events out; the caller owns the socket, and
//! `now` arrives as an argument rather than being read from a clock.
//!
//! **No allocator.** `std.mem.Allocator` may not appear either. Every buffer is
//! caller-owned and caller-sized, QPACK's dynamic table and the connection's
//! own state included. Tests that need one use `std.testing.allocator`, which
//! is a different needle.
//!
//! `@cImport` is forbidden for the same reason h2, ztls and hparse forbid it:
//! zero dependencies beyond the Zig toolchain. Packet protection is the one
//! place that would otherwise reach for libcrypto, and `std.crypto` covers it —
//! AES-GCM, ChaCha20-Poly1305, a raw AES block for header protection, and
//! HKDF-SHA256. `std.crypto` is deliberately *not* a boundary: it is
//! computation, not I/O, and it is what keeps the dependency table empty.
//!
//! The unbounded-loop rule is carried over from zoxy verbatim. It matters here
//! for a reason h2 did not have: a QUIC packet payload is a run of frames with
//! no frame count, and a stream is a run of packets with no end, so "consume
//! until the buffer is done" is the natural shape of nearly every loop in the
//! package and the natural shape of nearly every bug in it.
//!
//! Ported from zoxy-io/h2 `scripts/lint.zig`, which ported it from
//! zoxy-io/zoxy. Runs as `zig build lint` with the source root as its single
//! argument.

const std = @import("std");

const assert = std.debug.assert;

/// Bounded walk: a source tree past this size is itself a lint failure —
/// raise deliberately if the package legitimately grows.
const files_max: u32 = 192;
const file_bytes_max: u32 = 1024 * 1024;

/// One forbidden name: a needle that may appear only under `confined_to`.
/// Data rather than code, so adding a boundary is a row here instead of
/// another parameter threaded through `lintLine` and every one of its tests.
const Boundary = struct {
    needle: []const u8,
    /// A path prefix (`"quic/"`) or an exact file (`"root.zig"`), always
    /// written with forward slashes; `pathIsUnder` normalizes. Empty means
    /// the needle is allowed nowhere, which is every row today: this package
    /// has no privileged directory, and adding one should take an argument.
    confined_to: []const u8,
    message: []const u8,
};

const no_io_message =
    "no I/O in the seam: two consumers on two runtimes, so a socket, a reader " ++
    "or a writer here would exclude one of them (docs/TIGER_STYLE.md)";

const boundaries = [_]Boundary{
    .{
        .needle = "@cImport",
        .confined_to = "",
        .message = "@cImport is forbidden: zero dependencies beyond the Zig toolchain",
    },
    .{
        .needle = "std.mem.Allocator",
        .confined_to = "",
        .message = "no allocator: buffers are caller-owned and caller-sized " ++
            "(tests use std.testing.allocator)",
    },
    // `.debug.assert` rather than `std.debug.assert`, which is strictly
    // stronger: it catches the `@import("std").debug.assert` one-liner too.
    //
    // What it does not catch is an alias — `const d = std.debug;` and then
    // `d.assert(...)`. Closing that would mean forbidding `std.debug` outright,
    // and `src/` uses `std.debug.print` legitimately in its tests. The alias
    // line itself is conspicuous in a review in a way that typing the familiar
    // name is not, which is the drift this rule is actually aimed at.
    .{
        .needle = ".debug.assert",
        .confined_to = "",
        .message = "use `@import(\"../assert.zig\").assert`: std.debug.assert is " ++
            "`if (!ok) unreachable`, which ReleaseFast and ReleaseSmall are " ++
            "entitled to delete, so a consumer building for speed would ship a " ++
            "transport with its invariant checks removed (see src/assert.zig)",
    },
    .{ .needle = "std.Io", .confined_to = "", .message = no_io_message },
    .{ .needle = "std.posix", .confined_to = "", .message = no_io_message },
    .{ .needle = "std.os", .confined_to = "", .message = no_io_message },
    .{ .needle = "std.net", .confined_to = "", .message = no_io_message },
    .{ .needle = "std.fs", .confined_to = "", .message = no_io_message },
};

/// TIGER_STYLE's "put a limit on everything", made mechanical: `while (true)`
/// states no bound of its own, so it must carry one where a reviewer can see
/// it. Two shapes count.
///
/// An asserted counter:
///
///     while (true) : (passes += 1) {
///         assert(passes <= frames_per_packet_max);
///
/// Or a bound the syntax cannot show, which says so at the site with the
/// marker below and a reason.
///
/// The rule exists because of zoxy-io/zoxy#222: a `while (true) ... catch
/// continue` sized for a once-in-2^32 bad scalar met a persistently full heap
/// and spun at 100% CPU forever, taking both listeners and the admin plane
/// with it. An unbounded loop is a claim that some condition always
/// eventually holds; this makes the claim reviewable instead of implicit.
const unbounded_loop_needle = "while (true)";
const unbounded_loop_marker = "lint:unbounded-ok";
const unbounded_loop_message =
    "unbounded `while (true)`: assert a counter bound in the loop body, " ++
    "or mark it `lint:unbounded-ok — <why>` (TIGER_STYLE: put a limit on everything)";

/// Lines after the loop header within which the bound assertion must appear.
/// The assertion belongs at the top of the body, so this is deliberately
/// short — far enough to clear a comment between header and assert, near
/// enough that an unrelated `assert` deeper in the loop cannot satisfy it by
/// accident.
const loop_bound_lookahead_lines: u32 = 6;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1);
    if (args.len != 2) {
        std.debug.print("usage: lint <source-root>\n", .{});
        return 2;
    }

    var root = try std.Io.Dir.cwd().openDir(io, args[1], .{ .iterate = true });
    defer root.close(io);

    var violation_count: u32 = 0;
    var file_count: u32 = 0;
    var walker = try root.walk(arena);
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) {
            continue;
        }
        if (!std.mem.endsWith(u8, entry.path, ".zig")) {
            continue;
        }
        file_count += 1;
        assert(file_count <= files_max);
        const path = try normalizeSeparators(arena, entry.path);
        violation_count += try lintFile(arena, io, root, entry.path, path);
    }
    assert(file_count >= 1);

    if (violation_count > 0) {
        std.debug.print("lint: {d} violation(s)\n", .{violation_count});
        return 1;
    }
    return 0;
}

/// `walked_path` is what the walker handed back and what opens the file;
/// `path` is the same path with '/' separators, which is what the rules and
/// their messages speak. On a '/' host they are the same bytes.
fn lintFile(
    arena: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    walked_path: []const u8,
    path: []const u8,
) !u32 {
    assert(walked_path.len > 0);
    assert(path.len == walked_path.len);
    const contents = try root.readFileAlloc(io, walked_path, arena, .limited(file_bytes_max));
    assert(contents.len < file_bytes_max);

    var violation_count: u32 = 0;
    var line_number: u32 = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        line_number += 1;
        if (lintLine(line, path)) |message| {
            std.debug.print("{s}:{d}: {s}\n", .{ path, line_number, message });
            violation_count += 1;
        }
    }
    assert(line_number >= 1);
    return violation_count + lintUnboundedLoops(contents, path);
}

/// Returns a violation message for the line, or null if the line is clean.
///
/// Diverges from zoxy's original in one place: a comment-only line is exempt.
/// zoxy flags every line because its allowlist could otherwise be ridden by a
/// comment sharing a line with a real call — but a line that is *only* a
/// comment has no call to hide, and every rule here needs to be explainable
/// in prose inside the very files it governs (`src/root.zig` cannot say "this
/// package names no `std.Io`" otherwise). A line carrying both code and a
/// trailing comment is not comment-only, so the original's counter-example
/// stays caught.
fn lintLine(line: []const u8, path: []const u8) ?[]const u8 {
    assert(path.len > 0);
    if (lineIsComment(line)) {
        return null;
    }
    for (boundaries) |boundary| {
        if (pathIsUnder(path, boundary.confined_to)) continue;
        if (std.mem.indexOf(u8, line, boundary.needle) != null) {
            return boundary.message;
        }
    }
    return null;
}

/// Flag every `while (true)` whose bound is neither asserted nor declared. A
/// pass of its own rather than a `lintLine` rule because the evidence is not
/// on the line: the bound lives in the body below the header, which is
/// exactly why a line-at-a-time reader — human or lint — would miss it.
fn lintUnboundedLoops(contents: []const u8, path: []const u8) u32 {
    assert(path.len > 0);
    var violation_count: u32 = 0;
    var offset: usize = 0;
    while (nextUnboundedLoop(contents, offset)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        std.debug.print("{s}:{d}: {s}\n", .{
            path,
            lineNumberAt(contents, at),
            unbounded_loop_message,
        });
        violation_count += 1;
    }
    return violation_count;
}

/// Offset of the next unbounded `while (true)` at or after `from`, or null
/// when the rest is clean. The decision lives here, apart from the report, so
/// a test can make it without printing a violation it went looking for.
fn nextUnboundedLoop(contents: []const u8, from: usize) ?usize {
    assert(from <= contents.len);
    var offset = from;
    // Bounded: every iteration moves `offset` past the match it found, so this
    // runs at most once per occurrence in a file `lintFile` has already held
    // under `file_bytes_max`.
    while (std.mem.indexOfPos(u8, contents, offset, unbounded_loop_needle)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        const start = lineStartOf(contents, at);
        const end = lineEndOf(contents, at);
        assert(start <= at);
        assert(end >= at);
        const line = contents[start..end];
        // A loop named in prose — this file's own doc comments above, or a
        // `// Bounded: …` note — is not a loop.
        if (lineIsComment(line)) continue;
        if (markedUnboundedOk(contents, start, line)) continue;
        if (boundAssertedWithin(contents[end..], loop_bound_lookahead_lines)) continue;
        return at;
    }
    return null;
}

/// The count without the report — what the tests below assert on.
fn countUnboundedLoops(contents: []const u8) u32 {
    var count: u32 = 0;
    var offset: usize = 0;
    while (nextUnboundedLoop(contents, offset)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        count += 1;
    }
    return count;
}

/// True when the loop declares itself structurally bounded: the marker sits
/// either on the header line or on the comment line directly above it. Both
/// are accepted because the reason is what matters and it rarely fits after
/// `while (true) {`.
fn markedUnboundedOk(contents: []const u8, start: usize, line: []const u8) bool {
    assert(start <= contents.len);
    if (std.mem.indexOf(u8, line, unbounded_loop_marker) != null) return true;
    if (start == 0) return false;
    const above_end = start - 1; // The '\n' that ended the line above.
    const above_start = lineStartOf(contents, above_end);
    assert(above_start <= above_end);
    const above = contents[above_start..above_end];
    if (!lineIsComment(above)) return false;
    return std.mem.indexOf(u8, above, unbounded_loop_marker) != null;
}

/// True when one of the next `lines_max` lines asserts an upper bound — any
/// `assert` naming a `<` relation. Deliberately shape-based rather than
/// parsing the counter out of the loop header: the point is that a bound is
/// stated near the top of the body, and every way of writing
/// `assert(n <= max)` should satisfy it.
fn boundAssertedWithin(rest: []const u8, lines_max: u32) bool {
    assert(lines_max >= 1);
    var lines = std.mem.splitScalar(u8, rest, '\n');
    var seen: u32 = 0;
    while (lines.next()) |line| {
        if (seen == lines_max) return false;
        seen += 1;
        if (std.mem.indexOf(u8, line, "assert(") == null) continue;
        // `<=` contains `<`, so the one test covers both relations.
        if (std.mem.indexOfScalar(u8, line, '<') != null) return true;
    }
    assert(seen <= lines_max);
    return false;
}

fn lineStartOf(contents: []const u8, at: usize) usize {
    assert(at < contents.len);
    const newline = std.mem.lastIndexOfScalar(u8, contents[0..at], '\n') orelse return 0;
    assert(newline < at);
    return newline + 1;
}

fn lineEndOf(contents: []const u8, at: usize) usize {
    assert(at < contents.len);
    const newline = std.mem.indexOfScalarPos(u8, contents, at, '\n') orelse return contents.len;
    assert(newline >= at);
    return newline;
}

fn lineNumberAt(contents: []const u8, at: usize) u32 {
    assert(at < contents.len);
    return @intCast(std.mem.count(u8, contents[0..at], "\n") + 1);
}

/// True when the line's first non-blank characters are `//` — a doc comment,
/// a module comment, or an ordinary one.
fn lineIsComment(line: []const u8) bool {
    const trimmed = std.mem.trimStart(u8, line, " \t");
    assert(trimmed.len <= line.len);
    return std.mem.startsWith(u8, trimmed, "//");
}

/// Rewrite '\\' to '/' so the rules can be written one way.
///
/// zoxy's original asserts `std.fs.path.sep == '/'` at comptime instead,
/// which is right for a Linux-only proxy and wrong here: this package is
/// cross-platform, its CI runs on Windows, and a lint that refuses to compile
/// there is a lint that does not run on a third of the matrix. Normalizing is
/// cheap and the confinements stay written with '/'.
fn normalizeSeparators(arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    assert(path.len > 0);
    if (std.mem.indexOfScalar(u8, path, '\\') == null) return path;
    const normalized = try arena.dupe(u8, path);
    std.mem.replaceScalar(u8, normalized, '\\', '/');
    assert(normalized.len == path.len);
    return normalized;
}

/// True when `path` is the file named by `confinement`, or lies under it as a
/// directory prefix. A `confinement` ending in '/' is a directory, anything
/// else an exact file; empty confines a needle to nowhere.
fn pathIsUnder(path: []const u8, confinement: []const u8) bool {
    assert(path.len > 0);
    // The confinements are written in this file, so a stray separator is a
    // typo in a table row, not untrusted input.
    assert(std.mem.indexOfScalar(u8, confinement, '\\') == null);
    if (confinement.len == 0) return false;
    if (confinement[confinement.len - 1] != '/') {
        return std.mem.eql(u8, path, confinement);
    }
    const directory = confinement[0 .. confinement.len - 1];
    assert(directory.len >= 1);
    if (!std.mem.startsWith(u8, path, directory)) return false;
    // A sibling whose name merely starts the same is not under it: the byte
    // after the directory must be the separator, never more name.
    if (path.len == directory.len) return false;
    return path[directory.len] == '/';
}

test "lintLine: I/O types are forbidden everywhere" {
    try std.testing.expect(lintLine("const io = std.Io;", "quic/crypto/protect.zig") != null);
    try std.testing.expect(lintLine("var w: std.Io.Writer = undefined;", "varint.zig") != null);
    try std.testing.expect(lintLine("_ = std.posix.read(fd, buf);", "root.zig") != null);
    try std.testing.expect(lintLine("_ = std.os.linux.close(fd);", "root.zig") != null);
    try std.testing.expect(lintLine("const s = std.net.Stream;", "root.zig") != null);
    try std.testing.expect(lintLine("const f = std.fs.File;", "root.zig") != null);
    try std.testing.expect(lintLine("const decoded = decodeHuffman(source, target);", "qpack.zig") == null);
}

test "lintLine: no allocator, but std.testing.allocator is a different needle" {
    try std.testing.expect(lintLine("fn init(gpa: std.mem.Allocator) void {}", "qpack.zig") != null);
    try std.testing.expect(lintLine("const a = std.testing.allocator;", "qpack.zig") == null);
}

test "lintLine: std.debug.assert is forbidden, the package's own assert is not" {
    // The rule exists because `std.debug.assert` is `if (!ok) unreachable`, and
    // ReleaseFast may delete the check. A convention that is not mechanical
    // drifts back the first time someone types the familiar name.
    try std.testing.expect(lintLine("const assert = std.debug.assert;", "quic/crypto/protect.zig") != null);
    try std.testing.expect(lintLine("    std.debug.assert(index < len);", "quic/frame.zig") != null);
    // The one-liner that evades a `std.debug.assert` needle.
    try std.testing.expect(lintLine("const a = @import(\"std\").debug.assert;", "root.zig") != null);
    try std.testing.expect(lintLine("const assert = @import(\"../assert.zig\").assert;", "quic/crypto/protect.zig") == null);
    try std.testing.expect(lintLine("    assert(index < len);", "quic/frame.zig") == null);
    // `std.debug.print` and the rest of `std.debug` are not the target.
    try std.testing.expect(lintLine("std.debug.print(\"x\", .{});", "root.zig") == null);
}

test "lintLine: @cImport is forbidden" {
    try std.testing.expect(lintLine("const c = @cImport({});", "varint.zig") != null);
}

test "lintLine: a comment-only line explains a rule without tripping it" {
    // The divergence from zoxy's original, and the reason for it: these files
    // have to be able to describe their own constraints.
    try std.testing.expect(lintLine("//! This package never names std.Io.", "root.zig") == null);
    try std.testing.expect(lintLine("    // Not even std.posix here.", "varint.zig") == null);
    // A real call sharing a line with a comment is still caught.
    try std.testing.expect(lintLine("const x = std.posix.read(); // harmless?", "varint.zig") != null);
}

test "lintUnboundedLoops: a bare while (true) is a violation" {
    const source =
        \\fn spin() void {
        \\    while (true) {
        \\        step();
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(source));
}

test "lintUnboundedLoops: an asserted counter bound satisfies the rule" {
    const source =
        \\fn readContinuations() void {
        \\    var frames: u32 = 0;
        \\    while (true) : (frames += 1) {
        \\        assert(frames <= frames_per_packet_max);
        \\        if (done()) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: the marker exempts a structurally-bounded loop" {
    const source =
        \\fn parse() !void {
        \\    while (true) { // lint:unbounded-ok — the block ends at its own length
        \\        if (try next() == .end) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: the marker is accepted on the line above" {
    const source =
        \\fn parse() !void {
        \\    // lint:unbounded-ok — the block ends at its own length
        \\    while (true) {
        \\        if (try next() == .end) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
    // Only *directly* above: a blank line between them breaks the pairing, so
    // a stale marker cannot drift onto an unrelated loop.
    const detached =
        \\fn parse() !void {
        \\    // lint:unbounded-ok — the block ends at its own length
        \\
        \\    while (true) {
        \\        step();
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(detached));
}

test "lintUnboundedLoops: prose about a loop is not a loop" {
    const source =
        \\/// Bounded, unlike a bare `while (true)`, which this is not.
        \\fn ok() void {}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: an assert too far below the header does not count" {
    const source =
        \\while (true) {
        \\    a();
        \\    b();
        \\    c();
        \\    d();
        \\    e();
        \\    f();
        \\    assert(n <= max);
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(source));
}

test "lintUnboundedLoops: each unbounded loop in a file is counted" {
    const source =
        \\while (true) {
        \\    a();
        \\}
        \\while (true) {
        \\    b();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 2), countUnboundedLoops(source));
}

test "normalizeSeparators: a Windows path is rewritten, a POSIX one is not" {
    const arena = std.testing.allocator;
    const posix = try normalizeSeparators(arena, "quic/crypto/protect.zig");
    try std.testing.expectEqualStrings("quic/crypto/protect.zig", posix);
    const windows = try normalizeSeparators(arena, "quic\\crypto\\protect.zig");
    defer arena.free(windows);
    try std.testing.expectEqualStrings("quic/crypto/protect.zig", windows);
}

test "pathIsUnder: exact files, directory prefixes, and near misses" {
    try std.testing.expect(pathIsUnder("quic/crypto/protect.zig", "quic/crypto/protect.zig"));
    try std.testing.expect(!pathIsUnder("quic/crypto/protect_test.zig", "quic/crypto/protect.zig"));
    try std.testing.expect(pathIsUnder("quic/crypto/protect.zig", "quic/"));
    try std.testing.expect(pathIsUnder("quic/crypto/deep.zig", "quic/"));
    // A sibling directory whose name merely starts the same is not under it.
    try std.testing.expect(!pathIsUnder("quicksand/thing.zig", "quic/"));
    try std.testing.expect(!pathIsUnder("quic", "quic/"));
    // An empty spec confines a needle to nowhere.
    try std.testing.expect(!pathIsUnder("anything.zig", ""));
}
