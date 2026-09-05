//! A qlog file, which is where `src/qlog.zig`'s records go.
//!
//! The split is the same one the rest of this package makes: the library turns
//! a record into octets and this opens a file and writes them. The interop
//! runner names the directory in `QLOGDIR` and expects one file per connection,
//! named for the connection so that two endpoints' traces of the same
//! connection can be put side by side.
//!
//! A trace that cannot be opened is not an error. The runner sets `QLOGDIR`
//! only sometimes, the directory may not exist, and a shim that refused to run
//! a test because it could not write a log would be failing the test for the
//! log's sake. A trace that *can* be opened and then goes wrong is a different
//! thing, and this file is careful to leave no half-written one behind: a
//! header that fails to go out closes the file, because a `.sqlog` whose first
//! record is not the header is not a shorter trace, it is an unreadable one
//! that looks complete.

const std = @import("std");
const h3 = @import("h3");

const Io = std.Io;
const assert = std.debug.assert;

/// Octets buffered before a write reaches the file. A trace is written from the
/// same loop that drives the connection, so this is what keeps a `metrics`
/// record per datagram from being a syscall per datagram.
const buffer_octets = 16 * 1024;

/// Room for one record. Taken from the library rather than guessed at: this was
/// a local `1024` with a comment claiming it was "the largest record
/// `src/qlog.zig` produces", which that file guaranteed nothing about.
const record_octets = h3.qlog.record_octets_max;

/// A connection identifier in hex, which is what a trace is named for.
const group_octets = h3.qlog.group_id_octets_max;

/// `<group>.sqlog`, and the longest group there can be.
const name_octets = group_octets + ".sqlog".len;

pub const Trace = struct {
    file: ?Io.File = null,
    writer: Io.File.Writer = undefined,
    vantage: h3.qlog.VantagePoint = .client,
    buffer: [buffer_octets]u8 = undefined,
    scratch: [record_octets]u8 = undefined,
    /// Records that never reached the file, because they did not fit or a write
    /// failed. `finish` says so rather than leaving the hole silent: a trace
    /// that admits to a gap is worth more than one that looks complete.
    dropped: u32 = 0,

    /// Begin a trace, if there is anywhere to put one.
    ///
    /// `self` is written in place and must not be moved afterwards: `writer`
    /// holds a pointer into `buffer`, and `record` asserts that it still does.
    pub fn start(
        self: *Trace,
        io: Io,
        directory: ?Io.Dir,
        connection_id: []const u8,
        vantage: h3.qlog.VantagePoint,
    ) void {
        // Whatever was here is closed first. Without this a caller that starts
        // a second connection on the same `Trace` — which is what the client
        // does, once per request in `multiconnect` — leaks the first file
        // rather than replacing it.
        self.finish(io);
        self.* = .{ .vantage = vantage };

        const where = directory orelse return;
        assert(connection_id.len <= h3.quic.ConnectionId.octets_max);

        var group: [group_octets]u8 = undefined;
        const group_id = hex(&group, connection_id);
        var name_buffer: [name_octets]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, "{s}.sqlog", .{group_id}) catch return;

        const file = where.createFile(io, name, .{}) catch return;
        self.file = file;
        self.writer = file.writer(io, &self.buffer);

        const written = h3.qlog.header(&self.scratch, .{
            .group_id = group_id,
            .vantage_point = vantage,
            .code_version = "h3",
        }) catch {
            self.abandon(io);
            return;
        };
        self.writer.interface.writeAll(self.scratch[0..written]) catch {
            self.abandon(io);
        };
    }

    pub fn record(self: *Trace, at_ns: u64, one: h3.qlog.Record) void {
        if (self.file == null) return;
        // The pointer the writer holds is into this struct's own buffer, so a
        // `Trace` that was moved would be writing into the copy it came from.
        // The comment on `start` says so; this is the check that means it.
        assert(self.writer.interface.buffer.ptr == &self.buffer);
        const written = h3.qlog.event(&self.scratch, self.vantage, at_ns, one) catch {
            self.dropped += 1;
            return;
        };
        self.writer.interface.writeAll(self.scratch[0..written]) catch {
            self.dropped += 1;
        };
    }

    /// Flush and close. Safe to call on a trace that was never started, and on
    /// one that has already been finished — both are the ordinary path, because
    /// the callers that own a `Trace` do not all know which they hold.
    pub fn finish(self: *Trace, io: Io) void {
        const file = self.file orelse return;
        assert(self.writer.interface.buffer.ptr == &self.buffer);
        // A failed flush loses up to `buffer_octets` of trace tail, which is
        // the largest hole this file can have. Counted for the same reason
        // every other one is.
        self.writer.interface.flush() catch {
            self.dropped += 1;
        };
        file.close(io);
        self.file = null;
    }

    /// Give up on a trace that was opened and could not be started properly.
    fn abandon(self: *Trace, io: Io) void {
        const file = self.file orelse return;
        file.close(io);
        self.file = null;
        self.dropped += 1;
    }
};

/// Lower-case hex, which is how every qlog writer spells a connection
/// identifier and therefore how a reader expects to find it.
///
/// Asserts rather than truncating. The result names a *file* as well as the
/// trace inside it, so two identifiers sharing a prefix would write to one file
/// and be read as one connection — which is worse than any failure this shim
/// could report.
fn hex(target: []u8, source: []const u8) []const u8 {
    assert(source.len * 2 <= target.len);
    const digits = "0123456789abcdef";
    var length: usize = 0;
    // Bounded by `source`, and by the assertion above within `target`.
    for (source) |octet| {
        target[length] = digits[octet >> 4];
        target[length + 1] = digits[octet & 0x0f];
        length += 2;
    }
    assert(length == source.len * 2);
    return target[0..length];
}

const testing = std.testing;

test "an identifier is spelled in lower-case hex" {
    var buffer: [group_octets]u8 = undefined;
    try testing.expectEqualStrings("83a4c2f1", hex(&buffer, &.{ 0x83, 0xa4, 0xc2, 0xf1 }));
    // The longest identifier RFC 9000 section 17.2 allows, which is what
    // `group_octets` is sized for — the case that used to truncate.
    const longest: [h3.quic.ConnectionId.octets_max]u8 = @splat(0xab);
    try testing.expectEqual(@as(usize, group_octets), hex(&buffer, &longest).len);
}

test "a trace with nowhere to go writes nothing and reports nothing dropped" {
    var trace: Trace = .{};
    // `start` is what would open the file; without a directory it does not, and
    // every record after it is a no-op rather than a crash. This is the
    // ordinary case: the runner sets `QLOGDIR` only sometimes.
    trace.record(0, .{ .packets_lost = 1 });
    try testing.expectEqual(@as(u32, 0), trace.dropped);
}
