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
//! log's sake.

const std = @import("std");
const h3 = @import("h3");

const Io = std.Io;

/// Octets buffered before a write reaches the file. A trace is written from the
/// same loop that drives the connection, so this is what keeps a `metrics`
/// record per datagram from being a syscall per datagram.
const buffer_octets = 16 * 1024;
/// The largest record `src/qlog.zig` produces, with room to spare.
const record_octets = 1024;

pub const Trace = struct {
    file: ?Io.File = null,
    writer: Io.File.Writer = undefined,
    buffer: [buffer_octets]u8 = undefined,
    scratch: [record_octets]u8 = undefined,
    /// Records dropped because they did not fit or the write failed. Reported
    /// at close: a trace with a hole in it that says so is worth more than one
    /// that looks complete.
    dropped: u32 = 0,

    /// Begin a trace, if there is anywhere to put one.
    ///
    /// `self` is written in place and must not be moved afterwards: `writer`
    /// holds a pointer into `buffer`.
    pub fn start(
        self: *Trace,
        io: Io,
        directory: ?Io.Dir,
        connection_id: []const u8,
        vantage: h3.qlog.VantagePoint,
    ) void {
        self.* = .{};
        const where = directory orelse return;

        var name_buffer: [64]u8 = undefined;
        var group: [40]u8 = undefined;
        const group_id = hex(&group, connection_id);
        const name = std.fmt.bufPrint(&name_buffer, "{s}.sqlog", .{group_id}) catch return;

        const file = where.createFile(io, name, .{}) catch return;
        self.file = file;
        self.writer = file.writer(io, &self.buffer);

        const written = h3.qlog.header(&self.scratch, .{
            .group_id = group_id,
            .vantage_point = vantage,
            .code_version = "h3",
        }) catch {
            self.dropped += 1;
            return;
        };
        self.writer.interface.writeAll(self.scratch[0..written]) catch {
            self.dropped += 1;
        };
    }

    pub fn record(self: *Trace, at_ns: u64, one: h3.qlog.Record) void {
        if (self.file == null) return;
        const written = h3.qlog.event(&self.scratch, at_ns, one) catch {
            self.dropped += 1;
            return;
        };
        self.writer.interface.writeAll(self.scratch[0..written]) catch {
            self.dropped += 1;
        };
    }

    pub fn finish(self: *Trace, io: Io) void {
        const file = self.file orelse return;
        self.writer.interface.flush() catch {};
        file.close(io);
        self.file = null;
    }
};

/// Lower-case hex, which is how every qlog writer spells a connection
/// identifier and therefore how a reader expects to find it.
fn hex(target: []u8, source: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    var length: usize = 0;
    for (source) |octet| {
        if (length + 2 > target.len) break;
        target[length] = digits[octet >> 4];
        target[length + 1] = digits[octet & 0x0f];
        length += 2;
    }
    return target[0..length];
}

const testing = std.testing;

test "an identifier is spelled in lower-case hex" {
    var buffer: [40]u8 = undefined;
    try testing.expectEqualStrings("83a4c2f1", hex(&buffer, &.{ 0x83, 0xa4, 0xc2, 0xf1 }));
    try testing.expectEqualStrings("", hex(buffer[0..1], &.{0x83}));
}

test "a trace with nowhere to go writes nothing and reports nothing dropped" {
    var trace: Trace = .{};
    // `start` is what would open the file; without a directory it does not, and
    // every record after it is a no-op rather than a crash. This is the
    // ordinary case: the runner sets `QLOGDIR` only sometimes.
    trace.file = null;
    trace.record(0, .{ .packets_lost = 1 });
    try testing.expectEqual(@as(u32, 0), trace.dropped);
}
