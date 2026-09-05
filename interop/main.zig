//! The QUIC Interop Runner client, and the first thing in this tree to talk to
//! an implementation that did not come from it.
//!
//! docs/VERIFICATION.md section 5.5: every other gate here is fed by this
//! package. The unit tests, the fuzz targets and the simulator all encode one
//! reading of seven RFCs, and a misreading shared between the encoder and the
//! decoder passes all three. `corpus/qifs.zig` was the cheap half of the
//! answer and it only reaches QPACK's representation choices. This is the
//! other half: a real handshake with somebody else's server, over a real
//! socket, with the runner's own loss and reordering in the path.
//!
//! ## What this is not
//!
//! It is **not part of the library** and never ships: `build.zig.zon`'s
//! `paths` lists `src` and nothing here, and `zig build lint` does not reach
//! this directory. That is deliberate rather than an oversight — everything
//! `src/` forbids is here, because the runner's contract requires it. A UDP
//! socket, a clock, an allocator, an entropy draw and a TLS handshake, all in
//! one binary, all on the far side of the seam docs/DESIGN.md section 3 draws.
//!
//! It answers **both roles**. `ROLE=server` runs `server.zig` under the
//! runner's contract — port 443, `/www` for the files, `/certs` for the key —
//! and issues a Retry when the `retry` case asks for one. The server's list of
//! supported cases is shorter than the client's, and `ServerTestcase` says why
//! each absence is an absence.
//!
//! ## What it covers, and the two it cannot
//!
//! `handshake`, `transfer`, `chacha20`, `keyupdate`, `multiconnect`,
//! `handshakeloss` and `transferloss`, over `hq-interop` — HTTP/0.9, which is
//! `GET /path\r\n` on a bidirectional stream and the response until the FIN.
//! It is the runner's transport-only application protocol and it exercises
//! exactly what this package implements.
//!
//! `http3` runs HTTP/3 proper — `Http3` opens the control stream, exchanges
//! SETTINGS, and sequences HEADERS and DATA — while every other case uses
//! `hq-interop`, which is HTTP/0.9 and exercises the transport without the
//! framing on top of it.
//!
//! `retry` works too, and needs nothing from this file beyond asking for it:
//! `Connection.receiveRetry` adopts the server's identifier, re-derives the
//! Initial keys, carries the token into every subsequent Initial and checks
//! `retry_source_connection_id` against the handshake. It was the first gap
//! this directory named and it is closed.
//!
//! A test case this binary has never heard of — `zerortt`, `amplificationlimit`,
//! `resumption` — is exit 127, which is the runner's "unsupported". Reporting 1 for an
//! unimplemented feature is how an implementation ends up with a red square
//! that means "not attempted" and a red square that means "wrong" in the same
//! colour.

const std = @import("std");

const h3 = @import("h3");

const server_role = @import("server.zig");
const tls = @import("tls.zig");
const qlog_file = @import("qlog_file.zig");

const assert = std.debug.assert;

const Io = std.Io;
const quic = h3.quic;

/// The runner's own exit code for "this implementation does not claim to
/// support this test case". Anything else is a result.
const exit_unsupported: u8 = 127;

/// Where the runner expects downloaded files, when it does not say.
const downloads_default = "/downloads";

/// One connection's limits, which for a comptime-sized library is one type.
///
/// `crypto_octets` is the field the interop runner actually moves: a
/// certificate chain with an intermediate is comfortably past the 8 KiB
/// default, and RFC 9001 section 4.4 makes running out of room a connection
/// error rather than a stall — so a default that is too small fails as
/// `CRYPTO_BUFFER_EXCEEDED` on the handshake of a server that did nothing
/// wrong.
const stream_receive_octets: u32 = 128 * 1024;
const connection_receive_octets: u64 = 1 << 20;

/// Requests and unidirectional streams, both ways.
///
/// RFC 9000 section 3.2 makes an identifier at index N mean N+1 streams of that
/// kind exist, so whatever this endpoint advertises is a claim the peer can
/// make on the table all at once — and the same again for what it opens itself.
/// A table smaller than that answers a conforming peer with STREAM_LIMIT_ERROR,
/// which is this endpoint's sizing mistake reported as the peer's protocol
/// error.
const streams_max: u32 = 2 * (requests_max + unidirectional_max);

const Connection = quic.Connection(.{
    .crypto_octets = 32 * 1024,
    .ack_ranges_max = 64,
    .sent_max = 256,
    .streams_max = streams_max,
    .stream_receive_octets = stream_receive_octets,
    .stream_send_octets = 4 * 1024,
    .connection_receive_octets = connection_receive_octets,
});

/// RFC 9114 section 6.2 and RFC 9204 section 4.2: a control stream, a QPACK
/// encoder stream and a QPACK decoder stream, each way.
const unidirectional_max: u32 = 4;

const Http3 = h3.Http3(.{
    .requests_max = requests_max,
    .unidirectional_max = 2 * unidirectional_max,
});

/// Datagram buffers. The receive side takes anything the path delivers up to
/// QUIC's own ceiling; the send side is the connection's configured maximum.
const receive_octets: usize = 2048;

/// Connection identifiers, both drawn here because `src/` draws no randomness.
/// Eight octets is what most implementations use and is well inside RFC 9000
/// section 17.2's twenty.
const connection_id_octets: usize = 8;

/// How long a single connection is given before it is abandoned, when it is one
/// of many.
///
/// The runner's arithmetic rather than taste. `handshakeloss` is fifty
/// connections in three hundred seconds — it sets `TESTCASE=multiconnect` on
/// the endpoints — so a connection that stalls and holds a sixty-second
/// deadline is not one failure but ten: the ones that never got their turn.
const connection_deadline_short_ns: u64 = 30 * std.time.ns_per_s;

/// And when it is the only one. `transferloss` is a single connection carrying
/// a large file through a lossy path, where the same ten seconds is the
/// difference between slow and failed.
///
/// One constant would have to be wrong for one of the two, which is why there
/// are two: the shim knows which case it is running, and the runner's own
/// budgets differ by case for the same reason.
///
/// The short one was ten seconds, and ten seconds is a deadline this shim
/// invented. `handshakeloss` is fifty connections in three hundred, so the
/// budget is six apiece on average and nothing says any one of them may not
/// take longer — and under 30% loss the tail does. A connection abandoned at
/// ten seconds fails a run the runner would have allowed to finish, which is
/// the shim losing a result rather than the package failing to produce one.
const connection_deadline_long_ns: u64 = 60 * std.time.ns_per_s;

/// Datagrams built per flush before the loop goes back to the socket. A bound
/// rather than "until `wantsSend` is false", because a connection that always
/// wants to send is a bug this loop should not turn into a hang.
const flush_datagrams_max: u32 = 64;

/// Requests a single connection will carry, which is one per URL.
const requests_max: u32 = 8;

/// 1-RTT octets between key updates in the `keyupdate` test case. The runner
/// asks the client to update at least once during a transfer; this updates
/// repeatedly so that a transfer too short to reach the threshold is not
/// silently a test that did nothing.
const key_update_interval_octets: u64 = 64 * 1024;

/// And the minimum time between them, which is the half that is not optional.
///
/// RFC 9001 section 6.5 tells an endpoint to retain the old keys for three
/// times the PTO after an update, and section 6.1 not to start another until
/// the current phase is acknowledged. `canUpdateKeys` answers the second, and
/// **cannot answer the first**: it reads no clock, by the rule that makes the
/// rest of `src/` testable. Spacing updates in time is therefore the consumer's
/// job, and this is the consumer.
///
/// Learned from ngtcp2 rather than from the RFC. Over loopback, 64 KiB of a
/// 1 MiB transfer goes by in a millisecond, so the octet threshold alone fired
/// a second update about one round trip after the first: quic-go and aioquic
/// both accepted it and ngtcp2 stopped answering. Two implementations agreeing
/// with us was not evidence that we were right — which is the argument for this
/// whole directory, arriving as a bug in the directory itself.
const key_update_interval_ns: u64 = 1 * std.time.ns_per_s;

/// RFC 9000 section 2.1: client-initiated unidirectional streams are 2, 6, 10.
/// Fixed rather than allocated, because there are exactly three of them and
/// their order is this endpoint's choice.
const control_stream: u64 = 2;
const qpack_encoder_stream: u64 = 6;
const qpack_decoder_stream: u64 = 10;

/// Events taken from `Connection.poll` per pass. Larger than the connection's
/// own queue, so a pass always empties it.
const events_per_drain_max: u32 = 256;

const Testcase = enum {
    handshake,
    transfer,
    chacha20,
    keyupdate,
    multiconnect,
    handshakeloss,
    transferloss,
    retry,
    http3,

    fn parse(name: []const u8) ?Testcase {
        return std.meta.stringToEnum(Testcase, name);
    }

    /// Whether each request gets its own connection. `multiconnect` is the
    /// test case that asks for exactly that; everything else is more honest
    /// multiplexed onto one.
    fn oneConnectionPerRequest(self: Testcase) bool {
        return self == .multiconnect;
    }

    /// How long one connection may take. See the two constants.
    fn deadlineNs(self: Testcase) u64 {
        return if (self.oneConnectionPerRequest())
            connection_deadline_short_ns
        else
            connection_deadline_long_ns;
    }

    /// The application protocol. `http3` is the only case that runs HTTP/3
    /// proper; everything else uses `hq-interop`, which is HTTP/0.9 and
    /// exercises the transport without the framing on top of it.
    fn alpn(self: Testcase) []const u8 {
        return if (self == .http3) "h3" else "hq-interop";
    }

    /// `chacha20` asks the client to offer nothing but
    /// `TLS_CHACHA20_POLY1305_SHA256`, so that the server has no way to
    /// negotiate around it.
    fn offer(self: Testcase) []const tls.CipherSuite {
        return switch (self) {
            .chacha20 => &.{.chacha20_poly1305_sha256},
            else => &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 },
        };
    }
};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;
    const environ = init.environ_map;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buffer);
    const log = &stderr.interface;
    defer log.flush() catch {};

    // The runner runs the same image as client and as server and picks with
    // `ROLE`.
    const role = environ.get("ROLE") orelse "client";
    const testcase_name = environ.get("TESTCASE") orelse "transfer";

    if (std.mem.eql(u8, role, "server")) {
        const supported = ServerTestcase.parse(testcase_name) orelse {
            try log.print("h3-interop: server test case '{s}' is not implemented\n", .{testcase_name});
            return exit_unsupported;
        };
        return runServer(init, log, supported);
    }
    if (!std.mem.eql(u8, role, "client")) {
        try log.print("h3-interop: role '{s}' is not implemented\n", .{role});
        return exit_unsupported;
    }

    const testcase = Testcase.parse(testcase_name) orelse {
        try log.print("h3-interop: test case '{s}' is not implemented\n", .{testcase_name});
        return exit_unsupported;
    };

    const requests_line = environ.get("REQUESTS") orelse {
        try log.print("h3-interop: REQUESTS is empty\n", .{});
        return 1;
    };
    const downloads = environ.get("DOWNLOADS") orelse downloads_default;
    const verbose = environ.get("VERBOSE") != null;

    // One writer for the process, not one per secret. Opening the file again
    // for each line rewinds it: the first version of this wrote four secrets
    // over each other and left the last, which looks exactly like a handshake
    // that only derived one.
    var key_log_file: ?Io.File = null;
    var key_log_buffer: [512]u8 = undefined;
    var key_log_writer: Io.File.Writer = undefined;
    var key_log: ?*Io.Writer = null;
    if (environ.get("SSLKEYLOGFILE")) |path| {
        if (Io.Dir.cwd().createFile(io, path, .{})) |file| {
            key_log_file = file;
            key_log_writer = file.writer(io, &key_log_buffer);
            key_log = &key_log_writer.interface;
        } else |err| {
            try log.print("h3-interop: SSLKEYLOGFILE {s}: {s}\n", .{ path, @errorName(err) });
        }
    }
    defer if (key_log_file) |file| {
        if (key_log) |writer| writer.flush() catch {};
        file.close(io);
    };

    // The interop runner names a directory and expects one trace per
    // connection in it. Absent, unwritable or not there at all is the ordinary
    // case rather than an error: a shim that refused to run a test because it
    // could not write a log would be failing the test for the log's sake.
    var qlog_directory = try qlogDirectory(io, log, environ);
    defer if (qlog_directory) |*directory| directory.close(io);

    var requests: std.ArrayList([]const u8) = .empty;
    defer requests.deinit(gpa);
    var fields = std.mem.tokenizeAny(u8, requests_line, " \t\r\n");
    while (fields.next()) |one| try requests.append(gpa, one);
    if (requests.items.len == 0) {
        try log.print("h3-interop: REQUESTS held no URLs\n", .{});
        return 1;
    }

    // The whole connection is one value, and it is far too large for a stack
    // frame: the four flow control windows dominate `footprint_octets` and
    // docs/DESIGN.md section 5 is explicit that a connection belongs in an
    // arena.
    const session = try gpa.create(Session);
    defer gpa.destroy(session);

    // Resolved once, not once per connection. `multiconnect` and
    // `handshakeloss` open fifty connections to the same authority, and a name
    // lookup that costs seconds — as it does inside the interop runner, where
    // the only answer is in `/etc/hosts` and the resolver still consults the
    // network — turns fifty fast connections into a test that times out. The
    // measurement said so plainly: every connection finished in under two
    // seconds and seventeen of fifty finished at all.
    const first = try Url.parse(requests.items[0]);
    const resolve_start = Io.Timestamp.now(io, .awake);
    const peer = try resolve(io, first.host, first.port);
    const resolve_ms = @divTrunc(resolve_start.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, std.time.ns_per_ms);
    if (verbose) try note(log, "resolved {s} in {d}ms", .{ first.host, resolve_ms });

    var failed = false;
    if (testcase.oneConnectionPerRequest()) {
        for (requests.items) |one| {
            const only = [_][]const u8{one};
            session.run(io, log, testcase, downloads, key_log, qlog_directory, &only, verbose, peer) catch |err| {
                try log.print("h3-interop: {s}: {s}\n", .{ one, @errorName(err) });
                failed = true;
            };
        }
    } else {
        session.run(io, log, testcase, downloads, key_log, qlog_directory, requests.items, verbose, peer) catch |err| {
            try log.print("h3-interop: {s}\n", .{@errorName(err)});
            failed = true;
        };
    }

    return if (failed) 1 else 0;
}

/// What the server role answers to.
///
/// A shorter list than the client's, and the difference is not accidental. A
/// client can be pointed at a conforming server and either work or not; a
/// server has to *provoke* the behaviour each case tests, and the ones absent
/// here need something this package does not build: a NEW_TOKEN frame for
/// `resumption`, an early-data key for `zerortt`, a second connection ID for
/// `connectionmigration`, ECN for `ecn`, a second version for `v2`.
const ServerTestcase = enum {
    handshake,
    transfer,
    chacha20,
    multiplexing,
    retry,
    http3,
    amplificationlimit,
    handshakeloss,
    transferloss,
    handshakecorruption,
    transfercorruption,
    multiconnect,
    longrtt,
    blackhole,
    ipv6,
    goodput,
    crosstraffic,

    fn parse(name: []const u8) ?ServerTestcase {
        return std.meta.stringToEnum(ServerTestcase, name);
    }

    /// Whether to answer every first flight with a Retry. RFC 9000 section
    /// 8.1.2 leaves *when* to a server, and the runner's `retry` case is the
    /// answer "always".
    fn retries(self: ServerTestcase) bool {
        return self == .retry;
    }
};

/// The runner's server contract: port 443, `/www` for the files, `/certs` for
/// the key, and everything else from the environment.
fn runServer(init: std.process.Init, log: *Io.Writer, testcase: ServerTestcase) !u8 {
    const io = init.io;
    const gpa = init.gpa;
    const environ = init.environ_map;

    const certificate_path = environ.get("CERT") orelse "/certs/cert.pem";
    const key_path = environ.get("KEY") orelse "/certs/priv.key";
    const www_path = environ.get("WWW") orelse "/www";
    const port_text = environ.get("PORT") orelse "443";
    const port = std.fmt.parseInt(u16, port_text, 10) catch {
        try log.print("h3-interop: PORT '{s}' is not a number\n", .{port_text});
        return 1;
    };

    const certificate_pem = try readAll(io, gpa, certificate_path);
    defer gpa.free(certificate_pem);
    const key_pem = try readAll(io, gpa, key_path);
    defer gpa.free(key_pem);

    var www = Io.Dir.cwd().openDir(io, www_path, .{}) catch |err| {
        try log.print("h3-interop: {s}: {s}\n", .{ www_path, @errorName(err) });
        return 1;
    };
    defer www.close(io);

    var qlog = try qlogDirectory(io, log, environ);
    defer if (qlog) |*directory| directory.close(io);

    try server_role.run(io, gpa, log, .{
        .port = port,
        .certificate_pem = certificate_pem,
        .private_key_pem = key_pem,
        .www = www,
        .qlog = qlog,
        .retry = testcase.retries(),
        .verbose = environ.get("VERBOSE") != null,
    });
    return 0;
}

/// Where a per-connection qlog goes, or null.
///
/// The interop runner names a directory and expects one trace per connection in
/// it. Absent, unwritable or not there at all is the ordinary case rather than
/// an error: a shim that refused to run a test because it could not write a log
/// would be failing the test for the log's sake. One function because both
/// roles want exactly this and had a verbatim copy each.
fn qlogDirectory(io: Io, log: *Io.Writer, environ: *std.process.Environ.Map) !?Io.Dir {
    const path = environ.get("QLOGDIR") orelse return null;
    return Io.Dir.cwd().openDir(io, path, .{}) catch |err| {
        try log.print("h3-interop: QLOGDIR {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };
}

fn readAll(io: Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return try reader.interface.allocRemaining(gpa, .unlimited);
}

/// An address for a host name.
///
/// `IpAddress.resolve` parses a literal and otherwise goes straight to DNS,
/// which is not where the interop runner puts its names: `server4` lives in
/// `/etc/hosts`, written by docker from the compose file's `extra_hosts`.
/// `HostName.lookup` is the call that reads it — and reaching for the shorter
/// function first is why this client worked against every server on loopback
/// and could not find one inside the runner.
fn resolve(io: Io, host: []const u8, port: u16) !Io.net.IpAddress {
    if (Io.net.IpAddress.parse(host, port)) |literal| return literal else |_| {}

    const name = try Io.net.HostName.init(host);
    // Sixteen is what `lookup` needs to be guaranteed not to block, and more
    // than any name here resolves to.
    var results: [16]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&results);
    var task = io.async(Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port } });
    defer task.cancel(io) catch {};

    // The first address wins. A client that tried each in turn would be a
    // client with a connection policy, and this one has a single connection.
    while (queue.getOne(io)) |result| switch (result) {
        .address => |address| return address,
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        else => |e| return e,
    }
    return error.UnknownHostName;
}

/// A URL split into the three parts this client needs. `hq-interop` has no
/// notion of a query or a fragment, and the runner never sends one.
const Url = struct {
    host: []const u8,
    port: u16,
    path: []const u8,

    fn parse(text: []const u8) !Url {
        const scheme = "https://";
        if (!std.mem.startsWith(u8, text, scheme)) return error.UnsupportedScheme;
        const rest = text[scheme.len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const authority = rest[0..slash];
        const path = if (slash < rest.len) rest[slash..] else "/";

        // An IPv6 literal in brackets would put colons in the authority; the
        // runner uses names, and refusing beats parsing the wrong half.
        if (std.mem.indexOfScalar(u8, authority, '[') != null) return error.UnsupportedAuthority;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
            return .{
                .host = authority[0..colon],
                .port = try std.fmt.parseInt(u16, authority[colon + 1 ..], 10),
                .path = path,
            };
        }
        return .{ .host = authority, .port = 443, .path = path };
    }

    /// The name the downloaded body is written under: the last path segment,
    /// or `index` for a path that ends in a slash.
    fn fileName(self: Url) []const u8 {
        const trimmed = std.mem.trimEnd(u8, self.path, "/");
        const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return "index";
        const name = trimmed[slash + 1 ..];
        return if (name.len == 0) "index" else name;
    }
};

/// One request in flight: the stream it was sent on and the file its body is
/// being written to.
const Request = struct {
    url: Url,
    stream: u64,
    file: Io.File,
    writer: Io.File.Writer,
    buffer: [4096]u8 = undefined,
    octets: u64 = 0,
    complete: bool = false,
    /// Whether this slot holds a request at all.
    ///
    /// The slots are a *window* over the request list rather than the whole of
    /// it: `multiplexing` asks for 1999 files on one connection, which is more
    /// identifiers than a connection has room for at once. A finished slot is
    /// reused in place — `writer` holds a pointer into `buffer`, so a slot that
    /// moved would leave the writer pointing at another request's bytes.
    in_use: bool = false,
};

const Session = struct {
    connection: Connection = undefined,
    client: tls.Client = undefined,
    /// RFC 9114's sequencing, used only by the `http3` test case.
    http3: Http3 = undefined,
    /// Whether this endpoint's control and QPACK streams have gone out.
    http3_started: bool = false,
    /// Streams the connection has reported data on, so that a pass can drain
    /// each of them once. HTTP/3 needs this and `hq-interop` does not: a
    /// response arrives on a stream this endpoint opened, but the peer's
    /// control stream is one only an event can announce.
    readable: [streams_max]u64 = undefined,
    readable_len: usize = 0,
    requests: [requests_max]Request = undefined,
    /// Slots initialised, which only ever grows to `requests_max`. Whether a
    /// slot holds a live request is `in_use`.
    requests_len: usize = 0,
    /// The request list, and how far into it the window has reached.
    pending: []const []const u8 = &.{},
    next_url: usize = 0,
    next_stream: u64 = 0,
    finished: usize = 0,
    /// This connection's qlog, if the runner asked for one. Held here rather
    /// than passed around because its writer points into its own buffer, so it
    /// must not move.
    trace: qlog_file.Trace = .{},
    /// How many key updates this connection has seen, for the trace. Not the
    /// key *phase*, which alternates — qlog wants a number that only rises.
    key_generation: u64 = 0,

    /// A scratch datagram, held here rather than on the stack for the same
    /// reason the connection is.
    datagram: [Connection.datagram_octets]u8 = undefined,
    /// 1-RTT octets received since the last key update, for `keyupdate`.
    since_key_update: u64 = 0,
    /// When the last key update was initiated, for `key_update_interval_ns`.
    key_updated_ns: u64 = 0,
    /// Key updates this connection has initiated, reported at the end so that
    /// a `keyupdate` run that never reached the threshold is visibly a run that
    /// tested nothing.
    key_updates: u32 = 0,
    /// Whether to narrate the loop on stderr. The runner keeps a client's
    /// stderr next to its packet capture, and a shim that says nothing when it
    /// fails is a shim whose failures all look alike.
    verbose: bool = false,

    /// Run one connection to completion: handshake, requests, bodies, close.
    fn run(
        self: *Session,
        io: Io,
        log: *Io.Writer,
        testcase: Testcase,
        downloads: []const u8,
        key_log: ?*Io.Writer,
        qlog_directory: ?Io.Dir,
        urls: []const []const u8,
        verbose: bool,
        peer: Io.net.IpAddress,
    ) !void {
        self.verbose = verbose;
        std.debug.assert(urls.len > 0);
        self.pending = urls;

        const first = try Url.parse(urls[0]);

        const any: Io.net.IpAddress = switch (peer) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        var socket = try any.bind(io, .{ .mode = .dgram });
        defer socket.close(io);

        // The clock. `src/` takes `now_ns` as a parameter and reads no clock;
        // this is the caller that owns one, and the origin is the connection's
        // start so that the value stays inside a `u64` of nanoseconds.
        const origin = Io.Timestamp.now(io, .awake);

        var seed: [64]u8 = undefined;
        try io.randomSecure(&seed);
        var identifiers: [2 * connection_id_octets]u8 = undefined;
        try io.randomSecure(&identifiers);

        const destination = try quic.ConnectionId.init(identifiers[0..connection_id_octets]);
        const source = try quic.ConnectionId.init(identifiers[connection_id_octets..]);
        self.connection = .init(.{
            .side = .client,
            .original_destination = destination,
            .source = source,
        });
        // Named for the original Destination Connection ID, which is the one
        // value both endpoints agree on before either has chosen anything —
        // and therefore the one that lets two traces of the same connection be
        // put side by side.
        self.trace.start(io, qlog_directory, destination.bytes(), .client);
        // Immediately, not at the end of the setup below. There are four `try`s
        // between here and the end of it — one of them an `openDir` that is
        // *expected* to fail when the runner's download directory is missing —
        // and a `Session` is reused for the next connection, so a return in
        // between used to leak the file rather than close it.
        defer self.trace.finish(io);
        // The same numbers the transport parameters below carry. Without this
        // the stream layer enforces the table's size instead, which is larger
        // than what was offered — so a peer opening past the advertised limit
        // would be admitted, and section 3.2's implicit creation would then
        // spend table slots this endpoint had promised to nobody.
        self.connection.streams.setAdvertisedStreamLimits(requests_max, unidirectional_max);
        self.requests_len = 0;
        // Reset with it, because `Session` is reused across connections and
        // these three are what say how far through the request list this
        // *connection* has got. Carrying `finished` forward made `complete()`
        // answer true before the second connection had sent anything: the loop
        // broke on its first pass, `run` returned success, and the shim
        // reported "1 of 1 requests in 0ms" for forty-nine connections that
        // never happened. `multiconnect` is the only case that opens more than
        // one, so nothing else could have noticed.
        self.finished = 0;
        self.next_url = 0;
        self.next_stream = 0;
        self.key_generation = 0;
        self.since_key_update = 0;
        self.key_updated_ns = 0;
        self.key_updates = 0;
        self.http3 = .init(.client);
        self.http3_started = false;
        self.readable_len = 0;

        // The transport parameters this endpoint advertises. They are its
        // comptime limits and not a policy: a `Connection` enforces what it was
        // built with, so advertising anything else would be advertising a
        // window it will not honour. `initial_source_connection_id` is the
        // identifier the peer is being asked to address us by, which is what
        // section 7.3 has the peer check.
        var parameters_buffer: [512]u8 = undefined;
        const parameters_octets = try quic.transport_parameters.encode(&parameters_buffer, &.{
            .initial_max_data = connection_receive_octets,
            .initial_max_stream_data_bidi_local = stream_receive_octets,
            .initial_max_stream_data_bidi_remote = stream_receive_octets,
            .initial_max_stream_data_uni = stream_receive_octets,
            .initial_max_streams_bidi = requests_max,
            // Zero here refused the peer's control stream, which is how an
            // `http3` run fails before it starts: a server that cannot open one
            // cannot send SETTINGS, and a client that never sees SETTINGS is
            // talking to nobody.
            .initial_max_streams_uni = unidirectional_max,
            .max_udp_payload_size = Connection.datagram_octets,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = source,
        });

        self.client = .init(.{
            .server_name = first.host,
            .alpn = testcase.alpn(),
            .transport_parameters = parameters_buffer[0..parameters_octets],
            .offer = testcase.offer(),
            .random = seed[0..32].*,
            .key_seed = seed[32..64].*,
        });

        var hello_buffer: [2048]u8 = undefined;
        const hello = try self.client.clientHello(&hello_buffer);
        try self.connection.cryptoIn(.initial, hello);

        // Opened before the handshake so that a directory that does not exist
        // fails immediately rather than after a successful transfer. The files
        // themselves are opened as each request is issued, because 1999 of them
        // at once is more descriptors than a process is given.
        var directory = try Io.Dir.cwd().openDir(io, downloads, .{});
        defer directory.close(io);
        defer for (self.requests[0..self.requests_len]) |*request| {
            if (!request.in_use) continue;
            request.writer.interface.flush() catch {};
            request.file.close(io);
        };

        var receive_buffer: [receive_octets]u8 = undefined;

        // Bounded by the deadline: every iteration either moves data or waits,
        // and the wait is capped by `deadlineFor`.
        while (true) {
            const now = elapsed(io, origin);
            if (now > testcase.deadlineNs()) return error.Timeout;

            try self.pumpCrypto(log, key_log);
            if (self.verbose) try note(log, "state {s} at {d}ms", .{ @tagName(self.connection.state), now / std.time.ns_per_ms });

            if (self.connection.state == .established and !self.http3_started and testcase == .http3) {
                try self.startHttp3();
            }
            if (self.connection.state == .established) {
                try self.issue(io, log, testcase, &directory);
            }

            if (testcase == .http3) try self.drainHttp3(log) else try self.drainStreams(now);
            // On both paths. `drainStreams` never consults `readable`, so an
            // `hq-interop` run grew the list to `streams_max` and then dropped
            // identifiers in silence — which is the defect `compactReadable`
            // was written for, left in place on the other half of the fork.
            self.compactReadable();
            try self.keyUpdate(testcase, now);
            try self.drainEvents(log, now);
            try self.reap(io, log, origin);

            try self.flush(io, log, &socket, &peer, now);

            if (self.complete()) break;
            if (self.connection.state == .draining) return error.PeerClosed;

            const wait = self.deadlineFor(io, origin);
            const message = socket.receiveTimeout(io, &receive_buffer, wait) catch |err| switch (err) {
                error.Timeout => {
                    const at = elapsed(io, origin);
                    self.connection.onTimeout(at);
                    if (self.verbose) try note(log, "timer at {d}ms: wantsSend={any}", .{
                        at / std.time.ns_per_ms,
                        self.connection.wantsSend(),
                    });
                    continue;
                },
                else => return err,
            };
            if (self.verbose) try note(log, "received {d} octets", .{message.data.len});
            self.trace.record(elapsed(io, origin), .{ .datagrams_received = .{
                .count = 1,
                .octets = message.data.len,
            } });
            self.connection.receive(message.data, elapsed(io, origin)) catch |err| switch (err) {
                // A datagram that does not parse or does not authenticate is
                // discarded by the connection itself; what reaches here is a
                // protocol error, and section 10.2 says close rather than
                // ignore.
                else => {
                    try log.print("h3-interop: receive: {s}\n", .{@errorName(err)});
                    return err;
                },
            };
        }

        // Section 10.2: a clean close is one CONNECTION_CLOSE, sent once. The
        // runner does not require it and the servers do not wait for it, but a
        // client that vanishes leaves the server's connection to time out and
        // makes the next test case's logs harder to read.
        self.connection.close(.no_error);
        try self.flush(io, log, &socket, &peer, elapsed(io, origin));

        try log.print("h3-interop: {d} of {d} requests in {d}ms\n", .{
            self.finished,
            self.pending.len,
            elapsed(io, origin) / std.time.ns_per_ms,
        });
        if (testcase == .keyupdate) {
            try log.print("h3-interop: {d} key updates\n", .{self.key_updates});
        }
    }

    /// Move handshake octets between the connection and the TLS client, in
    /// both directions, and install whatever the schedule produced.
    fn pumpCrypto(self: *Session, log: *Io.Writer, key_log: ?*Io.Writer) !void {
        for ([_]quic.crypto.Level{ .initial, .handshake, .one_rtt }) |level| {
            const available = self.connection.cryptoOut(level);
            if (available.len == 0) continue;
            if (self.verbose) try note(log, "crypto {s}: {d} octets", .{ @tagName(level), available.len });
            const consumed = self.client.read(level, available) catch |err| {
                try log.print("h3-interop: tls at {s}: {s}\n", .{ @tagName(level), @errorName(err) });
                return err;
            };
            self.connection.cryptoConsumed(level, consumed);
        }

        for (self.client.drainInstalls()) |one| {
            var secret = try quic.crypto.Secret.init(&one.secret);
            // Switched rather than forwarded: `installSecret`'s direction is an
            // anonymous enum declared in its own signature, so the two types
            // are distinct even though the tags are the same.
            switch (one.direction) {
                .send => try self.connection.installSecret(one.level, .send, &secret, one.suite),
                .receive => try self.connection.installSecret(one.level, .receive, &secret, one.suite),
            }
            if (key_log) |writer| try writeKeyLog(writer, one.label, &self.client.random, &one.secret);
        }

        if (self.client.drainTransportParameters()) |octets| {
            try self.connection.transportParametersIn(octets);
        }

        const finished = self.client.drainFinished();
        if (finished.len > 0) try self.connection.cryptoIn(.handshake, finished);
    }

    /// RFC 9114 section 6.2: this endpoint's three unidirectional streams, sent
    /// as soon as there are 1-RTT keys to send them under.
    ///
    /// The QPACK streams carry their type octet and nothing else, ever. This
    /// endpoint advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so it will
    /// never encode a dynamic table instruction — but section 4.2 of RFC 9204
    /// still expects the streams to exist, and a server that waits for them
    /// before sending its own response is a server this client would hang on.
    fn startHttp3(self: *Session) !void {
        var buffer: [256]u8 = undefined;
        const control = try self.http3.writeControl(&buffer);
        if (try self.connection.write(control_stream, buffer[0..control], false) != control) {
            return error.RequestTooLarge;
        }
        const encoder = try h3.stream.write(&buffer, .qpack_encoder);
        _ = try self.connection.write(qpack_encoder_stream, buffer[0..encoder], false);
        const decoder = try h3.stream.write(&buffer, .qpack_decoder);
        _ = try self.connection.write(qpack_decoder_stream, buffer[0..decoder], false);
        self.http3_started = true;
    }

    /// One request, as a HEADERS frame. RFC 9114 section 4.3.1's four
    /// pseudo-headers and nothing else: `hq-interop`'s request line, spelled
    /// the way HTTP/3 spells it.
    fn writeRequest(self: *Session, target: []u8, url: Url) ![]const u8 {
        var authority: [256]u8 = undefined;
        const host = try std.fmt.bufPrint(&authority, "{s}:{d}", .{ url.host, url.port });
        const written = try self.http3.writeHeaders(target, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = host },
            .{ .name = ":path", .value = url.path },
        });
        return target[0..written];
    }

    /// Drive `Http3` over every stream the connection has reported data on.
    fn drainHttp3(self: *Session, log: *Io.Writer) !void {
        var index: usize = 0;
        // Bounded by `readable_len`, which is bounded by the stream table.
        while (index < self.readable_len) : (index += 1) {
            const id = self.readable[index];
            // A stream the connection has given up is one both halves have
            // finished with, so there is nothing more coming on it. Reading
            // that as "not yet" loses the FIN when the last of a body and the
            // end of the stream land in the same pass — the response is whole
            // and the client waits for it anyway.
            const stream = self.connection.findStream(id) orelse {
                if (self.requestFor(id)) |request| request.complete = true;
                continue;
            };
            if (stream.receive_state == .reset) return error.StreamReset;
            const data = self.connection.readable(id);
            // Whether the FIN sits at the end of what is readable now. A
            // half-arrived frame followed by a FIN is a truncated message, and
            // `Http3` has to be told which it is looking at.
            const fin = if (stream.received.final_size) |size|
                size == stream.consumed + data.len
            else
                false;
            if (data.len == 0 and !fin) continue;

            var events: [16]h3.http3.Event = undefined;
            const result = self.http3.receive(id, data, fin, &events) catch |err| {
                try note(log, "http3 on stream {d}: {s} (0x{x})", .{
                    id,
                    @errorName(err),
                    @intFromEnum(h3.http3.code(err)),
                });
                return err;
            };
            for (events[0..result.events]) |event| try self.applyHttp3(log, event);
            if (result.consumed > 0) try self.connection.consume(id, result.consumed);
            self.since_key_update += result.consumed;
        }
        self.compactReadable();
    }

    fn applyHttp3(self: *Session, log: *Io.Writer, event: h3.http3.Event) !void {
        switch (event) {
            .settings => |value| try note(log, "peer settings: table {d}, blocked {d}, section {d}", .{
                value.qpack_max_table_capacity,
                value.qpack_blocked_streams,
                value.max_field_section_size,
            }),
            .headers => |value| {
                // Decoded and validated here rather than in `Http3`: a decoded
                // field list is far larger than the section it came from, and
                // the buffer it needs is the caller's.
                var buffer: [16 * 1024]u8 = undefined;
                var iterator = try h3.qpack.field_line.iterate(value.section, &buffer, 1 << 20);
                var validator: h3.fields.MessageValidator = .init(.{
                    .kind = if (value.trailers) .trailer else .response,
                });
                while (try iterator.next()) |field| {
                    try validator.field(&field);
                    if (std.mem.eql(u8, field.name, ":status")) {
                        try note(log, "stream {d}: status {s}", .{ value.stream, field.value });
                    }
                }
                try validator.finish();
            },
            .data => |value| {
                const request = self.requestFor(value.stream) orelse return;
                try request.writer.interface.writeAll(value.payload);
                request.octets += value.payload.len;
            },
            .finished => |id| {
                const request = self.requestFor(id) orelse return;
                request.complete = true;
                self.http3.release(id);
            },
            .goaway => |id| try note(log, "peer is going away at {d}", .{id}),
        }
    }

    fn requestFor(self: *Session, id: u64) ?*Request {
        // Bounded by `requests_len`.
        for (self.requests[0..self.requests_len]) |*request| {
            if (request.in_use and request.stream == id) return request;
        }
        return null;
    }

    /// Drop the identifiers whose streams are gone, so the list does not fill
    /// up and start refusing new ones. See `interop/server.zig`, which had the
    /// same defect and showed it first.
    fn compactReadable(self: *Session) void {
        assert(self.readable_len <= self.readable.len);
        var kept: usize = 0;
        // Bounded by `readable_len`.
        for (self.readable[0..self.readable_len]) |id| {
            if (self.connection.findStream(id) == null) continue;
            self.readable[kept] = id;
            kept += 1;
        }
        assert(kept <= self.readable.len);
        self.readable_len = kept;
    }

    /// Remember that a stream has data, once.
    fn noteReadable(self: *Session, id: u64) void {
        // Bounded by `readable_len`.
        for (self.readable[0..self.readable_len]) |one| {
            if (one == id) return;
        }
        if (self.readable_len == self.readable.len) return;
        self.readable[self.readable_len] = id;
        self.readable_len += 1;
    }

    /// `hq-interop`: the response body is the stream, with no framing at all.
    fn drainStreams(self: *Session, now_ns: u64) !void {
        _ = now_ns;
        for (self.requests[0..self.requests_len]) |*request| {
            if (!request.in_use or request.complete) continue;
            const readable = self.connection.readable(request.stream);
            if (readable.len > 0) {
                try request.writer.interface.writeAll(readable);
                // Consumed only after it is written: `consume` is what moves
                // the flow control window, and moving it for octets that were
                // not stored would be asking for more of what was lost.
                try self.connection.consume(request.stream, readable.len);
                request.octets += readable.len;
                self.since_key_update += readable.len;
            }
            // A stream that is no longer in the table is one the connection
            // has given up, which it does only when both halves are finished.
            // Reading that as "not there yet" is a client that waits for a
            // response it already has.
            const stream = self.connection.findStream(request.stream) orelse {
                request.complete = true;
                continue;
            };
            if (stream.receive_state == .data_read) request.complete = true;
            if (stream.receive_state == .reset) return error.StreamReset;
        }
    }

    /// RFC 9001 section 6's key update, for the test case that asks for one.
    fn keyUpdate(self: *Session, testcase: Testcase, now_ns: u64) !void {
        if (testcase != .keyupdate) return;
        // Three conditions, and only one of them is the library's. RFC 9001
        // section 6.1's "the current phase has been acknowledged" is
        // `canUpdateKeys`; section 6.5's spacing in time is
        // `key_update_interval_ns` and is the consumer's because the library
        // reads no clock; the octet threshold is this shim's own, so that a
        // `keyupdate` run does something.
        if (self.since_key_update < key_update_interval_octets) return;
        // The first update is spaced only by the octet threshold: a transfer
        // that finishes in less than `key_update_interval_ns` would otherwise
        // update never, and a `keyupdate` run that updates no keys passes
        // without testing anything.
        if (self.key_updates > 0 and now_ns - self.key_updated_ns < key_update_interval_ns) return;
        if (!self.connection.canUpdateKeys()) return;
        self.connection.updateKeys();
        self.since_key_update = 0;
        self.key_updated_ns = now_ns;
        self.key_updates += 1;
    }

    /// Drain the connection's event queue. Nothing here needs an event that
    /// the accessors do not also answer — but `overflowed` is a real signal
    /// and a queue polled by nobody is a queue that reports its own overflow
    /// to nobody.
    fn drainEvents(self: *Session, log: *Io.Writer, now_ns: u64) !void {
        // Bounded: the queue is fixed and `poll` removes what it returns.
        for (0..events_per_drain_max) |_| {
            const event = self.connection.poll() orelse return;
            // The trace takes what it can name and ignores the rest. This is
            // the whole of what a qlog from this seam can say about the
            // connection's own behaviour — see `src/qlog.zig` on why there are
            // no packet events.
            switch (event) {
                .packets_lost => |count| self.trace.record(now_ns, .{ .packets_lost = count }),
                .key_updated => {
                    // The generation counts updates and only rises; the phase
                    // alternates. Two facts, and qlog has a field for each.
                    self.key_generation += 1;
                    self.trace.record(now_ns, .{ .key_updated = .{
                        .generation = self.key_generation,
                        .phase = @intFromBool(self.connection.one_rtt.phase),
                        .owner = .local,
                    } });
                },
                .closed => |value| self.trace.record(now_ns, .{
                    .connection_closed = .{
                        .code = value.code,
                        .application = value.application,
                        // `Event.closed` is only emitted for a close that *arrived*.
                        .owner = .remote,
                    },
                }),
                .stream_delivered => |id| self.trace.record(now_ns, .{ .stream_state = .{
                    .stream_id = id,
                    .state = .closed,
                } }),
                else => {},
            }
            switch (event) {
                // The one event worth a line whether or not the run is
                // verbose: a peer's close carries the reason the transfer
                // stopped, and reporting "the peer closed" without the code
                // throws away the only thing that says why.
                .closed => |value| try note(log, "peer closed: code 0x{x} application={any}", .{ value.code, value.application }),
                .stream_reset => |value| try note(log, "stream {d} reset: code 0x{x}", .{ value.stream, value.code }),
                .overflowed => |count| try note(log, "{d} events dropped", .{count}),
                // Which stream, so that `drainHttp3` can find the peer's
                // control stream — a stream this endpoint never opened and
                // could not otherwise know the identifier of.
                .stream_readable => |id| self.noteReadable(id),
                else => {},
            }
        }
    }

    /// Build and send datagrams until the connection has nothing more.
    fn flush(self: *Session, io: Io, log: *Io.Writer, socket: *Io.net.Socket, peer: *const Io.net.IpAddress, now_ns: u64) !void {
        var count: u32 = 0;
        var total: u64 = 0;
        defer if (count > 0) {
            self.trace.record(now_ns, .{ .datagrams_sent = .{ .count = count, .octets = total } });
            self.traceMetrics(now_ns);
        };
        for (0..flush_datagrams_max) |_| {
            const octets = try self.connection.send(&self.datagram, now_ns);
            if (octets == 0) return;
            try socket.send(io, peer, self.datagram[0..octets]);
            count += 1;
            total += octets;
            if (self.verbose) try note(log, "sent {d} octets at {d}ms", .{ octets, now_ns / std.time.ns_per_ms });
        }
    }

    /// What a congestion plot is drawn from, read straight off `Recovery`.
    ///
    /// Once per flush rather than once per packet: the numbers only move when
    /// something is sent or acknowledged, and a record per packet is what makes
    /// a trace larger than the transfer it describes.
    fn traceMetrics(self: *Session, now_ns: u64) void {
        const recovery = &self.connection.recovery;
        assert(recovery.smoothed_rtt > 0);
        self.trace.record(now_ns, .{ .metrics = .{
            .smoothed_rtt_ns = recovery.smoothed_rtt,
            .rtt_variance_ns = recovery.rttvar,
            .latest_rtt_ns = recovery.latest_rtt,
            .congestion_window = recovery.congestion_window,
            .bytes_in_flight = recovery.bytes_in_flight,
            .pto_count = recovery.pto_count,
        } });
    }

    /// When to wake, as the socket wants it: the loss detection timer if there
    /// is one, and the connection's own deadline otherwise.
    fn deadlineFor(self: *Session, io: Io, origin: Io.Timestamp) Io.Timeout {
        const now = elapsed(io, origin);
        const at = self.connection.timeout() orelse connection_deadline_long_ns;
        const wait = if (at > now) at - now else 0;
        return .{ .duration = .{ .raw = .{ .nanoseconds = @intCast(wait) }, .clock = .awake } };
    }

    fn complete(self: *const Session) bool {
        // `>=` with the assertion beside it, rather than `==`. An equality is
        // the comparison that turns a counter which has run ahead of itself
        // into a connection that never finishes and reports a timeout — and a
        // counter running ahead is exactly the defect this shim already had
        // once, when `finished` carried across connections.
        assert(self.finished <= self.pending.len);
        return self.finished >= self.pending.len;
    }

    /// Open as many requests as the window and the peer's stream limit allow.
    ///
    /// Called every pass rather than once: a slot frees when a response is
    /// complete, and section 4.6's limit rises as the peer's MAX_STREAMS
    /// arrive, so what can be asked for changes over the life of a connection.
    fn issue(self: *Session, io: Io, log: *Io.Writer, testcase: Testcase, directory: *Io.Dir) !void {
        assert(self.next_url <= self.pending.len);
        // Bounded by the window, which is `requests_max`.
        for (0..requests_max) |_| {
            if (self.next_url >= self.pending.len) return;
            const slot = self.free() orelse return;
            const id = self.next_stream;
            // The peer decides how many identifiers this endpoint may use, and
            // writing to one it has not permitted is a connection error at the
            // far end rather than a short write here.
            if (!self.connection.streams.peerPermits(id)) return;

            const url = try Url.parse(self.pending[self.next_url]);
            const file = try directory.createFile(io, url.fileName(), .{});
            slot.* = .{ .url = url, .stream = id, .file = file, .writer = undefined, .in_use = true };
            slot.writer = file.writer(io, &slot.buffer);
            self.next_url += 1;
            // RFC 9000 section 2.1: client-initiated bidirectional streams are
            // numbered 0, 4, 8 — the two least significant bits are the type,
            // and the assertion is what keeps that a fact rather than a comment.
            assert(self.next_stream % 4 == 0);
            self.next_stream += 4;
            assert(self.next_url <= self.pending.len);

            var line_buffer: [1024]u8 = undefined;
            const line = if (testcase == .http3)
                try self.writeRequest(&line_buffer, url)
            else
                // HTTP/0.9, which is the whole of `hq-interop`'s request.
                try std.fmt.bufPrint(&line_buffer, "GET {s}\r\n", .{url.path});
            const written = try self.connection.write(id, line, true);
            if (written != line.len) return error.RequestTooLarge;
            if (self.verbose) try note(log, "stream {d}: GET {s}", .{ id, url.path });
        }
    }

    /// A slot with nothing in it, growing the window until it is full.
    ///
    /// A grown slot is made inert before it is counted. `requests` is
    /// `undefined`, and `issue` can decline to fill the slot it asked for —
    /// the peer's stream limit refuses the identifier, or the file will not
    /// open — so a slot counted in `requests_len` and never written is an
    /// undefined `in_use` that every loop over the window then reads. Garbage
    /// that reads true wedges the window shut; garbage that reads true in
    /// `reap` counts a request that never happened, which is the same class of
    /// defect as the completion counter that used to carry across connections.
    fn free(self: *Session) ?*Request {
        assert(self.requests_len <= requests_max);
        // Bounded by `requests_len`.
        for (self.requests[0..self.requests_len]) |*request| {
            if (!request.in_use) return request;
        }
        if (self.requests_len == requests_max) return null;
        const slot = &self.requests[self.requests_len];
        slot.* = .{
            .url = undefined,
            .stream = 0,
            .file = undefined,
            .writer = undefined,
            .in_use = false,
        };
        self.requests_len += 1;
        assert(!slot.in_use);
        return slot;
    }

    /// Close what has finished, so the slot and the file both go back.
    fn reap(self: *Session, io: Io, log: *Io.Writer, origin: Io.Timestamp) !void {
        // Bounded by `requests_len`.
        for (self.requests[0..self.requests_len]) |*request| {
            if (!request.in_use or !request.complete) continue;
            try request.writer.interface.flush();
            request.file.close(io);
            request.in_use = false;
            request.complete = false;
            self.finished += 1;
            assert(self.finished <= self.pending.len);
            if (self.verbose) try note(log, "{s} {d} octets in {d}ms", .{
                request.url.path,
                request.octets,
                elapsed(io, origin) / std.time.ns_per_ms,
            });
        }
    }
};

/// One narration line, flushed. Buffered would be worse than silent: the
/// interesting runs are the ones that are killed by a timeout, and a buffer
/// that never flushed loses exactly the lines that say where it stopped.
fn note(log: *Io.Writer, comptime format: []const u8, arguments: anytype) !void {
    try log.print("h3-interop: " ++ format ++ "\n", arguments);
    try log.flush();
}

/// Nanoseconds since the connection began, which is the `now_ns` every entry
/// point in `src/` takes.
fn elapsed(io: Io, origin: Io.Timestamp) u64 {
    const now = Io.Timestamp.now(io, .awake);
    const difference = origin.durationTo(now).nanoseconds;
    // `.awake` is monotonic, so this cannot be negative; the cast is what says
    // so out loud.
    std.debug.assert(difference >= 0);
    return @intCast(difference);
}

/// NSS's key log format, which is what a packet capture needs to be readable.
/// The runner collects it and it is the difference between "the transfer
/// failed" and knowing which frame it failed on.
fn writeKeyLog(out: *Io.Writer, label: []const u8, random: *const [32]u8, secret: []const u8) !void {
    try out.print("{s} {x} {x}\n", .{ label, random, secret });
    // Flushed per line: a capture is read while the connection is still open,
    // and a secret still in a buffer decrypts nothing.
    try out.flush();
}

const testing = std.testing;

test "a URL splits into a host, a port and a path" {
    const one = try Url.parse("https://server4:443/abcdefg");
    try testing.expectEqualStrings("server4", one.host);
    try testing.expectEqual(@as(u16, 443), one.port);
    try testing.expectEqualStrings("/abcdefg", one.path);
    try testing.expectEqualStrings("abcdefg", one.fileName());

    const two = try Url.parse("https://server4/");
    try testing.expectEqualStrings("server4", two.host);
    try testing.expectEqual(@as(u16, 443), two.port);
    try testing.expectEqualStrings("/", two.path);
    try testing.expectEqualStrings("index", two.fileName());

    const three = try Url.parse("https://example.org:4433/a/b/c.bin");
    try testing.expectEqual(@as(u16, 4433), three.port);
    try testing.expectEqualStrings("c.bin", three.fileName());
}

test "a URL this client cannot use is refused rather than guessed at" {
    try testing.expectError(error.UnsupportedScheme, Url.parse("http://server4/x"));
    try testing.expectError(error.UnsupportedAuthority, Url.parse("https://[::1]:443/x"));
}

test "an unknown test case is unsupported rather than a failure" {
    // The distinction the runner draws, and the reason `main` returns 127 for
    // one and 1 for the other: a red square meaning "not attempted" and a red
    // square meaning "wrong" are not the same result.
    try testing.expectEqual(@as(?Testcase, null), Testcase.parse("zerortt"));
    try testing.expectEqual(@as(?Testcase, null), Testcase.parse("amplificationlimit"));
    try testing.expectEqual(@as(?Testcase, .retry), Testcase.parse("retry"));
    try testing.expectEqual(@as(?Testcase, .http3), Testcase.parse("http3"));
    try testing.expectEqual(@as(?Testcase, .transfer), Testcase.parse("transfer"));
}

test "chacha20 offers exactly one cipher suite" {
    // The point of the test case: a client that also offers AES lets the
    // server choose it, and the run proves nothing about ChaCha20.
    const offer = Testcase.chacha20.offer();
    try testing.expectEqual(@as(usize, 1), offer.len);
    try testing.expectEqual(tls.CipherSuite.chacha20_poly1305_sha256, offer[0]);
    try testing.expect(Testcase.transfer.offer().len > 1);
}

test "an address literal resolves without a name server" {
    // The other half — a name out of `/etc/hosts` — needs a host to have one,
    // and the interop runner is where that is exercised: `server4` is written
    // there by docker from the compose file's `extra_hosts`. This is the half
    // that can be checked here, and it is the half `IpAddress.resolve` already
    // did, which is why reaching for the shorter function looked right until
    // the runner asked for a name.
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const address = try resolve(io, "127.0.0.1", 4433);
    try testing.expectEqual(@as(u16, 4433), address.getPort());
    try testing.expect(address == .ip4);
}

test {
    // `qlog_file`'s own tests, which do not run unless something references
    // the module. `src/qlog.zig` was written, wired in and passing for an hour
    // before anyone noticed that none of its tests had ever executed, because
    // `src/root.zig` did not name it either — and the first one to run failed.
    _ = qlog_file;
}
