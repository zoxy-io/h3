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
//! It is also **client-only**. The runner's server side needs a certificate, a
//! Retry token and address validation this package's server half does not
//! issue, and the honest form of that is an exit code the runner understands
//! rather than a server that fails every test.
//!
//! ## What it covers, and the two it cannot
//!
//! `handshake`, `transfer`, `chacha20`, `keyupdate`, `multiconnect`,
//! `handshakeloss` and `transferloss`, over `hq-interop` — HTTP/0.9, which is
//! `GET /path\r\n` on a bidirectional stream and the response until the FIN.
//! It is the runner's transport-only application protocol and it exercises
//! exactly what this package implements.
//!
//! Two are refused with exit 127, which is the runner's "unsupported" and the
//! reason the code is not 1:
//!
//! - **`retry`.** `packet.zig` parses a Retry packet and `Connection`
//!   discards it: a client here never re-sends its Initial under the new
//!   Destination Connection ID, never carries the token, and never checks
//!   `retry_source_connection_id`. That is a real gap in `src/`, named in
//!   `packet.zig` as an exception on the *server* side and silently absent on
//!   the client's.
//! - **`http3`.** The control stream and the settings exchange are not built,
//!   so `h3` as an ALPN would be a lie told to a server.
//!
//! A test case this binary has never heard of is also 127. Reporting 1 for an
//! unimplemented feature is how an implementation ends up with a red square
//! that means "not attempted" and a red square that means "wrong" in the same
//! colour.

const std = @import("std");

const h3 = @import("h3");

const tls = @import("tls.zig");

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

const Connection = quic.Connection(.{
    .crypto_octets = 32 * 1024,
    .ack_ranges_max = 64,
    .sent_max = 256,
    .streams_max = requests_max,
    .stream_receive_octets = stream_receive_octets,
    .stream_send_octets = 4 * 1024,
    .connection_receive_octets = connection_receive_octets,
});

/// Datagram buffers. The receive side takes anything the path delivers up to
/// QUIC's own ceiling; the send side is the connection's configured maximum.
const receive_octets: usize = 2048;

/// Connection identifiers, both drawn here because `src/` draws no randomness.
/// Eight octets is what most implementations use and is well inside RFC 9000
/// section 17.2's twenty.
const connection_id_octets: usize = 8;

/// How long a single connection is given before it is abandoned. The runner's
/// own per-test timeout is a minute or more; failing first with a message
/// beats being killed with none.
const connection_deadline_ns: u64 = 60 * std.time.ns_per_s;

/// Datagrams built per flush before the loop goes back to the socket. A bound
/// rather than "until `wantsSend` is false", because a connection that always
/// wants to send is a bug this loop should not turn into a hang.
const flush_datagrams_max: u32 = 64;

/// Streams a single connection will open, which is one per request.
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

    fn parse(name: []const u8) ?Testcase {
        return std.meta.stringToEnum(Testcase, name);
    }

    /// Whether each request gets its own connection. `multiconnect` is the
    /// test case that asks for exactly that; everything else is more honest
    /// multiplexed onto one.
    fn oneConnectionPerRequest(self: Testcase) bool {
        return self == .multiconnect;
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
    // `ROLE`. This one is a client; see the module comment.
    const role = environ.get("ROLE") orelse "client";
    if (!std.mem.eql(u8, role, "client")) {
        try log.print("h3-interop: role '{s}' is not implemented\n", .{role});
        return exit_unsupported;
    }

    const testcase_name = environ.get("TESTCASE") orelse "transfer";
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

    var failed = false;
    if (testcase.oneConnectionPerRequest()) {
        for (requests.items) |one| {
            const only = [_][]const u8{one};
            session.run(io, log, testcase, downloads, key_log, &only, verbose) catch |err| {
                try log.print("h3-interop: {s}: {s}\n", .{ one, @errorName(err) });
                failed = true;
            };
        }
    } else {
        session.run(io, log, testcase, downloads, key_log, requests.items, verbose) catch |err| {
            try log.print("h3-interop: {s}\n", .{@errorName(err)});
            failed = true;
        };
    }

    return if (failed) 1 else 0;
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
};

const Session = struct {
    connection: Connection = undefined,
    client: tls.Client = undefined,
    requests: [requests_max]Request = undefined,
    requests_len: usize = 0,
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
        urls: []const []const u8,
        verbose: bool,
    ) !void {
        self.verbose = verbose;
        std.debug.assert(urls.len > 0);
        if (urls.len > requests_max) return error.TooManyRequests;

        const first = try Url.parse(urls[0]);
        const peer = try Io.net.IpAddress.resolve(io, first.host, first.port);

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
        self.requests_len = 0;
        self.since_key_update = 0;
        self.key_updated_ns = 0;
        self.key_updates = 0;

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
            .initial_max_streams_uni = 0,
            .max_udp_payload_size = Connection.datagram_octets,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = source,
        });

        self.client = .init(.{
            .server_name = first.host,
            .alpn = "hq-interop",
            .transport_parameters = parameters_buffer[0..parameters_octets],
            .offer = testcase.offer(),
            .random = seed[0..32].*,
            .key_seed = seed[32..64].*,
        });

        var hello_buffer: [2048]u8 = undefined;
        const hello = try self.client.clientHello(&hello_buffer);
        try self.connection.cryptoIn(.initial, hello);

        // Files are opened before the handshake so that a directory that does
        // not exist fails immediately rather than after a successful transfer.
        var directory = try Io.Dir.cwd().openDir(io, downloads, .{});
        defer directory.close(io);
        for (urls, 0..) |text, index| {
            const url = try Url.parse(text);
            const file = try directory.createFile(io, url.fileName(), .{});
            // RFC 9000 section 2.1: client-initiated bidirectional streams are
            // numbered 0, 4, 8 — the two least significant bits are the type.
            self.requests[index] = .{
                .url = url,
                .stream = @as(u64, index) * 4,
                .file = file,
                .writer = undefined,
            };
            self.requests[index].writer = file.writer(io, &self.requests[index].buffer);
            self.requests_len += 1;
        }
        defer for (self.requests[0..self.requests_len]) |*request| {
            request.writer.interface.flush() catch {};
            request.file.close(io);
        };

        var requests_sent = false;
        var receive_buffer: [receive_octets]u8 = undefined;

        // Bounded by the deadline: every iteration either moves data or waits,
        // and the wait is capped by `deadlineFor`.
        while (true) {
            const now = elapsed(io, origin);
            if (now > connection_deadline_ns) return error.Timeout;

            try self.pumpCrypto(log, key_log);
            if (self.verbose) try note(log, "state {s} at {d}ms", .{ @tagName(self.connection.state), now / std.time.ns_per_ms });

            if (!requests_sent and self.connection.state == .established) {
                for (self.requests[0..self.requests_len]) |*request| {
                    var line_buffer: [512]u8 = undefined;
                    // HTTP/0.9, which is the whole of `hq-interop`'s request.
                    const line = try std.fmt.bufPrint(&line_buffer, "GET {s}\r\n", .{request.url.path});
                    const written = try self.connection.write(request.stream, line, true);
                    if (written != line.len) return error.RequestTooLarge;
                }
                requests_sent = true;
            }

            try self.drainStreams(testcase, now);
            self.drainEvents();

            try self.flush(io, log, &socket, &peer, now);

            if (self.complete()) break;
            if (self.connection.state == .draining) return error.PeerClosed;

            const wait = self.deadlineFor(io, origin);
            const message = socket.receiveTimeout(io, &receive_buffer, wait) catch |err| switch (err) {
                error.Timeout => {
                    self.connection.onTimeout(elapsed(io, origin));
                    continue;
                },
                else => return err,
            };
            if (self.verbose) try note(log, "received {d} octets", .{message.data.len});
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

        for (self.requests[0..self.requests_len]) |*request| {
            try request.writer.interface.flush();
            try log.print("h3-interop: {s} {d} octets\n", .{ request.url.path, request.octets });
        }
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

    /// Take whatever is readable on each request's stream and write it out.
    fn drainStreams(self: *Session, testcase: Testcase, now_ns: u64) !void {
        for (self.requests[0..self.requests_len]) |*request| {
            if (request.complete) continue;
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
            const stream = self.connection.findStream(request.stream) orelse continue;
            if (stream.receive_state == .data_read) request.complete = true;
            if (stream.receive_state == .reset) return error.StreamReset;
        }

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
    fn drainEvents(self: *Session) void {
        // Bounded: the queue is fixed and `poll` removes what it returns.
        for (0..events_per_drain_max) |_| {
            _ = self.connection.poll() orelse return;
        }
    }

    /// Build and send datagrams until the connection has nothing more.
    fn flush(self: *Session, io: Io, log: *Io.Writer, socket: *Io.net.Socket, peer: *const Io.net.IpAddress, now_ns: u64) !void {
        for (0..flush_datagrams_max) |_| {
            const octets = try self.connection.send(&self.datagram, now_ns);
            if (octets == 0) return;
            try socket.send(io, peer, self.datagram[0..octets]);
            if (self.verbose) try note(log, "sent {d} octets at {d}ms", .{ octets, now_ns / std.time.ns_per_ms });
        }
    }

    /// When to wake, as the socket wants it: the loss detection timer if there
    /// is one, and the connection's own deadline otherwise.
    fn deadlineFor(self: *Session, io: Io, origin: Io.Timestamp) Io.Timeout {
        const now = elapsed(io, origin);
        const at = self.connection.timeout() orelse connection_deadline_ns;
        const wait = if (at > now) at - now else 0;
        return .{ .duration = .{ .raw = .{ .nanoseconds = @intCast(wait) }, .clock = .awake } };
    }

    fn complete(self: *const Session) bool {
        for (self.requests[0..self.requests_len]) |*request| {
            if (!request.complete) return false;
        }
        return true;
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
    try testing.expectEqual(@as(?Testcase, null), Testcase.parse("retry"));
    try testing.expectEqual(@as(?Testcase, null), Testcase.parse("http3"));
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
