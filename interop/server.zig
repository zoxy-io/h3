//! The HTTP/3 server role, for [h3spec](https://github.com/kazu-yamamoto/h3spec).
//!
//! h3spec is a conformance tester for HTTP/3 **servers**: it connects as a
//! client and checks what the server does with input a client should never
//! send. docs/VERIFICATION.md section 5.5 named it as what comes after the
//! interop runner, and it needs the one role `interop/main.zig` does not have.
//!
//! The interop runner's server role would need the same code and a little
//! more — a Retry token, and address validation this package does not issue —
//! so `ROLE=server` there still exits 127. This binary is pointed at by hand.
//!
//! ## What a server needs that a client does not
//!
//! - **A certificate and a signature.** `tls.Server` signs the transcript with
//!   the P-256 key it is handed. The certificate is sent verbatim: nothing
//!   here parses X.509, because nothing here has to decide whether to trust
//!   one.
//! - **An application close.** h3spec's assertions are mostly of the form
//!   "the server MUST send H3_FRAME_UNEXPECTED", which is a CONNECTION_CLOSE
//!   of type 0x1d carrying a code from the application's registry.
//!   `Connection.closeApplication` arrived with this file, and with it RFC
//!   9000 section 10.2.3's conversion to a transport close below 1-RTT — a
//!   rule that had held by construction because no application close could be
//!   built.
//! - **Several connections at once.** h3spec opens one per test case and does
//!   not always wait, so the table below is keyed by the Destination
//!   Connection ID this endpoint chose, which is what a client puts in every
//!   packet after the first.
//!
//! ## What it serves
//!
//! A 200 with a short body, for any request whose field section validates
//! under RFC 9114 section 4.3. That is all h3spec asks for: the tests are
//! about what happens on malformed input, and a server that answered nothing
//! at all would pass the error cases and fail every control.

const std = @import("std");

const h3 = @import("h3");

const tls = @import("tls.zig");

const Io = std.Io;
const quic = h3.quic;

/// Connections held at once. h3spec runs its cases in sequence but does not
/// wait for a connection to drain before starting the next, and a server that
/// dropped the previous one would fail the case that is still finishing.
const connections_max: usize = 16;

/// Requests, plus this endpoint's three unidirectional streams and the peer's
/// three, with room for the reserved stream types section 6.2.3 sends to prove
/// an implementation ignores what it does not know.
const requests_max: u32 = 8;
const unidirectional_max: u32 = 8;
const streams_max: u32 = requests_max + 2 * unidirectional_max;

const stream_receive_octets: u32 = 128 * 1024;
const connection_receive_octets: u64 = 1 << 20;

const Connection = quic.Connection(.{
    .crypto_octets = 32 * 1024,
    .ack_ranges_max = 64,
    .sent_max = 256,
    .streams_max = streams_max,
    .stream_receive_octets = stream_receive_octets,
    .stream_send_octets = 64 * 1024,
    .connection_receive_octets = connection_receive_octets,
});

const Http3 = h3.Http3(.{
    .requests_max = requests_max,
    .unidirectional_max = unidirectional_max,
});

/// RFC 9000 section 2.1: server-initiated unidirectional streams are 3, 7, 11.
const control_stream: u64 = 3;
const qpack_encoder_stream: u64 = 7;
const qpack_decoder_stream: u64 = 11;

const receive_octets: usize = 2048;
const connection_id_octets: usize = 8;
/// How long a silent connection is kept. h3spec's own per-case timeout is two
/// seconds by default, so anything quiet for longer than this is over.
///
/// Retirement matters more here than it looks. A table that fills up answers
/// nothing, and a server that answers nothing looks to h3spec exactly like a
/// server that failed to detect the error under test — which is how a run of
/// 49 cases showed sixteen passes and thirty-three "did not get expected
/// exception" while every one of them passed alone.
///
/// It was five seconds for that reason, and five seconds is a deadline rather
/// than a policy: on the runner's lossy path a peer's own probe timeout backs
/// off past it, so this server dropped connections its peer was still working
/// on and then answered nothing for the rest of their idle timeout. What keeps
/// the table clear is `accept` evicting the least recently heard from when it
/// is full, which is pressure-driven and cannot kill a live handshake.
const idle_ns: u64 = 30 * std.time.ns_per_s;

const body = "h3spec\n";

pub const Options = struct {
    port: u16,
    /// PEM, leaf first. The interop runner's `certs.sh` produces exactly this.
    certificate_pem: []const u8,
    /// PEM of the leaf's P-256 private key, in SEC1 or PKCS#8 form.
    private_key_pem: []const u8,
    /// Where a request's path is resolved. The interop runner mounts `/www`
    /// read-only and compares what the client downloaded against it byte for
    /// byte, so a server that answered with anything else would pass its own
    /// tests and fail the runner's.
    www: ?Io.Dir = null,
    /// Answer every new connection with a Retry, which is the runner's `retry`
    /// test case. Address validation policy, and therefore this file's: RFC
    /// 9000 section 8.1.2 leaves *when* to retry entirely to the server.
    retry: bool = false,
    verbose: bool,
};

/// RFC 9000 section 8.1.3's token, as this server chooses to build one.
///
/// `odcid_len || odcid || HMAC(key, odcid || address)`. The identifier is in
/// the clear because the server needs it back — section 7.3 has it repeated in
/// `original_destination_connection_id`, and after a Retry the packet no longer
/// carries it — and the MAC is what stops a client inventing one. Binding the
/// address is what stops a token being replayed from somewhere else.
///
/// No expiry, because that needs a clock and this file has one only for the
/// connection loop; the runner's tokens live for one test case.
const token_mac_octets: usize = 16;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// Everything the loop needs that is not one connection's.
const Shared = struct {
    certificates: []const []const u8,
    private_key: [32]u8,
    /// The key the Retry tokens are authenticated with, drawn once per process.
    token_key: [32]u8,
    www: ?Io.Dir,
    retry: bool,
    verbose: bool,
};

/// One connection and everything attached to it.
const Peer = struct {
    connection: Connection,
    server: tls.Server,
    http3: Http3,
    /// The identifier this endpoint chose, which is what a client addresses
    /// once it has seen a packet from here.
    local: quic.ConnectionId,
    /// And the one the client chose for its first Initial, which it keeps using
    /// until then. A client's first flight can span several datagrams — a
    /// ClientHello past 1200 octets does — and every one of them is addressed
    /// to this identifier, not to `local`. Matching on `local` alone made the
    /// second datagram look like a new connection, so the server answered it
    /// with a *different* Source Connection ID and quic-go refused the
    /// handshake: "expected initial_source_connection_id to equal ..., is ...".
    original: quic.ConnectionId,
    address: Io.net.IpAddress,
    started_ns: u64,
    last_ns: u64,
    /// Whether this endpoint's unidirectional streams have been *produced*.
    /// Not whether they have been sent: `writeControl` may be called once, and
    /// a peer that has not yet granted stream credit takes fewer octets than
    /// it is offered — so the octets are held here and pushed until they are
    /// gone. Calling `writeControl` again instead is an assertion failure, and
    /// was.
    http3_started: bool,
    uni_out: [3][256]u8,
    uni_len: [3]usize,
    uni_sent: [3]usize,
    /// Streams the connection has reported data on.
    readable: [streams_max]u64,
    readable_len: usize,
    /// Answers in flight. A megabyte does not fit in one `write` — the send
    /// buffer is `stream_send_octets` — so a response is pushed as the peer's
    /// flow control window opens, and this is what is left of it.
    answers: [requests_max]Answer,
    answers_len: usize,
    live: bool,
};

/// One response being written out.
const Answer = struct {
    stream: u64,
    /// The file the path resolved to, or null for the built-in body.
    file: ?Io.File,
    /// Octets handed to `write` so far, and how many there are.
    offset: u64,
    total: u64,
};

pub fn run(io: Io, gpa: std.mem.Allocator, log: *Io.Writer, options: Options) !void {
    var certificate_storage: [8 * 1024]u8 = undefined;
    const certificate = try pemBody(&certificate_storage, options.certificate_pem, "CERTIFICATE");
    const certificates = [_][]const u8{certificate};

    var key_storage: [1024]u8 = undefined;
    var shared: Shared = .{
        .certificates = &certificates,
        .private_key = try privateKey(&key_storage, options.private_key_pem),
        .token_key = undefined,
        .www = options.www,
        .retry = options.retry,
        .verbose = options.verbose,
    };
    // Drawn once per process: a Retry token is only as good as the key that
    // authenticates it, and a key a client can predict is a token a client can
    // mint for an address it does not own.
    try io.randomSecure(&shared.token_key);

    var parameters_buffer: [512]u8 = undefined;

    const address: Io.net.IpAddress = .{ .ip4 = .unspecified(options.port) };
    var socket = try address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    try note(log, "listening on {f}", .{socket.address});

    const peers = try gpa.alloc(Peer, connections_max);
    defer gpa.free(peers);
    for (peers) |*peer| peer.live = false;

    // One response chunk, shared by every connection: a body is read out of
    // `www` in pieces as the peer's window opens, and holding a megabyte per
    // request would be holding sixteen of them.
    const scratch = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(scratch);

    const origin = Io.Timestamp.now(io, .awake);
    var receive_buffer: [receive_octets]u8 = undefined;

    // Bounded by nothing: this is the server loop, and it runs until the
    // process is stopped.
    while (true) {
        const timeout: Io.Timeout = .{ .duration = .{
            .raw = .{ .nanoseconds = 20 * std.time.ns_per_ms },
            .clock = .awake,
        } };
        const message = socket.receiveTimeout(io, &receive_buffer, timeout) catch |err| switch (err) {
            error.Timeout => {
                try flushAll(io, log, &socket, peers, elapsed(io, origin), scratch);
                continue;
            },
            else => return err,
        };
        const now = elapsed(io, origin);

        const peer = find(peers, message.data, message.from) orelse
            accept(io, log, &socket, peers, message, now, &parameters_buffer, &shared) catch |err| {
            if (options.verbose) try note(log, "refused a datagram: {s}", .{@errorName(err)});
            continue;
        } orelse continue;

        peer.last_ns = now;
        peer.connection.receive(message.data, now) catch |err| {
            if (options.verbose) try note(log, "receive: {s}", .{@errorName(err)});
            peer.connection.close(Connection.errorCode(err));
            _ = flush(io, &socket, peer, now) catch {};
            peer.live = false;
            continue;
        };

        drive(io, log, peer, now, &shared, scratch) catch |err| {
            if (options.verbose) try note(log, "drive: {s}", .{@errorName(err)});
        };
        _ = flush(io, &socket, peer, now) catch {};

        retire(peers, now);
    }
}

/// RFC 8446 section 6.2's alert numbers, for the failures `tls.Server` names.
///
/// A server that answered every handshake failure with `internal_error` would
/// be telling a peer nothing: the alert is the only place TLS says *why* a
/// handshake stopped, and h3spec asserts on three of them by number.
fn alertFor(err: tls.Error) u8 {
    return switch (err) {
        // A message this endpoint did not expect where it arrived, which is
        // what an EndOfEarlyData or a post-handshake KeyUpdate is over QUIC.
        error.Unsupported => 10, // unexpected_message
        error.Malformed => 50, // decode_error
        error.BadFinished => 51, // decrypt_error
        error.TooLarge => 80, // internal_error
        // RFC 9001 sections 8.1 and 8.2 give these two their own numbers, and
        // the transport codes they become — 0x0178 and 0x016d — are the alert
        // plus `crypto_error_base`.
        error.NoApplicationProtocol => 120, // no_application_protocol
        error.MissingExtension => 109, // missing_extension
    };
}

/// Match a datagram to a connection by the Destination Connection ID it names.
fn find(peers: []Peer, data: []const u8, from: Io.net.IpAddress) ?*Peer {
    const parsed = quic.packet.parse(data, connection_id_octets) catch return null;
    const destination = switch (parsed.header) {
        .initial => |value| value.destination,
        .handshake, .zero_rtt => |value| value.destination,
        .retry => |value| value.destination,
        .short => |value| value.destination,
        else => return null,
    };
    // Bounded by the table.
    for (peers) |*peer| {
        if (!peer.live) continue;
        if (peer.local.eql(&destination)) return peer;
        // The client's first flight, still addressed to the identifier it drew
        // before it had seen anything from here. Matched with the address too,
        // because two clients drawing the same identifier is possible and
        // giving one of them the other's connection is not a failure anyone
        // would find twice.
        if (peer.original.eql(&destination) and peer.address.eql(&from)) return peer;
    }
    return null;
}

/// A datagram that matched no connection: either a new one, or noise.
fn accept(
    io: Io,
    log: *Io.Writer,
    socket: *Io.net.Socket,
    peers: []Peer,
    message: Io.net.IncomingMessage,
    now_ns: u64,
    parameters_buffer: []u8,
    shared: *const Shared,
) !?*Peer {
    const parsed = quic.packet.parse(message.data, connection_id_octets) catch |err| {
        if (shared.verbose) try note(log, "parse of {d} octets: {s}", .{ message.data.len, @errorName(err) });
        return null;
    };

    // RFC 9000 section 6.1: a long header in a version this endpoint does not
    // implement is answered with the list of versions it does. Not optional for
    // a server, and not only for politeness — the interop runner's network
    // simulator will not start a test until the server answers exactly this
    // probe, so a server that ignores it fails every case before the first
    // packet of the first handshake.
    //
    // The datagram floor is section 14.1's, applied here for the reason section
    // 6.1 gives: a Version Negotiation packet is larger than the packet that
    // provokes it, so answering a small one is an amplification vector.
    if (parsed.header == .unsupported_version) {
        const unsupported = parsed.header.unsupported_version;
        if (message.data.len >= 1200) {
            try sendVersionNegotiation(io, log, socket, message, unsupported, shared);
        }
        return null;
    }

    // Only an Initial starts a connection. Everything else addressed to an
    // identifier this endpoint does not hold is a packet for a connection that
    // is over, and section 10.3's stateless reset is the answer this package
    // does not have.
    if (parsed.header != .initial) return null;
    const initial = parsed.header.initial;

    var seed: [96]u8 = undefined;
    try io.randomSecure(&seed);
    const source = try quic.ConnectionId.init(seed[64..][0..connection_id_octets]);

    // Section 8.1.2's address validation, as the runner's `retry` case asks
    // for it. The identifier the transport parameters must repeat is the one
    // from *before* the Retry, and after a Retry the packet no longer carries
    // it — so it travels inside the token and comes back here.
    var original = initial.destination;
    if (shared.retry) {
        if (initial.token.len == 0) {
            try sendRetry(io, log, socket, message, initial, source, shared);
            return null;
        }
        original = validateToken(initial.token, message.from, shared) orelse {
            if (shared.verbose) try note(log, "a token that does not authenticate", .{});
            return null;
        };
    }

    const slot = free: {
        for (peers) |*peer| {
            if (!peer.live) break :free peer;
        }
        // Full: take the connection nobody has heard from in longest. A server
        // that answers nothing looks exactly like a server that failed the test
        // under way, so refusing here is the worst of the options — and the
        // peer being evicted is, by construction, the one least likely to still
        // be waiting for an answer.
        var oldest: *Peer = &peers[0];
        for (peers) |*peer| {
            if (peer.last_ns < oldest.last_ns) oldest = peer;
        }
        try note(log, "evicting {x}, silent {d}ms", .{
            oldest.local.bytes(),
            (now_ns -| oldest.last_ns) / std.time.ns_per_ms,
        });
        break :free oldest;
    };

    slot.* = .{
        .connection = .init(.{
            .side = .server,
            // RFC 9001 section 5.2: the Initial keys come from the Destination
            // Connection ID of the packet that just arrived — the client's own
            // choice on a first flight, and *this server's* Retry Source
            // Connection ID on a retried one. `original` above is the other
            // value, the one section 7.3 has the transport parameters repeat.
            .original_destination = initial.destination,
            .source = source,
        }),
        .server = .init(.{
            .certificates = shared.certificates,
            .private_key = shared.private_key,
            // `h3` for h3spec, and `hq-interop` so the same binary answers the
            // interop runner's HTTP/0.9 cases.
            .protocols = &.{ "h3", "hq-interop" },
            .transport_parameters = try transportParameters(
                parameters_buffer,
                source,
                original,
                if (shared.retry) initial.destination else null,
            ),
            .random = seed[0..32].*,
            .key_seed = seed[32..64].*,
        }),
        .http3 = .init(.server),
        .local = source,
        .original = initial.destination,
        .address = message.from,
        .started_ns = now_ns,
        .last_ns = now_ns,
        .http3_started = false,
        .uni_out = undefined,
        .uni_len = @splat(0),
        .uni_sent = @splat(0),
        .readable = undefined,
        .readable_len = 0,
        .answers = undefined,
        .answers_len = 0,
        .live = true,
    };
    // The same numbers the transport parameters above carry. The stream layer
    // enforces what was advertised and grants more as streams retire, and it
    // cannot know what a consumer chose to offer: the table is shared between
    // four kinds of stream, so `streams_max` is never the per-kind limit.
    slot.connection.streams.setAdvertisedStreamLimits(requests_max, unidirectional_max);
    try note(log, "accepted a connection as {x}", .{source.bytes()});
    return slot;
}

/// The versions this endpoint speaks, which is one.
const versions = [_]u32{quic.packet.version_1};

/// Answer an unknown version with the list of known ones.
fn sendVersionNegotiation(
    io: Io,
    log: *Io.Writer,
    socket: *Io.net.Socket,
    message: Io.net.IncomingMessage,
    unsupported: @FieldType(quic.packet.Header, "unsupported_version"),
    shared: *const Shared,
) !void {
    var datagram: [256]u8 = @splat(0);
    const written = try quic.packet.writeVersionNegotiation(
        &datagram,
        unsupported.source,
        unsupported.destination,
        &versions,
    );
    try socket.send(io, &message.from, datagram[0..written]);
    if (shared.verbose) try note(log, "version 0x{x} is not one of ours", .{unsupported.version});
}

/// Answer a first flight with a Retry, and forget about it.
///
/// No connection state is created: RFC 9000 section 8.1.2's whole point is that
/// a server retries *before* committing anything, so that an address it has not
/// validated cannot make it hold memory. The client comes back with the token
/// and `accept` starts from there.
fn sendRetry(
    io: Io,
    log: *Io.Writer,
    socket: *Io.net.Socket,
    message: Io.net.IncomingMessage,
    initial: @FieldType(quic.packet.Header, "initial"),
    source: quic.ConnectionId,
    shared: *const Shared,
) !void {
    // Section 17.2.5.1: the Source Connection ID a Retry carries must differ
    // from the one the client addressed, and a client discards a Retry that
    // breaks the rule. `source` is drawn fresh per datagram, so the only way
    // they collide is chance at 2^-64 — and answering nothing is better than
    // answering a packet the client will throw away.
    if (source.eql(&initial.destination)) return;

    var token: [1 + quic.ConnectionId.octets_max + token_mac_octets]u8 = undefined;
    const octets = makeToken(&token, initial.destination, message.from, shared);

    var datagram: [512]u8 = @splat(0);
    var scratch: [1024]u8 = undefined;
    const written = try quic.packet.writeRetry(&datagram, &scratch, .{
        .destination = initial.source,
        .source = source,
        .token = octets,
        .original_destination = initial.destination,
    });
    try socket.send(io, &message.from, datagram[0..written]);
    if (shared.verbose) try note(log, "retried {x} as {x}", .{ initial.destination.bytes(), source.bytes() });
}

/// `odcid_len || odcid || HMAC(key, odcid || address)`.
fn makeToken(
    target: []u8,
    original: quic.ConnectionId,
    address: Io.net.IpAddress,
    shared: *const Shared,
) []const u8 {
    const bytes = original.bytes();
    target[0] = @intCast(bytes.len);
    @memcpy(target[1..][0..bytes.len], bytes);
    var mac: [Hmac.mac_length]u8 = undefined;
    tokenMac(&mac, bytes, address, shared);
    @memcpy(target[1 + bytes.len ..][0..token_mac_octets], mac[0..token_mac_octets]);
    return target[0 .. 1 + bytes.len + token_mac_octets];
}

/// The identifier a token vouches for, or null if it vouches for nothing.
fn validateToken(
    token: []const u8,
    address: Io.net.IpAddress,
    shared: *const Shared,
) ?quic.ConnectionId {
    if (token.len < 1) return null;
    const length = token[0];
    if (length > quic.ConnectionId.octets_max) return null;
    if (token.len != 1 + @as(usize, length) + token_mac_octets) return null;

    const bytes = token[1..][0..length];
    var expected: [Hmac.mac_length]u8 = undefined;
    tokenMac(&expected, bytes, address, shared);
    // Constant-time, because a token that can be probed a byte at a time is a
    // token an off-path attacker can forge — and forging one is forging an
    // address validation.
    if (!std.crypto.timing_safe.eql(
        [token_mac_octets]u8,
        expected[0..token_mac_octets].*,
        token[1 + length ..][0..token_mac_octets].*,
    )) return null;
    return quic.ConnectionId.init(bytes) catch null;
}

fn tokenMac(
    out: *[Hmac.mac_length]u8,
    original: []const u8,
    address: Io.net.IpAddress,
    shared: *const Shared,
) void {
    var mac: Hmac = .init(&shared.token_key);
    mac.update(original);
    // The family goes in too, so that an IPv4 address and the IPv6 one that
    // embeds it cannot share a token.
    switch (address) {
        .ip4 => |one| {
            mac.update(&[_]u8{4});
            mac.update(&one.bytes);
            mac.update(std.mem.asBytes(&one.port));
        },
        .ip6 => |one| {
            mac.update(&[_]u8{6});
            mac.update(&one.bytes);
            mac.update(std.mem.asBytes(&one.port));
        },
    }
    mac.final(out);
}

/// This endpoint's transport parameters. RFC 9000 section 7.3 has the client
/// check both identifiers against the packets it saw.
fn transportParameters(
    target: []u8,
    source: quic.ConnectionId,
    original: quic.ConnectionId,
    retry_source: ?quic.ConnectionId,
) ![]const u8 {
    const written = try quic.transport_parameters.encode(target, &.{
        // Section 7.3: present exactly when a Retry was sent, and equal to the
        // Retry's Source Connection ID. A client refuses the connection if
        // either half is wrong, which is what makes the identifier an attacker
        // injected during the handshake detectable.
        .retry_source_connection_id = retry_source,
        .initial_max_data = connection_receive_octets,
        .initial_max_stream_data_bidi_local = stream_receive_octets,
        .initial_max_stream_data_bidi_remote = stream_receive_octets,
        .initial_max_stream_data_uni = stream_receive_octets,
        .initial_max_streams_bidi = requests_max,
        .initial_max_streams_uni = unidirectional_max,
        // The same number `idle_ns` retires on, so what this server does is
        // what it said it would do. It advertised nothing here while dropping
        // connections after five seconds, which is a server telling its peer
        // the connection never times out and then behaving as though it does.
        .max_idle_timeout_ms = idle_ns / std.time.ns_per_ms,
        .max_udp_payload_size = Connection.datagram_octets,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = source,
        .original_destination_connection_id = original,
    });
    return target[0..written];
}

/// Everything that happens between datagrams: the handshake, the HTTP/3
/// streams, and the responses.
fn drive(io: Io, log: *Io.Writer, peer: *Peer, now_ns: u64, shared: *const Shared, scratch: []u8) !void {
    _ = now_ns;
    const verbose = shared.verbose;

    // The handshake, in the same shape as the client's.
    for ([_]quic.crypto.Level{ .initial, .handshake, .one_rtt }) |level| {
        const available = peer.connection.cryptoOut(level);
        if (available.len == 0) continue;
        const consumed = peer.server.read(level, available) catch |err| {
            try note(log, "tls at {s}: {s}", .{ @tagName(level), @errorName(err) });
            // RFC 9001 section 4.8: a TLS alert becomes a transport code of
            // 0x0100 plus the alert, and `error_code.Transport.fromAlert` is that
            // arithmetic. Which alert is the one distinction `tls.Server` draws
            // in its error set, because it is the one h3spec asks about.
            peer.connection.close(quic.error_code.Transport.fromAlert(alertFor(err)));
            return err;
        };
        peer.connection.cryptoConsumed(level, consumed);
    }
    for (peer.server.drainInstalls()) |one| {
        var secret = try quic.crypto.Secret.init(&one.secret);
        switch (one.direction) {
            .send => try peer.connection.installSecret(one.level, .send, &secret, one.suite),
            .receive => try peer.connection.installSecret(one.level, .receive, &secret, one.suite),
        }
    }
    if (peer.server.drainTransportParameters()) |octets| {
        // Section 7.4: a parameter with an invalid value, and section 18.2's
        // server-only ones from a client, are both
        // `TRANSPORT_PARAMETER_ERROR`. `transportParametersIn` already refuses
        // all eight of the things h3spec sends here; what was missing was
        // anyone closing the connection when it did.
        peer.connection.transportParametersIn(octets) catch |err| {
            try note(log, "transport parameters: {s}", .{@errorName(err)});
            peer.connection.close(.transport_parameter_error);
            return;
        };
    }
    for ([_]quic.crypto.Level{ .initial, .handshake }) |level| {
        const owed = peer.server.drainOut(level);
        if (owed.len > 0) try peer.connection.cryptoIn(level, owed);
    }
    // RFC 9001 section 4.1.1: the handshake completes when this endpoint has
    // both sent its Finished and verified the peer's, and `tls.Server` reaching
    // `.established` is exactly that. Only the TLS engine knows it, which is
    // why `Connection` takes it as a report rather than inferring it.
    if (peer.server.state == .established and !peer.connection.recovery.handshake_confirmed) {
        peer.connection.confirmHandshake();
    }

    // Bounded: the queue is fixed and `poll` removes what it returns.
    for (0..256) |_| {
        const event = peer.connection.poll() orelse break;
        switch (event) {
            .stream_readable => |id| noteReadable(peer, id),
            .closed => |value| if (verbose) try note(log, "closed: 0x{x}", .{value.code}),
            else => {},
        }
    }

    if (peer.connection.state != .established) return;

    // `hq-interop` has no framing and no unidirectional streams: the request is
    // a line and the response is the file. Everything below it is HTTP/3's.
    if (std.mem.eql(u8, peer.server.alpn(), "hq-interop")) {
        var index: usize = 0;
        // Bounded by `readable_len`.
        while (index < peer.readable_len) : (index += 1) {
            respondHq(io, peer, shared, peer.readable[index]) catch {};
        }
        try pushAnswers(io, peer, scratch);
        compactReadable(peer);
        return;
    }

    if (!peer.http3_started) try startHttp3(peer);
    try pushUnidirectional(peer);

    var index: usize = 0;
    // Bounded by `readable_len`, which is bounded by the stream table.
    while (index < peer.readable_len) : (index += 1) {
        const id = peer.readable[index];
        const stream = peer.connection.findStream(id) orelse continue;
        if (stream.receive_state == .reset) continue;
        const data = peer.connection.readable(id);
        const fin = if (stream.received.final_size) |size|
            size == stream.consumed + data.len
        else
            false;
        if (data.len == 0 and !fin) continue;

        var events: [16]h3.http3.Event = undefined;
        const result = peer.http3.receive(id, data, fin, &events) catch |err| {
            const application = h3.http3.code(err);
            try note(log, "http3 on stream {d}: {s} (0x{x})", .{
                id,
                @errorName(err),
                @intFromEnum(application),
            });
            peer.connection.closeApplication(@intFromEnum(application));
            return;
        };
        for (events[0..result.events]) |event| {
            respond(io, peer, shared, event) catch |err| {
                const application = respondCode(err);
                try note(log, "response on stream {d}: {s} (0x{x})", .{
                    id,
                    @errorName(err),
                    @intFromEnum(application),
                });
                peer.connection.closeApplication(@intFromEnum(application));
                return;
            };
        }
        if (result.consumed > 0) try peer.connection.consume(id, result.consumed);
    }
    compactReadable(peer);
    try pushAnswers(io, peer, scratch);
}

const unidirectional_streams = [3]u64{ control_stream, qpack_encoder_stream, qpack_decoder_stream };

/// Produce this endpoint's three unidirectional streams, once.
fn startHttp3(peer: *Peer) !void {
    peer.uni_len[0] = try peer.http3.writeControl(&peer.uni_out[0]);
    peer.uni_len[1] = try h3.stream.write(&peer.uni_out[1], .qpack_encoder);
    peer.uni_len[2] = try h3.stream.write(&peer.uni_out[2], .qpack_decoder);
    peer.http3_started = true;
}

/// Push what is left of them. A stream this endpoint has no credit for takes
/// nothing and is tried again on the next pass, which is what a MAX_STREAM_DATA
/// from the peer is for.
fn pushUnidirectional(peer: *Peer) !void {
    for (unidirectional_streams, 0..) |id, index| {
        if (peer.uni_sent[index] == peer.uni_len[index]) continue;
        const rest = peer.uni_out[index][peer.uni_sent[index]..peer.uni_len[index]];
        peer.uni_sent[index] += peer.connection.write(id, rest, false) catch 0;
    }
}

/// One event, and the response a HEADERS on a request stream earns.
/// `Http3`'s errors plus the one only a consumer can raise: RFC 9114 section
/// 4.1.2's `H3_MESSAGE_ERROR`, which is about whether a field section is a
/// *message* and is therefore `fields.MessageValidator`'s verdict rather than
/// the sequencer's.
const RespondError = h3.http3.Error || error{MessageError};

fn respondCode(err: RespondError) h3.quic.error_code.Application {
    if (err == error.MessageError) return .message_error;
    // Narrowed rather than re-switched, so the mapping stays in one place
    // instead of ten arms copied into this file. The cast is checked in Debug
    // and the line above is the only thing it depends on.
    const narrowed: h3.http3.Error = @errorCast(err);
    return h3.http3.code(narrowed);
}

fn respond(io: Io, peer: *Peer, shared: *const Shared, event: h3.http3.Event) RespondError!void {
    switch (event) {
        .headers => |value| {
            // Validated before it is answered: RFC 9114 section 4.3 is what
            // decides whether a field section is a message at all, and a server
            // that skipped it would be the request-smuggling surface
            // `fields.zig` exists to close.
            var buffer: [16 * 1024]u8 = undefined;
            var iterator = h3.qpack.field_line.iterate(value.section, &buffer, 1 << 20) catch
                return error.GeneralProtocolError;
            var validator: h3.fields.MessageValidator = .init(.{
                .kind = if (value.trailers) .trailer else .request,
            });
            var path: [256]u8 = undefined;
            var path_len: usize = 0;
            while (iterator.next() catch return error.GeneralProtocolError) |field| {
                validator.field(&field) catch return error.MessageError;
                if (std.mem.eql(u8, field.name, ":path") and field.value.len <= path.len) {
                    @memcpy(path[0..field.value.len], field.value);
                    path_len = field.value.len;
                }
            }
            validator.finish() catch return error.MessageError;
            if (value.trailers) return;

            // Answered once. A second HEADERS on the same stream is trailers,
            // which is legal and is not a second request.
            if (findAnswer(peer, value.stream) != null) return;
            const answer = openAnswer(io, peer, shared, value.stream, path[0..path_len]) orelse
                return error.ExcessiveLoad;

            var out: [512]u8 = undefined;
            var length: [24]u8 = undefined;
            var offset = try peer.http3.writeHeaders(&out, &.{
                .{ .name = ":status", .value = "200" },
                .{
                    .name = "content-length",
                    .value = std.fmt.bufPrint(&length, "{d}", .{answer.total}) catch
                        return error.GeneralProtocolError,
                },
            });
            offset += try Http3.writeData(out[offset..], answer.total);
            // The frame header only. The body follows through `pushAnswers` as
            // the peer's window opens — a megabyte does not fit in one write,
            // and a server that assumed it did would truncate every large
            // response and call it a success.
            const written = peer.connection.write(value.stream, out[0..offset], false) catch
                return error.GeneralProtocolError;
            if (written != offset) return error.GeneralProtocolError;
        },
        .settings => {},
        .goaway => {},
        .data => {},
        .finished => |id| peer.http3.release(id),
    }
}

fn findAnswer(peer: *Peer, stream: u64) ?*Answer {
    // Bounded by `answers_len`.
    for (peer.answers[0..peer.answers_len]) |*answer| {
        if (answer.stream == stream) return answer;
    }
    return null;
}

/// Resolve a request path against `www` and record what has to go out.
///
/// A path that names nothing gets the built-in body rather than a 404: the
/// runner only ever asks for files it put there, and h3spec does not care what
/// the body is — but a server that answered 404 to h3spec's control requests
/// would fail every case that needs a working request first.
fn openAnswer(
    io: Io,
    peer: *Peer,
    shared: *const Shared,
    stream: u64,
    path: []const u8,
) ?*Answer {
    if (peer.answers_len == peer.answers.len) return null;
    const answer = &peer.answers[peer.answers_len];
    answer.* = .{ .stream = stream, .file = null, .offset = 0, .total = body.len };

    open: {
        const www = shared.www orelse break :open;
        const name = std.mem.trimStart(u8, path, "/");
        if (name.len == 0) break :open;
        // No path this file resolves may leave the directory it was given. The
        // runner never asks it to, which is exactly why the check has to be
        // here rather than implied by the runner's good manners.
        if (std.mem.indexOf(u8, name, "..") != null) break :open;
        const file = www.openFile(io, name, .{}) catch break :open;
        const size = file.stat(io) catch {
            file.close(io);
            break :open;
        };
        // The whole file, whatever its size. There was a two-megabyte cap here
        // and it was answered with a *prefix* — the runner's `transfer` case
        // asks for five megabytes and compares byte for byte, so the response
        // was wrong in the one way a test bed is built to catch. Nothing needs
        // the cap: the body is read in `scratch`-sized pieces as the peer's
        // window opens, so what bounds memory is the scratch buffer and not
        // the file.
        answer.file = file;
        answer.total = size.size;
    }

    peer.answers_len += 1;
    return answer;
}

/// Push what is left of every answer, as the peer's flow control allows.
fn pushAnswers(io: Io, peer: *Peer, scratch: []u8) !void {
    var index: usize = 0;
    // Bounded by `answers_len`.
    while (index < peer.answers_len) {
        const answer = &peer.answers[index];
        if (answer.offset < answer.total) {
            const want = @min(scratch.len, answer.total - answer.offset);
            const chunk = if (answer.file) |file|
                scratch[0..(file.readPositionalAll(io, scratch[0..want], answer.offset) catch 0)]
            else
                body[@intCast(answer.offset)..@intCast(answer.total)];
            if (chunk.len > 0) {
                const fin = answer.offset + chunk.len == answer.total;
                const taken = peer.connection.write(answer.stream, chunk, fin) catch 0;
                answer.offset += taken;
                // A short write is ordinary: it means the window closed, and
                // the FIN went with the last octet only if all of them fit.
                if (taken != chunk.len) {
                    index += 1;
                    continue;
                }
            }
        }
        if (answer.offset < answer.total) {
            index += 1;
            continue;
        }
        // Finished. The slot goes back, which for a `multiconnect` run is what
        // keeps the table from filling.
        if (answer.file) |file| file.close(io);
        peer.answers[index] = peer.answers[peer.answers_len - 1];
        peer.answers_len -= 1;
    }
}

/// `hq-interop`: the request is `GET /path\r\n` and the response is the file,
/// with no framing on either side.
fn respondHq(io: Io, peer: *Peer, shared: *const Shared, stream: u64) !void {
    if (findAnswer(peer, stream) != null) return;
    const readable = peer.connection.readable(stream);
    const end = std.mem.indexOf(u8, readable, "\r\n") orelse return;
    const line = readable[0..end];
    try peer.connection.consume(stream, end + 2);

    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return;
    _ = openAnswer(io, peer, shared, stream, line[space + 1 ..]) orelse return;
}

/// Drop the identifiers whose streams are gone.
///
/// This list is bounded by the stream table and it used to be append-only: once
/// `streams_max` distinct identifiers had been noted, the next one was silently
/// refused and its request was never answered. That is the same defect the
/// stream table itself had — a fixed array nobody gave back — and it surfaced
/// the same way, as a run that stopped partway with both endpoints idle. The
/// runner's `multiplexing` case served twenty-four of its files and stopped.
fn compactReadable(peer: *Peer) void {
    var kept: usize = 0;
    // Bounded by `readable_len`.
    for (peer.readable[0..peer.readable_len]) |id| {
        if (peer.connection.findStream(id) == null) continue;
        peer.readable[kept] = id;
        kept += 1;
    }
    peer.readable_len = kept;
}

fn noteReadable(peer: *Peer, id: u64) void {
    // Bounded by `readable_len`.
    for (peer.readable[0..peer.readable_len]) |one| {
        if (one == id) return;
    }
    if (peer.readable_len == peer.readable.len) return;
    peer.readable[peer.readable_len] = id;
    peer.readable_len += 1;
}

fn flush(io: Io, socket: *Io.net.Socket, peer: *Peer, now_ns: u64) !void {
    var datagram: [Connection.datagram_octets]u8 = undefined;
    // Bounded, for the reason the client's flush is.
    for (0..64) |_| {
        const octets = try peer.connection.send(&datagram, now_ns);
        if (octets == 0) return;
        try socket.send(io, &peer.address, datagram[0..octets]);
    }
}

fn flushAll(
    io: Io,
    log: *Io.Writer,
    socket: *Io.net.Socket,
    peers: []Peer,
    now_ns: u64,
    scratch: []u8,
) !void {
    _ = log;
    for (peers) |*peer| {
        if (!peer.live) continue;
        if (peer.connection.timeout()) |at| {
            if (at <= now_ns) peer.connection.onTimeout(now_ns);
        }
        // A response is pushed as the peer's window opens, and the window opens
        // when an acknowledgement arrives — but it also opens when a *timer*
        // frees congestion window, and nothing here was pushing then. A server
        // that only refills its send buffer on inbound datagrams stops sending
        // the moment the client has nothing to say, which for a client waiting
        // on a download is immediately: both endpoints then wait, and the
        // client's idle timer is what ends it.
        pushAnswers(io, peer, scratch) catch {};
        flush(io, socket, peer, now_ns) catch {};
    }
    retire(peers, now_ns);
}

/// Give the slot back once the connection is over.
///
/// `.closing` counts, not only `.draining`: this endpoint's own close has been
/// framed and sent by the flush that precedes every call here, and section
/// 10.2.1 says an endpoint sends one close and then nothing. Keeping the slot
/// afterwards is keeping it for a connection that will never speak again.
fn retire(peers: []Peer, now_ns: u64) void {
    for (peers) |*peer| {
        if (!peer.live) continue;
        const over = switch (peer.connection.state) {
            .closing, .draining => true,
            .handshaking, .established => now_ns -| peer.last_ns > idle_ns,
        };
        if (over) peer.live = false;
    }
}

fn elapsed(io: Io, origin: Io.Timestamp) u64 {
    const now = Io.Timestamp.now(io, .awake);
    const difference = origin.durationTo(now).nanoseconds;
    std.debug.assert(difference >= 0); // `.awake` is monotonic.
    return @intCast(difference);
}

fn note(log: *Io.Writer, comptime format: []const u8, arguments: anytype) !void {
    try log.print("h3-server: " ++ format ++ "\n", arguments);
    try log.flush();
}

/// The DER body of the first PEM block of the given type.
///
/// A parser rather than a dependency: what is wanted is the octets between the
/// markers, base64-decoded, and nothing about what they mean.
fn pemBody(target: []u8, pem: []const u8, comptime label: []const u8) ![]const u8 {
    const begin = "-----BEGIN " ++ label ++ "-----";
    const end = "-----END " ++ label ++ "-----";
    const start = (std.mem.indexOf(u8, pem, begin) orelse return error.NoSuchBlock) + begin.len;
    const stop = std.mem.indexOfPos(u8, pem, start, end) orelse return error.NoSuchBlock;

    // Base64 without the line breaks the PEM armour puts in.
    var packed_storage: [16 * 1024]u8 = undefined;
    var packed_len: usize = 0;
    for (pem[start..stop]) |octet| {
        if (octet == '\n' or octet == '\r' or octet == ' ' or octet == '\t') continue;
        if (packed_len == packed_storage.len) return error.TooLarge;
        packed_storage[packed_len] = octet;
        packed_len += 1;
    }
    const decoder = std.base64.standard.Decoder;
    const octets = try decoder.calcSizeForSlice(packed_storage[0..packed_len]);
    if (octets > target.len) return error.TooLarge;
    try decoder.decode(target[0..octets], packed_storage[0..packed_len]);
    return target[0..octets];
}

/// The 32-octet P-256 scalar out of a PEM private key.
///
/// Both forms the interop runner's script can produce: RFC 5915's `EC PRIVATE
/// KEY`, whose second element is the scalar, and PKCS#8's `PRIVATE KEY`, which
/// wraps one. Rather than write two DER parsers, this looks for the shape both
/// share — an OCTET STRING of exactly 32 octets — which is unambiguous here
/// because a P-256 key has exactly one.
fn privateKey(target: []u8, pem: []const u8) ![32]u8 {
    const der = pemBody(target, pem, "EC PRIVATE KEY") catch
        try pemBody(target, pem, "PRIVATE KEY");
    var index: usize = 0;
    // Bounded by the key, which is a few hundred octets.
    while (index + 2 + 32 <= der.len) : (index += 1) {
        if (der[index] != 0x04 or der[index + 1] != 32) continue;
        // The public key is also DER-tagged 0x04 inside a BIT STRING, but it is
        // 65 octets and preceded by a 0x00 pad, so a 32-octet OCTET STRING at
        // this depth is the scalar.
        var scalar: [32]u8 = undefined;
        @memcpy(&scalar, der[index + 2 ..][0..32]);
        return scalar;
    }
    return error.NoPrivateKey;
}

const testing = std.testing;

test "a PEM block decodes to the octets between its markers" {
    // "hello" in base64, wrapped the way PEM wraps.
    const pem =
        "noise before\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "aGVs\nbG8=\n" ++
        "-----END CERTIFICATE-----\n";
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("hello", try pemBody(&buffer, pem, "CERTIFICATE"));
    try testing.expectError(error.NoSuchBlock, pemBody(&buffer, pem, "PRIVATE KEY"));
}

/// The entry point, so the server is its own binary rather than a mode of the
/// interop client: the runner's contract and h3spec's are different enough
/// that one `main` reading both would be a `main` doing neither clearly.
pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;
    const environ = init.environ_map;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buffer);
    const log = &stderr.interface;
    defer log.flush() catch {};

    const certificate_path = environ.get("CERT") orelse "/certs/cert.pem";
    const key_path = environ.get("KEY") orelse "/certs/priv.key";
    const port_text = environ.get("PORT") orelse "4433";
    const port = std.fmt.parseInt(u16, port_text, 10) catch {
        try log.print("h3-server: PORT '{s}' is not a number\n", .{port_text});
        return 1;
    };

    const certificate_pem = try readAll(io, gpa, certificate_path);
    defer gpa.free(certificate_pem);
    const key_pem = try readAll(io, gpa, key_path);
    defer gpa.free(key_pem);

    try run(io, gpa, log, .{
        .port = port,
        .certificate_pem = certificate_pem,
        .private_key_pem = key_pem,
        .verbose = environ.get("VERBOSE") != null,
    });
    return 0;
}

fn readAll(io: Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return try reader.interface.allocRemaining(gpa, .unlimited);
}
