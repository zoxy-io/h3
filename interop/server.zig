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
const idle_ns: u64 = 5 * std.time.ns_per_s;

const body = "h3spec\n";

pub const Options = struct {
    port: u16,
    /// PEM, leaf first. The interop runner's `certs.sh` produces exactly this.
    certificate_pem: []const u8,
    /// PEM of the leaf's P-256 private key, in SEC1 or PKCS#8 form.
    private_key_pem: []const u8,
    verbose: bool,
};

/// One connection and everything attached to it.
const Peer = struct {
    connection: Connection,
    server: tls.Server,
    http3: Http3,
    /// The identifier this endpoint chose, which is how a datagram is matched
    /// to a connection.
    local: quic.ConnectionId,
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
    /// Requests answered, so that a stream is answered once.
    answered: [requests_max]u64,
    answered_len: usize,
    live: bool,
};

pub fn run(io: Io, gpa: std.mem.Allocator, log: *Io.Writer, options: Options) !void {
    var certificate_storage: [8 * 1024]u8 = undefined;
    const certificate = try pemBody(&certificate_storage, options.certificate_pem, "CERTIFICATE");
    const certificates = [_][]const u8{certificate};

    var key_storage: [1024]u8 = undefined;
    const private_key = try privateKey(&key_storage, options.private_key_pem);

    var parameters_buffer: [512]u8 = undefined;

    const address: Io.net.IpAddress = .{ .ip4 = .unspecified(options.port) };
    var socket = try address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    try note(log, "listening on {f}", .{socket.address});

    const peers = try gpa.alloc(Peer, connections_max);
    defer gpa.free(peers);
    for (peers) |*peer| peer.live = false;

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
                try flushAll(io, log, &socket, peers, elapsed(io, origin));
                continue;
            },
            else => return err,
        };
        const now = elapsed(io, origin);

        const peer = find(peers, message.data) orelse
            accept(io, log, peers, message, now, &parameters_buffer, &certificates, private_key) catch |err| {
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

        drive(io, log, peer, now, options.verbose) catch |err| {
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
fn find(peers: []Peer, data: []const u8) ?*Peer {
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
        if (peer.live and peer.local.eql(&destination)) return peer;
    }
    return null;
}

/// A datagram that matched no connection: either a new one, or noise.
fn accept(
    io: Io,
    log: *Io.Writer,
    peers: []Peer,
    message: Io.net.IncomingMessage,
    now_ns: u64,
    parameters_buffer: []u8,
    certificates: []const []const u8,
    private_key: [32]u8,
) !?*Peer {
    const parsed = quic.packet.parse(message.data, connection_id_octets) catch return null;
    // Only an Initial starts a connection. Everything else addressed to an
    // identifier this endpoint does not hold is a packet for a connection that
    // is over, and section 10.3's stateless reset is the answer this package
    // does not have.
    if (parsed.header != .initial) return null;
    const initial = parsed.header.initial;

    const slot = free: {
        for (peers) |*peer| {
            if (!peer.live) break :free peer;
        }
        return error.TooManyConnections;
    };

    var seed: [96]u8 = undefined;
    try io.randomSecure(&seed);
    const source = try quic.ConnectionId.init(seed[64..][0..connection_id_octets]);

    slot.* = .{
        .connection = .init(.{
            .side = .server,
            // RFC 9001 section 5.2: the Initial keys come from the identifier
            // the *client* chose, which is the Destination Connection ID of the
            // packet that just arrived.
            .original_destination = initial.destination,
            .source = source,
        }),
        .server = .init(.{
            .certificates = certificates,
            .private_key = private_key,
            // `h3` for h3spec, and `hq-interop` so the same binary answers the
            // interop runner's HTTP/0.9 cases.
            .protocols = &.{ "h3", "hq-interop" },
            .transport_parameters = try transportParameters(parameters_buffer, source, initial.destination),
            .random = seed[0..32].*,
            .key_seed = seed[32..64].*,
        }),
        .http3 = .init(.server),
        .local = source,
        .address = message.from,
        .started_ns = now_ns,
        .last_ns = now_ns,
        .http3_started = false,
        .uni_out = undefined,
        .uni_len = @splat(0),
        .uni_sent = @splat(0),
        .readable = undefined,
        .readable_len = 0,
        .answered = undefined,
        .answered_len = 0,
        .live = true,
    };
    try note(log, "accepted a connection as {x}", .{source.bytes()});
    return slot;
}

/// This endpoint's transport parameters. RFC 9000 section 7.3 has the client
/// check both identifiers against the packets it saw.
fn transportParameters(
    target: []u8,
    source: quic.ConnectionId,
    original: quic.ConnectionId,
) ![]const u8 {
    const written = try quic.transport_parameters.encode(target, &.{
        .initial_max_data = connection_receive_octets,
        .initial_max_stream_data_bidi_local = stream_receive_octets,
        .initial_max_stream_data_bidi_remote = stream_receive_octets,
        .initial_max_stream_data_uni = stream_receive_octets,
        .initial_max_streams_bidi = requests_max,
        .initial_max_streams_uni = unidirectional_max,
        .max_udp_payload_size = Connection.datagram_octets,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = source,
        .original_destination_connection_id = original,
    });
    return target[0..written];
}

/// Everything that happens between datagrams: the handshake, the HTTP/3
/// streams, and the responses.
fn drive(io: Io, log: *Io.Writer, peer: *Peer, now_ns: u64, verbose: bool) !void {
    _ = io;
    _ = now_ns;

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
    if (!peer.http3_started and std.mem.eql(u8, peer.server.alpn(), "h3")) {
        try startHttp3(peer);
    }
    if (!peer.http3_started) return;
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
            respond(log, peer, event) catch |err| {
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

fn respond(log: *Io.Writer, peer: *Peer, event: h3.http3.Event) RespondError!void {
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
            while (iterator.next() catch return error.GeneralProtocolError) |field| {
                validator.field(&field) catch return error.MessageError;
            }
            validator.finish() catch return error.MessageError;
            if (value.trailers) return;

            // Answered once. A second HEADERS on the same stream is trailers,
            // which is legal and is not a second request.
            for (peer.answered[0..peer.answered_len]) |one| {
                if (one == value.stream) return;
            }
            if (peer.answered_len < peer.answered.len) {
                peer.answered[peer.answered_len] = value.stream;
                peer.answered_len += 1;
            }

            var out: [512]u8 = undefined;
            var offset = try peer.http3.writeHeaders(&out, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "7" },
            });
            offset += try Http3.writeData(out[offset..], body.len);
            @memcpy(out[offset..][0..body.len], body);
            offset += body.len;
            // A short write would mean the peer's flow control window is
            // smaller than one response, which for a seven-octet body means
            // something is wrong with the connection rather than with the
            // response.
            _ = peer.connection.write(value.stream, out[0..offset], true) catch
                return error.GeneralProtocolError;
        },
        .settings => {},
        .goaway => {},
        .data => {},
        .finished => |id| peer.http3.release(id),
    }
    _ = log;
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

fn flushAll(io: Io, log: *Io.Writer, socket: *Io.net.Socket, peers: []Peer, now_ns: u64) !void {
    _ = log;
    for (peers) |*peer| {
        if (!peer.live) continue;
        if (peer.connection.timeout()) |at| {
            if (at <= now_ns) peer.connection.onTimeout(now_ns);
        }
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
