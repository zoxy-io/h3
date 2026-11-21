//! The server side of an HTTP/3 connection, over one QUIC `Connection`.
//!
//! `Http3.zig` answers "may this frame be here, now?" and nothing else: octets
//! in, events out, no stream of its own. Everything between that and a request
//! an application can act on — opening this endpoint's three unidirectional
//! streams and getting them onto the wire as the peer grants credit, reading a
//! request stream without reading more body than the application can take,
//! writing a response so that a frame is never split by a full send buffer,
//! cancelling a request, and draining the connection with GOAWAY — was written
//! by hand in `interop/server.zig`, and every embedder would have written it
//! again. This is that, once.
//!
//! ## The embedder's loop
//!
//!     connection.receive(datagram, now)            // or onTimeout(now)
//!     while (connection.poll()) |event| switch (event) {
//!         .stream_readable => |id| {
//!             const read = try session.receive(&connection, id, &events, body_room);
//!             for (events[0..read.events]) |one| handle(one);   // borrows!
//!             try session.consume(&connection, id, read);
//!         },
//!         .stream_reset => |reset| session.release(reset.stream),
//!         ...
//!     };
//!     try session.flush(&connection);               // control + QPACK streams
//!     ... writeHeaders / writeData / writeTrailers as responses progress ...
//!     while (connection.wantsSend()) send(connection.send(&buffer, now));
//!
//! **A request stream's events borrow the connection's receive buffer**, and
//! `consume` is what releases it: hand `headers` and `data` to the application
//! — decode a field section with `decodeSection` into storage of its own, copy
//! body octets into whatever relays them — and only then call `consume`. The
//! next `receive` on any stream may move that buffer.
//!
//! ## What a session owns, and what it does not
//!
//! It owns the HTTP/3 sequencing state and this endpoint's unidirectional
//! streams. It does not own the connection, which is passed to every call, nor
//! any request's state: what a request maps to — zoxy's exchange, a file — is
//! the embedder's, keyed by stream identifier.
//!
//! Server push is not offered: no MAX_PUSH_ID is sent, so a client may not
//! push and this endpoint does not. QPACK's dynamic table is not offered
//! either: SETTINGS advertises a capacity of zero, so every field section is
//! static-table and literal, and the encoder and decoder streams carry
//! nothing but their type.

const std = @import("std");

const assert = @import("assert.zig").assert;
const error_code = @import("quic/error_code.zig");
const fields = @import("fields.zig");
const frame = @import("frame.zig");
const http3 = @import("Http3.zig");
const qpack = @import("qpack.zig");
const stream_id = @import("quic/stream_id.zig");
const h3stream = @import("stream.zig");
const varint = @import("varint.zig");

/// RFC 9000 section 2.1: a server's unidirectional streams are 3, 7 and 11 —
/// the first three of its kind — and RFC 9114 sections 6.2.1 and 4.2 of RFC
/// 9204 put the control stream and QPACK's two on them.
const control_stream: u64 = stream_id.make(.server_unidirectional, 0);
const qpack_encoder_stream: u64 = stream_id.make(.server_unidirectional, 1);
const qpack_decoder_stream: u64 = stream_id.make(.server_unidirectional, 2);

/// This endpoint's unidirectional streams, in the order they are opened.
pub const unidirectional_streams = [_]u64{ control_stream, qpack_encoder_stream, qpack_decoder_stream };

/// Octets held for the control stream: its type and SETTINGS, which
/// `Http3.writeControl` writes in under thirty, and room after them for
/// `goaways_max` GOAWAY frames of at most ten octets each.
const goaways_max: usize = 2;
const goaway_frame_octets_max: usize = 1 + 1 + varint.octets_max;
const control_octets_max: usize = 64 + goaways_max * goaway_frame_octets_max;
/// A QPACK stream's type is one varint of one octet, and nothing follows it
/// on an endpoint without a dynamic table.
const qpack_stream_octets_max: usize = 8;

/// The largest DATA frame header a session writes: DATA's one-octet type and a
/// length at its widest.
const frame_header_octets_max: usize = 1 + varint.octets_max;

comptime {
    assert(control_stream == 3);
    assert(qpack_encoder_stream == 7);
    assert(qpack_decoder_stream == 11);
    assert(control_octets_max <= std.math.maxInt(u16));
}

/// What a request stream's octets meant, as `Http3.Event` says it, and how
/// many of them `consume` gives back.
pub const Received = struct {
    /// Octets to hand back with `consume`. Zero for a stream the session read
    /// and consumed itself — the peer's control and QPACK streams.
    consumed: usize,
    /// Events written into the caller's array. Their slices borrow from the
    /// connection's receive buffer until `consume`.
    events: usize,
};

pub const WriteError = error{
    /// The stream cannot take the whole frame now — the send buffer, the
    /// stream's credit or the connection's is short — and nothing was written.
    /// A frame split by a full buffer would corrupt the stream, so a HEADERS
    /// frame goes whole or not at all; try again when the peer's credit or an
    /// acknowledgement opens room.
    WouldBlock,
    /// The field section does not fit the caller's scratch buffer.
    OutputTooSmall,
    /// The stream is not one this endpoint may write a response on: not a
    /// request stream, or one whose send half is finished or reset.
    StreamState,
};

pub const GoawayError = http3.Error || error{
    /// The handshake is not confirmed, so the control stream a GOAWAY goes on
    /// does not exist yet; a connection that never got that far is closed
    /// rather than drained.
    HandshakeIncomplete,
};

pub const DecodeError = error{
    /// RFC 9204 section 2.2's decoding failure: a connection error of type
    /// QPACK_DECOMPRESSION_FAILED. `decodeSection` callers close with
    /// `.qpack_decompression_failed`.
    DecompressionFailed,
    /// RFC 9114 section 4.1.2: a malformed message — a stream error of type
    /// H3_MESSAGE_ERROR, which `cancel(.message_error)` sends.
    MessageError,
    /// More fields than `out`, or more octets than `storage`, holds: the
    /// caller's bound, not the peer's error. RFC 9114 section 4.2.2 lets a
    /// server answer it with a 431; resetting with H3_EXCESSIVE_LOAD also fits.
    TooLarge,
};

/// A request or trailer section decoded and validated.
pub const Decoded = struct {
    /// Every field, in wire order, its name and value in the caller's storage.
    fields: []const qpack.Field,
    /// RFC 9110 section 8.6's `content-length`, when the section carried one.
    content_length: ?u64,
};

/// Decode a field section against the static table and validate it as RFC
/// 9114 section 4.3 requires of `kind`, copying every name and value into
/// `storage` so the result outlives the connection's receive buffer.
///
/// `scratch` is the QPACK decoder's working space, the bound on how far a
/// Huffman string may expand; `max_field_section_size` is section 4.2.2's
/// limit, which `Http3`'s SETTINGS advertised.
pub fn decodeSection(
    section: []const u8,
    options: fields.Options,
    max_field_section_size: u64,
    scratch: []u8,
    storage: []u8,
    out: []qpack.Field,
) DecodeError!Decoded {
    var iterator = qpack.field_line.iterate(section, scratch, max_field_section_size) catch |err|
        return decodeError(err);
    var validator: fields.MessageValidator = .init(options);
    var used: usize = 0;
    var count: usize = 0;
    // Bounded by the section: every representation consumes at least one
    // octet, which the iterator asserts. A malformed field is reported before
    // a section too large for the caller, because the first is the peer's
    // error and the second only this endpoint's limit.
    while (iterator.next() catch |err| return decodeError(err)) |field| {
        validator.field(&field) catch return error.MessageError;
        if (count == out.len) return error.TooLarge;
        if (storage.len - used < field.name.len + field.value.len) return error.TooLarge;
        const name = storage[used..][0..field.name.len];
        @memcpy(name, field.name);
        used += name.len;
        const value = storage[used..][0..field.value.len];
        @memcpy(value, field.value);
        used += value.len;
        out[count] = .{ .name = name, .value = value };
        count += 1;
    }
    validator.finish() catch return error.MessageError;
    assert(count <= out.len);
    assert(used <= storage.len);
    return .{ .fields = out[0..count], .content_length = validator.contentLength() };
}

/// The decoder's four failures, sorted by whose they are: a section that does
/// not decode is the peer's, and RFC 9204 section 2.2's connection error; one
/// past section 4.2.2's advertised size or past the caller's scratch is a
/// limit, which a server answers per request rather than by closing.
fn decodeError(err: qpack.field_line.Error) DecodeError {
    return switch (err) {
        error.Truncated, error.DecompressionFailed => error.DecompressionFailed,
        error.ListTooLarge, error.OutputTooSmall => error.TooLarge,
    };
}

/// The server side of HTTP/3 over `Connection`, with `config`'s limits.
pub fn Http3Server(comptime Connection: type, comptime config: http3.Config) type {
    return struct {
        const Self = @This();
        pub const Sequencer = http3.Http3(config);

        /// One of this endpoint's unidirectional streams: what it carries, and
        /// how much of that the connection has taken. A stream is a byte
        /// stream, so a short write is ordinary and the rest goes next time.
        const Outgoing = struct {
            octets: [control_octets_max]u8 = undefined,
            len: u16 = 0,
            sent: u16 = 0,
        };

        sequencer: Sequencer,
        outgoing: [unidirectional_streams.len]Outgoing = @splat(.{}),
        /// Whether the three streams have been produced. They are produced
        /// once, when the handshake is confirmed, and pushed until gone.
        started: bool = false,
        /// One past the highest request stream this endpoint has seen, which
        /// is what a graceful GOAWAY names: RFC 9114 section 5.2 has it say
        /// "everything below this was or will be processed".
        next_request: u64 = 0,
        /// The identifier the last GOAWAY this endpoint sent named, if any. A
        /// request stream at or above it is refused as it arrives.
        goaway_sent: ?u64 = null,

        pub fn init() Self {
            return .{ .sequencer = .init(.server) };
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Each side MUST initiate a single control stream at the beginning of
        //# the connection and send its SETTINGS frame as the first frame on this
        //# stream.
        //= type=test
        /// Open the control stream and QPACK's two once the handshake is
        /// confirmed, and push whatever of them the peer's credit takes. Call
        /// it after every `receive` and `onTimeout`, before draining `send`:
        /// a stream the peer had no credit for goes as soon as it has.
        pub fn flush(self: *Self, connection: *Connection) void {
            if (!connection.handshakeConfirmed()) return;
            if (!self.started) self.start();
            assert(self.started);
            for (&self.outgoing, unidirectional_streams) |*outgoing, id| {
                assert(outgoing.sent <= outgoing.len);
                if (outgoing.sent == outgoing.len) continue;
                const rest = outgoing.octets[outgoing.sent..outgoing.len];
                const taken = connection.write(id, rest, false) catch |err| switch (err) {
                    // The peer's stream limit or its credit, which the next
                    // MAX_STREAMS or MAX_STREAM_DATA lifts: try again then.
                    error.TooManyStreams, error.FlowControl => 0,
                    // A send half the peer stopped, or a connection past
                    // holding streams: a critical stream that cannot be
                    // written is the peer's H3_CLOSED_CRITICAL_STREAM to
                    // raise, and nothing here can repair it.
                    error.StreamState, error.Protocol, error.NotFound, error.Retired, error.FinalSize, error.TooFragmented => 0,
                };
                outgoing.sent += @intCast(taken);
            }
        }

        /// Produce the three streams' octets. Infallible: the control stream's
        /// buffer holds SETTINGS several times over and a QPACK stream's
        /// eight octets hold its one-octet type, which is what the two
        /// `unreachable`s below rest on.
        fn start(self: *Self) void {
            assert(!self.started);
            const control = &self.outgoing[0];
            control.len = @intCast(self.sequencer.writeControl(&control.octets) catch unreachable); // `control_octets_max` is past SETTINGS' widest, which is under thirty octets.
            const kinds = [_]h3stream.Type{ .qpack_encoder, .qpack_decoder };
            for (self.outgoing[1..], kinds) |*outgoing, kind| {
                outgoing.len = @intCast(h3stream.write(outgoing.octets[0..qpack_stream_octets_max], kind) catch unreachable); // A stream type is one varint, at most eight octets.
            }
            self.started = true;
            assert(control.len > 0);
        }

        /// Read what `connection` has readable on `id` and say what it meant.
        ///
        /// The peer's control and QPACK streams are read and consumed here;
        /// their events — SETTINGS and GOAWAY — carry no borrowed octets. A
        /// request stream's events borrow the connection's buffer, so its
        /// octets are handed back by the caller's `consume` once the
        /// application has what it needs.
        ///
        /// `body_room` is how many octets of DATA payload the application can
        /// take now. Body past it stays unread, so the stream's flow control
        /// window does not move and the peer is held back by QUIC rather than
        /// buffered here — which is the whole of a proxy's backpressure.
        ///
        /// A connection error closes the connection with the code RFC 9114
        /// names and is returned for the caller's records.
        pub fn receive(
            self: *Self,
            connection: *Connection,
            id: u64,
            events: []http3.Event,
            body_room: u64,
        ) http3.Error!Received {
            const data = connection.readable(id);
            const fin = connection.readableFin(id);
            if (data.len == 0 and !fin) return .{ .consumed = 0, .events = 0 };
            const kind = stream_id.kindOf(id);
            if (!kind.bidirectional()) return self.receiveUnidirectional(connection, id, data, fin, events);
            // A server opens no bidirectional stream (RFC 9114 section 6.1),
            // so every one is a client's request.
            assert(kind.initiator() == .client);
            // A stream whose request this session finished and released, read
            // again only because the embedder's list still names it: nothing
            // new arrived (the FIN fixed the end), so there is nothing to say,
            // and handing it to the sequencer would make it a new request.
            if (data.len == 0 and !self.sequencer.tracks(id) and id < self.next_request) {
                return .{ .consumed = 0, .events = 0 };
            }
            if (self.refused(connection, id)) return .{ .consumed = 0, .events = 0 };
            self.next_request = @max(self.next_request, id + stream_id.kind_count);
            const read = self.sequencer.receiveBounded(id, data, fin, events, body_room) catch |err| {
                connection.closeApplication(@backingInt(http3.code(err)));
                return err;
            };
            assert(read.consumed <= data.len);
            assert(read.events <= events.len);
            return .{ .consumed = read.consumed, .events = read.events };
        }

        /// The peer's control and QPACK streams, which the session consumes
        /// itself: their events — SETTINGS and GOAWAY — borrow nothing.
        ///
        /// Read to the end of what is readable, in as many passes as that
        /// takes, because nothing would ask again: a stream whose octets were
        /// left unconsumed gets no new `stream_readable` until more arrive.
        /// Events past `events` are dropped rather than held, which loses no
        /// state — `settings` and the sequencer's GOAWAY keep it — and the
        /// passes are bounded by `data`, since each one that consumes nothing
        /// ends the loop.
        fn receiveUnidirectional(
            self: *Self,
            connection: *Connection,
            id: u64,
            data: []const u8,
            fin: bool,
            events: []http3.Event,
        ) http3.Error!Received {
            var consumed: usize = 0;
            var produced: usize = 0;
            var spare: [4]http3.Event = undefined;
            // Bounded by `data`: a pass that consumes nothing breaks, so every
            // other pass takes at least one octet.
            while (consumed < data.len or (fin and consumed == data.len and produced == 0)) {
                const into = if (produced < events.len) events[produced..] else &spare;
                const read = self.sequencer.receive(id, data[consumed..], fin, into) catch |err| {
                    connection.closeApplication(@backingInt(http3.code(err)));
                    return err;
                };
                if (produced < events.len) produced += read.events;
                consumed += read.consumed;
                if (read.consumed == 0) break;
            }
            assert(consumed <= data.len);
            assert(produced <= events.len);
            // `consumed` is at most `readable(id).len`, which `consume` accepts.
            if (consumed > 0) connection.consume(id, consumed) catch unreachable;
            return .{ .consumed = 0, .events = produced };
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# Upon sending a GOAWAY frame, the endpoint
        //# SHOULD explicitly cancel (see Sections 4.1.1 and 7.2.3) any requests
        //# or pushes that have identifiers greater than or equal to the one
        //# indicated, in order to clean up transport state for the affected
        //# streams.  The endpoint SHOULD continue to do so as more requests or
        //# pushes arrive.
        //= type=test
        //
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
        //# When the server cancels a request without performing any application
        //# processing, the request is considered "rejected".  The server SHOULD
        //# abort its response stream with the error code H3_REQUEST_REJECTED.
        //= type=test
        //
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
        //# Servers MUST NOT use the H3_REQUEST_REJECTED error code for requests
        //# that were partially or fully processed.
        //= type=test
        /// After a GOAWAY, a request stream at or above the identifier it named
        /// is reset as unprocessed — before any of its octets are read, which
        /// is what makes H3_REQUEST_REJECTED the honest code.
        fn refused(self: *Self, connection: *Connection, id: u64) bool {
            const limit = self.goaway_sent orelse return false;
            if (id < limit) return false;
            assert(id >= limit);
            self.cancel(connection, id, .request_rejected);
            return true;
        }

        /// Hand back a request stream's octets once the application is done
        /// with the events `receive` reported. This is what moves the stream's
        /// flow control window.
        pub fn consume(self: *Self, connection: *Connection, id: u64, received: Received) void {
            _ = self;
            if (received.consumed == 0) return;
            assert(stream_id.kindOf(id).bidirectional());
            connection.consume(id, received.consumed) catch unreachable; // `received` came from `receive` on this stream, whose `consumed` is at most what was readable, and nothing reads between the two.
        }

        /// A request's response headers, or with `fin` a response that is only
        /// headers. QPACK-encoded against the static table into `scratch`, and
        /// written whole or not at all.
        pub fn writeHeaders(
            self: *Self,
            connection: *Connection,
            id: u64,
            list: []const qpack.Field,
            scratch: []u8,
            fin: bool,
        ) WriteError!void {
            if (!stream_id.kindOf(id).bidirectional()) return error.StreamState;
            const octets = self.sequencer.writeHeaders(scratch, list) catch |err| switch (err) {
                error.OutputTooSmall => return error.OutputTooSmall,
                // `Http3.writeHeaders` returns `OutputTooSmall` and nothing
                // else — every failure in its body is the target's size — so
                // the arm above is the whole of what reaches here.
                else => unreachable,
            };
            assert(octets > 0);
            assert(octets <= scratch.len);
            try writeWhole(connection, id, scratch[0..octets], fin);
        }

        /// A request's trailer section, which ends the response.
        pub fn writeTrailers(
            self: *Self,
            connection: *Connection,
            id: u64,
            list: []const qpack.Field,
            scratch: []u8,
        ) WriteError!void {
            try self.writeHeaders(connection, id, list, scratch, true);
        }

        /// As much of `body` as fits now, as one DATA frame, and the number of
        /// its octets taken; with `fin`, the response ends once all of `body`
        /// has gone. Zero when not even a frame header and one octet fit.
        pub fn writeData(
            self: *Self,
            connection: *Connection,
            id: u64,
            body: []const u8,
            fin: bool,
        ) WriteError!usize {
            _ = self;
            if (!stream_id.kindOf(id).bidirectional()) return error.StreamState;
            if (body.len == 0) {
                if (fin) try writeWhole(connection, id, &.{}, true);
                return 0;
            }
            const room = connection.writable(id) orelse return error.StreamState;
            if (room <= frame_header_octets_max) return 0;
            // The header's length depends on the payload's, so the payload is
            // sized against the widest header and the header written for it.
            const payload: usize = @intCast(@min(body.len, room - frame_header_octets_max));
            var header: [frame_header_octets_max]u8 = undefined;
            // Nine octets hold DATA's type and any length up to 2^62, and the
            // payload is at most a stream's send buffer.
            const header_octets = frame.writeHeader(&header, .data, payload) catch unreachable;
            assert(header_octets + payload <= room);
            const last = fin and payload == body.len;
            // The header's write lowers the buffer, the stream's credit and the
            // connection's by the same amount, so the body still fits; only a
            // send half that died between the two could fail it, and nothing
            // runs between them.
            try writeWhole(connection, id, header[0..header_octets], false);
            try writeWhole(connection, id, body[0..payload], last);
            return payload;
        }

        /// End a response with no more octets.
        pub fn finish(self: *Self, connection: *Connection, id: u64) WriteError!void {
            _ = self;
            try writeWhole(connection, id, &.{}, true);
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
        //# Implementations SHOULD cancel requests by abruptly terminating any
        //# directions of a stream that are still open.
        /// Abandon a request in both directions with an RFC 9114 code: reset
        /// what this endpoint was sending and ask the peer to stop sending.
        /// The stream's sequencing state goes too.
        pub fn cancel(self: *Self, connection: *Connection, id: u64, code: error_code.Application) void {
            assert(stream_id.kindOf(id).bidirectional());
            // Each refusal means that half is already gone — retired, never
            // opened by the peer, or finished — which is what cancelling it
            // would have achieved.
            connection.resetStream(id, @backingInt(code)) catch |err| switch (err) {
                error.NotFound, error.Retired, error.StreamState, error.TooManyStreams => {},
                error.FlowControl, error.FinalSize, error.Protocol, error.TooFragmented => {},
            };
            connection.stopSending(id, @backingInt(code)) catch |err| switch (err) {
                error.NotFound, error.Retired, error.StreamState, error.TooManyStreams => {},
                error.FlowControl, error.FinalSize, error.Protocol, error.TooFragmented => {},
            };
            self.sequencer.release(id);
            assert(!self.sequencer.tracks(id));
        }

        /// Forget a request stream's sequencing state: when its response is
        /// done, or the peer reset it.
        pub fn release(self: *Self, id: u64) void {
            self.sequencer.release(id);
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# An endpoint MAY send multiple GOAWAY frames indicating different
        //# identifiers, but the identifier in each frame MUST NOT be greater
        //# than the identifier in any previous frame, since clients might
        //# already have retried unprocessed requests on another HTTP connection.
        //= type=test
        /// Begin a graceful drain: GOAWAY on the control stream, naming the
        /// first request stream this endpoint will not process. Without an
        /// `identifier`, one past the highest request seen — every request in
        /// flight completes and no new one is taken.
        ///
        /// Requests at or above it that arrive afterwards are reset with
        /// H3_REQUEST_REJECTED. Once the requests below it are answered, the
        /// embedder closes the connection with `closeApplication(no_error)`.
        pub fn goaway(self: *Self, connection: *Connection, identifier: ?u64) GoawayError!void {
            if (!self.started) self.flush(connection);
            if (!self.started) return error.HandshakeIncomplete;
            const id = identifier orelse self.next_request;
            // Section 5.2: the identifier is a client-initiated bidirectional
            // stream's. And not below a request already read: a GOAWAY says
            // everything at or above it will not be processed, and refusing a
            // request that was is section 4.1.1's MUST NOT — so a caller's
            // identifier is checked rather than trusted.
            if (stream_id.kindOf(id) != .client_bidirectional) return error.IdError;
            if (id < self.next_request) return error.IdError;
            const control = &self.outgoing[0];
            if (control.len + goaway_frame_octets_max > control.octets.len) return error.OutputTooSmall;
            const octets = try self.sequencer.writeGoaway(control.octets[control.len..], id);
            control.len += @intCast(octets);
            assert(control.len <= control.octets.len);
            self.goaway_sent = id;
            self.flush(connection);
        }

        /// The peer's SETTINGS, once they arrive.
        pub fn settings(self: *const Self) ?http3.Settings {
            return self.sequencer.settings();
        }
    };
}

/// Write all of `octets` on `id`, or nothing.
fn writeWhole(connection: anytype, id: u64, octets: []const u8, fin: bool) WriteError!void {
    const room = connection.writable(id) orelse return error.StreamState;
    if (room < octets.len) return error.WouldBlock;
    const taken = connection.write(id, octets, fin) catch return error.StreamState;
    // `writable` said it would fit, and nothing ran between the two.
    assert(taken == octets.len);
}

const testing = std.testing;
const quic_connection = @import("quic/Connection.zig");
const endpoint = @import("quic/endpoint.zig");
const crypto = @import("quic/crypto.zig");
const ConnectionId = @import("quic/ConnectionId.zig");

const TestConnection = quic_connection.Connection(.{
    .crypto_octets = 2048,
    .ack_ranges_max = 8,
    .sent_max = 64,
    .streams_max = 16,
    .stream_receive_octets = 4 * 1024,
    .stream_send_octets = 8 * 1024,
    .connection_receive_octets = 32 * 1024,
});
const test_config: http3.Config = .{ .requests_max = 4, .unidirectional_max = 6 };
const TestSession = Http3Server(TestConnection, test_config);
const ClientHttp3 = http3.Http3(test_config);

const client_cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_source = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const server_source = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

/// A client and a server connection through a scripted handshake, each having
/// applied the other's own transport parameters, the way a consumer gets
/// there. Pointer-stable: the caller owns both.
fn connect(client: *TestConnection, server: *TestConnection) !void {
    client.* = .init(.{
        .side = .client,
        .original_destination = try ConnectionId.init(&client_cid),
        .source = try ConnectionId.init(&client_source),
        // The server's three streams, and the client's four requests.
        .advertised = .{ .max_streams_bidirectional = 0, .max_streams_unidirectional = 3, .streams_opened_max = 4 },
    });
    try client.cryptoIn(.initial, "ClientHello");
    var first: [TestConnection.datagram_octets]u8 = undefined;
    const octets = try client.send(&first, 0);
    const datagram = endpoint.classify(first[0..octets], server_source.len);
    try server.initServer(.{
        .initial_destination = datagram.destination,
        .source = try ConnectionId.init(&server_source),
        .advertised = .{ .max_streams_bidirectional = 4, .max_streams_unidirectional = 6, .streams_opened_max = 3 },
    });
    try server.receive(first[0..octets], 0);
    for ([_]crypto.Level{ .handshake, .one_rtt }, [_]u8{ 0x11, 0x22 }) |level, seed| {
        const raw: [32]u8 = @splat(seed);
        const secret = try crypto.Secret.init(&raw);
        inline for (.{ client, server }) |one| {
            try one.installSecret(level, .send, &secret, .aes_128_gcm_sha256);
            try one.installSecret(level, .receive, &secret, .aes_128_gcm_sha256);
        }
    }
    server.cryptoConsumed(.initial, server.cryptoOut(.initial).len);
    try server.cryptoIn(.initial, "ServerHello");
    try server.cryptoIn(.handshake, "EncryptedExtensions");
    try pump(server, client);
    try client.cryptoIn(.handshake, "Finished");
    try pump(client, server);

    var client_parameters: [TestConnection.local_transport_parameters_octets_max]u8 = undefined;
    var server_parameters: [TestConnection.local_transport_parameters_octets_max]u8 = undefined;
    try server.transportParametersIn(try client.localTransportParameters(&client_parameters));
    try client.transportParametersIn(try server.localTransportParameters(&server_parameters));
    server.confirmHandshake();
    try pump(server, client);
    try testing.expect(client.handshakeConfirmed());
    try pump(client, server);
}

/// Everything `from` wants to send, delivered to `to`.
fn pump(from: *TestConnection, to: *TestConnection) !void {
    var datagram: [TestConnection.datagram_octets]u8 = undefined;
    for (0..32) |_| {
        const octets = try from.send(&datagram, 1000);
        if (octets == 0) return;
        try to.receive(datagram[0..octets], 1000);
    }
}

fn drainEvents(connection: *TestConnection) void {
    while (connection.poll()) |_| {}
}

/// A request a client would send: HEADERS, then a DATA frame carrying `body`,
/// then FIN.
fn sendRequest(client: *TestConnection, client_http3: *ClientHttp3, id: u64, body: []const u8) !void {
    var frames: [4096]u8 = undefined;
    var offset = try client_http3.writeHeaders(&frames, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/upload" },
    });
    offset += try ClientHttp3.writeData(frames[offset..], body.len);
    @memcpy(frames[offset..][0..body.len], body);
    offset += body.len;
    try testing.expectEqual(offset, try client.write(id, frames[0..offset], true));
}

test "a request crosses in, and a response with trailers crosses back" {
    var client: TestConnection = undefined;
    var server: TestConnection = undefined;
    try connect(&client, &server);
    var session: TestSession = .init();
    var client_http3: ClientHttp3 = .init(.client);

    try sendRequest(&client, &client_http3, 0, "hello");
    try pump(&client, &server);
    drainEvents(&server);

    var events: [8]http3.Event = undefined;
    const read = try session.receive(&server, 0, &events, 1024);
    try testing.expectEqual(@as(usize, 3), read.events);
    var scratch: [512]u8 = undefined;
    var storage: [512]u8 = undefined;
    var list: [16]qpack.Field = undefined;
    const request = try decodeSection(events[0].headers.section, .{ .kind = .request }, 1 << 16, &scratch, &storage, &list);
    try testing.expectEqualStrings(":method", request.fields[0].name);
    try testing.expectEqualStrings("/upload", request.fields[3].value);
    try testing.expectEqualStrings("hello", events[1].data.payload);
    try testing.expectEqual(@as(u64, 0), events[2].finished);
    session.consume(&server, 0, read);

    // The control and QPACK streams go out first, then the response.
    session.flush(&server);
    var header_scratch: [256]u8 = undefined;
    try session.writeHeaders(&server, 0, &.{.{ .name = ":status", .value = "200" }}, &header_scratch, false);
    try testing.expectEqual(@as(usize, 4), try session.writeData(&server, 0, "body", false));
    try session.writeTrailers(&server, 0, &.{.{ .name = "grpc-status", .value = "0" }}, &header_scratch);
    session.release(0);
    try pump(&server, &client);

    var answer: [8]http3.Event = undefined;
    const response = try client_http3.receive(0, client.readable(0), client.readableFin(0), &answer);
    try testing.expectEqual(@as(usize, 4), response.events);
    try testing.expect(!answer[0].headers.trailers);
    try testing.expectEqualStrings("body", answer[1].data.payload);
    try testing.expect(answer[2].headers.trailers);
    try testing.expectEqual(@as(u64, 0), answer[3].finished);
    // And the client saw this endpoint's SETTINGS on the control stream.
    const control = try client_http3.receive(3, client.readable(3), false, &answer);
    try testing.expectEqual(@as(usize, 1), control.events);
    try testing.expectEqual(@as(u64, 0), answer[0].settings.qpack_max_table_capacity);
}

test "body past what the application can take stays unread, and the window holds" {
    var client: TestConnection = undefined;
    var server: TestConnection = undefined;
    try connect(&client, &server);
    var session: TestSession = .init();
    var client_http3: ClientHttp3 = .init(.client);
    const body: [3000]u8 = @splat('b');
    try sendRequest(&client, &client_http3, 0, &body);
    try pump(&client, &server);

    var events: [8]http3.Event = undefined;
    var delivered: usize = 0;
    // Five hundred octets of room at a time: never more is handed over, and
    // the rest is still there for the next read.
    for (0..16) |_| {
        const read = try session.receive(&server, 0, &events, 500);
        for (events[0..read.events]) |event| switch (event) {
            .data => |value| {
                try testing.expect(value.payload.len <= 500);
                delivered += value.payload.len;
            },
            else => {},
        };
        session.consume(&server, 0, read);
        if (delivered == body.len) break;
    }
    try testing.expectEqual(body.len, delivered);
}

test "a HEADERS frame is written whole or not at all" {
    var client: TestConnection = undefined;
    var server: TestConnection = undefined;
    try connect(&client, &server);
    var session: TestSession = .init();
    var client_http3: ClientHttp3 = .init(.client);
    try sendRequest(&client, &client_http3, 0, "x");
    try pump(&client, &server);
    var events: [8]http3.Event = undefined;
    session.consume(&server, 0, try session.receive(&server, 0, &events, 64));

    // Fill the stream's credit with body, leaving less than a HEADERS frame.
    const filler: [8 * 1024]u8 = @splat('f');
    var written: usize = 0;
    for (0..8) |_| written += try session.writeData(&server, 0, &filler, false);
    // `writeData` stops once a frame header and an octet no longer fit.
    try testing.expect(server.writable(0).? <= frame_header_octets_max);
    const before = server.writable(0);
    var scratch: [256]u8 = undefined;
    try testing.expectError(error.WouldBlock, session.writeTrailers(&server, 0, &.{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "grpc-message", .value = "a trailer longer than the room left" },
    }, &scratch));
    try testing.expectEqual(before, server.writable(0));
    try testing.expect(written > 0);
    // And a stream whose response is over cannot be written on at all, which
    // is a different answer from "not yet".
    try session.finish(&server, 0);
    try testing.expectEqual(@as(?u64, null), server.writable(0));
    try testing.expectError(error.StreamState, session.writeData(&server, 0, "late", false));
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
//# Servers MUST NOT use the H3_REQUEST_REJECTED error code for requests
//# that were partially or fully processed.
//= type=test
test "after a GOAWAY a later request is rejected unread, and earlier ones run" {
    var client: TestConnection = undefined;
    var server: TestConnection = undefined;
    try connect(&client, &server);
    var session: TestSession = .init();
    var client_http3: ClientHttp3 = .init(.client);
    try sendRequest(&client, &client_http3, 0, "first");
    try pump(&client, &server);
    var events: [8]http3.Event = undefined;
    const read = try session.receive(&server, 0, &events, 64);
    try testing.expect(read.events > 0);
    session.consume(&server, 0, read);

    // A GOAWAY naming a request already read would be a lie about it.
    try testing.expectError(error.IdError, session.goaway(&server, 0));
    try testing.expectError(error.IdError, session.goaway(&server, 6));
    // A graceful drain names one past the highest request seen.
    try session.goaway(&server, null);
    try testing.expectEqual(@as(?u64, 4), session.goaway_sent);
    try pump(&server, &client);
    var answer: [4]http3.Event = undefined;
    const control = try client_http3.receive(3, client.readable(3), false, &answer);
    try testing.expectEqual(@as(u64, 4), answer[control.events - 1].goaway);

    // A request the client had already sent at or above it is refused.
    try sendRequest(&client, &client_http3, 4, "second");
    try pump(&client, &server);
    const refused = try session.receive(&server, 4, &events, 64);
    try testing.expectEqual(@as(usize, 0), refused.events);
    try pump(&server, &client);
    var reset_code: ?u64 = null;
    while (client.poll()) |event| switch (event) {
        .stream_reset => |value| if (value.stream == 4) {
            reset_code = value.code;
        },
        else => {},
    };
    try testing.expectEqual(@as(?u64, @backingInt(error_code.Application.request_rejected)), reset_code);
}

test "a field section is decoded into the caller's storage, or refused" {
    var section: [256]u8 = undefined;
    const encoded = try qpack.field_line.encode(&section, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        // No `:path`: section 4.3.1 makes the request malformed.
    });
    var scratch: [256]u8 = undefined;
    var storage: [256]u8 = undefined;
    var list: [8]qpack.Field = undefined;
    try testing.expectError(error.MessageError, decodeSection(section[0..encoded], .{ .kind = .request }, 1 << 16, &scratch, &storage, &list));
    try testing.expectError(error.DecompressionFailed, decodeSection(&.{ 0xff, 0xff, 0xff }, .{ .kind = .request }, 1 << 16, &scratch, &storage, &list));

    const good = try qpack.field_line.encode(&section, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
    });
    try testing.expectError(error.TooLarge, decodeSection(section[0..good], .{ .kind = .request }, 1 << 16, &scratch, &storage, list[0..2]));
    // Past the advertised field section size is a limit, not a decoding
    // failure: answered per request, never by closing the connection.
    try testing.expectError(error.TooLarge, decodeSection(section[0..good], .{ .kind = .request }, 64, &scratch, &storage, &list));
    const decoded = try decodeSection(section[0..good], .{ .kind = .request }, 1 << 16, &scratch, &storage, &list);
    try testing.expectEqual(@as(usize, 4), decoded.fields.len);
    // The names and values live in `storage`, not in the section.
    try testing.expect(@intFromPtr(decoded.fields[3].value.ptr) >= @intFromPtr(&storage));
}
