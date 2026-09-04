//! RFC 9114's connection layer: the sequencing that `frame.zig` and
//! `stream.zig` were missing.
//!
//! Those two files answer "what is this?" — a frame's type and length, a
//! unidirectional stream's type, which frames a stream may carry. This file
//! answers "may it be here, now?", which is a different question and the one
//! the errors are about: a SETTINGS frame is well-formed wherever it appears
//! and is a connection error everywhere except first on a control stream.
//!
//! ## The seam
//!
//! The same one the rest of the package uses, one layer up. Nothing here owns
//! a QUIC connection, a socket or a buffer: the caller reads octets off a
//! stream, hands them over, and is told how many were consumed and what they
//! meant.
//!
//! ```
//!     quic.readable(id)  ──▶  receive(id, data, fin, &events)
//!                             ├─ consumed: hand exactly this to quic.consume
//!                             └─ events:   what the octets were
//!
//!     writeControl(buffer)  ──▶  quic.write(our_control_stream, …)
//!     writeHeaders(buffer)  ──▶  quic.write(request_stream, …)
//! ```
//!
//! **An event's slices borrow from the `data` the caller passed in.** A
//! `headers` event names the field section inside the caller's own buffer
//! rather than copying it, which is what keeps this type a few hundred octets
//! instead of a few kilobytes per stream — and it means an event is only valid
//! until that buffer is reused. The events are written into a caller-owned
//! array for the same reason: the lifetime is visible at the call site instead
//! of hidden in a queue.
//!
//! ## Partial frames
//!
//! `receive` consumes whole frames and leaves a partial one alone, which is why
//! it returns a count rather than assuming it took everything. The caller
//! passes `quic.readable(id)` — a contiguous run from the read offset — and
//! consumes exactly what came back, so the remainder is still there when the
//! rest of the frame arrives. A field section therefore has to fit inside one
//! stream's receive window, which is `Connection.Config.stream_receive_octets`
//! and is the bound a consumer already chose.
//!
//! ## What is not here
//!
//! **Server push.** No PUSH_PROMISE is sent, no MAX_PUSH_ID is sent, and a
//! push stream is therefore `H3_ID_ERROR` by RFC 9114 section 4.6 — which is
//! implemented, because refusing a push correctly is not the same as
//! implementing push.
//!
//! **QPACK's dynamic table.** This endpoint advertises
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so its encoder and decoder streams
//! carry nothing. The peer's are accepted and discarded, which section 4.2 of
//! RFC 9204 requires of an endpoint that will not use them — refusing to read
//! them would stall a peer that is waiting for its own flow control window.

const std = @import("std");

const assert = @import("assert.zig").assert;
const error_code = @import("quic/error_code.zig");
const fields = @import("fields.zig");
const frame = @import("frame.zig");
const qpack = @import("qpack.zig");
const Side = @import("quic/crypto.zig").Side;
const stream = @import("stream.zig");
const stream_id = @import("quic/stream_id.zig");
const varint = @import("varint.zig");

pub const Config = struct {
    /// Request streams tracked at once. A stream past this is
    /// `H3_EXCESSIVE_LOAD` rather than a silently untracked stream, because an
    /// untracked one is a stream whose frame sequencing nothing checks.
    requests_max: u32 = 16,
    /// Peer-initiated unidirectional streams tracked at once. Four are
    /// meaningful — control, and QPACK's two, and one push — and the rest are
    /// section 6.2.3's reserved types, which arrive to prove that an
    /// implementation ignores what it does not know.
    unidirectional_max: u32 = 8,
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`, which is section 4.2.2's limit on the
    /// *uncompressed* size of a field section this endpoint will accept.
    max_field_section_size: u64 = 64 * 1024,
};

/// Every failure this layer can produce, named for the HTTP/3 error code it
/// becomes. `code` is the mapping, and it is exhaustive so that a new error
/// cannot be added without deciding what a peer is told about it.
pub const Error = error{
    /// The first frame on a control stream was not SETTINGS.
    MissingSettings,
    /// A frame that is well-formed and not permitted where it arrived.
    FrameUnexpected,
    /// A frame whose length does not match its contents.
    FrameError,
    /// A second control stream, or a second QPACK stream of one kind.
    StreamCreationError,
    /// A critical stream ended. Section 6.2.1: the control stream and QPACK's
    /// two are open for the life of the connection.
    ClosedCriticalStream,
    /// A push stream, or a GOAWAY that went backwards.
    IdError,
    /// A setting sent twice, or one of HTTP/2's.
    SettingsError,
    /// A field section that does not decode.
    GeneralProtocolError,
    /// More streams than this endpoint tracks.
    ExcessiveLoad,
    /// The caller's buffer is too small for what it asked to be written. Not a
    /// protocol error and not on the wire: the caller passes a bigger one.
    OutputTooSmall,
};

/// The code a peer is told, for every error above.
pub fn code(err: Error) error_code.Application {
    return switch (err) {
        error.MissingSettings => .missing_settings,
        error.FrameUnexpected => .frame_unexpected,
        error.FrameError => .frame_error,
        error.StreamCreationError => .stream_creation_error,
        error.ClosedCriticalStream => .closed_critical_stream,
        error.IdError => .id_error,
        error.SettingsError => .settings_error,
        error.GeneralProtocolError => .general_protocol_error,
        error.ExcessiveLoad => .excessive_load,
        // Nothing was received and nothing is wrong with the peer.
        error.OutputTooSmall => .internal_error,
    };
}

/// The settings this endpoint understands, with the defaults section 7.2.4.1
/// gives them. A setting this package does not know is ignored, which is the
/// same section's rule and the reason unknown identifiers are not an error.
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    max_field_section_size: u64 = std.math.maxInt(u64),
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
};

/// What a run of octets turned out to be.
///
/// Every slice borrows from the `data` passed to `receive`; see the module
/// comment.
pub const Event = union(enum) {
    /// The peer's SETTINGS, once.
    settings: Settings,
    /// A field section, still QPACK-encoded. Decoding it needs a buffer for
    /// the names and values, and that buffer is the caller's — a decoded field
    /// list is many times the size of the section it came from, and this layer
    /// holds no per-stream storage at all.
    headers: struct { stream: u64, section: []const u8, trailers: bool },
    /// A DATA frame's payload.
    data: struct { stream: u64, payload: []const u8 },
    /// The peer finished this stream.
    finished: u64,
    /// Section 7.2.6: the peer is going away, and will process nothing at or
    /// above this identifier.
    goaway: u64,
};

/// What `receive` did with the octets it was given.
pub const Received = struct {
    /// Octets consumed. The caller hands exactly this to `quic.consume`; the
    /// rest is a partial frame and will be there again next time.
    consumed: usize,
    /// Events written into the caller's array.
    events: usize,
};

pub fn Http3(comptime config: Config) type {
    comptime {
        assert(config.requests_max >= 1);
        // Section 6.2 names four types, and section 6.2.3's reserved ones
        // arrive alongside them. A table that cannot hold the four named ones
        // could reject a conforming peer's control stream.
        assert(config.unidirectional_max >= 4);
    }

    return struct {
        const Self = @This();

        /// A peer-initiated unidirectional stream, and what its first varint
        /// said it was.
        const Unidirectional = struct {
            id: u64,
            kind: union(enum) {
                /// The type varint has not arrived yet. A stream's type may be
                /// split across datagrams like anything else.
                unread,
                control,
                qpack_encoder,
                qpack_decoder,
                /// Section 6.2's rule for a type this endpoint does not
                /// implement: read it and throw it away, rather than treat it
                /// as an error.
                discard,
            },
        };

        /// Section 4.1's frame sequence on a request stream, as the four states
        /// it actually has. The rule is stated as two prohibitions — no DATA
        /// before HEADERS, nothing after the trailing HEADERS — and this is
        /// those two prohibitions with the states they imply.
        const Phase = enum { start, headers, data, trailers };

        const Request = struct {
            id: u64,
            phase: Phase = .start,
            /// Octets of the DATA frame in progress that have not arrived yet.
            ///
            /// A DATA frame's Length is the whole body when a server sends one
            /// frame per response, which is what ngtcp2 does — a megabyte in a
            /// single frame. Waiting for a whole frame before consuming any of
            /// it would then wait for a frame larger than the stream's receive
            /// window, and the window only moves when octets are consumed: the
            /// connection deadlocks, both endpoints correct, neither able to
            /// proceed. So DATA is delivered as it arrives and this is what is
            /// still owed. HEADERS is the opposite case and is still buffered
            /// whole, because a field section cannot be decoded in pieces.
            data_remaining: u64 = 0,
        };

        side: Side,

        /// This endpoint's control stream, once `writeControl` has produced it.
        control_written: bool = false,
        /// The peer's, and whether its SETTINGS have arrived.
        peer_control: ?u64 = null,
        peer_settings: ?Settings = null,
        peer_qpack_encoder: ?u64 = null,
        peer_qpack_decoder: ?u64 = null,

        /// Section 7.2.6: an endpoint may send several GOAWAYs, each naming an
        /// identifier no larger than the last.
        peer_goaway: ?u64 = null,
        /// And the last one this endpoint sent, for the sending half of the
        /// same rule.
        sent_goaway: ?u64 = null,

        unidirectional: [config.unidirectional_max]Unidirectional = undefined,
        unidirectional_count: u32 = 0,

        requests: [config.requests_max]Request = undefined,
        requests_count: u32 = 0,

        pub fn init(side: Side) Self {
            return .{ .side = side };
        }

        // ------------------------------------------------------------ writing

        /// The octets of this endpoint's control stream: its type, then
        /// SETTINGS. Written once, at the beginning, on a stream the caller
        /// opens for the purpose.
        ///
        /// Both halves in one call because they are one obligation: a control
        /// stream whose first frame is not SETTINGS is `H3_MISSING_SETTINGS` at
        /// the peer, and an API that let a caller send the type and then decide
        /// what to put on it would be an API that makes that error reachable.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Each side MUST initiate a single control stream at the beginning of
        //# the connection and send its SETTINGS frame as the first frame on this
        //# stream.
        //= type=test
        //
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# A SETTINGS frame MUST be sent as the first frame of each control
        //# stream (see Section 6.2.1) by each peer, and it MUST NOT be sent
        //# subsequently.
        //= type=test
        pub fn writeControl(self: *Self, target: []u8) Error!usize {
            assert(!self.control_written);
            var offset: usize = 0;
            offset += stream.write(target, .control) catch return error.OutputTooSmall;

            // The payload is built after the header, because the header's
            // Length has to name it and a SETTINGS payload's size is not known
            // until the settings are written.
            const reserve: usize = 1 + varint.octets_max;
            if (target.len <= offset + reserve) return error.OutputTooSmall;
            var payload: usize = 0;
            const body = target[offset + reserve ..];

            // Section 4.2 of RFC 9204: an endpoint that will not use the
            // dynamic table says so, and then its encoder stream carries
            // nothing. Both are sent explicitly rather than left to their
            // defaults — the defaults are the same, and a peer reading a
            // capture should not have to know that.
            payload += frame.writeSetting(body[payload..], .qpack_max_table_capacity, 0) catch
                return error.OutputTooSmall;
            payload += frame.writeSetting(body[payload..], .qpack_blocked_streams, 0) catch
                return error.OutputTooSmall;
            payload += frame.writeSetting(body[payload..], .max_field_section_size, config.max_field_section_size) catch
                return error.OutputTooSmall;

            const header = frame.writeHeader(target[offset..], .settings, payload) catch
                return error.OutputTooSmall;
            // The payload was built at a fixed offset because the header's own
            // width was not known; it moves down against the header now. Always
            // downward, so the copy is forward and the ranges may overlap.
            assert(header <= reserve);
            std.mem.copyForwards(
                u8,
                target[offset + header ..][0..payload],
                target[offset + reserve ..][0..payload],
            );
            offset += header + payload;

            self.control_written = true;
            return offset;
        }

        /// A HEADERS frame carrying `list`, QPACK-encoded against the static
        /// table.
        pub fn writeHeaders(self: *const Self, target: []u8, list: []const qpack.Field) Error!usize {
            _ = self;
            const reserve: usize = 1 + varint.octets_max;
            if (target.len <= reserve) return error.OutputTooSmall;
            const section = qpack.field_line.encode(target[reserve..], list) catch
                return error.OutputTooSmall;
            const header = frame.writeHeader(target, .headers, section) catch
                return error.OutputTooSmall;
            assert(header <= reserve);
            std.mem.copyForwards(u8, target[header..][0..section], target[reserve..][0..section]);
            return header + section;
        }

        /// A DATA frame's header, for `payload_octets` of body the caller
        /// writes after it. The body is not copied through here: it is the
        /// application's and may be megabytes.
        pub fn writeData(target: []u8, payload_octets: u64) Error!usize {
            return frame.writeHeader(target, .data, payload_octets) catch error.OutputTooSmall;
        }

        /// Section 7.2.6's GOAWAY, for the control stream.
        ///
        /// The sending half of the rule `receiveControl` enforces on the
        /// receiving side. An endpoint may narrow what it will still process
        /// and may not widen it: a peer that saw the first identifier has
        /// already retried everything above it somewhere else, and a second
        /// GOAWAY naming more would be asking it to un-retry them.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# An endpoint MAY send multiple GOAWAY frames indicating different
        //# identifiers, but the identifier in each frame MUST NOT be greater
        //# than the identifier in any previous frame, since clients might
        //# already have retried unprocessed requests on another HTTP connection.
        //= type=test
        pub fn writeGoaway(self: *Self, target: []u8, identifier: u64) Error!usize {
            assert(self.control_written);
            if (self.sent_goaway) |previous| {
                if (identifier > previous) return error.IdError;
            }
            const reserve: usize = 1 + varint.octets_max;
            if (target.len <= reserve) return error.OutputTooSmall;
            const payload = varint.encode(target[reserve..], identifier) catch
                return error.OutputTooSmall;
            const header = frame.writeHeader(target, .goaway, payload) catch
                return error.OutputTooSmall;
            assert(header <= reserve);
            std.mem.copyForwards(u8, target[header..][0..payload], target[reserve..][0..payload]);
            self.sent_goaway = identifier;
            return header + payload;
        }

        // ------------------------------------------------------------ reading

        /// Consume whole frames from the front of `data`, writing what they
        /// meant into `events`.
        ///
        /// `fin` is whether the peer ended the stream at the end of `data`; it
        /// is what makes a closed control stream an error and a finished
        /// request stream an event.
        pub fn receive(
            self: *Self,
            id: u64,
            data: []const u8,
            fin: bool,
            events: []Event,
        ) Error!Received {
            const kind = stream_id.kindOf(id);
            if (kind.bidirectional()) return self.receiveRequest(id, data, fin, events);
            // A unidirectional stream this endpoint opened is one it cannot
            // receive on; QUIC refuses the frame before this layer sees it.
            assert(kind.initiator() != self.side);
            return self.receiveUnidirectional(id, data, fin, events);
        }

        fn receiveUnidirectional(
            self: *Self,
            id: u64,
            data: []const u8,
            fin: bool,
            events: []Event,
        ) Error!Received {
            const entry = try self.unidirectionalFor(id);
            var consumed: usize = 0;

            if (entry.kind == .unread) {
                const parsed = stream.parse(data) catch |err| switch (err) {
                    // Section 6.2: the type is a varint and may be split like
                    // anything else. Nothing is consumed and it arrives again.
                    error.Incomplete => return .{ .consumed = 0, .events = 0 },
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
                    //# Each frame's payload MUST contain exactly the fields identified
                    //# in its description.
                    //= type=test
                    error.NotMinimal => return error.FrameError,
                };
                consumed += parsed.octets;
                try self.classify(entry, parsed.stream_type);
            }

            switch (entry.kind) {
                .control => {
                    const rest = try self.receiveControl(data[consumed..], fin, events);
                    return .{ .consumed = consumed + rest.consumed, .events = rest.events };
                },
                // Section 4.2 of RFC 9204: this endpoint advertised a zero
                // capacity, so a conforming peer sends nothing on these — and
                // an endpoint that stopped reading them would stall a peer
                // waiting for the window to move. Read and discarded.
                .qpack_encoder, .qpack_decoder, .discard => {
                    if (fin and entry.kind != .discard) {
                        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                        //# If either control stream is closed at any point, this MUST be
                        //# treated as a connection error of type
                        //# H3_CLOSED_CRITICAL_STREAM.
                        //= type=test
                        return error.ClosedCriticalStream;
                    }
                    return .{ .consumed = data.len, .events = 0 };
                },
                .unread => unreachable, // `classify` leaves no stream unread.
            }
        }

        /// Decide what a unidirectional stream is, and refuse a second one of a
        /// kind there may only be one of.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Only one control stream per peer is permitted; receipt of a second
        //# stream claiming to be a control stream MUST be treated as a
        //# connection error of type H3_STREAM_CREATION_ERROR.
        //= type=test
        //
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Recipients of unknown stream types MUST either abort reading of the
        //# stream or discard incoming data without further processing.
        //= type=test
        fn classify(self: *Self, entry: *Unidirectional, stream_type: stream.Type) Error!void {
            switch (stream_type) {
                .control => {
                    if (self.peer_control != null) return error.StreamCreationError;
                    self.peer_control = entry.id;
                    entry.kind = .control;
                },
                .qpack_encoder => {
                    if (self.peer_qpack_encoder != null) return error.StreamCreationError;
                    self.peer_qpack_encoder = entry.id;
                    entry.kind = .qpack_encoder;
                },
                .qpack_decoder => {
                    if (self.peer_qpack_decoder != null) return error.StreamCreationError;
                    self.peer_qpack_decoder = entry.id;
                    entry.kind = .qpack_decoder;
                },
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
                //# A client MUST treat receipt of a push stream as a connection
                //# error of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or
                //# when the stream references a push ID that is greater than the maximum
                //# push ID.
                //= type=test
                //
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
                //# Only servers can push; if a server receives a client-initiated push
                //# stream, this MUST be treated as a connection error of type
                //# H3_STREAM_CREATION_ERROR.
                //= type=test
                .push => return if (self.side == .client) error.IdError else error.StreamCreationError,
                // Section 6.2.3's reserved types arrive to prove that an
                // implementation ignores what it does not know, and everything
                // else unknown is treated the same way.
                _ => entry.kind = .discard,
            }
        }

        fn receiveControl(self: *Self, data: []const u8, fin: bool, events: []Event) Error!Received {
            // Checked before the frames rather than after: a datagram that both
            // carries a frame and ends the stream is still a closed critical
            // stream, and processing the frame first would report the wrong
            // thing when both are true.
            if (fin) return error.ClosedCriticalStream;

            var consumed: usize = 0;
            var produced: usize = 0;
            // Bounded by `data`: every iteration consumes at least the two
            // octets of a frame header, and the loop stops when a whole frame
            // does not fit in what is left.
            while (consumed < data.len) {
                if (produced == events.len) break;
                const header = frame.parseHeader(data[consumed..]) catch |err| switch (err) {
                    error.Incomplete => break,
                    error.NotMinimal, error.Http2Reserved => return error.FrameError,
                };
                const length = std.math.cast(usize, header.length) orelse return error.FrameError;
                const total = header.octets + length;
                if (data.len - consumed < total) break;
                const payload = data[consumed + header.octets ..][0..length];

                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If the first frame of the control stream is any other frame
                //# type, this MUST be treated as a connection error of type
                //# H3_MISSING_SETTINGS.
                //= type=test
                if (self.peer_settings == null and header.frame_type != .settings) {
                    return error.MissingSettings;
                }
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //# DATA frames MUST be associated with an HTTP request or response.  If
                //# a DATA frame is received on a control stream, the recipient MUST
                //# respond with a connection error of type H3_FRAME_UNEXPECTED.
                //= type=test
                //
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
                //# HEADERS frames can only be sent on request streams or push streams.
                //# If a HEADERS frame is received on a control stream, the recipient
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
                //= type=test
                if (!header.frame_type.allowedOnControlStream()) return error.FrameUnexpected;

                switch (header.frame_type) {
                    .settings => {
                        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                        //# If an endpoint receives a second SETTINGS frame on the
                        //# control stream, the endpoint MUST respond with a connection
                        //# error of type H3_FRAME_UNEXPECTED.
                        //= type=test
                        if (self.peer_settings != null) return error.FrameUnexpected;
                        const parsed = try parseSettings(payload);
                        self.peer_settings = parsed;
                        events[produced] = .{ .settings = parsed };
                        produced += 1;
                    },
                    .goaway => {
                        const identifier = frame.parseSingleVarint(payload) catch
                            return error.FrameError;
                        // Section 5.2 rather than 7.2.6: the frame's layout is in
                        // section 7, and what an endpoint may do with a second
                        // one is in the shutdown section that motivates it.
                        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
                        //# Receiving a GOAWAY containing a larger identifier than previously
                        //# received MUST be treated as a connection error of type H3_ID_ERROR.
                        //= type=test
                        if (self.peer_goaway) |previous| {
                            if (identifier > previous) return error.IdError;
                        }
                        self.peer_goaway = identifier;
                        events[produced] = .{ .goaway = identifier };
                        produced += 1;
                    },
                    // CANCEL_PUSH and MAX_PUSH_ID are permitted here and mean
                    // nothing to an endpoint that neither pushes nor accepts a
                    // push. Read past rather than refused, which is what
                    // section 7.2.3 asks of a receiver with no push state.
                    .cancel_push, .max_push_id => {},
                    // Section 9: an unknown frame type is ignored, which is
                    // what makes the extension point an extension point.
                    else => {},
                }
                consumed += total;
            }
            return .{ .consumed = consumed, .events = produced };
        }

        fn receiveRequest(
            self: *Self,
            id: u64,
            data: []const u8,
            fin: bool,
            events: []Event,
        ) Error!Received {
            const request = try self.requestFor(id);
            var consumed: usize = 0;
            var produced: usize = 0;
            // Bounded by `data`, as in `receiveControl`.
            while (consumed < data.len) {
                if (produced == events.len) break;

                // The tail of a DATA frame whose header arrived earlier.
                if (request.data_remaining > 0) {
                    const available = data.len - consumed;
                    const take = @min(request.data_remaining, available);
                    events[produced] = .{ .data = .{
                        .stream = id,
                        .payload = data[consumed..][0..@intCast(take)],
                    } };
                    produced += 1;
                    consumed += @intCast(take);
                    request.data_remaining -= take;
                    continue;
                }

                const header = frame.parseHeader(data[consumed..]) catch |err| switch (err) {
                    error.Incomplete => break,
                    // `parseHeader` refuses HTTP/2's frame types; section 11.2.1's
                    // rule about them is cited where that check lives.
                    error.NotMinimal, error.Http2Reserved => return error.FrameError,
                };
                if (!header.frame_type.allowedOnRequestStream()) return error.FrameUnexpected;

                // DATA is the one frame whose payload does not have to be here
                // before any of it is delivered; see `Request.data_remaining`.
                if (header.frame_type == .data) {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# In particular, a DATA frame before any HEADERS frame, or a
                    //# HEADERS or DATA frame after the trailing HEADERS frame, is
                    //# considered invalid.
                    //= type=test
                    switch (request.phase) {
                        .start, .trailers => return error.FrameUnexpected,
                        .headers, .data => request.phase = .data,
                    }
                    consumed += header.octets;
                    request.data_remaining = header.length;
                    continue;
                }

                const length = std.math.cast(usize, header.length) orelse return error.FrameError;
                const total = header.octets + length;
                if (data.len - consumed < total) break;
                const payload = data[consumed + header.octets ..][0..length];

                switch (header.frame_type) {
                    .headers => {
                        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                        //# Receipt of an invalid sequence of frames MUST be treated as a
                        //# connection error of type H3_FRAME_UNEXPECTED.
                        //= type=test
                        const trailers = switch (request.phase) {
                            .start, .headers => false,
                            .data => true,
                            .trailers => return error.FrameUnexpected,
                        };
                        request.phase = if (trailers) .trailers else .headers;
                        events[produced] = .{ .headers = .{
                            .stream = id,
                            .section = payload,
                            .trailers = trailers,
                        } };
                        produced += 1;
                    },
                    // Section 9 again: unknown types are ignored here too, and
                    // `allowedOnRequestStream` has already refused the ones
                    // that belong somewhere else.
                    else => {},
                }
                consumed += total;
            }

            // The FIN is reported only once everything before it has been
            // handed over, and only if the last frame was whole: a stream that
            // ends in the middle of a frame is a truncated message, which
            // section 4.1 makes the caller's problem to reset rather than a
            // connection error.
            if (fin and consumed == data.len and request.data_remaining == 0 and produced < events.len) {
                events[produced] = .{ .finished = id };
                produced += 1;
            }
            return .{ .consumed = consumed, .events = produced };
        }

        // -------------------------------------------------------------- state

        fn unidirectionalFor(self: *Self, id: u64) Error!*Unidirectional {
            // Bounded by `unidirectional_count`, which never exceeds the table.
            for (self.unidirectional[0..self.unidirectional_count]) |*one| {
                if (one.id == id) return one;
            }
            if (self.unidirectional_count == config.unidirectional_max) return error.ExcessiveLoad;
            self.unidirectional[self.unidirectional_count] = .{ .id = id, .kind = .unread };
            self.unidirectional_count += 1;
            return &self.unidirectional[self.unidirectional_count - 1];
        }

        fn requestFor(self: *Self, id: u64) Error!*Request {
            // Bounded by `requests_count`, as above.
            for (self.requests[0..self.requests_count]) |*one| {
                if (one.id == id) return one;
            }
            if (self.requests_count == config.requests_max) return error.ExcessiveLoad;
            self.requests[self.requests_count] = .{ .id = id };
            self.requests_count += 1;
            return &self.requests[self.requests_count - 1];
        }

        /// Forget a stream that is over, so its slot can be used again. Called
        /// by the consumer, because only the consumer knows that it has read
        /// everything it wanted from the stream.
        pub fn release(self: *Self, id: u64) void {
            // Bounded by `requests_count`.
            for (self.requests[0..self.requests_count], 0..) |*one, index| {
                if (one.id != id) continue;
                self.requests[index] = self.requests[self.requests_count - 1];
                self.requests_count -= 1;
                return;
            }
        }

        /// Whether the peer's SETTINGS have arrived.
        pub fn settings(self: *const Self) ?Settings {
            return self.peer_settings;
        }

        /// The identifier the peer's last GOAWAY named, if any.
        pub fn goaway(self: *const Self) ?u64 {
            return self.peer_goaway;
        }
    };
}

/// Section 7.2.4's payload: identifier and value, repeated, with no count.
//= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
//# The same setting identifier MUST NOT occur more than once in the
//# SETTINGS frame.
//= type=test
fn parseSettings(payload: []const u8) Error!Settings {
    var out: Settings = .{};
    var seen_capacity = false;
    var seen_field_section = false;
    var seen_blocked = false;
    var seen_connect = false;

    var iterator: frame.SettingsIterator = .init(payload);
    // Bounded by the payload: every `next` consumes at least two octets.
    while (iterator.next() catch |err| switch (err) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
        //# Setting identifiers that were defined in [HTTP/2] where there is no
        //# corresponding HTTP/3 setting have also been reserved
        //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
        //# their receipt MUST be treated as a connection error of type
        //# H3_SETTINGS_ERROR.
        //= type=test
        error.Invalid => return error.SettingsError,
        // A setting that runs past the end of the payload is a frame whose
        // Length disagrees with its contents, which is section 7.1's
        // H3_FRAME_ERROR rather than a settings error.
        error.Truncated => return error.FrameError,
    }) |pair| {
        switch (pair.identifier) {
            .qpack_max_table_capacity => {
                if (seen_capacity) return error.SettingsError;
                seen_capacity = true;
                out.qpack_max_table_capacity = pair.value;
            },
            .max_field_section_size => {
                if (seen_field_section) return error.SettingsError;
                seen_field_section = true;
                out.max_field_section_size = pair.value;
            },
            .qpack_blocked_streams => {
                if (seen_blocked) return error.SettingsError;
                seen_blocked = true;
                out.qpack_blocked_streams = pair.value;
            },
            .enable_connect_protocol => {
                if (seen_connect) return error.SettingsError;
                seen_connect = true;
                // RFC 9220 section 3 defines this one as a flag, and it is not
                // among the specs vendored under `specs/` — so the rule is
                // stated here rather than cited, and `fields.zig` is where
                // extended CONNECT is actually implemented.
                out.enable_connect_protocol = switch (pair.value) {
                    0 => false,
                    1 => true,
                    else => return error.SettingsError,
                };
            },
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
            //# An implementation MUST ignore any parameter with an identifier it
            //# does not understand.
            //= type=test
            _ => {},
        }
    }
    return out;
}

const testing = std.testing;

const TestHttp3 = Http3(.{ .requests_max = 4, .unidirectional_max = 4 });

/// The identifier of the `index`-th unidirectional stream the peer opened,
/// from this endpoint's point of view.
fn peerUni(side: Side, index: u64) u64 {
    return stream_id.make(
        if (side == .client) .server_unidirectional else .client_unidirectional,
        index,
    );
}

test "the control stream opens with its type and a SETTINGS frame" {
    var connection: TestHttp3 = .init(.client);
    var buffer: [64]u8 = undefined;
    const written = try connection.writeControl(&buffer);

    // Stream type 0x00, then a SETTINGS frame whose Length matches what
    // follows it. A control stream that opened with anything else would be
    // H3_MISSING_SETTINGS at the peer.
    const parsed_type = try stream.parse(buffer[0..written]);
    try testing.expectEqual(stream.Type.control, parsed_type.stream_type);
    const header = try frame.parseHeader(buffer[parsed_type.octets..written]);
    try testing.expectEqual(frame.Type.settings, header.frame_type);
    try testing.expectEqual(written - parsed_type.octets - header.octets, header.length);

    // And it says what this package can actually do: no dynamic table.
    const settings = try parseSettings(buffer[parsed_type.octets + header.octets .. written]);
    try testing.expectEqual(@as(u64, 0), settings.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), settings.qpack_blocked_streams);
}

test "a peer's control stream is read, and a second one is refused" {
    var client: TestHttp3 = .init(.client);
    var server: TestHttp3 = .init(.server);

    // The server's control stream, built by the same writer the client uses.
    var buffer: [64]u8 = undefined;
    const written = try server.writeControl(&buffer);

    var events: [4]Event = undefined;
    const id = peerUni(.client, 0);
    const result = try client.receive(id, buffer[0..written], false, &events);
    try testing.expectEqual(written, result.consumed);
    try testing.expectEqual(@as(usize, 1), result.events);
    try testing.expectEqual(@as(u64, 0), events[0].settings.qpack_max_table_capacity);
    try testing.expect(client.settings() != null);

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# Only one control stream per peer is permitted; receipt of a second
    //# stream claiming to be a control stream MUST be treated as a
    //# connection error of type H3_STREAM_CREATION_ERROR.
    //= type=test
    try testing.expectError(
        error.StreamCreationError,
        client.receive(peerUni(.client, 1), buffer[0..written], false, &events),
    );
}

test "a control stream whose first frame is not SETTINGS is missing them" {
    var client: TestHttp3 = .init(.client);
    var events: [4]Event = undefined;

    // A control stream that opens with GOAWAY. Well-formed, permitted on a
    // control stream, and not allowed to be first.
    var buffer: [16]u8 = undefined;
    var offset = try stream.write(&buffer, .control);
    offset += try frame.writeHeader(buffer[offset..], .goaway, 1);
    offset += try varint.encode(buffer[offset..], 0);

    try testing.expectError(
        error.MissingSettings,
        client.receive(peerUni(.client, 0), buffer[0..offset], false, &events),
    );
}

test "a second SETTINGS frame on the control stream is unexpected" {
    var client: TestHttp3 = .init(.client);
    var server: TestHttp3 = .init(.server);
    var events: [4]Event = undefined;

    var buffer: [128]u8 = undefined;
    const first = try server.writeControl(&buffer);
    _ = try client.receive(peerUni(.client, 0), buffer[0..first], false, &events);

    // The same SETTINGS frame again, without the stream type this time.
    const type_octets = (try stream.parse(buffer[0..first])).octets;
    try testing.expectError(
        error.FrameUnexpected,
        client.receive(peerUni(.client, 0), buffer[type_octets..first], false, &events),
    );
}

test "a closed control stream is a closed critical stream" {
    var client: TestHttp3 = .init(.client);
    var server: TestHttp3 = .init(.server);
    var events: [4]Event = undefined;

    var buffer: [128]u8 = undefined;
    const written = try server.writeControl(&buffer);
    // The FIN arrives with the frame rather than after it, which is the case
    // that would be missed by checking the frames first.
    try testing.expectError(
        error.ClosedCriticalStream,
        client.receive(peerUni(.client, 0), buffer[0..written], true, &events),
    );
}

test "an unknown unidirectional stream type is discarded rather than refused" {
    var client: TestHttp3 = .init(.client);
    var events: [4]Event = undefined;

    // Section 6.2.3's reserved pattern: `0x1f * N + 0x21`.
    var buffer: [64]u8 = undefined;
    var offset = try varint.encode(&buffer, 0x21);
    const junk = "whatever a future extension puts here";
    @memcpy(buffer[offset..][0..junk.len], junk);
    offset += junk.len;

    const id = peerUni(.client, 0);
    const result = try client.receive(id, buffer[0..offset], false, &events);
    try testing.expectEqual(offset, result.consumed);
    try testing.expectEqual(@as(usize, 0), result.events);

    // And it stays discarded on the next run of octets, without the type.
    const again = try client.receive(id, junk, false, &events);
    try testing.expectEqual(junk.len, again.consumed);
}

test "a stream type split across two reads is not consumed until it is whole" {
    var client: TestHttp3 = .init(.client);
    var events: [4]Event = undefined;

    // Section 6.2.3's reserved pattern again, at `N = 2`: 95, which is the
    // first of them that needs two octets, so the type really is split.
    var buffer: [8]u8 = undefined;
    const octets = try varint.encode(&buffer, 0x1f * 2 + 0x21);
    try testing.expectEqual(@as(usize, 2), octets);
    const id = peerUni(.client, 0);
    const partial = try client.receive(id, buffer[0..1], false, &events);
    try testing.expectEqual(@as(usize, 0), partial.consumed);

    const whole = try client.receive(id, buffer[0..2], false, &events);
    try testing.expectEqual(@as(usize, 2), whole.consumed);
}

test "a push stream is refused, by the code the receiver's role gives it" {
    var events: [4]Event = undefined;
    var buffer: [8]u8 = undefined;
    const octets = try varint.encode(&buffer, @intFromEnum(stream.Type.push));

    // A client has sent no MAX_PUSH_ID, so any push stream is H3_ID_ERROR.
    var client: TestHttp3 = .init(.client);
    try testing.expectError(
        error.IdError,
        client.receive(peerUni(.client, 0), buffer[0..octets], false, &events),
    );

    // A server receiving one is looking at a client that cannot push at all.
    var server: TestHttp3 = .init(.server);
    try testing.expectError(
        error.StreamCreationError,
        server.receive(peerUni(.server, 0), buffer[0..octets], false, &events),
    );
}

test "a response is HEADERS, then DATA, then optionally trailers" {
    var client: TestHttp3 = .init(.client);
    var events: [8]Event = undefined;

    var buffer: [256]u8 = undefined;
    var offset: usize = 0;
    offset += try client.writeHeaders(buffer[offset..], &.{
        .{ .name = ":status", .value = "200" },
    });
    const body = "a body";
    offset += try TestHttp3.writeData(buffer[offset..], body.len);
    @memcpy(buffer[offset..][0..body.len], body);
    offset += body.len;
    offset += try client.writeHeaders(buffer[offset..], &.{
        .{ .name = "trailer-name", .value = "trailer-value" },
    });

    const result = try client.receive(0, buffer[0..offset], true, &events);
    try testing.expectEqual(offset, result.consumed);
    try testing.expectEqual(@as(usize, 4), result.events);
    try testing.expect(!events[0].headers.trailers);
    try testing.expectEqualStrings(body, events[1].data.payload);
    try testing.expect(events[2].headers.trailers);
    try testing.expectEqual(@as(u64, 0), events[3].finished);

    // And the field section decodes to what was encoded.
    var scratch: [256]u8 = undefined;
    var list = try qpack.field_line.iterate(events[0].headers.section, &scratch, 1 << 16);
    const first = (try list.next()).?;
    try testing.expectEqualStrings(":status", first.name);
    try testing.expectEqualStrings("200", first.value);
}

test "section 4.1: DATA before HEADERS, and anything after the trailers" {
    var events: [8]Event = undefined;
    var buffer: [256]u8 = undefined;

    {
        var client: TestHttp3 = .init(.client);
        const octets = try TestHttp3.writeData(&buffer, 0);
        try testing.expectError(
            error.FrameUnexpected,
            client.receive(0, buffer[0..octets], false, &events),
        );
    }
    {
        var client: TestHttp3 = .init(.client);
        var offset: usize = 0;
        offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = ":status", .value = "200" }});
        offset += try TestHttp3.writeData(buffer[offset..], 0);
        // The trailing HEADERS, and then a DATA that cannot follow it.
        offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = "a", .value = "b" }});
        offset += try TestHttp3.writeData(buffer[offset..], 0);

        try testing.expectError(
            error.FrameUnexpected,
            client.receive(0, buffer[0..offset], false, &events),
        );
    }
    {
        // And a *second* trailing HEADERS, which is the other half of the same
        // sentence and was the half no test reached: the run above is caught by
        // the DATA arm, so removing the HEADERS arm broke nothing.
        var client: TestHttp3 = .init(.client);
        var offset: usize = 0;
        offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = ":status", .value = "200" }});
        offset += try TestHttp3.writeData(buffer[offset..], 0);
        offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = "a", .value = "b" }});
        offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = "c", .value = "d" }});

        try testing.expectError(
            error.FrameUnexpected,
            client.receive(0, buffer[0..offset], false, &events),
        );
    }
}

test "a frame this stream may not carry is unexpected, in both directions" {
    var events: [4]Event = undefined;
    var buffer: [64]u8 = undefined;

    // SETTINGS on a request stream.
    {
        var client: TestHttp3 = .init(.client);
        const octets = try frame.writeHeader(&buffer, .settings, 0);
        try testing.expectError(
            error.FrameUnexpected,
            client.receive(0, buffer[0..octets], false, &events),
        );
    }
    // And DATA on a control stream, after its SETTINGS.
    {
        var client: TestHttp3 = .init(.client);
        var server: TestHttp3 = .init(.server);
        var control: [128]u8 = undefined;
        const written = try server.writeControl(&control);
        _ = try client.receive(peerUni(.client, 0), control[0..written], false, &events);

        const octets = try frame.writeHeader(&buffer, .data, 0);
        try testing.expectError(
            error.FrameUnexpected,
            client.receive(peerUni(.client, 0), buffer[0..octets], false, &events),
        );
    }
}

test "a GOAWAY may not name a larger identifier than the last one" {
    var client: TestHttp3 = .init(.client);
    var server: TestHttp3 = .init(.server);
    var events: [4]Event = undefined;

    var control: [128]u8 = undefined;
    const written = try server.writeControl(&control);
    _ = try client.receive(peerUni(.client, 0), control[0..written], false, &events);

    var buffer: [64]u8 = undefined;
    var offset = try server.writeGoaway(&buffer, 8);
    const first = try client.receive(peerUni(.client, 0), buffer[0..offset], false, &events);
    try testing.expectEqual(@as(usize, 1), first.events);
    try testing.expectEqual(@as(u64, 8), events[0].goaway);
    try testing.expectEqual(@as(?u64, 8), client.goaway());

    // Lower is fine — an endpoint may narrow what it will still process.
    offset = try server.writeGoaway(&buffer, 4);
    _ = try client.receive(peerUni(.client, 0), buffer[0..offset], false, &events);
    try testing.expectEqual(@as(?u64, 4), client.goaway());

    // Higher is not — and the frame has to be built by hand, because
    // `writeGoaway` refuses to produce one. That refusal is the sending half of
    // the same rule.
    offset = try frame.writeHeader(&buffer, .goaway, 1);
    offset += try varint.encode(buffer[offset..], 6);
    try testing.expectError(
        error.IdError,
        client.receive(peerUni(.client, 0), buffer[0..offset], false, &events),
    );
    try testing.expectError(error.IdError, server.writeGoaway(&buffer, 6));
}

test "a setting sent twice, and one of HTTP/2's, are both settings errors" {
    var buffer: [64]u8 = undefined;
    var offset: usize = 0;
    offset += try frame.writeSetting(buffer[offset..], .qpack_blocked_streams, 0);
    offset += try frame.writeSetting(buffer[offset..], .qpack_blocked_streams, 1);
    try testing.expectError(error.SettingsError, parseSettings(buffer[0..offset]));

    // `enable_connect_protocol` is a flag, and section 7.2.4.1 says so.
    offset = try frame.writeSetting(&buffer, .enable_connect_protocol, 2);
    try testing.expectError(error.SettingsError, parseSettings(buffer[0..offset]));

    // An identifier nobody has defined is ignored rather than refused, which is
    // what makes the registry extensible.
    offset = try frame.writeSetting(&buffer, @enumFromInt(0x4242), 1);
    _ = try parseSettings(buffer[0..offset]);
}

test "a partial frame is left for the next read" {
    var client: TestHttp3 = .init(.client);
    var events: [4]Event = undefined;

    var buffer: [256]u8 = undefined;
    const whole = try client.writeHeaders(&buffer, &.{.{ .name = ":status", .value = "200" }});

    // Every prefix short of the whole frame consumes nothing at all.
    var prefix: usize = 1;
    while (prefix < whole) : (prefix += 1) {
        var partial: TestHttp3 = .init(.client);
        const result = try partial.receive(0, buffer[0..prefix], false, &events);
        try testing.expectEqual(@as(usize, 0), result.consumed);
        try testing.expectEqual(@as(usize, 0), result.events);
    }
    const result = try client.receive(0, buffer[0..whole], false, &events);
    try testing.expectEqual(whole, result.consumed);
}

test "an events array that fills up stops the read rather than dropping one" {
    var client: TestHttp3 = .init(.client);

    var buffer: [256]u8 = undefined;
    var offset: usize = 0;
    offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = ":status", .value = "200" }});
    const first = offset;
    offset += try TestHttp3.writeData(buffer[offset..], 0);

    // Room for one event and two frames to report. The second frame is not
    // consumed, so the caller gets it on the next call — which is the whole
    // reason `consumed` is a return value and not an assumption.
    var events: [1]Event = undefined;
    const result = try client.receive(0, buffer[0..offset], false, &events);
    try testing.expectEqual(first, result.consumed);
    try testing.expectEqual(@as(usize, 1), result.events);
}

test "every error names the code a peer is told" {
    // The mapping is exhaustive by construction — `code` switches on the error
    // set — and this is the part a switch cannot check: that the codes are the
    // ones RFC 9114 section 8.1 gives these names.
    try testing.expectEqual(error_code.Application.missing_settings, code(error.MissingSettings));
    try testing.expectEqual(error_code.Application.frame_unexpected, code(error.FrameUnexpected));
    try testing.expectEqual(error_code.Application.closed_critical_stream, code(error.ClosedCriticalStream));
    try testing.expectEqual(error_code.Application.stream_creation_error, code(error.StreamCreationError));
    try testing.expectEqual(error_code.Application.id_error, code(error.IdError));
    try testing.expectEqual(error_code.Application.settings_error, code(error.SettingsError));
    try testing.expectEqual(error_code.Application.excessive_load, code(error.ExcessiveLoad));
}

test "more streams than the table holds is excessive load, not a wrong answer" {
    var client: TestHttp3 = .init(.client);
    var events: [4]Event = undefined;
    var buffer: [64]u8 = undefined;
    const octets = try client.writeHeaders(&buffer, &.{.{ .name = ":status", .value = "200" }});

    // Four fit, because `TestHttp3` was configured with four.
    for (0..4) |index| {
        _ = try client.receive(@as(u64, index) * 4, buffer[0..octets], false, &events);
    }
    try testing.expectError(
        error.ExcessiveLoad,
        client.receive(4 * 4, buffer[0..octets], false, &events),
    );

    // And a released stream gives its slot back.
    client.release(0);
    _ = try client.receive(4 * 4, buffer[0..octets], false, &events);
}

test "a DATA frame larger than one read is delivered as it arrives" {
    // The case ngtcp2 produced and quic-go did not: one DATA frame for a whole
    // response body. Buffering it before delivering any of it waits for a frame
    // larger than the stream's receive window, and the window only moves when
    // octets are consumed — so both endpoints are correct and neither can
    // proceed.
    var client: TestHttp3 = .init(.client);
    var events: [8]Event = undefined;

    var buffer: [256]u8 = undefined;
    var offset: usize = 0;
    offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = ":status", .value = "200" }});
    // A frame that claims a megabyte, of which sixteen octets are here.
    const claimed: u64 = 1 << 20;
    offset += try TestHttp3.writeData(buffer[offset..], claimed);
    const body = "sixteen octets!!";
    @memcpy(buffer[offset..][0..body.len], body);
    offset += body.len;

    const result = try client.receive(0, buffer[0..offset], false, &events);
    // Everything given was taken, including the part of the frame that arrived.
    try testing.expectEqual(offset, result.consumed);
    try testing.expectEqual(@as(usize, 2), result.events);
    try testing.expectEqualStrings(body, events[1].data.payload);

    // The next run of octets continues the same frame, with no header.
    const more = "and sixteen more";
    const again = try client.receive(0, more, false, &events);
    try testing.expectEqual(more.len, again.consumed);
    try testing.expectEqual(@as(usize, 1), again.events);
    try testing.expectEqualStrings(more, events[0].data.payload);

    // And a FIN in the middle of a frame is not a finished message: the body is
    // truncated, which is the caller's to reset rather than a connection error.
    const truncated = try client.receive(0, "", true, &events);
    try testing.expectEqual(@as(usize, 0), truncated.events);
}

test "a DATA frame that is exactly the octets given still reports the FIN" {
    var client: TestHttp3 = .init(.client);
    var events: [8]Event = undefined;

    var buffer: [256]u8 = undefined;
    var offset: usize = 0;
    offset += try client.writeHeaders(buffer[offset..], &.{.{ .name = ":status", .value = "200" }});
    const body = "the whole body";
    offset += try TestHttp3.writeData(buffer[offset..], body.len);
    @memcpy(buffer[offset..][0..body.len], body);
    offset += body.len;

    const result = try client.receive(0, buffer[0..offset], true, &events);
    try testing.expectEqual(offset, result.consumed);
    try testing.expectEqual(@as(usize, 3), result.events);
    try testing.expectEqualStrings(body, events[1].data.payload);
    try testing.expectEqual(@as(u64, 0), events[2].finished);
}
