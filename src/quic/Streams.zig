//! RFC 9000 sections 2, 3 and 4: streams, their states, and flow control.
//!
//! A bounded set of streams, each with a receive half built on `Reassembler`
//! and a send half that buffers until acknowledged, plus the two levels of flow
//! control that decide how much a peer may send.
//!
//! ## Two levels, and the second one is the reason the first is not enough
//!
//! Section 4.1 gives every stream a limit and the connection a limit over all of
//! them. Only the second bounds memory: without it a peer opens as many streams
//! as it is allowed and fills each one's window, so the memory a connection can
//! be made to hold is the per-stream window times the stream limit. With it, the
//! connection window is the answer regardless of how the peer divides it.
//!
//! Both are enforced here rather than advertised and hoped for. A peer that
//! exceeds either has committed a `FLOW_CONTROL_ERROR`, and this refuses the
//! data instead of growing to fit it.
//!
//! ## A closed stream's accounting does not go away
//!
//! Section 4.1 counts the connection's flow control against the *highest offset
//! received* on every stream, and a stream that is reset or finished keeps
//! counting. Forgetting it would let a peer open a stream, fill its window,
//! reset it, and open another — consuming the connection window over and over
//! while never appearing to hold anything. `received_total` therefore only ever
//! rises, and it is credit consumed rather than memory held.
//!
//! ## Sized at compile time
//!
//! `Streams(config)` produces a type whose every buffer is a fixed array. The
//! peer's `initial_max_streams` and `initial_max_stream_data` are checked
//! *against* these numbers and never used as them — a limit that is not
//! comptime is a limit a peer can choose.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const error_code = @import("error_code.zig");
const stream_id = @import("stream_id.zig");
const varint = @import("../varint.zig");

const Reassembler = @import("Reassembler.zig").Reassembler;
const Side = @import("crypto.zig").Side;

/// Section 3.2: what has happened to a stream's receive half.
///
/// Four of section 3.2's six states. "Data Recvd" — everything has arrived but
/// the application has not taken it — is folded into `size_known`, which
/// `Streams.settle` tests together with `Reassembler.isComplete`; and "Reset
/// Read" is folded into `reset`, because nothing here delivers a reset signal
/// to an application separately from the data.
///
/// Nothing in this package asks the peer to stop. STOP_SENDING is *received*
/// by `Connection.receiveFrames`, which moves the send half to `.reset`; no
/// path generates one, so a reader that abandons a stream keeps paying for it
/// until the peer finishes or resets.
//= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
//# If the stream is in the "Recv" or "Size Known" state, the transport
//# SHOULD signal this by sending a STOP_SENDING frame to prompt closure
//# of the stream in the opposite direction.
//= type=todo
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
//# STOP_SENDING SHOULD only be sent for a stream that has not been reset
//# by the peer.
//= type=todo
pub const ReceiveState = enum {
    /// Data is arriving.
    receiving,
    /// A FIN named the final size; earlier data may still be missing.
    size_known,
    /// Everything up to the final size has been read by the application.
    data_read,
    /// The peer abandoned it with RESET_STREAM.
    reset,
};

/// Section 3.1: what has happened to a stream's send half.
///
/// Four of section 3.1's six states. "Ready" and "Send" are one `sending`
/// here, because nothing distinguishes a stream that has buffered data from
/// one that has framed it.
///
/// "Data Recvd" arrived with `Connection.onPacketsDelivered`, which is the
/// counterpart of `onPacketsLost` that did not exist: `Recovery` reported
/// losses to `Streams.rewind` and reported acknowledgements to nothing, so a
/// stream could be written, sent, fully acknowledged and sit in "Data Sent"
/// for the life of the connection.
///
/// **"Reset Recvd" is still the gap.** It is entered when a RESET_STREAM is
/// acknowledged, and no RESET_STREAM is ever framed — see `reset` below, which
/// is the same hole seen from the other end.
//= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
//# A sender MUST NOT send any of these frames from a terminal state
//# ("Data Recvd" or "Reset Recvd").
//= type=todo
pub const SendState = enum {
    /// Accepting writes.
    sending,
    /// A FIN was queued; no more writes are accepted.
    data_sent,
    /// This endpoint abandoned it with RESET_STREAM.
    ///
    /// Also where `Connection.receiveFrames` puts a stream on receiving
    /// STOP_SENDING — which is section 3.5's cue to *send* a RESET_STREAM, and
    /// no RESET_STREAM is ever framed. The state moves and the peer is never
    /// told, so a peer that asked us to stop learns nothing and the final size
    /// the two endpoints are supposed to agree on is never communicated.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    //# An endpoint that receives a STOP_SENDING frame MUST send a
    //# RESET_STREAM frame if the stream is in the "Ready" or "Send" state.
    //= type=todo
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    //# An endpoint SHOULD copy the error code from the STOP_SENDING frame to
    //# the RESET_STREAM frame it sends, but it can use any application error
    //# code.
    //= type=todo
    reset,
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.1
    //# Once all stream data has been successfully acknowledged, the sending
    //# part of the stream enters the "Data Recvd" state, which is a terminal
    //# state.
    ///
    /// Entered when the packet carrying the FIN is acknowledged, which is why
    /// it could not exist until `Recovery` reported acknowledgements as well as
    /// losses. Terminal: section 3.3 forbids sending anything more on a stream
    /// that has reached it.
    data_recvd,
};

pub const Config = struct {
    /// Concurrent streams tracked. A peer's `initial_max_streams` is checked
    /// against this, never used as it.
    streams_max: u32 = 64,
    /// The receive window offered on each stream.
    receive_octets: u32 = 64 * 1024,
    /// Bytes buffered on each stream's send half. They stay until acknowledged,
    /// because they are what a retransmission is rebuilt from.
    send_octets: u32 = 16 * 1024,
    /// The connection's own receive window, over all streams at once. This is
    /// the number that actually bounds memory; see the module comment.
    connection_receive_octets: u64 = 1 << 20,
};

/// Distinct received spans a *request* stream tolerates.
///
/// This was eight, on the argument that a connection holds `streams_max` of
/// these at once so a span budget is paid `streams_max` times over — and that
/// "a real path reorders within a few packets". The first half is true and the
/// second is not. The interop runner's ordinary transfer path — 15 ms of delay,
/// 10 Mbps, a 25-packet queue — put more than eight gaps in a single stream,
/// and a receiver that runs out of spans closes the connection with
/// `INTERNAL_ERROR`. A 5 MiB download failed at about a third of the way
/// through, every time.
///
/// The multiplier argument survives; the magnitude did not. A span is two
/// offsets, so this table is 512 octets beside a receive buffer measured in
/// tens of kilobytes — a fifth of one percent of what it indexes. Paying that
/// `streams_max` times is not a cost worth closing connections over.
const receive_spans_max: u32 = 32;

comptime {
    // Two is the least that can describe a gap at all.
    assert(receive_spans_max >= 2);
    // And the table stays small beside the buffer it indexes, which is the
    // relation the number above is chosen against rather than a round figure.
    assert(receive_spans_max * @sizeOf(u64) * 2 <= 1024);
}

pub fn Streams(comptime config: Config) type {
    comptime {
        assert(config.streams_max >= 1);
        assert(config.receive_octets >= 1);
        assert(config.send_octets >= 1);
        // The connection window has to be able to hold at least one stream's
        // worth, or a single stream could never fill its own.
        assert(config.connection_receive_octets >= config.receive_octets);
        assert(config.streams_max <= stream_id.count_max);
    }

    const Receive = Reassembler(.{ .capacity = config.receive_octets, .spans_max = receive_spans_max });

    return struct {
        const Self = @This();

        /// The limit this endpoint advertises, and the only one it will ever
        /// advertise: it is comptime, so it never rises and no MAX_STREAMS
        /// frame is generated anywhere in the package (see
        /// `Connection.max_data_sent`, which says the same about the field that
        /// used to sit beside it). The MUST NOT below is therefore satisfied
        /// vacuously — nothing waits for STREAMS_BLOCKED because nothing issues
        /// credit at all — and the cost is the one the sentence is warning
        /// about: a peer that closes streams never gets them back, so a
        /// long-lived connection reaches `streams_max` and stays there.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint MUST NOT wait to receive this signal before advertising
        //# additional credit, since doing so will mean that the peer will be
        //# blocked for at least an entire round trip, and potentially
        //# indefinitely if the peer chooses not to send STREAMS_BLOCKED frames.
        //= type=todo
        pub const streams_max: u32 = config.streams_max;
        pub const receive_octets: u32 = config.receive_octets;
        pub const connection_receive_octets: u64 = config.connection_receive_octets;

        pub const Stream = struct {
            id: u64,
            receive_state: ReceiveState = .receiving,
            send_state: SendState = .sending,

            received: Receive = .{},
            /// The highest offset seen on this stream, which is what section
            /// 4.1 counts against both limits — not what has arrived in order,
            /// and not what has been read.
            received_highest: u64 = 0,
            /// Octets the application has taken, which is what the advertised
            /// limit is measured forward from.
            consumed: u64 = 0,

            /// Bytes waiting to go out, and how far they have been framed. The
            /// same arrangement the CRYPTO stream uses, for the same reason:
            /// what a retransmission needs is held here, and what decides to
            /// send it is RFC 9002.
            send: [config.send_octets]u8 = @splat(0),
            send_len: u32 = 0,
            framed: u32 = 0,
            /// Octets already acknowledged and dropped from the front of
            /// `send`, which is what a STREAM frame's Offset field is measured
            /// from. It was here from the beginning and never advanced, so the
            /// buffer only ever filled: a stream could send `send_octets` in
            /// total and then nothing, for the life of the connection.
            send_offset: u64 = 0,
            /// The contiguous prefix the peer has acknowledged, as an absolute
            /// stream offset. `send_offset` follows it.
            acked_to: u64 = 0,
            send_fin: bool = false,
            /// Whether the FIN has been put in a packet. Without it nothing
            /// records that the FIN went out, `wantsSend` stays true forever
            /// and every packet carries another empty FIN — a loop that only
            /// stops when the connection does.
            fin_framed: bool = false,
            /// The peer's `MAX_STREAM_DATA` for this stream.
            send_limit: u64 = 0,

            /// The error code a RESET_STREAM carried, in either direction.
            reset_code: u64 = 0,
            /// The `MAX_STREAM_DATA` last advertised, so a new one goes out
            /// only when the window has moved enough to be worth a frame.
            max_data_sent: u64 = 0,

            /// Bytes readable in order.
            ///
            /// The ordering is `Reassembler`'s: this returns the contiguous run
            /// from the read offset and nothing past a gap, so an application
            /// never sees an octet before the one that precedes it.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
            //# Endpoints MUST be able to deliver stream data to an application as an
            //# ordered byte stream.
            pub fn readable(self: *const Stream) []const u8 {
                return self.received.readable();
            }

            /// Whether everything the peer will ever send has been read.
            pub fn isComplete(self: *const Stream) bool {
                return self.receive_state == .data_read;
            }

            /// Section 4.1: the limit to advertise, measured forward from what
            /// the application has taken rather than from what has arrived.
            /// Advertising from arrival would let a peer that sends faster than
            /// we read push the window ahead of the buffer.
            ///
            /// Nothing waits to be asked. `Connection.writePacket` compares this
            /// against `max_data_sent` on every packet it builds and emits a
            /// MAX_STREAM_DATA when the window has moved far enough to be worth
            /// a frame, and `Connection.receiveFrames` discards
            /// STREAM_DATA_BLOCKED and DATA_BLOCKED without reading them — so a
            /// peer that never sends one is never blocked by that silence.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-4.2
            //# Therefore, a receiver MUST NOT wait for a STREAM_DATA_BLOCKED or
            //# DATA_BLOCKED frame before sending a MAX_STREAM_DATA or MAX_DATA frame;
            //# doing so could result in the sender being blocked for the rest of the
            //# connection.
            //
            // What that loop does not read is `receive_state`, and this does
            // not either: the limit keeps moving forward as the application
            // drains a stream whose size the peer has already fixed with a FIN,
            // or one the peer has reset, so a MAX_STREAM_DATA goes out
            // extending a window nothing can ever be written into. Harmless on
            // the wire and pure waste — the test belongs here, where the state
            // is in reach, rather than in the caller.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
            //# An endpoint SHOULD stop sending
            //# MAX_STREAM_DATA frames when the receiving part of the stream
            //# enters a "Size Known" or "Reset Recvd" state.
            //= type=todo
            pub fn receiveLimit(self: *const Stream) u64 {
                // Section 4.1: the limit moves forward as the application
                // reads, so a stream that is never read never grows one.
                assert(self.consumed <= self.received_highest);
                const limit = self.consumed + config.receive_octets;
                assert(limit >= config.receive_octets);
                return limit;
            }

            /// Whether this endpoint may still write to it.
            pub fn writable(self: *const Stream) bool {
                return self.send_state == .sending;
            }
        };

        /// Which endpoint this is. Section 19.8's rules are all of the form
        /// "not on a stream you cannot send on", and that is unanswerable
        /// without knowing which side you are.
        side: Side = .client,

        streams: [streams_max]Stream = undefined,
        /// Section 4.6: how many streams of each kind the peer has permitted
        /// this endpoint to open. Zero until a transport parameter or a
        /// MAX_STREAMS frame says otherwise, which is what section 18.2's
        /// default of zero means — an endpoint may open none until told.
        peer_streams_bidi: u64 = 0,
        peer_streams_uni: u64 = 0,
        count: u32 = 0,

        /// Section 4.1's connection-level accounting: octets of *credit* the
        /// peer has consumed across every stream that ever existed, and octets
        /// the application has taken.
        received_total: u64 = 0,
        consumed_total: u64 = 0,
        /// The peer's `MAX_DATA` for this connection.
        send_limit: u64 = 0,

        /// Section 4.1: the peer's `initial_max_stream_data_*`, which is the
        /// send limit a stream *starts* with. Held here rather than pushed into
        /// each stream, because the streams a connection will open do not exist
        /// when the transport parameters arrive — and a limit applied only to
        /// the streams that happened to be open is a limit that silently does
        /// not apply to the first request.
        ///
        /// Named from this endpoint's point of view. The peer's
        /// `initial_max_stream_data_bidi_remote` is the limit on a stream *this*
        /// endpoint opened, because "remote" is that parameter's view of who
        /// initiated it; getting the two the wrong way round gives a limit that
        /// is usually the same number and occasionally not.
        peer_initial_bidi_local: u64 = 0,
        peer_initial_bidi_remote: u64 = 0,
        peer_initial_uni: u64 = 0,
        /// Octets this endpoint has queued across all streams, against that.
        sent_total: u64 = 0,

        pub const Error = error{
            /// More streams than `streams_max`. Section 4.6's
            /// `STREAM_LIMIT_ERROR` when the peer opened it, and a caller's own
            /// problem when this endpoint did.
            TooManyStreams,
            /// Data past a stream's limit or the connection's.
            /// `FLOW_CONTROL_ERROR`.
            FlowControl,
            /// Section 4.5: data past a final size, a second and different
            /// final size, or a final size below what has already arrived.
            /// `FINAL_SIZE_ERROR`.
            FinalSize,
            /// Section 2.2's rule that data at an offset never changes, or a
            /// write to a stream that cannot take one. `PROTOCOL_VIOLATION`.
            Protocol,
            /// The stream is not open.
            NotFound,
            /// More distinct received spans than the reassembler holds. Not a
            /// protocol error in the RFC's vocabulary: the peer is within its
            /// rights and this endpoint is out of room, so `INTERNAL_ERROR` is
            /// the honest answer. Reporting it as `FlowControl` — which this
            /// did — tells the peer it exceeded a limit it did not exceed, and
            /// a peer that trusts us then looks for a bug it does not have.
            TooFragmented,
            /// Section 19.8, 19.4, 19.5 and 19.10: a frame for a stream this
            /// endpoint cannot receive on, or a write to one it cannot send on.
            /// `STREAM_STATE_ERROR`.
            StreamState,
        };

        /// Whether the peer may send to us on this stream — section 2.1's
        /// addressing, read from the identifier itself.
        ///
        /// A unidirectional stream this endpoint opened is send-only for us and
        /// receive-only for the peer, so a STREAM, RESET_STREAM or FIN arriving
        /// on one is the peer writing where it cannot. Section 19.8 makes that
        /// a `STREAM_STATE_ERROR` rather than something to ignore.
        pub fn peerMaySend(self: *const Self, id: u64) bool {
            const kind = stream_id.kindOf(id);
            // The low two bits are the type tag, so every identifier has a
            // kind; there is no such thing as an unrecognised one to reject.
            assert(@intFromEnum(kind) == id & 0b11);
            return kind.bidirectional() or kind.initiator() != self.side;
        }

        /// And the mirror: whether this endpoint may write on it.
        pub fn weMaySend(self: *const Self, id: u64) bool {
            return stream_id.sendable(id, self.side);
        }

        pub fn weMayReceive(self: *const Self, id: u64) bool {
            return stream_id.receivable(id, self.side);
        }

        pub fn find(self: *Self, id: u64) ?*Stream {
            for (self.streams[0..self.count]) |*stream| {
                if (stream.id == id) return stream;
            }
            return null;
        }

        /// Section 4.6: raise how many streams of one kind this endpoint may
        /// open. Limits only ever rise, so a lower value is ignored rather than
        /// refused — that is what section 4.6 says to do with a stale frame.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# MAX_STREAMS frames that do not increase the stream limit MUST be
        //# ignored.
        pub fn setPeerStreamLimit(self: *Self, bidirectional: bool, maximum: u64) void {
            assert(maximum <= stream_id.count_max);
            const limit = if (bidirectional) &self.peer_streams_bidi else &self.peer_streams_uni;
            limit.* = @max(limit.*, maximum);
            assert(limit.* >= maximum);
        }

        /// Open a stream, or return the one already open.
        ///
        /// A stream is never removed: `count` only rises, and a finished or
        /// reset stream keeps its slot and its identifier for the life of the
        /// connection. That is what makes reuse impossible here — there is no
        /// path that hands the same identifier to a second stream — and it is
        /// also why `received_total` can go on counting a closed stream's
        /// credit, which section 4.1 requires.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        //# A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        //
        // Only the named stream is created. A peer that opens index 3 without
        // ever having opened 0, 1 and 2 gets one stream here, not four, so the
        // creation order the two endpoints see is not the same — and the count
        // this endpoint bounds with `streams_max` is not the count a
        // conforming peer believes it has opened. See `checkPeerStreamLimit`
        // for what that costs on the receive side.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
        //# Before a stream is created, all streams of the same type with lower-
        //# numbered stream IDs MUST be created.
        //= type=todo
        pub fn open(self: *Self, id: u64) Error!*Stream {
            assert(id <= varint.max);
            if (self.find(id)) |stream| return stream;
            if (self.count == streams_max) return error.TooManyStreams;
            self.streams[self.count] = .{ .id = id, .send_limit = self.initialSendLimit(id) };
            self.count += 1;
            return &self.streams[self.count - 1];
        }

        /// Section 4.1's starting credit for a stream, from whichever of the
        /// peer's three `initial_max_stream_data` parameters applies to it.
        fn initialSendLimit(self: *const Self, id: u64) u64 {
            const kind = stream_id.kindOf(id);
            if (!kind.bidirectional()) {
                // A unidirectional stream this endpoint did not open is one it
                // cannot send on at all, so the parameter that would apply to it
                // does not exist.
                return if (kind.initiator() == self.side) self.peer_initial_uni else 0;
            }
            return if (kind.initiator() == self.side)
                self.peer_initial_bidi_remote
            else
                self.peer_initial_bidi_local;
        }

        /// Apply the peer's `initial_max_stream_data_*`. Called once, when the
        /// transport parameters arrive.
        ///
        /// Streams already open are updated too: a server can have accepted the
        /// client's first stream out of a 0-RTT or coalesced packet before the
        /// handshake delivered the parameters, and a stream that missed its
        /// starting credit would never get it — no `MAX_STREAM_DATA` is coming
        /// for a limit the peer believes it already stated.
        pub fn setPeerInitialLimits(self: *Self, bidi_local: u64, bidi_remote: u64, uni: u64) void {
            self.peer_initial_bidi_local = bidi_local;
            self.peer_initial_bidi_remote = bidi_remote;
            self.peer_initial_uni = uni;
            // Bounded by `count`, which never exceeds `streams_max`.
            for (self.streams[0..self.count]) |*stream| {
                stream.send_limit = @max(stream.send_limit, self.initialSendLimit(stream.id));
            }
        }

        /// Section 4.6: a stream this endpoint initiates has to fit inside the
        /// limit the peer advertised. Nothing enforced this before, on the
        /// stated grounds that "this package opens what its comptime bound
        /// allows and no more, so a larger limit changes nothing and a smaller
        /// one is already respected" — the second half of which was simply
        /// untrue. The peer's limit was never recorded, so a peer permitting
        /// two streams while `streams_max` is sixty-four got however many the
        /// application asked for, and answered with `STREAM_LIMIT_ERROR`.
        ///
        /// A peer-initiated stream is not checked here: the limit on those is
        /// the one *we* advertised, and `streams_max` is what enforces it.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# Endpoints MUST NOT exceed the limit set by their peer.
        //
        // And the mirror of it, which is not implemented. The rule below is
        // about a stream *identifier*, and the only thing checked in that
        // direction is a count: `open` refuses the `streams_max + 1`-th stream
        // and nothing compares a peer-initiated identifier's index against the
        // limit this endpoint advertised. A peer that sends on index 10_000
        // while we advertised sixty-four gets a stream, because it is only the
        // first one. The count is a sound proxy only if section 3.2's
        // lower-numbered streams are created implicitly, and they are not —
        // see `open`.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint that receives a frame with a stream ID exceeding the limit
        //# it has sent MUST treat this as a connection error of type
        //# STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
        //= type=todo
        fn checkPeerStreamLimit(self: *const Self, id: u64) Error!void {
            assert(id <= varint.max);
            const kind = stream_id.kindOf(id);
            if (kind.initiator() != self.side) return;
            const limit = if (kind.bidirectional()) self.peer_streams_bidi else self.peer_streams_uni;
            // MAX_STREAMS counts streams, and an identifier's index counts from
            // zero — so the highest identifier a limit of N permits has index
            // N-1. Reading the count as an identifier is the error that lets a
            // quarter of the offered streams through, and comparing an index
            // against a count without the shift is how it happens.
            const position = stream_id.index(id);
            if (position >= limit) return error.TooManyStreams;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint
        //# that receives a frame with a stream ID exceeding the limit it has
        //# sent MUST treat this as a connection error of type
        //# STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
        ///
        /// The limit this endpoint advertised is `streams_max`, and the rule is
        /// about the stream *identifier* rather than about how many streams
        /// happen to be open. `open` refusing the `streams_max + 1`-th stream
        /// is a count, and a count is a sound proxy only if section 3.2's
        /// lower-numbered streams are implicitly created — which this package
        /// does not do. So a peer sending on index 10 000 while sixty-four were
        /// advertised used to get a stream, because it was only the first one.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
        //# An endpoint MUST terminate a connection with an error of type
        //# STREAM_LIMIT_ERROR if a peer opens more streams than was permitted.
        fn checkAdvertisedStreamLimit(self: *const Self, id: u64) Error!void {
            const kind = stream_id.kindOf(id);
            if (kind.initiator() == self.side) return;
            if (stream_id.index(id) >= streams_max) return error.TooManyStreams;
        }

        /// Take a STREAM frame.
        pub fn receive(self: *Self, id: u64, offset: u64, data: []const u8, fin: bool) Error!void {
            // Section 19.8 puts the sum past 2^62-1 in the same sentence as
            // FRAME_ENCODING_ERROR, and the addition has to be guarded before
            // it happens rather than tested after: `receive` is public, offsets
            // are 62-bit and peer-chosen, and an overflow lands ahead of any
            // check that was meant to catch it.
            if (!self.peerMaySend(id)) return error.StreamState;
            try self.checkAdvertisedStreamLimit(id);
            if (offset > varint.max or data.len > varint.max - offset) return error.FinalSize;
            const end = offset + data.len;

            const stream = try self.open(id);
            if (stream.receive_state == .reset) return; // Section 3.2: discard.

            try self.admit(stream, end);
            stream.received.push(offset, data) catch |err| return switch (err) {
                error.BeyondWindow => error.FlowControl,
                error.TooFragmented => error.TooFragmented,
                error.Inconsistent => error.Protocol,
                error.FinalSizeViolated => error.FinalSize,
            };
            if (fin) {
                stream.received.finish(end) catch return error.FinalSize;
                stream.receive_state = .size_known;
            }
            self.settle(stream);
        }

        /// Section 4.1: check both limits, and charge the connection for what
        /// this stream newly consumed.
        ///
        /// The charge is the *delta* of the stream's highest offset, so a
        /// retransmission of data already counted costs nothing and a peer
        /// cannot consume the connection window twice with the same octets.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.9
        //# An endpoint MUST terminate a connection with an error of type
        //# FLOW_CONTROL_ERROR if it receives more data than the maximum data
        //# value that it has sent.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        //# An endpoint MUST terminate a connection with an error of type
        //# FLOW_CONTROL_ERROR if it receives more data than the largest maximum
        //# stream data that it has sent for the affected stream.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.9
        //# The sum of the final sizes on all streams -- including streams in
        //# terminal states -- MUST NOT exceed the value advertised by a
        //# receiver.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        //# The data sent on a stream MUST NOT exceed the largest maximum stream
        //# data value advertised by the receiver.
        fn admit(self: *Self, stream: *Stream, end: u64) Error!void {
            if (end <= stream.received_highest) return;
            if (end > stream.receiveLimit()) return error.FlowControl;

            // Both comparisons above are returned errors rather than
            // assertions, because `end` is an offset the peer chose: the first
            // is what makes this subtraction safe, and the second is section
            // 4.1's connection-level window, which is the one that bounds
            // memory across every stream at once.
            assert(end > stream.received_highest);
            const charge = end - stream.received_highest;
            assert(charge <= config.receive_octets);
            if (self.received_total + charge > self.receiveLimit()) return error.FlowControl;
            self.received_total += charge;
            stream.received_highest = end;
            assert(stream.received_highest <= stream.receiveLimit());
        }

        /// Section 4.1: the connection's limit, measured forward from what the
        /// application has taken across all streams.
        pub fn receiveLimit(self: *const Self) u64 {
            assert(self.consumed_total <= self.received_total);
            const limit = self.consumed_total + config.connection_receive_octets;
            assert(limit >= config.connection_receive_octets);
            return limit;
        }

        /// Release bytes the application has read.
        pub fn consume(self: *Self, id: u64, octets: usize) Error!void {
            const stream = self.find(id) orelse return error.NotFound;
            // Checked, not asserted: `consume` is application-facing and takes
            // an unvalidated count, and `Reassembler.consume`'s own guard is an
            // assertion that the shipping build removes.
            if (octets > stream.readable().len) return error.Protocol;
            stream.received.consume(octets);
            stream.consumed += octets;
            self.consumed_total += octets;
            // Credit is released, never invented: what the application took
            // cannot exceed what the peer was admitted to send.
            assert(stream.consumed <= stream.received_highest);
            assert(self.consumed_total <= self.received_total);
            self.settle(stream);
        }

        /// Move a stream to `data_read` once everything has arrived and been
        /// taken. Separate from `consume` because a zero-length FIN completes a
        /// stream without anything being read.
        fn settle(self: *Self, stream: *Stream) void {
            _ = self;
            if (stream.receive_state != .size_known) return;
            if (stream.received.isComplete() and stream.readable().len == 0) {
                stream.receive_state = .data_read;
            }
        }

        /// Section 19.4: the peer abandoned a stream.
        ///
        /// One direction only. Nothing below touches `send_state`,
        /// `send_limit`, `send_offset` or `sent_total`, so a RESET_STREAM on a
        /// bidirectional stream leaves this endpoint's own half writable and
        /// still accounted for against both send-side windows.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
        //# Both endpoints MUST maintain flow control state for the stream in the
        //# unterminated direction until that direction enters a terminal state.
        //
        // The three `error.FinalSize` returns below are the three shapes a
        // final size can change in: a size that contradicts one a FIN already
        // fixed, one that retracts data already received, and — in
        // `Reassembler.push` — data arriving past a size already named. Each
        // reaches the consumer as `Connection.ReceiveError.FinalSize`, which
        // is the `FINAL_SIZE_ERROR` this names.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        //# If a RESET_STREAM or STREAM frame is received indicating a change in
        //# the final size for the stream, an endpoint SHOULD respond with an
        //# error of type FINAL_SIZE_ERROR; see Section 11 for details on error
        //# handling.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.4
        //# An endpoint that receives a RESET_STREAM frame for a send-only
        //# stream MUST terminate the connection with error STREAM_STATE_ERROR.
        //
        // What a cancelled stream *means* stops at this line. The transport's
        // share is the accounting below — the final size, the credit release,
        // the state — and `reset_code` is carried through opaquely because
        // section 11.2 puts its semantics in the application protocol. A
        // consumer reads it off the stream and decides; nothing here does.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-11.2
        //# Application protocols SHOULD define rules for handling streams that
        //# are prematurely canceled by either endpoint.
        //= type=exception
        //= reason=this is addressed to the application protocol rather than to the transport; RESET_STREAM's error code is carried opaquely to the consumer, and the rules for a prematurely cancelled request are RFC 9114's and the consumer's, not this file's
        pub fn reset(self: *Self, id: u64, code: u64, final_size: u64) Error!void {
            if (!self.peerMaySend(id)) return error.StreamState;
            if (final_size > varint.max) return error.FinalSize;
            const stream = try self.open(id);
            if (stream.receive_state == .reset) return;

            // Section 4.5: "Once a final size for a stream is known, it cannot
            // change." A FIN fixes it, and a RESET_STREAM afterwards naming a
            // different one is a peer contradicting itself — which, before this
            // check, moved `received_highest` and charged the difference to the
            // connection's window.
            if (stream.received.final_size) |known| {
                if (known != final_size) return error.FinalSize;
            }
            // And a size below what has already arrived would retract data the
            // peer itself sent.
            if (final_size < stream.received_highest) return error.FinalSize;
            try self.admit(stream, final_size);
            stream.receive_state = .reset;
            stream.reset_code = code;

            // Section 4.1 leaves the release policy to the implementation, and
            // the policy has to be *some* release: the octets a reset claimed
            // will never be delivered, so they can never be consumed, so
            // without this they hold connection credit for the rest of the
            // connection. Two RESET_STREAM frames of four octets each were
            // enough to exhaust the window permanently and refuse every
            // subsequent byte of real data.
            assert(final_size >= stream.consumed);
            self.consumed_total += final_size - stream.consumed;
            stream.consumed = final_size;
        }

        /// Queue bytes for sending, returning how many were taken.
        ///
        /// A short write is ordinary: the buffer is finite and the peer's flow
        /// control limit is not ours to exceed. A caller loops, or waits for
        /// `MAX_STREAM_DATA`.
        ///
        /// The refusal is here rather than at the sender, which is the point:
        /// `Connection.writeStream` frames whatever sits in `send[framed..]`
        /// without consulting a window, because nothing can get into that
        /// buffer that both limits did not already allow.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        //# An endpoint MUST NOT send data on any stream without ensuring that it
        //# is within the flow control limits set by its peer.
        //
        // What a short write does *not* do is tell the peer. Neither
        // STREAM_DATA_BLOCKED nor STREAMS_BLOCKED is generated anywhere in the
        // package — `Connection.receiveFrames` discards both on receipt and
        // frames neither — so a caller that hits `take == 0` here has no way
        // to say so, and a peer that is waiting to be asked waits forever.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint that is unable to open a new stream due to the peer's
        //# limits SHOULD send a STREAMS_BLOCKED frame (Section 19.14).
        //= type=todo
        pub fn write(self: *Self, id: u64, data: []const u8, fin: bool) Error!usize {
            // Section 19.8's mirror: a unidirectional stream the peer opened is
            // receive-only here, and writing on one is this endpoint's bug
            // rather than the peer's.
            if (!self.weMaySend(id)) return error.StreamState;
            // Section 4.6, and here rather than in `open` because `open` is
            // also how a peer's own frame creates a stream: the peer's
            // MAX_STREAMS governs what *this* endpoint opens on its own
            // initiative, not what the peer's frames bring into being.
            try self.checkPeerStreamLimit(id);
            const stream = try self.open(id);
            if (!stream.writable()) return error.Protocol;

            const room = @min(
                config.send_octets - stream.send_len,
                sendRoom(stream.send_limit, stream.send_offset + stream.send_len),
            );
            const connection_room = sendRoom(self.send_limit, self.sent_total);
            const take = @min(data.len, @min(room, connection_room));

            @memcpy(stream.send[stream.send_len..][0..take], data[0..take]);
            stream.send_len += @intCast(take);
            self.sent_total += take;
            if (fin and take == data.len) {
                stream.send_fin = true;
                stream.send_state = .data_sent;
            }
            return take;
        }

        // A room of zero is where a sender is blocked, and it is where the
        // frame that says so would be generated. Nothing counts how long this
        // has answered zero and nothing is periodic here, so the peer is told
        // nothing and the only thing keeping the connection alive is whatever
        // else it has to send.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        //# To keep the connection from closing, a sender that is flow control
        //# limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED
        //# frame when it has no ack-eliciting packets in flight.
        //= type=todo
        fn sendRoom(limit: u64, at: u64) u64 {
            // The comparison is the guard on the subtraction. `limit` is the
            // peer's advertised window and `at` is how far we have written, and
            // a peer may lower neither — but it may send a MAX_STREAM_DATA that
            // arrives after we have already written past it.
            const room = if (limit > at) limit - at else 0;
            assert(room == 0 or limit > at);
            assert(room <= limit);
            return room;
        }

        /// Section 19.10 and 19.9: raise a peer's limits.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        //# An endpoint that receives a MAX_STREAM_DATA frame for a receive-only
        //# stream MUST terminate the connection with error STREAM_STATE_ERROR.
        pub fn setSendLimit(self: *Self, id: u64, limit: u64) Error!void {
            // Section 19.10: MAX_STREAM_DATA for a stream this endpoint cannot
            // send on is the peer raising a limit that could never apply.
            if (!self.weMaySend(id)) return error.StreamState;
            const stream = try self.open(id);
            // Limits only ever rise; a peer lowering one is ignored rather than
            // an error, which is what section 4.1 says to do.
            stream.send_limit = @max(stream.send_limit, limit);
        }

        pub fn setConnectionSendLimit(self: *Self, limit: u64) void {
            self.send_limit = @max(self.send_limit, limit);
        }

        /// Streams with data waiting to be framed.
        ///
        /// The `.reset` test comes *after* the data test, and only the FIN is
        /// behind it: a stream whose send half was moved to `.reset` — which is
        /// what `Connection.receiveFrames` does on STOP_SENDING — still answers
        /// true while it has unframed octets, and `Connection.writeStream`,
        /// which reads no state at all, then frames them. So this endpoint goes
        /// on sending STREAM frames on a stream it has recorded as abandoned.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        //# A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a
        //# stream in the "Reset Sent" state or any terminal state -- that is,
        //# after sending a RESET_STREAM frame.
        //= type=todo
        //
        // And what it does answer is a set, not an order: the caller takes the
        // first stream with anything waiting, so a large body starves every
        // stream after it in the array and an application has no say in which.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.3
        //# A QUIC implementation SHOULD provide ways in which an application can
        //# indicate the relative priority of streams.
        //= type=todo
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        //# A sender MUST NOT send a STREAM or
        //# STREAM_DATA_BLOCKED frame for a stream in the "Reset Sent" state or
        //# any terminal state -- that is, after sending a RESET_STREAM frame.
        pub fn wantsSend(self: *const Self) bool {
            for (self.streams[0..self.count]) |*stream| {
                // The reset test used to come *after* the unframed-data test,
                // so a stream the peer had stopped with STOP_SENDING still
                // answered true while octets remained — and `writeStream` reads
                // no send state at all, so it framed and sent them. The peer
                // asked us to stop and we kept writing.
                if (stream.send_state == .reset) continue;
                if (stream.framed < stream.send_len) return true;
                // A FIN is owed once, not once per poll.
                if (stream.send_fin and !stream.fin_framed) return true;
            }
            return false;
        }

        /// Undo the framing of a lost range, so it is sent again.
        ///
        /// `fin_lost` is separate because a FIN carries no octets: an empty
        /// FIN frame records an empty range, so a lost one would otherwise have
        /// no way back — it is the one thing a byte range cannot describe.
        ///
        /// Loss always means retransmission here. A stream the peer asked us to
        /// stop is rewound like any other, because this reads no state; section
        /// 3.5 wants the loss taken as the moment to give up on it instead.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
        //# If any outstanding data is declared lost, the endpoint SHOULD send a
        //# RESET_STREAM frame instead of retransmitting the data.
        //= type=todo
        //
        // The priority rule falls out of the buffer's shape rather than being
        // scheduled: `framed` is a single watermark into `send`, everything
        // below it has gone out and everything above it has not, and a rewind
        // moves it backwards. `Connection.writeStream` then frames forward from
        // `framed`, so the retransmitted octets — which are the lower offsets —
        // are framed before any new data behind them, and no ordering decision
        // is made anywhere. The application has no say in it, which is the
        // half of this section 2.3 defers to and `wantsSend` marks as missing.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        //# Endpoints SHOULD prioritize retransmission of data over sending new
        //# data, unless priorities specified by the application indicate
        //# otherwise; see Section 2.3.
        /// `from` is an absolute stream offset, not an index into `send`.
        ///
        /// It used to be an index, which was the same number while nothing was
        /// ever reclaimed. Once the buffer can shift, a lost packet's range has
        /// to be named in coordinates that survive the shift — and a range
        /// entirely below `send_offset` is one the peer has already
        /// acknowledged, so there is nothing to send again.
        pub fn rewind(self: *Self, id: u64, from: u64, fin_lost: bool) void {
            const stream = self.find(id) orelse return;
            if (from >= stream.send_offset) {
                const index = from - stream.send_offset;
                if (index < stream.framed) stream.framed = @intCast(index);
            }
            if (fin_lost) stream.fin_framed = false;
        }

        /// Give back the octets a packet acknowledged.
        ///
        /// `start` and `end` are absolute stream offsets. Only a range that
        /// begins exactly where the acknowledged prefix ends advances it: a
        /// range past a gap is dropped, and comes back when the gap is filled.
        /// That is not a heuristic — `rewind` moves the framing watermark back
        /// to the *start* of a lost packet, so everything after it is framed
        /// again and its acknowledgements arrive in order behind the
        /// retransmission.
        pub fn reclaim(self: *Self, id: u64, start: u64, end: u64) void {
            const stream = self.find(id) orelse return;
            if (start != stream.acked_to) return;
            assert(end >= start);
            stream.acked_to = end;

            assert(stream.acked_to >= stream.send_offset);
            const octets = stream.acked_to - stream.send_offset;
            if (octets == 0) return;
            // Acknowledged implies *buffered*. It does not imply framed:
            // RFC 9002's loss detection is a heuristic, so a packet can be
            // declared lost — which rewinds `framed` behind it — and then
            // acknowledged anyway, because it was only late. The simulator
            // found this on the first sweep after reclamation landed, and the
            // assertion it broke was the claim that the two are the same.
            assert(octets <= stream.send_len);
            assert(stream.framed <= stream.send_len);
            const width: u32 = @intCast(octets);
            std.mem.copyForwards(
                u8,
                stream.send[0 .. stream.send_len - width],
                stream.send[width..stream.send_len],
            );
            stream.send_len -= width;
            // Octets the peer has do not need framing again, whatever a
            // spurious loss did to the watermark.
            stream.framed = if (stream.framed > width) stream.framed - width else 0;
            stream.send_offset += width;
            assert(stream.send_offset == stream.acked_to);
        }
    };
}

const testing = std.testing;

const Set = Streams(.{
    .streams_max = 4,
    .receive_octets = 64,
    .send_octets = 32,
    .connection_receive_octets = 128,
});

/// A set whose peer has permitted the streams this endpoint may hold.
///
/// Section 18.2 defaults every stream limit to zero, so a bare `Set{}` has been
/// permitted nothing and cannot open a locally-initiated stream — which is
/// correct, and which is why every test that opens one goes through here rather
/// than through `.{}`. The tests that are *about* the limit build their own.
fn testSet() Set {
    var set: Set = .{};
    set.setPeerStreamLimit(true, Set.streams_max);
    set.setPeerStreamLimit(false, Set.streams_max);
    return set;
}

test "data arrives, is read, and the window moves forward with the reader" {
    var set = testSet();
    try set.receive(0, 0, "hello", false);
    const stream = set.find(0).?;
    try testing.expectEqualStrings("hello", stream.readable());
    // Section 4.1: the limit is measured from what the application took, not
    // from what arrived — otherwise a peer that outruns the reader pushes the
    // window past the buffer.
    try testing.expectEqual(@as(u64, Set.receive_octets), stream.receiveLimit());

    try set.consume(0, 5);
    try testing.expectEqual(@as(u64, 5 + Set.receive_octets), stream.receiveLimit());
    try testing.expectEqual(@as(u64, 5), set.consumed_total);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
//# A receiver MUST close the connection with an error of type
//# FLOW_CONTROL_ERROR if the sender violates the advertised connection or
//# stream data limits; see Section 11 for details on error handling.
//= type=test
test "a peer may not send past a stream's limit" {
    var set = testSet();
    const oversized: [Set.receive_octets + 1]u8 = @splat('x');
    try testing.expectError(error.FlowControl, set.receive(0, 0, &oversized, false));

    // Exactly to the edge is fine.
    const exact: [Set.receive_octets]u8 = @splat('x');
    try set.receive(0, 0, &exact, false);
    // And one octet past it, on a second frame, is not.
    try testing.expectError(error.FlowControl, set.receive(0, Set.receive_octets, "y", false));
}

test "the connection limit binds across streams, which is what bounds memory" {
    var set = testSet();
    // Two streams' worth fits the connection window; a third does not, even
    // though each is within its own stream limit. Without this a peer's memory
    // budget is the per-stream window times the stream count.
    const chunk: [Set.receive_octets]u8 = @splat('x');
    try set.receive(0, 0, &chunk, false);
    try set.receive(4, 0, &chunk, false);
    try testing.expectEqual(Set.connection_receive_octets, set.received_total);
    try testing.expectError(error.FlowControl, set.receive(8, 0, "z", false));

    // Reading frees connection credit, and the third stream fits.
    try set.consume(0, 32);
    try set.receive(8, 0, "z", false);
}

test "a retransmission does not consume the window twice" {
    var set = testSet();
    try set.receive(0, 0, "hello", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
    // The same octets again: ordinary retransmission. Charging for them would
    // let a lossy path exhaust a connection's window without sending anything
    // new.
    try set.receive(0, 0, "hello", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
    // And an overlapping frame charges only for what is past the high mark.
    try set.receive(0, 3, "lo there", false);
    try testing.expectEqual(@as(u64, 11), set.received_total);
}

test "a reset stream keeps its accounting" {
    var set = testSet();
    try set.receive(0, 0, "hello", false);
    try set.reset(0, 7, 5);
    try testing.expectEqual(ReceiveState.reset, set.find(0).?.receive_state);
    // Section 4.1: the credit stays consumed. Forgetting it would let a peer
    // fill a window, reset, and repeat — holding nothing and consuming
    // everything.
    try testing.expectEqual(@as(u64, 5), set.received_total);

    // Data after a reset is discarded rather than an error: it was in flight
    // when the reset was sent.
    try set.receive(0, 5, "more", false);
    try testing.expectEqual(@as(u64, 5), set.received_total);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# The receiver MUST use the final size of the stream to account for all
//# bytes sent on the stream in its connection-level flow controller.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# If a RESET_STREAM or STREAM frame is received indicating a change in
//# the final size for the stream, an endpoint SHOULD respond with an
//# error of type FINAL_SIZE_ERROR; see Section 11 for details on error
//# handling.
//= type=test
test "a reset that retracts data already charged is refused" {
    var set = testSet();
    try set.receive(0, 0, "hello", false);
    // Section 4.5: a final size below what has arrived contradicts the peer's
    // own earlier frames, and accepting it would give back window credit.
    try testing.expectError(error.FinalSize, set.reset(0, 0, 3));
    // A final size above it charges the difference, as section 4.5 requires.
    try set.reset(0, 0, 9);
    try testing.expectEqual(@as(u64, 9), set.received_total);
}

test "a FIN completes a stream once everything has been read" {
    var set = testSet();
    try set.receive(0, 0, "hel", false);
    try set.receive(0, 3, "lo", true);
    const stream = set.find(0).?;
    try testing.expectEqual(ReceiveState.size_known, stream.receive_state);
    try testing.expect(!stream.isComplete());

    try set.consume(0, 5);
    try testing.expect(stream.isComplete());
}

test "an empty FIN completes a stream with nothing to read" {
    var set = testSet();
    try set.receive(0, 0, "", true);
    try testing.expect(set.find(0).?.isComplete());
}

test "section 4.5: the final size may not move" {
    var set = testSet();
    try set.receive(0, 0, "hello", true);
    try testing.expectError(error.FinalSize, set.receive(0, 5, "more", false));
    // A different final size on a second FIN.
    try testing.expectError(error.FinalSize, set.receive(0, 0, "hel", true));
}

test "section 2.2: data at an offset never changes" {
    var set = testSet();
    try set.receive(0, 0, "hello", false);
    try testing.expectError(error.Protocol, set.receive(0, 0, "HELLO", false));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
//# An endpoint MUST NOT send data on any stream without ensuring that it
//# is within the flow control limits set by its peer.
//= type=test
test "writes are bounded by the peer's limits, in both levels" {
    var set = testSet();
    // No limits yet: the peer has offered nothing, so nothing may go out.
    try testing.expectEqual(@as(usize, 0), try set.write(0, "hello", false));

    try set.setSendLimit(0, 3);
    set.setConnectionSendLimit(1000);
    try testing.expectEqual(@as(usize, 3), try set.write(0, "hello", false));
}

test "the connection's send limit binds independently of a stream's" {
    // A fresh set, because a limit never falls — lowering the connection's to
    // observe it would be observing nothing.
    var set = testSet();
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(2);
    // The stream would take all five; the connection allows two.
    try testing.expectEqual(@as(usize, 2), try set.write(0, "hello", false));
    try testing.expectEqual(@as(u64, 2), set.sent_total);

    // Raising it lets the rest through.
    set.setConnectionSendLimit(1000);
    try testing.expectEqual(@as(usize, 3), try set.write(0, "llo", false));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
//# A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do
//# not increase flow control limits.
//= type=test
test "a limit never falls" {
    var set = testSet();
    try set.setSendLimit(0, 100);
    try set.setSendLimit(0, 10);
    // Section 4.1: a smaller limit is ignored rather than an error. A reordered
    // MAX_STREAM_DATA is ordinary.
    try testing.expectEqual(@as(u64, 100), set.find(0).?.send_limit);

    set.setConnectionSendLimit(100);
    set.setConnectionSendLimit(10);
    try testing.expectEqual(@as(u64, 100), set.send_limit);
}

test "a FIN closes the send half to further writes" {
    var set = testSet();
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(1000);
    _ = try set.write(0, "hello", true);
    try testing.expectEqual(SendState.data_sent, set.find(0).?.send_state);
    try testing.expectError(error.Protocol, set.write(0, "more", false));
}

test "a partial write does not carry the FIN" {
    var set = testSet();
    try set.setSendLimit(0, 2);
    set.setConnectionSendLimit(1000);
    // Only two octets fit, so the stream is not finished — a FIN at the wrong
    // offset would tell the peer the stream ended early.
    try testing.expectEqual(@as(usize, 2), try set.write(0, "hello", true));
    try testing.expect(!set.find(0).?.send_fin);
    try testing.expectEqual(SendState.sending, set.find(0).?.send_state);
}

test "more streams than the bound is refused rather than grown into" {
    var set = testSet();
    for (0..Set.streams_max) |index| _ = try set.open(@as(u64, index) * 4);
    try testing.expectError(error.TooManyStreams, set.open(1000));
    // An already-open stream is found rather than opened again.
    const again = try set.open(0);
    try testing.expectEqual(@as(u64, 0), again.id);
}

test "rewinding re-frames a lost range" {
    var set = testSet();
    try set.setSendLimit(0, 1000);
    set.setConnectionSendLimit(1000);
    _ = try set.write(0, "hello", false);
    const stream = set.find(0).?;
    stream.framed = 5;
    try testing.expect(!set.wantsSend());

    set.rewind(0, 2, false);
    try testing.expectEqual(@as(u32, 2), stream.framed);
    try testing.expect(set.wantsSend());
}

test "section 19.8: a peer may not send on a stream it cannot send on" {
    // `Set` is a client, so stream 2 is *this endpoint's* unidirectional stream
    // — send-only here, receive-only for the peer. A STREAM or RESET_STREAM
    // arriving on one is the peer writing where it cannot.
    var set: Set = .{ .side = .client };
    // The peer permits what this test needs to open; section 4.6's limit is a
    // separate rule with its own tests below.
    set.setPeerStreamLimit(true, Set.streams_max);
    set.setPeerStreamLimit(false, Set.streams_max);
    const ours = stream_id.make(.client_unidirectional, 0);
    try testing.expectError(error.StreamState, set.receive(ours, 0, "x", false));
    try testing.expectError(error.StreamState, set.reset(ours, 0, 1));

    // The peer's own unidirectional stream is the other way round.
    const theirs = stream_id.make(.server_unidirectional, 0);
    try set.receive(theirs, 0, "x", false);
    try testing.expectError(error.StreamState, set.write(theirs, "x", false));
    try testing.expectError(error.StreamState, set.setSendLimit(theirs, 1000));

    // A bidirectional stream is legal in both directions.
    const both = stream_id.make(.client_bidirectional, 0);
    try set.receive(both, 0, "x", false);
    try set.setSendLimit(both, 1000);
    set.setConnectionSendLimit(1000);
    _ = try set.write(both, "x", false);
}

test "section 4.5: a RESET_STREAM may not move a final size a FIN already fixed" {
    var set = testSet();
    try set.receive(0, 0, "hello", true); // the FIN fixes it at 5
    // "Once a final size for a stream is known, it cannot change." Before this
    // check the reset was accepted, `received_highest` moved to 9, and the
    // difference was charged to the connection's window.
    try testing.expectError(error.FinalSize, set.reset(0, 0, 9));
    try testing.expectError(error.FinalSize, set.reset(0, 0, 3));
    try testing.expectEqual(@as(u64, 5), set.received_total);
    // The size it actually named is still accepted.
    try set.reset(0, 0, 5);
}

test "section 4.1: a reset stream gives its credit back" {
    var set = testSet();
    // Octets a reset claimed are never delivered, so they can never be
    // consumed. Without a release they hold connection credit forever: two
    // RESET_STREAM frames, eight octets of peer input, and the window was
    // exhausted for the rest of the connection.
    try set.reset(0, 7, Set.receive_octets);
    try set.reset(4, 7, Set.receive_octets);
    try testing.expectEqual(Set.connection_receive_octets, set.received_total);

    // The credit came back, so real data still fits.
    try testing.expect(set.receiveLimit() > set.received_total);
    try set.receive(8, 0, "real data", false);
    try testing.expectEqualStrings("real data", set.find(8).?.readable());
}

test "a resource limit is not reported as the peer's fault" {
    // `TooFragmented` used to arrive as `FlowControl`, which tells the peer it
    // exceeded a window it did not exceed. The peer is within its rights here —
    // gaps are what a lossy path produces — and this endpoint is the one out of
    // room, so the two answers have to be distinguishable to a consumer
    // choosing a close code.
    // Its own type rather than `Set`: the window has to be wide enough for more
    // spans than the table holds, or `BeyondWindow` fires first and this test
    // passes without reaching the limit it is about.
    const Wide = Streams(.{
        .streams_max = 1,
        .receive_octets = 4 * receive_spans_max,
        .send_octets = 32,
        .connection_receive_octets = 4 * receive_spans_max,
    });
    comptime assert(Wide.receive_octets / 2 > receive_spans_max);

    var set: Wide = .{ .side = .server };
    set.setPeerStreamLimit(true, 4);
    var offset: u64 = 0;
    var refused: ?anyerror = null;
    // Every other octet, which is the cheapest way for a peer to manufacture
    // spans.
    for (0..Wide.receive_octets / 2) |_| {
        set.receive(0, offset, "x", false) catch |err| {
            refused = err;
            break;
        };
        offset += 2;
    }
    try testing.expectEqual(@as(?anyerror, error.TooFragmented), refused);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
//# Endpoints MUST NOT exceed the limit set by their peer.
//= type=test
//
// The last two lines are the other half: a MAX_STREAMS that lowers the limit
// leaves it where it was.
//= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
//# MAX_STREAMS frames that do not increase the stream limit MUST be
//# ignored.
//= type=test
test "section 4.6: this endpoint may not open past the peer's limit" {
    var set: Set = .{ .side = .client };
    // Section 18.2's default: permitted nothing until told otherwise.
    const first = stream_id.make(.client_bidirectional, 0);
    set.setConnectionSendLimit(1000);
    try testing.expectError(error.TooManyStreams, set.write(first, "x", false));

    // Two streams permitted means indices 0 and 1, not identifiers 0 and 1 —
    // MAX_STREAMS counts streams and an identifier carries a two-bit type tag,
    // so reading the count as an identifier admits a quarter of what was
    // offered.
    set.setPeerStreamLimit(true, 2);
    try set.setSendLimit(first, 1000);
    _ = try set.write(first, "x", false);
    const second = stream_id.make(.client_bidirectional, 1);
    try set.setSendLimit(second, 1000);
    _ = try set.write(second, "x", false);
    const third = stream_id.make(.client_bidirectional, 2);
    try testing.expectError(error.TooManyStreams, set.write(third, "x", false));

    // Raising the limit lets the next one through; lowering it is ignored.
    set.setPeerStreamLimit(true, 3);
    try set.setSendLimit(third, 1000);
    _ = try set.write(third, "x", false);
    set.setPeerStreamLimit(true, 1);
    try testing.expectEqual(@as(u64, 3), set.peer_streams_bidi);
}

test "section 4.6: the peer's limit does not govern the peer's own streams" {
    // The limit is on what *we* open. A stream the peer initiates is bounded by
    // the limit we advertised, which is `streams_max`, and applying the peer's
    // number to it would refuse traffic the peer was entitled to send.
    var set: Set = .{ .side = .client };
    try testing.expectEqual(@as(u64, 0), set.peer_streams_uni);
    const theirs = stream_id.make(.server_unidirectional, 0);
    try set.receive(theirs, 0, "hello", false);
    try testing.expectEqualStrings("hello", set.find(theirs).?.readable());
}

test "the two stream kinds carry separate limits" {
    var set: Set = .{ .side = .client };
    set.setConnectionSendLimit(1000);
    set.setPeerStreamLimit(false, 1);
    const uni = stream_id.make(.client_unidirectional, 0);
    try set.setSendLimit(uni, 1000);
    _ = try set.write(uni, "x", false);
    // Unidirectional permission says nothing about bidirectional.
    const bidi = stream_id.make(.client_bidirectional, 0);
    try testing.expectError(error.TooManyStreams, set.write(bidi, "x", false));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
//# A sender MUST NOT send a STREAM or
//# STREAM_DATA_BLOCKED frame for a stream in the "Reset Sent" state or
//# any terminal state -- that is, after sending a RESET_STREAM frame.
//= type=test
test "section 3.3: a stopped stream stops being sent" {
    var set = testSet();
    set.setConnectionSendLimit(1000);
    try set.setSendLimit(0, 1000);
    _ = try set.write(0, "data", false);
    try testing.expect(set.wantsSend());

    // STOP_SENDING moves the send half to reset; nothing more may go out.
    set.find(0).?.send_state = .reset;
    try testing.expect(!set.wantsSend());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
//# An endpoint
//# that receives a frame with a stream ID exceeding the limit it has
//# sent MUST treat this as a connection error of type
//# STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
//= type=test
test "section 4.6: a stream identifier past our advertised limit is refused" {
    var set: Set = .{ .side = .client };
    // `Set` advertises four. The rule is about the identifier, not the count,
    // so the *first* stream the peer opens can already break it.
    const far = stream_id.make(.server_bidirectional, Set.streams_max);
    try testing.expectError(error.TooManyStreams, set.receive(far, 0, "x", false));

    // The highest one that fits is index `streams_max - 1`.
    const highest = stream_id.make(.server_bidirectional, Set.streams_max - 1);
    try set.receive(highest, 0, "x", false);
    try testing.expectEqualStrings("x", set.find(highest).?.readable());
}

test "a stream tolerates more gaps than a quiet path produces" {
    // This was eight, on the reasoning that "a real path reorders within a few
    // packets". The interop runner's ordinary transfer path — 15 ms of delay,
    // 10 Mbps, a 25-packet queue — put more than eight gaps in one stream, and
    // a receiver out of spans closes the connection with INTERNAL_ERROR. The
    // literal below is the number that was wrong, so this test fails if it
    // comes back.
    const Wide = Streams(.{
        .streams_max = 1,
        .receive_octets = 256,
        .send_octets = 32,
        .connection_receive_octets = 256,
    });
    var set: Wide = .{ .side = .server };
    set.setPeerStreamLimit(true, 1);

    // Sixteen disjoint spans, which the old bound refused at nine.
    var offset: u64 = 0;
    for (0..16) |_| {
        try set.receive(0, offset, "x", false);
        offset += 2;
    }
    try testing.expect(set.find(0).?.received.span_count > 8);
}
