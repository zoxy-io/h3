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
    /// Section 3.1's "Reset Sent": this endpoint abandoned the stream and the
    /// RESET_STREAM is owed or in flight, but not yet acknowledged.
    ///
    /// The state used to mean "abandoned" and nothing more, because no
    /// RESET_STREAM was ever framed: `Connection` moved a stream here on
    /// receiving STOP_SENDING and the peer was never told, so the final size
    /// the two endpoints are supposed to agree on was never communicated.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
    //# A sender MUST NOT send any of these frames from a terminal state
    //# ("Data Recvd" or "Reset Recvd").
    //= type=test
    reset,
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.1
    //# Once a packet containing a RESET_STREAM has been acknowledged, the
    //# sending part of the stream enters the "Reset Recvd" state, which is a
    //# terminal state.
    //= type=test
    ///
    /// Terminal, and the state a reset stream has to reach before its slot can
    /// be given back: retiring one that still owed a RESET_STREAM would drop
    /// the frame the peer is waiting for.
    reset_recvd,
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

        /// How many streams are tracked at once, which is a bound on this
        /// table and no longer a bound on the connection.
        ///
        /// It used to be both, and the comment here said so: "the only limit
        /// this endpoint will ever advertise", on the grounds that a comptime
        /// number never rises. A peer that closed a stream never got it back,
        /// and section 4.6's MUST NOT was called satisfied vacuously — nothing
        /// waits for STREAMS_BLOCKED if nothing issues credit at all. That is
        /// the shape of a limitation arguing itself into a design. See
        /// `advertised_bidi` for what replaced it, and `owesStreamCredit` for
        /// the sentence this used to cite.
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
            /// RFC 9000 section 4.1: this endpoint has octets to write on this
            /// stream and the peer's limit is what stops it. Owed as a
            /// STREAM_DATA_BLOCKED frame, and the reason it is worth sending is
            /// that a receiver has no other way to learn that the window update
            /// it believes it granted never arrived.
            send_blocked: bool = false,

            /// The error code a RESET_STREAM carried, in either direction.
            reset_code: u64 = 0,
            /// The Final Size this endpoint's own RESET_STREAM carries, fixed
            /// when the stream is abandoned. Section 13.3 requires the frame's
            /// content not to change when it is sent again, so it is recorded
            /// rather than recomputed — `send_len` moves when the buffer is
            /// reclaimed, and a retransmission built from it would carry a
            /// different final size than the one already on the wire.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
            //# The content of a RESET_STREAM frame MUST NOT change when it is sent
            //# again.
            //= type=test
            reset_final_size: u64 = 0,
            /// Whether that frame has been put in a packet. The counterpart of
            /// `fin_framed`, and owed again when the packet carrying it is lost.
            reset_framed: bool = false,
            /// Section 19.5: the code of a STOP_SENDING this endpoint owes on
            /// this stream, or null when it owes none. The mirror direction of
            /// `reset_code`: that one abandons what we send, this one asks the
            /// peer to stop sending to us.
            stop_code: ?u64 = null,
            /// Whether that frame has been put in a packet.
            stop_framed: bool = false,
            /// The `MAX_STREAM_DATA` last advertised, so a new one goes out
            /// only when the window has moved enough to be worth a frame.
            /// Starts at the window the transport parameters carried, which the
            /// peer has already been told.
            max_data_sent: u64 = config.receive_octets,

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
        /// The same, for the connection window.
        send_blocked: bool = false,

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

        /// Section 4.6: how many identifiers of each kind the peer may open,
        /// which is what a MAX_STREAMS frame carries and what
        /// `checkAdvertisedStreamLimit` enforces.
        ///
        /// It rises as finished streams are retired. It used to be the comptime
        /// `streams_max` and nothing else, which made the table's size a bound
        /// on the connection's *lifetime* rather than on its concurrency: a peer
        /// that closed a stream never got it back, and the runner's
        /// `multiplexing` case — 1999 files on one connection — stopped after
        /// the first eight and waited out the idle timeout.
        advertised_bidi: u64 = streams_max,
        advertised_uni: u64 = streams_max,
        /// What has already gone out in a MAX_STREAMS, so the frame is not
        /// repeated. Starts at the base for the reason `max_data_sent` does:
        /// the peer has already been told that much.
        max_streams_bidi_sent: u64 = streams_max,
        max_streams_uni_sent: u64 = streams_max,
        /// Identifiers of each kind, counting from zero, that have been opened
        /// and given up.
        ///
        /// Contiguous on purpose. A stream that finishes before a lower-numbered
        /// one keeps its slot until that one finishes too, because a watermark
        /// with holes in it cannot tell a retired identifier from one that was
        /// never opened — and the two need opposite answers: a frame for the
        /// first is a retransmission to ignore, and a frame for the second opens
        /// a stream.
        retired: [stream_id.kind_count]u64 = @splat(0),

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
            /// The stream existed and has been given up. Not a protocol error:
            /// a frame naming it is a retransmission of one that arrived before
            /// the stream finished, and section 3.2 has the receiver discard it.
            Retired,
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

        /// Owe every window update again.
        ///
        /// RFC 9000 section 13.3: MAX_DATA and MAX_STREAM_DATA are among the
        /// frames whose loss has to be repaired, and the repair is not a
        /// retransmission of the old frame — it is the *current* limit, sent
        /// again. `max_data_sent` records what was put on the wire, so a lost
        /// packet leaves the peer below a limit this endpoint believes it has
        /// granted, and the threshold that decides when to send the next one
        /// has already moved past it. The connection then deadlocks: the sender
        /// waiting for credit, the receiver waiting for data, both correct.
        ///
        /// Zeroing is safe because limits only rise. The next packet
        /// re-advertises whatever the windows are now, which is at least what
        /// was lost.
        pub fn reoweFlowControl(self: *Self) void {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| stream.max_data_sent = 0;
        }

        /// Whether a blocked report is owed, on the connection or any stream.
        pub fn owesBlocked(self: *const Self) bool {
            if (self.send_blocked) return true;
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                if (stream.send_blocked) return true;
            }
            return false;
        }

        /// Re-owe the reports, for the same reason `reoweFlowControl` exists:
        /// a lost STREAM_DATA_BLOCKED leaves both endpoints waiting.
        pub fn reoweBlocked(self: *Self) void {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                // Section 3.3 forbids a STREAM_DATA_BLOCKED once the stream has
                // been abandoned, and this loop read no send state at all — so
                // a lost flow-control packet re-armed the flag on a stream in
                // "Reset Sent" and the writer framed the frame that MUST NOT be
                // sent.
                switch (stream.send_state) {
                    .sending, .data_sent => {},
                    .reset, .reset_recvd, .data_recvd => continue,
                }
                // And only a stream with something waiting is blocked. The flag
                // means "this endpoint has octets to write and the peer's limit
                // is what stops it"; the condition below on its own is true of
                // every stream that has written up to its limit, including a
                // brand-new one where both numbers are zero.
                if (stream.framed == stream.send_len and !stream.send_fin) continue;
                if (stream.send_offset + stream.send_len >= stream.send_limit) stream.send_blocked = true;
            }
            if (self.sent_total >= self.send_limit) self.send_blocked = true;
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

        /// Open a stream, and every lower-numbered stream of its kind.
        ///
        /// An identifier is used once. A stream leaves the table only by
        /// retiring, which records it in `retired` and makes the identifier
        /// unusable rather than free — so there is no path that hands the same
        /// identifier to a second stream, which is what section 2.1 asks for.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        //# A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        //
        // Only the named stream used to be created, so a peer that opened index
        // 3 without having opened 0, 1 and 2 got one stream here and four at the
        // far end. The two endpoints then disagreed about which streams exist,
        // and about how much of the limit had been spent.
        //
        // It became a live defect once streams could retire. The retirement
        // watermark is contiguous — `retireOne` looks up the identifier at the
        // watermark and stops if it is missing — so an identifier that was
        // never created blocked it for ever, and the connection stopped issuing
        // MAX_STREAMS for the rest of its life. Creating the lower-numbered
        // streams is what makes a hole in that watermark impossible.
        //
        // The cost is that a peer holding index 7 open holds eight slots, and
        // that is right rather than unfortunate: section 3.2 says it has opened
        // eight streams, so it has spent eight of the identifiers this endpoint
        // advertised. A consumer sizing `streams_max` has to fit what it
        // advertises to the peer, plus what it opens itself; see
        // `setAdvertisedStreamLimits`.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
        //# Before a stream is created, all streams of the same type with lower-
        //# numbered stream IDs MUST be created.  This ensures that the creation
        //# order for streams is consistent on both endpoints.
        //= type=test
        pub fn open(self: *Self, id: u64) Error!*Stream {
            assert(id <= varint.max);
            if (self.find(id)) |stream| return stream;
            // A retired identifier is never handed out a second time. Section
            // 2.1's rule is about reuse for a *new* stream, and this is the
            // guard that keeps the slot reclamation below from being exactly
            // that: without it a retransmitted STREAM frame arriving after the
            // stream was given up would create a second stream with the same
            // identifier, at offset zero, with the peer's credit already spent.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
            //# A QUIC endpoint MUST NOT reuse a stream ID within a connection.
            //= type=test
            if (self.isRetired(id)) return error.Retired;
            // Here rather than at `receive` alone, which is where it used to
            // be. Section 3.2's implicit creation turned an identifier into a
            // request to allocate `index + 1` slots, and three frames reach
            // this function without passing through `receive`: RESET_STREAM,
            // STOP_SENDING and MAX_STREAM_DATA. One MAX_STREAM_DATA naming a
            // high index would fill the table — this endpoint's exhaustion,
            // reported to the next honest request as *its* STREAM_LIMIT_ERROR.
            try self.checkAdvertisedStreamLimit(id);

            const kind = stream_id.kindOf(id);
            const position = stream_id.index(id);
            // From the watermark rather than from zero: everything below it has
            // been created already and then given up.
            var lower = self.retired[@intFromEnum(kind)];
            // Bounded by the advertised limit, which `checkAdvertisedStreamLimit`
            // has already applied to `id` — and by `streams_max` in any case,
            // because `create` refuses past it.
            while (lower < position) : (lower += 1) {
                const earlier = stream_id.make(kind, lower);
                if (self.find(earlier) != null) continue;
                _ = try self.create(earlier);
            }
            return try self.create(id);
        }

        /// One stream, in the next free slot.
        ///
        /// `create` appends, so a pointer handed out earlier stays valid across
        /// it. `sweep` is the one that moves streams, and nothing may hold a
        /// `*Stream` across that.
        fn create(self: *Self, id: u64) Error!*Stream {
            if (self.count == streams_max) return error.TooManyStreams;
            self.streams[self.count] = .{ .id = id, .send_limit = self.initialSendLimit(id) };
            self.count += 1;
            return &self.streams[self.count - 1];
        }

        /// Section 3.3: abandon this endpoint's half of a stream.
        ///
        /// Idempotent, and deliberately so. Section 13.3 fixes the frame's
        /// content once it exists, so a second call with a different code would
        /// be a different RESET_STREAM for a stream the peer may already have
        /// seen one for.
        ///
        /// The Final Size is everything the application handed over, including
        /// octets still sitting in the buffer that will now never be sent. That
        /// is the number the peer needs: `write` charged them against both flow
        /// control windows when it took them, and section 4.5 makes the final
        /// size what the *receiver* counts, so anything smaller leaves the two
        /// endpoints disagreeing about how much credit this stream spent.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        //# A receiver SHOULD treat receipt of data at or beyond the final size as
        //# an error of type FINAL_SIZE_ERROR, even after a stream is closed.
        //= type=exception
        //= reason=this is the receive half, and `Reassembler.push` is what enforces it; the sentence is quoted here because it is the reason the final size below is what the application wrote rather than what went out
        pub fn resetSend(self: *Self, id: u64, code: u64) Error!void {
            if (!self.weMaySend(id)) return error.StreamState;
            const stream = self.open(id) catch |err| switch (err) {
                error.Retired => return, // Finished; there is nothing to abandon.
                else => return err,
            };
            switch (stream.send_state) {
                .reset, .reset_recvd, .data_recvd => return,
                .sending, .data_sent => {},
            }
            stream.send_state = .reset;
            stream.reset_code = code;
            stream.reset_final_size = stream.send_offset + stream.send_len;
            stream.reset_framed = false;
            // Section 3.3 forbids a STREAM_DATA_BLOCKED here as much as a
            // STREAM frame, and clearing the flag is what enforces it: `write`
            // refuses an abandoned stream, so nothing can set it again. A
            // report that the peer's limit is holding us up is also just false
            // — what is holding us up is that we gave up.
            stream.send_blocked = false;
        }

        /// Section 3.5: ask the peer to stop sending on a stream.
        ///
        /// The mirror of `resetSend`, and the other half of cancelling a
        /// bidirectional stream: that one abandons what this endpoint sends,
        /// this one asks the peer to stop sending to us. Neither implies the
        /// other, and a consumer cancelling a request wants both.
        ///
        /// Nothing is sent for a stream the peer has already reset — there is
        /// nothing left to stop — or for one whose data has all arrived.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
        //# An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that
        //# incoming data is being discarded on receipt per application request.
        //# STOP_SENDING requests that a peer cease transmission on a stream.
        //= type=test
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
        //# STOP_SENDING SHOULD only be sent for a stream that has not been reset
        //# by the peer.  STOP_SENDING is most useful for streams in the "Recv"
        //# or "Size Known" state.
        //= type=test
        pub fn stopSending(self: *Self, id: u64, code: u64) Error!void {
            // Section 19.5 makes a STOP_SENDING for a send-only stream a
            // connection error at the peer, so it is one this endpoint must not
            // send rather than one it merely need not.
            if (!self.weMayReceive(id)) return error.StreamState;
            const stream = self.open(id) catch |err| switch (err) {
                error.Retired => return, // Finished; there is nothing to stop.
                else => return err,
            };
            switch (stream.receive_state) {
                .receiving, .size_known => {},
                .reset, .data_read => return,
            }
            if (stream.stop_code != null) return; // Owed once.
            stream.stop_code = code;
            stream.stop_framed = false;
        }

        /// Whether a STOP_SENDING is owed on any stream.
        pub fn owesStopSending(self: *const Self) bool {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                if (stream.stop_code != null and !stream.stop_framed) return true;
            }
            return false;
        }

        /// The next stream owing one, for the writer.
        pub fn nextStopSending(self: *Self) ?*Stream {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                if (stream.stop_code != null and !stream.stop_framed) return stream;
            }
            return null;
        }

        /// Owe it again, because the packet carrying it was lost.
        ///
        /// Section 13.3 keeps it going until the peer answers rather than until
        /// this endpoint's packet is acknowledged, and the two differ: an
        /// acknowledged STOP_SENDING the peer has not acted on is still a
        /// request in flight. What ends it is `clearStopSending`.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        //# Similarly, a request to cancel stream transmission, as encoded in a
        //# STOP_SENDING frame, is sent until the receiving part of the stream
        //# enters either a "Data Recvd" or "Reset Recvd" state; see Section 3.5.
        //= type=test
        pub fn reoweStopSending(self: *Self, id: u64) void {
            const stream = self.find(id) orelse return;
            if (stream.stop_code == null) return;
            stream.stop_framed = false;
        }

        /// The request is over: the peer reset the stream, or all of its data
        /// arrived and was read.
        fn clearStopSending(stream: *Stream) void {
            stream.stop_code = null;
            stream.stop_framed = true;
        }

        /// Whether a RESET_STREAM is owed on any stream.
        pub fn owesReset(self: *const Self) bool {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                if (stream.send_state == .reset and !stream.reset_framed) return true;
            }
            return false;
        }

        /// The next stream owing one, for the writer.
        pub fn nextReset(self: *Self) ?*Stream {
            // Bounded by `count`.
            for (self.streams[0..self.count]) |*stream| {
                if (stream.send_state == .reset and !stream.reset_framed) return stream;
            }
            return null;
        }

        /// Owe it again, because the packet carrying it was lost.
        ///
        /// Section 13.3 lists RESET_STREAM among the frames that are sent until
        /// acknowledged, and it carries no byte range — so like a FIN it needs
        /// its own re-owing rather than a rewound watermark.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        //# Cancellation of stream transmission, as carried in a RESET_STREAM
        //# frame, is sent until acknowledged or until all stream data is
        //# acknowledged by the peer (that is, either the "Reset Recvd" or
        //# "Data Recvd" state is reached on the sending part of the stream).
        //= type=test
        pub fn reoweReset(self: *Self, id: u64) void {
            const stream = self.find(id) orelse return;
            if (stream.send_state != .reset) return;
            stream.reset_framed = false;
        }

        /// The peer has the RESET_STREAM, so section 3.1's terminal state.
        pub fn resetDelivered(self: *Self, id: u64) void {
            const stream = self.find(id) orelse return;
            if (stream.send_state != .reset) return;
            stream.send_state = .reset_recvd;
        }

        /// Whether an identifier names a stream that has been given up.
        pub fn isRetired(self: *const Self, id: u64) bool {
            const kind = stream_id.kindOf(id);
            return stream_id.index(id) < self.retired[@intFromEnum(kind)];
        }

        /// The stream credit this endpoint puts in its transport parameters.
        ///
        /// Held here as well as on the wire because it is the base a
        /// MAX_STREAMS is measured from, and because the limit that has to be
        /// enforced is the one that was advertised rather than the table's size.
        /// The two differ whenever a consumer offers the peer less than the
        /// table can hold, which it must do when one table is shared between
        /// four kinds of stream.
        ///
        /// **`streams_max` has to fit `bidi + uni` plus whatever this endpoint
        /// opens itself.** Section 3.2 makes an identifier at index N mean N+1
        /// streams of that kind, so a peer inside its limit can hold every
        /// identifier that limit names, all at once. A table too small for what
        /// was advertised answers a conforming peer with STREAM_LIMIT_ERROR,
        /// which is this endpoint's sizing mistake reported as the peer's
        /// protocol error.
        pub fn setAdvertisedStreamLimits(self: *Self, bidi: u64, uni: u64) void {
            assert(bidi <= streams_max);
            assert(uni <= streams_max);
            // The checkable half of the paragraph above. The two limits were
            // asserted separately, so `bidi = uni = streams_max` passed — and
            // that is exactly the sizing mistake the paragraph describes. What
            // cannot be asserted here is the streams this endpoint opens
            // itself, because the peer has not said yet how many it may.
            assert(bidi + uni <= streams_max);
            assert(self.count == 0);
            self.advertised_bidi = bidi;
            self.advertised_uni = uni;
            self.max_streams_bidi_sent = bidi;
            self.max_streams_uni_sent = uni;
        }

        /// Whether a MAX_STREAMS is owed on either kind.
        ///
        /// Any credit at all, rather than a fraction of the window: this
        /// endpoint sends no STREAMS_BLOCKED, so a peer that runs out has no way
        /// to ask. A threshold would then be a deadlock whenever the credit
        /// owed stopped one short of it — which is the ordinary end of a run,
        /// not a corner.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint MUST NOT wait to receive this signal before advertising
        //# additional credit, since doing so will mean that the peer will be
        //# blocked for at least an entire round trip, and potentially
        //# indefinitely if the peer chooses not to send STREAMS_BLOCKED frames.
        //= type=test
        pub fn owesStreamCredit(self: *const Self) bool {
            if (self.advertised_bidi > self.max_streams_bidi_sent) return true;
            if (self.advertised_uni > self.max_streams_uni_sent) return true;
            return false;
        }

        /// Owe both limits again, for the reason `reoweFlowControl` exists: a
        /// MAX_STREAMS is an ordinary frame and an ordinary frame can be lost.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        //# The limit on streams of a given type is sent in MAX_STREAMS
        //# frames.  Like MAX_DATA, an updated value is sent when a packet
        //# containing the most recent MAX_STREAMS for a stream type frame is
        //# declared lost or when the limit is updated, with care taken to
        //# prevent the frame from being sent too often.
        //= type=test
        pub fn reoweStreamCredit(self: *Self) void {
            self.max_streams_bidi_sent = 0;
            self.max_streams_uni_sent = 0;
        }

        /// The credit to put in the next MAX_STREAMS of this kind, and the note
        /// that it has gone out.
        pub fn takeStreamCredit(self: *Self, bidirectional: bool) ?u64 {
            const limit = if (bidirectional) self.advertised_bidi else self.advertised_uni;
            const sent = if (bidirectional) &self.max_streams_bidi_sent else &self.max_streams_uni_sent;
            if (limit <= sent.*) return null;
            sent.* = limit;
            return limit;
        }

        /// Whether a stream has nothing left to do in either direction it has.
        ///
        /// A unidirectional stream is asked about one half only: the other does
        /// not exist, and its state field sits at the value it was initialised
        /// with for the life of the stream.
        ///
        /// An abandoned half counts as finished. It has to: the watermark is
        /// contiguous, so a stream that could never retire would freeze the
        /// credit for its whole kind — one RESET_STREAM from the peer, which
        /// is an ordinary thing for it to send, and the connection stops
        /// granting stream identifiers for the rest of its life. Section 3.1
        /// and section 3.2 both make the reset states terminal, which is the
        /// same claim this needs.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
        //# Once the application receives the signal indicating that the
        //# stream was reset, the receiving part of the stream transitions
        //# to the "Reset Read" state, which is a terminal state.
        //= type=test
        fn finished(self: *const Self, stream: *const Stream) bool {
            assert(stream.id <= varint.max);
            if (stream_id.sendable(stream.id, self.side)) {
                switch (stream.send_state) {
                    // "Data Recvd" is not enough on its own, because this
                    // package enters it early: `Connection` sets it when the
                    // packet carrying the *FIN* is acknowledged, not when every
                    // packet is. Under reordering the FIN's packet can be
                    // acknowledged first, and retiring on that alone drops a
                    // stream with octets still on the wire — `rewind` then finds
                    // nothing, the peer holds everything after the hole, and
                    // this endpoint reports the stream delivered. Silent data
                    // loss, on the one path that reports success.
                    .data_recvd => {
                        if (stream.acked_to < stream.send_offset + stream.send_len) return false;
                    },
                    .reset_recvd => {},
                    // "Reset Sent" is not terminal: the RESET_STREAM is still
                    // owed or in flight, and retiring the stream would drop the
                    // frame the peer is waiting for.
                    .sending, .data_sent, .reset => return false,
                }
            }
            if (stream_id.receivable(stream.id, self.side)) {
                switch (stream.receive_state) {
                    .data_read, .reset => {},
                    .receiving, .size_known => return false,
                }
            }
            return true;
        }

        /// Give up every finished stream whose predecessors are also finished,
        /// and hand the credit back to the peer.
        ///
        /// Called where a stream can reach a terminal state: after the
        /// application consumes, and after `Connection` reports what a packet
        /// acknowledged. It moves streams within the table, so nothing may hold
        /// a `*Stream` across it.
        pub fn sweep(self: *Self) void {
            for (0..stream_id.kind_count) |raw| {
                const kind: stream_id.Kind = @enumFromInt(raw);
                // Bounded: each pass gives up one stream, and the table holds
                // `streams_max`.
                for (0..streams_max) |_| {
                    if (!self.retireOne(kind)) break;
                }
            }
        }

        fn retireOne(self: *Self, kind: stream_id.Kind) bool {
            const next = self.retired[@intFromEnum(kind)];
            if (next >= stream_id.count_max) return false;
            const id = stream_id.make(kind, next);
            const stream = self.find(id) orelse return false;
            if (!self.finished(stream)) return false;

            const offset = @intFromPtr(stream) - @intFromPtr(&self.streams[0]);
            assert(offset % @sizeOf(Stream) == 0);
            const at = @divExact(offset, @sizeOf(Stream));
            assert(at < self.count);
            // Not when the victim *is* the last slot: a struct assignment of
            // this size lowers to a `memcpy`, and a `memcpy` whose source and
            // destination are the same object is undefined.
            if (at != self.count - 1) self.streams[at] = self.streams[self.count - 1];
            self.count -= 1;
            self.retired[@intFromEnum(kind)] = next + 1;

            // Only the peer's own kinds earn it credit. A slot freed by a
            // stream this endpoint opened is room in the table and nothing the
            // peer is waiting for.
            if (kind.initiator() != self.side) {
                const limit = if (kind.bidirectional()) &self.advertised_bidi else &self.advertised_uni;
                assert(limit.* < stream_id.count_max);
                limit.* += 1;
            }
            return true;
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
        // And the mirror of it, which `checkAdvertisedStreamLimit` is.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint that receives a frame with a stream ID exceeding the limit
        //# it has sent MUST treat this as a connection error of type
        //# STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
        //= type=test
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

        /// Whether the peer's section 4.6 limit admits this identifier yet.
        ///
        /// For a caller that opens streams as earlier ones finish: writing to a
        /// stream the peer has not permitted is a connection error at the peer,
        /// so the question has to be askable before the write rather than only
        /// answerable after it.
        pub fn peerPermits(self: *const Self, id: u64) bool {
            self.checkPeerStreamLimit(id) catch return false;
            return true;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        //# An endpoint
        //# that receives a frame with a stream ID exceeding the limit it has
        //# sent MUST treat this as a connection error of type
        //# STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
        ///
        /// The rule is about the stream *identifier* rather than about how many
        /// streams happen to be open, and the two are now the same question:
        /// section 3.2's lower-numbered streams are created, so an identifier
        /// at index N means N+1 streams of that kind exist. A peer sending on
        /// index 10 000 while sixty-four were advertised used to get a stream,
        /// because it was only the first one.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
        //# An endpoint MUST terminate a connection with an error of type
        //# STREAM_LIMIT_ERROR if a peer opens more streams than was permitted.
        fn checkAdvertisedStreamLimit(self: *const Self, id: u64) Error!void {
            assert(id <= varint.max);
            const kind = stream_id.kindOf(id);
            if (kind.initiator() == self.side) return;
            const limit = if (kind.bidirectional()) self.advertised_bidi else self.advertised_uni;
            if (stream_id.index(id) >= limit) return error.TooManyStreams;
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

            // Section 3.2 has a receiver discard a frame for a stream it has
            // already finished with, and once the slot is reclaimed that is
            // every frame naming a retired identifier — a retransmission of one
            // that arrived while the stream was alive. `open` is the single
            // place that knows a retired identifier from a new one; each caller
            // decides what to do about it, and for a frame from the peer the
            // answer is nothing.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
            //# After all data has been received, any STREAM or
            //# STREAM_DATA_BLOCKED frames for the stream can be discarded.
            //= type=test
            const stream = self.open(id) catch |err| switch (err) {
                error.Retired => return,
                else => return err,
            };
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
            // `stream` is not touched again: `sweep` moves streams within the
            // table, so the pointer above is stale from here on.
            self.sweep();
        }

        /// Move a stream to `data_read` once everything has arrived and been
        /// taken. Separate from `consume` because a zero-length FIN completes a
        /// stream without anything being read.
        fn settle(self: *Self, stream: *Stream) void {
            _ = self;
            if (stream.receive_state != .size_known) return;
            if (stream.received.isComplete() and stream.readable().len == 0) {
                stream.receive_state = .data_read;
                // And the other of the two: everything arrived, so a request to
                // stop would be asking for something that already happened.
                clearStopSending(stream);
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
            const stream = self.open(id) catch |err| switch (err) {
                error.Retired => return, // Section 3.2: discard, as in `receive`.
                else => return err,
            };
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
            // Section 13.3: "Reset Recvd" is one of the two states that end a
            // STOP_SENDING. The peer answered; there is nothing left to ask.
            clearStopSending(stream);

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

            // Refused by a *limit* rather than by the buffer is the case
            // section 4.1 asks to be reported: the peer decides when it ends,
            // and until it hears about it, it may not know it has to.
            if (take < data.len) {
                const stream_room = sendRoom(stream.send_limit, stream.send_offset + stream.send_len);
                if (stream_room == take) stream.send_blocked = true;
                if (connection_room == take) self.send_blocked = true;
            }

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
            const stream = self.open(id) catch |err| switch (err) {
                error.Retired => return, // A limit raised on a finished stream raises nothing.
                else => return err,
            };
            // Limits only ever rise; a peer lowering one is ignored rather than
            // an error, which is what section 4.1 says to do.
            const raised = @max(stream.send_limit, limit);
            if (raised > stream.send_limit) stream.send_blocked = false;
            stream.send_limit = raised;
        }

        pub fn setConnectionSendLimit(self: *Self, limit: u64) void {
            const raised = @max(self.send_limit, limit);
            if (raised > self.send_limit) self.send_blocked = false;
            self.send_limit = raised;
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
                switch (stream.send_state) {
                    .sending, .data_sent => {},
                    .reset, .reset_recvd => continue,
                    // Not skipped, for the reason `Connection.writeStream`
                    // gives at length and this used to contradict: "Data Recvd"
                    // is entered when the FIN's packet is acknowledged rather
                    // than when every packet is, so a later loss rewinds the
                    // watermark on a stream in that state — and an accessor
                    // that answered false while the writer would have framed is
                    // a stream that stalls with nothing armed to wake it.
                    .data_recvd => {},
                }
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

        /// Note that the peer has this stream's octets up to `end`.
        ///
        /// The highest offset acknowledged, not a contiguous watermark: an
        /// acknowledgement can arrive for a later range before an earlier one,
        /// and a rule that insisted on contiguity would stop advancing the
        /// first time that happened and never start again.
        pub fn acknowledge(self: *Self, id: u64, end: u64) void {
            const stream = self.find(id) orelse return;
            stream.acked_to = @max(stream.acked_to, end);
        }

        /// Release the front of a stream's send buffer.
        ///
        /// `oldest` is the starting offset of the oldest packet still
        /// outstanding for this stream, or null when nothing is in flight. An
        /// octet below it is in no unacknowledged packet, so nothing can ask
        /// for it again — and it is capped by `acked_to` because a stream with
        /// nothing in flight has still only been acknowledged as far as it has.
        pub fn release(self: *Self, id: u64, oldest: ?u64) void {
            const stream = self.find(id) orelse return;
            const acknowledged = if (oldest) |one| @min(one, stream.acked_to) else stream.acked_to;
            // And never past what has been framed. A loss rewinds `framed` to
            // the start of the lost range, so those octets are back in the
            // buffer waiting to go again — and they can sit *below* the highest
            // offset the peer has acknowledged, because acknowledgements do not
            // arrive in order. Releasing them would drop data the peer never
            // received: the stream then carries a hole, the receiver holds
            // everything after it, and the symptom is a flow control error at
            // the far end rather than anything that names the cause.
            const bound = @min(acknowledged, stream.send_offset + stream.framed);
            if (bound <= stream.send_offset) return;

            const octets = bound - stream.send_offset;
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
            // spurious loss did to the watermark: RFC 9002's loss detection is
            // a heuristic, so a packet declared lost — which rewinds `framed`
            // behind it — can be acknowledged afterwards because it was only
            // late.
            stream.framed = if (stream.framed > width) stream.framed - width else 0;
            stream.send_offset = bound;
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
