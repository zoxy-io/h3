//! A QUIC connection: the state machine over `Reassembler` and `AckRanges`.
//!
//! Datagrams in, datagrams out, and handshake bytes crossing in both directions
//! as plain data. Nothing here opens a socket, reads a clock or runs a TLS
//! handshake — `now_ns` is an argument, the caller owns the buffers, and the five
//! entry points docs/DESIGN.md section 4 committed to are the whole of the TLS
//! seam:
//!
//!     installSecret(level, direction, secret, suite)
//!     cryptoIn(level, bytes)     handshake bytes to send
//!     cryptoOut(level)           handshake bytes received, in order
//!     cryptoConsumed(level, n)
//!     transportParametersIn / Out, as the extension's octets
//!
//! No function pointers, no vtable, no callback into the consumer's runtime.
//! zoxy wires those to ztls and zrk to zssl, and neither has to know the other
//! exists.
//!
//! ## Sized at compile time, and bigger than it looks
//!
//! `Connection(config)` produces a type whose every buffer is a fixed array, so
//! a connection's footprint is a closed-form function of constants the consumer
//! picked. A peer's transport parameter is checked *against* these limits and
//! never used as one — see docs/TIGER_STYLE.md, "a limit that is not comptime
//! is a bug".
//!
//! **A connection is not a stack value.** `footprint_octets` is what one costs,
//! and at the defaults it is megabytes: the stream buffers dominate, and there
//! are `streams_max` of them. Put connections in an arena sized at startup —
//! which is what zoxy does anyway, and what the closed-form size is *for* — and
//! not in a local. This is stated because it was learned: the first version of
//! this file had tests that built two connections as locals at the default
//! configuration, which is 5 MB apiece. Linux's 8 MB stack absorbed it and
//! every other platform in CI crashed.
//!
//! ## What this slice does and does not carry
//!
//! Carried: the three packet number spaces, the four encryption levels and
//! their keys, CRYPTO reassembly per level, ACK generation, section 12.4's
//! frame permissions, section 8.1's amplification limit, section 14.1's
//! Initial padding, section 4.9's key discarding, and the close sequence.
//!
//! Not carried, and each is somebody else's slice rather than an oversight:
//!
//! * **Migration, stateless reset and 0-RTT.** A connection here has one path.

const std = @import("std");

const assert = @import("../assert.zig").assert;
const crypto = @import("crypto.zig");
const error_code = @import("error_code.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const packet_number = @import("packet_number.zig");
const stream_id = @import("stream_id.zig");
const transport_parameters = @import("transport_parameters.zig");
const varint = @import("../varint.zig");

const AckRanges = @import("AckRanges.zig").AckRanges;
const ConnectionId = @import("ConnectionId.zig");
const Reassembler = @import("Reassembler.zig").Reassembler;
const StreamsOf = @import("Streams.zig").Streams;
const RecoveryOf = @import("Recovery.zig").Recovery;

const Level = crypto.Level;
const Side = crypto.Side;
const Space = packet_number.Space;

/// RFC 9000 section 14.1: a datagram carrying a client Initial is padded to at
/// least this, so a server knows the path carries enough for a handshake before
/// it commits state to it.
pub const initial_datagram_min: u32 = 1200;

/// Lost packets reported out of one acknowledgement or timeout. A bound rather
/// than a promise: `Recovery` answers the true count, so a caller can tell it
/// did not see everything — and this package's response to a loss is to rewind
/// a cursor, which the *earliest* lost packet decides. Seeing the rest changes
/// nothing.
const lost_report_max: u32 = 32;

comptime {
    // A report array smaller than what one ACK can retire means the caller sees
    // a prefix, which is what the comment above promises. Stated as a relation
    // so that raising `sent_max` without raising this stays a deliberate act
    // rather than a silent narrowing.
    assert(lost_report_max >= 1);
    assert(lost_report_max <= connection_config_sent_max_ceiling);
}

/// The largest payload a UDP datagram can carry: 65535 minus the eight-octet
/// UDP header. A `datagram_octets` above this names a datagram no socket can
/// send, so the bound is the transport's rather than this package's.
const udp_payload_octets_max: u32 = 65_535 - 8;

/// The largest `sent_max` this file's fixed arrays are written for. Not a limit
/// on `Config` — `Recovery` owns that — but the number `lost_report_max` is
/// checked against, so that the two cannot drift apart unnoticed.
const connection_config_sent_max_ceiling: u32 = 1024;

/// RFC 9000 section 18.2's default `ack_delay_exponent`, used until the peer's
/// transport parameters are decoded.
const ack_delay_exponent_default: u6 = 3;

/// The suite Initial and Handshake packets are always protected with (RFC 9001
/// section 5.2), named so `countSealed` does not have to guess at a level whose
/// suite was never negotiated.
const secrets_suite_initial: crypto.Suite = crypto.secrets.initial_suite;

/// The largest acknowledgement delay this endpoint will believe.
///
/// An ACK frame's Delay field is a variable-length integer, so a peer may send
/// any value up to 2^62-1, and RFC 9000 section 19.3 puts no ceiling on it.
/// Scaling one — `delay << exponent`, then microseconds to nanoseconds —
/// overflows `u64` well before that, which is a panic in the safe builds and a
/// wraparound in the `-Dassertions=false` one. Section 18.2 caps
/// `max_ack_delay` at 2^14 milliseconds, so anything past that is a delay the
/// protocol cannot mean.
///
/// Saturated rather than refused. Section 13.2.5 makes an inflated delay the
/// peer's own loss — `Recovery.updateRtt` clamps it again against
/// `max_ack_delay`, and a larger delay only shrinks the peer's own RTT credit —
/// so closing the connection over it would let a peer kill a connection by
/// lying about a field that costs us nothing.
const ack_delay_ns_max: u64 = (1 << 14) * std.time.ns_per_ms;

/// The same ceiling expressed in the units the wire carries, so the clamp
/// happens before the shift rather than after it.
const ack_delay_units_max: u64 = (ack_delay_ns_max / std.time.ns_per_us) >> ack_delay_exponent_default;

comptime {
    // The clamp is what makes the arithmetic below total: at the ceiling it
    // reproduces the ceiling exactly, and it cannot exceed it.
    assert((ack_delay_units_max << ack_delay_exponent_default) * std.time.ns_per_us == ack_delay_ns_max);
    assert(ack_delay_ns_max < std.math.maxInt(u64));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
//# Prior to validating the client address, servers MUST NOT send more
//# than three times as many bytes as the number of bytes they have
//# received.
//
/// RFC 9000 section 8.1: before a peer's address is validated, a server may
/// send no more than this multiple of what it has received. Without it a server
/// is a reflector for anyone who can spoof a source address.
pub const amplification_factor: u32 = 3;

pub const Config = struct {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.5
    //# Implementations MUST support buffering at least 4096 bytes of data
    //# received in out-of-order CRYPTO frames.
    //= type=todo
    //
    /// Handshake octets buffered per encryption level, each way. A TLS
    /// handshake with a certificate chain is a few kilobytes; this bounds what
    /// a peer can make us hold before the handshake completes, which is RFC
    /// 9001 section 4.4's `CRYPTO_BUFFER_EXCEEDED`.
    crypto_octets: u32 = 8 * 1024,
    /// Ack ranges tracked per packet number space.
    ack_ranges_max: u32 = 32,
    /// The largest datagram this endpoint will send. Not what it will
    /// *receive*: that is the caller's buffer, and section 14 requires
    /// accepting 1200 at minimum.
    datagram_octets: u32 = 1452,
    /// Transport parameter octets held from the peer, as the extension's own
    /// encoding.
    transport_parameters_octets: u32 = 1024,
    /// Unacknowledged packets tracked per space, for RFC 9002.
    sent_max: u32 = 128,
    /// Concurrent streams, and the two flow control windows of section 4.1.
    ///
    /// These four dominate `footprint_octets`, and the defaults are not small:
    /// 64 streams at a 64 KiB receive window and a 16 KiB send buffer is
    /// **5.1 MiB per connection**. That is not overhead, it is what a QUIC
    /// endpoint offering those windows costs — but it is worth knowing before
    /// multiplying it by a connection count, and it is why a connection belongs
    /// in an arena rather than on a stack.
    streams_max: u32 = 64,
    stream_receive_octets: u32 = 64 * 1024,
    stream_send_octets: u32 = 16 * 1024,
    connection_receive_octets: u64 = 1 << 20,
};

/// Where the connection is, in the terms section 10 uses.
pub const State = enum {
    /// The handshake has not completed.
    handshaking,
    /// The handshake completed; 1-RTT keys are in use both ways.
    established,
    /// A CONNECTION_CLOSE has been sent or is pending (section 10.2.1).
    closing,
    /// A CONNECTION_CLOSE arrived; nothing further will be sent (section 10.2.2).
    draining,
};

pub fn Connection(comptime config: Config) type {
    comptime {
        assert(config.crypto_octets >= 1);
        assert(config.ack_ranges_max >= 1);
        // A datagram smaller than section 14.1's floor could not carry a client
        // Initial, so the connection could never start.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14
        //# QUIC MUST NOT be used if the network path cannot support a
        //# maximum datagram size of at least 1200 bytes.
        assert(config.datagram_octets >= initial_datagram_min);
        assert(config.datagram_octets <= udp_payload_octets_max);
    }

    const CryptoLevel = struct {
        /// Handshake bytes from the peer, reassembled in order.
        received: Reassembler(.{ .capacity = config.crypto_octets, .spans_max = 8 }) = .{},
        /// Handshake bytes to send. They stay after being framed because the
        /// data a retransmission needs is this buffer; see the module comment
        /// on what is missing beside it.
        pending: [config.crypto_octets]u8 = @splat(0),
        pending_len: u32 = 0,
        /// How much of `pending` has been put in a packet at least once.
        framed: u32 = 0,
    };

    const PacketSpace = struct {
        received: AckRanges(.{ .ranges_max = config.ack_ranges_max }) = .{},
        /// The next number this endpoint will use when it sends.
        next: u64 = 0,
        /// The largest this endpoint has had acknowledged, which is what
        /// section 17.1 sizes a packet number encoding against.
        largest_acked: ?u64 = null,
        /// Discarded per section 4.9 once a later level's keys are in use.
        discarded: bool = false,
        /// Probe packets RFC 9002 section 6.2.4 asked for and that have not
        /// gone out yet.
        probes_pending: u8 = 0,
    };

    // The width a long header's Length field is reserved at: wide enough for
    // any length this connection can produce, and fixed, so the header's own
    // size does not change when the real length is written back into it.
    // Derived rather than chosen — a bigger datagram needs a wider field, and
    // nothing here has to be touched for it.
    const length_field_octets: u8 = varint.encodedLength(config.datagram_octets);

    // What a sent packet carried, so that losing it can be undone. RFC 9002
    // tracks a packet's number, size and send time and deliberately never
    // learns what was *in* it; this is the token `Recovery.Context` hands back
    // on loss, and it is the whole of what this slice needs to rebuild one —
    // the CRYPTO range, re-framed by rewinding the level's send cursor to where
    // the lost packet started.
    const PacketContext = struct {
        level: Level,
        crypto_start: u32 = 0,
        crypto_end: u32 = 0,
        /// The stream range this packet carried, if any. Same arrangement as
        /// the CRYPTO one: losing it rewinds the stream's send cursor.
        stream: u64 = 0,
        stream_start: u32 = 0,
        stream_end: u32 = 0,
        /// Whether the packet carried a FIN, which no byte range can express.
        stream_fin: bool = false,
        /// Whether the packet carried HANDSHAKE_DONE, which likewise has no
        /// range: losing it has to re-owe the frame or the client never
        /// confirms.
        handshake_done: bool = false,
    };

    // RFC 9001 section 6: 1-RTT keys come in generations, and the Key Phase
    // bit of a short header says which one protected a packet. Nothing below
    // 1-RTT updates — those levels are discarded long before any limit is near.
    const OneRtt = struct {
        send_secret: ?crypto.secrets.Secret = null,
        receive_secret: ?crypto.secrets.Secret = null,
        suite: crypto.Suite = .aes_128_gcm_sha256,
        /// The phase this endpoint is sending with.
        phase: bool = false,
        /// The generation before the current one, kept so packets reordered
        /// across an update still decrypt (section 6.3).
        previous_receive: ?crypto.Keys = null,
        /// The generation after, derived in advance rather than on demand.
        /// Section 6.3: deriving keys inside the receive path is a timing
        /// signal that leaks when an update happened, and therefore the
        /// value of a bit that is otherwise protected.
        next_receive: ?crypto.Keys = null,
        /// Packets sealed under the current send key, for section 6.6's
        /// confidentiality limit. Reset by an update, because the limit is
        /// per key rather than per connection.
        sealed: u64 = 0,
        /// Section 6.1: no second update until a packet sent in the current
        /// phase has been acknowledged, so that both peers are known to
        /// hold the keys before another one begins.
        phase_acknowledged: bool = true,
    };

    const ConnectionStreams = StreamsOf(.{
        .streams_max = config.streams_max,
        .receive_octets = config.stream_receive_octets,
        .send_octets = config.stream_send_octets,
        .connection_receive_octets = config.connection_receive_octets,
    });

    const Recovery = RecoveryOf(.{
        .sent_max = config.sent_max,
        .max_datagram_size = config.datagram_octets,
        .Context = PacketContext,
    });

    return struct {
        const Self = @This();

        pub const datagram_octets: u32 = config.datagram_octets;

        /// What one connection costs, in octets.
        ///
        /// Exported so a consumer can price its arena at startup — and so that
        /// a change which quietly doubles it shows up in a diff rather than in
        /// a crash on the one platform with the smallest stack.
        pub const footprint_octets: usize = @sizeOf(Self);

        side: Side,
        state: State = .handshaking,

        /// What this endpoint puts in the Destination field of what it sends.
        /// A server replaces it with the client's source identifier; a client
        /// replaces it when the server's first packet names a new one.
        destination: ConnectionId,
        /// What this endpoint told the peer to address it as.
        source: ConnectionId,
        /// The Destination the client used first, which is what the Initial
        /// keys derive from and what a Retry's integrity tag binds.
        original_destination: ConnectionId,
        /// The peer's Source Connection ID, once seen. Section 7.2 fixes it for
        /// the connection, so a second, different one is a protocol violation
        /// rather than a change of address.
        peer_source: ?ConnectionId = null,

        one_rtt: OneRtt = .{},
        /// Packets sealed per level, for section 6.6. The 1-RTT count lives in
        /// `one_rtt.sealed`, because it belongs to a generation rather than to
        /// the level.
        sealed: [Level.count]u64 = @splat(0),
        /// Section 6.6: packets that failed authentication, "within the
        /// connection, across all keys" — so one counter, not one per key.
        forgeries: u64 = 0,

        send_keys: [Level.count]?crypto.Keys = @splat(null),
        receive_keys: [Level.count]?crypto.Keys = @splat(null),
        levels: [Level.count]CryptoLevel = @splat(.{}),
        spaces: [Space.count]PacketSpace = @splat(.{}),

        /// Section 8.1's accounting. A client validates its peer by construction
        /// — it chose the address — so this only ever restrains a server.
        address_validated: bool,
        received_octets: u64 = 0,
        sent_octets: u64 = 0,

        /// The peer's transport parameters, as the extension's octets. Held
        /// rather than decoded so that a consumer's TLS engine can hand them
        /// over without this package caring when they arrive.
        peer_parameters: [config.transport_parameters_octets]u8 = @splat(0),
        peer_parameters_len: u32 = 0,

        /// RFC 9002: what decides that a packet was lost, and when to probe.
        recovery: Recovery = .{},

        /// Sections 2, 3 and 4: the streams and their flow control.
        streams: ConnectionStreams = .{},
        /// The limit last advertised, so a new one goes out only when it has
        /// moved enough to be worth a frame.
        ///
        /// There was a `max_streams_sent` beside this, written nowhere and read
        /// nowhere. This endpoint's stream limit is `streams_max`, a comptime
        /// bound that never moves, so there is no "last advertised" value to
        /// remember and no MAX_STREAMS to re-send — the field was a placeholder
        /// for a frame this package does not generate.
        max_data_sent: u64 = 0,

        //= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.2
        //# The server MUST send a HANDSHAKE_DONE frame as soon as the handshake
        //# is complete.
        //
        /// Owed once, framed once, and owed again if the packet carrying it is
        /// lost. Found missing by `sim/` on its first working sweep: the frame
        /// was handled on receipt and never generated, so a client talking to
        /// this server stayed in `handshaking` for the life of the connection
        /// — and RFC 9002 section 6.2.1 declines to arm an application-data
        /// probe timeout before confirmation, so its 1-RTT packets were never
        /// retransmitted either.
        handshake_done_pending: bool = false,
        handshake_done_framed: bool = false,

        /// Set by a CONNECTION_CLOSE in either direction.
        close_code: u64 = 0,
        close_is_application: bool = false,
        close_pending: bool = false,

        pub const Options = struct {
            side: Side,
            /// The Destination Connection ID of the client's first Initial.
            /// A client draws it at random — this package draws no randomness,
            /// so it arrives here — and a server takes it off the wire.
            original_destination: ConnectionId,
            /// What this endpoint asks the peer to address it as.
            source: ConnectionId,
        };

        pub fn init(options: Options) Self {
            var self: Self = .{
                .side = options.side,
                .destination = options.original_destination,
                .source = options.source,
                .original_destination = options.original_destination,
                // Section 8.1: a client picked the address it is talking to, so
                // there is nothing to validate and nothing to amplify.
                .address_validated = options.side == .client,
                .streams = .{ .side = options.side },
                // RFC 9002 appendix A.7's `PeerCompletedAddressValidation` is
                // the only thing in `Recovery` that differs by side.
                .recovery = .{ .side = options.side },
            };
            // Section 5.2 of RFC 9001: both sides can compute both halves from
            // the client's first Destination Connection ID.
            const bytes = options.original_destination.bytes();
            self.send_keys[@intFromEnum(Level.initial)] = .initial(bytes, options.side);
            self.receive_keys[@intFromEnum(Level.initial)] = .initial(bytes, options.side.peer());
            return self;
        }

        // ---------------------------------------------------------------- TLS

        pub const SecretError = error{
            /// A secret of the wrong length for the suite, or one installed at
            /// a level whose keys are already gone.
            Rejected,
        };

        /// Install the traffic secret a TLS engine produced for one level and
        /// direction. RFC 9001 section 4.1.
        pub fn installSecret(
            self: *Self,
            level: Level,
            direction: enum { send, receive },
            secret: *const crypto.secrets.Secret,
            suite: crypto.Suite,
        ) SecretError!void {
            if (secret.length != suite.hashOctets()) return error.Rejected;
            const keys: crypto.Keys = .fromSecret(suite, secret);
            switch (direction) {
                .send => self.send_keys[@intFromEnum(level)] = keys,
                .receive => self.receive_keys[@intFromEnum(level)] = keys,
            }
            // Section 4.9.1: Initial keys are discarded as soon as a Handshake
            // packet can be sent. Holding them longer is holding keys anyone who
            // saw the first packet can compute.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
            //# Thus, a client MUST discard Initial keys when it first sends a
            //# Handshake packet and a server MUST discard Initial keys when it first
            //# successfully processes a Handshake packet.  Endpoints MUST NOT send
            //# Initial packets after this point.
            if (level == .handshake) self.discard(.initial);

            // RFC 9001 section 4.1.2: the handshake is confirmed at the *server*
            // when the handshake completes, which is when it can send 1-RTT — a
            // client waits for HANDSHAKE_DONE instead. This matters to RFC 9002
            // rather than to anything here: section 6.2.1 declines to arm an
            // application-data PTO before it, because 1-RTT keys may not exist
            // on both sides yet, and a connection that never confirms is a
            // connection whose 1-RTT packets are never retransmitted.
            //
            // The Handshake keys are *not* dropped here, and by section 4.9.2
            // they should be: for a server, "confirmed" is this line.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.2
            //# An endpoint MUST discard its Handshake keys when the TLS handshake is
            //# confirmed (Section 4.1.2).
            //= type=todo
            if (level == .one_rtt and direction == .send and self.side == .server) {
                self.state = .established;
                self.recovery.handshake_confirmed = true;
                self.handshake_done_pending = true;
            }

            // Section 6 needs the secret, not just the keys: the next
            // generation is `HKDF-Expand-Label(secret, "quic ku", "", len)`, so
            // a connection that kept only the derived keys could never update.
            if (level == .one_rtt) {
                self.one_rtt.suite = suite;
                switch (direction) {
                    .send => self.one_rtt.send_secret = secret.*,
                    .receive => {
                        self.one_rtt.receive_secret = secret.*;
                        // Derived now rather than when a phase change arrives;
                        // see the note on `next_receive`. Through
                        // `nextGeneration`, which keeps the header protection
                        // key — section 6.1 does not update it.
                        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.3
                        //# For this reason, endpoints MUST be able to retain two sets of packet
                        //# protection keys for receiving packets: the current and the next.
                        //
                        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.3
                        //# Endpoints responding to an apparent key update MUST NOT generate a
                        //# timing side-channel signal that might indicate that the Key Phase bit
                        //# was invalid (see Section 9.5).
                        const next = crypto.secrets.update(suite, secret);
                        self.one_rtt.next_receive = keys.nextGeneration(suite, &next);
                    },
                }
            }
        }

        /// Queue handshake bytes for sending at `level`.
        pub fn cryptoIn(self: *Self, level: Level, data: []const u8) error{CryptoBufferExceeded}!void {
            assert(@intFromEnum(level) < self.levels.len);
            const stream = &self.levels[@intFromEnum(level)];
            assert(stream.pending_len <= config.crypto_octets);
            if (stream.pending_len + data.len > config.crypto_octets) {
                return error.CryptoBufferExceeded;
            }
            // That comparison is the guard on both the copy and the cast below:
            // it bounds `data.len` by a comptime constant, so neither can be
            // reached with a length the buffer cannot hold.
            assert(data.len <= config.crypto_octets);
            @memcpy(stream.pending[stream.pending_len..][0..data.len], data);
            stream.pending_len += @intCast(data.len);
            assert(stream.pending_len <= config.crypto_octets);
        }

        /// Handshake bytes received at `level`, in order. Borrows until the next
        /// `receive`.
        pub fn cryptoOut(self: *const Self, level: Level) []const u8 {
            assert(@intFromEnum(level) < self.levels.len);
            const out = self.levels[@intFromEnum(level)].received.readable();
            assert(out.len <= config.crypto_octets);
            return out;
        }

        /// Release handshake bytes a TLS engine has taken.
        pub fn cryptoConsumed(self: *Self, level: Level, octets: usize) void {
            assert(@intFromEnum(level) < self.levels.len);
            // A consumer cannot give back more than it was handed, and
            // `Reassembler.consume` would otherwise move the read cursor past
            // data that was never delivered.
            assert(octets <= self.levels[@intFromEnum(level)].received.readable().len);
            self.levels[@intFromEnum(level)].received.consume(octets);
        }

        /// The peer's transport parameters, as the extension's octets, or an
        /// empty slice before they arrive.
        pub fn transportParametersOut(self: *const Self) []const u8 {
            return self.peer_parameters[0..self.peer_parameters_len];
        }

        /// Hand over the peer's transport parameters extension.
        pub fn transportParametersIn(
            self: *Self,
            octets: []const u8,
        ) (error{TooLarge} || transport_parameters.ParseError)!void {
            if (octets.len > config.transport_parameters_octets) return error.TooLarge;
            // Parsed before it is kept, so a malformed extension is refused
            // rather than stored and handed back to a consumer as if it were a
            // peer's settings. Section 18 makes either failure a
            // `TRANSPORT_PARAMETER_ERROR`.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
            //# An endpoint MUST treat receipt of a transport parameter with an
            //# invalid value as a connection error of type
            //# TRANSPORT_PARAMETER_ERROR.
            const parsed = try transport_parameters.parse(octets);

            // Section 4.6: the peer's initial stream limits are limits on *us*,
            // and until this they were parsed by nobody. The data limits are
            // deliberately not applied here — `setConnectionSendLimit` and
            // `setSendLimit` are the consumer's seam for those and are already
            // driven by MAX_DATA and MAX_STREAM_DATA on the same path.
            self.streams.setPeerStreamLimit(true, parsed.initial_max_streams_bidi);
            self.streams.setPeerStreamLimit(false, parsed.initial_max_streams_uni);

            @memcpy(self.peer_parameters[0..octets.len], octets);
            self.peer_parameters_len = @intCast(octets.len);
            assert(self.peer_parameters_len == octets.len);
        }

        // ------------------------------------------------------------ receive

        /// RFC 9001 section 6.1: move to the next generation of 1-RTT keys.
        ///
        /// Both directions at once. The Key Phase bit is one bit shared by both
        /// peers, so an endpoint that updated only its write keys would be
        /// sending in a phase its own reader does not recognise.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.2
        //# An endpoint MUST discard its Handshake keys when the TLS handshake is
        //# confirmed (Section 4.1.2).
        ///
        /// The client reaches this on HANDSHAKE_DONE by itself. A server cannot:
        /// section 4.1.2 confirms the handshake at the server "when the
        /// handshake completes", which is when its TLS engine has processed the
        /// client's Finished — and that engine is the consumer's, by the design
        /// in docs/DESIGN.md section 4. Installing 1-RTT send keys is not the
        /// same moment: there the server has sent its own Finished and still
        /// needs Handshake keys to read the client's.
        ///
        /// So confirmation is an entry point rather than an inference. A server
        /// whose consumer never calls it keeps its Handshake keys and its
        /// Handshake packet number space alive for the life of the connection,
        /// which is what this package did before there was anything to call.
        ///
        /// Idempotent: a consumer that calls it twice, or a client that has
        /// already discarded, must not discard a space twice.
        pub fn confirmHandshake(self: *Self) void {
            self.state = .established;
            self.recovery.handshake_confirmed = true;
            if (self.spaces[@intFromEnum(Space.handshake)].discarded) return;
            self.discard(.handshake);
            assert(self.spaces[@intFromEnum(Space.handshake)].discarded);
        }

        pub fn updateKeys(self: *Self) void {
            const one = &self.one_rtt;
            const send_secret = one.send_secret orelse return;
            const receive_secret = one.receive_secret orelse return;

            const next_send = crypto.secrets.update(one.suite, &send_secret);
            const next_receive = crypto.secrets.update(one.suite, &receive_secret);

            // The outgoing generation is kept for reading, not for writing:
            // section 6.3 expects reordered packets from the old phase for up
            // to a PTO after the update.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
            //# An endpoint MUST retain old keys until it has successfully
            //# unprotected a packet sent using the new keys.
            //
            // Retained without a clock, and so retained until the *next*
            // update rather than for three times the PTO. Nothing here reads
            // `now_ns`, so the expiry below has no timer to hang off.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.5
            //# An endpoint SHOULD retain old read keys for no more than three times
            //# the PTO after having received a packet protected using the new keys.
            //# After this period, old read keys and their corresponding secrets
            //# SHOULD be discarded.
            //= type=todo
            const current_send = self.send_keys[@intFromEnum(Level.one_rtt)] orelse return;
            const current_receive = self.receive_keys[@intFromEnum(Level.one_rtt)] orelse return;

            // Every generation below is built with `nextGeneration`, which
            // carries the header protection key forward. Section 6.1 does not
            // update it, and a fresh one makes the peer unable to unmask the
            // very bit that announces the update.
            one.previous_receive = current_receive;
            self.send_keys[@intFromEnum(Level.one_rtt)] = current_send.nextGeneration(one.suite, &next_send);
            self.receive_keys[@intFromEnum(Level.one_rtt)] = one.next_receive orelse
                current_receive.nextGeneration(one.suite, &next_receive);

            one.send_secret = next_send;
            one.receive_secret = next_receive;
            const after = crypto.secrets.update(one.suite, &next_receive);
            one.next_receive = current_receive.nextGeneration(one.suite, &after);

            one.phase = !one.phase;
            one.sealed = 0;
            one.phase_acknowledged = false;
        }

        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
        //# An endpoint MUST NOT initiate a key update prior to having confirmed
        //# the handshake (Section 4.1.2).  An endpoint MUST NOT initiate a
        //# subsequent key update unless it has received an acknowledgment for a
        //# packet that was sent protected with keys from the current key phase.
        //
        /// Whether section 6.1 permits this endpoint to start an update.
        pub fn canUpdateKeys(self: *const Self) bool {
            if (self.state != .established) return false; // Section 6.1: not before the handshake is confirmed.
            if (!self.one_rtt.phase_acknowledged) return false;
            return self.one_rtt.send_secret != null and self.one_rtt.receive_secret != null;
        }

        pub const ReceiveError = error{
            /// A frame that section 12.4 does not permit at this encryption
            /// level, a reserved bit set, or a malformed frame.
            /// `PROTOCOL_VIOLATION` or `FRAME_ENCODING_ERROR`.
            Protocol,
            /// More handshake data than `crypto_octets`. RFC 9001 section 4.4's
            /// `CRYPTO_BUFFER_EXCEEDED`.
            CryptoBufferExceeded,
            /// Section 4.1: the peer sent past a flow control limit.
            /// `FLOW_CONTROL_ERROR`.
            FlowControl,
            /// Section 4.5: data past a final size, or a contradictory one.
            /// `FINAL_SIZE_ERROR`.
            FinalSize,
            /// Section 4.6: more streams than this endpoint tracks.
            /// `STREAM_LIMIT_ERROR`.
            StreamLimit,
            /// Sections 19.4, 19.5, 19.8 and 19.10: a frame for a stream the
            /// peer cannot send on. `STREAM_STATE_ERROR`.
            StreamState,
            /// RFC 9001 section 6.6: too many packets failed authentication, or
            /// a key reached its confidentiality limit with no update possible.
            /// `AEAD_LIMIT_REACHED`, and the connection stops here.
            AeadLimitReached,
            /// A stream arrived in more pieces than the reassembler holds. The
            /// peer broke no rule and this endpoint ran out of room, so the
            /// honest close is `INTERNAL_ERROR` rather than a code that accuses
            /// the peer of something.
            TooFragmented,
        };

        /// Take one UDP datagram.
        ///
        /// Section 12.2: a datagram may carry several packets, and a packet that
        /// cannot be decrypted is *discarded* rather than fatal — an off-path
        /// attacker can inject anything, and tearing the connection down on one
        /// is the attack. So a decryption failure ends the datagram quietly and
        /// only a protocol violation by the authenticated peer returns an error.
        pub fn receive(self: *Self, datagram: []u8, now_ns: u64) ReceiveError!void {
            if (self.state == .draining) return;

            // Section 14.1: "A server MUST discard an Initial packet that is
            // carried in a UDP datagram with a payload that is smaller than the
            // smallest allowed maximum datagram size of 1200 bytes."
            //
            // Discarded before the octets are credited, which is the half that
            // matters. `received_octets` is what section 8.1 multiplies by
            // three, so counting a datagram this endpoint refuses to process
            // would sell amplification allowance for forty octets — the padding
            // requirement exists precisely so a server knows the path carries a
            // handshake before it commits anything to it.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            //# A server MUST discard an Initial packet that is carried in a UDP
            //# datagram with a payload that is smaller than the smallest allowed
            //# maximum datagram size of 1200 bytes.
            //
            // Discarded rather than closed on, which is the other half of the
            // rule: a datagram's size is not authenticated, so treating an
            // undersized one as a connection error would hand anyone who can
            // spoof a source address a way to kill the connection.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14
            //# Therefore, an endpoint MUST NOT close a connection
            //# when it receives a datagram that does not meet size constraints; the
            //# endpoint MAY discard such datagrams.
            if (self.side == .server and datagram.len < initial_datagram_min) {
                const first = packet.parse(datagram, self.source.length) catch return;
                if (first.header == .initial) return;
            }

            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
            //# For the purposes of
            //# avoiding amplification prior to address validation, servers MUST
            //# count all of the payload bytes received in datagrams that are
            //# uniquely attributed to a single connection.  This includes datagrams
            //# that contain packets that are successfully processed and datagrams
            //# that contain packets that are all discarded.
            self.received_octets += datagram.len;

            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
            //# Receivers MUST be able to
            //# process coalesced packets.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
            //# The receiver of coalesced QUIC packets MUST
            //# individually process each QUIC packet and separately acknowledge
            //# them, as if they were received as the payload of different UDP
            //# datagrams.
            var offset: usize = 0;
            var packets: u32 = 0;
            while (offset < datagram.len) : (packets += 1) {
                assert(packets <= datagram.len);
                const parsed = packet.parse(datagram[offset..], self.source.length) catch return;
                const consumed = parsed.octets;
                assert(consumed >= 1);
                try self.receivePacket(datagram[offset..][0..consumed], parsed.header, now_ns);
                offset += consumed;
            }
        }

        fn receivePacket(self: *Self, bytes: []u8, header: packet.Header, now_ns: u64) ReceiveError!void {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
            //# A client that supports only this version of QUIC MUST abandon the
            //# current connection attempt if it receives a Version Negotiation
            //# packet, with the following two exceptions.
            //= type=exception
            //= reason=version negotiation is out of scope for this slice; a connection here speaks one version. See docs/DESIGN.md section 2, which puts the QUIC connection state machine in this package and leaves the packet types that begin a *different* connection to the consumer.
            //
            // Retry is refused here for the same reason and is not excused: the
            // integrity tag and the key re-derivation it implies are written
            // (`original_destination` exists for it) and nothing calls them.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
            //# A client MUST accept and process at most one Retry packet for each
            //# connection attempt.
            //= type=todo
            const level = header.level() orelse return; // Retry, Version Negotiation: not this slice.
            const offset = header.packetNumberOffset() orelse return;
            const index = @intFromEnum(level);
            if (self.spaces[@intFromEnum(level.space())].discarded) return;
            // The TLS engine is the gate: 1-RTT read keys reach `installSecret`
            // only when the handshake is complete, so a packet that arrives
            // before then has no key to open it and is discarded here.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
            //# Endpoints in either role MUST NOT decrypt 1-RTT packets from
            //# their peer prior to completing the handshake.
            const keys = self.receive_keys[index] orelse return; // No keys yet: discard.

            const space = &self.spaces[@intFromEnum(level.space())];
            const opened = self.openPacket(level, keys, bytes, offset, space.received.largest()) catch |err| switch (err) {
                // Section 5.4: a packet that fails to authenticate is discarded,
                // never a connection error — an off-path attacker can inject
                // one at will, so closing on it is the attack rather than the
                // defence. The counter is what bounds how long that can go on.
                error.Discard => return,
                error.AeadLimitReached => return error.AeadLimitReached,
            };

            // Section 12.3: a duplicate is discarded rather than reprocessed,
            // which is what stops a replayed packet from counting twice toward
            // anything. After `openPacket`, never before it.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
            //# A receiver MUST discard a newly unprotected packet unless it is
            //# certain that it has not processed another packet with the same packet
            //# number from the same packet number space.  Duplicate suppression MUST
            //# happen after removing packet protection for the reasons described in
            //# Section 9.5 of [QUIC-TLS].
            if (space.received.contains(opened.number)) return;

            // Section 8.1: receiving a Handshake packet proves the peer holds
            // keys only the real one could have, which validates the address.
            if (level == .handshake) self.address_validated = true;

            // The ACK debt is recorded only after every frame has been applied,
            // so a payload that fails halfway is never acknowledged.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.1
            //# A packet MUST NOT be acknowledged until packet protection has been
            //# successfully removed and all frames contained in the packet have been
            //# processed.
            const eliciting = try self.receiveFrames(level, opened.payload, now_ns);
            space.received.record(opened.number, now_ns, eliciting);

            // Section 7.2: a client's Source Connection ID is chosen once and
            // fixed for the connection, so a server adopts it from the first
            // Initial it can open and refuses a different one afterwards.
            //
            // Re-adopting on every Initial was a hole rather than a nicety.
            // Initial keys derive from a connection identifier that travels in
            // cleartext, so anyone who saw the first flight can seal a valid
            // Initial packet — passing the AEAD at this level is not evidence
            // of anything. An off-path observer could therefore point all of a
            // server's subsequent packets at an identifier the real client
            // discards, and the connection dies with neither endpoint at fault.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            //# A server MUST set the Destination Connection ID it
            //# uses for sending packets based on the first received Initial packet.
            //
            // The second Initial with a different Source Connection ID is a
            // *connection error* here, and section 7.2 asks for it to be
            // discarded instead. Left as it stands rather than changed under a
            // ledger pass, because the two readings differ in what an off-path
            // forgery costs and that is a decision rather than an edit.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            //# Any further changes to the Destination Connection ID are only
            //# permitted if the values are taken from NEW_CONNECTION_ID frames; if
            //# subsequent Initial packets include a different Source Connection ID,
            //# they MUST be discarded.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            //# Once a
            //# client has received a valid Initial packet from the server, it MUST
            //# discard any subsequent packet it receives on that connection with a
            //# different Source Connection ID.
            //
            // Both halves, and both are a *discard* rather than a connection
            // error. This used to answer a mismatch with `error.Protocol`,
            // which closes the connection — and Initial keys are derivable by
            // anyone who watched the first flight, so one forged Initial from
            // an off-path observer ended the connection. The RFC's remedy is to
            // drop the packet and carry on, which costs an attacker the ability
            // to do anything at all.
            //
            // The client half was absent entirely. A short header carries no
            // Source Connection ID, so this can only speak for long headers,
            // which is where the identifier is established.
            // The three long-header kinds carry a source; `initial` has its own
            // struct because of the token field, so the identifier is pulled out
            // before the comparison rather than captured across arms.
            const carried_source: ?ConnectionId = switch (header) {
                .initial => |value| value.source,
                .handshake, .zero_rtt => |value| value.source,
                else => null,
            };
            if (carried_source) |source| {
                if (self.peer_source) |known| {
                    if (!known.eql(&source)) return;
                } else {
                    // A server pins on the first Initial; a client pins on the
                    // first long header it opens from the server, which by this
                    // point has authenticated.
                    const pins = (self.side == .server and header == .initial) or self.side == .client;
                    if (pins) {
                        self.peer_source = source;
                        self.destination = source;
                    }
                }
            }
        }

        /// Remove protection, choosing the 1-RTT generation the Key Phase bit
        /// names, and count a failure against section 6.6's integrity limit.
        fn openPacket(
            self: *Self,
            level: Level,
            keys: crypto.Keys,
            bytes: []u8,
            offset: usize,
            largest: ?u64,
        ) error{ Discard, AeadLimitReached }!crypto.Keys.Opened {
            // Header protection first and on its own: RFC 9001 section 6.1
            // keeps the header protection key across an update, so this works
            // whichever generation protected the payload.
            assert(offset < bytes.len);
            const header = keys.unprotectHeader(bytes, offset, largest) catch return error.Discard;
            // The packet number is the AEAD nonce, so a header that unprotected
            // has to name a width the wire actually carried.
            assert(header.number_octets >= 1);
            assert(header.number_octets <= 4);
            assert(header.header_octets <= bytes.len);

            if (level != .one_rtt) {
                return keys.decrypt(bytes, header) catch return self.countForgery();
            }

            const one = &self.one_rtt;
            // Section 6.1: the header protection key is not updated, so the
            // phase bit read above is meaningful whichever generation sealed
            // the payload. Getting this wrong once produced `ReservedBitsSet`.
            assert(level == .one_rtt);
            if (header.key_phase == one.phase) {
                return keys.decrypt(bytes, header) catch return self.countForgery();
            }

            // A phase that is not ours is either the peer starting an update or
            // a packet reordered from before ours. Both carry the opposite bit,
            // so there is nothing to tell them apart but trying: the next
            // generation first, then the previous.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.2
            //# If a packet is successfully processed using the next key and IV, then
            //# the peer has initiated a key update.  The endpoint MUST update its
            //# send keys to the corresponding key phase in response, as described in
            //# Section 6.1.  Sending keys MUST be updated before sending an
            //# acknowledgment for the packet that was received with updated keys.
            if (one.next_receive) |next| {
                if (next.decrypt(bytes, header)) |opened| {
                    // Section 6.2: a packet that opens under the next generation
                    // *is* the peer's update, and this endpoint follows it.
                    self.updateKeys();
                    return opened;
                } else |_| {}
            }
            // The old generation is tried without comparing packet numbers, so
            // a peer that goes *backwards* — old keys on a higher number than
            // one the new keys covered — is accepted rather than reported.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.4
            //# Packets with higher packet numbers MUST be protected with either the
            //# same or newer packet protection keys than packets with lower packet
            //# numbers.  An endpoint that successfully removes protection with old
            //# keys when newer keys were used for packets with lower packet numbers
            //# MUST treat this as a connection error of type KEY_UPDATE_ERROR.
            //= type=todo
            if (one.previous_receive) |previous| {
                if (previous.decrypt(bytes, header)) |opened| return opened else |_| {}
            }
            //= https://www.rfc-editor.org/rfc/rfc9001#section-5.5
            //# Similarly, a packet
            //# that appears to trigger a key update but cannot be unprotected
            //# successfully MUST be discarded.
            return self.countForgery();
        }

        /// Section 6.6: count a packet that failed authentication, and close
        /// the connection once the integrity limit for the suite is passed.
        fn countForgery(self: *Self) error{ Discard, AeadLimitReached } {
            // RFC 9001 section 6.6 counts every failure, not every packet: an
            // off-path attacker injects at will, so this is the only number
            // that bounds how long a key stays in use under attack.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
            //# In addition to counting packets sent, endpoints MUST count the number
            //# of received packets that fail authentication during the lifetime of a
            //# connection.  If the total number of received packets that fail
            //# authentication within the connection, across all keys, exceeds the
            //# integrity limit for the selected AEAD, the endpoint MUST immediately
            //# close the connection with a connection error of type
            //# AEAD_LIMIT_REACHED and not process any more packets.
            assert(self.forgeries < std.math.maxInt(u64));
            self.forgeries += 1;
            assert(self.forgeries >= 1);
            if (self.forgeries > crypto.integrityLimit(self.one_rtt.suite)) {
                self.close(.aead_limit_reached);
                return error.AeadLimitReached;
            }
            return error.Discard;
        }

        /// Walk the frames of one payload, returning whether any was
        /// ack-eliciting.
        fn receiveFrames(self: *Self, level: Level, payload: []const u8, now_ns: u64) ReceiveError!bool {
            var iterator: frame.Iterator = .init(payload);
            var eliciting = false;
            var count: u32 = 0;
            while (count <= payload.len) : (count += 1) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
                //# An endpoint MUST treat the receipt of a frame of unknown type as a
                //# connection error of type FRAME_ENCODING_ERROR.
                const one = iterator.next() catch return error.Protocol;
                const value = one orelse break;
                // Section 12.4, Table 3. A STREAM frame in an Initial packet is
                // application data accepted before anyone is authenticated.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
                //# An endpoint MUST treat
                //# receipt of a frame in a packet type that is not permitted as a
                //# connection error of type PROTOCOL_VIOLATION.
                if (!value.frameType().allowedIn(level)) return error.Protocol;
                if (value.ackEliciting()) eliciting = true;
                try self.receiveFrame(level, value, now_ns);
            }
            return eliciting;
        }

        fn receiveFrame(self: *Self, level: Level, one: frame.Frame, now_ns: u64) ReceiveError!void {
            switch (one) {
                .padding, .ping => {},
                .ack => |value| try self.receiveAck(level, value, now_ns),
                .crypto => |value| try self.receiveCrypto(level, value),
                .handshake_done => try self.receiveHandshakeDone(),
                .connection_close => |value| {
                    self.close_code = value.code;
                    self.close_is_application = value.application;
                    // Section 10.2.2: a receiver enters draining and sends
                    // nothing further but a single close of its own.
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
                    //# An endpoint that receives a CONNECTION_CLOSE frame MAY send a single
                    //# packet containing a CONNECTION_CLOSE frame before entering the
                    //# draining state, using a NO_ERROR code if appropriate.  An endpoint
                    //# MUST NOT send further packets.
                    self.state = .draining;
                },
                //= https://www.rfc-editor.org/rfc/rfc9000#section-9
                //# An endpoint MUST
                //# perform path validation (Section 8.2) if it detects any change to a
                //# peer's address, unless it has previously validated that address.
                //= type=exception
                //= reason=connection migration is out of scope; a connection here has one path and never sees an address change, because the seam of docs/DESIGN.md section 3 takes datagrams rather than sockets. See docs/DESIGN.md section 2 for what this package owns and section 6 for what it does not.
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
                //# On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by
                //# echoing the data contained in the PATH_CHALLENGE frame in a
                //# PATH_RESPONSE frame.
                //= type=exception
                //= reason=path validation belongs to migration, which is out of scope; see docs/DESIGN.md section 2 and section 6. PATH_CHALLENGE payloads would also need randomness, which docs/DESIGN.md section 3 keeps outside this package.
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
                //# When an endpoint issues a connection ID, it MUST accept packets that
                //# carry this connection ID for the duration of the connection or until
                //# its peer invalidates the connection ID via a RETIRE_CONNECTION_ID
                //# frame (Section 19.16).
                //= type=exception
                //= reason=this endpoint issues exactly one connection identifier, the one in Options.source, and never a second; issuing more is migration's business. See docs/DESIGN.md section 2 and section 6.
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6
                //# If a
                //# client receives packets from a new server address when the client has
                //# not initiated a migration to that address, the client SHOULD discard
                //# these packets.
                //= type=exception
                //= reason=a server's preferred address is migration by another name and is out of scope; nothing here sees a source address at all, because the seam of docs/DESIGN.md section 3 hands over a datagram and not a peer. See docs/DESIGN.md section 2 and section 6.
                .new_connection_id, .retire_connection_id, .path_challenge, .path_response => {
                    // Migration is not this slice; the frames parse and are
                    // ignored rather than refused, because they are legal and a
                    // conforming peer may send them.
                },
                // Ignored in both directions, and the receive half of that is
                // wrong: a server is required to refuse the frame outright.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.7
                //# Clients MUST NOT send NEW_TOKEN frames.  A server MUST treat receipt
                //# of a NEW_TOKEN frame as a connection error of type
                //# PROTOCOL_VIOLATION.
                //= type=todo
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                //# A server MUST ensure that every NEW_TOKEN frame it sends
                //# is unique across all clients, with the exception of those sent to
                //# repair losses of previously sent NEW_TOKEN frames.
                //= type=exception
                //= reason=NEW_TOKEN issuance is out of scope; the token is a server's own encrypted state and needs randomness and a clock, neither of which crosses the seam of docs/DESIGN.md section 3. See docs/DESIGN.md section 2.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.7
                //# Clients MUST NOT send NEW_TOKEN frames.  A server MUST treat receipt
                //# of a NEW_TOKEN frame as a connection error of type
                //# PROTOCOL_VIOLATION.
                //
                // Ignored at both roles before this. A client has no use for
                // the frame either — this package requests no token and stores
                // none — but only the server's half is a rule, so only the
                // server's half is enforced.
                .new_token => if (self.side == .server) return error.Protocol,
                // Both take `@max`, so a limit that moved backwards under loss
                // or reordering leaves the send window where it was.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
                //# A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do
                //# not increase flow control limits.
                .max_data => |value| self.streams.setConnectionSendLimit(value.maximum),
                .max_stream_data => |value| self.streams.setSendLimit(value.stream, value.maximum) catch |err| {
                    return streamError(err);
                },
                // Section 4.6: the peer telling us how many streams we may
                // open. The claim that stood here — that "this package opens
                // what its comptime bound allows and no more, so a larger limit
                // changes nothing and a smaller one is already respected" — was
                // half false, and the false half mattered: the peer's limit was
                // never recorded, so a peer permitting two streams while
                // `streams_max` is sixty-four got as many as the application
                // asked for and answered with `STREAM_LIMIT_ERROR`.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
                //# MAX_STREAMS frames that do not increase the stream limit MUST be
                //# ignored.
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
                //# An endpoint MUST NOT open more streams than permitted by the current
                //# stream limit set by its peer.
                .max_streams => |value| self.streams.setPeerStreamLimit(value.bidirectional, value.maximum),
                // Section 4.1 and 4.6: the peer says it is blocked. Purely
                // informational — it is a signal that our advertised limit is
                // too low, and raising it is what `writePayload` already does
                // as the application reads.
                //
                // The mirror image is missing: this endpoint never *sends* one,
                // so a peer whose limit is too low learns it only from silence.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
                //# A sender SHOULD send a
                //# STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
                //# that it has data to write but is blocked by flow control limits.
                //= type=todo
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.14
                //# A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when
                //# it wishes to open a stream but is unable to do so due to the maximum
                //# stream limit set by its peer; see Section 19.11.
                //= type=todo
                .data_blocked, .stream_data_blocked, .streams_blocked => {},
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.8
                //# An endpoint MUST terminate the connection with error
                //# STREAM_STATE_ERROR if it receives a STREAM frame for a locally
                //# initiated stream that has not yet been created, or for a send-only
                //# stream.
                .stream => |value| {
                    if (level != .one_rtt and level != .zero_rtt) return error.Protocol;
                    self.streams.receive(value.stream, value.offset, value.data, value.fin) catch |err| {
                        return streamError(err);
                    };
                },
                //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
                //# The receiver MUST use the final size of the stream to
                //# account for all bytes sent on the stream in its connection-level flow
                //# controller.
                .reset_stream => |value| {
                    self.streams.reset(value.stream, @intFromEnum(value.code), value.final_size) catch |err| {
                        return streamError(err);
                    };
                },
                // Section 3.5: the peer wants us to stop sending. Recorded as a
                // reset of our send half; what to tell the application is the
                // consumer's decision.
                //
                // `Streams.open` creates whatever identifier it is handed and
                // asks nothing about direction, so neither half of the rule
                // below is enforced here: a STOP_SENDING for a receive-only
                // stream is accepted, and one for a locally initiated stream
                // that was never created brings that stream into existence.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
                //# Receiving a STOP_SENDING frame for a
                //# locally initiated stream that has not yet been created MUST be
                //# treated as a connection error of type STREAM_STATE_ERROR.  An
                //# endpoint that receives a STOP_SENDING frame for a receive-only stream
                //# MUST terminate the connection with error STREAM_STATE_ERROR.
                //= type=todo
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
                //# Receiving a STOP_SENDING frame for a
                //# locally initiated stream that has not yet been created MUST be
                //# treated as a connection error of type STREAM_STATE_ERROR.  An
                //# endpoint that receives a STOP_SENDING frame for a receive-only stream
                //# MUST terminate the connection with error STREAM_STATE_ERROR.
                //
                // Neither half was checked. The second let a peer stop a stream
                // it is the only one allowed to write on; the first is worse,
                // because `open` *creates* the stream — so a peer could fill
                // the table with identifiers this endpoint never opened, up to
                // `streams_max`, using a frame that names them.
                .stop_sending => |value| {
                    if (!self.streams.weMaySend(value.stream)) return error.StreamState;
                    if (self.streams.find(value.stream) == null and
                        stream_id.kindOf(value.stream).initiator() == self.side)
                    {
                        return error.StreamState;
                    }
                    const stream = self.streams.open(value.stream) catch |err| return streamError(err);
                    stream.send_state = .reset;
                    stream.reset_code = @intFromEnum(value.code);
                },
            }
        }

        /// Section 13.2 and RFC 9002 section 5: what an acknowledgement moves.
        fn receiveAck(self: *Self, level: Level, value: frame.Ack, now_ns: u64) ReceiveError!void {
            // The caller applied section 12.4's Table 3 before dispatching, so
            // an ACK cannot arrive at a level that forbids one.
            assert(frame.Type.ack.allowedIn(level));
            const space = &self.spaces[@intFromEnum(level.space())];

            // A peer cannot acknowledge a number we never sent; doing so would
            // move our packet number encoding window somewhere we never were.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.1
            //# An endpoint SHOULD treat receipt of an acknowledgment for a packet it
            //# did not send as a connection error of type PROTOCOL_VIOLATION, if it
            //# is able to detect the condition.
            if (value.largest >= space.next) return error.Protocol;
            assert(space.next > 0);
            space.largest_acked = @max(space.largest_acked orelse 0, value.largest);
            assert(space.largest_acked.? >= value.largest);
            assert(space.largest_acked.? < space.next);
            // Section 6.1: a second update waits for an acknowledgement of
            // something sent in the current phase, which is what proves the
            // peer has these keys.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
            //# An endpoint MUST NOT initiate a
            //# subsequent key update unless it has received an acknowledgment for a
            //# packet that was sent protected with keys from the current key phase.
            if (level == .one_rtt) self.one_rtt.phase_acknowledged = true;

            // Section 13.2.5: the delay is in microseconds, scaled by the
            // exponent the peer advertised. Until the transport parameters are
            // decoded this uses section 18.2's default, which is what an absent
            // one means. Clamped before the shift — see `ack_delay_units_max`.
            // The `u64` annotation is load-bearing. `@min` narrows its result
            // type to fit the comptime-known bound, so `@min(x, 2_048_000)` is
            // a `u21` — and `u21 << 3` needs twenty-four bits and overflows.
            // The clamp written without it *created* the overflow it was added
            // to prevent.
            const delay_units: u64 = @min(value.delay, ack_delay_units_max);
            assert(delay_units <= ack_delay_units_max);
            const delay_ns: u64 = (delay_units << ack_delay_exponent_default) * std.time.ns_per_us;
            assert(delay_ns <= ack_delay_ns_max);

            var lost: [lost_report_max]PacketContext = undefined;
            const result = self.recovery.onAckReceived(
                level.space(),
                value,
                delay_ns,
                now_ns,
                &lost,
            ) catch return error.Protocol;
            // `onPacketsLost` indexes `lost`, so the count has to be clamped to
            // it rather than trusted — the clamp is the guard, and `result.lost`
            // counts what was detected rather than what was reported.
            assert(result.lost >= @min(result.lost, lost.len));
            self.onPacketsLost(lost[0..@min(result.lost, lost.len)]);
        }

        /// Section 19.6: CRYPTO carries the handshake, at its own offsets, in a
        /// stream that is separate per encryption level.
        fn receiveCrypto(self: *Self, level: Level, value: frame.Crypto) ReceiveError!void {
            assert(frame.Type.crypto.allowedIn(level));
            assert(@intFromEnum(level) < self.levels.len);
            const stream = &self.levels[@intFromEnum(level)];
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.6
            //# The largest offset delivered on a stream -- the sum of the offset and
            //# data length -- cannot exceed 2^62-1.  Receipt of a frame that exceeds
            //# this limit MUST be treated as a connection error of type
            //# FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.
            stream.received.push(value.offset, value.data) catch |err| return switch (err) {
                // A CRYPTO stream that outruns its buffer is a resource limit
                // rather than a peer breaking a rule, and section 7.5 gives it
                // its own code.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-7.5
                //# If an endpoint does not expand its buffer, it MUST close
                //# the connection with a CRYPTO_BUFFER_EXCEEDED error code.
                error.BeyondWindow, error.TooFragmented => error.CryptoBufferExceeded,
                error.Inconsistent, error.FinalSizeViolated => error.Protocol,
            };
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.20
        //# A HANDSHAKE_DONE frame can only be sent by the server.  Servers MUST
        //# NOT send a HANDSHAKE_DONE frame before completing the handshake.  A
        //# server MUST treat receipt of a HANDSHAKE_DONE frame as a connection
        //# error of type PROTOCOL_VIOLATION.
        //
        /// RFC 9001 section 4.1.2: only a server sends HANDSHAKE_DONE, and it
        /// is what confirms the handshake for a client.
        fn receiveHandshakeDone(self: *Self) ReceiveError!void {
            if (self.side == .server) return error.Protocol;
            assert(self.side == .client);
            // Section 4.1.2: "At the client, the handshake is considered
            // confirmed when a HANDSHAKE_DONE frame is received." A server
            // reaches the same door through `confirmHandshake`, which its
            // consumer calls — see there for why it cannot be inferred here.
            self.confirmHandshake();
            assert(self.recovery.handshake_confirmed);
        }

        /// Map a stream-layer error onto what the connection reports, so that
        /// each one keeps the RFC's own name for it: a flow control violation
        /// and a final size violation are different connection errors, and
        /// collapsing them would tell a peer the wrong thing about its bug.
        fn streamError(err: ConnectionStreams.Error) ReceiveError {
            return switch (err) {
                error.FlowControl => error.FlowControl,
                error.FinalSize => error.FinalSize,
                error.TooManyStreams => error.StreamLimit,
                error.StreamState => error.StreamState,
                error.TooFragmented => error.TooFragmented,
                error.Protocol, error.NotFound => error.Protocol,
            };
        }

        // ------------------------------------------------------------ streams

        /// Queue bytes on a stream, returning how many were taken. A short
        /// write means the peer's flow control limit or this endpoint's buffer
        /// is full; the caller retries when `MAX_STREAM_DATA` raises it.
        pub fn write(self: *Self, id: u64, data: []const u8, fin: bool) ConnectionStreams.Error!usize {
            return self.streams.write(id, data, fin);
        }

        /// Bytes readable in order on a stream, or an empty slice.
        pub fn readable(self: *Self, id: u64) []const u8 {
            const stream = self.streams.find(id) orelse return &.{};
            const out = stream.readable();
            // What a stream offers is bounded by the buffer it was given, which
            // is the comptime limit rather than anything the peer sent.
            assert(out.len <= config.stream_receive_octets);
            return out;
        }

        /// Release bytes the application has read, which is what moves the flow
        /// control window forward.
        pub fn consume(self: *Self, id: u64, octets: usize) ConnectionStreams.Error!void {
            return self.streams.consume(id, octets);
        }

        /// The stream's own state — its receive and send states, its final
        /// size, the code a RESET_STREAM carried. Named `findStream` rather
        /// than `stream` because `stream` is what every local that holds one is
        /// called, and a method that shadows them all is a method nobody can
        /// use next to them.
        pub fn findStream(self: *Self, id: u64) ?*ConnectionStreams.Stream {
            return self.streams.find(id);
        }

        /// Section 4.9: drop a level's keys and its packet number space.
        fn discard(self: *Self, level: Level) void {
            assert(@intFromEnum(level) < self.send_keys.len);
            assert(@intFromEnum(level) < self.receive_keys.len);
            // Section 4.9 of RFC 9001: discarding is one-way. A level whose
            // keys came back would be one where a packet number could repeat,
            // and a repeated number in a space is a repeated AEAD nonce.
            //
            // Each level keeps its own CRYPTO buffer and its own send cursor,
            // so the only thing a discarded level could still have carried is
            // exactly what this drops with it.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9
            //# Though an endpoint might retain older keys, new data MUST be sent at
            //# the highest currently available encryption level.  Only ACK frames
            //# and retransmissions of data in CRYPTO frames are sent at a previous
            //# encryption level.
            assert(level != .one_rtt);
            self.send_keys[@intFromEnum(level)] = null;
            self.receive_keys[@intFromEnum(level)] = null;
            self.spaces[@intFromEnum(level.space())].discarded = true;
            // Section 6.2.3 of RFC 9002: what was outstanding there is neither
            // lost nor acknowledged, and leaving its octets in flight would
            // hold the congestion window down for the rest of the connection.
            self.recovery.discardSpace(level.space());
        }

        /// Undo the sending of packets RFC 9002 declared lost.
        ///
        /// Rewinding the level's send cursor to where the lost packet began is
        /// the whole of it: everything from there is framed again on the next
        /// send. That re-sends octets a *later* packet also carried and that may
        /// have arrived, which is wasteful and not wrong — the peer's
        /// reassembler treats a duplicate as free, and section 2.2 guarantees
        /// the bytes are identical. Tracking per-range acknowledgement to avoid
        /// it would be a second reassembler on the send side, and a handshake is
        /// a few kilobytes.
        fn onPacketsLost(self: *Self, contexts: []const PacketContext) void {
            // Bounded by the caller's array rather than by anything the peer
            // chose; `receiveAck` clamps the count to it before calling here.
            assert(contexts.len <= lost_report_max);
            for (contexts) |context| {
                assert(context.crypto_end >= context.crypto_start);
                assert(context.stream_end >= context.stream_start);
                if (context.crypto_end > context.crypto_start) {
                    assert(@intFromEnum(context.level) < self.levels.len);
                    const level = &self.levels[@intFromEnum(context.level)];
                    // Rewinding is what makes a lost packet retransmittable, so
                    // it may only ever move the cursor back.
                    assert(@min(level.framed, context.crypto_start) <= level.framed);
                    level.framed = @min(level.framed, context.crypto_start);
                }
                //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
                //# The HANDSHAKE_DONE frame MUST be retransmitted until it is
                //# acknowledged.
                if (context.handshake_done) self.handshake_done_framed = false;
                if (context.stream_end > context.stream_start or context.stream_fin) {
                    self.streams.rewind(context.stream, context.stream_start, context.stream_fin);
                }
            }
        }

        /// When the caller must wake this connection, in its own clock's
        /// nanoseconds, or null when nothing is outstanding.
        ///
        /// Returned rather than armed: the caller owns the timer, because the
        /// two consumers arm one very differently and neither wants this
        /// package's idea of a timer wheel.
        pub fn timeout(self: *const Self) ?u64 {
            // Only `Recovery`'s timer is reported. There is no close timer, so
            // nothing here tells the caller when the closing or draining state
            // is over — the connection stops answering and the consumer decides
            // when to let go of it.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
            //# These states SHOULD persist for at least three
            //# times the current PTO interval as defined in [QUIC-RECOVERY].
            //= type=todo
            if (self.state == .draining) return null;
            return self.recovery.timeoutAt();
        }

        /// Section A.9 of RFC 9002: the timer fired.
        pub fn onTimeout(self: *Self, now_ns: u64) void {
            var lost: [lost_report_max]PacketContext = undefined;
            switch (self.recovery.onLossDetectionTimeout(now_ns, &lost)) {
                .lost => |count| self.onPacketsLost(lost[0..@min(count, lost.len)]),
                // Section 6.2.4: nothing is known to be lost and the peer has
                // gone quiet, so send something it must answer — and where
                // there is unacknowledged data, that rather than a bare PING,
                // because a probe that carries the handshake makes progress and
                // a probe that carries nothing only asks whether the path is
                // alive. The PING in `writePayload` is the fallback for when
                // there is no data to resend.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
                //# To
                //# prevent this deadlock, clients MUST send a packet on a Probe Timeout
                //# (PTO); see Section 6.2 of [QUIC-RECOVERY].  Specifically, the client
                //# MUST send an Initial packet in a UDP datagram that contains at least
                //# 1200 bytes if it does not have Handshake keys, and otherwise send a
                //# Handshake packet.
                .probe => |probe| {
                    self.spaces[@intFromEnum(probe.space)].probes_pending = probe.packets;
                    if (self.recovery.earliestContext(probe.space)) |context| {
                        self.onPacketsLost(&.{context});
                    }
                },
                .idle => {},
            }
        }

        // --------------------------------------------------------------- send

        pub const SendError = error{
            /// `buffer` is smaller than `datagram_octets`.
            BufferTooSmall,
        };

        /// Build one datagram into `buffer`, returning its length; zero when
        /// there is nothing to send.
        ///
        /// One datagram per call rather than as many as will fit, because the
        /// caller owns the socket and the pacing: a loop here would be this
        /// package deciding how fast to send.
        pub fn send(self: *Self, buffer: []u8, now_ns: u64) SendError!usize {
            if (buffer.len < config.datagram_octets) return error.BufferTooSmall;
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
            //# While otherwise identical to the closing state, an
            //# endpoint in the draining state MUST NOT send any packets.
            if (self.state == .draining) return 0;

            const room = self.sendRoom();
            if (room == 0) return 0;
            const limit = @min(room, config.datagram_octets);

            var offset: usize = 0;
            // Section 12.2: levels are coalesced oldest first, so a peer that
            // has not yet installed later keys still gets the earlier packet.
            //
            // Every packet in the datagram is addressed to `self.destination`,
            // which is one value for the connection, so the coalescing rule
            // below holds by construction rather than by a check.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
            //# Senders MUST NOT coalesce QUIC packets
            //# with different connection IDs into a single UDP datagram.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
            //# An endpoint SHOULD include multiple frames in a single packet if they
            //# are to be sent at the same encryption level, instead of coalescing
            //# multiple packets at the same encryption level.
            var initial_ack_eliciting = false;
            for ([_]Level{ .initial, .handshake, .one_rtt }) |level| {
                var eliciting = false;
                offset += self.sendPacket(buffer[offset..limit], level, now_ns, &eliciting) catch 0;
                if (level == .initial and eliciting) initial_ack_eliciting = true;
            }
            if (offset == 0) return 0;

            // Section 14.1: a datagram carrying a client Initial is padded to
            // 1200 octets. The padding is zeroes, which *is* a PADDING frame,
            // but it goes outside the packet rather than inside it — this
            // endpoint has already sealed by now, and section 12.2 allows a
            // datagram to be longer than the packets it carries.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            //# A client MUST expand the payload of all UDP datagrams carrying
            //# Initial packets to at least the smallest allowed maximum datagram
            //# size of 1200 bytes by adding PADDING frames to the Initial packet or
            //# by coalescing the Initial packet; see Section 12.2.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            //# Similarly, a server MUST expand the payload of all UDP
            //# datagrams carrying ack-eliciting Initial packets to at least the
            //# smallest allowed maximum datagram size of 1200 bytes.
            //
            // The server's half, which was a `todo` here and — worse — was
            // asserted the other way by a test that called the floor "the
            // client's obligation". Both halves now run through the same
            // padding, gated on what each side actually owes: a client pads
            // every datagram carrying an Initial, a server only those carrying
            // an *ack-eliciting* Initial, because a bare ACK from a server
            // neither probes the path nor needs to.
            //
            // Padding past `limit` is not possible and that is correct: for an
            // unvalidated server `limit` is section 8.1's three-times budget,
            // and section 14.1 does not license exceeding it.
            const owes_padding = (self.side == .client and
                self.send_keys[@intFromEnum(Level.initial)] != null) or
                initial_ack_eliciting;
            if (owes_padding) {
                if (offset < initial_datagram_min and limit >= initial_datagram_min) {
                    @memset(buffer[offset..initial_datagram_min], 0);
                    offset = initial_datagram_min;
                }
            }
            self.sent_octets += offset;
            return offset;
        }

        /// Section 6.6: count a packet sealed under the current key, and act
        /// before the confidentiality limit is passed rather than after.
        ///
        /// "Endpoints MUST initiate a key update before sending more protected
        /// packets than the confidentiality limit for the selected AEAD
        /// permits. If a key update is not possible or integrity limits are
        /// reached, the endpoint MUST stop using the connection... It is
        /// RECOMMENDED that endpoints immediately close the connection with a
        /// connection error of type AEAD_LIMIT_REACHED before reaching a state
        /// where key updates are not possible."
        ///
        /// So: update if section 6.1 allows one, and close if it does not.
        /// Below 1-RTT there is no update to make — those levels hold a
        /// handshake, are discarded early, and cannot approach the limit — so
        /// reaching it there is a close.
        fn countSealed(self: *Self, level: Level) void {
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
            //# Endpoints MUST count the number of encrypted packets for each set of
            //# keys.
            // Kept because exceeding the confidentiality limit is a break rather
            // than a degradation.
            assert(@intFromEnum(level) < self.sealed.len);
            if (level != .one_rtt) {
                assert(self.sealed[@intFromEnum(level)] < std.math.maxInt(u64));
                self.sealed[@intFromEnum(level)] += 1;
                if (self.sealed[@intFromEnum(level)] >= crypto.confidentialityLimit(secrets_suite_initial)) {
                    self.close(.aead_limit_reached);
                }
                return;
            }
            assert(self.one_rtt.sealed < std.math.maxInt(u64));
            self.one_rtt.sealed += 1;
            assert(self.one_rtt.sealed >= 1);
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
            //# If the total number of encrypted packets with the same key
            //# exceeds the confidentiality limit for the selected AEAD, the endpoint
            //# MUST stop using those keys.
            //
            //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
            //# An endpoint MUST initiate a key update
            //# (Section 6) prior to exceeding any limit set for the AEAD that is in
            //# use.
            if (self.one_rtt.sealed < crypto.confidentialityLimit(self.one_rtt.suite)) return;
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
            //# Endpoints MUST initiate a key update
            //# before sending more protected packets than the confidentiality limit
            //# for the selected AEAD permits.
            if (self.canUpdateKeys()) {
                self.updateKeys();
                return;
            }
            // No stateless reset follows, which is the RECOMMENDED close taken
            // in its place rather than the sentence's whole content.
            //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
            //# If a key update is not possible or
            //# integrity limits are reached, the endpoint MUST stop using the
            //# connection and only send stateless resets in response to receiving
            //# packets.  It is RECOMMENDED that endpoints immediately close the
            //# connection with a connection error of type AEAD_LIMIT_REACHED before
            //# reaching a state where key updates are not possible.
            self.close(.aead_limit_reached);
        }

        /// Section 8.1: what a server may still send before the address is
        /// validated. A client, and a validated server, are unbounded here and
        /// bounded by the datagram size instead.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8
        //# Therefore, after receiving packets from an address that is not yet
        //# validated, an endpoint MUST limit the amount of data it sends to the
        //# unvalidated address to three times the amount of data received from
        //# that address.
        //
        // The closing state is not exempt: `send` consults this before it
        // frames a CONNECTION_CLOSE, so a close to an unvalidated address is
        // held to the same three times.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
        //# An endpoint in the closing state MUST either discard
        //# packets received from an unvalidated address or limit the cumulative
        //# size of packets it sends to an unvalidated address to three times the
        //# size of packets it receives from that address.
        fn sendRoom(self: *const Self) u64 {
            if (self.address_validated) return config.datagram_octets;
            const allowance = self.received_octets * amplification_factor;
            // The comparison is what makes the subtraction below safe, and it
            // is a returned value rather than an assertion because both terms
            // are driven by the peer: this underflowed once, and the panic it
            // produced was reachable from the network.
            if (allowance <= self.sent_octets) return 0;
            assert(allowance > self.sent_octets);
            const room = @min(allowance - self.sent_octets, config.datagram_octets);
            assert(room <= config.datagram_octets);
            return room;
        }

        /// One packet at one level, or `error.Empty` when the level has nothing
        /// to say.
        fn sendPacket(self: *Self, buffer: []u8, level: Level, now_ns: u64, ack_eliciting_out: *bool) !usize {
            const index = @intFromEnum(level);
            const keys = self.send_keys[index] orelse return error.Empty;
            const space = &self.spaces[@intFromEnum(level.space())];
            if (space.discarded) return error.Empty;

            const number = space.next;
            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.1
            //# Prior to receiving an acknowledgment for a packet number space, the
            //# full packet number MUST be included; it is not to be truncated, as
            //# described below.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.1
            //# After an acknowledgment is received for a packet number space, the
            //# sender MUST use a packet number size able to represent more than
            //# twice as large a range as the difference between the largest
            //# acknowledged packet number and the packet number being sent.
            const number_octets = packet_number.encodedLength(number, space.largest_acked);
            const header = try self.writeHeader(buffer, level, number, number_octets);

            // The payload goes after the header, leaving room for the tag.
            // Checked, not assumed. `send` hands this a slice whose length is
            // `min(sendRoom(), datagram_octets)`, and for an unvalidated server
            // `sendRoom()` is `3 * received - sent` — a number the peer tunes by
            // choosing how much it sends. Land it in the sixteen-octet window
            // where a header fits but the header plus the tag does not, and the
            // subtraction below underflows: a panic in the safe builds and an
            // out-of-bounds slice in the `-Dassertions=false` one. Found by
            // review, reproduced by walking `sent_octets` across the window.
            const overhead = header.header_octets + crypto.tag_octets;
            if (buffer.len <= overhead) return error.Empty;
            const payload_room = buffer.len - overhead;
            assert(payload_room >= 1);
            assert(overhead + payload_room == buffer.len);
            // `writePayload` commits as it builds: it clears the ACK debt,
            // advances the CRYPTO and stream cursors, spends a probe and clears
            // `close_pending`. If sealing then fails, every one of those
            // believes a packet went out that did not — a dropped ACK, a
            // handshake that deadlocks because its bytes are marked framed and
            // never resent, a CONNECTION_CLOSE the peer never hears. So the
            // undo is captured first.
            const undo: Undo = .{
                .ack_eliciting_pending = space.received.ack_eliciting_pending,
                .probes_pending = space.probes_pending,
                .close_pending = self.close_pending,
                .crypto_framed = self.levels[index].framed,
                .handshake_done_framed = self.handshake_done_framed,
            };
            // Whether an ack-eliciting frame may be added at all. Without this
            // the ACK-only exemption below was accidental rather than real: a
            // sender with a full window framed its stream data *and* its ACK,
            // had the whole packet refused, and so never sent the
            // acknowledgement that would have opened the window. The peer keeps
            // sending, this endpoint keeps owing an ACK it cannot deliver, and
            // neither side moves. Adding HANDSHAKE_DONE made that reachable on
            // a handshake rather than only under load, which is how `sim/`
            // surfaced it.
            //
            // A probe is exempt (section 6.2.4 requires it to be ack-eliciting)
            // and so is a level with no congestion state of its own.
            const probes_before = space.probes_pending;
            const window_open = space.probes_pending > 0 or
                self.recovery.canSend(config.datagram_octets);
            const written = self.writePayload(buffer[header.header_octets..][0..payload_room], level, now_ns, window_open);
            const payload_octets = written.octets;
            // An empty payload is not a packet: the header is abandoned rather
            // than sealed over nothing.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
            //# The payload of a packet that contains frames MUST contain at least
            //# one frame, and MAY contain multiple frames and multiple frame types.
            if (payload_octets == 0) {
                self.rollback(level, undo, written);
                return error.Empty;
            }

            // A long header's Length field was reserved at a fixed width above
            // and is written back now that the payload's size is known. This is
            // section 16's non-minimal encoding used for the one thing it is
            // for; writing the header twice instead would risk the second one
            // being a different length and moving the payload out from under
            // what was just built.
            if (level != .one_rtt) {
                const length = @as(u64, number_octets) + payload_octets + crypto.tag_octets;
                const at = header.packet_number_offset - length_field_octets;
                varint.encodeIn(buffer[at..][0..length_field_octets], length, length_field_octets) catch unreachable; // The width was chosen at comptime to hold any length this datagram can carry.
            }

            // RFC 9002 section 7: "An endpoint MUST NOT send a packet if it
            // would cause bytes_in_flight to exceed the congestion window,
            // unless the packet is sent on a probe timeout."
            //
            // This is the line that makes the congestion controller a
            // controller. Without it the window was computed, halved, floored
            // and tested, and then nothing consulted it before sending — a
            // sender with a congestion window it does not obey is a sender with
            // no congestion control, however carefully the number is
            // maintained.
            //
            // Only ack-eliciting packets are held back. A packet carrying
            // nothing but an ACK is not in flight (section 2), and throttling
            // acknowledgements would throttle the feedback the window itself
            // depends on. A probe is exempt because a connection that cannot
            // probe cannot discover that the path recovered.
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7
            //# An endpoint MUST NOT send a packet if it would cause bytes_in_flight
            //# (see Appendix B.2) to be larger than the congestion window, unless
            //# the packet is sent on a PTO timer expiration (see Section 6.2) or
            //# when entering recovery (see Section 7.3.2).
            const in_flight_estimate = header.header_octets + payload_octets + crypto.tag_octets;
            if (written.ack_eliciting and space.probes_pending == 0 and
                !self.recovery.canSend(in_flight_estimate))
            {
                self.rollback(level, undo, written);
                return error.Empty;
            }

            const total = keys.seal(buffer, header.packet_number_offset, header.header_octets, payload_octets, number) catch {
                self.rollback(level, undo, written);
                return error.Empty;
            };
            // Advanced only after a successful seal, and never rewound: the
            // packet number is the AEAD nonce, so a number used twice under one
            // key is a nonce used twice.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
            //# Packet numbers in each space start
            //# at packet number 0.  Subsequent packets sent in the same packet
            //# number space MUST increase the packet number by at least one.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
            //# A QUIC endpoint MUST NOT reuse a packet number within the same packet
            //# number space in one connection.
            //
            // The ceiling has no handling: `writeHeader` asserts the number is
            // encodable, so at 2^62-1 a safe build panics and an
            // assertions-off build encodes a number it cannot represent.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
            //# If the packet number for sending
            //# reaches 2^62-1, the sender MUST close the connection without sending
            //# a CONNECTION_CLOSE frame or any further packets; an endpoint MAY send
            //# a Stateless Reset (Section 10.3) in response to further packets that
            //# it receives.
            //= type=todo
            space.next += 1;
            self.countSealed(level);

            // Section 6.2.4: the probe is spent by any ack-eliciting packet,
            // not only by the PING. The credit used to be consumed on the PING
            // path alone, so a probe that carried CRYPTO or stream data instead
            // — the case section 6.2.4 actually prefers, because it makes
            // progress rather than only asking whether the path is alive —
            // left `probes_pending` standing. That is not a cosmetic leak: a
            // non-zero `probes_pending` is what exempts a packet from the
            // congestion window below, so the window stopped binding for the
            // rest of the connection. Found by `sim/`, whose window oracle
            // fired on three seeds with the same excess.
            //
            // Consumed after the seal rather than before it, so a packet that
            // failed to seal has not spent the credit that would have let the
            // next one through.
            ack_eliciting_out.* = written.ack_eliciting;
            if (written.ack_eliciting and space.probes_pending > 0) {
                space.probes_pending -= 1;
            }
            // Section 7's rule, asserted where it is decidable: at the instant
            // a non-probe ack-eliciting packet is recorded, everything in
            // flight fits the window, because `canSend` was just consulted
            // with this packet's own size. It is *not* an invariant that holds
            // between sends — a congestion event halves the window under data
            // already on the wire, and RFC 9002 does not retract it — which is
            // why `sim/` cannot state this and this line can.
            if (written.ack_eliciting and probes_before == 0) {
                assert(self.recovery.bytes_in_flight <= self.recovery.congestion_window);
            }

            // Section 2 of RFC 9002: a packet is in flight when it is
            // ack-eliciting *or contains a PADDING frame*. The second half
            // never applies to a packet this endpoint sends — section 14.1's
            // padding is written into the datagram after the sealed packet
            // rather than into the payload before it (see `send`), so no packet
            // built here carries a PADDING frame and `ack_eliciting` decides
            // both. A packet carrying nothing but an ACK is neither, which is
            // what stops congestion control throttling the feedback it depends
            // on.
            //
            // The consequence, named rather than left implicit: the octets of
            // datagram padding are counted for section 8.1's amplification
            // limit (`sent_octets`) and not for the congestion window. On the
            // first flight that is roughly 950 octets the window does not see.
            // It is not binding — the initial window is ten datagrams — but a
            // reader comparing this against another stack's accounting should
            // know which of the two numbers it is looking at.
            self.recovery.onPacketSent(level.space(), .{
                .number = number,
                .time_sent = now_ns,
                .octets = @intCast(total),
                .ack_eliciting = written.ack_eliciting,
                .in_flight = written.ack_eliciting,
                .context = .{
                    .level = level,
                    .crypto_start = written.crypto_start,
                    .crypto_end = written.crypto_end,
                    .stream = written.stream,
                    .stream_start = written.stream_start,
                    .stream_end = written.stream_end,
                    .stream_fin = written.stream_fin,
                    .handshake_done = written.handshake_done,
                },
            }) catch {};
            return total;
        }

        fn writeHeader(self: *const Self, buffer: []u8, level: Level, number: u64, number_octets: u8) !packet.Written {
            // A number wider than four octets has no encoding, and one at the
            // varint ceiling has no successor — either would make the next
            // packet in this space reuse a nonce.
            assert(number_octets >= 1);
            assert(number_octets <= 4);
            assert(number <= varint.max);
            return switch (level) {
                .one_rtt => packet.writeShort(buffer, .{
                    .destination = self.destination,
                    .number = number,
                    .number_octets = number_octets,
                    // Section 6: the bit that tells the peer which generation
                    // sealed this packet. Without it an update is invisible and
                    // the peer decrypts with the wrong keys.
                    .key_phase = self.one_rtt.phase,
                }),
                .initial, .handshake => packet.writeLong(buffer, .{
                    .long_type = if (level == .initial) .initial else .handshake,
                    .destination = self.destination,
                    .source = self.source,
                    // A placeholder: the field is pinned to `length_field_octets`
                    // and back-filled once the payload exists.
                    .payload_octets = 0,
                    .number = number,
                    .number_octets = number_octets,
                    .length_octets = length_field_octets,
                }),
                //= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
                //# A client
                //# therefore MUST NOT use 0-RTT for application data unless specifically
                //# requested by the application that is in use.
                //= type=exception
                //= reason=0-RTT is out of scope; no header is ever written at this level, so no 0-RTT packet leaves this endpoint. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
                //
                //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.3
                //# Therefore, a client SHOULD discard 0-RTT keys as soon as it installs
                //# 1-RTT keys as they have no use after that moment.
                //= type=exception
                //= reason=0-RTT keys are never installed, so there are none to discard; 0-RTT is out of scope per docs/DESIGN.md section 2 and section 6.
                .zero_rtt => error.Empty,
            };
        }

        /// The send-side state `writePayload` commits, captured so it can be
        /// put back when the packet turns out not to exist.
        const Undo = struct {
            ack_eliciting_pending: bool,
            probes_pending: u8,
            close_pending: bool,
            crypto_framed: u32,
            handshake_done_framed: bool,
        };

        /// Put back everything `writePayload` committed. Called on every path
        /// out of `sendPacket` that does not produce a packet.
        fn rollback(self: *Self, level: Level, undo: Undo, written: Payload) void {
            const space = &self.spaces[@intFromEnum(level.space())];
            space.received.ack_eliciting_pending = undo.ack_eliciting_pending;
            space.probes_pending = undo.probes_pending;
            self.close_pending = undo.close_pending;
            self.levels[@intFromEnum(level)].framed = undo.crypto_framed;
            self.handshake_done_framed = undo.handshake_done_framed;
            if (written.stream_end > written.stream_start or written.stream_fin) {
                self.streams.rewind(written.stream, written.stream_start, written.stream_fin);
            }
        }

        const Payload = struct {
            octets: usize = 0,
            /// Section 2 of RFC 9002: whether anything here obliges the peer to
            /// acknowledge. An ACK-only packet does not, and must not count
            /// against the congestion window.
            ack_eliciting: bool = false,
            /// The CRYPTO range this packet carried, so losing it can rewind.
            crypto_start: u32 = 0,
            crypto_end: u32 = 0,
            /// And the stream range, likewise.
            stream: u64 = 0,
            stream_start: u32 = 0,
            stream_end: u32 = 0,
            /// Whether this packet carried the stream's FIN. Tracked apart from
            /// the range because a FIN carries no octets, so a lost one has no
            /// byte range to rewind.
            stream_fin: bool = false,
            /// Likewise for HANDSHAKE_DONE.
            handshake_done: bool = false,
        };

        /// Fill a payload: an ACK if one is owed, then whatever handshake bytes
        /// are waiting.
        /// Section 10.2's closing state: a CONNECTION_CLOSE and nothing else.
        ///
        /// Separate from `writePayload` rather than a branch inside it, because
        /// "nothing else" is the whole content of the rule and a reader should
        /// be able to see that this function cannot reach the ACK, CRYPTO or
        /// STREAM paths at all.
        fn writeClose(self: *Self, payload: []u8, result: *Payload) Payload {
            assert(self.state == .closing);
            // One close and then silence: `close_pending` is cleared below and
            // is never set again, so a closing endpoint does not answer every
            // incoming packet with a fresh CONNECTION_CLOSE. That is quieter
            // than the rate limit asks for and coarser than it: the peer that
            // loses the one close hears nothing until its own idle timeout.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
            //# An endpoint SHOULD limit the rate at which it generates packets in
            //# the closing state.
            //= type=todo
            if (!self.close_pending) return result.*;
            // Section 19.19: a transport close carries the frame type that
            // triggered it and an application close does not. Writing `null`
            // for both makes a type 0x1c frame that omits a field the peer's
            // parser requires, which is a close the peer cannot read.
            //
            // `close` always sets `close_is_application` false, so the 0x1d
            // form is never generated at any level and the rule below has no
            // way to be broken from here.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.5
            //# *  CONNECTION_CLOSE frames signaling errors at the QUIC layer (type
            //# 0x1c) MAY appear in any packet number space.  CONNECTION_CLOSE
            //# frames signaling application errors (type 0x1d) MUST only appear
            //# in the application data packet number space.
            const written = frame.encode(payload, .{ .connection_close = .{
                .application = self.close_is_application,
                .code = self.close_code,
                .triggered_by = if (self.close_is_application) null else 0,
                .reason = &.{},
            } }) catch return result.*;
            self.close_pending = false;
            result.octets = written;
            result.ack_eliciting = false;
            assert(result.octets <= payload.len);
            return result.*;
        }

        fn writePayload(self: *Self, payload: []u8, level: Level, now_ns: u64, window_open: bool) Payload {
            var result: Payload = .{};
            var offset: usize = 0;
            const space = &self.spaces[@intFromEnum(level.space())];

            // Section 10.2: an endpoint in the closing state "retains only
            // enough information to generate a packet containing a
            // CONNECTION_CLOSE frame", and sends that in response to an
            // incoming packet. It does not go on acknowledging, framing
            // handshake data or opening streams — this gated only on
            // `.draining`, so a closing endpoint kept doing all three, which is
            // both wasted work and a peer being told about progress on a
            // connection that is over.
            if (self.state == .closing) return self.writeClose(payload, &result);

            if (space.received.ack_eliciting_pending) {
                // Section 13.2.5's delay exponent is the peer's transport
                // parameter; until this package decodes them it uses the
                // default, which is what section 18.2 says an absent one means.
                const written = space.received.write(payload[offset..], now_ns, 3) catch null;
                if (written) |value| offset += value.octets;
            }

            // Nothing below this point is ACK-only, so a closed window stops
            // here and the packet goes out carrying the acknowledgement alone.
            if (!window_open) {
                result.octets = offset;
                return result;
            }

            // Section 6.2.4: a probe must be ack-eliciting, and a PING is the
            // cheapest frame that is. Real handshake data takes its place when
            // there is any, which is why this runs before the CRYPTO below and
            // only claims the space when it has nothing to say.
            if (space.probes_pending > 0 and stream_has_nothing: {
                const stream = &self.levels[@intFromEnum(level)];
                break :stream_has_nothing stream.framed >= stream.pending_len;
            }) {
                offset += frame.encode(payload[offset..], .ping) catch 0;
                result.ack_eliciting = true;
            }

            const stream = &self.levels[@intFromEnum(level)];
            if (stream.framed < stream.pending_len) {
                result.crypto_start = stream.framed;
                offset += self.writeCrypto(payload[offset..], stream);
                result.crypto_end = stream.framed;
                if (result.crypto_end > result.crypto_start) result.ack_eliciting = true;
            }

            // Application data only: sections 4.1 and 2 put streams and their
            // limits in the 1-RTT space alone.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.5
            //# *  All other frame types MUST only be sent in the application data
            //# packet number space.
            if (level == .one_rtt) {
                if (self.handshake_done_pending and !self.handshake_done_framed) {
                    const written = frame.encode(payload[offset..], .handshake_done) catch 0;
                    if (written > 0) {
                        offset += written;
                        self.handshake_done_framed = true;
                        result.handshake_done = true;
                        result.ack_eliciting = true;
                    }
                }
                offset += self.writeFlowControl(payload[offset..]);
                const framed = self.writeStream(payload[offset..], &result);
                offset += framed;
                if (framed > 0) result.ack_eliciting = true;
            }

            if (self.close_pending and offset < payload.len) {
                offset += frame.encode(payload[offset..], .{ .connection_close = .{
                    .application = self.close_is_application,
                    .code = self.close_code,
                    .triggered_by = if (self.close_is_application) null else 0,
                    .reason = "",
                } }) catch 0;
                self.close_pending = false;
            }
            result.octets = offset;
            return result;
        }

        /// Section 4.1: raise the peer's limits as the application reads.
        ///
        /// Sent when the window has moved by half, rather than on every read: a
        /// MAX_DATA per octet consumed would spend more of the connection on
        /// flow control than on data, and a peer only needs the limit before it
        /// runs out.
        fn writeFlowControl(self: *Self, target: []u8) usize {
            var offset: usize = 0;
            const limit = self.streams.receiveLimit();
            if (limit >= self.max_data_sent + config.connection_receive_octets / 2) {
                offset += frame.encode(target[offset..], .{ .max_data = .{ .maximum = limit } }) catch 0;
                if (offset > 0) self.max_data_sent = limit;
            }

            for (self.streams.streams[0..self.streams.count]) |*stream| {
                if (offset >= target.len) break;
                const stream_limit = stream.receiveLimit();
                if (stream_limit < stream.max_data_sent + config.stream_receive_octets / 2) continue;
                const written = frame.encode(target[offset..], .{ .max_stream_data = .{
                    .stream = stream.id,
                    .maximum = stream_limit,
                } }) catch 0;
                if (written == 0) break;
                offset += written;
                stream.max_data_sent = stream_limit;
            }
            return offset;
        }

        // Both limits are `Streams`': `write` refuses what would exceed the
        // connection or stream window and what would follow a FIN, so
        // everything in `send[framed..send_len]` is already within both.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        //# Senders MUST NOT send data in excess of either limit.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        //# An endpoint MUST NOT send data on a stream at or beyond the final
        //# size.
        //
        /// Frame whatever one stream has waiting.
        ///
        /// One stream per packet rather than as many as fit: a packet carrying
        /// two streams' data has to record two ranges to undo on loss, and the
        /// gain is a few octets of header on a path that is already
        /// AEAD-bound.
        fn writeStream(self: *Self, target: []u8, result: *Payload) usize {
            assert(self.streams.count <= self.streams.streams.len);
            for (self.streams.streams[0..self.streams.count]) |*stream| {
                // `framed` is how much of the send buffer has been put into a
                // packet, so it never passes what the application wrote —
                // `onPacketsLost` only ever moves it back.
                assert(stream.framed <= stream.send_len);
                const waiting = stream.send_len - stream.framed;
                // Owed once. Without `fin_framed` this was permanently true,
                // so every packet carried another empty FIN and `wantsSend`
                // never answered false again.
                const fin_owed = stream.send_fin and !stream.fin_framed;
                if (waiting == 0 and !fin_owed) continue;

                // Type, stream id, offset and length, each at its widest.
                const overhead = 1 + varint.octets_max * 3;
                if (target.len <= overhead) return 0;
                // The comparison above is the guard on this subtraction:
                // `target` is what is left of the datagram after the header,
                // and a frame that does not fit its own overhead writes nothing.
                assert(target.len > overhead);
                const take = @min(waiting, target.len - overhead);
                assert(take <= waiting);
                const written = frame.encode(target, .{ .stream = .{
                    .stream = stream.id,
                    .offset = stream.send_offset + stream.framed,
                    .data = stream.send[stream.framed..][0..take],
                    .fin = stream.send_fin and stream.framed + take == stream.send_len,
                } }) catch return 0;

                const carries_fin = stream.send_fin and stream.framed + take == stream.send_len;
                result.stream = stream.id;
                result.stream_start = stream.framed;
                stream.framed += @intCast(take);
                result.stream_end = stream.framed;
                result.stream_fin = carries_fin;
                if (carries_fin) stream.fin_framed = true;
                return written;
            }
            return 0;
        }

        fn writeCrypto(self: *Self, target: []u8, stream: *CryptoLevel) usize {
            _ = self;
            const waiting = stream.pending[stream.framed..stream.pending_len];
            // The frame costs a type, an offset and a length. Reserving the
            // widest each is a few octets of slack against serializing twice.
            const overhead = 1 + varint.octets_max * 2;
            if (target.len <= overhead) return 0;
            const take = @min(waiting.len, target.len - overhead);
            const written = frame.encode(target, .{ .crypto = .{
                .offset = stream.framed,
                .data = waiting[0..take],
            } }) catch return 0;
            stream.framed += @intCast(take);
            return written;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-11
        //# An endpoint that detects an error SHOULD signal the existence of that
        //# error to its peer.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
        //# An endpoint that wishes to communicate a fatal
        //# connection error MUST use a CONNECTION_CLOSE frame if it is able.
        //
        // A connection here always has the state to frame one, and never sends
        // a Stateless Reset, so the rule below holds by having no other path.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-11
        //# A
        //# stateless reset MUST NOT be used by an endpoint that has the state
        //# necessary to send a frame on the connection.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
        //# Endpoints MUST send Stateless Resets formatted as a packet with a
        //# short header.  However, endpoints MUST treat any packet ending in a
        //# valid stateless reset token as a Stateless Reset, as other QUIC
        //# versions might allow the use of a long header.
        //= type=exception
        //= reason=stateless reset is out of scope; it is the answer of an endpoint that has *lost* the connection state, which is the consumer's lookup table rather than this type, and its token needs randomness that docs/DESIGN.md section 3 keeps outside the package. See docs/DESIGN.md section 2 and section 6.
        //
        /// Begin closing (section 10.2). The close frame goes out on the next
        /// `send`.
        pub fn close(self: *Self, code: error_code.Transport) void {
            if (self.state == .draining or self.state == .closing) return;
            self.state = .closing;
            self.close_code = @intFromEnum(code);
            self.close_is_application = false;
            self.close_pending = true;
        }

        /// Whether anything is waiting to go out. A caller with nothing else to
        /// do can skip building a datagram.
        pub fn wantsSend(self: *const Self) bool {
            if (self.state == .draining) return false;
            if (self.close_pending) return true;
            if (self.handshake_done_pending and !self.handshake_done_framed) return true;
            for (self.spaces) |space| {
                if (space.probes_pending > 0 and !space.discarded) return true;
            }
            if (self.streams.wantsSend()) return true;
            for (0..Level.count) |index| {
                const level: Level = @enumFromInt(index);
                if (self.send_keys[index] == null) continue;
                if (self.spaces[@intFromEnum(level.space())].discarded) continue;
                const stream = &self.levels[index];
                if (stream.framed < stream.pending_len) return true;
                if (self.spaces[@intFromEnum(level.space())].received.ack_eliciting_pending) return true;
            }
            return false;
        }
    };
}

const testing = std.testing;

/// Deliberately small. These tests exercise behaviour, not capacity, and a
/// connection at the default configuration is megabytes — see the note on
/// `footprint_octets`.
const TestConnection = Connection(.{
    .crypto_octets = 4096,
    .ack_ranges_max = 8,
    .sent_max = 32,
    .streams_max = 4,
    .stream_receive_octets = 8 * 1024,
    .stream_send_octets = 8 * 1024,
    .connection_receive_octets = 32 * 1024,
});

test "a connection's footprint is a number a consumer can price" {
    // Not a limit, a tripwire. The point of sizing everything at compile time
    // is that this number exists; a change that moves it by an order of
    // magnitude should be a decision rather than a surprise.
    try testing.expect(TestConnection.footprint_octets > 0);
    try testing.expect(TestConnection.footprint_octets < 256 * 1024);
}

const client_cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_source = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const server_source = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

fn testClient() TestConnection {
    return .init(.{
        .side = .client,
        .original_destination = ConnectionId.init(&client_cid) catch unreachable, // Eight octets.
        .source = ConnectionId.init(&client_source) catch unreachable, // Four octets.
    });
}

fn testServer() TestConnection {
    return .init(.{
        .side = .server,
        .original_destination = ConnectionId.init(&client_cid) catch unreachable, // As above.
        .source = ConnectionId.init(&server_source) catch unreachable, // Eight octets.
    });
}

/// Stand in for the TLS engine both sides would run.
///
/// A real handshake derives the same traffic secret on both endpoints from the
/// key exchange; this hands the same bytes to both, which is the same thing
/// from this package's point of view. That is the payoff of the seam being data
/// rather than a callback: the whole of TLS can be replaced by a constant in a
/// test, and what is left under test is the transport.
fn installBoth(a: *TestConnection, b: *TestConnection, level: Level, seed: u8) !void {
    const raw: [32]u8 = @splat(seed);
    const secret = try crypto.secrets.Secret.init(&raw);
    try a.installSecret(level, .send, &secret, .aes_128_gcm_sha256);
    try b.installSecret(level, .receive, &secret, .aes_128_gcm_sha256);
}

/// Move one datagram from `from` to `to`, returning its length.
fn deliver(from: *TestConnection, to: *TestConnection, now_ns: u64) !usize {
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try from.send(&datagram, now_ns);
    if (octets == 0) return 0;
    try to.receive(datagram[0..octets], now_ns);
    return octets;
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
//# A client MUST expand the payload of all UDP datagrams carrying
//# Initial packets to at least the smallest allowed maximum datagram
//# size of 1200 bytes by adding PADDING frames to the Initial packet or
//# by coalescing the Initial packet; see Section 12.2.
//= type=test
test "a client's first flight is a padded Initial carrying its CRYPTO bytes" {
    var client = testClient();
    var server = testServer();

    // What a TLS engine would have produced.
    try client.cryptoIn(.initial, "a ClientHello would be here");
    try testing.expect(client.wantsSend());

    const octets = try deliver(&client, &server, 0);
    // Section 14.1: a datagram carrying a client Initial is padded to 1200, so
    // a server knows the path carries a handshake before committing state.
    try testing.expectEqual(@as(usize, initial_datagram_min), octets);

    // The server has the handshake bytes, in order, ready for its TLS engine.
    try testing.expectEqualStrings("a ClientHello would be here", server.cryptoOut(.initial));
    // And it adopted the client's source identifier as its destination.
    try testing.expectEqualSlices(u8, &client_source, server.destination.bytes());
}

test "the server's reply completes the Initial exchange in both directions" {
    var client = testClient();
    var server = testServer();

    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    server.cryptoConsumed(.initial, server.cryptoOut(.initial).len);

    try server.cryptoIn(.initial, "ServerHello");
    const octets = try deliver(&server, &client, 1000);
    try testing.expect(octets > 0);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
    //# Similarly, a server MUST expand the payload of all UDP
    //# datagrams carrying ack-eliciting Initial packets to at least the
    //# smallest allowed maximum datagram size of 1200 bytes.
    //= type=test
    //
    // This line read `try testing.expect(octets < initial_datagram_min)`, with
    // the comment "a server does not pad: section 14.1's floor is the client's
    // obligation". Section 14.1 says the opposite in the sentence quoted above,
    // so the test was not merely silent about the requirement — it defended its
    // absence, which is the shape docs/VERIFICATION.md section 1 calls a test
    // that asserts the bug. This server's Initial carries CRYPTO and is
    // therefore ack-eliciting, so it is padded.
    try testing.expect(octets >= initial_datagram_min);
    try testing.expectEqualStrings("ServerHello", client.cryptoOut(.initial));

    // The server's packet carried an ACK for the client's Initial, which is
    // what moves the client's packet number encoding window.
    try testing.expectEqual(@as(?u64, 0), client.spaces[@intFromEnum(Space.initial)].largest_acked);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
//# Thus, a client MUST discard Initial keys when it first sends a
//# Handshake packet and a server MUST discard Initial keys when it first
//# successfully processes a Handshake packet.  Endpoints MUST NOT send
//# Initial packets after this point.
//= type=test
test "a handshake reaches 1-RTT through all three levels" {
    var client = testClient();
    var server = testServer();
    var now_ns: u64 = 0;

    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, now_ns);

    // Both sides derive Handshake keys. Installing them discards Initial, which
    // is section 4.9.1 of RFC 9001: keys anyone who saw the first packet can
    // compute are not kept.
    now_ns += 1000;
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try testing.expect(client.send_keys[@intFromEnum(Level.initial)] == null);
    try testing.expect(server.receive_keys[@intFromEnum(Level.initial)] == null);

    try server.cryptoIn(.handshake, "EncryptedExtensions, Certificate, Finished");
    _ = try deliver(&server, &client, now_ns);
    try testing.expectEqualStrings("EncryptedExtensions, Certificate, Finished", client.cryptoOut(.handshake));

    // 1-RTT keys, and the server confirms the handshake.
    now_ns += 1000;
    try installBoth(&server, &client, .one_rtt, 0x33);
    try installBoth(&client, &server, .one_rtt, 0x44);
    try client.cryptoIn(.handshake, "Finished");
    _ = try deliver(&client, &server, now_ns);
    try testing.expectEqualStrings("Finished", server.cryptoOut(.handshake));

    // HANDSHAKE_DONE is the server's alone, and it is what establishes the
    // connection for the client.
    try testing.expectEqual(State.handshaking, client.state);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const written = try frame.encode(&datagram, .handshake_done);
    try client.receiveFrame(.one_rtt, (try frame.parse(datagram[0..written])).frame, now_ns);
    try testing.expectEqual(State.established, client.state);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
//# Prior to validating the client address, servers MUST NOT send more
//# than three times as many bytes as the number of bytes they have
//# received.
//= type=test
test "section 8.1: a server may not amplify before the address is validated" {
    var server = testServer();
    // Nothing received, so nothing may be sent: an unvalidated address gets
    // three times zero.
    try testing.expectEqual(@as(u64, 0), server.sendRoom());

    var client = testClient();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);

    // 1200 octets in buys 3600 out, less whatever the ACK already cost.
    try testing.expect(server.sendRoom() > 0);
    try testing.expect(!server.address_validated);
    server.sent_octets = server.received_octets * amplification_factor;
    try testing.expectEqual(@as(u64, 0), server.sendRoom());

    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 0), try server.send(&datagram, 0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
//# For the purposes of
//# avoiding amplification prior to address validation, servers MUST
//# count all of the payload bytes received in datagrams that are
//# uniquely attributed to a single connection.
//= type=test
test "a Handshake packet validates the address and lifts the limit" {
    var client = testClient();
    var server = testServer();

    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    try testing.expect(!server.address_validated);

    try installBoth(&client, &server, .handshake, 0x22);
    try installBoth(&server, &client, .handshake, 0x11);
    try client.cryptoIn(.handshake, "Finished");
    _ = try deliver(&client, &server, 1000);

    // Section 8.1: a Handshake packet proves the peer holds keys only the real
    // one could have.
    try testing.expect(server.address_validated);
    try testing.expectEqual(@as(u64, TestConnection.datagram_octets), server.sendRoom());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-12.4
//# An endpoint MUST treat
//# receipt of a frame in a packet type that is not permitted as a
//# connection error of type PROTOCOL_VIOLATION.
//= type=test
test "section 12.4: a frame the level does not permit is a protocol violation" {
    var client = testClient();
    var server = testServer();
    var payload: [64]u8 = @splat(0);

    // A STREAM frame is application data, and an Initial packet is sent before
    // anybody is authenticated.
    const written = try frame.encode(&payload, .{
        .stream = .{ .stream = 0, .offset = 0, .data = "body", .fin = false },
    });
    try testing.expectError(error.Protocol, server.receiveFrames(.initial, payload[0..written], 0));

    // HANDSHAKE_DONE from a client is a client telling a server the handshake
    // finished.
    const done = try frame.encode(&payload, .handshake_done);
    try testing.expectError(error.Protocol, server.receiveFrames(.one_rtt, payload[0..done], 0));
    // The same frame is ordinary in the other direction.
    try client.receiveFrame(.one_rtt, (try frame.parse(payload[0..done])).frame, 0);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.1
//# An endpoint SHOULD treat receipt of an acknowledgment for a packet it
//# did not send as a connection error of type PROTOCOL_VIOLATION, if it
//# is able to detect the condition.
//= type=test
test "an ACK for a packet never sent is refused" {
    var client = testClient();
    var payload: [64]u8 = @splat(0);
    // The client has sent nothing, so acknowledging packet 0 is a peer claiming
    // to have seen something that does not exist — and it would move the packet
    // number encoding window somewhere this endpoint never was.
    const written = try frame.encode(&payload, .{ .ack = .{
        .largest = 0,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges = &.{},
        .ecn = null,
    } });
    try testing.expectError(error.Protocol, client.receiveFrames(.initial, payload[0..written], 0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
//# For example, if decryption fails (because the keys are
//# not available or for any other reason), the receiver MAY either
//# discard or buffer the packet for later processing and MUST attempt to
//# process the remaining packets.
//= type=test
test "a datagram that cannot be decrypted is discarded, not fatal" {
    var server = testServer();
    var datagram: [initial_datagram_min]u8 = @splat(0);
    // A long header with the right shape and the wrong keys. An off-path
    // attacker can inject this at will, so tearing the connection down on it
    // would be the attack rather than the defence.
    datagram[0] = 0xc3;
    std.mem.writeInt(u32, datagram[1..5], packet.version_1, .big);
    datagram[5] = 0;
    datagram[6] = 0;
    datagram[7] = 0;
    datagram[8] = 0x44;
    datagram[9] = 0x00;
    try server.receive(&datagram, 0);
    try testing.expectEqual(State.handshaking, server.state);
    try testing.expectEqual(@as(u32, 0), server.spaces[@intFromEnum(Space.initial)].received.count);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
//# A receiver MUST discard a newly unprotected packet unless it is
//# certain that it has not processed another packet with the same packet
//# number from the same packet number space.  Duplicate suppression MUST
//# happen after removing packet protection for the reasons described in
//# Section 9.5 of [QUIC-TLS].
//= type=test
test "a duplicate packet is not processed twice" {
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");

    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try client.send(&datagram, 0);
    var copy = datagram;
    try server.receive(datagram[0..octets], 0);
    try testing.expectEqualStrings("ClientHello", server.cryptoOut(.initial));

    // Section 12.3: the replay is discarded. Without the check the CRYPTO frame
    // would be pushed again — harmless here because the reassembler treats a
    // duplicate as free, which is exactly why both checks exist.
    try server.receive(copy[0..octets], 0);
    try testing.expectEqual(@as(u32, 1), server.spaces[@intFromEnum(Space.initial)].received.count);
    try testing.expectEqualStrings("ClientHello", server.cryptoOut(.initial));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
//# While otherwise identical to the closing state, an
//# endpoint in the draining state MUST NOT send any packets.
//= type=test
test "a CONNECTION_CLOSE puts the receiver in draining" {
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);

    client.close(.protocol_violation);
    try testing.expectEqual(State.closing, client.state);
    _ = try deliver(&client, &server, 1000);

    try testing.expectEqual(State.draining, server.state);
    try testing.expectEqual(@intFromEnum(error_code.Transport.protocol_violation), server.close_code);
    // Section 10.2.2: a draining endpoint sends nothing further.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 0), try server.send(&datagram, 2000));
    try testing.expect(!server.wantsSend());
}

test "handshake bytes larger than one packet span several" {
    var client = testClient();
    var server = testServer();

    // A certificate chain is the reason this case exists: it does not fit one
    // packet, and the CRYPTO frame's offset is what puts it back together.
    var chain: [3000]u8 = undefined;
    for (&chain, 0..) |*octet, index| octet.* = @truncate(index);
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try server.cryptoIn(.handshake, &chain);
    server.address_validated = true;

    var datagrams: u32 = 0;
    while (server.wantsSend() and datagrams < 8) : (datagrams += 1) {
        _ = try deliver(&server, &client, datagrams);
    }
    try testing.expect(datagrams >= 2);
    try testing.expectEqualSlices(u8, &chain, client.cryptoOut(.handshake));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-7.5
//# If an endpoint does not expand its buffer, it MUST close
//# the connection with a CRYPTO_BUFFER_EXCEEDED error code.
//= type=test
test "more handshake data than the buffer holds is refused rather than overrun" {
    var client = testClient();
    const oversized: [5000]u8 = @splat(0);
    try testing.expectError(error.CryptoBufferExceeded, client.cryptoIn(.initial, &oversized));
}

test "a send buffer smaller than a datagram is refused" {
    var client = testClient();
    var small: [64]u8 = @splat(0);
    try testing.expectError(error.BufferTooSmall, client.send(&small, 0));
}

test "transport parameters cross as opaque octets" {
    var client = testClient();
    try testing.expectEqual(@as(usize, 0), client.transportParametersOut().len);

    var encoded: [256]u8 = @splat(0);
    const written = try transport_parameters.encode(&encoded, &.{
        .initial_max_data = 1 << 20,
        .initial_source_connection_id = try ConnectionId.init(&server_source),
    });
    try client.transportParametersIn(encoded[0..written]);

    // Held rather than decoded: when they arrive is the TLS engine's business,
    // and what they mean is the consumer's.
    const parameters = try transport_parameters.parse(client.transportParametersOut());
    try testing.expectEqual(@as(u64, 1 << 20), parameters.initial_max_data);
}

test "a handshake survives a dropped datagram" {
    // The point of RFC 9002, end to end: without it this test hangs forever,
    // because QUIC has no retransmission of its own and a lost Initial is a
    // handshake that never starts.
    var client = testClient();
    var server = testServer();
    var now_ns: u64 = 0;

    try client.cryptoIn(.initial, "ClientHello");

    // The first flight goes out and is dropped on the floor.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const dropped = try client.send(&datagram, now_ns);
    try testing.expect(dropped > 0);
    try testing.expectEqualStrings("", server.cryptoOut(.initial));

    // Nothing is owed until the probe timeout, and the client knows when.
    const at = client.timeout().?;
    try testing.expect(at > now_ns);
    try testing.expect(!client.wantsSend());

    // The timer fires. Section 6.2.4: the probe carries the unacknowledged
    // handshake data rather than a bare PING, so the retransmission is the
    // thing that makes progress.
    now_ns = at;
    client.onTimeout(now_ns);
    try testing.expect(client.wantsSend());

    const octets = try deliver(&client, &server, now_ns);
    try testing.expect(octets > 0);
    try testing.expectEqualStrings("ClientHello", server.cryptoOut(.initial));
}

test "an acknowledgement stops the retransmission and resets the backoff" {
    var client = testClient();
    var server = testServer();

    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    // The server's answer carries an ACK.
    try server.cryptoIn(.initial, "ServerHello");
    _ = try deliver(&server, &client, 1000);

    try testing.expectEqual(@as(u32, 0), client.recovery.pto_count);
    // Section 5.3: the round trip was measured, so the 333ms default is gone.
    try testing.expect(client.recovery.has_rtt_sample);
    try testing.expect(client.recovery.smoothed_rtt < initial_rtt_reference);
    // And nothing is outstanding, so nothing is owed.
    try testing.expectEqual(@as(u32, 0), client.recovery.outstanding(.initial));
}

const initial_rtt_reference = @import("Recovery.zig").initial_rtt_ns;

test "a packet carrying only an ACK is not in flight" {
    // Section 2 of RFC 9002: acknowledgement traffic must not be throttled by
    // congestion control, or congestion feedback throttles itself.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);

    const before = server.recovery.bytes_in_flight;
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try server.send(&datagram, 1000);
    try testing.expect(octets > 0);
    // The server had nothing to say but an ACK.
    try testing.expectEqual(before, server.recovery.bytes_in_flight);
}

test "the timer is only about what is outstanding" {
    var client = testClient();
    // Nothing sent, nothing to wait for.
    try testing.expectEqual(@as(?u64, null), client.timeout());

    try client.cryptoIn(.initial, "ClientHello");
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 0);
    try testing.expect(client.timeout() != null);
}

/// Bring two connections to the point where 1-RTT keys are installed both ways,
/// which is where streams become legal.
fn established(client: *TestConnection, server: *TestConnection) !void {
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(client, server, 0);
    try installBoth(server, client, .handshake, 0x11);
    try installBoth(client, server, .handshake, 0x22);
    try installBoth(server, client, .one_rtt, 0x33);
    try installBoth(client, server, .one_rtt, 0x44);

    // RFC 9001 section 4.1.2: the server confirms on completing the handshake
    // and tells the client with HANDSHAKE_DONE. Both matter to RFC 9002, which
    // will not arm an application-data probe timeout before confirmation.
    var payload: [16]u8 = @splat(0);
    const written = try frame.encode(&payload, .handshake_done);
    _ = try client.receiveFrames(.one_rtt, payload[0..written], 0);

    // Section 18.2 defaults every stream limit to zero, so a peer that never
    // says otherwise has permitted nothing. A real handshake carries these in
    // the transport parameters; this is that exchange, spelled out.
    const permitted = @TypeOf(client.streams).streams_max;
    client.streams.setPeerStreamLimit(true, permitted);
    client.streams.setPeerStreamLimit(false, permitted);
    server.streams.setPeerStreamLimit(true, permitted);
    server.streams.setPeerStreamLimit(false, permitted);

    client.streams.setConnectionSendLimit(1 << 20);
    server.streams.setConnectionSendLimit(1 << 20);
    try client.streams.setSendLimit(0, 1 << 16);
    try server.streams.setSendLimit(0, 1 << 16);
    client.address_validated = true;
    server.address_validated = true;
}

test "a stream carries bytes from one connection to the other" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // Stream 0 is the first client-initiated bidirectional stream, which is
    // where RFC 9114 section 6.1 puts the first request.
    const taken = try client.write(0, "GET / HTTP/3-ish", true);
    try testing.expectEqual(@as(usize, 16), taken);
    try testing.expect(client.wantsSend());

    _ = try deliver(&client, &server, 1000);
    try testing.expectEqualStrings("GET / HTTP/3-ish", server.readable(0));
    // The FIN travelled with it, so the server knows the request is whole.
    try testing.expect(server.findStream(0).?.receive_state != .receiving);

    try server.consume(0, server.readable(0).len);
    try testing.expect(server.findStream(0).?.isComplete());
}

test "a response larger than one packet arrives in order" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    var body: [4096]u8 = undefined;
    for (&body, 0..) |*octet, index| octet.* = @truncate(index);
    var queued: usize = 0;
    var attempts: u32 = 0;
    while (attempts < 32 and queued < body.len) : (attempts += 1) {
        queued += try server.write(0, body[queued..], queued + 1 >= body.len);
    }
    try testing.expectEqual(body.len, queued);

    var rounds: u32 = 0;
    var received: [4096]u8 = undefined;
    var received_len: usize = 0;
    // `now_ns` only ever moves forward. A connection whose clock goes backwards is
    // one whose ACK delay is negative, and `AckRanges.write` asserts against it
    // — which is how the first version of this test failed.
    var now_ns: u64 = 1000;
    while (rounds < 16 and received_len < body.len) : (rounds += 1) {
        now_ns += 1000;
        _ = try deliver(&server, &client, now_ns);
        const ready = client.readable(0);
        @memcpy(received[received_len..][0..ready.len], ready);
        received_len += ready.len;
        try client.consume(0, ready.len);
        // The client's acknowledgements are what free the server's window.
        now_ns += 1000;
        _ = try deliver(&client, &server, now_ns);
    }
    try testing.expectEqual(body.len, received_len);
    try testing.expectEqualSlices(u8, &body, received[0..body.len]);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
//# A receiver MUST close the connection with an error of type
//# FLOW_CONTROL_ERROR if the sender violates the advertised connection
//# or stream data limits; see Section 11 for details on error handling.
//= type=test
test "section 4.1: a peer that sends past its limit is refused" {
    var server = testServer();
    var payload: [256]u8 = @splat(0);
    // Far past the stream window this connection advertised.
    const written = try frame.encode(&payload, .{ .stream = .{
        .stream = 0,
        .offset = 1 << 30,
        .data = "x",
        .fin = false,
    } });
    try testing.expectError(error.FlowControl, server.receiveFrames(.one_rtt, payload[0..written], 0));
}

test "the window is raised as the application reads" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    const before = server.max_data_sent;

    // Enough for the half-window heuristic to fire. `write` takes what fits and
    // answers how much — a zero is ordinary, not an error, and a loop that does
    // not expect one spins forever. This one did, the first time it was
    // written.
    var body: [40 * 1024]u8 = @splat('x');
    var queued: usize = 0;
    var rounds: u32 = 0;
    var now_ns: u64 = 1000;
    while (rounds < 64 and queued < body.len) : (rounds += 1) {
        queued += try client.write(0, body[queued..], false);
        now_ns += 1000;
        _ = try deliver(&client, &server, now_ns);
        const ready = server.readable(0);
        if (ready.len > 0) try server.consume(0, ready.len);
        now_ns += 1000;
        _ = try deliver(&server, &client, now_ns);
    }
    try testing.expect(queued > 0);
    // Section 4.1: reading is what moves the limit, and the peer learns about
    // it — otherwise a stream stalls forever at its initial window.
    try testing.expect(server.max_data_sent > before);
    try testing.expect(client.streams.send_limit > 0);
}

test "a lost stream packet is sent again" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    _ = try client.write(0, "the body", true);

    // Dropped on the floor.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 1000);
    try testing.expectEqualStrings("", server.readable(0));

    // The probe timeout rewinds the stream's send cursor, the same way it does
    // the CRYPTO stream's.
    const at = client.timeout().?;
    client.onTimeout(at);
    _ = try deliver(&client, &server, at);
    try testing.expectEqualStrings("the body", server.readable(0));
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
//# The receiver MUST use the final size of the stream to
//# account for all bytes sent on the stream in its connection-level flow
//# controller.
//= type=test
test "a RESET_STREAM ends the receive half and keeps its accounting" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    _ = try client.write(0, "partial", false);
    _ = try deliver(&client, &server, 1000);
    try testing.expectEqual(@as(u64, 7), server.streams.received_total);

    var payload: [64]u8 = @splat(0);
    const written = try frame.encode(&payload, .{ .reset_stream = .{
        .stream = 0,
        .code = .request_cancelled,
        .final_size = 7,
    } });
    _ = try server.receiveFrames(.one_rtt, payload[0..written], 2000);
    try testing.expectEqual(@import("Streams.zig").ReceiveState.reset, server.findStream(0).?.receive_state);
    // Section 4.1: the credit stays consumed, so resetting is not a way to
    // reuse the connection's window.
    try testing.expectEqual(@as(u64, 7), server.streams.received_total);
}

test "STOP_SENDING closes this endpoint's send half" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    _ = try client.write(0, "data", false);

    var payload: [64]u8 = @splat(0);
    const written = try frame.encode(&payload, .{ .stop_sending = .{
        .stream = 0,
        .code = .request_rejected,
    } });
    _ = try client.receiveFrames(.one_rtt, payload[0..written], 1000);
    try testing.expectError(error.Protocol, client.write(0, "more", false));
}

test "a STREAM frame before 1-RTT is a protocol violation" {
    var server = testServer();
    var payload: [64]u8 = @splat(0);
    const written = try frame.encode(&payload, .{ .stream = .{
        .stream = 0,
        .offset = 0,
        .data = "x",
        .fin = false,
    } });
    // Section 12.4's Table 3 already refuses this at the Initial and Handshake
    // levels; the check inside the frame handler is the second lock, for a
    // level that is permitted by the table but not by this package.
    try testing.expectError(error.Protocol, server.receiveFrames(.initial, payload[0..written], 0));
}

test "an HTTP/3 request crosses a QUIC stream and validates" {
    // The whole stack, end to end: QPACK encodes the field section, the HTTP/3
    // frame layer wraps it, a QUIC stream carries it, and the far side decodes
    // and checks it against RFC 9114 section 4.3. This is what everything in
    // this repository has been building toward.
    const h3 = @import("../root.zig");
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    const request = [_]h3.qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/catalog?page=3" },
        .{ .name = "user-agent", .value = "zrk" },
    };

    // QPACK, then the HEADERS frame around it.
    var section: [512]u8 = undefined;
    const section_octets = try h3.qpack.field_line.encode(&section, &request);
    var payload: [512]u8 = undefined;
    const header_octets = try h3.frame.writeHeader(&payload, .headers, section_octets);
    @memcpy(payload[header_octets..][0..section_octets], section[0..section_octets]);
    const message = payload[0 .. header_octets + section_octets];

    // RFC 9114 section 6.1: a request goes on a client-initiated bidirectional
    // stream, and stream 0 is the first of them.
    const id = h3.quic.stream_id.make(.client_bidirectional, 0);
    try testing.expectEqual(@as(u64, 0), id);
    var queued: usize = 0;
    var attempts: u32 = 0;
    while (attempts < 8 and queued < message.len) : (attempts += 1) {
        queued += try client.write(id, message[queued..], queued + 1 >= message.len);
    }
    try testing.expectEqual(message.len, queued);
    _ = try deliver(&client, &server, 1000);

    // And the far side reads it back.
    const received = server.readable(id);
    try testing.expectEqual(message.len, received.len);

    const frame_header = try h3.frame.parseHeader(received);
    try testing.expectEqual(h3.frame.Type.headers, frame_header.frame_type);
    try testing.expectEqual(@as(u64, section_octets), frame_header.length);

    var buffer: [512]u8 = undefined;
    var iterator = try h3.qpack.field_line.iterate(
        received[frame_header.octets..][0..@intCast(frame_header.length)],
        &buffer,
        1 << 16,
    );
    var validator: h3.fields.MessageValidator = .init(.{ .kind = .request });
    var seen: usize = 0;
    while (try iterator.next()) |one| {
        try validator.field(&one);
        try testing.expectEqualStrings(request[seen].name, one.name);
        try testing.expectEqualStrings(request[seen].value, one.value);
        seen += 1;
    }
    try validator.finish();
    try testing.expectEqual(request.len, seen);
}

test "a response crosses back, and a malformed one is caught" {
    const h3 = @import("../root.zig");
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // A response missing `:status` is not a message at all, and section 4.3.2
    // is what says so — the transport carried it perfectly well.
    var section: [256]u8 = undefined;
    const octets = try h3.qpack.field_line.encode(&section, &.{
        .{ .name = "content-length", .value = "0" },
    });
    var payload: [256]u8 = undefined;
    const header_octets = try h3.frame.writeHeader(&payload, .headers, octets);
    @memcpy(payload[header_octets..][0..octets], section[0..octets]);

    const id = h3.quic.stream_id.make(.client_bidirectional, 0);
    _ = try server.write(id, payload[0 .. header_octets + octets], true);
    _ = try deliver(&server, &client, 1000);

    const received = client.readable(id);
    const frame_header = try h3.frame.parseHeader(received);
    var buffer: [256]u8 = undefined;
    var iterator = try h3.qpack.field_line.iterate(
        received[frame_header.octets..][0..@intCast(frame_header.length)],
        &buffer,
        1 << 16,
    );
    var validator: h3.fields.MessageValidator = .init(.{ .kind = .response });
    while (try iterator.next()) |one| try validator.field(&one);
    try testing.expectError(error.PseudoMissing, validator.finish());
}

test "the amplification limit cannot be tuned into an underflow" {
    // Found by review and reproduced before it was fixed: an unvalidated
    // server's send room is `3 * received - sent`, which the peer chooses. Land
    // it where a header fits but the header plus the AEAD tag does not, and
    // `sendPacket` used to underflow computing the payload room — a panic in
    // the safe builds, an out-of-bounds slice in the one zrk ships.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);

    var spare: u64 = 0;
    while (spare < 128) : (spare += 1) {
        var probe = server;
        probe.sent_octets = probe.received_octets * amplification_factor - spare;
        var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
        const octets = try probe.send(&datagram, 1000);
        // Whatever it decides, it must be a packet that fits or no packet.
        try testing.expect(octets <= datagram.len);
    }
}

test "an inflated ACK delay is clamped rather than overflowing" {
    // The Delay field is an unbounded varint, and scaling it overflows `u64`
    // long before 2^62. Section 18.2 caps what the field can mean at 2^14 ms.
    var client = testClient();
    var payload: [32]u8 = @splat(0);
    try client.cryptoIn(.initial, "ClientHello");
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 0);

    for ([_]u64{ varint.max, varint.max - 1, 1 << 40, ack_delay_units_max, ack_delay_units_max + 1 }) |delay| {
        const written = try frame.encode(&payload, .{ .ack = .{
            .largest = 0,
            .delay = delay,
            .first_range = 0,
            .range_count = 0,
            .ranges = &.{},
            .ecn = null,
        } });
        var probe = client;
        _ = try probe.receiveFrames(.initial, payload[0..written], 1_000_000);
    }
}

test "a FIN is framed once, and the connection stops wanting to send" {
    // Before this was tracked, `wantsSend()` stayed true forever: nothing
    // recorded that the FIN had gone out, so every packet carried another empty
    // FIN frame. A consumer's loop that drains until `wantsSend()` is false
    // never terminated, and because each of those packets is ack-eliciting it
    // was a two-endpoint packet loop as well.
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    _ = try client.write(0, "body", true);

    var rounds: u32 = 0;
    var now_ns: u64 = 1000;
    while (rounds < 8 and client.wantsSend()) : (rounds += 1) {
        now_ns += 1000;
        _ = try deliver(&client, &server, now_ns);
    }
    try testing.expect(!client.wantsSend());
    try testing.expectEqualStrings("body", server.readable(0));
    try testing.expect(server.findStream(0).?.receive_state != .receiving);
}

test "a lost FIN is sent again even though it carries no octets" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    // The FIN rides alone: the data goes first, then the FIN in its own packet.
    _ = try client.write(0, "body", false);
    _ = try deliver(&client, &server, 1000);
    _ = try client.write(0, "", true);

    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 2000); // dropped
    try testing.expect(server.findStream(0).?.receive_state == .receiving);

    // A FIN records an empty byte range, so rewinding by offset cannot bring it
    // back — it is tracked separately for exactly this case.
    const at = client.timeout().?;
    client.onTimeout(at);
    _ = try deliver(&client, &server, at);
    try testing.expect(server.findStream(0).?.receive_state != .receiving);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.2
//# If a packet is successfully processed using the next key and IV, then
//# the peer has initiated a key update.  The endpoint MUST update its
//# send keys to the corresponding key phase in response, as described in
//# Section 6.1.
//= type=test
test "RFC 9001 section 6: a key update crosses the wire and the peer follows" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    try testing.expect(!client.one_rtt.phase);

    // Before: an ordinary packet in phase 0.
    _ = try client.write(0, "before", false);
    _ = try deliver(&client, &server, 1000);
    try testing.expectEqualStrings("before", server.readable(0));
    try server.consume(0, server.readable(0).len);

    // Section 6.1: the update toggles the phase and moves both directions —
    // the Key Phase bit is one bit shared by both peers.
    try testing.expect(client.canUpdateKeys());
    client.updateKeys();
    try testing.expect(client.one_rtt.phase);
    try testing.expect(client.one_rtt.previous_receive != null);

    _ = try client.write(0, "after", false);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try client.send(&datagram, 2000);
    // The bit is under header protection, so it is not readable here — what is
    // checkable is that the server follows it without being told.
    try server.receive(datagram[0..octets], 2000);
    try testing.expectEqualStrings("after", server.readable(0));
    // Section 6.2: opening under the next generation *is* the peer's update,
    // so the server moved with it.
    try testing.expect(server.one_rtt.phase);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# An endpoint MUST retain old keys until it has successfully
//# unprotected a packet sent using the new keys.
//= type=test
test "section 6.3: a packet reordered from before an update still opens" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // Sealed in phase 0, then held back while the client updates.
    _ = try client.write(0, "early", false);
    var held: [TestConnection.datagram_octets]u8 = @splat(0);
    const held_octets = try client.send(&held, 1000);

    client.updateKeys();
    _ = try client.write(0, "", false);

    // The old packet arrives after the update. Section 6.3 expects exactly this
    // for up to a PTO, which is why the outgoing generation is kept for reading.
    try server.receive(held[0..held_octets], 2000);
    try testing.expectEqualStrings("early", server.readable(0));
    // And it did not drag the server's phase along with it.
    try testing.expect(!server.one_rtt.phase);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# An endpoint MUST NOT initiate a key update prior to having confirmed
//# the handshake (Section 4.1.2).  An endpoint MUST NOT initiate a
//# subsequent key update unless it has received an acknowledgment for a
//# packet that was sent protected with keys from the current key phase.
//= type=test
test "section 6.1: no second update until the first is acknowledged" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    try testing.expect(client.canUpdateKeys());
    client.updateKeys();
    // Until something sent in this phase comes back acknowledged, the peer is
    // not known to hold the keys — a second update would leave it two
    // generations behind with only one bit to describe the gap.
    try testing.expect(!client.canUpdateKeys());

    _ = try client.write(0, "x", false);
    _ = try deliver(&client, &server, 1000);
    _ = try deliver(&server, &client, 2000); // carries the ACK
    try testing.expect(client.canUpdateKeys());
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# Endpoints MUST initiate a key update
//# before sending more protected packets than the confidentiality limit
//# for the selected AEAD permits.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# Endpoints MUST count the number of encrypted packets for each set of
//# keys.
//= type=test
test "section 6.6: the confidentiality limit updates keys rather than closing" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // The real limit is 2^23 packets; reaching it honestly would be a very long
    // test, so the counter is placed one short of it.
    client.one_rtt.sealed = crypto.confidentialityLimit(client.one_rtt.suite) - 1;
    const phase_before = client.one_rtt.phase;

    _ = try client.write(0, "trigger", false);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 1000);

    // "Endpoints MUST initiate a key update before sending more protected
    // packets than the confidentiality limit permits."
    try testing.expect(client.one_rtt.phase != phase_before);
    try testing.expectEqual(@as(u64, 0), client.one_rtt.sealed);
    try testing.expectEqual(State.established, client.state);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# If a key update is not possible or
//# integrity limits are reached, the endpoint MUST stop using the
//# connection and only send stateless resets in response to receiving
//# packets.  It is RECOMMENDED that endpoints immediately close the
//# connection with a connection error of type AEAD_LIMIT_REACHED before
//# reaching a state where key updates are not possible.
//= type=test
test "section 6.6: the confidentiality limit closes when no update is possible" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);
    client.one_rtt.sealed = crypto.confidentialityLimit(client.one_rtt.suite) - 1;
    // An update already in flight and unacknowledged, so section 6.1 forbids
    // another. The RFC's instruction then is to close rather than to keep
    // sealing past the limit.
    client.one_rtt.phase_acknowledged = false;

    _ = try client.write(0, "trigger", false);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    _ = try client.send(&datagram, 1000);
    try testing.expectEqual(State.closing, client.state);
    try testing.expectEqual(@intFromEnum(error_code.Transport.aead_limit_reached), client.close_code);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# In addition to counting packets sent, endpoints MUST count the number
//# of received packets that fail authentication during the lifetime of a
//# connection.  If the total number of received packets that fail
//# authentication within the connection, across all keys, exceeds the
//# integrity limit for the selected AEAD, the endpoint MUST immediately
//# close the connection with a connection error of type
//# AEAD_LIMIT_REACHED and not process any more packets.
//= type=test
test "section 6.6: forgeries past the integrity limit close the connection" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // A real packet with one payload octet flipped. It has to get *past* header
    // unprotection to be an authentication failure at all — an unsealed packet
    // fails the reserved-bits check first, which is a malformed header rather
    // than a forgery and rightly does not count.
    _ = try client.write(0, "payload that is long enough to sample", false);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try client.send(&datagram, 1000);
    datagram[octets - 1] ^= 0x01;

    // Section 5.4 says one failed packet is a discard, not an error: an
    // off-path attacker can inject them at will, so closing on one is the
    // attack. Section 6.6's counter is what bounds how long that can go on.
    // The real limit is 2^52, so the counter starts one short of it.
    server.forgeries = crypto.integrityLimit(server.one_rtt.suite) - 1;
    var first = datagram;
    try server.receive(first[0..octets], 1000);
    try testing.expectEqual(State.established, server.state);
    try testing.expectEqual(crypto.integrityLimit(server.one_rtt.suite), server.forgeries);

    // The one that passes the limit closes the connection and stops processing.
    var again = datagram;
    try testing.expectError(error.AeadLimitReached, server.receive(again[0..octets], 2000));
    try testing.expectEqual(State.closing, server.state);
    try testing.expectEqual(@intFromEnum(error_code.Transport.aead_limit_reached), server.close_code);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
//# A server MUST set the Destination Connection ID it
//# uses for sending packets based on the first received Initial packet.
//= type=test
test "section 7.2: a client's source connection id is fixed for the connection" {
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    try testing.expectEqualSlices(u8, &client_source, server.destination.bytes());

    // Initial keys derive from a connection identifier that travels in
    // cleartext, so anyone who watched the first flight can seal a valid
    // Initial. Re-adopting from one would let an off-path observer point every
    // subsequent server packet at an identifier the real client discards.
    var impostor = testClient();
    impostor.source = try ConnectionId.init(&.{ 0xde, 0xad, 0xbe, 0xef });
    // A packet number the server has not already seen, or duplicate suppression
    // discards it before the identifier is ever looked at — which is a real
    // defence, and would have made this test pass without the fix.
    impostor.spaces[@intFromEnum(Space.initial)].next = 9;
    try impostor.cryptoIn(.initial, "ClientHello");
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try impostor.send(&datagram, 1000);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    //# Any further changes to the Destination Connection ID are only
    //# permitted if the values are taken from NEW_CONNECTION_ID frames; if
    //# subsequent Initial packets include a different Source Connection ID,
    //# they MUST be discarded.
    //= type=test
    //
    // Discarded, and the connection carries on. This asserted `error.Protocol`
    // — a connection error — which reads like the stricter, safer answer and is
    // the opposite: closing hands the off-path observer exactly what it wants,
    // since one forged Initial then ends a connection it could otherwise only
    // watch. The RFC's remedy costs the attacker everything.
    try server.receive(datagram[0..octets], 1000);
    try testing.expectEqualSlices(u8, &client_source, server.destination.bytes());
    try testing.expect(server.state != .closing);
    try testing.expect(server.state != .draining);

    // And the real client is still heard.
    try client.cryptoIn(.initial, "more");
    _ = try deliver(&client, &server, 2000);
    try testing.expectEqualSlices(u8, &client_source, server.destination.bytes());
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
//# A server MUST discard an Initial packet that is carried in a UDP
//# datagram with a payload that is smaller than the smallest allowed
//# maximum datagram size of 1200 bytes.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9000#section-14
//# Therefore, an endpoint MUST NOT close a connection
//# when it receives a datagram that does not meet size constraints; the
//# endpoint MAY discard such datagrams.
//= type=test
test "section 14.1: an undersized Initial is discarded and buys no allowance" {
    var server = testServer();
    var client = testClient();
    try client.cryptoIn(.initial, "ClientHello");

    // A real first flight, truncated to below the 1200-octet floor. The padding
    // requirement exists so a server knows the path carries a handshake before
    // it commits anything; crediting a datagram it refuses to process would
    // sell three times its length in amplification allowance.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const full = try client.send(&datagram, 0);
    try testing.expectEqual(@as(usize, initial_datagram_min), full);
    try server.receive(datagram[0..600], 0);

    try testing.expectEqual(@as(u64, 0), server.received_octets);
    try testing.expectEqual(@as(u64, 0), server.sendRoom());
    try testing.expectEqualStrings("", server.cryptoOut(.initial));

    // The full-sized one is processed and does buy allowance.
    try server.receive(datagram[0..full], 0);
    try testing.expectEqual(@as(u64, initial_datagram_min), server.received_octets);
    try testing.expect(server.sendRoom() > 0);
}

//= https://www.rfc-editor.org/rfc/rfc9002#section-7
//# An endpoint MUST NOT send a packet if it would cause bytes_in_flight
//# (see Appendix B.2) to be larger than the congestion window, unless
//# the packet is sent on a PTO timer expiration (see Section 6.2) or
//# when entering recovery (see Section 7.3.2).
//= type=test
test "RFC 9002 section 7: a full congestion window stops the sender" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // Fill the window. Before this was wired, the window was computed, halved,
    // floored and tested, and then nothing consulted it: a sender with a
    // congestion window it does not obey has no congestion control.
    client.recovery.bytes_in_flight = client.recovery.congestion_window;
    try testing.expect(!client.recovery.canSend(1));

    _ = try client.write(0, "held back", false);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try client.send(&datagram, 1000);
    // Nothing ack-eliciting goes out, and the stream data is still queued
    // rather than lost — `rollback` put the send cursor back.
    try testing.expectEqual(@as(usize, 0), octets);
    try testing.expect(client.streams.wantsSend());

    // Room again, and it flows.
    client.recovery.bytes_in_flight = 0;
    _ = try deliver(&client, &server, 2000);
    try testing.expectEqualStrings("held back", server.readable(0));
}

test "a full window does not throttle acknowledgements" {
    // Section 2 of RFC 9002: a packet carrying only an ACK is not in flight, so
    // holding it back would throttle the feedback the window depends on — the
    // connection would wedge itself shut.
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    _ = try client.write(0, "data", false);
    _ = try deliver(&client, &server, 1000);
    try testing.expect(server.spaces[@intFromEnum(Space.application)].received.ack_eliciting_pending);

    server.recovery.bytes_in_flight = server.recovery.congestion_window;
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try server.send(&datagram, 2000);
    try testing.expect(octets > 0);
    try testing.expect(!server.spaces[@intFromEnum(Space.application)].received.ack_eliciting_pending);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
//# An endpoint that receives a CONNECTION_CLOSE frame MAY send a single
//# packet containing a CONNECTION_CLOSE frame before entering the
//# draining state, using a NO_ERROR code if appropriate.  An endpoint
//# MUST NOT send further packets.
//= type=test
test "section 10.2: a closing endpoint sends only CONNECTION_CLOSE" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // Give the client something it would otherwise want to send, and an
    // acknowledgement it would otherwise owe.
    _ = try client.write(0, "never sent", false);
    _ = try deliver(&server, &client, 1000);
    try testing.expect(client.spaces[@intFromEnum(Space.application)].received.ack_eliciting_pending);

    client.close(.protocol_violation);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try client.send(&datagram, 2000);
    try testing.expect(octets > 0);

    // Exactly one frame, and it is the close. Before this gated on `.closing`,
    // the packet also carried the ACK and the STREAM data — section 10.2 keeps
    // "only enough information to generate a packet containing a
    // CONNECTION_CLOSE frame", and sending progress on a connection that is
    // over tells the peer something untrue.
    _ = try server.receive(datagram[0..octets], 2001);
    try testing.expectEqual(State.draining, server.state);
    try testing.expectEqualStrings("", server.readable(0));
    // The stream data stayed queued rather than going out with the close.
    try testing.expect(client.streams.wantsSend());
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.2
//# The server MUST send a HANDSHAKE_DONE frame as soon as the handshake
//# is complete.
//= type=test
test "RFC 9001 section 4.1.2: the server sends HANDSHAKE_DONE" {
    // Found by sim/: the frame was handled on receipt and generated never, so
    // a client talking to this server stayed in `handshaking` for the life of
    // the connection. Nothing in the unit tests caught it because every one of
    // them injects the frame by hand — the helper below did too.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try installBoth(&server, &client, .one_rtt, 0x33);
    try installBoth(&client, &server, .one_rtt, 0x44);

    // Installing a 1-RTT send key is this seam's "the handshake is complete".
    try testing.expect(server.handshake_done_pending);
    try testing.expect(server.wantsSend());

    _ = try deliver(&server, &client, 1000);
    try testing.expectEqual(State.established, client.state);
    try testing.expect(client.recovery.handshake_confirmed);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
//# The HANDSHAKE_DONE frame MUST be retransmitted until it is
//# acknowledged.
//= type=test
test "a lost HANDSHAKE_DONE is sent again" {
    // It carries no byte range, so like a FIN it needs its own re-owing: a
    // client that missed it never confirms, and RFC 9002 section 6.2.1 then
    // declines to arm an application-data probe timeout for the rest of the
    // connection.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try installBoth(&server, &client, .one_rtt, 0x33);
    try installBoth(&client, &server, .one_rtt, 0x44);

    // Send it into the void, then declare the packet lost.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try server.send(&datagram, 1000);
    try testing.expect(octets > 0);
    try testing.expect(server.handshake_done_framed);
    try testing.expect(!server.wantsSend());

    // The loss path reported directly, which is what `onTimeout` would hand it.
    server.onPacketsLost(&.{.{ .level = .one_rtt, .handshake_done = true }});
    try testing.expect(!server.handshake_done_framed);
    try testing.expect(server.wantsSend());
}

test "RFC 9002 section 6.2.4: a probe carrying data still spends its credit" {
    // The credit used to be consumed on the PING path alone, so a probe that
    // carried CRYPTO — the case section 6.2.4 prefers, because it makes
    // progress — left `probes_pending` standing. A non-zero `probes_pending`
    // exempts a packet from the congestion window, so the window stopped
    // binding for the rest of the connection. sim/ found it as an overshoot
    // that three seeds reproduced exactly.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");

    const space = &client.spaces[@intFromEnum(Space.initial)];
    space.probes_pending = 2;
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    // The client has CRYPTO to send, so the probe carries it rather than a PING.
    const octets = try client.send(&datagram, 1000);
    try testing.expect(octets > 0);
    try testing.expectEqual(@as(u8, 1), space.probes_pending);
    _ = &server;
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.2
//# An endpoint MUST discard its Handshake keys when the TLS handshake is
//# confirmed (Section 4.1.2).
//= type=test
test "RFC 9001 section 4.9.2: a server discards its Handshake keys on confirmation" {
    // The client did this for itself on HANDSHAKE_DONE and the server did it
    // never, so a server's Handshake keys and Handshake packet number space
    // stayed live for the whole connection. It cannot be inferred from
    // installing 1-RTT send keys: at that moment the server has sent its own
    // Finished and still needs Handshake keys to read the client's.
    var client = testClient();
    var server = testServer();
    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, 0);
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try installBoth(&server, &client, .one_rtt, 0x33);
    try installBoth(&client, &server, .one_rtt, 0x44);

    // Still live: the client's Finished has not been processed yet.
    try testing.expect(server.send_keys[@intFromEnum(Level.handshake)] != null);
    try testing.expect(!server.spaces[@intFromEnum(Space.handshake)].discarded);

    server.confirmHandshake();
    try testing.expect(server.send_keys[@intFromEnum(Level.handshake)] == null);
    try testing.expect(server.receive_keys[@intFromEnum(Level.handshake)] == null);
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].discarded);
    try testing.expectEqual(State.established, server.state);

    // Idempotent: a consumer that calls it twice, or a client that already
    // discarded on HANDSHAKE_DONE, must not discard a space twice.
    server.confirmHandshake();
    try testing.expect(server.spaces[@intFromEnum(Space.handshake)].discarded);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-19.7
//# Clients MUST NOT send NEW_TOKEN frames.  A server MUST treat receipt
//# of a NEW_TOKEN frame as a connection error of type
//# PROTOCOL_VIOLATION.
//= type=test
test "section 19.7: a server refuses NEW_TOKEN" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    var payload: [64]u8 = @splat(0);
    const written = try frame.encode(&payload, .{ .new_token = .{ .token = "tok" } });
    try testing.expectError(
        error.Protocol,
        server.receiveFrames(.one_rtt, payload[0..written], 1000),
    );
    // A client has no rule to break here, so it keeps ignoring the frame.
    _ = try client.receiveFrames(.one_rtt, payload[0..written], 1000);
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
//# Receiving a STOP_SENDING frame for a
//# locally initiated stream that has not yet been created MUST be
//# treated as a connection error of type STREAM_STATE_ERROR.  An
//# endpoint that receives a STOP_SENDING frame for a receive-only stream
//# MUST terminate the connection with error STREAM_STATE_ERROR.
//= type=test
test "section 19.5: STOP_SENDING may not create a stream or stop a read-only one" {
    var client = testClient();
    var server = testServer();
    try established(&client, &server);

    // A stream the *client* would initiate, which the client has not opened.
    // `open` used to create it, so a peer could fill the table with
    // identifiers this endpoint never opened.
    const uncreated = stream_id.make(.client_bidirectional, 3);
    var payload: [64]u8 = @splat(0);
    var written = try frame.encode(&payload, .{ .stop_sending = .{
        .stream = uncreated,
        .code = @enumFromInt(0),
    } });
    try testing.expectError(
        error.StreamState,
        client.receiveFrames(.one_rtt, payload[0..written], 1000),
    );
    try testing.expect(client.findStream(uncreated) == null);

    // And a stream this endpoint may only read from: the peer is the only one
    // allowed to write on it, so asking us to stop is meaningless.
    var other = testClient();
    var peer = testServer();
    try established(&other, &peer);
    const theirs = stream_id.make(.server_unidirectional, 0);
    written = try frame.encode(&payload, .{ .stop_sending = .{
        .stream = theirs,
        .code = @enumFromInt(0),
    } });
    try testing.expectError(
        error.StreamState,
        other.receiveFrames(.one_rtt, payload[0..written], 1000),
    );
}
