//! A QUIC connection: the state machine over `Reassembler` and `AckRanges`.
//!
//! Datagrams in, datagrams out, and handshake bytes crossing in both directions
//! as plain data. Nothing here opens a socket, reads a clock or runs a TLS
//! handshake — `now` is an argument, the caller owns the buffers, and the five
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
const lost_report_max: usize = 32;

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

/// RFC 9000 section 8.1: before a peer's address is validated, a server may
/// send no more than this multiple of what it has received. Without it a server
/// is a reflector for anyone who can spoof a source address.
pub const amplification_factor: u32 = 3;

pub const Config = struct {
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
        assert(config.datagram_octets >= initial_datagram_min);
        assert(config.datagram_octets <= 65_527);
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
        /// The limits last advertised, so a new one goes out only when it has
        /// moved enough to be worth a frame.
        max_data_sent: u64 = 0,
        max_streams_sent: u64 = 0,

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
            if (level == .handshake) self.discard(.initial);

            // RFC 9001 section 4.1.2: the handshake is confirmed at the *server*
            // when the handshake completes, which is when it can send 1-RTT — a
            // client waits for HANDSHAKE_DONE instead. This matters to RFC 9002
            // rather than to anything here: section 6.2.1 declines to arm an
            // application-data PTO before it, because 1-RTT keys may not exist
            // on both sides yet, and a connection that never confirms is a
            // connection whose 1-RTT packets are never retransmitted.
            if (level == .one_rtt and direction == .send and self.side == .server) {
                self.state = .established;
                self.recovery.handshake_confirmed = true;
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
                        const next = crypto.secrets.update(suite, secret);
                        self.one_rtt.next_receive = keys.nextGeneration(suite, &next);
                    },
                }
            }
        }

        /// Queue handshake bytes for sending at `level`.
        pub fn cryptoIn(self: *Self, level: Level, data: []const u8) error{CryptoBufferExceeded}!void {
            const stream = &self.levels[@intFromEnum(level)];
            if (stream.pending_len + data.len > config.crypto_octets) {
                return error.CryptoBufferExceeded;
            }
            @memcpy(stream.pending[stream.pending_len..][0..data.len], data);
            stream.pending_len += @intCast(data.len);
        }

        /// Handshake bytes received at `level`, in order. Borrows until the next
        /// `receive`.
        pub fn cryptoOut(self: *const Self, level: Level) []const u8 {
            return self.levels[@intFromEnum(level)].received.readable();
        }

        /// Release handshake bytes a TLS engine has taken.
        pub fn cryptoConsumed(self: *Self, level: Level, octets: usize) void {
            self.levels[@intFromEnum(level)].received.consume(octets);
        }

        /// The peer's transport parameters, as the extension's octets, or an
        /// empty slice before they arrive.
        pub fn transportParametersOut(self: *const Self) []const u8 {
            return self.peer_parameters[0..self.peer_parameters_len];
        }

        /// Hand over the peer's transport parameters extension.
        pub fn transportParametersIn(self: *Self, octets: []const u8) error{TooLarge}!void {
            if (octets.len > config.transport_parameters_octets) return error.TooLarge;
            @memcpy(self.peer_parameters[0..octets.len], octets);
            self.peer_parameters_len = @intCast(octets.len);
        }

        // ------------------------------------------------------------ receive

        /// RFC 9001 section 6.1: move to the next generation of 1-RTT keys.
        ///
        /// Both directions at once. The Key Phase bit is one bit shared by both
        /// peers, so an endpoint that updated only its write keys would be
        /// sending in a phase its own reader does not recognise.
        pub fn updateKeys(self: *Self) void {
            const one = &self.one_rtt;
            const send_secret = one.send_secret orelse return;
            const receive_secret = one.receive_secret orelse return;

            const next_send = crypto.secrets.update(one.suite, &send_secret);
            const next_receive = crypto.secrets.update(one.suite, &receive_secret);

            // The outgoing generation is kept for reading, not for writing:
            // section 6.3 expects reordered packets from the old phase for up
            // to a PTO after the update.
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
            /// RFC 9001 section 6.6: too many packets failed authentication, or
            /// a key reached its confidentiality limit with no update possible.
            /// `AEAD_LIMIT_REACHED`, and the connection stops here.
            AeadLimitReached,
        };

        /// Take one UDP datagram.
        ///
        /// Section 12.2: a datagram may carry several packets, and a packet that
        /// cannot be decrypted is *discarded* rather than fatal — an off-path
        /// attacker can inject anything, and tearing the connection down on one
        /// is the attack. So a decryption failure ends the datagram quietly and
        /// only a protocol violation by the authenticated peer returns an error.
        pub fn receive(self: *Self, datagram: []u8, now: u64) ReceiveError!void {
            self.received_octets += datagram.len;
            if (self.state == .draining) return;

            var offset: usize = 0;
            var packets: u32 = 0;
            while (offset < datagram.len) : (packets += 1) {
                assert(packets <= datagram.len);
                const parsed = packet.parse(datagram[offset..], self.source.length) catch return;
                const consumed = parsed.octets;
                assert(consumed >= 1);
                try self.receivePacket(datagram[offset..][0..consumed], parsed.header, now);
                offset += consumed;
            }
        }

        fn receivePacket(self: *Self, bytes: []u8, header: packet.Header, now: u64) ReceiveError!void {
            const level = header.level() orelse return; // Retry, Version Negotiation: not this slice.
            const offset = header.packetNumberOffset() orelse return;
            const index = @intFromEnum(level);
            if (self.spaces[@intFromEnum(level.space())].discarded) return;
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
            // anything.
            if (space.received.contains(opened.number)) return;

            // Section 8.1: receiving a Handshake packet proves the peer holds
            // keys only the real one could have, which validates the address.
            if (level == .handshake) self.address_validated = true;

            const eliciting = try self.receiveFrames(level, opened.payload, now);
            space.received.record(opened.number, now, eliciting);

            // A server adopts the client's source identifier as its destination
            // once it has a packet it could decrypt.
            if (self.side == .server) {
                switch (header) {
                    .initial => |value| self.destination = value.source,
                    else => {},
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
            const header = keys.unprotectHeader(bytes, offset, largest) catch return error.Discard;

            if (level != .one_rtt) {
                return keys.decrypt(bytes, header) catch return self.countForgery();
            }

            const one = &self.one_rtt;
            if (header.key_phase == one.phase) {
                return keys.decrypt(bytes, header) catch return self.countForgery();
            }

            // A phase that is not ours is either the peer starting an update or
            // a packet reordered from before ours. Both carry the opposite bit,
            // so there is nothing to tell them apart but trying: the next
            // generation first, then the previous.
            if (one.next_receive) |next| {
                if (next.decrypt(bytes, header)) |opened| {
                    // Section 6.2: a packet that opens under the next generation
                    // *is* the peer's update, and this endpoint follows it.
                    self.updateKeys();
                    return opened;
                } else |_| {}
            }
            if (one.previous_receive) |previous| {
                if (previous.decrypt(bytes, header)) |opened| return opened else |_| {}
            }
            return self.countForgery();
        }

        /// Section 6.6: count a packet that failed authentication, and close
        /// the connection once the integrity limit for the suite is passed.
        fn countForgery(self: *Self) error{ Discard, AeadLimitReached } {
            self.forgeries += 1;
            if (self.forgeries > crypto.integrityLimit(self.one_rtt.suite)) {
                self.close(.aead_limit_reached);
                return error.AeadLimitReached;
            }
            return error.Discard;
        }

        /// Walk the frames of one payload, returning whether any was
        /// ack-eliciting.
        fn receiveFrames(self: *Self, level: Level, payload: []const u8, now: u64) ReceiveError!bool {
            var iterator: frame.Iterator = .init(payload);
            var eliciting = false;
            var count: u32 = 0;
            while (count <= payload.len) : (count += 1) {
                const one = iterator.next() catch return error.Protocol;
                const value = one orelse break;
                // Section 12.4, Table 3. A STREAM frame in an Initial packet is
                // application data accepted before anyone is authenticated.
                if (!value.frameType().allowedIn(level)) return error.Protocol;
                if (value.ackEliciting()) eliciting = true;
                try self.receiveFrame(level, value, now);
            }
            return eliciting;
        }

        fn receiveFrame(self: *Self, level: Level, one: frame.Frame, now: u64) ReceiveError!void {
            switch (one) {
                .padding, .ping => {},
                .ack => |value| {
                    const space = &self.spaces[@intFromEnum(level.space())];
                    // A peer cannot acknowledge a number we never sent; doing so
                    // would move our packet number encoding window somewhere we
                    // never were.
                    if (value.largest >= space.next) return error.Protocol;
                    space.largest_acked = @max(space.largest_acked orelse 0, value.largest);
                    // Section 6.1: a second update waits for an acknowledgement
                    // of something sent in the current phase, which is what
                    // proves the peer has these keys.
                    if (level == .one_rtt) self.one_rtt.phase_acknowledged = true;

                    // Section 13.2.5: the delay is in microseconds, scaled by
                    // the exponent the peer advertised. Until the transport
                    // parameters are decoded this uses section 18.2's default,
                    // which is what an absent one means. Clamped before the
                    // shift — see `ack_delay_units_max`.
                    // The `u64` annotation is load-bearing. `@min` narrows its
                    // result type to fit the comptime-known bound, so
                    // `@min(x, 2_048_000)` is a `u21` — and `u21 << 3` needs
                    // twenty-four bits and overflows. The clamp written without
                    // it *created* the overflow it was added to prevent.
                    const delay_units: u64 = @min(value.delay, ack_delay_units_max);
                    const delay_ns: u64 = (delay_units << ack_delay_exponent_default) * std.time.ns_per_us;
                    assert(delay_ns <= ack_delay_ns_max);
                    var lost: [lost_report_max]PacketContext = undefined;
                    const result = self.recovery.onAckReceived(
                        level.space(),
                        value,
                        delay_ns,
                        now,
                        &lost,
                    ) catch return error.Protocol;
                    self.onPacketsLost(lost[0..@min(result.lost, lost.len)]);
                },
                .crypto => |value| {
                    const stream = &self.levels[@intFromEnum(level)];
                    stream.received.push(value.offset, value.data) catch |err| return switch (err) {
                        error.BeyondWindow, error.TooFragmented => error.CryptoBufferExceeded,
                        error.Inconsistent, error.FinalSizeViolated => error.Protocol,
                    };
                },
                .handshake_done => {
                    // Section 4.1.2 of RFC 9001: only a server sends it, and it
                    // is what confirms the handshake for a client.
                    if (self.side == .server) return error.Protocol;
                    self.state = .established;
                    self.recovery.handshake_confirmed = true;
                    self.discard(.handshake);
                },
                .connection_close => |value| {
                    self.close_code = value.code;
                    self.close_is_application = value.application;
                    // Section 10.2.2: a receiver enters draining and sends
                    // nothing further but a single close of its own.
                    self.state = .draining;
                },
                .new_connection_id, .retire_connection_id, .path_challenge, .path_response => {
                    // Migration is not this slice; the frames parse and are
                    // ignored rather than refused, because they are legal and a
                    // conforming peer may send them.
                },
                .new_token => {},
                .max_data => |value| self.streams.setConnectionSendLimit(value.maximum),
                .max_stream_data => |value| self.streams.setSendLimit(value.stream, value.maximum) catch |err| {
                    return streamError(err);
                },
                // Section 4.6's stream limits are the peer telling us how many
                // we may open. This package opens what its comptime bound
                // allows and no more, so a larger limit changes nothing and a
                // smaller one is already respected.
                .max_streams => {},
                // Section 4.1 and 4.6: the peer says it is blocked. Purely
                // informational — it is a signal that our advertised limit is
                // too low, and raising it is what `writePayload` already does
                // as the application reads.
                .data_blocked, .stream_data_blocked, .streams_blocked => {},
                .stream => |value| {
                    if (level != .one_rtt and level != .zero_rtt) return error.Protocol;
                    self.streams.receive(value.stream, value.offset, value.data, value.fin) catch |err| {
                        return streamError(err);
                    };
                },
                .reset_stream => |value| {
                    self.streams.reset(value.stream, @intFromEnum(value.code), value.final_size) catch |err| {
                        return streamError(err);
                    };
                },
                // Section 3.5: the peer wants us to stop sending. Recorded as a
                // reset of our send half; what to tell the application is the
                // consumer's decision.
                .stop_sending => |value| {
                    const stream = self.streams.open(value.stream) catch |err| return streamError(err);
                    stream.send_state = .reset;
                    stream.reset_code = @intFromEnum(value.code);
                },
            }
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
            return stream.readable();
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
            for (contexts) |context| {
                if (context.crypto_end > context.crypto_start) {
                    const level = &self.levels[@intFromEnum(context.level)];
                    level.framed = @min(level.framed, context.crypto_start);
                }
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
            if (self.state == .draining) return null;
            return self.recovery.timeoutAt();
        }

        /// Section A.9 of RFC 9002: the timer fired.
        pub fn onTimeout(self: *Self, now: u64) void {
            var lost: [lost_report_max]PacketContext = undefined;
            switch (self.recovery.onLossDetectionTimeout(now, &lost)) {
                .lost => |count| self.onPacketsLost(lost[0..@min(count, lost.len)]),
                // Section 6.2.4: nothing is known to be lost and the peer has
                // gone quiet, so send something it must answer — and where
                // there is unacknowledged data, that rather than a bare PING,
                // because a probe that carries the handshake makes progress and
                // a probe that carries nothing only asks whether the path is
                // alive. The PING in `writePayload` is the fallback for when
                // there is no data to resend.
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
        pub fn send(self: *Self, buffer: []u8, now: u64) SendError!usize {
            if (buffer.len < config.datagram_octets) return error.BufferTooSmall;
            if (self.state == .draining) return 0;

            const room = self.sendRoom();
            if (room == 0) return 0;
            const limit = @min(room, config.datagram_octets);

            var offset: usize = 0;
            // Section 12.2: levels are coalesced oldest first, so a peer that
            // has not yet installed later keys still gets the earlier packet.
            for ([_]Level{ .initial, .handshake, .one_rtt }) |level| {
                offset += self.sendPacket(buffer[offset..limit], level, now) catch 0;
            }
            if (offset == 0) return 0;

            // Section 14.1: a datagram carrying a client Initial is padded to
            // 1200 octets. The padding is zeroes, which *is* a PADDING frame,
            // but it goes outside the packet rather than inside it — this
            // endpoint has already sealed by now, and section 12.2 allows a
            // datagram to be longer than the packets it carries.
            if (self.side == .client and self.send_keys[@intFromEnum(Level.initial)] != null) {
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
            if (level != .one_rtt) {
                self.sealed[@intFromEnum(level)] += 1;
                if (self.sealed[@intFromEnum(level)] >= crypto.confidentialityLimit(secrets_suite_initial)) {
                    self.close(.aead_limit_reached);
                }
                return;
            }
            self.one_rtt.sealed += 1;
            if (self.one_rtt.sealed < crypto.confidentialityLimit(self.one_rtt.suite)) return;
            if (self.canUpdateKeys()) {
                self.updateKeys();
                return;
            }
            self.close(.aead_limit_reached);
        }

        /// Section 8.1: what a server may still send before the address is
        /// validated. A client, and a validated server, are unbounded here and
        /// bounded by the datagram size instead.
        fn sendRoom(self: *const Self) u64 {
            if (self.address_validated) return config.datagram_octets;
            const allowance = self.received_octets * amplification_factor;
            if (allowance <= self.sent_octets) return 0;
            return @min(allowance - self.sent_octets, config.datagram_octets);
        }

        /// One packet at one level, or `error.Empty` when the level has nothing
        /// to say.
        fn sendPacket(self: *Self, buffer: []u8, level: Level, now: u64) !usize {
            const index = @intFromEnum(level);
            const keys = self.send_keys[index] orelse return error.Empty;
            const space = &self.spaces[@intFromEnum(level.space())];
            if (space.discarded) return error.Empty;

            const number = space.next;
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
            };
            const written = self.writePayload(buffer[header.header_octets..][0..payload_room], level, now);
            const payload_octets = written.octets;
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

            const total = keys.seal(buffer, header.packet_number_offset, header.header_octets, payload_octets, number) catch {
                self.rollback(level, undo, written);
                return error.Empty;
            };
            space.next += 1;
            self.countSealed(level);

            // Section 2 of RFC 9002: a packet is in flight when it is
            // ack-eliciting or padded, and only ack-eliciting packets oblige
            // the peer to answer. A packet carrying nothing but an ACK is
            // neither, so that congestion control cannot throttle the feedback
            // it depends on.
            self.recovery.onPacketSent(level.space(), .{
                .number = number,
                .time_sent = now,
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
                },
            }) catch {};
            return total;
        }

        fn writeHeader(self: *const Self, buffer: []u8, level: Level, number: u64, number_octets: u8) !packet.Written {
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
        };

        /// Put back everything `writePayload` committed. Called on every path
        /// out of `sendPacket` that does not produce a packet.
        fn rollback(self: *Self, level: Level, undo: Undo, written: Payload) void {
            const space = &self.spaces[@intFromEnum(level.space())];
            space.received.ack_eliciting_pending = undo.ack_eliciting_pending;
            space.probes_pending = undo.probes_pending;
            self.close_pending = undo.close_pending;
            self.levels[@intFromEnum(level)].framed = undo.crypto_framed;
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
        };

        /// Fill a payload: an ACK if one is owed, then whatever handshake bytes
        /// are waiting.
        fn writePayload(self: *Self, payload: []u8, level: Level, now: u64) Payload {
            var result: Payload = .{};
            var offset: usize = 0;
            const space = &self.spaces[@intFromEnum(level.space())];

            if (space.received.ack_eliciting_pending) {
                // Section 13.2.5's delay exponent is the peer's transport
                // parameter; until this package decodes them it uses the
                // default, which is what section 18.2 says an absent one means.
                const written = space.received.write(payload[offset..], now, 3) catch null;
                if (written) |value| offset += value.octets;
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
                space.probes_pending -= 1;
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
            if (level == .one_rtt) {
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

        /// Frame whatever one stream has waiting.
        ///
        /// One stream per packet rather than as many as fit: a packet carrying
        /// two streams' data has to record two ranges to undo on loss, and the
        /// gain is a few octets of header on a path that is already
        /// AEAD-bound.
        fn writeStream(self: *Self, target: []u8, result: *Payload) usize {
            for (self.streams.streams[0..self.streams.count]) |*stream| {
                const waiting = stream.send_len - stream.framed;
                // Owed once. Without `fin_framed` this was permanently true,
                // so every packet carried another empty FIN and `wantsSend`
                // never answered false again.
                const fin_owed = stream.send_fin and !stream.fin_framed;
                if (waiting == 0 and !fin_owed) continue;

                // Type, stream id, offset and length, each at its widest.
                const overhead = 1 + varint.octets_max * 3;
                if (target.len <= overhead) return 0;
                const take = @min(waiting, target.len - overhead);
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
fn deliver(from: *TestConnection, to: *TestConnection, now: u64) !usize {
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const octets = try from.send(&datagram, now);
    if (octets == 0) return 0;
    try to.receive(datagram[0..octets], now);
    return octets;
}

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
    // A server does not pad: section 14.1's floor is the client's obligation.
    try testing.expect(octets < initial_datagram_min);
    try testing.expectEqualStrings("ServerHello", client.cryptoOut(.initial));

    // The server's packet carried an ACK for the client's Initial, which is
    // what moves the client's packet number encoding window.
    try testing.expectEqual(@as(?u64, 0), client.spaces[@intFromEnum(Space.initial)].largest_acked);
}

test "a handshake reaches 1-RTT through all three levels" {
    var client = testClient();
    var server = testServer();
    var now: u64 = 0;

    try client.cryptoIn(.initial, "ClientHello");
    _ = try deliver(&client, &server, now);

    // Both sides derive Handshake keys. Installing them discards Initial, which
    // is section 4.9.1 of RFC 9001: keys anyone who saw the first packet can
    // compute are not kept.
    now += 1000;
    try installBoth(&server, &client, .handshake, 0x11);
    try installBoth(&client, &server, .handshake, 0x22);
    try testing.expect(client.send_keys[@intFromEnum(Level.initial)] == null);
    try testing.expect(server.receive_keys[@intFromEnum(Level.initial)] == null);

    try server.cryptoIn(.handshake, "EncryptedExtensions, Certificate, Finished");
    _ = try deliver(&server, &client, now);
    try testing.expectEqualStrings("EncryptedExtensions, Certificate, Finished", client.cryptoOut(.handshake));

    // 1-RTT keys, and the server confirms the handshake.
    now += 1000;
    try installBoth(&server, &client, .one_rtt, 0x33);
    try installBoth(&client, &server, .one_rtt, 0x44);
    try client.cryptoIn(.handshake, "Finished");
    _ = try deliver(&client, &server, now);
    try testing.expectEqualStrings("Finished", server.cryptoOut(.handshake));

    // HANDSHAKE_DONE is the server's alone, and it is what establishes the
    // connection for the client.
    try testing.expectEqual(State.handshaking, client.state);
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const written = try frame.encode(&datagram, .handshake_done);
    try client.receiveFrame(.one_rtt, (try frame.parse(datagram[0..written])).frame, now);
    try testing.expectEqual(State.established, client.state);
}

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
    var now: u64 = 0;

    try client.cryptoIn(.initial, "ClientHello");

    // The first flight goes out and is dropped on the floor.
    var datagram: [TestConnection.datagram_octets]u8 = @splat(0);
    const dropped = try client.send(&datagram, now);
    try testing.expect(dropped > 0);
    try testing.expectEqualStrings("", server.cryptoOut(.initial));

    // Nothing is owed until the probe timeout, and the client knows when.
    const at = client.timeout().?;
    try testing.expect(at > now);
    try testing.expect(!client.wantsSend());

    // The timer fires. Section 6.2.4: the probe carries the unacknowledged
    // handshake data rather than a bare PING, so the retransmission is the
    // thing that makes progress.
    now = at;
    client.onTimeout(now);
    try testing.expect(client.wantsSend());

    const octets = try deliver(&client, &server, now);
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
    // `now` only ever moves forward. A connection whose clock goes backwards is
    // one whose ACK delay is negative, and `AckRanges.write` asserts against it
    // — which is how the first version of this test failed.
    var now: u64 = 1000;
    while (rounds < 16 and received_len < body.len) : (rounds += 1) {
        now += 1000;
        _ = try deliver(&server, &client, now);
        const ready = client.readable(0);
        @memcpy(received[received_len..][0..ready.len], ready);
        received_len += ready.len;
        try client.consume(0, ready.len);
        // The client's acknowledgements are what free the server's window.
        now += 1000;
        _ = try deliver(&client, &server, now);
    }
    try testing.expectEqual(body.len, received_len);
    try testing.expectEqualSlices(u8, &body, received[0..body.len]);
}

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
    var now: u64 = 1000;
    while (rounds < 64 and queued < body.len) : (rounds += 1) {
        queued += try client.write(0, body[queued..], false);
        now += 1000;
        _ = try deliver(&client, &server, now);
        const ready = server.readable(0);
        if (ready.len > 0) try server.consume(0, ready.len);
        now += 1000;
        _ = try deliver(&server, &client, now);
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
    var validator: h3.fields.MessageValidator = .init(.request);
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
    var validator: h3.fields.MessageValidator = .init(.response);
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
    var now: u64 = 1000;
    while (rounds < 8 and client.wantsSend()) : (rounds += 1) {
        now += 1000;
        _ = try deliver(&client, &server, now);
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
