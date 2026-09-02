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
//! ## Sized at compile time
//!
//! `Connection(config)` produces a type whose every buffer is a fixed array, so
//! a connection's footprint is a closed-form function of constants the consumer
//! picked and can print at startup. A peer's transport parameter is checked
//! *against* these limits and never used as one — see docs/TIGER_STYLE.md, "a
//! limit that is not comptime is a bug".
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
//! * **Retransmission and congestion control** are RFC 9002 (roadmap slice 3).
//!   The consequence is stated where it bites: CRYPTO bytes stay in their send
//!   buffer after being framed, so the data needed to retransmit is *held* —
//!   what is missing is the loss detection that decides to. A handshake over a
//!   lossy path stalls until that lands.
//! * **Streams and flow control** are roadmap slice 5. STREAM frames are
//!   refused rather than ignored, so a peer that sends one before this package
//!   can honour it gets an error instead of silence.
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

const Level = crypto.Level;
const Side = crypto.Side;
const Space = packet_number.Space;

/// RFC 9000 section 14.1: a datagram carrying a client Initial is padded to at
/// least this, so a server knows the path carries enough for a handshake before
/// it commits state to it.
pub const initial_datagram_min: u32 = 1200;

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
    };

    // The width a long header's Length field is reserved at: wide enough for
    // any length this connection can produce, and fixed, so the header's own
    // size does not change when the real length is written back into it.
    // Derived rather than chosen — a bigger datagram needs a wider field, and
    // nothing here has to be touched for it.
    const length_field_octets: u8 = varint.encodedLength(config.datagram_octets);

    return struct {
        const Self = @This();

        pub const datagram_octets: u32 = config.datagram_octets;

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

        pub const ReceiveError = error{
            /// A frame that section 12.4 does not permit at this encryption
            /// level, a reserved bit set, or a malformed frame.
            /// `PROTOCOL_VIOLATION` or `FRAME_ENCODING_ERROR`.
            Protocol,
            /// More handshake data than `crypto_octets`. RFC 9001 section 4.4's
            /// `CRYPTO_BUFFER_EXCEEDED`.
            CryptoBufferExceeded,
            /// A frame this slice does not implement — a STREAM frame, before
            /// slice 5 lands. Refused rather than ignored, so a peer gets an
            /// error instead of silence.
            Unsupported,
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
            const opened = keys.open(bytes, offset, space.received.largest()) catch return;

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
            _ = now;
            switch (one) {
                .padding, .ping => {},
                .ack => |value| {
                    const space = &self.spaces[@intFromEnum(level.space())];
                    // A peer cannot acknowledge a number we never sent; doing so
                    // would move our packet number encoding window somewhere we
                    // never were.
                    if (value.largest >= space.next) return error.Protocol;
                    space.largest_acked = @max(space.largest_acked orelse 0, value.largest);
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
                .new_token, .max_data, .max_stream_data, .max_streams => {},
                .data_blocked, .stream_data_blocked, .streams_blocked => {},
                // Slice 5. Refused rather than dropped: a peer that opened a
                // stream is waiting for an answer this package cannot give.
                .stream, .reset_stream, .stop_sending => return error.Unsupported,
            }
        }

        /// Section 4.9: drop a level's keys and its packet number space.
        fn discard(self: *Self, level: Level) void {
            self.send_keys[@intFromEnum(level)] = null;
            self.receive_keys[@intFromEnum(level)] = null;
            self.spaces[@intFromEnum(level.space())].discarded = true;
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
            const payload_room = buffer.len - header.header_octets - crypto.tag_octets;
            const payload_octets = self.writePayload(buffer[header.header_octets..][0..payload_room], level, now);
            if (payload_octets == 0) return error.Empty;

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

            const total = keys.seal(buffer, header.packet_number_offset, header.header_octets, payload_octets, number) catch return error.Empty;
            space.next += 1;
            return total;
        }

        fn writeHeader(self: *const Self, buffer: []u8, level: Level, number: u64, number_octets: u8) !packet.Written {
            return switch (level) {
                .one_rtt => packet.writeShort(buffer, .{
                    .destination = self.destination,
                    .number = number,
                    .number_octets = number_octets,
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

        /// Fill a payload: an ACK if one is owed, then whatever handshake bytes
        /// are waiting.
        fn writePayload(self: *Self, payload: []u8, level: Level, now: u64) usize {
            var offset: usize = 0;
            const space = &self.spaces[@intFromEnum(level.space())];

            if (space.received.ack_eliciting_pending) {
                // Section 13.2.5's delay exponent is the peer's transport
                // parameter; until this package decodes them it uses the
                // default, which is what section 18.2 says an absent one means.
                const written = space.received.write(payload[offset..], now, 3) catch null;
                if (written) |value| offset += value.octets;
            }

            const stream = &self.levels[@intFromEnum(level)];
            if (stream.framed < stream.pending_len) {
                offset += self.writeCrypto(payload[offset..], stream);
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
            return offset;
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

const TestConnection = Connection(.{ .crypto_octets = 4096, .ack_ranges_max = 8 });

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
