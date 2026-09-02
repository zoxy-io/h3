//! The QUIC transport: RFC 9000 (transport), RFC 9001 (packet protection over
//! TLS) and RFC 9002 (loss detection and congestion control).
//!
//! Three RFCs in one namespace because they are one protocol. RFC 9000 cannot
//! be read without RFC 9001 — the bits saying how long a packet number is are
//! themselves encrypted — and cannot be *used* without RFC 9002, because a
//! sender with no loss detection stalls the first time a datagram is dropped.
//! Splitting them into three namespaces would produce three that no consumer
//! can use one of.
//!
//! What stays outside is the TLS handshake and the UDP socket. See
//! `crypto.zig` for the first and docs/DESIGN.md for both.

const std = @import("std");

pub const AckRanges = @import("quic/AckRanges.zig").AckRanges;
pub const ConnectionId = @import("quic/ConnectionId.zig");
pub const crypto = @import("quic/crypto.zig");
pub const error_code = @import("quic/error_code.zig");
pub const frame = @import("quic/frame.zig");
pub const connection = @import("quic/Connection.zig");
pub const Connection = connection.Connection;
pub const Reassembler = @import("quic/Reassembler.zig").Reassembler;
pub const packet = @import("quic/packet.zig");
pub const packet_number = @import("quic/packet_number.zig");
pub const stream_id = @import("quic/stream_id.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");

test {
    _ = @import("quic/AckRanges.zig");
    _ = ConnectionId;
    _ = crypto;
    _ = error_code;
    _ = frame;
    _ = connection;
    _ = @import("quic/Reassembler.zig");
    _ = packet;
    _ = packet_number;
    _ = stream_id;
    _ = transport_parameters;
}
