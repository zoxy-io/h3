//! The README's usage example, as a program that runs.
//!
//! One client Initial packet, built and then read back: a CRYPTO frame holding
//! what a ClientHello's octets would be, padded to the 1200 the specification
//! requires, sealed under the Initial keys, and then parsed and opened from the
//! other side. Every layer this package ships appears exactly once, in the
//! order a real client uses them.
//!
//! It is a compiled, run program rather than a snippet — `zig build example`,
//! and `zig build ci` runs it — so a usage example that stopped building fails
//! the build instead of greeting the next reader.

const std = @import("std");

const h3 = @import("h3");

const quic = h3.quic;

/// RFC 9000 section 14.1: a datagram carrying a client Initial packet must be
/// at least 1200 octets, so that a server can be sure the path carries enough
/// for a handshake before it commits any state to it.
const initial_datagram_min: usize = 1200;

pub fn main() !void {
    // What a TLS engine would have handed us. This package never builds it:
    // zoxy's comes from ztls and zrk's from zssl, and the bytes are opaque here.
    const client_hello = "<the octets of a ClientHello>";

    // 1. The connection identifiers. A real client draws the destination one at
    //    random; this package draws no randomness, so it arrives as an argument.
    const destination = try quic.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const source = try quic.ConnectionId.init(&.{ 0xc0, 0xff, 0xee });

    // 2. RFC 9001 section 5.2: the Initial keys come from the destination
    //    identifier of this very packet. Both sides can compute both halves.
    const send_keys: quic.crypto.Keys = .initial(destination.bytes(), .client);
    const receive_keys: quic.crypto.Keys = .initial(destination.bytes(), .client);

    var datagram: [initial_datagram_min]u8 = @splat(0);

    // 3. The payload: a CRYPTO frame, then PADDING to the required size. The
    //    padding is written by leaving the buffer zeroed, because PADDING *is*
    //    a zero octet (RFC 9000 section 19.1).
    var payload: [initial_datagram_min]u8 = @splat(0);
    const crypto_octets = try quic.frame.encode(&payload, .{
        .crypto = .{ .offset = 0, .data = client_hello },
    });

    // 4. The header. `writeLong` returns exactly the two offsets `seal` wants,
    //    which is the join this package exists to make.
    const payload_octets = payloadOctetsFor(crypto_octets);
    const written = try quic.packet.writeLong(&datagram, .{
        .long_type = .initial,
        .destination = destination,
        .source = source,
        .payload_octets = payload_octets,
        .number = 0,
        .number_octets = 4,
    });
    @memcpy(datagram[written.header_octets..][0..crypto_octets], payload[0..crypto_octets]);

    // 5. Packet protection, in place.
    const total = try send_keys.seal(
        &datagram,
        written.packet_number_offset,
        written.header_octets,
        payload_octets,
        0,
    );

    // --- The receiving side now sees `datagram[0..total]` off a UDP socket. ---

    // 6. Phase one of the parse: everything legible before the keys are
    //    involved, which is what tells us where the packet number begins.
    const parsed = try quic.packet.parse(datagram[0..total], 0);
    const initial = parsed.header.initial;

    // 7. Phase two: header protection off, packet number reconstructed, payload
    //    decrypted — all in the same buffer.
    const opened = try receive_keys.open(datagram[0..total], initial.packet_number_offset, null);

    // 8. The payload is a run of frames with no count and no separator.
    var frames: quic.frame.Iterator = .init(opened.payload);
    var crypto_bytes: usize = 0;
    var padding_octets: usize = 0;
    while (try frames.next()) |one| switch (one) {
        .crypto => |value| crypto_bytes += value.data.len,
        .padding => |value| padding_octets += value.octets,
        else => {},
    };

    std.debug.assert(opened.number == 0);
    std.debug.assert(crypto_bytes == client_hello.len);
    std.debug.assert(padding_octets > 0);
    std.debug.assert(total == initial_datagram_min);

    std.debug.print("initial packet: {d} octets, {d} of CRYPTO, {d} of PADDING\n", .{
        total,
        crypto_bytes,
        padding_octets,
    });
}

/// The payload has to fill the datagram out to 1200 octets once the header and
/// the tag are accounted for. Solved rather than guessed, because the header's
/// length field is itself variable-length: a longer payload can make the Length
/// field longer, which changes how much payload fits.
fn payloadOctetsFor(crypto_octets: usize) usize {
    // The header is fixed here — the identifiers, the token length and the
    // packet number are all known — so the only unknown is the Length field's
    // own width, and at 1200 octets it is two.
    const first_octet = 1;
    const version = 4;
    const identifiers = 1 + 8 + 1 + 3;
    const token_length = 1;
    const length_field = 2;
    const number = 4;
    const header = first_octet + version + identifiers + token_length + length_field + number;
    std.debug.assert(crypto_octets < initial_datagram_min - header);
    return initial_datagram_min - header - h3.quic.crypto.tag_octets;
}
