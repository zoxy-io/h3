//! Conformance against RFC 9001 Appendix A's worked packets.
//!
//! Everything else in this package checks the protection path against itself: a
//! packet is sealed and then opened, and the two agree. That catches a great
//! deal and cannot, even in principle, catch a *shared* misreading — a nonce
//! built wrong in both directions, associated data that omits the same octets
//! twice, a header protection mask sampled from the same wrong offset. This
//! file is the answer to that: complete packets the RFC's authors produced,
//! compared octet for octet.
//!
//! Lives outside `src/` because it embeds fixtures no consumer needs, and
//! because a corpus that ships to consumers is 1200 octets of test data in
//! everyone's dependency tree.
//!
//! The vectors themselves are machine-lifted; see `extract.py` and README.md.

const std = @import("std");

const h3 = @import("h3");
const vectors = @import("rfc9001_vectors.zig");

const quic = h3.quic;

/// RFC 9001 section 5.4.2: the packet number of A.2's Initial sits 18 octets
/// in, which is what the appendix's own `header[18..21] ^= mask[1..4]` says.
const client_packet_number_offset: usize = 18;
const client_header_octets: usize = 22;
const client_packet_number: u64 = 2;

/// A.3's server Initial: a two-octet packet number after an eight-octet source
/// connection ID and no destination one, so the offset lands in the same place
/// for a different reason.
const server_packet_number_offset: usize = 18;
const server_header_octets: usize = 20;
const server_packet_number: u64 = 1;

/// A.5: a short header over an empty destination connection ID, so the packet
/// number begins immediately after the first octet.
const chacha_packet_number_offset: usize = 1;
const chacha_header_octets: usize = 4;
const chacha_packet_number: u64 = 654_360_564;

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The secret used by clients to construct Initial packets uses the PRK and
//# the label "client in" as input to the HKDF-Expand-Label function from
//# TLS [TLS13] to produce a 32-byte secret. Packets constructed by the
//# server use the same process with the label "server in".
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# The current encryption level secret and the label "quic key" are input
//# to the KDF to produce the AEAD key; the label "quic iv" is used to
//# derive the Initialization Vector (IV); see Section 5.3. The header
//# protection key uses the "quic hp" label; see Section 5.4.
//= type=test
test "A.1: the Initial secrets and both sides' keys" {
    // src/quic/crypto/ tests these too. They are repeated here so that the
    // corpus is the whole appendix rather than the parts left over, and so a
    // failure further down has one obvious first thing to rule out.
    const client_secret = quic.crypto.secrets.initial(&vectors.destination_connection_id, .client);
    try std.testing.expectEqualSlices(u8, &vectors.client_initial_secret, client_secret.bytes());

    const client_keys: quic.crypto.Keys = .initial(&vectors.destination_connection_id, .client);
    try std.testing.expectEqualSlices(u8, &vectors.client_key, client_keys.key());
    try std.testing.expectEqualSlices(u8, &vectors.client_iv, &client_keys.iv);
    try std.testing.expectEqualSlices(u8, &vectors.client_hp, client_keys.headerKey());

    const server_secret = quic.crypto.secrets.initial(&vectors.destination_connection_id, .server);
    try std.testing.expectEqualSlices(u8, &vectors.server_initial_secret, server_secret.bytes());

    const server_keys: quic.crypto.Keys = .initial(&vectors.destination_connection_id, .server);
    try std.testing.expectEqualSlices(u8, &vectors.server_key, server_keys.key());
    try std.testing.expectEqualSlices(u8, &vectors.server_iv, &server_keys.iv);
    try std.testing.expectEqualSlices(u8, &vectors.server_hp, server_keys.headerKey());
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# The associated data, A, for the AEAD is the contents of the QUIC header,
//# starting from the first byte of either the short or long header, up to
//# and including the unprotected packet number. The input plaintext, P, for
//# the AEAD is the payload of the QUIC packet, as described in
//# [QUIC-TRANSPORT]. The output ciphertext, C, of the AEAD is transmitted
//# in place of P.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
//# The output of this algorithm is a 5-byte mask that is applied to the
//# protected header fields using exclusive OR. The least significant bits
//# of the first byte of the packet are masked by the least significant bits
//# of the first mask byte, and the packet number is masked with the
//# remaining bytes.
//= type=test
test "A.2: sealing the client Initial reproduces the RFC's packet exactly" {
    // The strongest test in the package. Every part of the protection path has
    // to be right at once for these 1200 octets to match: the nonce, the
    // associated data, the AEAD, the sampling offset, the mask, and which bits
    // of the first octet the mask applies to.
    const keys: quic.crypto.Keys = .initial(&vectors.destination_connection_id, .client);

    var datagram: [vectors.client_initial_protected.len]u8 = @splat(0);
    @memcpy(datagram[0..client_header_octets], &vectors.client_initial_header);
    @memcpy(datagram[client_header_octets..][0..vectors.client_initial_payload.len], &vectors.client_initial_payload);

    const total = try keys.seal(
        &datagram,
        client_packet_number_offset,
        client_header_octets,
        vectors.client_initial_payload.len,
        client_packet_number,
    );
    try std.testing.expectEqual(vectors.client_initial_protected.len, total);
    try std.testing.expectEqualSlices(u8, &vectors.client_initial_protected, datagram[0..total]);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# When processing packets, an endpoint first removes the header
//# protection.
//= type=test
test "A.2: opening the RFC's packet recovers its payload" {
    const keys: quic.crypto.Keys = .initial(&vectors.destination_connection_id, .client);

    var datagram = vectors.client_initial_protected;
    const parsed = try quic.packet.parse(&datagram, 0);
    try std.testing.expectEqual(quic.packet.Kind.initial, @as(quic.packet.Kind, parsed.header));
    try std.testing.expectEqual(datagram.len, parsed.octets);

    const initial = parsed.header.initial;
    try std.testing.expectEqual(client_packet_number_offset, initial.packet_number_offset);
    try std.testing.expectEqualSlices(u8, &vectors.destination_connection_id, initial.destination.bytes());
    try std.testing.expect(initial.source.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), initial.token.len);

    const opened = try keys.open(&datagram, initial.packet_number_offset, null);
    try std.testing.expectEqual(client_packet_number, opened.number);
    try std.testing.expectEqual(@as(u8, 4), opened.number_octets);
    try std.testing.expectEqualSlices(u8, &vectors.client_initial_payload, opened.payload);
}

test "A.2: the frames the RFC's payload decodes to" {
    // The payload is a CRYPTO frame carrying a ClientHello, then PADDING out to
    // 1162 octets. Reading it back is what ties `quic.frame` to a real packet
    // rather than to a frame this package built for itself.
    var iterator: quic.frame.Iterator = .init(&vectors.client_initial_payload);

    const crypto_frame = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u64, 0), crypto_frame.crypto.offset);
    try std.testing.expectEqual(vectors.client_initial_crypto_frame.len - 4, crypto_frame.crypto.data.len);
    // The first octet of a TLS ClientHello handshake message.
    try std.testing.expectEqual(@as(u8, 0x01), crypto_frame.crypto.data[0]);

    const padding = (try iterator.next()).?;
    try std.testing.expectEqual(
        vectors.client_initial_payload.len - vectors.client_initial_crypto_frame.len,
        padding.padding.octets,
    );
    try std.testing.expectEqual(@as(?quic.frame.Frame, null), try iterator.next());
}

test "A.2: writeLong builds the header the RFC printed" {
    // The other direction on the same octets: this package's header writer has
    // to produce what the appendix shows, or `seal` above was handed a header
    // no consumer of this package would ever produce.
    var target: [64]u8 = @splat(0);
    const written = try quic.packet.writeLong(&target, .{
        .long_type = .initial,
        .destination = try quic.ConnectionId.init(&vectors.destination_connection_id),
        .source = try quic.ConnectionId.init(&.{}),
        .payload_octets = vectors.client_initial_payload.len,
        .number = client_packet_number,
        .number_octets = 4,
    });
    try std.testing.expectEqual(client_header_octets, written.header_octets);
    try std.testing.expectEqual(client_packet_number_offset, written.packet_number_offset);
    try std.testing.expectEqualSlices(u8, &vectors.client_initial_header, target[0..written.header_octets]);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# Initial packets apply the packet protection process, but use a secret
//# derived from the Destination Connection ID field from the client's first
//# Initial packet.
//= type=test
test "A.3: sealing and opening the server Initial" {
    const keys: quic.crypto.Keys = .initial(&vectors.destination_connection_id, .server);

    var datagram: [vectors.server_initial_protected.len]u8 = @splat(0);
    @memcpy(datagram[0..server_header_octets], &vectors.server_initial_header);
    @memcpy(datagram[server_header_octets..][0..vectors.server_initial_payload.len], &vectors.server_initial_payload);

    const total = try keys.seal(
        &datagram,
        server_packet_number_offset,
        server_header_octets,
        vectors.server_initial_payload.len,
        server_packet_number,
    );
    try std.testing.expectEqualSlices(u8, &vectors.server_initial_protected, datagram[0..total]);

    var received = vectors.server_initial_protected;
    const parsed = try quic.packet.parse(&received, 0);
    const opened = try keys.open(&received, parsed.header.initial.packet_number_offset, null);
    try std.testing.expectEqual(server_packet_number, opened.number);
    try std.testing.expectEqual(@as(u8, 2), opened.number_octets);
    try std.testing.expectEqualSlices(u8, &vectors.server_initial_payload, opened.payload);
    // The server chose a new connection identifier, which is the field a client
    // must adopt for everything it sends afterwards.
    try std.testing.expectEqualSlices(u8, &.{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 }, parsed.header.initial.source.bytes());
}

test "A.3: the frames the server's payload decodes to" {
    var iterator: quic.frame.Iterator = .init(&vectors.server_initial_payload);
    const ack = (try iterator.next()).?;
    // The ACK acknowledges packet number **0**, not the 2 that A.2's client
    // Initial carried. The two examples are not a matched exchange — A.3 says
    // only "the server sends the following payload in response" — so reading
    // this as an acknowledgement *of* A.2 would be reading in something the
    // appendix does not claim. Asserted as the appendix has it, and noted here
    // because the first instinct on seeing 0 is that the decoder is wrong.
    try std.testing.expectEqual(@as(u64, 0), ack.ack.largest);
    try std.testing.expectEqual(@as(u64, 0), ack.ack.delay);
    try std.testing.expectEqual(@as(u64, 0), ack.ack.range_count);
    try std.testing.expectEqual(@as(u64, 0), try ack.ack.smallest());
    try std.testing.expectEqual(@as(?quic.frame.Ecn, null), ack.ack.ecn);

    const crypto_frame = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u64, 0), crypto_frame.crypto.offset);
    try std.testing.expectEqual(@as(usize, 90), crypto_frame.crypto.data.len);
    // A TLS ServerHello.
    try std.testing.expectEqual(@as(u8, 0x02), crypto_frame.crypto.data[0]);
    try std.testing.expectEqual(@as(?quic.frame.Frame, null), try iterator.next());
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The Retry Integrity Tag is a 128-bit field that is computed as the
//# output of AEAD_AES_128_GCM [AEAD] used with the following inputs:
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The presence of this field ensures that a valid Retry packet can only be
//# sent by an entity that observes the Initial packet.
//= type=test
test "A.4: the Retry integrity tag binds the original connection identifier" {
    var scratch: [128]u8 = undefined;
    try quic.crypto.retry.verify(&scratch, &vectors.destination_connection_id, &vectors.retry_packet);

    // And the check is load-bearing: the same packet against any other original
    // identifier must fail, which is what stops an off-path attacker from
    // injecting a Retry it never saw the first packet for.
    const other: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    try std.testing.expectError(error.IntegrityFailed, quic.crypto.retry.verify(&scratch, &other, &vectors.retry_packet));

    // The packet parses as a Retry, and its token is the appendix's "token".
    const parsed = try quic.packet.parse(&vectors.retry_packet, 0);
    try std.testing.expectEqualStrings("token", parsed.header.retry.token);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.4
//# When AEAD_CHACHA20_POLY1305 is in use, header protection uses the raw
//# ChaCha20 function as defined in Section 2.4 of [CHACHA]. This uses a
//# 256-bit key and 16 bytes sampled from the packet protection output.
//= type=test
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
//= type=test
test "A.5: the ChaCha20-Poly1305 short header packet" {
    // The only vector that exercises the ChaCha20 header protection path and
    // the only short header in the appendix. Both are otherwise checked only
    // against this package's own round-trips.
    const secret = try quic.crypto.secrets.Secret.init(&vectors.chacha_secret);
    const keys: quic.crypto.Keys = .fromSecret(.chacha20_poly1305_sha256, &secret);
    try std.testing.expectEqualSlices(u8, &vectors.chacha_key, keys.key());
    try std.testing.expectEqualSlices(u8, &vectors.chacha_iv, &keys.iv);
    try std.testing.expectEqualSlices(u8, &vectors.chacha_hp, keys.headerKey());

    // Section 6.1's next generation, which nothing else in the package checks
    // against a published value.
    const updated = quic.crypto.secrets.update(.chacha20_poly1305_sha256, &secret);
    try std.testing.expectEqualSlices(u8, &vectors.chacha_ku, updated.bytes());

    var datagram: [vectors.chacha_packet.len]u8 = @splat(0);
    @memcpy(datagram[0..chacha_header_octets], &vectors.chacha_header);
    @memcpy(datagram[chacha_header_octets..][0..vectors.chacha_plaintext.len], &vectors.chacha_plaintext);

    const total = try keys.seal(
        &datagram,
        chacha_packet_number_offset,
        chacha_header_octets,
        vectors.chacha_plaintext.len,
        chacha_packet_number,
    );
    try std.testing.expectEqualSlices(u8, &vectors.chacha_packet, datagram[0..total]);

    // And back. The destination connection identifier is empty, which the
    // parser cannot know from the wire — it is told, which is the whole reason
    // `parse` takes that length.
    var received = vectors.chacha_packet;
    const parsed = try quic.packet.parse(&received, 0);
    try std.testing.expectEqual(chacha_packet_number_offset, parsed.header.short.packet_number_offset);
    const opened = try keys.open(&received, chacha_packet_number_offset, chacha_packet_number - 1);
    try std.testing.expectEqual(chacha_packet_number, opened.number);
    try std.testing.expectEqual(@as(u8, 3), opened.number_octets);
    try std.testing.expectEqualSlices(u8, &vectors.chacha_plaintext, opened.payload);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# The key and IV for the packet are computed as described in Section 5.1.
//# The nonce, N, is formed by combining the packet protection IV with the
//# packet number. The 62 bits of the reconstructed QUIC packet number in
//# network byte order are left- padded with zeros to the size of the IV.
//# The exclusive OR of the padded packet number and the IV forms the AEAD
//# nonce.
//= type=test
test "A.5: the nonce the appendix prints" {
    const secret = try quic.crypto.secrets.Secret.init(&vectors.chacha_secret);
    const keys: quic.crypto.Keys = .fromSecret(.chacha20_poly1305_sha256, &secret);
    // `nonce` is private, so this reconstructs it the way section 5.3 describes
    // and checks that against the appendix — which pins the *ordering* of the
    // XOR, the part a round-trip test cannot see because both directions would
    // be wrong together.
    var nonce = keys.iv;
    var padded: [8]u8 = undefined;
    std.mem.writeInt(u64, &padded, chacha_packet_number, .big);
    for (padded, 0..) |octet, index| nonce[nonce.len - padded.len + index] ^= octet;
    try std.testing.expectEqualSlices(u8, &vectors.chacha_nonce, &nonce);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
//# The sample of ciphertext is taken starting from an offset of 4 bytes
//# after the start of the Packet Number field. That is, in sampling packet
//# ciphertext for header protection, the Packet Number field is assumed to
//# be 4 bytes long (its maximum possible encoded length).
//= type=test
test "A.2: the header protection sample is drawn from the offset the RFC prints" {
    // The RFC prints this sample explicitly, and it was extracted and then
    // referenced by nothing — so the one step of header protection that a
    // wrong constant silently breaks had no vector behind it. Section 5.4.2
    // puts the sample four octets past the start of the packet number field,
    // which is chosen so it never overlaps a packet number of any width: get
    // the offset wrong and every packet still encrypts, still decrypts against
    // your own implementation, and is unreadable by every other stack.
    const protected = vectors.client_initial_protected;
    const from = client_packet_number_offset + quic.crypto.protect.sample_offset;
    const sample = protected[from..][0..quic.crypto.protect.sample_octets];
    try std.testing.expectEqualSlices(u8, &vectors.client_initial_sample, sample);

    // And the sample sits entirely past the widest packet number, which is the
    // property the offset exists to have.
    try std.testing.expect(from >= client_packet_number_offset + quic.packet_number.octets_max);
    try std.testing.expectEqual(@as(usize, 4), quic.crypto.protect.sample_offset);
}
