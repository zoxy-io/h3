//! RFC 9001 section 5.8: the Retry packet integrity tag.
//!
//! A Retry is the one packet with no packet protection: it carries a token and
//! nothing else, and it is sent before any key exists. What it carries instead
//! is a 16-octet tag over a pseudo-packet that includes the *original*
//! Destination Connection ID — the one the client used before the Retry — under
//! a key printed in the RFC. That key is not a secret and cannot be: the point
//! is not confidentiality but proof that the sender saw the client's first
//! packet, which is what stops an off-path attacker from injecting a Retry and
//! forcing a connection to restart against an address it chose.
//!
//! Both endpoints need this. A server builds the tag; a client verifies it and
//! discards the Retry if it does not match (section 17.2.5.2 of RFC 9000), and
//! a client that skipped the check would accept a downgrade from anyone on the
//! path.

const std = @import("std");

const assert = @import("../../assert.zig").assert;
const crypto = @import("../crypto.zig");

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.7
//# Although it is in principle possible to use this feature for address
//# verification, QUIC implementations SHOULD instead use the Retry
//# feature; see Section 8.1 of [QUIC-TRANSPORT].
//= type=exception
//= reason=the choice between HelloRetryRequest and Retry belongs to the endpoint that validates an address, and this package makes neither move: HelloRetryRequest is a TLS handshake message the consumer's engine produces (docs/DESIGN.md section 4), and a server here sends no Retry at all, because issuing one needs a token and so a server key, a clock and randomness that the seam of docs/DESIGN.md section 3 keeps outside. See docs/DESIGN.md section 2 and section 6. What is implemented is the receiving half -- the integrity tag a client checks before honouring a Retry -- which is what makes preferring Retry safe in the first place.

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The secret key, K, is 128 bits equal to
//# 0xbe0c690b9f66575a1d766b54e368c84e.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The nonce, N, is 96 bits equal to 0x461599d35d632bf2239825bb.
/// RFC 9001 section 5.8: the key and nonce for QUIC version 1. Constants of the
/// version, published in the RFC, and named for the version because version 2
/// changes both.
pub const key_v1: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
pub const nonce_v1: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The Retry Integrity Tag is a 128-bit field that is computed as the
//# output of AEAD_AES_128_GCM [AEAD] used with the following inputs:
/// The tag's length, which is the AEAD's.
pub const tag_octets: u8 = crypto.tag_octets;

comptime {
    assert(key_v1.len == 16);
    assert(nonce_v1.len == crypto.iv_octets);
    assert(tag_octets == 16);
}

pub const Error = error{
    /// The pseudo-packet does not fit `scratch`. The caller sizes that buffer;
    /// see `pseudoPacketOctets`.
    ScratchTooSmall,
    /// A connection identifier longer than RFC 9000 section 17.2 allows.
    ConnectionIdTooLong,
    /// `retry` is shorter than the tag it is supposed to end with.
    Truncated,
    /// The tag does not match. RFC 9000 section 17.2.5.2: discard the packet.
    IntegrityFailed,
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# The Retry Pseudo-Packet is not sent over the wire. It is computed by
//# taking the transmitted Retry packet, removing the Retry Integrity Tag,
//# and prepending the two following fields:
/// Octets the pseudo-packet occupies: a one-octet length, the original
/// Destination Connection ID, and the Retry packet up to but excluding its tag.
///
/// Exported so a caller can size `scratch` without reading section 5.8.
pub fn pseudoPacketOctets(original_destination_connection_id_octets: usize, retry_octets: usize) usize {
    assert(retry_octets >= tag_octets);
    return 1 + original_destination_connection_id_octets + (retry_octets - tag_octets);
}

/// Compute the tag for a Retry packet.
///
/// `retry` is the Retry packet with its tag field either absent or ignored —
/// only `retry[0 .. retry.len - tag_octets]` is read. `scratch` is caller-owned
/// working space of at least `pseudoPacketOctets` octets; it holds the
/// pseudo-packet, which is the AEAD's associated data.
pub fn tag(
    scratch: []u8,
    original_destination_connection_id: []const u8,
    retry: []const u8,
) Error![tag_octets]u8 {
    if (original_destination_connection_id.len > 20) return error.ConnectionIdTooLong;
    if (retry.len < tag_octets) return error.Truncated;

    const needed = pseudoPacketOctets(original_destination_connection_id.len, retry.len);
    if (scratch.len < needed) return error.ScratchTooSmall;

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
    //# ODCID Length: The ODCID Length field contains the length in bytes of
    //# the Original Destination Connection ID field that follows it,
    //# encoded as an 8-bit unsigned integer.
    scratch[0] = @intCast(original_destination_connection_id.len);
    @memcpy(scratch[1..][0..original_destination_connection_id.len], original_destination_connection_id);
    const body = retry[0 .. retry.len - tag_octets];
    @memcpy(scratch[1 + original_destination_connection_id.len ..][0..body.len], body);
    assert(1 + original_destination_connection_id.len + body.len == needed);

    // The plaintext is empty: the tag authenticates the pseudo-packet and
    // encrypts nothing, which is why the key can be published.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
    //# The plaintext, P, is empty.
    //
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
    //# The associated data, A, is the contents of the Retry Pseudo- Packet,
    //# as illustrated in Figure 8:
    var computed: [tag_octets]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&.{}, &computed, &.{}, scratch[0..needed], nonce_v1, key_v1);
    return computed;
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# Retry packets (see Section 17.2.5 of [QUIC-TRANSPORT]) carry a Retry
//# Integrity Tag that provides two properties: it allows the discarding of
//# packets that have accidentally been corrupted by the network, and only
//# an entity that observes an Initial packet can send a valid Retry packet.
/// Verify the tag a Retry packet arrived with.
///
/// The comparison is constant-time. Not because the tag is a secret — it
/// travels in the clear — but because a timing oracle on a 16-octet check is a
/// forgery oracle, and there is no reason to leave one lying around.
pub fn verify(
    scratch: []u8,
    original_destination_connection_id: []const u8,
    retry: []const u8,
) Error!void {
    const computed = try tag(scratch, original_destination_connection_id, retry);
    const received = retry[retry.len - tag_octets ..][0..tag_octets];
    if (!std.crypto.timing_safe.eql([tag_octets]u8, computed, received.*)) {
        return error.IntegrityFailed;
    }
}

test "a tag this module computes is a tag this module accepts" {
    // A structural round-trip. The known-answer test against RFC 9001 appendix
    // A.4 belongs beside the rest of the appendix's packets and is tracked as
    // its own slice; what this proves is that `tag` and `verify` agree on the
    // pseudo-packet's shape, which is the part section 5.8 is easy to get
    // wrong — the length octet in front of the original connection identifier
    // is not part of the Retry packet and is easy to omit.
    const original: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var retry: [32]u8 = @splat(0);
    retry[0] = 0xf0; // Long header, fixed bit, Retry.
    std.mem.writeInt(u32, retry[1..5], 1, .big);

    var scratch: [64]u8 = undefined;
    const computed = try tag(&scratch, &original, &retry);
    @memcpy(retry[retry.len - tag_octets ..], &computed);
    try verify(&scratch, &original, &retry);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.8
//# Original Destination Connection ID: The Original Destination Connection
//# ID contains the value of the Destination Connection ID from the Initial
//# packet that this Retry is in response to. The length of this field is
//# given in ODCID Length. The presence of this field ensures that a valid
//# Retry packet can only be sent by an entity that observes the Initial
//# packet.
//= type=test
test "a Retry that names a different original connection is rejected" {
    const original: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const other: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 };
    var retry: [32]u8 = @splat(0);
    retry[0] = 0xf0;

    var scratch: [64]u8 = undefined;
    const computed = try tag(&scratch, &original, &retry);
    @memcpy(retry[retry.len - tag_octets ..], &computed);
    // This is the check that makes a Retry unforgeable by an off-path
    // attacker: it binds the packet to the connection identifier the client
    // chose, which an attacker that did not see the first packet cannot know.
    try std.testing.expectError(error.IntegrityFailed, verify(&scratch, &other, &retry));
}

test "the buffers are checked rather than assumed" {
    const original: [8]u8 = .{1} ** 8;
    var retry: [32]u8 = @splat(0);
    var small: [8]u8 = undefined;
    try std.testing.expectError(error.ScratchTooSmall, tag(&small, &original, &retry));

    var scratch: [64]u8 = undefined;
    try std.testing.expectError(error.Truncated, tag(&scratch, &original, retry[0..8]));

    const too_long: [21]u8 = @splat(0);
    try std.testing.expectError(error.ConnectionIdTooLong, tag(&scratch, &too_long, &retry));
}
