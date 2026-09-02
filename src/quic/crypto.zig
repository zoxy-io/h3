//! RFC 9001: using TLS to secure QUIC.
//!
//! The RFC the user did not ask for and the package cannot do without. RFC 9000
//! describes packets whose payloads are, without exception, encrypted; there is
//! no plaintext mode and no "just parse the header" shortcut, because the bits
//! that say how long the packet number is are themselves protected. So a QUIC
//! transport that stops at RFC 9000 cannot read a single packet, and this
//! layer is where the two RFCs meet.
//!
//! ## What is here, and what is deliberately not
//!
//! Here: section 5's packet protection and header protection, section 5.2's
//! Initial secrets, section 5.8's Retry integrity tag, and section 6's key
//! update. All of it computation over caller-supplied keys, all of it through
//! `std.crypto`, none of it needing an allocator or a dependency.
//!
//! Not here: **the TLS handshake**. h3 never builds a ClientHello, never
//! verifies a certificate, and never holds a private key. What it does is hand
//! the consumer the CRYPTO stream bytes for each encryption level and take back
//! the secrets that come out — pure data in both directions, so the consumer
//! plugs in whatever TLS engine it already has. zoxy has ztls; zrk has zssl;
//! neither wants the other's, and a package that chose for them would be
//! unusable by one of them. docs/DESIGN.md, "Where TLS attaches", is the long
//! version of this paragraph.
//!
//! ## The consequence for the seam
//!
//! Because the handshake is outside, `Level` and `Secret` are part of the
//! public API: they are the vocabulary the consumer's TLS engine and this
//! package use to talk about the same key schedule. A consumer wires
//! `installSecret(.handshake, .receive, secret, suite)` from wherever its TLS
//! engine reports a traffic secret, and this package does the rest.

const std = @import("std");

const assert = @import("../assert.zig").assert;

pub const secrets = @import("crypto/secrets.zig");
pub const protect = @import("crypto/protect.zig");
pub const retry = @import("crypto/retry.zig");

pub const Keys = protect.Keys;
pub const Secret = secrets.Secret;

/// RFC 9001 section 4.1.1: the four encryption levels.
///
/// Not the same thing as a packet number space, and the difference is the bug
/// this comment exists to prevent: 0-RTT and 1-RTT are two levels sharing the
/// *application data* number space, because a 0-RTT packet and the 1-RTT packet
/// that may replace it must not reuse a number. Three spaces, four levels.
pub const Level = enum(u2) {
    initial,
    zero_rtt,
    handshake,
    one_rtt,

    /// The packet number space this level draws from (section 12.3).
    pub fn space(level: Level) @import("packet_number.zig").Space {
        return switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt, .one_rtt => .application,
        };
    }

    pub const count: usize = 4;
};

comptime {
    assert(Level.count == @typeInfo(Level).@"enum".fields.len);
    // The pairing that makes the comment above true rather than merely stated.
    assert(Level.zero_rtt.space() == Level.one_rtt.space());
    assert(Level.initial.space() != Level.handshake.space());
}

/// Which half of the connection a key protects.
///
/// Spelled by role rather than by direction — `.client` keys are the ones a
/// client seals with and a server opens with — because RFC 9001 section 5.2's
/// labels are `"client in"` and `"server in"`, and a name that has to be
/// mentally inverted at half the call sites is a name that will be inverted at
/// one of them.
pub const Side = enum(u1) {
    client,
    server,

    pub fn peer(side: Side) Side {
        return switch (side) {
            .client => .server,
            .server => .client,
        };
    }
};

/// The AEAD and hash pairing a level's keys were derived under.
///
/// RFC 9001 section 5.3 admits every TLS 1.3 cipher suite except
/// `TLS_AES_128_CCM_8_SHA256`, whose 8-octet tag is too short for QUIC's
/// authentication limits. `TLS_AES_128_CCM_SHA256` is legal and absent here on
/// purpose: `std.crypto` has no CCM, adding one would be this package writing
/// its own AEAD, and no deployment needs it — TLS 1.3's mandatory-to-implement
/// suite is `TLS_AES_128_GCM_SHA256`, which is the first row. A peer that
/// negotiates CCM is refused by name rather than mis-decrypted.
pub const Suite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,

    /// Octets in the packet protection key.
    pub fn keyOctets(suite: Suite) u8 {
        return switch (suite) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => 32,
        };
    }

    /// Octets in the header protection key. The same length as the packet
    /// protection key for every suite QUIC admits, but derived from a different
    /// label and used with a different primitive, so it is asked for separately.
    pub fn headerKeyOctets(suite: Suite) u8 {
        return suite.keyOctets();
    }

    /// Octets in the hash output, which is also the length of a traffic secret.
    pub fn hashOctets(suite: Suite) u8 {
        return switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
        };
    }

    /// Which header protection construction section 5.4 pairs with the suite.
    pub fn headerProtection(suite: Suite) HeaderProtection {
        return switch (suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => .aes,
            .chacha20_poly1305_sha256 => .chacha20,
        };
    }
};

/// Section 5.4.3 and 5.4.4: the two ways a header protection mask is produced.
pub const HeaderProtection = enum { aes, chacha20 };

/// Section 5.3: every AEAD QUIC admits produces a 16-octet tag, and the format
/// depends on that — the tag is what makes a packet's length known before its
/// contents are, and section 5.4.2's sampling relies on there being 16 octets
/// after the packet number that are not header.
pub const tag_octets: u8 = 16;

/// Section 5.3: the nonce is the write IV, so it is the AEAD's nonce length.
pub const iv_octets: u8 = 12;

/// RFC 9001 section 6.6: how many packets one key may seal.
///
/// "Endpoints MUST count the number of encrypted packets for each set of keys.
/// If the total number of encrypted packets with the same key exceeds the
/// confidentiality limit for the selected AEAD, the endpoint MUST stop using
/// those keys." Past it, an attacker's advantage in distinguishing the AEAD
/// from a random permutation stops being negligible.
///
/// ChaCha20-Poly1305's limit is above the number of packets a connection can
/// have — a packet number is 62 bits — so the RFC says it "can be disregarded".
/// Answered as the packet number ceiling rather than as a special case, so
/// every caller compares the same way.
pub fn confidentialityLimit(suite: Suite) u64 {
    return switch (suite) {
        .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 1 << 23,
        .chacha20_poly1305_sha256 => (1 << 62) - 1,
    };
}

/// RFC 9001 section 6.6: how many forgeries a connection may survive.
///
/// "If the total number of received packets that fail authentication within the
/// connection, across all keys, exceeds the integrity limit for the selected
/// AEAD, the endpoint MUST immediately close the connection with a connection
/// error of type AEAD_LIMIT_REACHED and not process any more packets."
///
/// Across all keys, and for the whole connection — which is why the counter
/// lives on the connection rather than beside a key. TLS closes on the first
/// failed record; QUIC cannot, because an off-path attacker can inject packets
/// at will, so it counts instead.
pub fn integrityLimit(suite: Suite) u64 {
    return switch (suite) {
        .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 1 << 52,
        .chacha20_poly1305_sha256 => 1 << 36,
    };
}

comptime {
    // The numbers appendix B.1 derives, and the one section 6.6 declines to
    // impose. Stated as a relation rather than repeated as literals: the
    // confidentiality limit is what forces a key update, so it must be far
    // below the space of packet numbers or an update could never be reached.
    assert(confidentialityLimit(.aes_128_gcm_sha256) == 1 << 23);
    assert(integrityLimit(.aes_128_gcm_sha256) == 1 << 52);
    assert(integrityLimit(.chacha20_poly1305_sha256) == 1 << 36);
    for (std.enums.values(Suite)) |suite| {
        assert(confidentialityLimit(suite) <= @import("packet_number.zig").max);
        assert(confidentialityLimit(suite) < integrityLimit(suite) or
            suite == .chacha20_poly1305_sha256);
    }
}

/// Section 5.4.1: the mask is five octets — one for the header's protected
/// bits, four for the longest packet number.
pub const header_mask_octets: u8 = 5;

/// The widest key, secret and hash this package can be asked to hold, so that
/// every buffer here is a fixed array. Sized by the widest suite rather than by
/// the negotiated one, because a `Keys` is stored before the negotiation that
/// would narrow it is visible to the storage.
pub const key_octets_max: u8 = 32;
pub const secret_octets_max: u8 = 48;

comptime {
    assert(tag_octets == 16);
    assert(iv_octets == 12);
    assert(header_mask_octets == 1 + 4);
    // The maxima have to actually bound every suite, or a fixed array here is a
    // buffer overflow one call away.
    for (std.enums.values(Suite)) |suite| {
        assert(suite.keyOctets() <= key_octets_max);
        assert(suite.headerKeyOctets() <= key_octets_max);
        assert(suite.hashOctets() <= secret_octets_max);
        // Section 5.3 derives the IV at a fixed 12 octets regardless of suite.
        assert(suite.hashOctets() >= iv_octets);
    }
}

test {
    _ = secrets;
    _ = protect;
    _ = retry;
}

test "a level's space is the one section 12.3 assigns it" {
    try std.testing.expectEqual(@import("packet_number.zig").Space.initial, Level.initial.space());
    try std.testing.expectEqual(@import("packet_number.zig").Space.handshake, Level.handshake.space());
    try std.testing.expectEqual(@import("packet_number.zig").Space.application, Level.zero_rtt.space());
    try std.testing.expectEqual(@import("packet_number.zig").Space.application, Level.one_rtt.space());
}

test "a side's peer is the other one" {
    try std.testing.expectEqual(Side.server, Side.client.peer());
    try std.testing.expectEqual(Side.client, Side.server.peer());
}
