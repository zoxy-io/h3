//! RFC 9001 sections 5.1, 5.2 and 6.1: the QUIC key schedule.
//!
//! Three derivations, all of them HKDF-Expand-Label over a traffic secret:
//!
//! * **Initial secrets** (section 5.2) come from the client's *first*
//!   Destination Connection ID and a version-specific salt. They are not
//!   secret in any useful sense — anyone who saw the first packet can compute
//!   them — and exist to make Initial packets self-describing rather than
//!   confidential.
//! * **Packet protection keys** (section 5.1) — a key, a 12-octet IV and a
//!   header protection key — from whatever traffic secret applies at a level.
//! * **The next generation** (section 6.1), for a key update.
//!
//! ## Why HKDF-Expand-Label is written out here
//!
//! It is RFC 8446 section 7.1's function, so it belongs to TLS, and this
//! package does not implement TLS. It is nonetheless here, in twenty lines,
//! because the alternative is a dependency on a TLS library — and the whole
//! shape of this package is that the consumer brings its own. zoxy's is ztls
//! and zrk's is zssl; a `Hkdf` in the seam would force one of them to link the
//! other's. Twenty lines of `std.crypto` is the cheaper trade, and the labels
//! it is called with are QUIC's, not TLS's.
//!
//! ## Salt and label are version-scoped
//!
//! The Initial salt is a constant *of QUIC version 1*. Version 2 (RFC 9369)
//! changes it, and changes the labels beside it. `version.zig` is where that
//! lives when a second version arrives; until then the constant is named for
//! its version rather than for its purpose, so the day it becomes a table
//! nothing has to be renamed to notice.

const std = @import("std");

const assert = @import("../../assert.zig").assert;
const crypto = @import("../crypto.zig");

const Side = crypto.Side;
const Suite = crypto.Suite;

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# Initial packets apply the packet protection process, but use a secret
//# derived from the Destination Connection ID field from the client's first
//# Initial packet.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# This secret is determined by using HKDF-Extract (see Section 2.2 of
//# [HKDF]) with a salt of 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and
//# the input keying material (IKM) of the Destination Connection ID field.
/// RFC 9001 section 5.2: the salt for QUIC version 1.
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The hash function for HKDF when deriving initial secrets and keys is
//# SHA-256 [SHA].
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# The KDF used for initial secrets is always the HKDF-Expand-Label
//# function from TLS 1.3; see Section 5.2.
/// Section 5.2: Initial packets are protected with AES-128-GCM and SHA-256
/// whatever the handshake later negotiates, because they are sent before there
/// is a negotiation to consult.
pub const initial_suite: Suite = .aes_128_gcm_sha256;

/// The longest label this package expands with, so the `info` buffer below is a
/// fixed array. `"client in"` and `"server in"` are nine octets; the rest are
/// eight.
const label_octets_max: usize = 9;

/// RFC 8446 section 7.1's `HkdfLabel`, at its widest: a `uint16` length, a
/// length-prefixed label carrying the `"tls13 "` prefix, and a length-prefixed
/// context which is always empty here.
const info_octets_max: usize = 2 + 1 + tls13_prefix.len + label_octets_max + 1;

const tls13_prefix = "tls13 ";

comptime {
    assert(initial_salt_v1.len == 20);
    assert(tls13_prefix.len == 6);
    assert(info_octets_max == 2 + 1 + 6 + 9 + 1);
}

/// A traffic secret: the hash-length output the key schedule hands around.
///
/// Fixed storage sized by SHA-384, because a `Secret` is stored per level
/// before the suite that would narrow it is known to the storage. `length` is
/// the suite's hash length and is the only part `bytes()` exposes.
pub const Secret = struct {
    storage: [crypto.secret_octets_max]u8 = @splat(0),
    length: u8 = 0,

    pub const Error = error{
        /// Longer than SHA-384's output. A caller passing a secret this package
        /// has no suite for.
        TooLong,
    };

    pub fn init(source: []const u8) Error!Secret {
        if (source.len > crypto.secret_octets_max) return error.TooLong;
        var secret: Secret = .{ .length = @intCast(source.len) };
        @memcpy(secret.storage[0..source.len], source);
        assert(secret.length <= crypto.secret_octets_max);
        return secret;
    }

    pub fn bytes(self: *const Secret) []const u8 {
        assert(self.length <= crypto.secret_octets_max);
        return self.storage[0..self.length];
    }

    /// Overwrite the storage. Not a security guarantee — Zig may elide it, and
    /// a secret that has been copied is beyond reach anyway — but it turns a
    /// use-after-discard into a wrong answer rather than a working one, which
    /// is what a test can catch.
    pub fn discard(self: *Secret) void {
        @memset(&self.storage, 0);
        self.length = 0;
        assert(self.length == 0);
    }
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# The keys used for packet protection are computed from the TLS secrets
//# using the KDF provided by TLS. In TLS 1.3, the HKDF-Expand-Label
//# function described in Section 7.1 of [TLS13] is used with the hash
//# function from the negotiated cipher suite. All uses of HKDF-Expand-
//# Label in QUIC use a zero-length Context.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# Note that labels, which are described using strings, are encoded as
//# bytes using ASCII [ASCII] without quotes or any trailing NUL byte.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# Other versions of TLS MUST provide a similar function in order to be
//# used with QUIC.
//= type=exception
//= reason=the seam takes traffic secrets, not a TLS engine, and `Suite` names only TLS 1.3 cipher suites -- so there is no version of TLS other than 1.3 that can reach these labels. A requirement on the specification of a future TLS, not on this package. See docs/DESIGN.md section 4.
/// RFC 8446 section 7.1's HKDF-Expand-Label, with the empty context every QUIC
/// use of it has.
///
/// `suite` picks the hash, which is the only thing that varies. Fills `out`
/// completely.
pub fn expandLabel(suite: Suite, out: []u8, secret: []const u8, label: []const u8) void {
    assert(out.len >= 1);
    assert(out.len <= 255);
    assert(label.len >= 1);
    assert(label.len <= label_octets_max);
    assert(secret.len == suite.hashOctets());

    var info: [info_octets_max]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(tls13_prefix.len + label.len);
    @memcpy(info[3..][0..tls13_prefix.len], tls13_prefix);
    @memcpy(info[3 + tls13_prefix.len ..][0..label.len], label);
    const context_at = 3 + tls13_prefix.len + label.len;
    info[context_at] = 0;
    const used = context_at + 1;
    assert(used <= info_octets_max);

    switch (suite) {
        .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
            const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
            Hkdf.expand(out, info[0..used], secret[0..Hkdf.prk_length].*);
        },
        .aes_256_gcm_sha384 => {
            const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
            Hkdf.expand(out, info[0..used], secret[0..Hkdf.prk_length].*);
        },
    }
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The secret used by clients to construct Initial packets uses the PRK and
//# the label "client in" as input to the HKDF-Expand-Label function from
//# TLS [TLS13] to produce a 32-byte secret. Packets constructed by the
//# server use the same process with the label "server in".
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The HKDF-Expand-Label function defined in TLS 1.3 MUST be used for
//# Initial packets even where the TLS versions offered do not include TLS
//# 1.3.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The connection ID used with HKDF-Expand-Label is the Destination
//# Connection ID in the Initial packet sent by the client. This will be a
//# randomly selected value unless the client creates the Initial packet
//# after receiving a Retry packet, where the Destination Connection ID is
//# selected by the server.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# The secrets used for constructing subsequent Initial packets change when
//# a server sends a Retry packet to use the connection ID value selected by
//# the server. The secrets do not change when a client changes the
//# Destination Connection ID it uses in response to an Initial packet from
//# the server.
/// RFC 9001 section 5.2: the client's and server's Initial secrets, derived
/// from the Destination Connection ID of the client's *first* Initial packet.
///
/// "First" is load-bearing and is the caller's to remember. A server that sends
/// a Retry causes the client to send a second Initial with a different
/// Destination Connection ID, and the Initial keys change with it; a client
/// that keeps deriving from the original will not decrypt anything the server
/// sends afterwards. Section 7.2 spells the rule out because implementations
/// get it wrong.
pub fn initial(destination_connection_id: []const u8, side: Side) Secret {
    assert(destination_connection_id.len <= 20);

    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const initial_secret = Hkdf.extract(&initial_salt_v1, destination_connection_id);

    const label = switch (side) {
        .client => "client in",
        .server => "server in",
    };
    assert(label.len == 9);

    var secret: Secret = .{ .length = initial_suite.hashOctets() };
    expandLabel(initial_suite, secret.storage[0..secret.length], &initial_secret, label);
    assert(secret.length == 32);
    return secret;
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# An endpoint initiates a key update by updating its packet protection
//# write secret and using that to protect new packets.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6
//# Endpoints MUST NOT send a TLS KeyUpdate message.
//= type=exception
//= reason=a TLS KeyUpdate is a TLS handshake message, and this package neither builds nor parses one: CRYPTO stream octets cross the seam as data and the consumer's TLS engine is what would see an unexpected message. QUIC's own key update, which is `update` below and the Key Phase bit, is implemented. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6
//# Endpoints MUST treat the receipt of a TLS KeyUpdate message as a
//# connection error of type 0x010a, equivalent to a fatal TLS alert of
//# unexpected_message; see Section 4.8.
//= type=exception
//= reason=the other half of the same seam: this package never parses a TLS handshake message, so the engine that decodes the CRYPTO stream is the only thing that can recognise a KeyUpdate and report it. What crosses back is a connection error, which `Connection.close` already carries.
/// RFC 9001 section 6.1: the next generation of a traffic secret.
///
/// Only ever applied to 1-RTT secrets — a key update at any other level is a
/// protocol error, because no other level lives long enough to need one. The
/// caller enforces that; this function is arithmetic.
pub fn update(suite: Suite, current: *const Secret) Secret {
    assert(current.length == suite.hashOctets());
    var next: Secret = .{ .length = suite.hashOctets() };
    expandLabel(suite, next.storage[0..next.length], current.bytes(), "quic ku");
    assert(next.length == current.length);
    return next;
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
//# initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a initial_secret
//# = HKDF-Extract(initial_salt, client_dst_connection_id)
//# client_initial_secret = HKDF-Expand-Label(initial_secret, "client in",
//# "", Hash.length) server_initial_secret =
//# HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
//= type=test
test "RFC 9001 appendix A.1: the Initial secrets for the sample connection" {
    // The appendix's Destination Connection ID, and the two secrets it derives.
    // Transcribed from the RFC: this is a known-answer test, so the numbers'
    // only source is the document, and the implementation above must reproduce
    // them without having been shown them.
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const client = initial(&dcid, .client);
    try std.testing.expectEqualSlices(u8, &.{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    }, client.bytes());

    const server = initial(&dcid, .server);
    try std.testing.expectEqualSlices(u8, &.{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    }, server.bytes());
}

test "a secret's storage does not leak past its length" {
    var secret = try Secret.init(&.{ 1, 2, 3, 4 });
    try std.testing.expectEqual(@as(usize, 4), secret.bytes().len);
    secret.discard();
    try std.testing.expectEqual(@as(usize, 0), secret.bytes().len);
    const too_long: [crypto.secret_octets_max + 1]u8 = @splat(0);
    try std.testing.expectError(error.TooLong, Secret.init(&too_long));
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
//# The endpoint creates a new write secret from the existing write secret
//# as performed in Section 7.2 of [TLS13]. This uses the KDF function
//# provided by TLS with a label of "quic ku".
//= type=test
test "a key update is deterministic and changes the secret" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const first = initial(&dcid, .client);
    const second = update(initial_suite, &first);
    const again = update(initial_suite, &first);
    try std.testing.expect(!std.mem.eql(u8, first.bytes(), second.bytes()));
    try std.testing.expectEqualSlices(u8, second.bytes(), again.bytes());
    try std.testing.expectEqual(first.length, second.length);
}
