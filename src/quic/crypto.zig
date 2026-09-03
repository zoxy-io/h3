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

// What RFC 9001 asks of the TLS engine rather than of this package.
//
// The module comment above says the handshake is outside; this is the same
// claim in a form the ledger can check. Every requirement below is one this
// package will never satisfy, because satisfying it means holding a private
// key, verifying a certificate, choosing an application protocol or decoding
// a TLS message — and the whole shape of the seam is that a consumer brings
// the engine that does those. Left silent, each of them is indistinguishable
// from an oversight, which is the thing docs/VERIFICATION.md section 5.1
// exists to end.

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.2
//# Clients MUST NOT offer TLS versions older than 1.3.
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.2
//# An endpoint MUST terminate the connection if a version of TLS older than
//# 1.3 is negotiated.
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.4
//# A client MUST authenticate the identity of the server.
//= type=exception
//= reason=certificate verification and hostname checking are the consumer's, which is what docs/DESIGN.md section 4 means by "what the consumer owes in return". This package holds no certificate and no private key.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.4
//# A server MUST NOT use post-handshake client authentication (as defined
//# in Section 4.6.2 of [TLS13]) because the multiplexing offered by QUIC
//# prevents clients from correlating the certificate request with the
//# application-level event that triggered it (see [HTTP2-TLS13]).
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.4
//# More specifically, servers MUST NOT send post- handshake TLS
//# CertificateRequest messages, and clients MUST treat receipt of such
//# messages as a connection error of type PROTOCOL_VIOLATION.
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.8
//# As QUIC provides alternative mechanisms for connection termination and
//# the TLS connection is only closed if an error is encountered, a QUIC
//# endpoint MUST treat any alert from TLS as if it were at the "fatal"
//# level.
//= type=exception
//= reason=a TLS alert is produced by the consumer's TLS engine, which reports it across the seam as an error rather than as a record this package decodes. The CONNECTION_CLOSE that carries it is `Connection.close`.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.1
//# Unless another mechanism is used for agreeing on an application
//# protocol, endpoints MUST use ALPN for this purpose.
//= type=exception
//= reason=ALPN is one of the four things docs/DESIGN.md section 4 names as the consumer's: certificate verification, hostname checking, ALPN, and the 0-RTT decision. This package never sees the extension.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.1
//# When using ALPN, endpoints MUST immediately close a connection (see
//# Section 10.2 of [QUIC-TRANSPORT]) with a no_application_protocol TLS
//# alert (QUIC error code 0x0178; see Section 4.8) if an application
//# protocol is not negotiated. While [ALPN] only specifies that servers use
//# this alert, QUIC clients MUST use error 0x0178 to terminate a connection
//# when ALPN negotiation fails.
//= type=exception
//= reason=ALPN is one of the four things docs/DESIGN.md section 4 names as the consumer's: certificate verification, hostname checking, ALPN, and the 0-RTT decision. This package never sees the extension.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.1
//# Servers MUST select an application protocol compatible with the QUIC
//# version that the client has selected. The server MUST treat the
//# inability to select a compatible application protocol as a connection
//# error of type 0x0178 (no_application_protocol). Similarly, a client MUST
//# treat the selection of an incompatible application protocol by a server
//# as a connection error of type 0x0178.
//= type=exception
//= reason=ALPN is one of the four things docs/DESIGN.md section 4 names as the consumer's: certificate verification, hostname checking, ALPN, and the 0-RTT decision. This package never sees the extension.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.2
//# Endpoints MUST send the quic_transport_parameters extension; endpoints
//# that receive ClientHello or EncryptedExtensions messages without the
//# quic_transport_parameters extension MUST close the connection with an
//# error of type 0x016d (equivalent to a fatal TLS missing_extension alert,
//# see Section 4.8).
//= type=exception
//= reason=transport parameters cross the seam as the extension's octets in both directions; carrying them in the ClientHello and EncryptedExtensions, and noticing that the extension is absent, is the TLS engine's half. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.2
//# Endpoints MUST NOT send this extension in a TLS connection that does not
//# use QUIC (such as the use of TLS with TCP defined in [TLS13]). A fatal
//# unsupported_extension alert MUST be sent by an implementation that
//# supports this extension if the extension is received when the transport
//# is not QUIC.
//= type=exception
//= reason=transport parameters cross the seam as the extension's octets in both directions; carrying them in the ClientHello and EncryptedExtensions, and noticing that the extension is absent, is the TLS engine's half. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.3
//# Clients MUST NOT send the EndOfEarlyData message.
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.4
//# A client MUST NOT request the use of the TLS 1.3 compatibility mode.
//= type=exception
//= reason=the TLS handshake is the consumer's engine, not this package: h3 never builds or parses a TLS message, and hands CRYPTO stream octets across the seam as data. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-9.2
//# Endpoints MUST implement and use the replay protections described in
//# [TLS13], however it is recognized that these protections are imperfect.
//= type=exception
//= reason=TLS's replay protections are session-ticket machinery inside the consumer's TLS engine, and this package neither issues nor validates a ticket. 0-RTT, the thing they protect, is out of scope. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-9.2
//# These MUST NOT be used to communicate application semantics between
//# endpoints; clients MUST treat them as opaque values.
//= type=exception
//= reason=this package issues no session ticket and no NEW_TOKEN frame, so it defines the contents of neither; the address validation token it does carry is copied between packets without being read.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.5
//# Clients SHOULD NOT reuse tickets as that allows entities other than
//# the server to correlate connections; see Appendix C.4 of [TLS13].
//= type=exception
//= reason=a session ticket is a TLS 1.3 NewSessionTicket message, and this package neither stores, offers nor recognises one: resumption state lives on the consumer's side of the seam with the TLS engine that issued it. Declining to reuse a ticket is a decision taken where the ticket is kept. See docs/DESIGN.md section 4.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.4
//# A server SHOULD treat the receipt of a TLS ClientHello with a
//# non-empty legacy_session_id field as a connection error of type
//# PROTOCOL_VIOLATION.
//= type=exception
//= reason=the ClientHello is never decoded here -- CRYPTO stream octets cross the seam as data -- so `legacy_session_id` is a field only the consumer's TLS engine can read. What crosses back is a connection error, which `Connection.close` carries. See docs/DESIGN.md section 4.

// Keys that have not arrived yet, and what happens to a packet that needs them.
//
// The seam of docs/DESIGN.md section 4 means a level's keys appear when the
// consumer's TLS engine hands over a secret, which can be after a packet
// protected with them is already in hand. Section 4.1.4 says what to do about
// that, and this package does one of the two things it asks.

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.4
//# While waiting for TLS processing to complete, an endpoint SHOULD
//# buffer received packets if they might be processed using keys that are
//# not yet available.
//= type=exception
//= reason=there is nowhere to buffer one: docs/DESIGN.md section 5 makes the package allocation-free, so `Connection` holds no queue of datagrams it cannot yet read and discards a packet whose level has no keys. The cost is a retransmission the peer's loss recovery already covers, not a broken handshake -- which is why this is a trade rather than a gap.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.4
//# An endpoint SHOULD continue to respond to packets that can be
//# processed during this time.
// The other half, and this one is implemented: each packet of a coalesced
// datagram is opened at its own level, so one whose keys are missing is
// discarded on its own and the packets beside it are still processed. A
// missing key stops one packet rather than the datagram.

// The rule below is implemented in two places and neither half is it alone:
// keys are chosen by level here, and `Connection.onPacketsLost` rewinds the
// *level's* CRYPTO cursor, so data lost at one level is framed again at that
// level and therefore sealed with that level's keys.
//= https://www.rfc-editor.org/rfc/rfc9001#section-4
//# Each chunk of data that is produced by TLS is associated with the set of
//# keys that TLS is currently using. If QUIC needs to retransmit that data,
//# it MUST use the same keys even if TLS has already updated to newer keys.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.9
//# If packets from a lower encryption level contain CRYPTO frames, frames
//# that retransmit that data MUST be sent at the same encryption level.
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

    //= https://www.rfc-editor.org/rfc/rfc9001#section-4
    //# Each encryption level corresponds to a packet number space.
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

// What `zero_rtt` above costs, and what it does not.
//
// The level exists because RFC 9001 section 4.1.1 defines four of them and
// because 0-RTT shares the application-data number space with 1-RTT — a rule
// `space()` has to state whether or not a packet is ever sent at that level.
// Nothing installs a 0-RTT secret, so no `Keys` is ever derived for it and no
// packet is sealed or opened there. Every 0-RTT requirement RFC 9001 places on
// an endpoint therefore has the same answer, and it is written out once here
// rather than inferred from an absence.

//= https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
//# Servers MUST NOT send the early_data extension with a
//# max_early_data_size field set to any value other than 0xffffffff. A
//# client MUST treat receipt of a NewSessionTicket that contains an
//# early_data extension with any other value as a connection error of type
//# PROTOCOL_VIOLATION.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.6.2
//# When rejecting 0-RTT, a server MUST NOT process any 0-RTT packets, even
//# if it could.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.6.2
//# The client therefore MUST reset the state of all streams, including
//# application state bound to those streams.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.3
//# After receiving a 1-RTT packet, servers MUST discard 0-RTT keys within a
//# short time; the RECOMMENDED time period is three times the Probe Timeout
//# (PTO, see [QUIC-RECOVERY]).
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
//# An application protocol that uses QUIC MUST include a profile that
//# defines acceptable use of 0-RTT; otherwise, 0-RTT can only be used to
//# carry QUIC frames that do not carry application data.
//= type=exception
//= reason=a requirement on an application protocol's specification rather than on a QUIC implementation, and moot here: 0-RTT is out of scope and no 0-RTT keys are ever installed. See docs/DESIGN.md section 2.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
//# A server MUST NOT use 0-RTT keys to protect packets; it uses 1-RTT keys
//# to protect acknowledgments of 0-RTT packets.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
//# A client MUST NOT attempt to decrypt 0-RTT packets it receives and
//# instead MUST discard them.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
//# Once a client has installed 1-RTT keys, it MUST NOT send any more 0-RTT
//# packets.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-8.3
//# A server MUST treat receipt of a CRYPTO frame in a 0-RTT packet as a
//# connection error of type PROTOCOL_VIOLATION.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no packet is sealed or opened at this level. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-9.2
//# An application protocol that uses QUIC MUST describe how the protocol
//# uses 0-RTT and the measures that are employed to protect against replay
//# attack.
//= type=exception
//= reason=a requirement on an application protocol's specification rather than on a QUIC implementation, and moot here: 0-RTT is out of scope and no 0-RTT keys are ever installed. See docs/DESIGN.md section 2.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-9.2
//# QUIC extensions MUST either describe how replay attacks affect their
//# operation or prohibit the use of the extension in 0-RTT. Application
//# protocols MUST either prohibit the use of extensions that carry
//# application semantics in 0-RTT or provide replay mitigation strategies.
//= type=exception
//= reason=a requirement on an application protocol's specification rather than on a QUIC implementation, and moot here: 0-RTT is out of scope and no 0-RTT keys are ever installed. See docs/DESIGN.md section 2.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-4.6.2
//# When 0-RTT was rejected, a client SHOULD treat receipt of an
//# acknowledgment for a 0-RTT packet as a connection error of type
//# PROTOCOL_VIOLATION, if it is able to detect the condition.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so this endpoint sends no 0-RTT packet and there is no acknowledgment of one for it to detect. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
//# A client SHOULD stop sending 0-RTT data if it receives an indication
//# that 0-RTT data has been rejected.
//= type=exception
//= reason=0-RTT is out of scope: no 0-RTT keys are ever installed, so no 0-RTT data is ever sent and there is nothing to stop. See docs/DESIGN.md section 2 for what this package owns and section 6 for the list this sits on.

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

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# QUIC can use any of the cipher suites defined in [TLS13] with the
//# exception of TLS_AES_128_CCM_8_SHA256. A cipher suite MUST NOT be
//# negotiated unless a header protection scheme is defined for the cipher
//# suite. This document defines a header protection scheme for all cipher
//# suites defined in [TLS13] aside from TLS_AES_128_CCM_8_SHA256.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# An endpoint MUST NOT reject a ClientHello that offers a cipher suite
//# that it does not support, or it would be impossible to deploy a new
//# cipher suite.
//= type=exception
//= reason=the ClientHello is the consumer's TLS engine's and this package never sees one: `installSecret` is told which suite was negotiated, after the fact. A suite absent from this enum is one no key can be derived for, which is a different refusal from rejecting the offer. See docs/DESIGN.md section 4.
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

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
    //# Before a TLS cipher suite can be used with QUIC, a header protection
    //# algorithm MUST be specified for the AEAD used with that cipher
    //# suite.
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

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# These cipher suites have a 16-byte authentication tag and produce an
//# output 16 bytes larger than their input.
/// Section 5.3: every AEAD QUIC admits produces a 16-octet tag, and the format
/// depends on that — the tag is what makes a packet's length known before its
/// contents are, and section 5.4.2's sampling relies on there being 16 octets
/// after the packet number that are not header.
pub const tag_octets: u8 = 16;

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
//# The Length provided with "quic iv" is the minimum length of the AEAD
//# nonce or 8 bytes if that is larger; see [AEAD].
/// Section 5.3: the nonce is the write IV, so it is the AEAD's nonce length.
pub const iv_octets: u8 = 12;

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# Endpoints MUST count the number of encrypted packets for each set of
//# keys. If the total number of encrypted packets with the same key exceeds
//# the confidentiality limit for the selected AEAD, the endpoint MUST stop
//# using those keys. Endpoints MUST initiate a key update before sending
//# more protected packets than the confidentiality limit for the selected
//# AEAD permits.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the confidentiality limit is
//# 2^23 encrypted packets; see Appendix B.1. For AEAD_CHACHA20_POLY1305,
//# the confidentiality limit is greater than the number of possible packets
//# (2^62) and so can be disregarded.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
//# An endpoint MUST initiate a key update (Section 6) prior to exceeding
//# any limit set for the AEAD that is in use.
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

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# In addition to counting packets sent, endpoints MUST count the number of
//# received packets that fail authentication during the lifetime of a
//# connection. If the total number of received packets that fail
//# authentication within the connection, across all keys, exceeds the
//# integrity limit for the selected AEAD, the endpoint MUST immediately
//# close the connection with a connection error of type AEAD_LIMIT_REACHED
//# and not process any more packets.
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the integrity limit is 2^52
//# invalid packets; see Appendix B.1. For AEAD_CHACHA20_POLY1305, the
//# integrity limit is 2^36 invalid packets; see [AEBounds].
//
//= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
//# Any TLS cipher suite that is specified for use with QUIC MUST define
//# limits on the use of the associated AEAD function that preserves margins
//# for confidentiality and integrity. That is, limits MUST be specified for
//# the number of packets that can be authenticated and for the number of
//# packets that can fail authentication.
//= type=exception
//= reason=a requirement on the specification of a cipher suite rather than on an implementation of one. RFC 9001 specifies the limits for the three suites `Suite` admits and they are the two functions here; a future suite that arrived without them could not be added to `Suite` at all.
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
