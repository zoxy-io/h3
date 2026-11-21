//! RFC 9001 appendix A, as a check any crypto backend can be run through.
//!
//! `corpus/rfc9001.zig` proves this package's protection path against the
//! appendix's worked packets with `backend.Std`. A consumer that supplies its
//! own backend — zoxy, over libcrypto through zssl — needs the same evidence
//! for *its* primitives, and it cannot reach `corpus/`, which does not ship.
//! So the vectors ship here, and `check` is the appendix as a function:
//!
//!     test "our backend passes RFC 9001 appendix A" {
//!         try h3.quic.crypto.conformance.check(ZsslBackend);
//!     }
//!
//! ## What it exercises, primitive by primitive
//!
//! - **A.1**: HKDF-SHA256 extract and expand, through the Initial secrets and
//!   both sides' keys, IVs and header protection keys.
//! - **A.2**: the AES-128 block on the appendix's sample against the mask it
//!   prints, then AES-128-GCM sealing the 1200-octet client Initial octet for
//!   octet, then opening it, which must recover the payload.
//! - **A.3**: the same for the server's Initial, in the other direction.
//! - **A.4**: the Retry integrity tag, which is an AES-128-GCM seal over an
//!   *empty* plaintext — the one call with `data.len == 0`.
//! - **A.5**: the ChaCha20 keystream on its sample against its mask, then
//!   ChaCha20-Poly1305 on a short header, and the key update's HKDF-Expand.
//!
//! The appendix has nothing under AES-256-GCM or SHA-384, so those two — and
//! the AES-256 block — are checked against `backend.Std` on fixed inputs
//! instead: a differential check rather than a known answer, and said so. Last,
//! every AEAD must refuse a forgery: every octet of the tag flipped in turn,
//! and the first and last octet of the ciphertext and of the associated data,
//! each have to come back as `error.AuthenticationFailed`.
//!
//! Each failure is its own error, named for what disagreed, so a backend that
//! fails says where.

const std = @import("std");

const assert = @import("../../assert.zig").assert;
const backend = @import("backend.zig");
const crypto = @import("../crypto.zig");
const protect = @import("protect.zig");
const retry = @import("retry.zig");
const secrets = @import("secrets.zig");

pub const vectors = @import("rfc9001_vectors.zig");

pub const Failure = error{
    /// A.1: an Initial secret, key, IV or header protection key differs.
    InitialKeys,
    /// A.2: the AES-128 block over the appendix's sample is not its mask.
    AesHeaderProtection,
    /// A.5: the ChaCha20 keystream over the appendix's sample is not its mask.
    ChaChaHeaderProtection,
    /// A.2: sealing the client Initial did not reproduce the appendix's packet.
    ClientInitialSeal,
    /// A.2: the appendix's packet did not open, or opened to something else.
    ClientInitialOpen,
    /// A.3: the same, for the server's Initial.
    ServerInitialSeal,
    ServerInitialOpen,
    /// A.4: the Retry integrity tag did not verify, or verified under the wrong
    /// original Destination Connection ID.
    RetryTag,
    /// A.5: the ChaCha20-Poly1305 keys, packet or open differ.
    ChaChaPacket,
    /// A.5: section 6.1's next secret differs.
    KeyUpdate,
    /// Against `backend.Std`: AES-256-GCM, HKDF-SHA384 or the AES-256 block
    /// disagree on the same inputs.
    Aes256Gcm,
    HkdfSha384,
    Aes256Block,
    /// An AEAD accepted a packet whose tag, ciphertext or associated data had
    /// been altered.
    ForgeryAccepted,
};

/// Run RFC 9001 appendix A, and the checks it does not cover, through
/// `Backend`. Returns the first disagreement.
pub fn check(comptime Backend: type) Failure!void {
    comptime backend.check(Backend);
    try initialKeys(Backend);
    try headerProtection(Backend);
    try clientInitial(Backend);
    try serverInitial(Backend);
    try retryTag(Backend);
    try chachaShortHeader(Backend);
    try againstStd(Backend);
    try refusesForgeries(Backend);
}

/// A.2's Initial: the packet number sits 18 octets in and the header is 22.
const client_packet_number_offset: usize = 18;
const client_header_octets: usize = 22;
const client_packet_number: u64 = 2;
/// A.3's: a two-octet number at the same offset, for a different reason.
const server_packet_number_offset: usize = 18;
const server_header_octets: usize = 20;
const server_packet_number: u64 = 1;
/// A.5's short header over an empty Destination Connection ID.
const chacha_packet_number_offset: usize = 1;
const chacha_header_octets: usize = 4;
const chacha_packet_number: u64 = 654_360_564;

comptime {
    assert(client_header_octets == client_packet_number_offset + 4);
    assert(server_header_octets == server_packet_number_offset + 2);
    assert(chacha_header_octets == chacha_packet_number_offset + 3);
}

fn initialKeys(comptime Backend: type) Failure!void {
    const schedule = secrets.Schedule(Backend);
    const Keys = protect.KeysOf(Backend);
    const dcid = &vectors.destination_connection_id;

    const client_secret = schedule.initial(dcid, .client);
    if (!std.mem.eql(u8, &vectors.client_initial_secret, client_secret.bytes())) return error.InitialKeys;
    const server_secret = schedule.initial(dcid, .server);
    if (!std.mem.eql(u8, &vectors.server_initial_secret, server_secret.bytes())) return error.InitialKeys;

    const client: Keys = .initial(dcid, .client);
    if (!std.mem.eql(u8, &vectors.client_key, client.key())) return error.InitialKeys;
    if (!std.mem.eql(u8, &vectors.client_iv, &client.iv)) return error.InitialKeys;
    if (!std.mem.eql(u8, &vectors.client_hp, client.headerKey())) return error.InitialKeys;

    const server: Keys = .initial(dcid, .server);
    if (!std.mem.eql(u8, &vectors.server_key, server.key())) return error.InitialKeys;
    if (!std.mem.eql(u8, &vectors.server_iv, &server.iv)) return error.InitialKeys;
    if (!std.mem.eql(u8, &vectors.server_hp, server.headerKey())) return error.InitialKeys;
}

/// Section 5.4.3 and 5.4.4's two masks, each on its own: the primitive over
/// the appendix's sample, and nothing of the packet around it. Checked before
/// the packets, so that a wrong block or keystream is named as one rather than
/// as a packet that did not match.
fn headerProtection(comptime Backend: type) Failure!void {
    var block: [16]u8 = undefined;
    Backend.aes128EncryptBlock(&block, &vectors.client_initial_sample, &vectors.client_hp);
    if (!std.mem.eql(u8, &vectors.client_initial_mask, block[0..crypto.header_mask_octets])) {
        return error.AesHeaderProtection;
    }
    var mask: [crypto.header_mask_octets]u8 = undefined;
    const counter = std.mem.readInt(u32, vectors.chacha_sample[0..4], .little);
    Backend.chacha20Keystream(&mask, &vectors.chacha_hp, counter, vectors.chacha_sample[4..16]);
    if (!std.mem.eql(u8, &vectors.chacha_mask, &mask)) return error.ChaChaHeaderProtection;
}

fn clientInitial(comptime Backend: type) Failure!void {
    const Keys = protect.KeysOf(Backend);
    const keys: Keys = .initial(&vectors.destination_connection_id, .client);

    var datagram: [vectors.client_initial_protected.len]u8 = @splat(0);
    @memcpy(datagram[0..client_header_octets], &vectors.client_initial_header);
    @memcpy(datagram[client_header_octets..][0..vectors.client_initial_payload.len], &vectors.client_initial_payload);
    const total = keys.seal(
        &datagram,
        client_packet_number_offset,
        client_header_octets,
        vectors.client_initial_payload.len,
        client_packet_number,
    ) catch return error.ClientInitialSeal;
    if (total != vectors.client_initial_protected.len) return error.ClientInitialSeal;
    if (!std.mem.eql(u8, &vectors.client_initial_protected, datagram[0..total])) return error.ClientInitialSeal;

    var received = vectors.client_initial_protected;
    const opened = keys.open(&received, client_packet_number_offset, null) catch return error.ClientInitialOpen;
    if (opened.number != client_packet_number) return error.ClientInitialOpen;
    if (!std.mem.eql(u8, &vectors.client_initial_payload, opened.payload)) return error.ClientInitialOpen;
}

fn serverInitial(comptime Backend: type) Failure!void {
    const Keys = protect.KeysOf(Backend);
    const keys: Keys = .initial(&vectors.destination_connection_id, .server);

    var datagram: [vectors.server_initial_protected.len]u8 = @splat(0);
    @memcpy(datagram[0..server_header_octets], &vectors.server_initial_header);
    @memcpy(datagram[server_header_octets..][0..vectors.server_initial_payload.len], &vectors.server_initial_payload);
    const total = keys.seal(
        &datagram,
        server_packet_number_offset,
        server_header_octets,
        vectors.server_initial_payload.len,
        server_packet_number,
    ) catch return error.ServerInitialSeal;
    if (!std.mem.eql(u8, &vectors.server_initial_protected, datagram[0..total])) return error.ServerInitialSeal;

    var received = vectors.server_initial_protected;
    const opened = keys.open(&received, server_packet_number_offset, null) catch return error.ServerInitialOpen;
    if (opened.number != server_packet_number) return error.ServerInitialOpen;
    if (!std.mem.eql(u8, &vectors.server_initial_payload, opened.payload)) return error.ServerInitialOpen;
}

fn retryTag(comptime Backend: type) Failure!void {
    const integrity = retry.Integrity(Backend);
    var scratch: [retry.pseudoPacketOctets(vectors.destination_connection_id.len, vectors.retry_packet.len)]u8 = undefined;
    integrity.verify(&scratch, &vectors.destination_connection_id, &vectors.retry_packet) catch
        return error.RetryTag;
    // And the tag binds the identifier: under any other one it must fail.
    var other = vectors.destination_connection_id;
    other[other.len - 1] ^= 1;
    if (integrity.verify(&scratch, &other, &vectors.retry_packet)) |_| {
        return error.RetryTag;
    } else |err| switch (err) {
        error.IntegrityFailed => {},
        // The scratch is sized for this packet above, the identifier is eight
        // octets and the packet ends in a tag, so any other refusal is the
        // check itself going wrong rather than the backend.
        error.ScratchTooSmall, error.ConnectionIdTooLong, error.Truncated => return error.RetryTag,
    }
}

fn chachaShortHeader(comptime Backend: type) Failure!void {
    const Keys = protect.KeysOf(Backend);
    const schedule = secrets.Schedule(Backend);
    const secret = secrets.Secret.init(&vectors.chacha_secret) catch return error.ChaChaPacket;
    const keys: Keys = .fromSecret(.chacha20_poly1305_sha256, &secret);
    if (!std.mem.eql(u8, &vectors.chacha_key, keys.key())) return error.ChaChaPacket;
    if (!std.mem.eql(u8, &vectors.chacha_iv, &keys.iv)) return error.ChaChaPacket;
    if (!std.mem.eql(u8, &vectors.chacha_hp, keys.headerKey())) return error.ChaChaPacket;

    const updated = schedule.update(.chacha20_poly1305_sha256, &secret);
    if (!std.mem.eql(u8, &vectors.chacha_ku, updated.bytes())) return error.KeyUpdate;

    var datagram: [vectors.chacha_packet.len]u8 = @splat(0);
    @memcpy(datagram[0..chacha_header_octets], &vectors.chacha_header);
    @memcpy(datagram[chacha_header_octets..][0..vectors.chacha_plaintext.len], &vectors.chacha_plaintext);
    const total = keys.seal(
        &datagram,
        chacha_packet_number_offset,
        chacha_header_octets,
        vectors.chacha_plaintext.len,
        chacha_packet_number,
    ) catch return error.ChaChaPacket;
    if (!std.mem.eql(u8, &vectors.chacha_packet, datagram[0..total])) return error.ChaChaPacket;

    var received = vectors.chacha_packet;
    const opened = keys.open(&received, chacha_packet_number_offset, chacha_packet_number - 1) catch
        return error.ChaChaPacket;
    if (opened.number != chacha_packet_number) return error.ChaChaPacket;
    if (!std.mem.eql(u8, &vectors.chacha_plaintext, opened.payload)) return error.ChaChaPacket;
}

/// Fixed inputs for the differential half. Not secrets and not vectors: any
/// octets will do, as long as both backends see the same ones.
const probe_key: [32]u8 = .{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
const probe_nonce: [12]u8 = .{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
const probe_ad = "a header, as associated data";
const probe_plaintext = "a payload long enough to cross a sixteen-octet block boundary twice";
const probe_prk: [48]u8 = @splat(0x5a);
/// A well-formed `HkdfLabel` for 48 octets of "quic key", as section 5.1 would
/// build one under SHA-384 — though for a differential any octets would do.
const probe_info = "\x00\x30\x0etls13 quic key\x00";

fn againstStd(comptime Backend: type) Failure!void {
    // AES-256-GCM.
    var ours = probe_plaintext.*;
    var theirs = probe_plaintext.*;
    var our_tag: [16]u8 = undefined;
    var their_tag: [16]u8 = undefined;
    Backend.aes256GcmSeal(&ours, &our_tag, probe_ad, &probe_nonce, &probe_key);
    backend.Std.aes256GcmSeal(&theirs, &their_tag, probe_ad, &probe_nonce, &probe_key);
    if (!std.mem.eql(u8, &ours, &theirs)) return error.Aes256Gcm;
    if (!std.mem.eql(u8, &our_tag, &their_tag)) return error.Aes256Gcm;
    Backend.aes256GcmOpen(&ours, &our_tag, probe_ad, &probe_nonce, &probe_key) catch return error.Aes256Gcm;
    if (!std.mem.eql(u8, &ours, probe_plaintext)) return error.Aes256Gcm;

    // And over an empty plaintext, the shape the Retry tag takes at AES-128.
    var nothing: [0]u8 = .{};
    Backend.aes256GcmSeal(&nothing, &our_tag, probe_ad, &probe_nonce, &probe_key);
    backend.Std.aes256GcmSeal(&nothing, &their_tag, probe_ad, &probe_nonce, &probe_key);
    if (!std.mem.eql(u8, &our_tag, &their_tag)) return error.Aes256Gcm;

    // HKDF-SHA384, at the widest length h3 ever asks for. That is one HMAC
    // block, T(1), so RFC 5869's block chaining is never reached — and never
    // needed: the contract bounds `out.len` at 48.
    var our_secret: [48]u8 = undefined;
    var their_secret: [48]u8 = undefined;
    Backend.hkdfSha384Expand(&our_secret, &probe_prk, probe_info);
    backend.Std.hkdfSha384Expand(&their_secret, &probe_prk, probe_info);
    if (!std.mem.eql(u8, &our_secret, &their_secret)) return error.HkdfSha384;

    // The AES-256 block AES-256-GCM's header protection is made of.
    var our_block: [16]u8 = undefined;
    var their_block: [16]u8 = undefined;
    Backend.aes256EncryptBlock(&our_block, probe_plaintext[0..16], &probe_key);
    backend.Std.aes256EncryptBlock(&their_block, probe_plaintext[0..16], &probe_key);
    if (!std.mem.eql(u8, &our_block, &their_block)) return error.Aes256Block;
}

/// What a forgery is: one octet of the tag, the ciphertext or the header
/// flipped. Every tag octet in turn, because a binding that compares a prefix
/// of the tag passes a test that flips only the last one; the first and last of
/// the other two, because a binding that authenticates a suffix passes one that
/// flips only the first.
const Tamper = union(enum) { tag: u8, ciphertext_first, ciphertext_last, associated_data_first, associated_data_last };

const tampers = blk: {
    var list: [crypto.tag_octets + 4]Tamper = undefined;
    for (0..crypto.tag_octets) |index| list[index] = .{ .tag = index };
    list[crypto.tag_octets + 0] = .ciphertext_first;
    list[crypto.tag_octets + 1] = .ciphertext_last;
    list[crypto.tag_octets + 2] = .associated_data_first;
    list[crypto.tag_octets + 3] = .associated_data_last;
    break :blk list;
};

fn refusesForgeries(comptime Backend: type) Failure!void {
    for (tampers) |tamper| {
        for (std.enums.values(crypto.Suite)) |suite| try refusesForgery(Backend, suite, tamper);
    }
}

fn refusesForgery(comptime Backend: type, suite: crypto.Suite, tamper: Tamper) Failure!void {
    var data = probe_plaintext.*;
    var ad = probe_ad.*;
    var tag: [16]u8 = undefined;
    seal(Backend, suite, &data, &tag, &ad);
    switch (tamper) {
        .tag => |index| tag[index] ^= 0x80,
        .ciphertext_first => data[0] ^= 0x01,
        .ciphertext_last => data[data.len - 1] ^= 0x01,
        .associated_data_first => ad[0] ^= 0x01,
        .associated_data_last => ad[ad.len - 1] ^= 0x01,
    }
    if (open(Backend, suite, &data, &tag, &ad)) |_| {
        return error.ForgeryAccepted;
    } else |err| {
        // The only error the contract permits, which is what makes an
        // exhaustive switch the right shape for the check.
        switch (err) {
            error.AuthenticationFailed => {},
        }
    }
}

fn seal(comptime Backend: type, suite: crypto.Suite, data: []u8, tag: *[16]u8, ad: []const u8) void {
    switch (suite) {
        .aes_128_gcm_sha256 => Backend.aes128GcmSeal(data, tag, ad, &probe_nonce, probe_key[0..16]),
        .aes_256_gcm_sha384 => Backend.aes256GcmSeal(data, tag, ad, &probe_nonce, &probe_key),
        .chacha20_poly1305_sha256 => Backend.chacha20Poly1305Seal(data, tag, ad, &probe_nonce, &probe_key),
    }
}

fn open(comptime Backend: type, suite: crypto.Suite, data: []u8, tag: *const [16]u8, ad: []const u8) backend.AuthenticationError!void {
    switch (suite) {
        .aes_128_gcm_sha256 => try Backend.aes128GcmOpen(data, tag, ad, &probe_nonce, probe_key[0..16]),
        .aes_256_gcm_sha384 => try Backend.aes256GcmOpen(data, tag, ad, &probe_nonce, &probe_key),
        .chacha20_poly1305_sha256 => try Backend.chacha20Poly1305Open(data, tag, ad, &probe_nonce, &probe_key),
    }
}

// No citation here, deliberately: the requirements this exercises are cited at
// their implementations and tested by corpus/rfc9001.zig, and a harness that
// reruns them for another backend is evidence about the backend, not the RFC.
test "the default backend passes RFC 9001 appendix A" {
    try check(backend.Std);
}

/// `backend.Std` with exactly one primitive wrong, so the tests below can show
/// that `check` notices — a check that cannot fail is the silence
/// docs/VERIFICATION.md section 1 records six times.
fn Mutant(comptime broken: enum {
    chacha20_keystream,
    hkdf_sha256_expand,
    hkdf_sha384,
    aes128_gcm_open,
    aes256_gcm_open,
    aes128_block,
    aes256_block,
    tag_prefix,
}) type {
    return struct {
        const Std = backend.Std;
        pub fn aes128GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) void {
            Std.aes128GcmSeal(data, tag, ad, nonce, key);
        }
        pub fn aes128GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) backend.AuthenticationError!void {
            // A binding that refuses everything, which a round trip of its own
            // seal would not notice either.
            if (broken == .aes128_gcm_open) return error.AuthenticationFailed;
            return Std.aes128GcmOpen(data, tag, ad, nonce, key);
        }
        pub fn aes256GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
            Std.aes256GcmSeal(data, tag, ad, nonce, key);
        }
        pub fn aes256GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) backend.AuthenticationError!void {
            // The forgery a careless binding produces: decrypt, and never
            // compare the tag.
            if (broken == .aes256_gcm_open) {
                Std.aes256GcmOpen(data, tag, ad, nonce, key) catch |err| switch (err) {
                    error.AuthenticationFailed => {},
                };
                return;
            }
            return Std.aes256GcmOpen(data, tag, ad, nonce, key);
        }
        pub fn chacha20Poly1305Seal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
            Std.chacha20Poly1305Seal(data, tag, ad, nonce, key);
        }
        pub fn chacha20Poly1305Open(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) backend.AuthenticationError!void {
            // A binding that compares only the first eight octets of the tag:
            // correct on every honest packet, and on a forgery that changed
            // the last octet, which is the one a careless test flips.
            if (broken == .tag_prefix) {
                if (data.len > probe_plaintext.len) return Std.chacha20Poly1305Open(data, tag, ad, nonce, key);
                // RFC 8439 section 2.8 encrypts from block 1, so the plaintext
                // is the ciphertext under that keystream, and resealing it
                // gives the tag an honest binding would compare against.
                var keystream: [probe_plaintext.len]u8 = undefined;
                Std.chacha20Keystream(keystream[0..data.len], key, 1, nonce);
                var plain: [probe_plaintext.len]u8 = undefined;
                for (data, keystream[0..data.len], plain[0..data.len]) |cipher, key_octet, *out| out.* = cipher ^ key_octet;
                var resealed = plain;
                var expected: [16]u8 = undefined;
                Std.chacha20Poly1305Seal(resealed[0..data.len], &expected, ad, nonce, key);
                if (!std.mem.eql(u8, expected[0..8], tag[0..8])) return error.AuthenticationFailed;
                @memcpy(data, plain[0..data.len]);
                return;
            }
            return Std.chacha20Poly1305Open(data, tag, ad, nonce, key);
        }
        pub fn aes128EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [16]u8) void {
            Std.aes128EncryptBlock(out, in, key);
            if (broken == .aes128_block) out[0] ^= 1;
        }
        pub fn aes256EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [32]u8) void {
            Std.aes256EncryptBlock(out, in, key);
            if (broken == .aes256_block) out[15] ^= 1;
        }
        pub fn chacha20Keystream(out: []u8, key: *const [32]u8, counter: u32, nonce: *const [12]u8) void {
            // The mistake section 5.4.4 is easiest to make: a keystream that
            // starts one block late.
            Std.chacha20Keystream(out, key, if (broken == .chacha20_keystream) counter +% 1 else counter, nonce);
        }
        pub fn hkdfSha256Extract(prk: *[32]u8, salt: []const u8, ikm: []const u8) void {
            Std.hkdfSha256Extract(prk, salt, ikm);
        }
        pub fn hkdfSha256Expand(out: []u8, prk: *const [32]u8, info: []const u8) void {
            Std.hkdfSha256Expand(out, prk, info);
            if (broken == .hkdf_sha256_expand) out[0] ^= 1;
        }
        pub fn hkdfSha384Expand(out: []u8, prk: *const [48]u8, info: []const u8) void {
            Std.hkdfSha384Expand(out, prk, info);
            if (broken == .hkdf_sha384) out[out.len - 1] ^= 1;
        }
    };
}

test "a backend with one primitive wrong fails, and says which" {
    // Each mutant is caught by the check written for its primitive and not
    // by an earlier one, which is what makes the error name worth reading.
    try std.testing.expectError(error.InitialKeys, check(Mutant(.hkdf_sha256_expand)));
    try std.testing.expectError(error.AesHeaderProtection, check(Mutant(.aes128_block)));
    try std.testing.expectError(error.ChaChaHeaderProtection, check(Mutant(.chacha20_keystream)));
    try std.testing.expectError(error.ClientInitialOpen, check(Mutant(.aes128_gcm_open)));
    try std.testing.expectError(error.HkdfSha384, check(Mutant(.hkdf_sha384)));
    try std.testing.expectError(error.Aes256Block, check(Mutant(.aes256_block)));
    try std.testing.expectError(error.ForgeryAccepted, check(Mutant(.aes256_gcm_open)));
    // Only a tag flipped in its first half catches this one.
    try std.testing.expectError(error.ForgeryAccepted, check(Mutant(.tag_prefix)));
}
