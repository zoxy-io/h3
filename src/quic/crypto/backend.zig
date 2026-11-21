//! The packet-protection backend: every cryptographic primitive this package
//! computes with, behind one comptime seam.
//!
//! docs/DESIGN.md section 4 keeps packet protection inside this package, and
//! the argument for that is about *where QUIC's mistakes live* — the nonce
//! construction, the header protection sampling offset, the key update and
//! the AEAD limits all sit beside the packet parser that produces their inputs.
//! None of that argument is about whose AES it is. A consumer that wants every
//! primitive from one audited library (zoxy's policy is libcrypto, through
//! zssl, because constant-time code wants the most-watched assembly) supplies a
//! backend type here, and everything above the primitives stays this package's.
//!
//! ## What is behind the seam, and what is not
//!
//! Behind it: the three AEADs RFC 9001 section 5.3 admits, sealing and opening
//! in place; the two raw ciphers section 5.4's header protection masks are
//! made of — one AES block, and the ChaCha20 keystream; and HKDF-SHA256 and
//! HKDF-SHA384, which RFC 8446 section 7.1's HKDF-Expand-Label is built on.
//!
//! Not behind it, and deliberately: the nonce (section 5.3's IV XOR packet
//! number), the associated data (the header), which octets the sample is taken
//! from (section 5.4.2), how the mask is applied to the first octet and the
//! packet number (section 5.4.1), the labels and the `HkdfLabel` encoding (RFC
//! 8446 section 7.1), the key update (RFC 9001 section 6), the confidentiality
//! and integrity limits (section 6.6), and the Retry integrity key and nonce
//! (section 5.8). A backend computes; it decides nothing.
//!
//! ## The contract
//!
//! A backend is a type — usually a `struct` with no fields — that declares at
//! least the twelve functions below, with exactly these signatures; anything
//! else it declares is its own business. `check` compares them at compile
//! time, so a backend with a wrong or missing declaration is a compile error
//! naming the declaration rather than a type mismatch three calls deep. The
//! error set of every `Open` must be exactly `error{AuthenticationFailed}`
//! (the named `AuthenticationError` is that set): an inferred `!void` is a
//! different type and fails the check.
//!
//! **AEAD**, AEAD_AES_128_GCM, AEAD_AES_256_GCM and AEAD_CHACHA20_POLY1305 of
//! RFC 5116 and RFC 8439, with a 12-octet nonce and a 16-octet tag:
//!
//!     aes128GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8,
//!                   nonce: *const [12]u8, key: *const [16]u8) void
//!     aes128GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8,
//!                   nonce: *const [12]u8, key: *const [16]u8) AuthenticationError!void
//!     aes256GcmSeal / aes256GcmOpen               — the same, with key: *const [32]u8
//!     chacha20Poly1305Seal / chacha20Poly1305Open — the same, with key: *const [32]u8
//!
//! - **In place, always.** `data` is the plaintext on entry to `Seal` and the
//!   ciphertext on return, and the reverse for `Open`; there is no separate
//!   output buffer, so there is no partial-overlap case to define.
//! - **No other aliasing.** `ad`, `tag`, `nonce` and `key` never overlap `data`
//!   or each other. In a packet `ad` is the header and ends where `data`
//!   begins, and `tag` (for `Open`) begins where `data` ends — adjacent, not
//!   overlapping. A backend may rely on that.
//! - **Empty `data` is legal.** It is empty for the Retry integrity tag (RFC
//!   9001 section 5.8 seals an empty plaintext under the pseudo-packet as
//!   `ad`), and a backend may not refuse it. h3 never passes an empty `ad`.
//! - **Lengths.** `data` is at most `data_octets_max` (65527, the largest UDP
//!   payload) octets. `ad` is a packet header — at most a long header, well
//!   under 256 octets — or, for the Retry tag, a pseudo-packet whose length is
//!   bounded by the caller's Retry buffer (`Connection` holds it under 1 KiB).
//!   Every call carries the raw key: there is no key object and no state
//!   between calls, so a backend that caches expanded key schedules does so on
//!   its own account.
//! - **`Seal` cannot fail.** Every input is sized by the types above, so a
//!   backend whose underlying library can report failure must treat that as a
//!   fatal internal error (a panic), never as a value to return. h3 would
//!   otherwise have sent a packet it never sealed.
//! - **`Open` failure.** `error.AuthenticationFailed` and nothing else, for a
//!   tag that does not verify. The contents of `data` are then **unspecified**
//!   — `std.crypto` deliberately scrubs them — and h3 never reads them: where
//!   it must try a second key on the same packet (section 6.3's key phases) it
//!   keeps its own copy of the ciphertext first.
//! - **Constant time** in the key, the plaintext and the tag comparison. That
//!   is the property the seam exists to let a consumer choose an
//!   implementation for, and this package cannot check it.
//!
//! **Header protection**, RFC 9001 sections 5.4.3 and 5.4.4:
//!
//!     aes128EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [16]u8) void
//!     aes256EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [32]u8) void
//!     chacha20Keystream(out: []u8, key: *const [32]u8, counter: u32,
//!                       nonce: *const [12]u8) void
//!
//! - `EncryptBlock` is one raw AES block (ECB over exactly sixteen octets).
//!   `out` and `in` never overlap.
//! - `chacha20Keystream` writes `out.len` octets of RFC 8439 section 2.4's
//!   ChaCha20 keystream — the encryption of `out.len` zero octets — starting at
//!   block `counter`. h3 passes the sample's first four octets, read
//!   little-endian, as `counter` and its last twelve as `nonce`; `out.len` is 5
//!   in every call it makes, and a backend must accept 1 through 64. (A
//!   libcrypto `EVP_chacha20` takes a 16-octet IV that is `counter` in
//!   little-endian followed by `nonce` — which is the 16-octet sample exactly.)
//!
//! **Key derivation**, RFC 5869:
//!
//!     hkdfSha256Extract(prk: *[32]u8, salt: []const u8, ikm: []const u8) void
//!     hkdfSha256Expand(out: []u8, prk: *const [32]u8, info: []const u8) void
//!     hkdfSha384Expand(out: []u8, prk: *const [48]u8, info: []const u8) void
//!
//! - Extract is only ever SHA-256: RFC 9001 section 5.2's Initial secret,
//!   salted with the version 1 salt over the client's Destination Connection
//!   ID (0 to 20 octets).
//! - Expand fills `out` completely; `out.len` is 1 through 48 (the widest
//!   secret, `crypto.secret_octets_max`), which `secrets.expandLabel` asserts.
//!   `info` is the `HkdfLabel` h3 has already built, at most 19 octets. `out`
//!   never overlaps `prk` or `info`.
//! - None of the three can fail, for the reason `Seal` cannot.

const std = @import("std");

const assert = @import("../../assert.zig").assert;

/// The widths the contract's signatures are written in, named so that the
/// callers above the seam slice their key storage with the same numbers the
/// signatures take.
pub const aes128_key_octets: usize = 16;
pub const aes256_key_octets: usize = 32;
pub const chacha20_key_octets: usize = 32;
pub const sha256_octets: usize = 32;
pub const sha384_octets: usize = 48;

/// The longest `data` any AEAD call carries: the largest UDP payload.
pub const data_octets_max: usize = 65_535 - 8;

/// The one error an `Open` may return. Named rather than inferred, so that a
/// backend's signature can be compared with the contract's exactly.
pub const AuthenticationError = error{AuthenticationFailed};

/// The signatures the contract above states in prose, as types `check` compares
/// against. One per shape: the three AEADs share two of them per key width.
pub fn Seal(comptime key_octets: usize) type {
    return fn (
        data: []u8,
        tag: *[16]u8,
        ad: []const u8,
        nonce: *const [12]u8,
        key: *const [key_octets]u8,
    ) void;
}

pub fn Open(comptime key_octets: usize) type {
    return fn (
        data: []u8,
        tag: *const [16]u8,
        ad: []const u8,
        nonce: *const [12]u8,
        key: *const [key_octets]u8,
    ) AuthenticationError!void;
}

pub fn EncryptBlock(comptime key_octets: usize) type {
    return fn (out: *[16]u8, in: *const [16]u8, key: *const [key_octets]u8) void;
}

pub const Keystream = fn (out: []u8, key: *const [32]u8, counter: u32, nonce: *const [12]u8) void;

pub fn Expand(comptime prk_octets: usize) type {
    return fn (out: []u8, prk: *const [prk_octets]u8, info: []const u8) void;
}

pub const Extract = fn (prk: *[32]u8, salt: []const u8, ikm: []const u8) void;

/// Every declaration the contract requires, and the type it must have.
const required = .{
    .{ "aes128GcmSeal", Seal(aes128_key_octets) },
    .{ "aes128GcmOpen", Open(aes128_key_octets) },
    .{ "aes256GcmSeal", Seal(aes256_key_octets) },
    .{ "aes256GcmOpen", Open(aes256_key_octets) },
    .{ "chacha20Poly1305Seal", Seal(chacha20_key_octets) },
    .{ "chacha20Poly1305Open", Open(chacha20_key_octets) },
    .{ "aes128EncryptBlock", EncryptBlock(aes128_key_octets) },
    .{ "aes256EncryptBlock", EncryptBlock(aes256_key_octets) },
    .{ "chacha20Keystream", Keystream },
    .{ "hkdfSha256Extract", Extract },
    .{ "hkdfSha256Expand", Expand(sha256_octets) },
    .{ "hkdfSha384Expand", Expand(sha384_octets) },
};

/// The number of declarations a backend provides. Stated so that adding one to
/// `required` without updating the module comment is a test failure.
pub const declarations: u32 = required.len;

/// Refuse, at compile time, a backend that does not satisfy the contract.
///
/// Called by every generic that takes a backend, so the first use of a wrong
/// one fails here, naming the declaration, rather than inside a seal.
pub fn check(comptime Backend: type) void {
    comptime {
        assert(declarations == 12);
        for (required) |entry| {
            const name: []const u8 = entry[0];
            const Expected: type = entry[1];
            if (!@hasDecl(Backend, name)) {
                @compileError("crypto backend " ++ @typeName(Backend) ++ " does not declare `" ++
                    name ++ "`; see src/quic/crypto/backend.zig for the contract");
            }
            const Actual = @TypeOf(@field(Backend, name));
            if (Actual != Expected) {
                @compileError("crypto backend " ++ @typeName(Backend) ++ ": `" ++ name ++ "` is " ++
                    @typeName(Actual) ++ ", the contract requires " ++ @typeName(Expected));
            }
        }
    }
}

/// `std.crypto`, and the default everywhere a backend is a parameter.
///
/// Every function is the call this package made directly before the seam
/// existed, and `zig build bench`'s two protection rows measured the same band
/// before and after it was introduced. `EncryptBlock` expands the AES key
/// schedule on every call, as the code before it did.
pub const Std = struct {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

    comptime {
        // The contract's widths are std.crypto's, and the two must not drift.
        assert(Aes128Gcm.tag_length == 16);
        assert(Aes128Gcm.nonce_length == 12);
        assert(Aes256Gcm.key_length == 32);
        assert(ChaCha20Poly1305.key_length == 32);
        assert(HkdfSha256.prk_length == 32);
        assert(HkdfSha384.prk_length == 48);
    }

    pub fn aes128GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) void {
        Aes128Gcm.encrypt(data, tag, data, ad, nonce.*, key.*);
    }

    pub fn aes128GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) AuthenticationError!void {
        Aes128Gcm.decrypt(data, data, tag.*, ad, nonce.*, key.*) catch return error.AuthenticationFailed;
    }

    pub fn aes256GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
        Aes256Gcm.encrypt(data, tag, data, ad, nonce.*, key.*);
    }

    pub fn aes256GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) AuthenticationError!void {
        Aes256Gcm.decrypt(data, data, tag.*, ad, nonce.*, key.*) catch return error.AuthenticationFailed;
    }

    pub fn chacha20Poly1305Seal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
        ChaCha20Poly1305.encrypt(data, tag, data, ad, nonce.*, key.*);
    }

    pub fn chacha20Poly1305Open(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) AuthenticationError!void {
        ChaCha20Poly1305.decrypt(data, data, tag.*, ad, nonce.*, key.*) catch return error.AuthenticationFailed;
    }

    pub fn aes128EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [16]u8) void {
        std.crypto.core.aes.Aes128.initEnc(key.*).encrypt(out, in);
    }

    pub fn aes256EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [32]u8) void {
        std.crypto.core.aes.Aes256.initEnc(key.*).encrypt(out, in);
    }

    pub fn chacha20Keystream(out: []u8, key: *const [32]u8, counter: u32, nonce: *const [12]u8) void {
        std.crypto.stream.chacha.ChaCha20IETF.stream(out, counter, key.*, nonce.*);
    }

    pub fn hkdfSha256Extract(prk: *[32]u8, salt: []const u8, ikm: []const u8) void {
        prk.* = HkdfSha256.extract(salt, ikm);
    }

    pub fn hkdfSha256Expand(out: []u8, prk: *const [32]u8, info: []const u8) void {
        HkdfSha256.expand(out, info, prk.*);
    }

    pub fn hkdfSha384Expand(out: []u8, prk: *const [48]u8, info: []const u8) void {
        HkdfSha384.expand(out, info, prk.*);
    }
};

comptime {
    check(Std);
}

/// Compare two tags in time that does not depend on where they differ.
///
/// Not a primitive of the contract — it is a comparison, and RFC 9001 section
/// 5.8's Retry tag it compares is not a secret — but it is the one other place
/// this package would reach for `std.crypto`, and keeping it in this file keeps
/// `std.crypto` in one file, which `zig build lint` enforces.
pub fn tagsEqual(a: *const [16]u8, b: *const [16]u8) bool {
    return std.crypto.timing_safe.eql([16]u8, a.*, b.*);
}

test "the contract names twelve declarations, and Std has every one" {
    // The module comment lists them; this pins the count it lists.
    try std.testing.expectEqual(@as(u32, 12), declarations);
    inline for (required) |entry| {
        try std.testing.expect(@hasDecl(Std, entry[0]));
    }
}

test "Std seals and opens in place, and refuses a tag that does not verify" {
    const key: [16]u8 = @splat(0x11);
    const nonce: [12]u8 = @splat(0x22);
    const ad = "header";
    var data = "payload".*;
    var tag: [16]u8 = undefined;
    Std.aes128GcmSeal(&data, &tag, ad, &nonce, &key);
    try std.testing.expect(!std.mem.eql(u8, &data, "payload"));
    try Std.aes128GcmOpen(&data, &tag, ad, &nonce, &key);
    try std.testing.expectEqualStrings("payload", &data);

    Std.aes128GcmSeal(&data, &tag, ad, &nonce, &key);
    tag[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, Std.aes128GcmOpen(&data, &tag, ad, &nonce, &key));
}

test "the ChaCha20 keystream is the encryption of zeroes" {
    const key: [32]u8 = @splat(0x42);
    const nonce: [12]u8 = @splat(0x24);
    var stream: [5]u8 = undefined;
    Std.chacha20Keystream(&stream, &key, 7, &nonce);
    var xored: [5]u8 = undefined;
    const zeroes: [5]u8 = @splat(0);
    std.crypto.stream.chacha.ChaCha20IETF.xor(&xored, &zeroes, 7, key, nonce);
    try std.testing.expectEqualSlices(u8, &xored, &stream);
}

test "tagsEqual is equality" {
    const a: [16]u8 = @splat(7);
    var b = a;
    try std.testing.expect(tagsEqual(&a, &b));
    b[15] ^= 1;
    try std.testing.expect(!tagsEqual(&a, &b));
}
