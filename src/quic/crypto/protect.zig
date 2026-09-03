//! RFC 9001 sections 5.3 and 5.4: packet protection and header protection.
//!
//! Two layers, applied in that order on the way out and unwound in the reverse
//! order on the way in, and the order is the whole difficulty. The AEAD
//! authenticates the header — including the packet number — so the header must
//! be final before the payload is sealed. Header protection then hides the bits
//! that say *how long the packet number is*, sampling its mask from the AEAD's
//! own output. A receiver therefore has to unwind header protection before it
//! knows where the header ends, using a sample drawn from a fixed offset
//! chosen so that the sample never overlaps the packet number:
//!
//!     sample = packet[packet_number_offset + 4 ..][0..16]
//!
//! Four, because a packet number is at most four octets; sixteen, because the
//! tag guarantees that many octets exist past the number even in the shortest
//! packet.
//!
//! ## What this module does not decide
//!
//! Where `packet_number_offset` is. That comes from `packet.zig`, which parses
//! the part of the header that is *not* protected, and it is the one number
//! this module cannot compute for itself: in a long header it follows the
//! Length field, and in a short header it follows a Destination Connection ID
//! whose length is not on the wire at all. Passing it in is what keeps this
//! module from having to know which of the two it is looking at, and what keeps
//! a short-header parse from guessing a length the peer would then control.
//!
//! ## In-place, and destructive on failure
//!
//! `open` works in the caller's datagram buffer, and it removes header
//! protection *before* it can know whether the AEAD will authenticate. A packet
//! that fails to open therefore leaves the buffer modified — the first octet
//! and the packet number are unmasked, and `std.crypto`'s AEADs overwrite the
//! plaintext region with undefined bytes on a tag mismatch. That is fine and it
//! is stated here rather than discovered: RFC 9001 section 5.4 requires a
//! packet that fails authentication to be *discarded*, not retried under other
//! keys, so there is nothing left to preserve. What a caller must not do is
//! re-parse the same octets afterwards and believe them.

const std = @import("std");

const assert = @import("../../assert.zig").assert;
const crypto = @import("../crypto.zig");
const packet_number = @import("../packet_number.zig");
const secrets = @import("secrets.zig");

const Secret = secrets.Secret;
const Side = crypto.Side;
const Suite = crypto.Suite;

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
//# The sample of ciphertext is taken starting from an offset of 4 bytes
//# after the start of the Packet Number field. That is, in sampling packet
//# ciphertext for header protection, the Packet Number field is assumed to
//# be 4 bytes long (its maximum possible encoded length).
/// Section 5.4.2: the sample begins four octets past the start of the packet
/// number, so that it is the same octets whatever the number's length turns out
/// to be.
pub const sample_offset: usize = 4;

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3
//# This algorithm samples 16 bytes from the packet ciphertext.
/// Section 5.4.1: sixteen octets, one AES block.
pub const sample_octets: usize = 16;

comptime {
    assert(sample_offset == packet_number.octets_max);
    assert(sample_octets == 16);
    // The invariant that makes a fixed sample offset safe: after the longest
    // packet number there are still at least `tag_octets` octets, so the sample
    // never runs past a well-formed packet.
    assert(sample_octets <= crypto.tag_octets + packet_number.octets_max - sample_offset + sample_offset);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
//# if (packet[0] & 0x80) == 0x80: # Long header: 4 bits masked packet[0] ^=
//# mask[0] & 0x0f else: # Short header: 5 bits masked packet[0] ^= mask[0]
//# & 0x1f
/// The bits header protection masks in the first octet, per form.
///
/// Long headers protect the two reserved bits and the two packet number length
/// bits; short headers protect those plus the key phase. The spin bit is
/// deliberately outside both — it is meant to be observable by the path.
const first_octet_mask_long: u8 = 0x0f;
const first_octet_mask_short: u8 = 0x1f;

/// RFC 9000 sections 17.2 and 17.3: the bits that must be zero once header
/// protection is removed. A peer setting one is a `PROTOCOL_VIOLATION`, and
/// this is the only place in the stack where they are legible.
const reserved_mask_long: u8 = 0x0c;
const reserved_mask_short: u8 = 0x18;

/// The high bit of the first octet: set for a long header (section 17.2).
const header_form_long: u8 = 0x80;

//= https://www.rfc-editor.org/rfc/rfc9001#section-6
//# The Key Phase bit indicates which packet protection keys are used to
//# protect the packet. The Key Phase bit is initially set to 0 for the
//# first set of 1-RTT packets and toggled to signal each subsequent key
//# update.
/// RFC 9001 section 6: the Key Phase bit of a short header, which says which
/// generation of 1-RTT keys protected the packet.
const key_phase_bit: u8 = 0x04;

/// The two low bits of the first octet carry the packet number length, minus
/// one (sections 17.2 and 17.3).
const packet_number_length_mask: u8 = 0x03;

comptime {
    assert(first_octet_mask_long == reserved_mask_long | packet_number_length_mask);
    // The short-header mask adds exactly the key phase bit to the long one.
    assert(first_octet_mask_short == reserved_mask_short | packet_number_length_mask | key_phase_bit);
    // The key phase is under header protection, which is why reading it needs
    // the mask removed first — and why `unprotectHeader` exists.
    assert(first_octet_mask_short & key_phase_bit != 0);
}

//= https://www.rfc-editor.org/rfc/rfc9001#section-6.3
//# For this reason, endpoints MUST be able to retain two sets of packet
//# protection keys for receiving packets: the current and the next.
/// One direction's protection state at one encryption level.
///
/// Derived from a traffic secret and then immutable: a key update produces a
/// new `Keys` from a new secret rather than mutating this one, which is what
/// keeps the previous generation available for the reordered packets section
/// 6.3 requires an endpoint to keep accepting.
pub const Keys = struct {
    suite: Suite,
    key_storage: [crypto.key_octets_max]u8,
    key_octets: u8,
    iv: [crypto.iv_octets]u8,
    header_key_storage: [crypto.key_octets_max]u8,
    header_key_octets: u8,

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.1
    //# The current encryption level secret and the label "quic key" are
    //# input to the KDF to produce the AEAD key; the label "quic iv" is
    //# used to derive the Initialization Vector (IV); see Section 5.3. The
    //# header protection key uses the "quic hp" label; see Section 5.4.
    /// RFC 9001 section 5.1: derive a level's keys from its traffic secret.
    pub fn fromSecret(suite: Suite, secret: *const Secret) Keys {
        assert(secret.length == suite.hashOctets());

        var keys: Keys = .{
            .suite = suite,
            .key_storage = @splat(0),
            .key_octets = suite.keyOctets(),
            .iv = @splat(0),
            .header_key_storage = @splat(0),
            .header_key_octets = suite.headerKeyOctets(),
        };
        secrets.expandLabel(suite, keys.key_storage[0..keys.key_octets], secret.bytes(), "quic key");
        secrets.expandLabel(suite, &keys.iv, secret.bytes(), "quic iv");
        secrets.expandLabel(suite, keys.header_key_storage[0..keys.header_key_octets], secret.bytes(), "quic hp");

        assert(keys.key_octets >= 16);
        assert(keys.header_key_octets >= 16);
        return keys;
    }

    /// RFC 9001 section 5.2: the Initial keys for one side of a connection,
    /// from the Destination Connection ID of the client's first Initial packet.
    pub fn initial(destination_connection_id: []const u8, side: Side) Keys {
        assert(destination_connection_id.len <= 20);
        var secret = secrets.initial(destination_connection_id, side);
        defer secret.discard();
        return fromSecret(secrets.initial_suite, &secret);
    }

    pub fn key(self: *const Keys) []const u8 {
        assert(self.key_octets <= crypto.key_octets_max);
        return self.key_storage[0..self.key_octets];
    }

    pub fn headerKey(self: *const Keys) []const u8 {
        assert(self.header_key_octets <= crypto.key_octets_max);
        return self.header_key_storage[0..self.header_key_octets];
    }

    pub const SealError = error{
        /// `buffer` has no room for the header, the payload and the tag.
        OutputTooLong,
        /// The packet number does not sit inside the header, or is not 1-4
        /// octets long. A caller bug, not a wire condition.
        HeaderMalformed,
        /// The packet is too short for section 5.4.2's sample. RFC 9001
        /// requires a sender to pad rather than emit one.
        SampleUnavailable,
    };

    /// Protect a packet in place.
    ///
    /// On entry `buffer[0..header_octets]` is the header with its packet number
    /// already written and its first octet unprotected, and
    /// `buffer[header_octets..][0..payload_octets]` is the plaintext. On return
    /// the first `header_octets + payload_octets + tag_octets` octets are the
    /// packet as it goes on the wire, and that length is what is returned.
    ///
    /// `packet_number` is the full 62-bit number, not the truncation written
    /// into the header: the nonce is built from all of it (section 5.3).
    pub fn seal(
        self: *const Keys,
        buffer: []u8,
        packet_number_offset: usize,
        header_octets: usize,
        payload_octets: usize,
        number: u64,
    ) SealError!usize {
        if (packet_number_offset >= header_octets) return error.HeaderMalformed;
        const number_octets = header_octets - packet_number_offset;
        if (number_octets > packet_number.octets_max) return error.HeaderMalformed;
        assert(number_octets >= packet_number.octets_min);
        if (number > packet_number.max) return error.HeaderMalformed;

        const total = header_octets + payload_octets + crypto.tag_octets;
        if (buffer.len < total) return error.OutputTooLong;
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
        //# To ensure that sufficient data is available for sampling,
        //# packets are padded so that the combined lengths of the encoded
        //# packet number and protected payload is at least 4 bytes longer
        //# than the sample required for header protection.
        // Section 5.4.2 makes this the *sender's* obligation: a packet too
        // short to sample is one the peer cannot unprotect, so refusing to
        // build one is better than emitting a packet that will be discarded.
        if (total < packet_number_offset + sample_offset + sample_octets) return error.SampleUnavailable;

        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
        //# When constructing packets, the AEAD function is applied prior to
        //# applying header protection; see Section 5.4. The unprotected
        //# packet header is part of the associated data (A).
        //
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
        //# The associated data, A, for the AEAD is the contents of the QUIC
        //# header, starting from the first byte of either the short or long
        //# header, up to and including the unprotected packet number. The
        //# input plaintext, P, for the AEAD is the payload of the QUIC
        //# packet, as described in [QUIC-TRANSPORT]. The output ciphertext,
        //# C, of the AEAD is transmitted in place of P.
        const packet_nonce = self.nonce(number);
        const associated_data = buffer[0..header_octets];
        const plaintext = buffer[header_octets..][0..payload_octets];
        var tag: [crypto.tag_octets]u8 = undefined;
        self.aeadSeal(plaintext, &tag, plaintext, associated_data, packet_nonce);
        @memcpy(buffer[header_octets + payload_octets ..][0..crypto.tag_octets], &tag);

        //= https://www.rfc-editor.org/rfc/rfc9001#section-9.5
        //# For the sending of packets, construction and protection of
        //# packet payloads and packet numbers MUST be free from side
        //# channels that would reveal the packet number or its encoded
        //# size.
        //= type=todo
        // A todo rather than an implementation claim, and the gap is one line
        // down: `applyHeaderMask` XORs `number_octets` octets, so its trip
        // count *is* the encoded size of a field header protection exists to
        // hide. `std.crypto`'s AEADs and the AES and ChaCha20 cores below are
        // constant-time, so the payload half of this holds; the loop is not,
        // and saying so is cheaper than pretending otherwise.
        const mask = self.headerMask(buffer[packet_number_offset + sample_offset ..][0..sample_octets]);
        applyHeaderMask(buffer, packet_number_offset, number_octets, mask);

        assert(total <= buffer.len);
        return total;
    }

    pub const OpenError = error{
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
        //# An endpoint MUST discard packets that are not long enough to
        //# contain a complete sample.
        /// Too short to hold a sample, or too short to hold a tag. Section
        /// 5.4.2 requires such a packet to be discarded without further work.
        Truncated,
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.5
        //# Failure to unprotect a packet does not necessarily indicate the
        //# existence of a protocol error in a peer or an attack. The
        //# truncated packet number encoding used in QUIC can cause packet
        //# numbers to be decoded incorrectly if they are delayed
        //# significantly.
        /// The AEAD tag did not verify. Section 5.4: discard the packet. Not a
        /// connection error — an off-path attacker can inject packets, and
        /// tearing the connection down on one is the attack.
        AuthenticationFailed,
        /// RFC 9000 sections 17.2 and 17.3: a reserved bit was set once header
        /// protection came off. Unlike the two above, this *is* a connection
        /// error of type `PROTOCOL_VIOLATION` — the bits are authenticated, so
        /// only the real peer can have set them.
        ReservedBitsSet,
    };

    pub const Opened = struct {
        /// The reconstructed 62-bit packet number.
        number: u64,
        /// Octets the number occupied on the wire, 1-4.
        number_octets: u8,
        /// The unprotected header, borrowed from the caller's buffer.
        header: []const u8,
        /// The decrypted payload, borrowed from the caller's buffer. The tag is
        /// not part of it.
        payload: []u8,
    };

    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
    //# The endpoint creates a new write secret from the existing write
    //# secret as performed in Section 7.2 of [TLS13]. This uses the KDF
    //# function provided by TLS with a label of "quic ku". The
    //# corresponding key and IV are created from that secret as defined in
    //# Section 5.1. The header protection key is not updated.
    /// RFC 9001 section 6.1: the next generation of packet protection keys.
    ///
    /// Takes its key and IV from the next secret and **keeps the header
    /// protection key it already had**, because section 6.1 says so outright:
    /// "The header protection key is not updated."
    ///
    /// That is not a detail. The Key Phase bit lives under header protection,
    /// so a receiver has to unmask the header before it can know which
    /// generation to decrypt with — which is only possible if unmasking does
    /// not itself depend on knowing. Deriving a fresh header protection key
    /// here makes every packet after an update unreadable by the peer, and the
    /// failure surfaces as `ReservedBitsSet` rather than as anything mentioning
    /// keys, because the mask that came off was not the mask that went on.
    pub fn nextGeneration(self: *const Keys, suite: Suite, next_secret: *const secrets.Secret) Keys {
        var keys: Keys = .fromSecret(suite, next_secret);
        keys.header_key_storage = self.header_key_storage;
        keys.header_key_octets = self.header_key_octets;
        assert(std.mem.eql(u8, keys.headerKey(), self.headerKey()));
        return keys;
    }

    /// A header with its protection removed, and what it says.
    ///
    /// Separated from decryption because RFC 9001 section 6.1 keeps the header
    /// protection key across a key update — "The header protection key is not
    /// updated" — which is exactly what makes the Key Phase bit legible
    /// *before* choosing which generation of AEAD keys to decrypt with.
    /// Composing the two, as `open` does, is right everywhere the phase cannot
    /// change; at 1-RTT it is not.
    pub const Unprotected = struct {
        number: u64,
        number_octets: u8,
        header_octets: usize,
        /// Section 17.3.1's Key Phase bit. Meaningless outside 1-RTT, where the
        /// octet holds a long header's packet type instead.
        key_phase: bool,
    };

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
    //# When processing packets, an endpoint first removes the header
    //# protection.
    //
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
    //# Removing header protection only differs in the order in which the
    //# packet number length (pn_length) is determined
    /// Section 5.4: remove header protection, and nothing else.
    pub fn unprotectHeader(
        self: *const Keys,
        packet: []u8,
        packet_number_offset: usize,
        largest: ?u64,
    ) OpenError!Unprotected {
        if (packet.len < packet_number_offset + sample_offset + sample_octets) return error.Truncated;
        assert(packet_number_offset < packet.len);

        const mask = self.headerMask(packet[packet_number_offset + sample_offset ..][0..sample_octets]);
        const long = packet[0] & header_form_long != 0;
        packet[0] ^= mask[0] & (if (long) first_octet_mask_long else first_octet_mask_short);
        const number_octets: u8 = (packet[0] & packet_number_length_mask) + 1;
        assert(number_octets >= packet_number.octets_min);
        assert(number_octets <= packet_number.octets_max);

        for (packet[packet_number_offset..][0..number_octets], 0..) |*octet, index| {
            octet.* ^= mask[1 + index];
        }

        //= https://www.rfc-editor.org/rfc/rfc9001#section-9.5
        //# For authentication to be free from side channels, the entire
        //# process of header protection removal, packet number recovery,
        //# and packet protection removal MUST be applied together without
        //# timing and other side channels.
        //= type=todo
        // "Applied together" is exactly what the next line does not do: a
        // reserved bit that survives unmasking returns before the AEAD runs,
        // so the time an injected packet takes to be refused says whether the
        // mask's two reserved bits came off zero. The bits are worth two of an
        // attacker's guesses per packet, and the fix is to carry the verdict
        // to after `decrypt` rather than to return here — which is a change to
        // behaviour, so this pass records it rather than making it.
        const reserved = if (long) reserved_mask_long else reserved_mask_short;
        if (packet[0] & reserved != 0) return error.ReservedBitsSet;

        const header_octets = packet_number_offset + number_octets;
        if (packet.len < header_octets + crypto.tag_octets) return error.Truncated;

        const truncated = packet_number.read(packet[packet_number_offset..][0..number_octets]);
        return .{
            .number = packet_number.decode(largest, truncated, number_octets),
            .number_octets = number_octets,
            .header_octets = header_octets,
            .key_phase = !long and (packet[0] & key_phase_bit) != 0,
        };
    }

    /// Decrypt a packet whose header protection has already been removed.
    ///
    /// Split from `unprotectHeader` so a 1-RTT packet can be decrypted with a
    /// *different* generation's keys than the ones that unmasked its header,
    /// which is the whole of what a key update is.
    pub fn decrypt(self: *const Keys, packet: []u8, header: Unprotected) OpenError!Opened {
        assert(header.header_octets <= packet.len);
        if (packet.len < header.header_octets + crypto.tag_octets) return error.Truncated;

        const ciphertext_octets = packet.len - header.header_octets - crypto.tag_octets;
        const ciphertext = packet[header.header_octets..][0..ciphertext_octets];
        const tag = packet[header.header_octets + ciphertext_octets ..][0..crypto.tag_octets];
        const packet_nonce = self.nonce(header.number);
        self.aeadOpen(ciphertext, ciphertext, tag.*, packet[0..header.header_octets], packet_nonce) catch {
            return error.AuthenticationFailed;
        };
        return .{
            .number = header.number,
            .number_octets = header.number_octets,
            .header = packet[0..header.header_octets],
            .payload = ciphertext,
        };
    }

    /// Unprotect a packet in place.
    ///
    /// `packet` is exactly one QUIC packet: for a long header the caller has
    /// already sliced it by its Length field, and for a short header it runs to
    /// the end of the datagram. `largest` is the largest packet number already
    /// processed in this packet's number space, or null if none has been.
    ///
    /// Mutates `packet` whatever the outcome; see the module comment.
    pub fn open(
        self: *const Keys,
        packet: []u8,
        packet_number_offset: usize,
        largest: ?u64,
    ) OpenError!Opened {
        // Both checks before anything is written: a packet that cannot carry a
        // sample is discarded without touching the buffer, which is what makes
        // a truncated datagram cheap to reject.
        if (packet.len < packet_number_offset + sample_offset + sample_octets) return error.Truncated;
        assert(packet_number_offset < packet.len);

        const mask = self.headerMask(packet[packet_number_offset + sample_offset ..][0..sample_octets]);

        // The first octet has to come off before the number's length is
        // legible, and the number's length decides how much of the mask to
        // spend — so this cannot be one pass.
        const long = packet[0] & header_form_long != 0;
        packet[0] ^= mask[0] & (if (long) first_octet_mask_long else first_octet_mask_short);
        const number_octets: u8 = (packet[0] & packet_number_length_mask) + 1;
        assert(number_octets >= packet_number.octets_min);
        assert(number_octets <= packet_number.octets_max);

        for (packet[packet_number_offset..][0..number_octets], 0..) |*octet, index| {
            octet.* ^= mask[1 + index];
        }

        const reserved = if (long) reserved_mask_long else reserved_mask_short;
        if (packet[0] & reserved != 0) return error.ReservedBitsSet;

        const header_octets = packet_number_offset + number_octets;
        assert(header_octets <= packet.len);
        if (packet.len < header_octets + crypto.tag_octets) return error.Truncated;

        const truncated = packet_number.read(packet[packet_number_offset..][0..number_octets]);
        const number = packet_number.decode(largest, truncated, number_octets);
        assert(number <= packet_number.max);

        const ciphertext_octets = packet.len - header_octets - crypto.tag_octets;
        const ciphertext = packet[header_octets..][0..ciphertext_octets];
        const tag = packet[header_octets + ciphertext_octets ..][0..crypto.tag_octets];
        const packet_nonce = self.nonce(number);
        self.aeadOpen(ciphertext, ciphertext, tag.*, packet[0..header_octets], packet_nonce) catch {
            return error.AuthenticationFailed;
        };

        return .{
            .number = number,
            .number_octets = number_octets,
            .header = packet[0..header_octets],
            .payload = ciphertext,
        };
    }

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
    //# The key and IV for the packet are computed as described in Section
    //# 5.1. The nonce, N, is formed by combining the packet protection IV
    //# with the packet number. The 62 bits of the reconstructed QUIC packet
    //# number in network byte order are left- padded with zeros to the size
    //# of the IV. The exclusive OR of the padded packet number and the IV
    //# forms the AEAD nonce.
    /// RFC 9001 section 5.3: the nonce is the write IV with the packet number
    /// XORed into its low octets, left-padded with zeroes.
    ///
    /// The whole security of the AEAD rests on this being unique per key, which
    /// is why the packet number is the *full* 62-bit value and never the
    /// truncation that went on the wire.
    fn nonce(self: *const Keys, number: u64) [crypto.iv_octets]u8 {
        assert(number <= packet_number.max);
        var result = self.iv;
        var padded: [8]u8 = undefined;
        std.mem.writeInt(u64, &padded, number, .big);
        for (padded, 0..) |octet, index| {
            result[crypto.iv_octets - padded.len + index] ^= octet;
        }
        assert(result.len == crypto.iv_octets);
        return result;
    }

    //= https://www.rfc-editor.org/rfc/rfc9001#section-9.4
    //# Future header protection variants based on this construction MUST
    //# use a PRF to ensure equivalent security guarantees.
    //= type=exception
    //= reason=this package defines no header protection variant. It implements the two RFC 9001 specifies -- section 5.4.3's AES-ECB and section 5.4.4's ChaCha20 -- and `Suite` admits no cipher suite that would need a third.
    /// RFC 9001 sections 5.4.3 and 5.4.4: the five mask octets, from a sample.
    fn headerMask(self: *const Keys, sample: *const [sample_octets]u8) [crypto.header_mask_octets]u8 {
        var mask: [crypto.header_mask_octets]u8 = undefined;
        switch (self.suite.headerProtection()) {
            .aes => {
                //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3
                //# AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES in
                //# Electronic Codebook (ECB) mode. AEAD_AES_256_GCM uses
                //# 256-bit AES in ECB mode.
                // Section 5.4.3: one raw AES block, the sample as plaintext,
                // the header protection key as the key. Not a mode — ECB over
                // exactly one block — which is the one context where that is
                // not a mistake.
                var block: [16]u8 = undefined;
                switch (self.header_key_octets) {
                    16 => std.crypto.core.aes.Aes128.initEnc(self.header_key_storage[0..16].*).encrypt(&block, sample),
                    32 => std.crypto.core.aes.Aes256.initEnc(self.header_key_storage[0..32].*).encrypt(&block, sample),
                    // The two AES suites are the only ones reaching this arm,
                    // and `Suite.headerKeyOctets` answers 16 or 32 for both.
                    // Not guarded by an assertion alone: with `-Dassertions=false`
                    // this would be undefined behaviour rather than a panic, so
                    // the exhaustive `switch` above is the guard and this arm is
                    // unreachable by construction of `Suite`.
                    else => unreachable,
                }
                @memcpy(&mask, block[0..crypto.header_mask_octets]);
            },
            .chacha20 => {
                //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.4
                //# When AEAD_CHACHA20_POLY1305 is in use, header protection
                //# uses the raw ChaCha20 function as defined in Section 2.4
                //# of [CHACHA]. This uses a 256-bit key and 16 bytes
                //# sampled from the packet protection output.
                //
                //= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.4
                //# The encryption mask is produced by invoking ChaCha20 to
                //# protect 5 zero bytes.
                // Section 5.4.4: the first four octets of the sample are a
                // little-endian block counter, the remaining twelve the nonce,
                // and the mask is the keystream over five zero octets.
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const chacha_nonce: [12]u8 = sample[4..16].*;
                const zeroes: [crypto.header_mask_octets]u8 = @splat(0);
                std.crypto.stream.chacha.ChaCha20IETF.xor(
                    &mask,
                    &zeroes,
                    counter,
                    self.header_key_storage[0..32].*,
                    chacha_nonce,
                );
            },
        }
        return mask;
    }

    fn aeadSeal(
        self: *const Keys,
        ciphertext: []u8,
        tag: *[crypto.tag_octets]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        packet_nonce: [crypto.iv_octets]u8,
    ) void {
        assert(ciphertext.len == plaintext.len);
        switch (self.suite) {
            .aes_128_gcm_sha256 => std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                packet_nonce,
                self.key_storage[0..16].*,
            ),
            .aes_256_gcm_sha384 => std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                packet_nonce,
                self.key_storage[0..32].*,
            ),
            .chacha20_poly1305_sha256 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                packet_nonce,
                self.key_storage[0..32].*,
            ),
        }
    }

    fn aeadOpen(
        self: *const Keys,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [crypto.tag_octets]u8,
        associated_data: []const u8,
        packet_nonce: [crypto.iv_octets]u8,
    ) std.crypto.errors.AuthenticationError!void {
        assert(plaintext.len == ciphertext.len);
        switch (self.suite) {
            .aes_128_gcm_sha256 => try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                packet_nonce,
                self.key_storage[0..16].*,
            ),
            .aes_256_gcm_sha384 => try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                packet_nonce,
                self.key_storage[0..32].*,
            ),
            .chacha20_poly1305_sha256 => try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                packet_nonce,
                self.key_storage[0..32].*,
            ),
        }
    }
};

//= https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
//# The output of this algorithm is a 5-byte mask that is applied to the
//# protected header fields using exclusive OR. The least significant bits
//# of the first byte of the packet are masked by the least significant bits
//# of the first mask byte, and the packet number is masked with the
//# remaining bytes. Any unused bytes of mask that might result from a
//# shorter packet number encoding are unused.
/// XOR the mask into the first octet and the packet number. Shared by `seal`
/// and `open` so that the two cannot disagree about which bits are protected —
/// which they would, silently, in one direction only.
fn applyHeaderMask(
    buffer: []u8,
    packet_number_offset: usize,
    number_octets: usize,
    mask: [crypto.header_mask_octets]u8,
) void {
    assert(number_octets >= packet_number.octets_min);
    assert(number_octets <= packet_number.octets_max);
    assert(packet_number_offset + number_octets <= buffer.len);

    const long = buffer[0] & header_form_long != 0;
    buffer[0] ^= mask[0] & (if (long) first_octet_mask_long else first_octet_mask_short);
    for (buffer[packet_number_offset..][0..number_octets], 0..) |*octet, index| {
        octet.* ^= mask[1 + index];
    }
}

test "RFC 9001 appendix A.1: the client's Initial packet protection keys" {
    // Known-answer, transcribed from the appendix. If these three match, the
    // key schedule, the labels and the lengths are all right at once.
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);

    try std.testing.expectEqualSlices(u8, &.{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    }, keys.key());
    try std.testing.expectEqualSlices(u8, &.{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    }, &keys.iv);
    try std.testing.expectEqualSlices(u8, &.{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    }, keys.headerKey());
}

test "RFC 9001 appendix A.1: the server's Initial packet protection keys" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .server);

    try std.testing.expectEqualSlices(u8, &.{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    }, keys.key());
    try std.testing.expectEqualSlices(u8, &.{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
    }, &keys.iv);
    try std.testing.expectEqualSlices(u8, &.{
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    }, keys.headerKey());
}

test "the nonce is the IV with the packet number XORed into its tail" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);
    // Packet number 2 flips exactly one bit of the IV's last octet.
    const with_two = keys.nonce(2);
    try std.testing.expectEqual(keys.iv[crypto.iv_octets - 1] ^ 2, with_two[crypto.iv_octets - 1]);
    for (0..crypto.iv_octets - 1) |index| {
        try std.testing.expectEqual(keys.iv[index], with_two[index]);
    }
    // And packet number 0 is the IV unchanged.
    try std.testing.expectEqualSlices(u8, &keys.iv, &keys.nonce(0));
}

/// Build a minimal long-header packet in `buffer` and return the pieces `seal`
/// needs. Deliberately hand-rolled rather than reaching for `packet.zig`: this
/// module's tests should fail when *this* module breaks.
fn sampleLongHeader(buffer: []u8, payload: []const u8, number: u64) struct {
    packet_number_offset: usize,
    header_octets: usize,
    payload_octets: usize,
    number: u64,
} {
    // 0xc3: long header, fixed bit, Initial, four-octet packet number.
    buffer[0] = 0xc3;
    std.mem.writeInt(u32, buffer[1..5], 0x0000_0001, .big); // Version 1.
    buffer[5] = 0; // Destination Connection ID length.
    buffer[6] = 0; // Source Connection ID length.
    buffer[7] = 0; // Token length, a one-octet varint.
    const packet_number_offset: usize = 8;
    std.mem.writeInt(u32, buffer[packet_number_offset..][0..4], @intCast(number), .big);
    const header_octets = packet_number_offset + 4;
    @memcpy(buffer[header_octets..][0..payload.len], payload);
    return .{
        .packet_number_offset = packet_number_offset,
        .header_octets = header_octets,
        .payload_octets = payload.len,
        .number = number,
    };
}

test "a sealed packet opens back to what went in" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);

    const plaintext = "CRYPTO frames would live here, and then some padding.";
    var buffer: [256]u8 = @splat(0);
    const shape = sampleLongHeader(&buffer, plaintext, 42);

    const total = try keys.seal(&buffer, shape.packet_number_offset, shape.header_octets, shape.payload_octets, shape.number);
    try std.testing.expectEqual(shape.header_octets + plaintext.len + crypto.tag_octets, total);
    // Protection actually happened: the packet number is no longer legible.
    try std.testing.expect(!std.mem.eql(u8, buffer[shape.packet_number_offset..][0..4], &.{ 0, 0, 0, 42 }));

    const opened = try keys.open(buffer[0..total], shape.packet_number_offset, 41);
    try std.testing.expectEqual(@as(u64, 42), opened.number);
    try std.testing.expectEqual(@as(u8, 4), opened.number_octets);
    try std.testing.expectEqualStrings(plaintext, opened.payload);
}

test "every suite round-trips, including the ChaCha20 header mask" {
    // The three suites take two different header protection paths and two
    // different hashes, and nothing else in the package exercises the wide one.
    for ([_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        const raw: [48]u8 = @splat(0x5a);
        const secret = try Secret.init(raw[0..suite.hashOctets()]);
        const keys: Keys = .fromSecret(suite, &secret);

        var buffer: [256]u8 = @splat(0);
        const shape = sampleLongHeader(&buffer, "payload", 7);
        const total = try keys.seal(&buffer, shape.packet_number_offset, shape.header_octets, shape.payload_octets, shape.number);
        const opened = try keys.open(buffer[0..total], shape.packet_number_offset, 6);
        try std.testing.expectEqual(@as(u64, 7), opened.number);
        try std.testing.expectEqualStrings("payload", opened.payload);
    }
}

test "a flipped octet anywhere fails authentication rather than decoding" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);

    // Every position in the packet, including the header the AEAD only
    // authenticates: the point of the associated data is that tampering there
    // is caught too.
    var position: usize = 0;
    const original_payload = "payload that is long enough to sample";
    while (position < 60) : (position += 1) {
        var buffer: [256]u8 = @splat(0);
        const shape = sampleLongHeader(&buffer, original_payload, 3);
        const total = try keys.seal(&buffer, shape.packet_number_offset, shape.header_octets, shape.payload_octets, shape.number);
        if (position >= total) break;
        buffer[position] ^= 0x01;
        const result = keys.open(buffer[0..total], shape.packet_number_offset, 2);
        // A flip in the header form bit or the reserved bits can be rejected
        // earlier, by a rule rather than by the tag. What must never happen is
        // a successful open.
        try std.testing.expect(std.meta.isError(result));
    }
}

test "a packet too short to sample is refused in both directions" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);

    var buffer: [64]u8 = @splat(0);
    // A header ending at offset 12 needs 8 + 4 + 16 = 28 octets before a sample
    // exists; an empty payload gives 12 + 16 = 28, which is exactly enough, so
    // shorten the packet number instead.
    buffer[0] = 0xc0;
    const short_packet = buffer[0..20];
    try std.testing.expectError(error.Truncated, keys.open(short_packet, 8, null));
}

test "reserved bits set are a protocol violation, not a discard" {
    const dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys: Keys = .initial(&dcid, .client);

    var buffer: [256]u8 = @splat(0);
    const shape = sampleLongHeader(&buffer, "payload that is long enough", 3);
    // Set a reserved bit before sealing, so that it is authenticated: a bit an
    // attacker flipped would fail the tag instead, which is a different answer
    // to a different question.
    buffer[0] |= reserved_mask_long;
    const total = try keys.seal(&buffer, shape.packet_number_offset, shape.header_octets, shape.payload_octets, shape.number);
    try std.testing.expectError(error.ReservedBitsSet, keys.open(buffer[0..total], shape.packet_number_offset, 2));
}
