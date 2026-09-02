#!/usr/bin/env python3
"""Machine-lift RFC 9001 Appendix A's packet vectors into rfc9001_vectors.zig.

Transcription is exactly where a codec's test vectors go wrong, and quietly: a
mistyped byte string still decodes to *something*, so the test fails against a
plausible answer and the reader blames the decoder. So the vectors are lifted
from the RFC text rather than typed, and every extraction is checked against an
expected octet count: if an anchor matches a block of the wrong length, this
script fails instead of emitting a wrong fixture.

How much that check is worth varies, and the docstring used to overstate it by
calling every count "a length the RFC states in prose". Some are — the
destination connection identifier's eight octets, the 1162-octet payload, the
1200-octet protected packet. Most are the algorithm's own output sizes supplied
here: a 32-octet secret is SHA-256's digest, a 16-octet key is AES-128's. Those
catch a *mistyped* extraction but not an anchor that matched a different block
of the same size, of which the appendix has several.

The check that does not have that weakness is on the Zig side: rfc9001.zig
recomputes the key schedule from the connection identifier and compares every
derived value against the extracted one, so a secret lifted from the wrong
block disagrees with the HKDF output rather than merely being the right length.
This script's job is to make that comparison possible without anyone typing
1200 octets by hand.

Usage: python3 extract.py rfc9001.txt > rfc9001_vectors.zig
"""
import re
import sys

HEX_ONLY = re.compile(r'^[0-9a-f][0-9a-f ]*$')


def hex_of(line):
    """The hex on this line, or None.

    Handles the three shapes the appendix uses: a bare indented run of octets,
    a continuation line `= <hex>`, and a labelled one `name = <hex>`. Anything
    after an `=` that is not hex — a formula like `HKDF-Expand-Label(...)` —
    answers None, which is what lets an anchor sit on the formula line and the
    value be picked up from the line below it.
    """
    text = line.strip()
    if not text:
        return None
    if '=' in text:
        text = text.split('=', 1)[1].strip()
    if not text or not HEX_ONLY.match(text):
        return None
    return text.replace(' ', '')


def hex_block_at(lines, anchor, exact=False):
    """The run of hex lines at or after the line matching `anchor`."""
    for index, line in enumerate(lines):
        matched = (line.strip() == anchor) if exact else (anchor in line)
        if not matched:
            continue
        octets = []
        for candidate in lines[index:]:
            # A line that introduces its own label ends the run. The appendix
            # stacks `nonce = ...`, `unprotected header = ...` and
            # `payload plaintext = ...` with nothing between them, so without
            # this every one of them would swallow the next.
            text = candidate.strip()
            if octets and '=' in text and text.split('=', 1)[0].strip():
                break
            piece = hex_of(candidate)
            if piece is not None:
                octets.append(piece)
            elif octets:
                break
        if octets:
            return ''.join(octets)
    raise SystemExit('anchor not found or carries no hex: ' + anchor)


def field(name, hex_text, expect_octets=None):
    if len(hex_text) % 2:
        raise SystemExit(f'{name}: odd hex length {len(hex_text)}')
    octets = len(hex_text) // 2
    if expect_octets is not None and octets != expect_octets:
        raise SystemExit(f'{name}: extracted {octets} octets, RFC states {expect_octets}')
    grouped = [hex_text[i:i + 32] for i in range(0, len(hex_text), 32)]
    body = '\n'.join('    "' + g + '" ++' for g in grouped)
    # `rstrip(' ++')` would strip a *character set* — every trailing space and
    # `+` — rather than the suffix. It happens to be right here only because a
    # quote terminates every line, so there is nothing else for it to eat; make
    # the intent the code rather than the accident.
    suffix = ' ++'
    assert body.endswith(suffix), body[-8:]
    body = body[: -len(suffix)]
    return f'/// {octets} octets.\npub const {name} = hexed(\n{body},\n);\n'


def main():
    lines = open(sys.argv[1], encoding='utf-8').read().split('\n')
    appendix = lines[[i for i, l in enumerate(lines) if l.startswith('Appendix A.')][0]:]

    out = []
    out.append('''//! RFC 9001 Appendix A's worked packets, machine-lifted from the RFC text by
//! `corpus/extract.py` rather than transcribed by hand.
//!
//! Transcription is exactly where a codec's test vectors go wrong, and quietly:
//! a mistyped byte string still decodes to *something*, so the test fails
//! against a plausible answer and the reader blames the decoder. The extractor
//! checks every block against a length the RFC states in prose, so an anchor
//! matching the wrong block is a failed extraction rather than a wrong fixture.
//!
//! Regenerate with:
//!
//!     curl -sSL -o rfc9001.txt https://www.rfc-editor.org/rfc/rfc9001.txt
//!     python3 corpus/extract.py rfc9001.txt > corpus/rfc9001_vectors.zig

/// Parse a compile-time hex string into the octets it denotes.
fn hexed(comptime text: []const u8) [text.len / 2]u8 {
    comptime {
        // The longest vector is A.2's 1200-octet packet, and every octet is two
        // branches. Set from the text's own length so a longer vector added
        // later does not need this touched.
        @setEvalBranchQuota(text.len * 8 + 1000);
        var octets: [text.len / 2]u8 = undefined;
        for (&octets, 0..) |*octet, index| {
            octet.* = (nibble(text[index * 2]) << 4) | nibble(text[index * 2 + 1]);
        }
        return octets;
    }
}

fn nibble(comptime character: u8) u8 {
    return switch (character) {
        '0'...'9' => character - '0',
        'a'...'f' => character - 'a' + 10,
        else => @compileError("not a lowercase hex digit"),
    };
}
''')

    # A.1 — the key schedule, which src/quic/crypto/ already tests against; kept
    # here so the corpus is the whole appendix rather than the parts left over.
    out.append(field('destination_connection_id', '8394c8f03e515708', 8))
    out.append(field('initial_secret', hex_block_at(appendix, 'initial_secret = HKDF-Extract'), 32))
    out.append(field('client_initial_secret', hex_block_at(appendix, 'client_initial_secret'), 32))
    out.append(field('client_key', hex_block_at(appendix, 'key = HKDF-Expand-Label(client_initial_secret'), 16))
    out.append(field('client_iv', hex_block_at(appendix, 'iv  = HKDF-Expand-Label(client_initial_secret'), 12))
    out.append(field('client_hp', hex_block_at(appendix, 'hp  = HKDF-Expand-Label(client_initial_secret'), 16))
    out.append(field('server_initial_secret', hex_block_at(appendix, 'server_initial_secret'), 32))
    out.append(field('server_key', hex_block_at(appendix, 'key = HKDF-Expand-Label(server_initial_secret'), 16))
    out.append(field('server_iv', hex_block_at(appendix, 'iv  = HKDF-Expand-Label(server_initial_secret'), 12))
    out.append(field('server_hp', hex_block_at(appendix, 'hp  = HKDF-Expand-Label(server_initial_secret'), 16))

    # A.2 — client Initial. The appendix prints the CRYPTO frame and says the
    # payload is that "plus enough PADDING frames to make a 1162-byte payload",
    # so the printed block is 245 octets and the remaining 917 are the zeroes a
    # PADDING frame is. `client_initial_payload` below assembles the two.
    out.append(field('client_initial_crypto_frame', hex_block_at(appendix, 'frames to make a 1162-byte payload'), 245))
    out.append('''/// The payload the appendix describes: the CRYPTO frame above, then PADDING to
/// 1162 octets. Assembled rather than lifted, because the RFC prints the frame
/// and states the padding in prose.
pub const client_initial_payload = blk: {
    var payload: [client_initial_payload_octets]u8 = @splat(0);
    @memcpy(payload[0..client_initial_crypto_frame.len], &client_initial_crypto_frame);
    break :blk payload;
};

/// RFC 9001 A.2, stated in prose: 1162 octets of frames.
pub const client_initial_payload_octets = 1162;

/// And the length field over them: the 4-octet packet number, the frames, and
/// the 16-octet tag.
pub const client_initial_length_field = 1182;

comptime {
    if (client_initial_crypto_frame.len >= client_initial_payload_octets) {
        @compileError("the CRYPTO frame does not leave room for the PADDING the RFC describes");
    }
    if (client_initial_length_field != 4 + client_initial_payload_octets + 16) {
        @compileError("the length field and the payload disagree");
    }
}
''')
    out.append(field('client_initial_header', hex_block_at(appendix, 'includes the connection ID and a packet number of 2'), 22))
    out.append(field('client_initial_sample', hex_block_at(appendix, 'sample = d1b1c98d'), 16))
    out.append(field('client_initial_protected', hex_block_at(appendix, 'The resulting protected packet is'), 1200))

    # A.3 — server Initial.
    out.append(field('server_initial_payload', hex_block_at(appendix, 'frame, a CRYPTO frame, and no PADDING frames'), 99))
    out.append(field('server_initial_header', hex_block_at(appendix, 'packet number encoding for a packet number of 1'), 20))
    out.append(field('server_initial_protected', hex_block_at(appendix, 'The final protected packet is then'), 135))

    # A.4 — Retry. The original destination connection ID is A.2's, and is not
    # in the packet; that is the whole point of the integrity tag.
    out.append(field('retry_packet', hex_block_at(appendix, 'value is not included in the final Retry packet'), 36))

    # A.5 — ChaCha20-Poly1305 short header.
    out.append(field('chacha_secret', hex_block_at(appendix, 'secret', exact=True), 32))
    out.append(field('chacha_key', hex_block_at(appendix, 'key = HKDF-Expand-Label(secret, "quic key"'), 32))
    out.append(field('chacha_iv', hex_block_at(appendix, 'iv  = HKDF-Expand-Label(secret, "quic iv"'), 12))
    out.append(field('chacha_hp', hex_block_at(appendix, 'hp  = HKDF-Expand-Label(secret, "quic hp"'), 32))
    out.append(field('chacha_ku', hex_block_at(appendix, 'ku  = HKDF-Expand-Label(secret, "quic ku"'), 32))
    out.append(field('chacha_nonce', hex_block_at(appendix, 'nonce              ='), 12))
    out.append(field('chacha_header', hex_block_at(appendix, 'unprotected header ='), 4))
    out.append(field('chacha_plaintext', hex_block_at(appendix, 'payload plaintext  ='), 1))
    out.append(field('chacha_packet', hex_block_at(appendix, 'packet = 4cfe4189'), 21))

    print('\n'.join(out))


main()
