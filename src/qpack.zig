//! RFC 9204: QPACK field compression.
//!
//! HPACK's problem, restated for a protocol with no ordering guarantee between
//! streams. HPACK's dynamic table works because every field block arrives in
//! the order it was encoded; over QUIC the streams are independent, so a field
//! section that referenced a table entry might arrive before the instruction
//! that inserted it. QPACK's answer is to split the state onto two dedicated
//! unidirectional streams and to have each field section declare, in its
//! prefix, how much of the table it depends on — the Required Insert Count.
//!
//! ## Two of these pieces are not QPACK's
//!
//! Section 4.1.1 adopts RFC 7541 section 5.1's prefixed integer and section
//! 4.1.2 adopts section 5.2's Huffman code, both unchanged and the Huffman with
//! the same 257-symbol table. They come from
//! [zoxy-io/hpack](https://github.com/zoxy-io/hpack), which holds RFC 7541, and
//! are re-exported here so that a caller working in QPACK never has to know
//! which RFC a given piece came from.
//!
//! The one thing that differs between the two protocols is how wide an integer
//! can be, and it is a parameter rather than a fork: HPACK's values are bounded
//! by HTTP/2 SETTINGS, which are `u32`, while QPACK's are bounded by a QUIC
//! stream offset, which is 62 bits. Hence `Integer(u62)` below.
//!
//! ## What is here, and what is next
//!
//! The static table, and the two borrowed primitives. A decoder that advertises
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` — which is what zrk does for HPACK
//! today, and for the same reason — never blocks and never keeps per-connection
//! compression state, so those plus the literal representations are the whole
//! of what it needs.
//!
//! The field line representations, the dynamic table and the encoder and
//! decoder streams are the next slices; see docs/DESIGN.md section 6.

const std = @import("std");

const hpack = @import("hpack");

/// RFC 9204 section 4.1.1's prefixed integer, at QPACK's width.
///
/// `u62` because every QPACK index and length is ultimately bounded by a QUIC
/// stream offset (RFC 9000 section 16). Naming the width here is what makes the
/// bound visible at every call site instead of buried in a constant.
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.1.1
//# QPACK implementations MUST be able to decode integers up to and
//# including 62 bits long.
pub const integer = hpack.integer.Integer(u62);

/// RFC 9204 section 4.1.2's Huffman code, which is RFC 7541 section 5.2's
/// unchanged. `huffman.decode` is the one to call; `huffman.decodeReference` is
/// the second kernel it is proved against.
pub const huffman = hpack.huffman;

/// RFC 9204 appendix A: the ninety-nine entry table, indexed from zero.
pub const static_table = @import("qpack/static_table.zig");

/// RFC 9204 section 4.5: encoded field sections, both directions.
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
//# An endpoint MUST allow its peer to create an encoder stream and a
//# decoder stream even if the connection's settings prevent their use.
//= type=exception
//= reason=creating and accepting unidirectional streams is the HTTP/3 connection layer's, which docs/DESIGN.md section 6 lists as next rather than built; stream.zig names both QPACK types so it can
pub const field_line = @import("qpack/field_line.zig");

/// A decoded field. RFC 9204 keeps RFC 7541's notion of one, so this is
/// hpack's rather than a second type with the same shape.
pub const Field = field_line.Field;

test {
    _ = static_table;
    _ = field_line;
}
