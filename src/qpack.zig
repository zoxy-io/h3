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
//! What is here today is the part that does not need that machinery: the
//! prefixed integer both HPACK and QPACK use, and the static table. A decoder
//! that advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` — which is what zrk
//! does for HPACK today, and for the same reason — never blocks and never keeps
//! per-connection compression state, so the static table and the literal
//! representations are the whole of what it needs.
//!
//! The dynamic table, the encoder and decoder streams, and Huffman are the next
//! slice. docs/DESIGN.md records why Huffman is a port rather than a rewrite:
//! it is RFC 7541's table unchanged, and zoxy-io/h2 already has a fuzzed,
//! vectorised implementation of it.

const std = @import("std");

pub const integer = @import("qpack/integer.zig");
pub const static_table = @import("qpack/static_table.zig");

test {
    _ = integer;
    _ = static_table;
}
