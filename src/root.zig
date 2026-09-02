//! h3 — QUIC (RFC 9000, RFC 9001, RFC 9002), QPACK (RFC 9204) and HTTP/3
//! (RFC 9114) in Zig.
//!
//! Datagrams in, events out. Nothing here opens a socket, reads a clock, or
//! runs a TLS handshake: the two consumers do not share a runtime and do not
//! share a TLS engine, so anything that needs one belongs to them. See
//! README.md for the scope, docs/DESIGN.md for where the seam is and why, and
//! docs/TIGER_STYLE.md for the rules `zig build lint` enforces.

const std = @import("std");

/// `assert` and the `-Dassertions` build option. Named for the option rather
/// than for the function, so the flag reads `h3.assertions.enabled` and the
/// function does not stutter as `h3.assert.assert`.
pub const assertions = @import("assert.zig");

/// RFC 9000 section 16's variable-length integer. The primitive every layer
/// above is built out of, so it sits at the root rather than inside `quic`:
/// HTTP/3 frame headers and settings are varints too.
pub const varint = @import("varint.zig");

/// The transport: RFC 9000, RFC 9001 and RFC 9002.
pub const quic = @import("quic.zig");

/// RFC 9204: QPACK field compression.
pub const qpack = @import("qpack.zig");

/// RFC 9114 section 7: the HTTP/3 frame layer, on top of QUIC streams.
pub const frame = @import("frame.zig");

/// RFC 9114 section 6.2: what the first octets of a unidirectional stream mean.
pub const stream = @import("stream.zig");

test {
    _ = assertions;
    _ = varint;
    _ = quic;
    _ = qpack;
    _ = frame;
    _ = stream;
}
