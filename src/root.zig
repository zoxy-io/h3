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

/// RFC 9114 sections 4.2 and 4.3: what makes a field section a message.
pub const fields = @import("fields.zig");

/// RFC 9114 section 7: the HTTP/3 frame layer, on top of QUIC streams.
pub const frame = @import("frame.zig");

/// RFC 9114 section 6.2: what the first octets of a unidirectional stream mean.
pub const stream = @import("stream.zig");

/// RFC 9114's connection layer: the control stream, the SETTINGS exchange,
/// GOAWAY, and section 4.1's frame sequence on a request stream. `frame.zig`
/// and `stream.zig` say what a thing is; this says whether it may be here.
pub const http3 = @import("Http3.zig");

/// qlog records, for a consumer that wants a trace a tool can read. Sans-I/O
/// like everything else here: it writes octets into a buffer and never opens a
/// file. See the module comment for what a trace from this seam can and cannot
/// contain.
pub const qlog = @import("qlog.zig");
pub const Http3 = http3.Http3;

test {
    _ = assertions;
    _ = varint;
    _ = quic;
    _ = qpack;
    _ = fields;
    _ = frame;
    _ = stream;
    _ = http3;
    _ = qlog;
}
