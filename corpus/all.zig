//! Root of the corpus test binary: RFC 9001 Appendix A's worked packets.
//!
//! Its own binary because it embeds fixtures no consumer needs, and a corpus
//! that ships to consumers is test data in everyone's dependency tree.

test {
    _ = @import("rfc9001.zig");
}
