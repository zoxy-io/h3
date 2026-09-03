//! Root of the corpus test binary: evidence from outside this package.
//!
//! Its own binary because it embeds fixtures no consumer needs, and a corpus
//! that ships to consumers is test data in everyone's dependency tree.
//!
//! Two kinds of outside evidence, and the distinction matters. RFC 9001
//! appendix A is the specification's own worked answer, which catches a
//! derivation that is self-consistent and wrong. `qifs.zig` is four other
//! implementations' output, which catches a *reading* that is self-consistent
//! and wrong — the failure no test written against this package can see,
//! because every one of them shares the author's reading.

test {
    _ = @import("rfc9001.zig");
    _ = @import("qifs.zig");
}
