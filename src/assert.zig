//! `assert`, and the build option that decides whether it ships.
//!
//! ## Why this is not `std.debug.assert`
//!
//! `std.debug.assert` is `if (!ok) unreachable`, and in `ReleaseFast` and
//! `ReleaseSmall` `unreachable` is undefined behaviour rather than a trap. The
//! optimizer is therefore entitled to assume the condition holds and delete the
//! check — so a consumer building for speed gets a stack whose safety argument
//! rests on checks that are not in the binary.
//!
//! Inherited from zoxy-io/h2, and the argument survives the move intact. What
//! changes is how much rests on it: h2 is a codec, and its worst failure is a
//! wrong header. This package owns packet protection, so an invariant it stops
//! checking is a nonce it might reuse.
//!
//! ## The rule this makes load-bearing
//!
//! An assertion may not be the only guard on a `catch unreachable`. Once
//! assertions are optional, an `unreachable` behind one is reachable — and in
//! ReleaseFast that is undefined behaviour rather than a panic. h2 violated the
//! rule exactly once, in `Encoder.encodeSizeUpdate`, where the guard on a
//! peer-supplied capacity was an assertion and the fallout was a spin that
//! could not be interrupted. If an `unreachable` is reachable when the
//! assertions are gone, the guard is a returned error and the assertion beside
//! it is documentation.
//!
//! ## The option, and why it is an option
//!
//! docs/TIGER_STYLE.md records the one place the two consumers genuinely
//! disagree. zoxy wants assertions on in production: it is the security
//! boundary and it points this stack at the open internet. zrk is a
//! latency-measuring tool whose whole pitch is not injecting client-side noise
//! into the measurement.
//!
//! A library cannot decide that for its consumers, so `-Dassertions` decides
//! it, defaulting to on. zoxy inherits the default and states nothing; zrk opts
//! out in a line a reviewer can see:
//!
//!     const h3 = b.dependency("h3", .{
//!         .target = target,
//!         .optimize = optimize,
//!         .assertions = false,
//!     });
//!
//! ## Comptime is not part of the bargain
//!
//! An assertion evaluated during the build costs a consumer nothing at run
//! time, and several of this package's are proofs its correctness rests on —
//! `varint.zig` checks its four encodings against their prefixes over the whole
//! `u62` range boundary set, and `qpack/static_table.zig` checks its
//! transcription against RFC 9204's entry count. Turning those off with the
//! option would silently delete the proofs, so `assert` detects comptime and
//! ignores the option there. Nothing has to remember to use a different name.

const std = @import("std");
const build_options = @import("build_options");

/// Whether run-time assertions are compiled in. Public so a consumer can branch
/// on it — a test that measures assertion behaviour has to know — and so the
/// benchmark can print which build it measured.
pub const enabled: bool = build_options.assertions;

/// Check an invariant.
///
/// A failure is a bug in this package or a violated precondition in its caller,
/// never a malformed input: every wire-format error has a named error value and
/// a path that returns it. So this is the "downgrade correctness bugs into
/// liveness bugs" trade of docs/TIGER_STYLE.md — a crash a consumer can see and
/// report, in place of a wrong answer it cannot.
pub inline fn assert(ok: bool) void {
    // At comptime the option does not apply; see the note above. `unreachable`
    // here is a compile error rather than undefined behaviour, which is exactly
    // what a failed proof should be.
    if (@inComptime()) {
        if (!ok) unreachable;
        return;
    }
    if (!enabled) return;
    if (!ok) {
        @branchHint(.cold);
        fail();
    }
}

/// Out of line, so a holding assertion costs a not-taken branch and nothing
/// else — no panic path inlined into a decode loop, and no register pressure
/// from one.
fn fail() noreturn {
    @branchHint(.cold);
    @panic("h3: assertion failed");
}

test "assert admits what is true" {
    assert(true);
    assert(1 + 1 == 2);
}

test "the option is what the build said it was" {
    // Weak on purpose. The claim worth proving — that a *comptime* assertion is
    // checked whichever way `-Dassertions` was set — cannot be made in a `test`
    // block, because the failing case is a compile error rather than a failing
    // test. The real gate is `checks/comptime_assert_is_not_optional.zig`, a
    // fixture `zig build checks` requires to *fail* to compile.
    try std.testing.expectEqual(@import("build_options").assertions, enabled);
}
