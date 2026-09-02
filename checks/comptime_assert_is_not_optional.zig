//! A fixture that must FAIL to compile, whichever way `-Dassertions` was set.
//!
//! The claim: a `comptime` assertion is a proof the package rests on, and the
//! build option does not reach it. That cannot be stated in a `test` block,
//! because the failing case is a compile error rather than a failing test — and
//! the obvious attempt, `comptime assert(true)`, passes even if the
//! `@inComptime()` branch in `src/assert.zig` were deleted outright. A
//! tautology wearing a proof's name.
//!
//! So the fixture asserts something false at comptime and `zig build checks`
//! requires the build to reject it with "reached unreachable code". If someone
//! makes comptime assertions follow the option, this file starts compiling and
//! the build fails on its silence.

const h3 = @import("h3");

comptime {
    h3.assertions.assert(1 == 2);
}
