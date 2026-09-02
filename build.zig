const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Assertions in release builds: the one place docs/TIGER_STYLE.md records
    // that the two consumers genuinely disagree, so it is a knob rather than a
    // decision this package makes for them. On by default — zoxy inherits it
    // and says nothing; zrk passes `.assertions = false` through `b.dependency`
    // in a line a reviewer can see.
    //
    // Not derived from `optimize`. `std.debug.assert` already derives from it,
    // and deriving is exactly the behaviour this replaces: a consumer choosing
    // ReleaseFast for throughput is not thereby choosing to ship a transport
    // with its invariant checks removed.
    const assertions = b.option(bool, "assertions", "Compile in run-time assertions (default true)") orelse true;
    const h3_options = b.addOptions();
    h3_options.addOption(bool, "assertions", assertions);
    // A marker, so this package's generated options file is distinct from
    // another's. Zig content-addresses the file `addOptions` produces, and a
    // file cannot be the root of two modules — so two packages whose options
    // hold nothing but `assertions: bool` with the same value collide with
    // "file exists in modules 'build_options' and 'build_options0'".
    //
    // hpack learned this against its consumers. The same trap sits one level
    // up: zrk depends on h2 *and* h3, and their options were byte-for-byte
    // identical. The marker is never read; its whole job is to differ.
    h3_options.addOption([]const u8, "package", "h3");

    // RFC 7541's Huffman code and prefixed integer, which RFC 9204 sections
    // 4.1.2 and 4.1.1 adopt unchanged. The assertions option is **forwarded**,
    // not defaulted: hpack sits two levels below a binary, so a consumer that
    // turned assertions off would otherwise still be running hpack's, with no
    // way to tell. This line is load-bearing.
    const hpack_dependency = b.dependency("hpack", .{
        .target = target,
        .optimize = optimize,
        .assertions = assertions,
    });
    const hpack_module = hpack_dependency.module("hpack");

    // The public module: consumers `@import("h3")` this.
    const h3_module = b.addModule("h3", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = h3_options.createModule() },
            .{ .name = "hpack", .module = hpack_module },
        },
    });

    const lib = b.addLibrary(.{
        .name = "h3",
        .root_module = h3_module,
    });
    b.installArtifact(lib);

    const module_tests = b.addRunArtifact(b.addTest(.{ .root_module = h3_module }));

    // The boundary lint of docs/TIGER_STYLE.md. Its own tests ride the `test`
    // step: a lint whose rules are untested is a lint that silently stops
    // having rules.
    const lint_exe = b.addExecutable(.{
        .name = "h3-lint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/lint.zig"),
            .target = b.graph.host,
        }),
    });
    const lint_tests = b.addRunArtifact(b.addTest(.{ .root_module = lint_exe.root_module }));

    const lint_run = b.addRunArtifact(lint_exe);
    lint_run.addDirectoryArg(b.path("src"));
    const lint_step = b.step("lint", "Boundary lint: no I/O types, no allocator, no unbounded loops");
    lint_step.dependOn(&lint_run.step);

    // The fuzz gate. `zig build fuzz` replays the corpus as regression; with
    // `--fuzz` it runs coverage-guided. See fuzz/fuzz.zig for why the harness
    // lives outside `src/`.
    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("fuzz/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "h3", .module = h3_module },
        },
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_module,
        // Patched copy of the default test runner; the stock one fails to
        // compile in fuzz mode (`-ffuzz`) on Zig 0.16.0. Vendored from
        // zoxy-io/h2, which vendored it from zoxy-io/hparse, and deletable
        // together with this override once upstream ships the fix.
        .test_runner = .{ .path = b.path("fuzz/test_runner.zig"), .mode = .server },
        // The self-hosted x86_64 backend emits no fuzz coverage
        // instrumentation: the build runner's coverage thread panics on an
        // empty PC table.
        .use_llvm = true,
    });
    const fuzz_run = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run the fuzz harness (pass --fuzz to actually fuzz)");
    fuzz_step.dependOn(&fuzz_run.step);

    // The performance gate. ReleaseFast is hardcoded rather than offered:
    // `standardOptimizeOption`'s `preferred_optimize_mode` still yields Debug
    // unless `-Drelease` is passed, and a benchmark built in Debug reports
    // numbers that mean nothing.
    const bench_runs = b.option(u64, "runs", "Repetitions per workload (default 5)") orelse 5;
    const bench_iterations = b.option(u64, "iterations", "Units of work per run (default 1_000_000)") orelse 1_000_000;
    const bench_options = b.addOptions();
    bench_options.addOption(u64, "runs", bench_runs);
    bench_options.addOption(u64, "iterations", bench_iterations);

    const bench_exe = b.addExecutable(.{
        .name = "h3-bench",
        // Zig 0.16's self-hosted x86_64 backend scalarizes `@Vector` code, and
        // AES-GCM through `std.crypto` is exactly the kind of work that would
        // silently lose an order of magnitude without this.
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "h3", .module = h3_module },
                .{ .name = "bench_options", .module = bench_options.createModule() },
            },
        }),
    });
    const bench_run = b.addRunArtifact(bench_exe);
    if (b.args) |args| bench_run.addArgs(args);
    const bench_step = b.step("bench", "Run the packet-protection and codec microbenchmarks (ReleaseFast)");
    bench_step.dependOn(&bench_run.step);

    // The README's usage example, compiled and run. A usage example that is
    // only prose rots the first time a signature changes, and the first thing a
    // reader tries is the thing that no longer builds.
    const example_exe = b.addExecutable(.{
        .name = "h3-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("example/initial.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "h3", .module = h3_module }},
        }),
    });
    const example_run = b.addRunArtifact(example_exe);
    const example_step = b.step("example", "Build and run the README's usage example");
    example_step.dependOn(&example_run.step);

    // Conformance against RFC 9001 appendix A's worked packets. Its own binary
    // because it embeds fixtures no consumer needs — a corpus that ships is
    // test data in everyone's dependency tree.
    const corpus_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("corpus/all.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "h3", .module = h3_module }},
        }),
    });
    const corpus_run = b.addRunArtifact(corpus_tests);
    const corpus_step = b.step("corpus", "RFC 9001 appendix A's worked packets, octet for octet");
    corpus_step.dependOn(&corpus_run.step);

    // A negative fixture: `checks/` holds files that must FAIL to compile. This
    // one proves that a `comptime` assertion is still checked with
    // `-Dassertions=false`, which no `test` block can express.
    const comptime_check = b.addObject(.{
        .name = "h3-comptime-assert-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("checks/comptime_assert_is_not_optional.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "h3", .module = h3_module }},
        }),
    });
    comptime_check.expect_errors = .{ .contains = "reached unreachable code" };
    const checks_step = b.step("checks", "Fixtures that must fail to compile");
    checks_step.dependOn(&comptime_check.step);

    const test_step = b.step("test", "Run unit tests, the lint's own tests, and the fuzz corpus");
    test_step.dependOn(&module_tests.step);
    test_step.dependOn(&lint_tests.step);
    // A corpus replayed only under `zig build fuzz` is a corpus that rots.
    test_step.dependOn(&fuzz_run.step);
    test_step.dependOn(&corpus_run.step);
    // So that `zig build ci` fails on a README example that stopped compiling.
    test_step.dependOn(&example_run.step);
    test_step.dependOn(&comptime_check.step);

    // The format gate. A build step rather than a documented `zig fmt --check`
    // incantation, so that the list of formatted paths lives in exactly one
    // place and CI cannot check a different set than a developer does.
    const fmt_paths = &.{ "src", "scripts", "bench", "fuzz", "example", "checks", "corpus/all.zig", "corpus/rfc9001.zig", "build.zig", "build.zig.zon" };
    const fmt_check = b.addFmt(.{ .paths = fmt_paths, .check = true });
    const fmt_step = b.step("fmt", "Check formatting (zig build fmt-fix rewrites)");
    fmt_step.dependOn(&fmt_check.step);

    const fmt_fix = b.addFmt(.{ .paths = fmt_paths });
    const fmt_fix_step = b.step("fmt-fix", "Reformat in place");
    fmt_fix_step.dependOn(&fmt_fix.step);

    // Every per-change gate behind one name, so CI and a local check cannot
    // drift apart. `bench` is deliberately excluded: its verdict is a band
    // comparison a human makes across runs, not a pass/fail a shared runner can
    // produce. CLAUDE.md requires it by hand for a change that touches a
    // protection or codec path.
    const ci_step = b.step("ci", "Per-change gates: fmt + test + lint (bench is run by hand)");
    ci_step.dependOn(fmt_step);
    ci_step.dependOn(test_step);
    ci_step.dependOn(lint_step);
}
