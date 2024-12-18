const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const snappyz = b.dependency("snappyz", .{
        .target = target,
        .optimize = optimize,
    }).module("snappyz");

    const mod = b.addModule("snappyframesz.zig", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/frames.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "snappyz", .module = snappyz },
        },
    });
    _ = mod;

    const lib = b.addStaticLibrary(.{
        .name = "snappyframesz",
        .root_source_file = .{ .cwd_relative = "src/frames.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/frames.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("snappyz", snappyz);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
