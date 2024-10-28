const std = @import("std");

const binutils = @import("src/binutils.zig");

const USE_LLVM = false;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Command line executable
    const exe = target: {
        const exe = b.addExecutable(.{
            .name = "binutils",
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .use_llvm = USE_LLVM,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| run_cmd.addArgs(args);

        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);

        break :target exe;
    };

    // unit tests
    {
        const exe_unit_tests = b.addTest(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .use_llvm = USE_LLVM,
        });
        const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_exe_unit_tests.step);
    }

    // integration tests
    {
        const TEST_DIR = "test";

        const integration_test_step = b.step("test_integration", "Run integration tests");
        integration_test_step.dependOn(&exe.step);
        integration_test_step.dependOn(b.getInstallStep());

        const integration_test_exe = b.addTest(.{
            .root_source_file = b.path(TEST_DIR ++ "/test.zig"),
            .target = target,
            .optimize = optimize,
            .use_llvm = USE_LLVM,
        });
        const run_integration_tests = b.addRunArtifact(integration_test_exe);
        integration_test_step.dependOn(&run_integration_tests.step);

        const destination_dir = std.Build.Step.InstallArtifact.Options.Dir{ .override = .{ .custom = "test" } };

        const hello_world_exe = b.addExecutable(.{
            .name = "hello_world",
            .root_source_file = b.path(TEST_DIR ++ "/hello_world.zig"),
            .target = target,
            .optimize = optimize,
            .use_llvm = USE_LLVM,
        });
        const hello_world_install = b.addInstallArtifact(hello_world_exe, .{ .dest_dir = destination_dir });
        integration_test_exe.step.dependOn(&hello_world_install.step);

        // objcopy --strip-all
        const strip_all = binutils.Build.Step.ObjCopy.create(b, hello_world_exe.getEmittedBin(), .{
            .strip_all = true,
        });

        const strip_all_install = b.addInstallFileWithDir(
            strip_all.getOutput(),
            .{ .custom = TEST_DIR },
            "hello_world_strip_all",
        );
        integration_test_step.dependOn(&strip_all_install.step);
    }
}
