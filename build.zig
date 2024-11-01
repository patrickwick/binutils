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

        // TODO: add non-native endianness target and 32bit target architecture
        const test_base_exe = b.addExecutable(.{
            .name = "test_base",
            .root_source_file = b.path(TEST_DIR ++ "/test_base.zig"),
            .target = target,
            .optimize = optimize,
            .use_llvm = USE_LLVM,
        });
        const test_base_install = b.addInstallArtifact(test_base_exe, .{ .dest_dir = destination_dir });
        integration_test_exe.step.dependOn(&test_base_install.step);

        // objcopy --strip-all
        {
            const name = "test_base_strip_all";
            const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                .strip_all = true,
            });
            const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_install.step);
        }

        // objcopy --compress-debug
        {
            const name = "test_base_compress_debug";
            const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                .compress_debug_sections = true,
            });
            const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_install.step);
        }

        // objcopy --only-keep-debug
        {
            const name = "test_base_only_keep_debug";
            const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                .only_keep_debug = true,
            });
            const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_install.step);
        }

        // objcopy --add-section
        {
            const name = "test_base_add_section";
            const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                .add_section = .{
                    .section_name = ".abc123",
                    .file_path = test_base_exe.getEmittedBin(),
                },
            });
            const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_install.step);
        }

        // objcopy: debug split convenience function
        {
            const name = "test_base_extract_to_separate_file";
            const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                .extract_to_separate_file = "test_base.debug",
            });

            const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_install.step);

            const objcopy_debug_install = b.addInstallFileWithDir(objcopy_target.getOutputSeparatedDebug().?, .{ .custom = TEST_DIR }, name);
            integration_test_step.dependOn(&objcopy_debug_install.step);
        }
    }
}
