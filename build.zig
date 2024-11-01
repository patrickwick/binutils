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

        const targets = [_]std.Build.ResolvedTarget{
            target, // native
            b.resolveTargetQuery(.{ .cpu_arch = .riscv32 }), // test 32bit
            b.resolveTargetQuery(.{ .cpu_arch = .aarch64_be }), // test big endian arch
        };

        const target_names = &.{
            "test_base_x86_64",
            "test_base_riscv32",
            "test_base_aarch64_big_endian",
        };

        inline for (targets, target_names) |t, base_name| {
            const test_base_exe = b.addExecutable(.{
                .name = base_name,
                .root_source_file = .{ .cwd_relative = b.pathJoin(&.{ TEST_DIR, "/test_base.zig" }) },
                .target = t,
                .optimize = optimize,
                .use_llvm = true, // zig backend does not support all targets yet
            });
            const test_base_install = b.addInstallArtifact(test_base_exe, .{ .dest_dir = destination_dir });
            integration_test_exe.step.dependOn(&test_base_install.step);

            // TODO: skipping test big endian target: NYI, will corrupt enum values, etc.
            comptime if (std.mem.eql(u8, base_name, target_names[2])) continue;

            // objcopy --strip-all
            {
                const name = base_name ++ "_strip_all";
                const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                    .strip_all = true,
                });
                const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
                integration_test_step.dependOn(&objcopy_install.step);
            }

            // objcopy --compress-debug
            {
                const name = base_name ++ "_compress_debug";
                const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                    .compress_debug_sections = true,
                });
                const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
                integration_test_step.dependOn(&objcopy_install.step);
            }

            // objcopy --only-keep-debug
            {
                const name = base_name ++ "_only_keep_debug";
                const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                    .only_keep_debug = true,
                });
                const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
                integration_test_step.dependOn(&objcopy_install.step);
            }

            // objcopy --add-section
            {
                const name = base_name ++ "_add_section";
                const objcopy_target = binutils.Build.Step.ObjCopy.create(b, test_base_exe.getEmittedBin(), .{
                    .add_section = .{
                        .section_name = ".abc123",
                        .file_path = test_base_exe.getEmittedBin(),
                    },
                });
                const objcopy_install = b.addInstallFileWithDir(objcopy_target.getOutput(), .{ .custom = TEST_DIR }, name);
                integration_test_step.dependOn(&objcopy_install.step);
            }

            // objcopy: debug split convenience function equivalent to:
            // * objcopy in out --strip-debug
            // * objcopy in out.debug --only-keep-debug
            // * objcopy out --add-gnu-debuglink=out.debug
            {
                const name = base_name ++ "_extract_to_separate_file";
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
}
