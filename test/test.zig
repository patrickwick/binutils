// Integration test entry point testing functionality on compiled binaries.
const std = @import("std");

const PREFIX = "./zig-out"; // TODO: no hardcoded prefix

test "objcopy --add-section .new_section_abc123=./test_base_x86_64" {
    if (true) return; // FIXME: update

    const allocator = std.testing.allocator;

    {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .cwd = PREFIX,
            .argv = &.{
                "./bin/binutils",
                "objcopy",
                "./test/test_base_x86_64",
                "./test/test_base_x86_64_add_section",
                "--add-section",
                ".new_section_abc123=./test/test_base_x86_64",
            },
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        errdefer std.log.err("stdout: {s}", .{result.stdout});
        errdefer std.log.err("stderr: {s}", .{result.stderr});
        defer std.log.info("stdout: {s}", .{result.stdout});
        defer std.log.info("stderr: {s}", .{result.stderr});

        try std.testing.expect(std.meta.activeTag(result.term) == .Exited);
        try std.testing.expectEqual(0, result.term.Exited);
    }

    {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .cwd = PREFIX,
            .argv = &.{
                "./bin/binutils",
                "readelf",
                "./test/test_base_x86_64_add_section",
                "--sections",
            },
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        errdefer std.log.err("stdout: {s}", .{result.stdout});
        errdefer std.log.err("stderr: {s}", .{result.stderr});
        defer std.log.info("stdout: {s}", .{result.stdout});
        defer std.log.info("stderr: {s}", .{result.stderr});
        try std.testing.expect(std.meta.activeTag(result.term) == .Exited);
        try std.testing.expectEqual(0, result.term.Exited);

        try std.testing.expect(std.mem.containsAtLeast(u8, result.stdout, 1, ".new_section_abc123 PROGBITS"));
    }
}
