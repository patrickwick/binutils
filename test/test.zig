// Integration test entry point testing functionality on compiled binaries.
const std = @import("std");

const PREFIX = "./zig-out"; // TODO: no hardcoded prefix

test "objcopy --add-section .new_section_abc123=./hello_world" {
    const allocator = std.testing.allocator;

    {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .cwd = PREFIX,
            .argv = &.{
                "./bin/binutils",
                "objcopy",
                "./test/hello_world",
                "./test/hello_world_add_section",
                "--add-section",
                ".new_section_abc123=./test/hello_world",
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
                "./test/hello_world_add_section",
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

// TODO: consider adding fuzz tests over the CLI arguments
test "fuzz" {
    const global = struct {
        fn testOne(input: []const u8) anyerror!void {
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(global.testOne, .{});
}
