const std = @import("std");
const builtin = @import("builtin");

/// Expect the function to cause the process to exit with a non-zero exit code.
pub fn expectExit(comptime expected_exit_code: u32, function: anytype) !void {
    if (builtin.os.tag != .linux) {
        std.log.warn("expectExit is only executed on linux", .{});
        return;
    }
    if (expected_exit_code == 0) @compileError("Only non-zero exit codes are supported");

    // fork the process: child executes the function, parent waits for the exit code
    const child_pid = try std.posix.fork();
    if (child_pid == 0) {
        // child
        function() catch {};
        std.process.exit(0);
    }

    // parent
    const has_not_changed = 0;
    var status: u32 = 0;
    while (std.os.linux.waitpid(child_pid, &status, 0) == has_not_changed or !std.os.linux.W.IFEXITED(status)) {}
    const exit_code = std.os.linux.W.EXITSTATUS(status);
    if (exit_code != expected_exit_code) {
        std.testing.expectEqual(expected_exit_code, exit_code) catch |err| {
            std.log.err("Function did not exit with the expected error code", .{});

            const max_frames = 20;
            var addresses: [max_frames]usize = [1]usize{0} ** max_frames;
            var stack_trace = std.builtin.StackTrace{
                .instruction_addresses = &addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(@returnAddress(), &stack_trace);
            std.debug.dumpStackTrace(stack_trace);

            return err;
        };
    }
}

const t = std.testing;

test expectExit {
    const exit_code = 1;
    try expectExit(exit_code, struct {
        fn F() !void {
            std.process.exit(exit_code);
        }
    }.F);
}
