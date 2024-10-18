const std = @import("std");

const readelf = @import("readelf.zig");
const objdump = @import("objdump.zig");
const objcopy = @import("objcopy.zig");

const FATAL_ERROR = 1;

pub fn main() !void {
    const std_out = std.io.getStdOut().writer().any();

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = general_purpose_allocator.allocator();

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var args = std.process.argsAlloc(arena) catch fatal("failed copying command line arguments", .{});
    if (args.len < 1) fatal("expected executable path argument", .{});
    args = args[1..];

    const command = parseCommand(std_out, args);
    switch (command) {
        .readelf => |options| readelf.readelf(options),
        .objdump => |options| objdump.objdump(options),
        .objcopy => |options| objcopy.objcopy(options),
    }
}

fn printUsage(out: std.io.AnyWriter) void {
    const usage =
        \\Usage: binutil command [options]
        \\
        \\Commands:
        \\
        \\  readelf          Display information about ELF files
        \\  objdump          Display information from object files
        \\  objcopy          Copy and translate object files
        \\
        \\General Options:
        \\
        \\  -h, --help       Print command-specific usage
        \\
    ;

    out.writeAll(usage) catch @panic("failed printing usage");
}

const Command = union(enum) {
    readelf: readelf.ReadElfOptions,
    objdump: objdump.ObjDumpOptions,
    objcopy: objcopy.ObjCopyOptions,
};

fn parseCommand(out: std.io.AnyWriter, args: []const []const u8) Command {
    if (args.len < 1) fatalPrintUsage(out, "command argument required", .{});
    const command = args[0];
    if (std.mem.eql(u8, command, "readelf")) return Command{ .readelf = parseReadelf(out, args[1..]) };
    if (std.mem.eql(u8, command, "objdump")) return Command{ .objdump = parseObjdump(out, args[1..]) };
    if (std.mem.eql(u8, command, "objcopy")) return Command{ .objcopy = parseObjcopy(out, args[1..]) };
    fatalPrintUsage(out, "unrecognized command: '{s}'", .{args[0]});
}

fn parseReadelf(out: std.io.AnyWriter, args: []const []const u8) readelf.ReadElfOptions {
    _ = out;
    if (args.len < 1) fatal("expected input file path", .{});

    return .{
        .file_path = args[0],
    };
}

fn parseObjdump(out: std.io.AnyWriter, args: []const []const u8) objdump.ObjDumpOptions {
    _ = out;
    _ = args;
    return .{};
}

fn parseObjcopy(out: std.io.AnyWriter, args: []const []const u8) objcopy.ObjCopyOptions {
    _ = out;
    _ = args;
    return .{};
}

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    std.process.exit(FATAL_ERROR);
}

pub fn fatalPrintUsage(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    printUsage(out);
    std.process.exit(FATAL_ERROR);
}

const t = std.testing;

/// Expect the function to cause the process to exit with a non-zero exit code.
fn expectExit(comptime expected_exit_code: u32, function: anytype) !void {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("expectExit is only executed on linux", .{});
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
        t.expectEqual(expected_exit_code, exit_code) catch |err| {
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

test parseCommand {
    try expectExit(FATAL_ERROR, struct {
        fn F() !void {
            _ = parseCommand(std.io.null_writer.any(), &.{});
        }
    }.F);

    try expectExit(FATAL_ERROR, struct {
        fn F() !void {
            _ = parseCommand(std.io.null_writer.any(), &.{""});
        }
    }.F);

    try expectExit(FATAL_ERROR, struct {
        fn F() !void {
            _ = parseCommand(std.io.null_writer.any(), &.{"discombobulate"});
        }
    }.F);

    const writer = std.io.null_writer.any();
    try t.expect(std.meta.activeTag(parseCommand(writer, &.{ "readelf", "./file" })) == .readelf);
    try t.expect(std.meta.activeTag(parseCommand(writer, &.{ "objdump", "file_path" })) == .objdump);
    try t.expect(std.meta.activeTag(parseCommand(writer, &.{ "objcopy", "/home/abc/input", "./output" })) == .objcopy);
}

test {
    t.refAllDecls(@This());
}
