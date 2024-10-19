const std = @import("std");
const builtin = @import("builtin");

const testing = @import("testing.zig");
const readelf = @import("readelf.zig");
const objdump = @import("objdump.zig");
const objcopy = @import("objcopy.zig");

const FATAL_EXIT_CODE = 1;

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
        .readelf => |options| readelf.readelf(gpa, options),
        .objdump => |options| objdump.objdump(gpa, options),
        .objcopy => |options| objcopy.objcopy(gpa, options),
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

    // TODO: parse options
    // TODO: error on additional arguments

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

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    if (!builtin.is_test) std.log.err(format, args);
    std.process.exit(FATAL_EXIT_CODE);
}

fn fatalPrintUsage(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    if (!builtin.is_test) std.log.err(format, args);
    printUsage(out);
    std.process.exit(FATAL_EXIT_CODE);
}

const t = std.testing;

test parseCommand {
    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            _ = parseCommand(std.io.null_writer.any(), &.{});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            _ = parseCommand(std.io.null_writer.any(), &.{""});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
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
