const std = @import("std");

const readelf = @import("readelf.zig");
const objdump = @import("objdump.zig");
const objcopy = @import("objcopy.zig");

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

    const command = parseCommand(std_out, args) catch |err| switch (err) {
        CommandParsingError.MissingCommand => fatalPrintUsage(std_out, "command argument required", .{}),
        CommandParsingError.UnrecognizedCommand => fatalPrintUsage(std_out, "unrecognized command: '{s}'", .{args[0]}),
    };

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

const CommandParsingError = error{
    MissingCommand,
    UnrecognizedCommand,
};

fn parseCommand(out: std.io.AnyWriter, args: []const []const u8) CommandParsingError!Command {
    if (args.len < 1) return CommandParsingError.MissingCommand;
    const command = args[0];
    if (std.mem.eql(u8, command, "readelf")) return Command{ .readelf = parseReadelf(out, args[1..]) };
    if (std.mem.eql(u8, command, "objdump")) return Command{ .objdump = parseObjdump(out, args[1..]) };
    if (std.mem.eql(u8, command, "objcopy")) return Command{ .objcopy = parseObjcopy(out, args[1..]) };
    return CommandParsingError.UnrecognizedCommand;
}

fn parseReadelf(out: std.io.AnyWriter, args: []const []const u8) readelf.ReadElfOptions {
    _ = out;
    _ = args;
    return .{};
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
    std.process.exit(1);
}

pub fn fatalPrintUsage(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    printUsage(out);
    std.process.exit(1);
}

const t = std.testing;

test parseCommand {
    const writer = std.io.null_writer.any();
    try t.expect(std.meta.activeTag(try parseCommand(writer, &.{"readelf"})) == .readelf);
    try t.expect(std.meta.activeTag(try parseCommand(writer, &.{"objdump"})) == .objdump);
    try t.expect(std.meta.activeTag(try parseCommand(writer, &.{"objcopy"})) == .objcopy);
    try t.expectError(CommandParsingError.MissingCommand, parseCommand(writer, &.{}));
    try t.expectError(CommandParsingError.UnrecognizedCommand, parseCommand(writer, &.{"discombobulate"}));
}

test {
    t.refAllDecls(@This());
}
