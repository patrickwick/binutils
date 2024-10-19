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
        \\Usage: binutils command [options]
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
    if (std.mem.eql(u8, command, "readelf")) return Command{ .readelf = parseReadElf(out, args[1..]) };
    if (std.mem.eql(u8, command, "objdump")) return Command{ .objdump = parseObjDump(out, args[1..]) };
    if (std.mem.eql(u8, command, "objcopy")) return Command{ .objcopy = parseObjCopy(out, args[1..]) };
    fatalPrintUsage(out, "unrecognized command: '{s}'", .{args[0]});
}

fn parseReadElf(out: std.io.AnyWriter, args: []const []const u8) readelf.ReadElfOptions {
    var file_path: ?[]const u8 = null;
    var file_header = false;
    var section_headers = false;
    var program_headers = false;

    for (args) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-') {
            if (arg.len > 1 and arg[1] == '-') {
                // TODO: --help => print usage and exit

                if (std.mem.eql(u8, arg, "--file-header")) {
                    file_header = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--section-headers")) {
                    section_headers = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--sections")) {
                    section_headers = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--program-headers")) {
                    program_headers = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--segments")) {
                    program_headers = true;
                    continue;
                }
            } else {
                // single dash args allow 0 to n options
                for (arg[1..]) |c| {
                    switch (c) {
                        'h' => file_header = true,
                        'S' => section_headers = true,
                        'l' => program_headers = true,
                        else => fatalPrintUsageReadElf(out, "unrecognized argument '-{s}'", .{[_]u8{c}}),
                    }
                }
                continue;
            }
        } else {
            if (file_path) |path| fatalPrintUsageReadElf(out, "expecting a single positional argument, got '{s}' and additional '{s}'", .{ path, arg });
            file_path = arg;
            continue;
        }

        fatalPrintUsageReadElf(out, "unrecognized argument '{s}'", .{arg});
    }

    if (file_path == null) fatalPrintUsageReadElf(out, "positional argument required", .{});

    return .{
        .file_path = file_path.?,
        .file_header = file_header,
        .section_headers = section_headers,
        .program_headers = program_headers,
    };
}

fn parseObjDump(out: std.io.AnyWriter, args: []const []const u8) objdump.ObjDumpOptions {
    _ = out;
    _ = args;
    return .{};
}

fn parseObjCopy(out: std.io.AnyWriter, args: []const []const u8) objcopy.ObjCopyOptions {
    var in_file_path: ?[]const u8 = null;
    var out_file_path: ?[]const u8 = null;

    for (args) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-') {
            if (arg.len > 1 and arg[1] == '-') {
                // TODO: --help => print usage and exit
            } else {
                // single dash args allow 0 to n options
                for (arg[1..]) |c| {
                    switch (c) {
                        else => fatalPrintUsageObjCopy(out, "unrecognized argument '-{s}'", .{[_]u8{c}}),
                    }
                }
                continue;
            }
        } else {
            if (in_file_path == null) {
                in_file_path = arg;
                continue;
            }

            if (out_file_path == null) {
                out_file_path = arg;
                continue;
            }

            fatalPrintUsageObjCopy(out, "expecting two positional arguments, got '{s}', '{s}' and additional '{s}'", .{
                in_file_path.?,
                out_file_path.?,
                arg,
            });
        }

        fatalPrintUsageObjCopy(out, "unrecognized argument '{s}'", .{arg});
    }

    if (in_file_path == null) fatalPrintUsageObjCopy(out, "two positional argument required, got none", .{});
    if (out_file_path == null) fatalPrintUsageObjCopy(out, "two positional argument required, got one: '{s}'", .{in_file_path.?});

    return .{
        .in_file_path = in_file_path.?,
        .out_file_path = out_file_path.?,
    };
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    std.process.exit(FATAL_EXIT_CODE);
}

fn fatalPrintUsage(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    printUsage(out);
    std.process.exit(FATAL_EXIT_CODE);
}

fn fatalPrintUsageReadElf(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    const usage =
        \\Usage: binutils readelf [options] elf-file
        \\
        \\Options:
        \\
        \\  -h, --file-headers     
        \\      Display file headers.
        \\
        \\  -S, --section-headers
        \\      Display section headers.
        \\
        \\  -l, --program-headers, segments
        \\      Display program headers.
        \\
        \\General Options:
        \\
        \\  --help
        \\      Print command-specific usage
        \\
    ;

    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    out.writeAll(usage) catch @panic("failed printing usage");
    std.process.exit(FATAL_EXIT_CODE);
}

fn fatalPrintUsageObjCopy(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    const usage =
        \\Usage: binutils objcopy [options] in-file out-file
        \\
        \\Options:
        \\
        \\General Options:
        \\
        \\  -h, --help
        \\      Print command-specific usage
        \\
    ;

    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    out.writeAll(usage) catch @panic("failed printing usage");
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

test parseReadElf {
    const writer = std.io.null_writer.any();

    // positional argument
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file" },
        parseReadElf(writer, &.{"./file"}),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "--file-header", "./file" }),
    );

    // double dash options
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "./file", "--file-header" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "./file", "--file-header", "--file-header" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .section_headers = true },
        parseReadElf(writer, &.{ "./file", "--section-headers" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .section_headers = true },
        parseReadElf(writer, &.{ "./file", "--sections" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .program_headers = true },
        parseReadElf(writer, &.{ "./file", "--program-headers" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .program_headers = true },
        parseReadElf(writer, &.{ "./file", "--segments" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{
            .file_path = "./file",
            .file_header = true,
            .section_headers = true,
            .program_headers = true,
        },
        parseReadElf(writer, &.{ "./file", "--file-header", "--section-headers", "--program-headers" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{
            .file_path = "./file",
            .file_header = true,
            .section_headers = true,
            .program_headers = true,
        },
        parseReadElf(writer, &.{ "./file", "--file-header", "--section-headers", "--sections", "--program-headers", "--segments" }),
    );

    // single dash options
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "./file", "-h" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .section_headers = true },
        parseReadElf(writer, &.{ "./file", "-S" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .program_headers = true },
        parseReadElf(writer, &.{ "./file", "-l" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true, .section_headers = true, .program_headers = true },
        parseReadElf(writer, &.{ "./file", "-Shl" }),
    );

    // multiple single dash options
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true, .section_headers = true, .program_headers = true },
        parseReadElf(writer, &.{ "./file", "-S", "-h", "-l" }),
    );

    // dashes without flags
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file" },
        parseReadElf(writer, &.{ "./file", "-" }),
    );
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "./file", "-", "-h" }),
    );
}

test "parseReadElf fatal errors" {
    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // double positional argument is not supported
            _ = parseReadElf(std.io.null_writer.any(), &.{ "a", "b" });
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // no positional argument
            _ = parseReadElf(std.io.null_writer.any(), &.{});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // no positional argument
            _ = parseReadElf(std.io.null_writer.any(), &.{"--file-header"});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // unrecognized option
            _ = parseReadElf(std.io.null_writer.any(), &.{ "./file", "--do-stuff" });
        }
    }.F);
}

test parseObjCopy {
    const writer = std.io.null_writer.any();

    // positional argument
    try t.expectEqualDeep(
        objcopy.ObjCopyOptions{ .in_file_path = "./in", .out_file_path = "./out" },
        parseObjCopy(writer, &.{ "./in", "./out" }),
    );
}

test "parseObjCopy fatal errors" {
    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // requires two positional arguments
            _ = parseObjCopy(std.io.null_writer.any(), &.{"a"});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // no positional argument
            _ = parseObjCopy(std.io.null_writer.any(), &.{});
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // unrecognized option
            _ = parseObjCopy(std.io.null_writer.any(), &.{ "./in", "./out", "--do-stuff" });
        }
    }.F);

    try testing.expectExit(FATAL_EXIT_CODE, struct {
        fn F() !void {
            // unrecognized option
            _ = parseObjCopy(std.io.null_writer.any(), &.{ "./in", "./out", "-Ö" });
        }
    }.F);
}

test {
    t.refAllDecls(@This());
}
