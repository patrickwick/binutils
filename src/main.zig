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
    if (args.len < 1) {
        printUsage(out);
        std.process.exit(0);
    }

    const command = args[0];
    if (std.mem.eql(u8, command, "readelf")) return Command{ .readelf = parseReadElf(out, args[1..]) };
    if (std.mem.eql(u8, command, "objdump")) return Command{ .objdump = parseObjDump(out, args[1..]) };
    if (std.mem.eql(u8, command, "objcopy")) return Command{ .objcopy = parseObjCopy(out, args[1..]) };
    if (std.mem.eql(u8, command, "--help")) {
        printUsage(out);
        std.process.exit(0);
    }
    fatalPrintUsage(out, "unrecognized command: '{s}'", .{args[0]});
}

fn parseReadElf(out: std.io.AnyWriter, args: []const []const u8) readelf.ReadElfOptions {
    var file_path: ?[]const u8 = null;
    var file_header = false;
    var section_headers = false;
    var program_headers = false;
    var symbols = false;

    // TODO: add -wA for gnu_debuglink
    for (args) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-') {
            if (arg.len > 1 and arg[1] == '-') {
                if (std.mem.eql(u8, arg, "--help")) {
                    out.writeAll(READELF_USAGE) catch @panic("failed printing usage");
                    std.process.exit(0);
                }

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

                if (std.mem.eql(u8, arg, "--headers")) {
                    file_header = true;
                    section_headers = true;
                    program_headers = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--segments")) {
                    program_headers = true;
                    continue;
                }

                if (std.mem.eql(u8, arg, "--symbols") or std.mem.eql(u8, arg, "--syms")) {
                    symbols = true;
                    continue;
                }
            } else {
                // single dash args allow 0 to n options
                for (arg[1..]) |c| {
                    switch (c) {
                        'h' => file_header = true,
                        'S' => section_headers = true,
                        'l' => program_headers = true,
                        'e' => {
                            file_header = true;
                            section_headers = true;
                            program_headers = true;
                        },
                        's' => symbols = true,
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
        .symbols = symbols,
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

    var output_target: objcopy.OutputTarget = .elf;
    var only_section: ?objcopy.OnlySectionOption = null;
    var pad_to: ?objcopy.PadToOption = null;
    var strip_debug: bool = false;
    var strip_all: bool = false;
    var only_keep_debug: bool = false;
    var add_gnu_debuglink: ?objcopy.AddGnuDebugLinkOption = null;
    var compress_debug_sections: bool = false;
    var set_section_alignment: ?objcopy.SetSectionAlignmentOption = null;
    var set_section_flags: ?objcopy.SetSectionFlagsOption = null;
    var add_section: ?objcopy.AddSectionOption = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (arg.len == 0) continue;
        if (arg[0] == '-') {
            if (arg.len > 1 and arg[1] == '-') {
                //  --help
                if (std.mem.eql(u8, arg, "--help")) {
                    out.writeAll(OBJCOPY_USAGE) catch std.process.exit(1);
                    std.process.exit(0);
                }

                // --output-target=<value>
                if (std.mem.startsWith(u8, arg, "--output-target")) {
                    const split = splitOption(arg) orelse fatalPrintUsageObjCopy(
                        out,
                        "unrecognized argument: '{s}', expecting --output-target=<value>",
                        .{arg},
                    );
                    _ = split;
                    output_target = .elf; // TODO: parse
                    continue;
                }

                // --pad-to <addr>
                if (std.mem.eql(u8, arg, "--pad-to")) {
                    if (args.len > i + 1) {
                        defer i += 1;
                        const opt = args[i + 1];
                        // TODO: support hex with 0x prefix
                        const address = std.fmt.parseInt(usize, opt, 10) catch fatalPrintUsageObjCopy(
                            out,
                            "unrecognized argument: '{s}', expecting --pad-to <addr>",
                            .{arg},
                        );
                        pad_to = .{ .address = address };
                    } else fatalPrintUsageObjCopy(out, "unrecognized {s} argument, expecting --pad-to <addr>", .{arg});
                    continue;
                }

                // --strip-debug
                if (std.mem.eql(u8, arg, "--strip-debug")) {
                    strip_debug = true;
                    continue;
                }

                // --strip-all
                if (std.mem.eql(u8, arg, "--strip-all")) {
                    strip_all = true;
                    continue;
                }

                // --only-section=<section>
                if (std.mem.startsWith(u8, arg, "--only-section")) {
                    const split = splitOption(arg) orelse fatalPrintUsageObjCopy(
                        out,
                        "unrecognized argument: '{s}', expecting --only-section=<section>",
                        .{arg},
                    );
                    only_section = .{ .section_name = split.second };
                    continue;
                }

                // --only-keep-debug
                if (std.mem.eql(u8, arg, "--only-keep-debug")) {
                    only_keep_debug = true;
                    continue;
                }

                // --add-gnu-debuglink=<file>
                if (std.mem.startsWith(u8, arg, "--add-gnu-debuglink")) {
                    const split = splitOption(arg) orelse fatalPrintUsageObjCopy(
                        out,
                        "unrecognized {s} argument, expecting --add-gnu-debuglink=<file>",
                        .{arg},
                    );
                    add_gnu_debuglink = .{ .link = split.second };
                    continue;
                }

                // --compress-debug-sections
                if (std.mem.eql(u8, arg, "--compress-debug-sections")) {
                    compress_debug_sections = true;
                    continue;
                }

                // --set-section-alignment <name>=<align>
                if (std.mem.eql(u8, arg, "--set-section-alignment")) {
                    if (args.len > i + 1) {
                        defer i += 1;
                        const opt = args[i + 1];
                        const split = splitOption(opt) orelse fatalPrintUsageObjCopy(
                            out,
                            "unrecognized {s} argument: '{s}', expecting <name>=<alignment>",
                            .{ arg, opt },
                        );
                        const alignment = std.fmt.parseInt(usize, split.second, 10) catch fatalPrintUsageObjCopy(
                            out,
                            "unrecognized argument: '{s}', expecting decimal alignment number argument",
                            .{arg},
                        );
                        set_section_alignment = .{ .section_name = split.first, .alignment = alignment };
                    } else fatalPrintUsageObjCopy(out, "unrecognized {s} argument, expecting --set-section-alignment <name>=<alignment>", .{arg});
                    continue;
                }

                // --set-section-flags <name>=<flags>
                if (std.mem.eql(u8, arg, "--set-section-flags")) {
                    if (args.len > i + 1) {
                        defer i += 1;
                        const opt = args[i + 1];
                        const split = splitOption(opt) orelse fatalPrintUsageObjCopy(
                            out,
                            "unrecognized {s} argument: '{s}', expecting <name>=<flags>",
                            .{ arg, opt },
                        );
                        set_section_flags = .{ .section_name = split.first, .flags = parseSectionFlags(split.second) };
                    } else fatalPrintUsageObjCopy(out, "unrecognized {s} argument, expecting --set-section-flags <name>=<flags>", .{arg});
                    continue;
                }

                // --add-section <name>=<file>
                if (std.mem.eql(u8, arg, "--add-section")) {
                    if (args.len > i + 1) {
                        defer i += 1;
                        const opt = args[i + 1];
                        const split = splitOption(opt) orelse fatalPrintUsageObjCopy(
                            out,
                            "unrecognized {s} argument: '{s}', expecting <name>=<file>",
                            .{ arg, opt },
                        );
                        add_section = .{ .section_name = split.first, .file_path = split.second };
                    } else fatalPrintUsageObjCopy(out, "unrecognized {s} argument, expecting --add-section <name>=<file>", .{arg});
                    continue;
                }
            } else {
                if (arg[1] == 'O') {
                    const split = splitOption(arg) orelse fatalPrintUsageObjCopy(
                        out,
                        "unrecognized argument: '{s}', expecting --output-target=<value>",
                        .{arg},
                    );
                    _ = split;
                    output_target = .elf; // TODO: parse
                    continue;
                }

                // single dash args allow 0 to n options
                for (arg[1..]) |c| {
                    switch (c) {
                        'h' => {
                            out.writeAll(OBJCOPY_USAGE) catch std.process.exit(1);
                            std.process.exit(0);
                        },
                        'j' => {
                            if (args.len > i + 1) {
                                i += 1;
                                only_section = .{ .section_name = args[i] };
                            } else fatalPrintUsageObjCopy(out, "unrecognized -j argument, expecting -j <section>", .{});
                        },
                        'g' => strip_debug = true,
                        'S' => strip_all = true,
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
        .output_target = output_target,
        .only_section = only_section,
        .pad_to = pad_to,
        .strip_debug = strip_debug,
        .strip_all = strip_all,
        .only_keep_debug = only_keep_debug,
        .add_gnu_debuglink = add_gnu_debuglink,
        .compress_debug_sections = compress_debug_sections,
        .set_section_alignment = set_section_alignment,
        .set_section_flags = set_section_flags,
        .add_section = add_section,
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

const READELF_USAGE =
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
    \\  -e, --headers
    \\      Display file, section and program headers. Equivalent to -S -h -l.
    \\
    \\  -s, --symbols, syms
    \\      Display the symbol table.
    \\
    \\General Options:
    \\
    \\  --help
    \\      Print command-specific usage
    \\
;

fn fatalPrintUsageReadElf(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    out.writeAll(READELF_USAGE) catch @panic("failed printing usage");
    std.process.exit(FATAL_EXIT_CODE);
}

const OBJCOPY_USAGE =
    \\Usage: binutils objcopy [options] in-file out-file
    \\
    \\Options:
    \\
    \\  -j <section>, --only-section=<section>
    \\      Remove all sections except <section> and the section name table section (.shstrtab).
    \\
    \\  --pad-to <addr>
    \\      Pad the last section up to address <addr>.
    \\
    \\  -g, strip-debug
    \\      Remove all debug sections from the output.
    \\
    \\  -S, --strip-all
    \\      Remove all debug sections and symbol table from the output.
    \\
    \\  --only-keep-debug
    \\      Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact.
    \\
    \\  --add-gnu-debuglink=<file>
    \\      Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.
    \\      The <file> path is relative to the in-file directory. Absolute paths are supported as well.
    \\
    \\  --compress-debug-sections
    \\      Compress DWARF debug sections with zlib
    \\
    \\  --set-section-alignment <name>=<align>
    \\      Set alignment of section <name> to <align> bytes. Must be a power of two.
    \\
    \\  --set-section-flags <name>=<flags>
    \\      Set flags of section <name> to <flags> represented as a comma separated set of flags.
    \\
    \\  --add-section <name>=<file>
    \\      Add file content from <file> with the a new section named <name>.
    \\
    \\General Options:
    \\
    \\  -h, --help
    \\      Print command-specific usage
    \\
;

fn fatalPrintUsageObjCopy(out: std.io.AnyWriter, comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    out.writeAll(OBJCOPY_USAGE) catch @panic("failed printing usage");
    std.process.exit(FATAL_EXIT_CODE);
}

fn parseSectionFlags(comma_separated_flags: []const u8) objcopy.SetSectionFlagsOption.SectionFlags {
    const P = struct {
        fn parse(flags: *objcopy.SetSectionFlagsOption.SectionFlags, string: []const u8) void {
            if (string.len == 0) return;

            if (std.mem.eql(u8, string, "alloc")) {
                flags.alloc = true;
            } else if (std.mem.eql(u8, string, "contents")) {
                flags.contents = true;
            } else if (std.mem.eql(u8, string, "load")) {
                flags.load = true;
            } else if (std.mem.eql(u8, string, "noload")) {
                flags.noload = true;
            } else if (std.mem.eql(u8, string, "readonly")) {
                flags.readonly = true;
            } else if (std.mem.eql(u8, string, "code")) {
                flags.code = true;
            } else if (std.mem.eql(u8, string, "data")) {
                flags.data = true;
            } else if (std.mem.eql(u8, string, "rom")) {
                flags.rom = true;
            } else if (std.mem.eql(u8, string, "exclude")) {
                flags.exclude = true;
            } else if (std.mem.eql(u8, string, "shared")) {
                flags.shared = true;
            } else if (std.mem.eql(u8, string, "debug")) {
                flags.debug = true;
            } else if (std.mem.eql(u8, string, "large")) {
                flags.large = true;
            } else if (std.mem.eql(u8, string, "merge")) {
                flags.merge = true;
            } else if (std.mem.eql(u8, string, "strings")) {
                flags.strings = true;
            } else {
                std.log.warn("Skipping unrecognized section flag '{s}'", .{string});
            }
        }
    };

    var flags = objcopy.SetSectionFlagsOption.SectionFlags{};
    var offset: usize = 0;
    for (comma_separated_flags, 0..) |c, i| {
        if (c == ',') {
            defer offset = i + 1;
            const string = comma_separated_flags[offset..i];
            P.parse(&flags, string);
        }
    }
    P.parse(&flags, comma_separated_flags[offset..]);
    return flags;
}

const SplitResult = struct { first: []const u8, second: []const u8 };

fn splitOption(option: []const u8) ?SplitResult {
    const separator = '=';
    if (option.len < 3) return null; // minimum "a=b"
    for (1..option.len - 1) |i| {
        if (option[i] == separator) return .{
            .first = option[0..i],
            .second = option[i + 1 ..],
        };
    }
    return null;
}

const t = std.testing;

test "Parse section flags" {
    const F = objcopy.SetSectionFlagsOption.SectionFlags;
    try t.expectEqual(F{}, parseSectionFlags(""));
    try t.expectEqual(F{}, parseSectionFlags(","));
    try t.expectEqual(F{}, parseSectionFlags("abc"));
    try t.expectEqual(F{ .alloc = true }, parseSectionFlags("alloc"));
    try t.expectEqual(F{ .data = true }, parseSectionFlags("data,"));
    try t.expectEqual(F{ .alloc = true, .code = true }, parseSectionFlags("alloc,code"));
    try t.expectEqual(F{ .alloc = true, .code = true }, parseSectionFlags("alloc,code,not_supported"));
}

test splitOption {
    {
        const split = splitOption(".abc=123");
        try t.expect(split != null);
        try t.expectEqualStrings(".abc", split.?.first);
        try t.expectEqualStrings("123", split.?.second);
    }

    try t.expectEqual(null, splitOption(""));
    try t.expectEqual(null, splitOption("=abc"));
    try t.expectEqual(null, splitOption("abc="));
    try t.expectEqual(null, splitOption("abc"));
}

test parseCommand {
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
    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
    }, parseReadElf(writer, &.{"./file"}));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
    }, parseReadElf(writer, &.{ "--file-header", "./file" }));

    // double dash options
    try t.expectEqualDeep(
        readelf.ReadElfOptions{ .file_path = "./file", .file_header = true },
        parseReadElf(writer, &.{ "./file", "--file-header" }),
    );

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
    }, parseReadElf(writer, &.{ "./file", "--file-header", "--file-header" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .section_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--section-headers" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .section_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--sections" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--program-headers" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--segments" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--headers" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .symbols = true,
    }, parseReadElf(writer, &.{ "./file", "--symbols" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .symbols = true,
    }, parseReadElf(writer, &.{ "./file", "--syms" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--file-header", "--section-headers", "--program-headers" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "--file-header", "--section-headers", "--sections", "--program-headers", "--segments" }));

    // single dash options
    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
    }, parseReadElf(writer, &.{ "./file", "-h" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .section_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-S" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-l" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-e" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .symbols = true,
    }, parseReadElf(writer, &.{ "./file", "-s" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-Shl" }));

    // multiple single dash options
    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-S", "-h", "-l" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
        .section_headers = true,
        .program_headers = true,
    }, parseReadElf(writer, &.{ "./file", "-eSSSSSSSSSSSSS" }));

    // dashes without flags
    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
    }, parseReadElf(writer, &.{ "./file", "-" }));

    try t.expectEqualDeep(readelf.ReadElfOptions{
        .file_path = "./file",
        .file_header = true,
    }, parseReadElf(writer, &.{ "./file", "-", "-h" }));
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
    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
    }, parseObjCopy(writer, &.{ "./in", "./out" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .strip_debug = true,
    }, parseObjCopy(writer, &.{ "./in", "./out", "-g" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .strip_all = true,
    }, parseObjCopy(writer, &.{ "./in", "./out", "-S" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .strip_debug = true,
        .strip_all = true,
    }, parseObjCopy(writer, &.{ "./in", "./out", "-gS" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .strip_debug = true,
    }, parseObjCopy(writer, &.{ "./in", "./out", "--strip-debug" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .strip_all = true,
    }, parseObjCopy(writer, &.{ "./in", "./out", "--strip-all" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .add_gnu_debuglink = .{ .link = "link.debug" },
    }, parseObjCopy(writer, &.{ "./in", "./out", "--add-gnu-debuglink=link.debug" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .set_section_alignment = .{ .section_name = ".abc", .alignment = 128 },
    }, parseObjCopy(writer, &.{ "./in", "./out", "--set-section-alignment", ".abc=128" }));

    try t.expectEqualDeep(objcopy.ObjCopyOptions{
        .in_file_path = "./in",
        .out_file_path = "./out",
        .set_section_flags = .{ .section_name = ".abc", .flags = .{ .data = true, .readonly = true } },
    }, parseObjCopy(writer, &.{ "./in", "./out", "--set-section-flags", ".abc=data,readonly" }));
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
