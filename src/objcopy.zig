const std = @import("std");
const builtin = @import("builtin");

const testing = @import("testing.zig");
const Elf = @import("Elf.zig").Elf;

const FATAL_EXIT_CODE = 1;

pub const ObjCopyOptions = struct {
    in_file_path: []const u8,
    out_file_path: []const u8,
    output_target: OutputTarget = .elf,
    only_section: ?OnlySectionOption = null,
    pad_to: ?PadToOption = null,
    strip_debug: bool = false,
    strip_all: bool = false,
    only_keep_debug: bool = false,
    add_gnu_debuglink: ?AddGnuDebugLinkOption = null,
    extract_to: ?ExtractToOption = null,
    compress_debug_sections: bool = false,
    set_section_alignment: ?SetSectionAlignmentOption = null,
    set_section_flags: ?SetSectionFlagsOption = null,
    add_section: ?AddSectionOption = null,
};

pub const OutputTarget = enum {
    elf,
    raw,
    hex,
};

pub const PadToOption = struct {
    address: u64,
};

pub const AddGnuDebugLinkOption = struct {
    link: []const u8,
};

pub const ExtractToOption = struct {
    target_path: []const u8,
};

pub const SetSectionFlagsOption = struct {
    section_name: []const u8,
    flags: usize, // TODO: add packed struct
};

pub const SetSectionAlignmentOption = struct {
    section_name: []const u8,
    alignment: usize,
};

pub const AddSectionOption = struct {
    section_name: []const u8,
    file_path: []const u8,
};

pub const OnlySectionOption = struct {
    section_name: []const u8,
};

pub fn objcopy(allocator: std.mem.Allocator, options: ObjCopyOptions) void {
    const out = std.io.getStdOut();
    _ = out;

    if (std.mem.eql(u8, options.in_file_path, options.out_file_path)) fatal("input and output file path are not allowed to be equal", .{});

    var in_file = std.fs.cwd().openFile(options.in_file_path, .{}) catch |err| fatal(
        "unable to open input '{s}': {s}",
        .{ options.in_file_path, @errorName(err) },
    );
    defer in_file.close();

    var elf = Elf.read(allocator, in_file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.in_file_path, @errorName(err) });
    defer elf.deinit();

    var out_file = std.fs.cwd().createFile(options.out_file_path, .{
        .read = true,
        .truncate = true,
        .mode = 0o755,
    }) catch |err| fatal(
        "failed creating output '{s}': {s}",
        .{ options.out_file_path, @errorName(err) },
    );
    defer out_file.close();

    // --add-section
    if (options.add_section) |add_section| {
        var add_section_input = std.fs.cwd().openFile(add_section.file_path, .{}) catch |err| fatal(
            "unable to open add-section input '{s}': {s}",
            .{ options.in_file_path, @errorName(err) },
        );
        defer add_section_input.close();

        const content = add_section_input.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |err| fatal(
            "failed reading add-sectipn input '{s}': {s}",
            .{ options.in_file_path, @errorName(err) },
        );
        defer allocator.free(content);

        elf.addSection(in_file, add_section.section_name, content) catch |err| fatal(
            "failed adding new section '{s}': {s}",
            .{ add_section.section_name, @errorName(err) },
        );
    }

    // --only-section
    if (options.only_section) |only_section| {
        // double loop since iteration needs to be restarted on modified array
        while (true) {
            for (elf.sections.items, 0..) |*section, i| {
                // keep null section and section name string table section
                if (i == 0 or i == elf.e_shstrndx) continue;

                const name = elf.getSectionName(section);
                if (std.mem.eql(u8, name, only_section.section_name)) continue;

                elf.removeSection(section.handle) catch |err| fatal(
                    "failed removing section '{s}': {s}",
                    .{ name, @errorName(err) },
                );

                break; // restart iteration => items are invalidated
            } else break;
        }
    }

    // --set-section-alignment
    if (options.set_section_alignment) |set_section_alignment| {
        if (!std.math.isPowerOfTwo(set_section_alignment.alignment)) {
            fatal("section alignment must be a power of two, got {d}", .{set_section_alignment.alignment});
        }

        const section = for (elf.sections.items) |*section| {
            const name = elf.getSectionName(section);
            if (std.mem.eql(u8, name, set_section_alignment.section_name)) break section;
        } else fatal("uknown section '{s}'", .{set_section_alignment.section_name});

        section.header.sh_addralign = @intCast(set_section_alignment.alignment);
        elf.fixup() catch |err| fatal("failed overwriting section alignemnt: {s}", .{@errorName(err)});
    }

    elf.write(allocator, in_file, out_file) catch |err| fatal(
        "failed writing output '{s}': {s}",
        .{ options.out_file_path, @errorName(err) },
    );
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils objcopy";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    if (builtin.mode == .Debug) testing.printStackTrace(@returnAddress());
    std.process.exit(FATAL_EXIT_CODE);
}
