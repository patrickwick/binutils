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
    pub const SectionFlags = packed struct {
        alloc: bool = false,
        contents: bool = false,
        load: bool = false,
        noload: bool = false,
        readonly: bool = false,
        code: bool = false,
        data: bool = false,
        rom: bool = false,
        exclude: bool = false,
        shared: bool = false,
        debug: bool = false,
        large: bool = false,
        merge: bool = false,
        strings: bool = false,
    };

    section_name: []const u8,
    flags: SectionFlags,
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

    // TODO: allow single argument objcopy as well using temporary output, see man objcopy:
    // "If you do not specify outfile, objcopy creates a temporary file and destructively renames the result with the name of infile."
    // The input file cannot be overwritten since sections are copied lazyly on write and the file needs to stay valid if an operations fails.
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

    // -O, --output_target
    switch (options.output_target) {
        .elf => {},
        else => fatal("only ELF to ELF copying is currently supported", .{}),
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

    // --pad-to
    if (options.pad_to) |pad_to| {
        if (elf.sections.items.len == 0) fatal("ELF input does not contain any sections to pad", .{});
        if (elf.sections.items.len == 1) fatal("ELF input null section cannot be padded", .{});

        // TODO: add function to Elf
        const sorted = sorted: {
            const sorted_sections = elf.sections.clone() catch |err| fatal("failed sorting sections: {s}", .{@errorName(err)});

            const Sort = struct {
                fn lessThan(context: *const @This(), left: Elf.Section, right: Elf.Section) bool {
                    _ = context;
                    return left.header.sh_offset < right.header.sh_offset;
                }
            };
            var sort_context = Sort{};
            std.mem.sort(Elf.Section, sorted_sections.items, &sort_context, Sort.lessThan);

            break :sorted sorted_sections;
        };
        defer sorted.deinit();

        const section = &sorted.items[sorted.items.len - 1];
        const end = section.header.sh_offset + section.header.sh_size;
        if (pad_to.address > end) {
            section.header.sh_size += pad_to.address - end;
            elf.fixup() catch |err| fatal("failed increasing section size: {s}", .{@errorName(err)});
        } else {
            std.log.info("section end 0x{x} already exceeds address 0x{x}", .{ end, pad_to.address });
        }
    }

    // -g, --strip-debug
    if (options.strip_debug) {
        // double loop since iteration needs to be restarted on modified array
        while (true) {
            for (elf.sections.items) |*section| {
                const name = elf.getSectionName(section);

                // TODO: check if any other sections links to this section transitively

                // TODO: is the name sufficient?
                if (std.mem.startsWith(u8, name, ".debug_")) {
                    std.log.info("Stripping debug section '{s}'", .{name});
                    elf.removeSection(section.handle) catch |err| fatal("failed removing section '{s}': {s}", .{ name, @errorName(err) });
                    break;
                }
            } else break;
        }
    }

    // -S, --strip-all
    if (options.strip_all) {
        // TODO: strip all sections that are not mapped to a segment.
        // for (elf.sections.items) |*section| {
        //     const is_in_segment = mapped: for (elf.program_segments.items) |segment| {
        //         for (segment.segment_mapping.items) |handle| if (section.handle == handle) break :mapped true;
        //     } else false;
        //     _ = is_in_segment;

        //     switch (section.header.sh_type) {
        //         std.elf.SHT_SYMTAB => {},
        //         else => {},
        //     }
        // }
    }

    // --only-keep-debug
    if (options.only_keep_debug) {
        // double loop since iteration needs to be restarted on modified array
        while (true) {
            for (elf.sections.items) |*section| {
                const name = elf.getSectionName(section);

                // TODO: is the name sufficient?
                const not_debug = !std.mem.startsWith(u8, name, ".debug_");

                // TODO: check if any other sections links to this section transitively

                const remove = switch (section.header.sh_type) {
                    std.elf.SHT_SYMTAB => false,
                    std.elf.SHT_STRTAB => false,
                    else => not_debug,
                };

                if (remove) {
                    std.log.info("Stripping non-debug section '{s}'", .{name});
                    elf.removeSection(section.handle) catch |err| fatal("failed removing section '{s}': {s}", .{ name, @errorName(err) });
                    break;
                }
            } else break;
        }

        // TODO: compact file. Header will not be shifted up automatically to minimize layout modifications
    }

    // --add-gnu-debuglink
    if (options.add_gnu_debuglink) |add_gnu_debuglink| {
        const link = add_gnu_debuglink.link;

        const crc = crc: {
            // relative paths are relative to the input file, not working directory
            const directory = std.fs.path.dirname(options.in_file_path) orelse fatal(
                "could not determine directory of '{s}'",
                .{options.in_file_path},
            );

            const base_name = std.fs.path.basename(link);
            const path = std.fs.path.join(allocator, &.{ directory, base_name }) catch |err| fatal(
                "failed joing paths '{s}', '{s}': {s}",
                .{ directory, base_name, @errorName(err) },
            );

            const file = std.fs.cwd().openFile(path, .{}) catch |err| fatal("cannot open file '{s}': {s}", .{
                path,
                @errorName(err),
            });
            defer file.close();

            var buffer: [8000]u8 = undefined;
            var crc = std.hash.Crc32.init();
            while (true) {
                const bytes_read = file.read(&buffer) catch |err| fatal("failed reading '{s}': {s}", .{
                    path,
                    @errorName(err),
                });

                if (bytes_read == 0) break;
                crc.update(buffer[0..bytes_read]);
            }

            break :crc crc.final();
        };

        const crc_bytes = std.mem.toBytes(crc);
        const alignment = 4;
        const crc_offset = std.mem.alignForward(usize, link.len + 1, alignment);
        const link_content = allocator.alloc(u8, crc_offset + crc_bytes.len) catch |err| fatal(
            "failed allocating debuglink section content: {s}",
            .{@errorName(err)},
        );
        @memcpy(link_content[0..link.len], link);
        @memset(link_content[link.len..crc_offset], 0);
        @memcpy(link_content[crc_offset..], &crc_bytes);

        const name = ".gnu_debuglink";
        if (elf.getSectionByName(name)) |section| {
            section.content = .{ .data_allocated = link_content };
            elf.fixup() catch |err| fatal(
                "failed overwriting .gnu_debuglink: {s}",
                .{@errorName(err)},
            );
        } else {
            elf.addSection(in_file, name, link_content) catch |err| fatal(
                "failed adding .gnu_debuglink: {s}",
                .{@errorName(err)},
            );
        }
    }

    // --extract-to
    if (options.extract_to) |extract_to| {
        _ = extract_to; // TODO
    }

    // --compress-debug-sections
    if (options.compress_debug_sections) {
        _ = options.compress_debug_sections; // TODO
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
        elf.fixup() catch |err| fatal("failed overwriting section alignment: {s}", .{@errorName(err)});
    }

    // --set-section-flags
    if (options.set_section_flags) |set_section_flags| {
        const s = for (elf.sections.items) |*section| {
            const name = elf.getSectionName(section);
            if (std.mem.eql(u8, name, set_section_flags.section_name)) break section;
        } else fatal("uknown section '{s}'", .{set_section_flags.section_name});

        const f = set_section_flags.flags;
        s.header.sh_flags = std.elf.SHF_WRITE; // default is writable cleared by "readonly"

        // Supporting a subset of GNU and LLVM objcopy for ELF only
        // GNU:
        // alloc: add SHF_ALLOC
        // contents: if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing
        // load: if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing (same as contents)
        // noload: not ELF relevant
        // readonly: clear default SHF_WRITE flag
        // code: add SHF_EXECINSTR
        // data: not ELF relevant
        // rom: ignored
        // exclude: add SHF_EXCLUDE
        // share: not ELF relevant
        // debug: not ELF relevant
        // large: add SHF_X86_64_LARGE. Fatal error if target is not x86_64
        if (f.alloc) s.header.sh_flags |= std.elf.SHF_ALLOC;
        if (f.contents or f.load) {
            if (s.header.sh_type == std.elf.SHT_NOBITS) s.header.sh_type = std.elf.SHT_PROGBITS;
        }
        if (f.readonly) s.header.sh_flags &= ~@as(@TypeOf(s.header.sh_type), std.elf.SHF_WRITE);
        if (f.code) s.header.sh_flags |= std.elf.SHF_EXECINSTR;
        if (f.exclude) s.header.sh_flags |= std.elf.SHF_EXCLUDE;
        if (f.large) {
            if (elf.e_machine != std.elf.EM.X86_64)
                fatal("zig objcopy: 'large' section flag is only supported on x86_64 targets", .{});
            s.header.sh_flags |= std.elf.SHF_X86_64_LARGE;
        }

        // LLVM:
        // merge: add SHF_MERGE
        // strings: add SHF_STRINGS
        if (f.merge) s.header.sh_flags |= std.elf.SHF_MERGE;
        if (f.strings) s.header.sh_flags |= std.elf.SHF_STRINGS;

        elf.fixup() catch |err| fatal("failed overwriting section flags: {s}", .{@errorName(err)});
    }

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
