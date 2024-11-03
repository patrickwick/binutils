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
    compress_debug_sections: bool = false,
    set_section_alignment: ?SetSectionAlignmentOption = null,
    set_section_flags: ?SetSectionFlagsOption = null,
    add_section: ?AddSectionOption = null,
};

pub const OutputTarget = enum {
    elf,
    // NOTE: does not support other output formats than ELF, see original discussion https://github.com/ziglang/zig/issues/2826
    // raw, // equivalent to gnu objcopy -O binary
    // hex, // Intel hex format (ihex)
};

pub const PadToOption = struct {
    address: u64,
};

pub const AddGnuDebugLinkOption = struct {
    link: []const u8,
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

    // Uses temporary file if input and output are the same then overwrites the input
    const use_temporary_file = std.mem.eql(u8, options.in_file_path, options.out_file_path);
    const out_path = if (use_temporary_file) std.mem.concat(allocator, u8, &.{ options.out_file_path, ".tmp" }) catch |err| fatal(
        "failed reading ELF file '{s}': {s}",
        .{ options.in_file_path, @errorName(err) },
    ) else options.out_file_path;
    defer if (use_temporary_file) allocator.free(out_path);

    var in_file = std.fs.cwd().openFile(options.in_file_path, .{}) catch |err| fatal(
        "unable to open input '{s}': {s}",
        .{ options.in_file_path, @errorName(err) },
    );
    defer in_file.close();

    var elf = Elf.read(allocator, in_file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.in_file_path, @errorName(err) });
    defer elf.deinit();

    var out_file = std.fs.cwd().createFile(out_path, .{
        .read = true,
        .truncate = true,
        .mode = in_file.mode() catch |err| fatal("failed getting input file mode '{s}': {s}", .{ options.in_file_path, @errorName(err) }),
    }) catch |err| fatal(
        "failed creating output '{s}': {s}",
        .{ out_path, @errorName(err) },
    );
    defer out_file.close();

    // -O, --output_target
    switch (options.output_target) {
        .elf => {},
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

        const sorted = elf.getSortedSectionPointersAlloc(allocator) catch |err| fatal("failed sorting sections: {s}", .{@errorName(err)});
        defer sorted.deinit();

        std.debug.assert(sorted.items.len > 0);
        const section = sorted.items[sorted.items.len - 1];
        const current_end = section.header.sh_offset + section.header.sh_size;
        if (pad_to.address > current_end) {
            const old_content = section.readContent(in_file) catch |err| fatal(
                "failed reading section content of '{s}': {s}",
                .{ elf.getSectionName(section), @errorName(err) },
            );

            const new_size = pad_to.address - section.header.sh_offset;
            var new_content = allocator.realloc(old_content, new_size) catch |err| fatal(
                "failed reallocating section content of '{s}' from {d} to {d} bytes: {s}",
                .{ elf.getSectionName(section), old_content.len, new_size, @errorName(err) },
            );
            @memset(new_content[old_content.len..], 0);

            elf.updateSectionContent(in_file, section.handle, new_content) catch |err| fatal(
                "failed updating section content of '{s}': {s}",
                .{ elf.getSectionName(section), @errorName(err) },
            );
        } else {
            std.log.info("section end 0x{x} already exceeds address 0x{x}", .{ current_end, pad_to.address });
        }
    }

    // -g, --strip-debug
    if (options.strip_debug) {
        // double loop since iteration needs to be restarted on modified array
        while (true) {
            // skip null section
            for (elf.sections.items[1..]) |*section| {
                if (!elf.isDebugSection(section)) continue;

                const name = elf.getSectionName(section);

                // TODO: check if any kept section links to this section transitively
                // => sh_link, sh_info

                std.log.debug("stripping debug section '{s}'", .{name});
                elf.removeSection(section.handle) catch |err| fatal("failed removing section '{s}': {s}", .{ name, @errorName(err) });
                break; // restart iteration after modification
            } else break;
        }

        elf.compact() catch |err| fatal("failed compacting ELF file: {s}", .{@errorName(err)});
    }

    // -S, --strip-all
    if (options.strip_all) {
        // double loop since iteration needs to be restarted on modified array
        while (true) {
            // skip null section
            for (elf.sections.items[1..], 1..) |*section, i| {
                // keep section header string table
                if (i == elf.e_shstrndx) continue;

                // keep mapped
                const is_mapped = mapped: for (elf.program_segments.items) |segment| {
                    for (segment.segment_mapping.items) |handle| if (section.handle == handle) break :mapped true;
                } else false;
                if (is_mapped) continue;

                const name = elf.getSectionName(section);

                // keep .comment and debug link sections
                // NOTE: please let me know if there is a more general rule for this.
                switch (section.header.sh_type) {
                    std.elf.SHT_PROGBITS => {
                        if (std.mem.eql(u8, name, ".comment")) continue;
                        if (std.mem.eql(u8, name, ".gnu_debuglink")) continue;
                        if (std.mem.eql(u8, name, ".gnu_debugaltlink")) continue;
                        if (std.mem.eql(u8, name, ".debug_sup")) continue;
                    },
                    else => {},
                }

                // TODO: check if any kept section links to this section transitively
                // => sh_link, sh_info

                std.log.debug("stripping section '{s}'", .{name});
                elf.removeSection(section.handle) catch |err| fatal("failed removing section '{s}': {s}", .{ name, @errorName(err) });
                break; // restart iteration after modification
            } else break;
        }

        elf.compact() catch |err| fatal("failed compacting ELF file: {s}", .{@errorName(err)});
    }

    // --only-keep-debug
    if (options.only_keep_debug) {
        if (options.strip_all) fatal("cannot use --only-keep-debug in combination with --strip-all", .{});
        if (options.strip_debug) fatal("cannot use --only-keep-debug in combination with --strip-debug", .{});

        // double loop since iteration needs to be restarted on modified array
        while (true) {
            // skip null section
            for (elf.sections.items[1..]) |*section| {
                if (elf.isDebugSection(section)) continue;

                const name = elf.getSectionName(section);

                // keep symbol and string tables
                switch (section.header.sh_type) {
                    std.elf.SHT_SYMTAB, std.elf.SHT_STRTAB => continue,
                    else => {},
                }

                // TODO: check if any kept section links to this section transitively
                // => sh_link, sh_info

                std.log.debug("stripping non-debug section '{s}'", .{name});
                elf.removeSection(section.handle) catch |err| fatal("failed removing section '{s}': {s}", .{ name, @errorName(err) });
                break; // restart iteration after modification
            } else break;
        }

        elf.compact() catch |err| fatal("failed compacting ELF file: {s}", .{@errorName(err)});
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
        const crc_offset = std.mem.alignForward(usize, link.len + 1, Elf.SECTION_ALIGN);
        const link_content = allocator.alignedAlloc(u8, Elf.SECTION_ALIGN, crc_offset + crc_bytes.len) catch |err| fatal(
            "failed allocating debuglink section content: {s}",
            .{@errorName(err)},
        );
        @memcpy(link_content[0..link.len], link);
        @memset(link_content[link.len..crc_offset], 0);
        @memcpy(link_content[crc_offset..], &crc_bytes);

        const name = ".gnu_debuglink";
        if (elf.getSectionByName(name)) |section| {
            elf.updateSectionContent(in_file, section.handle, link_content) catch |err| fatal(
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

    // --compress-debug-sections
    if (options.compress_debug_sections) {
        for (elf.sections.items) |*section| {
            if (!elf.isDebugSection(section)) continue;

            const name = elf.getSectionName(section);

            if ((section.header.sh_flags & std.elf.SHF_COMPRESSED) != 0) {
                std.log.debug("Skipping already compresed debug section: '{s}'", .{name});
                continue;
            }

            const content = section.readContent(in_file) catch |err| fatal(
                "failed reading uncompressed section content from '{s}': {s}",
                .{ name, @errorName(err) },
            );

            // only compress if the compressed data is smaller than the input data
            var compressed = allocator.alignedAlloc(u8, Elf.SECTION_ALIGN, content.len + @sizeOf(std.elf.Chdr)) catch |err| fatal(
                "failed allocating buffer for compression of size '{d}': {s}",
                .{ content.len, @errorName(err) },
            );

            var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = content, .pos = 0 };
            var out_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = compressed, .pos = 0 };

            std.log.debug("compressing debug section '{s}'", .{name});
            switch (elf.e_ident.ei_class) {
                inline else => |class| {
                    const CompressionHeader = if (class == .elfclass64) std.elf.Elf64_Chdr else std.elf.Elf32_Chdr;

                    out_buffer_stream.writer().writeStructEndian(CompressionHeader{
                        .ch_type = .ZLIB,
                        .ch_size = @intCast(content.len), // uncompressed size
                        .ch_addralign = @intCast(section.header.sh_addralign), // uncompressed alignment
                    }, elf.e_ident.ei_data) catch |err| fatal(
                        "failed writing section compression header '{s}': {s}",
                        .{ name, @errorName(err) },
                    );

                    std.compress.zlib.compress(in_buffer_stream.reader(), out_buffer_stream.writer(), .{}) catch |err| fatal(
                        "failed compressing section content '{s}': {s}",
                        .{ name, @errorName(err) },
                    );

                    if (out_buffer_stream.pos >= content.len) {
                        std.log.debug("skipped compressing section '{s}' since size was not reduced", .{name});
                        continue;
                    }

                    // reduce buffer size to what was actually required
                    compressed = allocator.realloc(compressed, out_buffer_stream.pos) catch |err| fatal(
                        "failed reducing compressed buffer size from {d} to {d} for section '{s}': {s}",
                        .{ compressed.len, out_buffer_stream.pos, name, @errorName(err) },
                    );
                    std.log.debug("compressed section '{s}' from {d} to {d} bytes", .{ name, content.len, compressed.len });

                    section.header.sh_flags |= std.elf.SHF_COMPRESSED;
                    section.header.sh_size = compressed.len;

                    elf.updateSectionContent(in_file, section.handle, compressed) catch |err| fatal(
                        "failed updating section content '{s}': {s}",
                        .{ name, @errorName(err) },
                    );
                },
            }
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

        elf.updateSectionAlignment(in_file, section.handle, set_section_alignment.alignment) catch |err| fatal(
            "failed overwriting section alignment: {s}",
            .{@errorName(err)},
        );
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
    }

    // --add-section
    if (options.add_section) |add_section| {
        var add_section_input = std.fs.cwd().openFile(add_section.file_path, .{}) catch |err| fatal(
            "unable to open add-section input '{s}': {s}",
            .{ options.in_file_path, @errorName(err) },
        );
        defer add_section_input.close();

        const content = add_section_input.readToEndAllocOptions(
            allocator,
            std.math.maxInt(usize),
            null,
            Elf.SECTION_ALIGN,
            null,
        ) catch |err| fatal(
            "failed reading add-sectipn input '{s}': {s}",
            .{ options.in_file_path, @errorName(err) },
        );
        defer allocator.free(content);

        elf.addSection(in_file, add_section.section_name, content) catch |err| fatal(
            "failed adding new section '{s}': {s}",
            .{ add_section.section_name, @errorName(err) },
        );
    }

    std.log.debug("writing ELF output to '{s}'", .{out_path});
    elf.write(in_file, out_file) catch |err| fatal(
        "failed writing output '{s}': {s}",
        .{ out_path, @errorName(err) },
    );

    if (use_temporary_file) {
        std.fs.cwd().rename(out_path, options.in_file_path) catch |err| fatal(
            "failed overwriting input file '{s}' with temporary result '{s}': {s}",
            .{ options.in_file_path, out_path, @errorName(err) },
        );
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils objcopy";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    if (builtin.mode == .Debug) testing.printStackTrace(@returnAddress());
    std.process.exit(FATAL_EXIT_CODE);
}
