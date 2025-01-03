const std = @import("std");
const builtin = @import("builtin");

const Elf = @import("Elf.zig").Elf;

const FATAL_EXIT_CODE = 1;

pub const ReadElfOptions = struct {
    file_path: []const u8,
    file_header: bool = false,
    section_headers: bool = false,
    program_headers: bool = false,
    symbols: bool = false,
};

pub fn readelf(allocator: std.mem.Allocator, options: ReadElfOptions) void {
    const out = std.io.getStdOut();

    var file = std.fs.cwd().openFile(options.file_path, .{}) catch |err| fatal("unable to open '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer file.close();

    var elf = Elf.read(allocator, file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer elf.deinit();

    if (options.file_header) printElfHeader(out.writer().any(), &elf) catch |err| fatal("failed printing ELF header: {s}", .{@errorName(err)});
    if (options.section_headers) printElfSectionHeaders(out.writer().any(), &elf) catch |err| fatal("failed printing ELF section headers: {s}", .{@errorName(err)});
    if (options.program_headers) printElfProgramHeaders(file, out.writer().any(), &elf) catch |err| fatal("failed printing program headers: {s}", .{@errorName(err)});
    if (options.symbols) printSymbols(file, out.writer().any(), &elf) catch |err| fatal("failed printing symbol table: {s}", .{@errorName(err)});
}

fn printSymbolTable(symbol_table: *Elf.Section, input: std.fs.File, out: std.io.AnyWriter, elf: *const Elf) !void {
    const symbol_count = std.math.divExact(usize, symbol_table.header.sh_size, symbol_table.header.sh_entsize) catch fatal(
        "Symbol table size {d} is not divisble by entry size {d}",
        .{ symbol_table.header.sh_size, symbol_table.header.sh_entsize },
    );

    const symtab_content = try symbol_table.readContent(input);

    const section_name = elf.getSectionName(symbol_table);
    try out.print(
        \\Symbol table '{s}' contains {d} entries:
        \\   Num:    Value          Size Type    Bind   Vis      Ndx Name
        \\
    , .{ section_name, symbol_count });

    switch (elf.e_ident.ei_class) {
        inline else => |class| {
            const SymbolRef = if (class == .elfclass64) std.elf.Elf64_Sym else std.elf.Elf32_Sym;

            if (@sizeOf(SymbolRef) != symbol_table.header.sh_entsize) fatal("unexpected symbol table entry size {d}, expected {d}", .{
                symbol_table.header.sh_entsize,
                @sizeOf(SymbolRef),
            });

            const string_table_section_index = symbol_table.header.sh_link;
            const string_table_section = &elf.sections.items[string_table_section_index];
            const string_table_content = try string_table_section.readContent(input);

            const symbol_entries = std.mem.bytesAsSlice(SymbolRef, symtab_content);
            for (symbol_entries, 0..) |entry_raw, i| {
                var entry = entry_raw;
                if (elf.isEndianMismatch()) std.mem.byteSwapAllFields(SymbolRef, &entry);

                const st_type = Elf.SymbolType.fromRawType(SymbolRef.st_type(entry));

                const name = name: {
                    switch (st_type) {
                        .notype => break :name "",
                        .section => break :name elf.getSectionName(&elf.sections.items[entry.st_shndx]),
                        else => {},
                    }
                    if (entry.st_name == 0) break :name "";
                    break :name std.mem.span(@as([*:0]const u8, @ptrCast(&string_table_content[entry.st_name])));
                };

                try out.print(
                    \\{d} 0x{x:0>8} 0x{x:0>8} {s} {s}
                    \\
                , .{
                    i,
                    @as(u32, @truncate(entry.st_value)),
                    @as(u32, @truncate(entry.st_size)),
                    @tagName(st_type),
                    name,
                });
            }
        },
    }
}

fn printSymbols(input: std.fs.File, out: std.io.AnyWriter, elf: *const Elf) !void {
    for (elf.sections.items) |*section| {
        if (section.header.sh_type == std.elf.SHT_SYMTAB) try printSymbolTable(section, input, out, elf);
    } else try out.print("ELF input does not contain any symbol table SHT_SYMTAB section", .{});
}

fn printElfHeader(out: std.io.AnyWriter, elf: *const Elf) !void {
    const eb = elf.e_ident.toBuffer();

    const class = switch (elf.e_ident.ei_class) {
        .elfclass64 => "ELF64",
        .elfclass32 => "ELF32",
    };

    const data = switch (elf.e_ident.ei_data) {
        .little => "2's complement, little endian",
        .big => "2's complement, big endian",
    };

    const version = switch (elf.e_ident.ei_version) {
        .ev_current => "1 (current)",
    };

    const os_abi = switch (elf.e_ident.ei_osabi) {
        .NONE => "UNIX - System V",
        .HPUX => "UNIX - HP-UX",
        .NETBSD => "UNIX - NetBSD",
        .GNU => "UNIX - GNU",
        .SOLARIS => "UNIX - Solaris",
        .AIX => "UNIX - AIX",
        .IRIX => "UNIX - IRIX",
        .FREEBSD => "UNIX - FreeBSD",
        .TRU64 => "UNIX - TRU64",
        .MODESTO => "Novell - Modesto",
        .OPENBSD => "UNIX - OpenBSD",
        .OPENVMS => "VMS - OpenVMS",
        .NSK => "HP - Non-Stop Kernel",
        .AROS => "AROS",
        .FENIXOS => "FenixOS",
        .CLOUDABI => "Nuxi CloudABI",
        .OPENVOS => "Stratus Technologies OpenVOS",
        .CUDA => "CUDA",
        else => |abi| @tagName(abi),
    };

    // there are too many to map manually
    const machine = @tagName(elf.e_machine);

    try out.print(
        \\
        \\ELF Header:
        \\  Magic:   {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}
        \\
    , .{ eb[0], eb[1], eb[2], eb[3], eb[4], eb[5], eb[6], eb[7], eb[8], eb[9], eb[10], eb[11], eb[12], eb[13], eb[14], eb[15] });

    try out.print(
        \\  Class:                             {s}
        \\  Data:                              {s}
        \\  Version:                           {s}
        \\  OS/ABI:                            {s}
        \\  ABI Version:                       {d}
        \\  Type:                              {s}
        \\  Machine:                           {s}
        \\  Version:                           0x{x}
        \\  Entry point address:               0x{x}
        \\  Start of program headers:          {d} (bytes into file)
        \\  Start of section headers:          {d} (bytes into file)
        \\  Flags:                             0x{x}
        \\  Size of this header:               {d} (bytes)
        \\  Size of program headers:           {d} (bytes)
        \\  Number of program headers:         {d}
        \\  Size of section headers:           {d} (bytes)
        \\  Number of section headers:         {d}
        \\  Section header string table index: {d}
        \\
    , .{
        class,
        data,
        version,
        os_abi,
        elf.e_ident.ei_abiversion,
        verboseFileType(elf.e_type),
        machine,
        @intFromEnum(elf.e_version),
        elf.e_entry,
        elf.e_phoff,
        elf.e_shoff,
        elf.e_flags,
        elf.e_ehsize,
        elf.e_phentsize,
        elf.e_phnum,
        elf.e_shentsize,
        elf.e_shnum,
        elf.e_shstrndx,
    });
}

fn printElfSectionHeaders(out: std.io.AnyWriter, elf: *const Elf) !void {
    try out.print(
        \\
        \\There are {d} section headers, starting at offset 0x{x}
        \\
        \\
    , .{ elf.sections.items.len, elf.e_shoff });

    const indentation = indentation: {
        var longest_name: usize = 0;
        for (elf.sections.items) |*section| longest_name = @max(longest_name, elf.getSectionName(section).len);
        break :indentation longest_name;
    };

    try out.writeAll(
        \\Section Headers:
        \\  [Nr] Name
    );
    const correction = 3;
    try out.writeByteNTimes(' ', @max(correction, indentation) - correction);
    try out.writeAll(
        \\Type          Address            Offset     Size       ES         Flg
        \\
    );

    for (elf.sections.items, 0..) |*section, i| {
        const h = section.header;

        const type_name = switch (h.sh_type) {
            std.elf.SHT_NULL => "NULL",
            std.elf.SHT_PROGBITS => "PROGBITS",
            std.elf.SHT_SYMTAB => "SYMTAB",
            std.elf.SHT_STRTAB => "STRTAB",
            std.elf.SHT_RELA => "RELA",
            std.elf.SHT_HASH => "HASH",
            std.elf.SHT_DYNAMIC => "DYNAMIC",
            std.elf.SHT_NOTE => "NOTE",
            std.elf.SHT_NOBITS => "NOBITS",
            std.elf.SHT_REL => "REL",
            std.elf.SHT_SHLIB => "SHLIB",
            std.elf.SHT_DYNSYM => "DYNSYM",
            std.elf.SHT_INIT_ARRAY => "INIT_ARRAY",
            std.elf.SHT_FINI_ARRAY => "FINI_ARRAY",
            std.elf.SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
            std.elf.SHT_GROUP => "GROUP",
            std.elf.SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
            std.elf.SHT_LOOS => "LOOS",
            std.elf.SHT_LLVM_ADDRSIG => "LLVM_ADDRSIG",
            std.elf.SHT_GNU_HASH => "GNU_HASH",
            std.elf.SHT_GNU_VERDEF => "GNU_VERDEF",
            std.elf.SHT_GNU_VERNEED => "GNU_VERNEED",
            std.elf.SHT_GNU_VERSYM => "GNU_VERSYM",
            std.elf.SHT_LOPROC => "LOPROC",
            std.elf.SHT_X86_64_UNWIND => "X86_64_UNWIND",
            std.elf.SHT_HIPROC => "HIPROC",
            std.elf.SHT_LOUSER => "LOUSER",
            std.elf.SHT_HIUSER => "HIUSER",
            else => "INVALID",
        };

        const section_name = elf.getSectionName(section);
        try out.print("  [{s}{d}] {s} ", .{ if (i < 10) " " else "", i, section_name });
        try out.writeByteNTimes(' ', indentation - section_name.len);
        try out.writeAll(type_name);
        const type_indentation = 14;
        try out.writeByteNTimes(' ', type_indentation - type_name.len);

        const flags = flags: {
            const MAX_FLAGS = 3;

            const Flags = struct {
                f: [MAX_FLAGS]u8,
                offset: u8,

                fn insert(self: *@This(), flag: u8) void {
                    if (self.offset >= self.f.len) return;
                    self.f[self.offset] = flag;
                    self.offset += 1;
                }
            };
            var flags = Flags{
                .f = [_]u8{' '} ** 3,
                .offset = 0,
            };

            // sorted according to "Key to Flags" legend
            if ((h.sh_flags & std.elf.SHF_WRITE) != 0) flags.insert('W');
            if ((h.sh_flags & std.elf.SHF_ALLOC) != 0) flags.insert('A');
            if ((h.sh_flags & std.elf.SHF_EXECINSTR) != 0) flags.insert('X');
            if ((h.sh_flags & std.elf.SHF_MERGE) != 0) flags.insert('M');
            if ((h.sh_flags & std.elf.SHF_STRINGS) != 0) flags.insert('S');
            if ((h.sh_flags & std.elf.SHF_INFO_LINK) != 0) flags.insert('I');
            if ((h.sh_flags & std.elf.SHF_LINK_ORDER) != 0) flags.insert('L');
            if ((h.sh_flags & std.elf.SHF_OS_NONCONFORMING) != 0) flags.insert('O');
            if ((h.sh_flags & std.elf.SHF_GROUP) != 0) flags.insert('G');
            if ((h.sh_flags & std.elf.SHF_TLS) != 0) flags.insert('T');
            if ((h.sh_flags & std.elf.SHF_COMPRESSED) != 0) flags.insert('C');
            if ((h.sh_flags & std.elf.SHF_EXCLUDE) != 0) flags.insert('E');
            if ((h.sh_flags & std.elf.SHF_GNU_RETAIN) != 0) flags.insert('R');
            if ((h.sh_flags & std.elf.SHF_X86_64_LARGE) != 0) flags.insert('l');
            break :flags flags.f;
        };

        try out.print("0x{x:0>16} 0x{x:0>8} 0x{x:0>8} 0x{x:0>8} {s}\n", .{
            h.sh_addr,
            @as(u32, @truncate(h.sh_offset)),
            @as(u32, @truncate(h.sh_size)),
            @as(u32, @truncate(h.sh_entsize)),
            flags,
        });
    }

    try out.writeAll(
        \\Key to Flags:
        \\  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
        \\  L (link order), O (extra OS processing required), G (group), T (TLS),
        \\  C (compressed), E (exclude), R (retain), l (large)
        \\
    );
}

fn verboseFileType(e_type: Elf.Type) []const u8 {
    return switch (e_type) {
        .none => "NONE (None)",
        .relocatable => "REL (Relocatable file)",
        .executable => "EXEC (Executable file)",
        .dynamic => "DYN (Position-Independent Executable or Shared Object file)",
        .core => "CORE (Core file)",
        else => "Unknown Type",
    };
}

fn printElfProgramHeaders(in: anytype, out: std.io.AnyWriter, elf: *const Elf) !void {
    try out.print(
        \\
        \\Elf file type is {s}
        \\Entry point 0x{x}
        \\There are {d} program headers, starting at offset {d}
        \\
        \\Program Headers:
        \\Type             Offset     VirtAddr           PhysAddr           FileSiz    MemSiz
        \\
    , .{ verboseFileType(elf.e_type), elf.e_entry, elf.e_phnum, elf.e_phoff });

    for (elf.program_segments.items) |program_segment| {
        const h = program_segment.header;

        const program_header_type = switch (h.p_type) {
            std.elf.PT_NULL => "NULL",
            std.elf.PT_LOAD => "LOAD",
            std.elf.PT_DYNAMIC => "DYNAMIC",
            std.elf.PT_INTERP => "INTERP",
            std.elf.PT_NOTE => "NOTE",
            std.elf.PT_SHLIB => "SHLIB",
            std.elf.PT_PHDR => "PHDR",
            std.elf.PT_TLS => "TLS",
            std.elf.PT_NUM => "NUM",
            std.elf.PT_LOOS => "LOOS",
            std.elf.PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            std.elf.PT_GNU_STACK => "GNU_STACK",
            std.elf.PT_GNU_RELRO => "GNU_RELRO",
            std.elf.PT_SUNWBSS => "SUNWBSS",
            std.elf.PT_SUNWSTACK => "SUNWSTACK",
            else => "UNKNOWN",
        };

        try out.print("  {s}", .{program_header_type});
        const indentation = 15;
        try out.writeByteNTimes(' ', @max(indentation, program_header_type.len) - program_header_type.len);

        try out.print("0x{x:0>8} 0x{x:0>16} 0x{x:0>16} 0x{x:0>8} 0x{x:0>8}", .{
            @as(u32, @truncate(h.p_offset)),
            h.p_vaddr,
            h.p_paddr,
            @as(u32, @truncate(h.p_filesz)),
            @as(u32, @truncate(h.p_memsz)),
        });

        if (h.p_type == std.elf.PT_INTERP) {
            for (program_segment.segment_mapping.items, 0..) |mapping, i| {
                const section = elf.getSection(mapping) orelse fatal(
                    "corrupt section to segment mapping: segment {d} references non existing section handle {d}",
                    .{ i, mapping },
                );

                const content = section.readContent(in) catch |err| fatal(
                    "failed reading '{s}' section content: {s}",
                    .{ elf.getSectionName(section), @errorName(err) },
                );

                try out.print(
                    \\
                    \\    [Requesting program interpreter: {s}]
                , .{content});
            }
        }
        try out.writeByte('\n');
    }

    try out.writeAll(
        \\
        \\Section to Segment mapping:
        \\  Segment Sections...
        \\
    );

    for (elf.program_segments.items, 0..) |program_segment, i| {
        try out.print("    {s}{d}    ", .{ if (i < 10) "0" else "", i });
        for (program_segment.segment_mapping.items) |mapping| {
            const section = elf.getSection(mapping) orelse fatal(
                "corrupt section to segment mapping: segment {d} references non existing section handle {d}",
                .{ i, mapping },
            );
            const name = elf.getSectionName(section);
            if (name.len > 0) try out.print("{s} ", .{name});
        }
        try out.writeByte('\n');
    }

    // sections not mapped
    try out.writeAll("    None  ");
    for (elf.sections.items) |*section| {
        const is_mapped = mapped: for (elf.program_segments.items) |segment| {
            for (segment.segment_mapping.items) |handle| if (section.handle == handle) break :mapped true;
        } else false;

        if (!is_mapped) {
            const name = elf.getSectionName(section);
            if (name.len > 0) try out.print("{s} ", .{name});
        }
    }
    try out.writeByte('\n');
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils readelf";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    std.process.exit(FATAL_EXIT_CODE);
}

const t = std.testing;

test printElfHeader {
    const expected =
        \\
        \\ELF Header:
        \\  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
        \\  Class:                             ELF64
        \\  Data:                              2's complement, little endian
        \\  Version:                           1 (current)
        \\  OS/ABI:                            UNIX - System V
        \\  ABI Version:                       0
        \\  Type:                              DYN (Position-Independent Executable or Shared Object file)
        \\  Machine:                           X86_64
        \\  Version:                           0x1
        \\  Entry point address:               0x128
        \\  Start of program headers:          64 (bytes into file)
        \\  Start of section headers:          800 (bytes into file)
        \\  Flags:                             0x0
        \\  Size of this header:               64 (bytes)
        \\  Size of program headers:           56 (bytes)
        \\  Number of program headers:         0
        \\  Size of section headers:           64 (bytes)
        \\  Number of section headers:         2
        \\  Section header string table index: 1
        \\
    ;

    var out_buffer = [_]u8{0} ** (expected.len * 2);
    var out_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &out_buffer, .pos = 0 };

    const elf = Elf{
        .section_handle_counter = 1,
        .e_ident = .{
            .ei_class = .elfclass64,
            .ei_data = .little,
            .ei_version = .ev_current,
            .ei_osabi = .NONE,
            .ei_abiversion = 0,
        },
        .e_type = .dynamic,
        .e_machine = std.elf.EM.X86_64,
        .e_version = .ev_current,
        .e_entry = 0x128,
        .e_phoff = 64,
        .e_shoff = 800,
        .e_flags = 0,
        .e_ehsize = @sizeOf(std.elf.Ehdr),
        .e_phentsize = @sizeOf(std.elf.Phdr),
        .e_phnum = 0,
        .e_shentsize = @sizeOf(std.elf.Shdr),
        .e_shnum = 2,
        .e_shstrndx = 1,
        .sections = Elf.Sections.init(t.allocator),
        .program_segments = Elf.ProgramSegments.init(t.allocator),
        .allocator = t.allocator,
    };
    try printElfHeader(out_buffer_stream.writer().any(), &elf);

    try t.expectEqualStrings(expected, out_buffer[0..expected.len]);
}
