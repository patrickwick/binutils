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

pub const SymbolType = enum(u4) {
    notype = std.elf.STT_NOTYPE,
    object = std.elf.STT_OBJECT,
    func = std.elf.STT_FUNC,
    section = std.elf.STT_SECTION,
    file = std.elf.STT_FILE,
    common = std.elf.STT_COMMON,
    tls = std.elf.STT_TLS,
    num = std.elf.STT_NUM,
    gnu_ifunc = std.elf.STT_GNU_IFUNC,

    pub inline fn fromRawType(st_type: u4) @This() {
        return std.meta.intToEnum(@This(), st_type) catch fatal("failed mapping st_type to enum, unexpected value {d}", .{st_type});
    }
};

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

    // TODO: add support for non-native input files
    const SymbolRef = std.elf.Elf64_Sym;
    if (elf.isEndianMismatch()) fatal("input file with non-native endianness is not supported yet", .{});

    if (@sizeOf(SymbolRef) != symbol_table.header.sh_entsize) fatal("unexpected symbol table entry size {d}, expected {d}", .{
        symbol_table.header.sh_entsize,
        @sizeOf(SymbolRef),
    });

    const string_table_section_index = symbol_table.header.sh_link;
    const string_table_section = &elf.sections.items[string_table_section_index];
    const string_table_content = try string_table_section.readContent(input);

    const symbol_entries = std.mem.bytesAsSlice(SymbolRef, symtab_content);
    for (symbol_entries, 0..) |entry, i| {
        const st_type = SymbolType.fromRawType(SymbolRef.st_type(entry));

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
            \\{d} 0x{s} 0x{s} {s} {s}
            \\
        , .{
            i,
            intToHex(@as(u32, @truncate(entry.st_value))),
            intToHex(@as(u32, @truncate(entry.st_size))),
            @tagName(st_type),
            name,
        });
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
        \\  Magic:   {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s}
        \\
    , .{
        intToHex(eb[0]),
        intToHex(eb[1]),
        intToHex(eb[2]),
        intToHex(eb[3]),
        intToHex(eb[4]),
        intToHex(eb[5]),
        intToHex(eb[6]),
        intToHex(eb[7]),
        intToHex(eb[8]),
        intToHex(eb[9]),
        intToHex(eb[10]),
        intToHex(eb[11]),
        intToHex(eb[12]),
        intToHex(eb[13]),
        intToHex(eb[14]),
        intToHex(eb[15]),
    });

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
            var f = [_]u8{' '} ** 3;
            var offset: u8 = 0;

            // sorted according to "Key to Flags" legend
            if (offset < f.len and (h.sh_flags & std.elf.SHF_WRITE) != 0) {
                f[offset] = 'W';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_ALLOC) != 0) {
                f[offset] = 'A';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_EXECINSTR) != 0) {
                f[offset] = 'X';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_MERGE) != 0) {
                f[offset] = 'M';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_STRINGS) != 0) {
                f[offset] = 'S';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_INFO_LINK) != 0) {
                f[offset] = 'I';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_LINK_ORDER) != 0) {
                f[offset] = 'L';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_OS_NONCONFORMING) != 0) {
                f[offset] = 'O';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_GROUP) != 0) {
                f[offset] = 'G';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_TLS) != 0) {
                f[offset] = 'T';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_COMPRESSED) != 0) {
                f[offset] = 'C';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_EXCLUDE) != 0) {
                f[offset] = 'E';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_GNU_RETAIN) != 0) {
                f[offset] = 'R';
                offset += 1;
            }

            if (offset < f.len and (h.sh_flags & std.elf.SHF_X86_64_LARGE) != 0) {
                f[offset] = 'l';
                offset += 1;
            }

            break :flags f;
        };

        try out.print("0x{s} 0x{s} 0x{s} 0x{s} {s}\n", .{
            intToHex(h.sh_addr),
            intToHex(@as(u32, @truncate(h.sh_offset))),
            intToHex(@as(u32, @truncate(h.sh_size))),
            intToHex(@as(u32, @truncate(h.sh_entsize))),
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

inline fn intToHex(data: anytype) [@sizeOf(@TypeOf(data)) * 2]u8 {
    var bytes = std.mem.toBytes(data);
    std.mem.reverse(u8, &bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn verboseFileType(e_type: std.elf.ET) []const u8 {
    return switch (e_type) {
        .NONE => "NONE (None)",
        .REL => "REL (Relocatable file)",
        .EXEC => "EXEC (Executable file)",
        .DYN => "DYN (Position-Independent Executable or Shared Object file)",
        .CORE => "CORE (Core file)",
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
        const h = program_segment.program_header;

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

        try out.print("0x{s} 0x{s} 0x{s} 0x{s} 0x{s}", .{
            intToHex(@as(u32, @truncate(h.p_offset))),
            intToHex(h.p_vaddr),
            intToHex(h.p_paddr),
            intToHex(@as(u32, @truncate(h.p_filesz))),
            intToHex(@as(u32, @truncate(h.p_memsz))),
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

    const elf = .{
        .section_handle_counter = 1,
        .e_ident = .{
            .ei_class = .elfclass64,
            .ei_data = .little,
            .ei_version = .ev_current,
            .ei_osabi = std.elf.OSABI.NONE,
            .ei_abiversion = 0,
        },
        .e_type = std.elf.ET.DYN,
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
