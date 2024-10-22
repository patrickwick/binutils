const std = @import("std");
const builtin = @import("builtin");

const Elf = @import("Elf.zig").Elf;

const FATAL_EXIT_CODE = 1;

pub const ReadElfOptions = struct {
    file_path: []const u8,
    file_header: bool = false,
    section_headers: bool = false,
    program_headers: bool = false,
};

pub fn readelf(allocator: std.mem.Allocator, options: ReadElfOptions) void {
    const out = std.io.getStdOut();

    var file = std.fs.cwd().openFile(options.file_path, .{}) catch |err| fatal("unable to open '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer file.close();

    var elf = Elf.read(allocator, file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer elf.deinit();

    if (options.file_header) printElfHeader(out.writer().any(), &elf) catch |err| fatal("failed writing to output: {s}", .{@errorName(err)});
    if (options.section_headers) printElfSectionHeaders(out.writer().any(), &elf) catch |err| fatal("failed writing to output: {s}", .{@errorName(err)});
    if (options.program_headers) printElfProgramHeaders(out.writer().any(), &elf) catch |err| fatal("failed writing to output: {s}", .{@errorName(err)});
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
        // TODO: add all verbose names
        else => |abi| @tagName(abi),
    };

    // TODO: extract function
    const file_type = switch (elf.e_type) {
        .DYN => "DYN (Position-Independent Executable file)",
        // TODO: add all verbose names
        else => |file_type| @tagName(file_type),
    };

    const machine = switch (elf.e_machine) {
        .X86_64 => "Advanced Micro Devices X86-64",
        // TODO: add all verbose names
        else => |machine| @tagName(machine),
    };

    // TODO: print leading zeroes in hex values for constant width and adapt test
    try out.print(
        \\
        \\ELF Header:
        \\  Magic:   {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x}
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
        file_type,
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
    // TODO: Lk Inf Al
    // try out.writeAll(
    //     \\Type          Address            Offset   Size     ES   Flg Lk Inf Al
    //     \\
    // );
    try out.writeAll(
        \\Type          Address            Offset   Size     ES   Flg
        \\
    );

    for (elf.sections.items, 0..) |*section, i| {
        // TODO: extract function
        const type_name = switch (section.header.sh_type) {
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

        // TODO: extract function for fixed hex format
        var address_bytes = (std.mem.toBytes(@as(u64, section.header.sh_addr))[0..8]).*;
        std.mem.reverse(u8, &address_bytes);
        const address_hex = std.fmt.bytesToHex(address_bytes, .lower);

        // TODO: truncated if 64bit offset is above the 32bit limit
        var offset_bytes = (std.mem.toBytes(section.header.sh_offset)[0..3]).*;
        std.mem.reverse(u8, &offset_bytes);
        const offset_hex = std.fmt.bytesToHex(offset_bytes, .lower);

        var size_bytes = (std.mem.toBytes(section.header.sh_size)[0..3]).*;
        std.mem.reverse(u8, &size_bytes);
        const size_hex = std.fmt.bytesToHex(size_bytes, .lower);

        var entry_size_bytes = (std.mem.toBytes(section.header.sh_entsize)[0..1]).*;
        std.mem.reverse(u8, &entry_size_bytes);
        const entry_size_hex = std.fmt.bytesToHex(entry_size_bytes, .lower);

        // TODO: extract function?
        const flags = flags: {
            var f = [_]u8{' '} ** 3;
            var offset: u8 = 0;

            // sorted according to "Key to Flags" legend
            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_WRITE) != 0) {
                f[offset] = 'W';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_ALLOC) != 0) {
                f[offset] = 'A';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_EXECINSTR) != 0) {
                f[offset] = 'X';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_MERGE) != 0) {
                f[offset] = 'M';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_STRINGS) != 0) {
                f[offset] = 'S';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_INFO_LINK) != 0) {
                f[offset] = 'I';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_LINK_ORDER) != 0) {
                f[offset] = 'L';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_OS_NONCONFORMING) != 0) {
                f[offset] = 'O';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_GROUP) != 0) {
                f[offset] = 'G';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_TLS) != 0) {
                f[offset] = 'T';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_COMPRESSED) != 0) {
                f[offset] = 'C';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_EXCLUDE) != 0) {
                f[offset] = 'E';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_GNU_RETAIN) != 0) {
                f[offset] = 'R';
                offset += 1;
            }

            if (offset < f.len and (section.header.sh_flags & std.elf.SHF_X86_64_LARGE) != 0) {
                f[offset] = 'l';
                offset += 1;
            }

            break :flags f;
        };

        try out.print("0x{s} 0x{s} 0x{s} 0x{s} {s}\n", .{
            address_hex,
            offset_hex,
            size_hex,
            entry_size_hex,
            flags,
        });

        // TODO: links (Lk)
        // TODO: info (Inf)
        // TODO: alignment (Al)
    }

    try out.writeAll(
        \\Key to Flags:
        \\  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
        \\  L (link order), O (extra OS processing required), G (group), T (TLS),
        \\  C (compressed), E (exclude), R (retain), l (large)
        \\
    );
}

fn printElfProgramHeaders(out: std.io.AnyWriter, elf: *const Elf) !void {
    // TODO: extract function
    const file_type = switch (elf.e_type) {
        .DYN => "DYN (Position-Independent Executable file)",
        // TODO: add all verbose names
        else => |file_type| @tagName(file_type),
    };

    try out.print(
        \\
        \\Elf file type is {s}
        \\Entry point 0x{x}
        \\There are {d} program headers, starting at offset {d}
        \\
        \\Program Headers:
        \\Type             Offset   VirtAddr           PhysAddr           FileSiz  MemSiz
        \\
    , .{ file_type, elf.e_entry, elf.e_phnum, elf.e_phoff });

    for (elf.program_segments.items) |program_segment| {
        // TODO: extract function
        const program_header_type = switch (program_segment.program_header.p_type) {
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

        // TODO: extract function for fixed hex format
        var offset_bytes = (std.mem.toBytes(@as(u64, program_segment.program_header.p_offset))[0..3]).*;
        std.mem.reverse(u8, &offset_bytes);
        const offset_hex = std.fmt.bytesToHex(offset_bytes, .lower);

        var virtual_address_bytes = (std.mem.toBytes(@as(u64, program_segment.program_header.p_vaddr))[0..8]).*;
        std.mem.reverse(u8, &virtual_address_bytes);
        const virtual_address_hex = std.fmt.bytesToHex(virtual_address_bytes, .lower);

        var physical_address_bytes = (std.mem.toBytes(@as(u64, program_segment.program_header.p_paddr))[0..8]).*;
        std.mem.reverse(u8, &physical_address_bytes);
        const physical_address_hex = std.fmt.bytesToHex(virtual_address_bytes, .lower);

        var file_size_bytes = (std.mem.toBytes(@as(u64, program_segment.program_header.p_filesz))[0..3]).*;
        std.mem.reverse(u8, &file_size_bytes);
        const file_size_hex = std.fmt.bytesToHex(file_size_bytes, .lower);

        var memory_size_bytes = (std.mem.toBytes(@as(u64, program_segment.program_header.p_memsz))[0..3]).*;
        std.mem.reverse(u8, &memory_size_bytes);
        const memory_size_hex = std.fmt.bytesToHex(memory_size_bytes, .lower);

        try out.print("  {s}", .{program_header_type});
        const indentation = 15;
        try out.writeByteNTimes(' ', @max(indentation, program_header_type.len) - program_header_type.len);
        try out.print(
            "0x{s} 0x{s} 0x{s} 0x{s} 0x{s}",
            .{ offset_hex, virtual_address_hex, physical_address_hex, file_size_hex, memory_size_hex },
        );

        // TODO: program interpreter
        // if (program_segment.program_header.p_type == std.elf.PT_INTERP) {
        //     try out.print(
        //         \\
        //         \\      [Requesting program interpreter: {s}]
        //     , .{"TODO: NYI"});
        // }
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

    // TODO: sections not mapped
    // try out.writeAll("    None  TODO: NYI");
    // try out.writeByte('\n');
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
        \\  Magic:   7f 45 4c 46 2 1 1 0 0 0 0 0 0 0 0 0
        \\  Class:                             ELF64
        \\  Data:                              2's complement, little endian
        \\  Version:                           1 (current)
        \\  OS/ABI:                            UNIX - System V
        \\  ABI Version:                       0
        \\  Type:                              DYN (Position-Independent Executable file)
        \\  Machine:                           Advanced Micro Devices X86-64
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
