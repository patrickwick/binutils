const std = @import("std");
const builtin = @import("builtin");

const Section = @import("Section.zig").Section;
const ProgramSegment = @import("ProgramSegment.zig").ProgramSegment;

const FATAL_EXIT_CODE = 1;

/// Stores ELF information in native endianess and provides helpers for modifications and converting the file back to target endianness.
pub const Elf = @This();

pub const Version = enum(u8) {
    ev_current = 1,
};

/// ELF header e_ident fields of interest.
/// Each field has the size of a single byte, so endianness does not matter.
pub const EIdent = struct {
    pub const Class = enum(u8) {
        elfclass32 = std.elf.ELFCLASS32,
        elfclass64 = std.elf.ELFCLASS64,
    };

    pub const AbiVersion = u8;

    ei_class: Class,
    ei_data: std.builtin.Endian,

    // ELF specification version
    ei_version: Version,
    ei_osabi: std.elf.OSABI,
    ei_abiversion: AbiVersion,

    pub fn toBuffer(self: *const @This()) [std.elf.EI_NIDENT]u8 {
        const e_ident_buffer = std.elf.MAGIC // EI_MAG0-3
        ++ [_]u8{@intFromEnum(self.ei_class)} // EI_CLASS
        ++ [_]u8{@intFromEnum(self.ei_data)} // EI_DATA
        ++ [_]u8{@intFromEnum(self.ei_version)} // EI_VERSION
        ++ [_]u8{@intFromEnum(self.ei_osabi)} // EI_OSABI
        ++ [_]u8{self.ei_abiversion} // EI_ABIVERSION
        ++ [_]u8{0} ** 7; // EI_PAD
        return e_ident_buffer.*;
    }
};

comptime {
    // TODO: verify that each field is a byte in size => important if source endianess does not match native endianness
}

pub const Sections = std.ArrayList(Section);
pub const ProgramSegments = std.ArrayList(ProgramSegment);

e_ident: EIdent,

e_type: std.elf.ET,

e_machine: std.elf.EM,

// ELF file version
e_version: Version,

// Entry point address
e_entry: usize,

// Program header offset
e_phoff: usize,

// Section header offset
e_shoff: usize,
e_flags: usize, // TODO: add bitfield

// ELF header size
e_ehsize: usize,

// Program header size
e_phentsize: usize,

// Program header entry count
e_phnum: usize,

// Sectipn header size
e_shentsize: usize,

// Section header entry count
e_shnum: usize,

// Section header name string table section index
e_shstrndx: usize,

sections: Sections,
program_segments: ProgramSegments,

allocator: std.mem.Allocator,

pub fn deinit(self: *@This()) void {
    for (self.sections.items) |section| self.allocator.free(section.name);
    self.sections.deinit();
    self.program_segments.deinit();
}

pub fn addSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

pub fn removeSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

pub fn write(self: *@This(), allocator: std.mem.Allocator, source: anytype, target: anytype) !void {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(target), "writer"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(target), "seekableStream"));

    const writer = target.writer();
    const out_stream = target.seekableStream();

    var header = std.elf.Ehdr{
        .e_ident = self.e_ident.toBuffer(),
        .e_type = self.e_type,
        .e_machine = self.e_machine,
        .e_version = @intFromEnum(Version.ev_current),
        .e_entry = @intCast(self.e_entry),
        .e_phoff = @intCast(self.e_phoff),
        .e_shoff = @intCast(self.e_shoff),
        .e_flags = @intCast(self.e_flags),
        .e_ehsize = @intCast(self.e_ehsize),
        .e_phentsize = @intCast(self.e_phentsize),
        .e_phnum = @intCast(self.e_phnum),
        .e_shentsize = @intCast(self.e_shentsize),
        .e_shnum = @intCast(self.e_shnum),
        .e_shstrndx = @intCast(self.e_shstrndx),
    };

    const output_endianness = self.e_ident.ei_data;

    // convert endianness if output and native endianness do not match
    if (output_endianness != builtin.target.cpu.arch.endian()) std.mem.byteSwapAllFields(std.elf.Ehdr, &header);

    try out_stream.seekTo(0);
    try writer.writeStruct(header);

    // TODO: perform validation that header, section header, program headers and section content regions don't overlap

    // section headers
    try out_stream.seekTo(self.e_shoff);
    for (self.sections.items) |section| {
        try writer.writeStruct(section.toShdr(output_endianness));
    }

    // program headers
    try out_stream.seekTo(self.e_phoff);
    for (self.program_segments.items) |program_segment| {
        try writer.writeStruct(program_segment.program_header);
    }

    // section content
    for (self.sections.items) |section| {
        switch (section.content) {
            .data => |data| {
                try out_stream.seekTo(section.header.sh_offset);
                try writer.writeAll(data);
            },
            .no_bits => {},
            .input_file_range => |range| {
                const data = section.readContentAlloc(source, allocator) catch |err| {
                    std.log.err("failed reading '{s}' section content at 0x{x} of size 0x{x} ({d}): {}", .{
                        section.name,
                        range.offset,
                        range.size,
                        range.size,
                        err,
                    });
                    return err;
                };
                defer allocator.free(data);

                try out_stream.seekTo(section.header.sh_offset);
                try writer.writeAll(data);
            },
        }
    }
}

pub fn readFromFile(path: []const u8) !@This() {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try read(file);
}

pub fn read(allocator: std.mem.Allocator, source: anytype) !@This() {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "reader"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "seekableStream"));

    // not all e_ident fields are stored in the parsed std.elf.Header but are required to emit the new header
    var e_ident: [std.elf.EI_NIDENT]u8 = undefined;
    try source.seekableStream().seekTo(0);
    const bytes_read = try source.reader().readAll(&e_ident);
    if (bytes_read < std.elf.EI_NIDENT) return error.TruncatedElf;

    // NOTE: ei_version is the specification version while e_version is the file version
    const ei_version = std.meta.intToEnum(Version, e_ident[std.elf.EI_VERSION]) catch return error.UnrecognizedElfVersion;
    const e_version = .ev_current;

    const header = try std.elf.Header.read(source);

    const string_table_section = shstrtab: {
        // NOTE: iterator already accounts for endianess, so it always has native endianness
        var section_it = header.section_header_iterator(source);
        var i: usize = 0;
        while (try section_it.next()) |section| : (i += 1) {
            if (i == header.shstrndx) {
                if (!isStringTable(section)) fatal(
                    "section type of section name string table must be SHT_STRTAB 0x{x}, got 0x{x}",
                    .{ std.elf.SHT_STRTAB, section.sh_type },
                );

                break :shstrtab Section{
                    .name = ".shstrtab", // TODO: use name from shstrtab itself instead of hardcoding it
                    .header = section,
                    .content = .{ .input_file_range = .{ .offset = section.sh_offset, .size = section.sh_size } },
                };
            }
        }
        fatal("input ELF file does not contain a string table section (usually .shstrtab)", .{});
    };
    const string_table_content = try string_table_section.readContentAlloc(source, allocator);
    defer allocator.free(string_table_content);

    var sections = Sections.init(allocator);
    errdefer sections.deinit();
    {
        var section_it = header.section_header_iterator(source);
        while (try section_it.next()) |section| {
            if (section.sh_name >= string_table_content.len)
                fatal("invalid ELF input file: section name offset {d} exceeds strtab size {d}", .{ section.sh_name, string_table_content.len });

            // TODO: extract function
            // name is always copied, so the string table content can be free'd
            const name_source = std.mem.span(@as([*:0]const u8, @ptrCast(&string_table_content[section.sh_name])));
            const name = try allocator.dupe(u8, name_source);

            const content: Section.ContentSource = if (isSectionInFile(section)) .{
                .input_file_range = .{
                    .offset = section.sh_offset,
                    .size = section.sh_size,
                },
            } else .{
                .no_bits = .{
                    .offset = section.sh_offset,
                    .size = section.sh_size,
                },
            };

            try sections.append(.{
                .name = name,
                .header = section,
                .content = content,
            });
        }
    }

    // TODO: section to segment mapping
    // => represent it via handles, not file offsets to have stability again section relocation
    var program_segments = ProgramSegments.init(allocator);
    errdefer program_segments.deinit();
    var program_it = header.program_header_iterator(source);
    while (try program_it.next()) |program_header| {
        try program_segments.append(.{ .program_header = program_header });
    }

    return .{
        .e_ident = .{
            .ei_class = if (header.is_64) .elfclass64 else .elfclass32,
            .ei_data = header.endian,
            .ei_version = ei_version,
            .ei_osabi = header.os_abi,
            .ei_abiversion = header.abi_version,
        },
        .e_type = header.type,
        .e_machine = header.machine,
        .e_version = e_version,
        .e_entry = header.entry,
        .e_phoff = header.phoff,
        .e_shoff = header.shoff,
        .e_flags = 0, // TODO: no non-zero flags supported
        .e_ehsize = @sizeOf(std.elf.Ehdr),
        .e_phentsize = @sizeOf(std.elf.Phdr),
        .e_phnum = header.phnum,
        .e_shentsize = @sizeOf(std.elf.Shdr),
        .e_shnum = header.shnum,
        .e_shstrndx = header.shstrndx,
        .sections = sections,
        .program_segments = program_segments,
        .allocator = allocator,
    };
}

inline fn isStringTable(section_header: std.elf.Shdr) bool {
    return section_header.sh_type == std.elf.SHT_STRTAB;
}

inline fn isSectionInFile(section_header: std.elf.Shdr) bool {
    return section_header.sh_type != std.elf.SHT_NOBITS;
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    std.process.exit(FATAL_EXIT_CODE);
}

const t = std.testing;

test read {
    const allocator = t.allocator;

    {
        var in_buffer = try createTestElfBuffer();
        var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
        var elf = try read(allocator, &in_buffer_stream);
        defer elf.deinit();
    }

    {
        var empty_buffer = [0]u8{};
        var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &empty_buffer, .pos = 0 };
        try t.expectError(error.TruncatedElf, read(allocator, &in_buffer_stream));
    }
}

test "read endianness conversion" {
    if (builtin.cpu.arch.endian() != .little) {
        std.log.warn("endianness conversion test only runs on little endian targets", .{});
        return;
    }

    // TODO: input endianness does not match native endianness
}

test write {
    // TODO
}

test "write endianness conversion" {
    if (builtin.cpu.arch.endian() != .little) {
        std.log.warn("endianness conversion test only runs on little endian targets", .{});
        return;
    }

    // TODO: target endianness does not match native endianness
}

// Roundtrip test:
// * read from buffer
// * write to buffer
// * compare if the written bytes equal the input buffer
test "Read and write roundtrip" {
    const allocator = t.allocator;

    var in_buffer = try createTestElfBuffer();
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
    var elf = try read(allocator, &in_buffer_stream);
    defer elf.deinit();

    var out_buffer = [_]u8{0} ** in_buffer.len;
    var out_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &out_buffer, .pos = 0 };
    try elf.write(allocator, &in_buffer_stream, &out_buffer_stream);

    try t.expectEqualSlices(u8, &in_buffer, &out_buffer);
}

// Minimal ELF file in a buffer as a basis for tests
fn createTestElfBuffer() ![256]u8 {
    const section_header_table_offset = 64;
    const section_not_mapped = 0;
    const section_dynamic_size = 0;

    const e_ident =
        std.elf.MAGIC // EI_MAG0-3
    ++ [_]u8{std.elf.ELFCLASS64} // EI_CLASS
    ++ [_]u8{std.elf.ELFDATA2LSB} // EI_DATA
    ++ [_]u8{@intFromEnum(Version.ev_current)} // EI_VERSION
    ++ [_]u8{@intFromEnum(std.elf.OSABI.GNU)} // EI_OSABI
    ++ [_]u8{0} // EI_ABIVERSION
    ++ [_]u8{0} ** 7; // EI_PAD

    const header = std.elf.Ehdr{
        .e_ident = e_ident.*,
        .e_type = std.elf.ET.DYN,
        .e_machine = std.elf.EM.X86_64,
        .e_version = @intFromEnum(Version.ev_current),
        .e_entry = 0,
        .e_phoff = 0,
        .e_shoff = @sizeOf(std.elf.Ehdr),
        .e_flags = 0,
        .e_ehsize = @sizeOf(std.elf.Ehdr),
        .e_phentsize = @sizeOf(std.elf.Phdr),
        .e_phnum = 0,
        .e_shentsize = @sizeOf(std.elf.Shdr),
        .e_shnum = 2,
        .e_shstrndx = 1,
    };

    const test_buffer_size = 256;
    var in_buffer = [_]u8{0} ** test_buffer_size;
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
    const in_buffer_writer = in_buffer_stream.writer();

    // write input ELF
    {
        try in_buffer_writer.writeStruct(header);

        // section headers
        try t.expectEqual(section_header_table_offset, try in_buffer_stream.getPos());

        // null section
        const null_section_header = [_]u8{0} ** @sizeOf(std.elf.Shdr);
        try in_buffer_writer.writeAll(&null_section_header);

        // shstrtab
        const string_table_offset = 192;
        const string_table_size = 11;
        try in_buffer_writer.writeStruct(std.elf.Shdr{
            .sh_name = 1,
            .sh_type = std.elf.SHT_STRTAB,
            .sh_flags = std.elf.SHF_STRINGS,
            .sh_addr = section_not_mapped,
            .sh_offset = string_table_offset,
            .sh_size = string_table_size,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = section_dynamic_size,
        });

        // shstrtab content
        const string_table_section_offset = try in_buffer_stream.getPos();
        try in_buffer_writer.writeByte(0); // 0 for null section without a name
        try in_buffer_writer.writeAll(".shstrtab");
        try in_buffer_writer.writeByte(0);
        const string_table_section_end = try in_buffer_stream.getPos();

        try t.expectEqual(string_table_offset, string_table_section_offset);
        try t.expectEqual(string_table_size, string_table_section_end - string_table_section_offset);
    }

    return in_buffer;
}
