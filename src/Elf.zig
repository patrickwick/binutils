const std = @import("std");
const builtin = @import("builtin");

const testing = @import("testing.zig");
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

section_handle_counter: Section.Handle,

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

pub fn init(
    allocator: std.mem.Allocator,
    header: std.elf.Header,
    ei_version: Version,
    e_version: Version,
    sections: Sections,
    program_segments: ProgramSegments,
) !@This() {
    return .{
        .section_handle_counter = sections.items.len + 1,
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

pub fn deinit(self: *@This()) void {
    // TODO: use sections / segments types with deinit functions
    for (self.sections.items) |*section| section.deinit();
    self.sections.deinit();
    self.program_segments.deinit();
}

pub inline fn getNextSectionHandle(self: *@This()) Section.Handle {
    defer self.section_handle_counter += 1;
    return self.section_handle_counter;
}

pub fn addSectionName(self: *@This(), source: anytype, section_name: []const u8) !usize {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "reader"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "seekableStream"));

    const shstrtab = &self.sections.items[self.e_shstrndx];
    const data = try shstrtab.readContent(source, self.allocator);
    const name_index = data.len;
    const copy = try self.allocator.alloc(u8, data.len + section_name.len + 1);
    errdefer self.allocator.free(copy);

    @memcpy(copy[0..name_index], data);
    self.allocator.free(data);
    @memcpy(copy[name_index .. copy.len - 1], section_name);
    copy[copy.len - 1] = 0;

    // update content
    shstrtab.content = .{ .data_allocated = copy };
    shstrtab.header.sh_size = copy.len;

    // relocate headers and sections contents due to size increase if needed
    // TODO: extract fixup function => critical function, must be well tested
    var sorted_sections = try self.sections.clone();
    defer sorted_sections.deinit();

    const Sort = struct {
        fn lessThan(context: *const @This(), left: Section, right: Section) bool {
            _ = context;
            return left.header.sh_offset < right.header.sh_offset;
        }
    };
    var sort_context = Sort{};
    std.mem.sort(Section, sorted_sections.items, &sort_context, Sort.lessThan);

    // TODO: use these checks and reports in the test verify function
    var previous = &sorted_sections.items[0];
    for (sorted_sections.items[1..]) |*section| {
        if (section.header.sh_type == std.elf.SHT_NOBITS) continue;
        defer previous = section;

        // relocate section content
        if (section.header.sh_offset < previous.header.sh_offset + previous.header.sh_size) {
            std.log.debug("section '{s}' 0x{x}-0x{x} overlaps with section '{s}' 0x{x}-0x{x}", .{
                self.getSectionName(section),
                section.header.sh_offset,
                section.header.sh_offset + section.header.sh_size,
                self.getSectionName(previous),
                previous.header.sh_offset,
                previous.header.sh_offset + previous.header.sh_size,
            });

            const alignment = section.header.sh_addralign;
            section.header.sh_offset = std.mem.alignForward(usize, previous.header.sh_offset + previous.header.sh_size, alignment);
            std.log.debug("  moving section content to 0x{x}-0x{x}", .{
                section.header.sh_offset,
                section.header.sh_offset + self.e_shoff + self.e_shnum * self.e_shentsize,
            });

            // TODO: update program header offsets that map the moved section

            // TODO: move e_entry if it was in the moved section
        }

        // relocate section headers
        if (isIntersect(
            section.header.sh_offset,
            section.header.sh_offset + section.header.sh_size,
            self.e_shoff,
            self.e_shoff + self.e_shnum * self.e_shentsize,
        )) {
            std.log.debug("section '{s}' 0x{x}-0x{x} overlaps with section headers 0x{x}-0x{x}", .{
                self.getSectionName(section),
                section.header.sh_offset,
                section.header.sh_offset + section.header.sh_size,
                self.e_shoff,
                self.e_shoff + self.e_shnum * self.e_shentsize,
            });

            const alignment = 8;
            self.e_shoff = std.mem.alignForward(usize, section.header.sh_offset + section.header.sh_size, alignment);
            std.log.debug("  moving section headers to 0x{x}-0x{x}", .{
                self.e_shoff,
                self.e_shoff + self.e_shnum * self.e_shentsize,
            });

            // TODO: moving the headers also may require shifting down the following sections
            // => shift immediately instead of hitting this branch again in the next iteration
        }

        // relocate program headers
        if (isIntersect(
            section.header.sh_offset,
            section.header.sh_offset + section.header.sh_size,
            self.e_phoff,
            self.e_phoff + self.e_phnum * self.e_phentsize,
        )) {
            std.log.debug("section '{s}' 0x{x}-0x{x} overlaps with program headers 0x{x}-0x{x}", .{
                self.getSectionName(section),
                section.header.sh_offset,
                section.header.sh_offset + section.header.sh_size,
                self.e_phoff,
                self.e_phoff + self.e_phnum * self.e_phentsize,
            });

            const alignment = 8;
            self.e_phoff = std.mem.alignForward(usize, section.header.sh_offset + section.header.sh_size, alignment);
            std.log.debug("  moving program headers to 0x{x}-0x{x}", .{
                self.e_phoff,
                self.e_phoff + self.e_phnum * self.e_phentsize,
            });

            // TODO: moving the headers also may require shifting down the following sections
            // => shift immediately instead of hitting this branch again in the next iteration
        }
    }

    return name_index;
}

inline fn isIntersect(a_min: anytype, a_max: anytype, b_min: anytype, b_max: anytype) bool {
    return a_min < b_max and b_min < a_max;
}

pub fn addSection(self: *@This(), source: anytype, section_name: []const u8, content: []const u8) !void {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "reader"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "seekableStream"));

    const name_index = try self.addSectionName(source, section_name);

    // TODO: revisit spec on restrictions wrt. to alignment
    const default_file_alignment = 8;

    // TODO: extract function and test well
    const offset = offset: {
        var highest: usize = 0;
        for (self.sections.items) |*section| {
            if (section.header.sh_type == std.elf.SHT_NOBITS) continue;
            const section_end = section.header.sh_offset + section.header.sh_size;
            if (highest < section_end) highest = section_end;
        }

        const section_headers_end = self.e_shoff + self.e_shnum * self.e_shentsize;
        if (highest < section_headers_end) highest = section_headers_end;

        const program_headers_end = self.e_phoff + self.e_phnum * self.e_phentsize;
        if (highest < program_headers_end) highest = program_headers_end;

        break :offset std.mem.alignForward(usize, highest, default_file_alignment);
    };

    const no_flags = 0;
    const default_address_alignment = 8;
    const not_mapped = 0;
    const dynamic = 0;

    try self.sections.append(.{
        .handle = self.getNextSectionHandle(),
        .header = .{
            .sh_name = @intCast(name_index),
            .sh_type = std.elf.SHT_PROGBITS,
            .sh_flags = no_flags,
            .sh_addr = not_mapped,
            .sh_offset = offset,
            .sh_size = content.len,
            .sh_link = std.elf.SHN_UNDEF,
            .sh_info = std.elf.SHN_UNDEF,
            .sh_addralign = default_address_alignment,
            .sh_entsize = dynamic,
        },
        .content = .{ .data_allocated = try self.allocator.dupe(u8, content) },
        .allocator = self.allocator,
    });
    self.e_shnum = self.sections.items.len;
}

pub fn removeSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

// Precondition: shstrtab is located in sections at index e_shstrndx
pub fn getSectionName(self: *const @This(), section: *const Section) []const u8 {
    const shstrtab = self.sections.items[self.e_shstrndx];
    const string_table_content = shstrtab.content.data_allocated;
    if (section.header.sh_name >= string_table_content.len) fatal(
        "invalid ELF input file: section name offset {d} exceeds strtab size {d}",
        .{ section.header.sh_name, string_table_content.len },
    );
    return std.mem.span(@as([*:0]const u8, @ptrCast(&string_table_content[section.header.sh_name])));
}

pub fn write(self: *@This(), allocator: std.mem.Allocator, source: anytype, target: anytype) !void {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(target), "writer"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(target), "seekableStream"));

    const writer = target.writer();
    const out_stream = target.seekableStream();

    // TODO: write header in input file class, not native size
    const output_64bit = if (self.e_ident.ei_class == .elfclass64) true else false;
    _ = output_64bit;
    const output_endianness = self.e_ident.ei_data;

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

    // convert endianness if output and native endianness do not match
    if (output_endianness != builtin.target.cpu.arch.endian()) std.mem.byteSwapAllFields(std.elf.Ehdr, &header);

    try out_stream.seekTo(0);
    try writer.writeStruct(header);

    // TODO: perform validation that header, section header, program headers and section content regions don't overlap

    // section content
    for (self.sections.items) |*section| {
        switch (section.content) {
            .input_file_range, .data, .data_allocated => {
                const data = try section.readContent(source, allocator);
                try out_stream.seekTo(section.header.sh_offset);
                try writer.writeAll(data);
            },
            .no_bits => {},
        }
    }

    // program headers
    try out_stream.seekTo(self.e_phoff);
    for (self.program_segments.items) |program_segment| {
        try writer.writeStruct(program_segment.program_header);
    }

    // section headers
    try out_stream.seekTo(self.e_shoff);
    for (self.sections.items) |section| {
        try writer.writeStruct(section.toShdr(output_endianness));
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

    var sections = Sections.init(allocator);
    errdefer {
        // TODO: use sections / segments types with deinit functions
        for (sections.items) |*section| section.deinit();
        sections.deinit();
    }

    var section_handle_counter: Section.Handle = 1;
    var string_table_section = shstrtab: {
        // NOTE: iterator already accounts for endianess, so it always has native endianness
        var section_it = header.section_header_iterator(source);
        var i: usize = 0;
        while (try section_it.next()) |section| : (i += 1) {
            if (i == header.shstrndx) {
                if (!isStringTable(section)) fatal(
                    "section type of section name string table must be SHT_STRTAB 0x{x}, got 0x{x}",
                    .{ std.elf.SHT_STRTAB, section.sh_type },
                );

                defer section_handle_counter += 1;
                break :shstrtab Section{
                    .handle = section_handle_counter,
                    .header = section,
                    .content = .{ .input_file_range = .{ .offset = section.sh_offset, .size = section.sh_size } },
                    .allocator = allocator,
                };
            }
        }
        fatal("input ELF file does not contain a string table section (usually .shstrtab)", .{});
    };
    const string_table_content = try string_table_section.readContent(source, allocator);

    {
        var section_it = header.section_header_iterator(source);
        var i: usize = 0;
        while (try section_it.next()) |section| : (i += 1) {
            if (i == header.shstrndx) {
                try sections.append(string_table_section);
                continue;
            }

            if (section.sh_name >= string_table_content.len) fatal(
                "invalid ELF input file: section {d} name offset {d} exceeds strtab size {d}",
                .{ i, section.sh_name, string_table_content.len },
            );

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

            defer section_handle_counter += 1;
            try sections.append(.{
                .handle = section_handle_counter,
                .header = section,
                .content = content,
                .allocator = allocator,
            });
        }
    }

    // section to segment mapping
    var program_segments = ProgramSegments.init(allocator);
    errdefer program_segments.deinit();
    var program_it = header.program_header_iterator(source);
    var segment_i: usize = 0;
    while (try program_it.next()) |program_header| {
        defer segment_i += 1;
        var segment_mapping = ProgramSegment.SegmentMapping.init(allocator);
        for (sections.items, 0..) |section, section_i| {
            // NOBITS section like .bss are not contained in the file, so they're handled differently
            if (section.header.sh_type == std.elf.SHT_NOBITS) {
                const segment_start = program_header.p_vaddr;
                const segment_end = segment_start + program_header.p_memsz;
                const section_start = section.header.sh_addr;
                const section_end = section_start + section.header.sh_size;

                if (segment_start <= section_start and segment_end >= section_end) {
                    try segment_mapping.append(section.handle);
                }
            } else {
                const segment_start = program_header.p_offset;
                const segment_end = segment_start + program_header.p_filesz;
                const section_start = section.header.sh_offset;
                const section_end = section_start + section.header.sh_size;

                // NOTE: limitation: rejects input if program header loads a subset of a section
                // * start is between section start and end but end is not after section end
                // * end is between section start and end but start is not before section start
                if ((segment_start >= section_start and segment_start < section_end and segment_end < section_end) //
                or (segment_end > section_start and segment_end <= section_end and segment_start > section_start)) fatal(
                    "segment {d} (0x{x}-0x{x}) is not allowed to map section {d} subset (0x{x}-0x{x}). Only entire sections can be mapped",
                    .{ segment_i, segment_start, segment_end, section_i, section_start, section_end },
                );

                if (segment_start <= section_start and segment_end >= section_end) {
                    try segment_mapping.append(section.handle);
                }
            }
        }

        try program_segments.append(.{
            .program_header = program_header,
            .segment_mapping = segment_mapping,
        });
    }

    return try @This().init(allocator, header, ei_version, e_version, sections, program_segments);
}

pub fn getSection(self: *const @This(), handle: Section.Handle) ?*Section {
    return for (self.sections.items) |*section| {
        if (section.handle == handle) return section;
    } else null;
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
    if (builtin.mode == .Debug) testing.printStackTrace(@returnAddress());
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
        try assertElf(&elf);
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

test addSectionName {
    const allocator = t.allocator;

    var in_buffer = try createTestElfBuffer();
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
    var elf = try read(allocator, &in_buffer_stream);
    defer elf.deinit();

    const old_size = elf.sections.items[elf.e_shstrndx].header.sh_size;

    const new_name = ".new_section";
    const name_index = try elf.addSectionName(&in_buffer_stream, new_name);
    try t.expectEqual(old_size, name_index);

    const new_size = elf.sections.items[elf.e_shstrndx].header.sh_size;
    try t.expectEqual(old_size + new_name.len + 1, new_size); // + 1 for 0 sentinel in front of new name

    try assertElf(&elf);
}

test addSection {
    const allocator = t.allocator;

    var in_buffer = try createTestElfBuffer();
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
    var elf = try read(allocator, &in_buffer_stream);
    defer elf.deinit();

    const last_section = &elf.sections.items[elf.sections.items.len - 1];
    const old_section_count = elf.sections.items.len;

    try elf.addSection(&in_buffer_stream, ".abc", "content");
    try t.expectEqual(old_section_count + 1, elf.sections.items.len);

    const new = &elf.sections.items[elf.sections.items.len - 1];
    try t.expectEqual(last_section.header.sh_offset + last_section.header.sh_size, new.header.sh_offset);

    try assertElf(&elf);
}

// internal runtime checks that to be executed in debug mode after modifications
fn assertElf(elf: *const Elf) !void {
    // TODO: report errors in more readable way
    try t.expectEqual(elf.e_version, .ev_current);
    try t.expectEqual(elf.e_ident.ei_version, .ev_current);
    try t.expect(elf.e_shstrndx != 0);
    try t.expectEqual(elf.e_flags, 0);
    // FIXME: not true for 32bit file on 64bit native system
    try t.expectEqual(elf.e_shentsize, @sizeOf(std.elf.Shdr));
    try t.expectEqual(elf.e_phentsize, @sizeOf(std.elf.Phdr));
    try t.expectEqual(elf.e_shnum, elf.sections.items.len);
    try t.expectEqual(elf.e_phnum, elf.program_segments.items.len);

    for (elf.sections.items) |section| {
        const file_size = switch (section.content) {
            .data, .data_allocated => |data| data.len,
            .no_bits => 0,
            .input_file_range => |range| range.size,
        };
        try t.expectEqual(section.header.sh_size, file_size);
    }

    // TODO: check for section and header overlap, see fixup function
}
