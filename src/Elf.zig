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
string_table_content: []const u8, // TODO: add type?

allocator: std.mem.Allocator,

pub fn init(
    allocator: std.mem.Allocator,
    header: std.elf.Header,
    ei_version: Version,
    e_version: Version,
    sections: Sections,
    program_segments: ProgramSegments,
    string_table_content: []const u8,
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
        .string_table_content = string_table_content,
        .allocator = allocator,
    };
}

pub fn deinit(self: *@This()) void {
    // TODO: use sections / segments types with deinit functions
    for (self.sections.items) |*section| section.deinit();
    self.sections.deinit();
    self.program_segments.deinit();
    self.allocator.free(self.string_table_content);
}

pub inline fn getNextSectionHandle(self: *@This()) Section.Handle {
    defer self.section_handle_counter += 1;
    return self.section_handle_counter;
}

pub fn addSectionName(self: *@This(), source: anytype, section_name: []const u8) !usize {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "reader"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "seekableStream"));

    const shstrtab = &self.sections.items[self.e_shstrndx];
    var name_index: usize = 0;
    const copy = switch (shstrtab.content) {
        .data => |data| copy: {
            name_index = data.len;

            const copy = try self.allocator.alloc(u8, data.len + section_name.len + 1);
            errdefer self.allocator.free(copy);
            @memcpy(copy[0..data.len], data);

            break :copy copy;
        },
        .data_allocated => |data| copy: {
            name_index = data.len + 1;

            const copy = try self.allocator.alloc(u8, data.len + section_name.len + 1);
            errdefer self.allocator.free(copy);
            @memcpy(copy[0..data.len], data);
            self.allocator.free(data);

            break :copy copy;
        },
        .input_file_range => |range| data: {
            name_index = range.size;

            const copy = try self.allocator.alloc(u8, range.size + section_name.len + 1);
            errdefer self.allocator.free(copy);

            try source.seekableStream().seekTo(range.offset);
            const bytes_read = try source.reader().readAll(copy[0..range.size]);
            if (bytes_read != range.size) return error.TruncatedElf;

            break :data copy;
        },
        .no_bits => fatal("unexpected NOBITS section name string table section", .{}),
    };

    std.debug.assert(name_index != 0);
    std.debug.assert(copy.len > 0);
    @memcpy(copy[name_index .. copy.len - 1], section_name);
    copy[copy.len - 1] = 0;

    // TODO: update content
    // shstrtab.content = .{ .data_allocated = copy };

    // relocate content after updated shstrtab section due to size increase
    // TODO: relocate section headers and update sh_shoff

    // TODO: relocate program headers and update sh_phoff

    // TODO: relocate section content

    // TODO: update program header offsets

    return name_index;
}

pub fn addSection(self: *@This(), source: anytype, section_name: []const u8, content: []const u8) !void {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "reader"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(source), "seekableStream"));

    // TODO: decide on strategy: either update shstrtab, headers, etc. on write or immediately
    // * pro on write:
    //   * performance - less reallocating shstrtab, recomputing offsets, etc.
    //   * very hard to track what needs to be updated.
    //     How do you know if gaps are intentional or due to a removed section, etc.?
    // * pro immediately:
    //   * data does not go out of sync
    //   * issues are detected immediately
    //   * use knowledge of modification to reduce update scope
    //      * easier to test as a result
    // => I'll adjust everything immediately

    const name_index = try self.addSectionName(source, section_name);
    _ = name_index;
    _ = content;

    //defer self.handle_counter += 1;
    //try self.sections.append(Section{.name = section_name, .content = .{.data = content }, .handle = self.handle_counter, .header = .{},);
}

pub fn removeSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

pub fn getSectionName(self: *const @This(), section: Section) []const u8 {
    if (section.header.sh_name >= self.string_table_content.len) fatal(
        "invalid ELF input file: section name offset {d} exceeds strtab size {d}",
        .{ section.header.sh_name, self.string_table_content.len },
    );
    return std.mem.span(@as([*:0]const u8, @ptrCast(&self.string_table_content[section.header.sh_name])));
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

    // TODO: put the section into sections immediately then skip it later
    // => avoid reading the content twice
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
                    // .name = ".shstrtab", // TODO: use name from shstrtab itself instead of hardcoding it
                    .header = section,
                    .content = .{ .input_file_range = .{ .offset = section.sh_offset, .size = section.sh_size } },
                    .allocator = allocator,
                };
            }
        }
        fatal("input ELF file does not contain a string table section (usually .shstrtab)", .{});
    };
    defer string_table_section.deinit();
    const string_table_content_slice = try string_table_section.readContent(source, allocator);
    const string_table_content = try allocator.dupe(u8, string_table_content_slice);
    errdefer allocator.free(string_table_content);

    var sections = Sections.init(allocator);
    errdefer {
        // TODO: use sections / segments types with deinit functions
        for (sections.items) |*section| section.deinit();
        sections.deinit();
    }

    {
        var section_it = header.section_header_iterator(source);
        var i: usize = 0;
        while (try section_it.next()) |section| {
            defer i += 1;
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
                // .name = name,
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

    return try @This().init(allocator, header, ei_version, e_version, sections, program_segments, string_table_content);
}

pub fn getSection(self: *const @This(), handle: Section.Handle) ?Section {
    return for (self.sections.items) |section| {
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
    // TODO: NYI
    // const sections = Elf.Sections.init(t.allocator);

    // var elf = Elf{
    //     .section_handle_counter = 1,
    //     .e_ident = .{
    //         .ei_class = .elfclass64,
    //         .ei_data = .little,
    //         .ei_version = .ev_current,
    //         .ei_osabi = std.elf.OSABI.NONE,
    //         .ei_abiversion = 0,
    //     },
    //     .e_type = std.elf.ET.DYN,
    //     .e_machine = std.elf.EM.X86_64,
    //     .e_version = .ev_current,
    //     .e_entry = 0x128,
    //     .e_phoff = 64,
    //     .e_shoff = 800,
    //     .e_flags = 0,
    //     .e_ehsize = @sizeOf(std.elf.Ehdr),
    //     .e_phentsize = @sizeOf(std.elf.Phdr),
    //     .e_phnum = 0,
    //     .e_shentsize = @sizeOf(std.elf.Shdr),
    //     .e_shnum = 2,
    //     .e_shstrndx = 1,
    //     .sections = sections,
    //     .program_segments = Elf.ProgramSegments.init(t.allocator),
    //     .allocator = t.allocator,
    // };

    // try sections.append(.{
    //     .handle = elf.getNextSectionHandle(),
    //     .header = .{},
    //     .content = "",
    //     .name = ".shstrtab",
    // });

    // const name_index = try elf.addSectionName(".new_section");
    // _ = name_index;
}
