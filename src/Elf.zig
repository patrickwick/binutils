const std = @import("std");

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
};

comptime {
    // TODO: verify that each field is a byte in size => important if source endianess does not match native endianness
}

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

pub fn addSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

pub fn removeSection(self: *@This()) void {
    // TODO: NYI
    _ = self;
}

pub fn writeToFile(self: *@This(), path: []const u8) void {
    // TODO: NYI
    _ = self;
    _ = path;
}

pub fn readFromFile(path: []const u8) !@This() {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try readFromSource(file);
}

pub fn readFromSource(source: anytype) !@This() {
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

    // TODO: sections
    // TODO: program headers
    // TODO: section to segment mapping

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
    };
}

const t = std.testing;

test readFromSource {
    // TODO
}
