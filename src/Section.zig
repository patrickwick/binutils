// TODO: consider inlining this file into Elf.zig
const std = @import("std");

pub const Section = @This();

pub const Handle = u64;

// copy from the input file
pub const InputFileRange = struct {
    offset: usize,
    size: usize,
};

pub const NoBits = struct {
    // TODO: are those required at all?
    // * the information is stored in the header, so it's redundant and can go out of sync.
    // * rename: they're **not** file offsets / sizes, they're process virtual addresses / memory size when laoded.
    offset: usize,
    size: usize,
};

// new data written into new sections that did not exist in the input
pub const Data = []const u8;

/// Section contents have different sources and are only loaded and copied on demand.
/// For example, appending data to a section from the input file converts it from a file range to a modified heap allocated copy of the input section.
/// Unmodified sections remain file range references and are only read on demand when writing the ELF file.
pub const ContentSource = union(enum) {
    /// Each section only references the input file range when read initially.
    input_file_range: InputFileRange,
    /// SHT_NOBITS sections (e.g.: .bss) are not contained in the file. All information is contained in the headers.
    no_bits: NoBits,
    /// Section content that is written programmatically.
    data: Data,
    /// Section content that is written programmatically and needs to be freed.
    data_allocated: Data,

    pub inline fn fileSize(self: *const @This()) usize {
        return switch (self.*) {
            .input_file_range => |range| range.size,
            .no_bits => 0, // no size in ELF file, only at runtime
            .data => |data| data.len,
        };
    }

    pub inline fn headerSize(self: *const @This()) usize {
        return switch (self.*) {
            .input_file_range => |range| range.size,
            .no_bits => |range| range.size,
            .data => |data| data.len,
        };
    }
};

// unique handle to identify the section without comparing names
handle: Handle,

name: []const u8, // head allocated copy

// TODO: sh_name, sh_offset and sh_size may go out of sync and are fixed during processing. Is this avoidable?
// * sh_name: if any section name before was changed / removed / added
// * sh_offset: if any section content before was resized, have updated alignment or are reordered
// * sh_size: section content is overwritten
// => could extract functions on these operations to always update all sections immediately or store the affected fields separately
header: std.elf.Shdr,
content: ContentSource,

// User has to free memory
pub fn readContentAlloc(self: *const @This(), input: anytype, allocator: std.mem.Allocator) ![]const u8 {
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(input), "seekableStream"));
    comptime std.debug.assert(std.meta.hasMethod(@TypeOf(input), "reader"));

    switch (self.content) {
        .input_file_range => |range| {
            const data = try allocator.alloc(u8, range.size);
            errdefer allocator.free(data);

            try input.seekableStream().seekTo(range.offset);
            const bytes_read = try input.reader().readAll(data);
            if (bytes_read != data.len) return error.TruncatedElf;

            return data;
        },
        .no_bits => return "", // e.g.: .bss
        .data, .data_allocated => |data| {
            const copy = try allocator.alloc(u8, data.len);
            @memcpy(copy, data);
            return copy;
        },
    }
}

// Create the section header in the input file endianess
pub fn toShdr(self: *const @This(), output_endianess: std.builtin.Endian) std.elf.Shdr {
    _ = output_endianess;
    std.log.warn("TODO: apply endianess on copy if native does not match target", .{});
    // std.mem.byteSwapAllFields(comptime S: type, ptr: *S)
    return self.header;
}
