const std = @import("std");

pub const ProgramSegment = @This();

// TODO: temporary copy of the input
// => represent section to segment mapping via handles and create
// the offset only when writing, so data does not go out of sync
program_header: std.elf.Phdr,
