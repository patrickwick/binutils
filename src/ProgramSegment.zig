// TODO: consider inlining this file into Elf.zig
const std = @import("std");

const Section = @import("Section.zig").Section;

pub const ProgramSegment = @This();

pub const SegmentMapping = std.ArrayList(Section.Handle);

// TODO: temporary copy of the input
// => represent section to segment mapping via handles and create
// the offset only when writing, so data does not go out of sync
program_header: std.elf.Phdr,

/// Section to segment mapping. A segment can reference 0 to n sections.
/// Does not support referencing a subrange of a section.
segment_mapping: SegmentMapping,
