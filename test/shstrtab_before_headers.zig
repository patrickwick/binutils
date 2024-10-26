// Executable that puts the section name string table content (shstrtab) in front of the section and program headers.
// This has the implication that adding a new section will increase the shstrtab size that requires shifting down all other content.
// A failure to do so correctly would cause ELF file corruption.
const std = @import("std");

pub fn main() !void {
    try std.io.getStdOut().writeAll("Hello World!\n");
}
