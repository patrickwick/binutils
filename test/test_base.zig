// NOTE: basis for intergration tests located in build.zig.
// Unit tests are located directly in the corresponding source files.
const std = @import("std");

pub fn main() !void {
    try std.io.getStdOut().writeAll("Hello World!\n");
}
