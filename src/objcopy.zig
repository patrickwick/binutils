const std = @import("std");

pub const ObjCopyOptions = struct {
    in_file_path: []const u8,
    out_file_path: []const u8,
};

pub fn objcopy(allocator: std.mem.Allocator, options: ObjCopyOptions) void {
    _ = allocator;
    _ = options;
}
