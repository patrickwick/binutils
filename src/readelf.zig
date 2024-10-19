const std = @import("std");
const Elf = @import("Elf.zig");

const FATAL_EXIT_CODE = 1;

pub const ReadElfOptions = struct {
    file_path: []const u8,
};

pub fn readelf(allocator: std.mem.Allocator, options: ReadElfOptions) void {
    var file = std.fs.cwd().openFile(options.file_path, .{}) catch |err| fatal("unable to open '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer file.close();

    var elf = Elf.readFromSource(allocator, file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer elf.deinit();
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    std.process.exit(FATAL_EXIT_CODE);
}
