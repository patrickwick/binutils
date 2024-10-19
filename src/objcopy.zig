const std = @import("std");
const builtin = @import("builtin");

const Elf = @import("Elf.zig").Elf;

const FATAL_EXIT_CODE = 1;

pub const ObjCopyOptions = struct {
    in_file_path: []const u8,
    out_file_path: []const u8,
};

pub fn objcopy(allocator: std.mem.Allocator, options: ObjCopyOptions) void {
    const out = std.io.getStdOut();
    _ = out;

    if (std.mem.eql(u8, options.in_file_path, options.out_file_path)) fatal("input and output file path are not allowed to be equal", .{});

    var in_file = std.fs.cwd().openFile(options.in_file_path, .{}) catch |err| fatal(
        "unable to open input '{s}': {s}",
        .{ options.in_file_path, @errorName(err) },
    );
    defer in_file.close();

    var elf = Elf.read(allocator, in_file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.in_file_path, @errorName(err) });
    defer elf.deinit();

    var out_file = std.fs.cwd().createFile(options.out_file_path, .{
        .read = true,
        .truncate = true,
        .mode = 0o755,
    }) catch |err| fatal(
        "failed creating output '{s}': {s}",
        .{ options.out_file_path, @errorName(err) },
    );
    defer out_file.close();

    // TODO: apply options

    elf.write(allocator, in_file, out_file) catch |err| fatal(
        "failed writing output '{s}': {s}",
        .{ options.out_file_path, @errorName(err) },
    );
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils objcopy";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    std.process.exit(FATAL_EXIT_CODE);
}
