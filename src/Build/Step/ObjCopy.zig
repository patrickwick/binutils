const std = @import("std");

const objcopy = @import("../../objcopy.zig");

/// Zig build step integration
pub const ObjCopy = @This();

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const File = std.fs.File;
const InstallDir = std.Build.InstallDir;
const Step = std.Build.Step;
const elf = std.elf;
const fs = std.fs;
const io = std.io;
const sort = std.sort;

pub const base_id: Step.Id = .objcopy;

pub const RawFormat = enum {
    bin,
    hex,
    elf,
};

pub const Strip = enum {
    none,
    debug,
    debug_and_symbols,
};

step: Step,
input_file: std.Build.LazyPath,
basename: []const u8,
output_file: std.Build.GeneratedFile,
output_file_debug: ?std.Build.GeneratedFile,

format: ?RawFormat,
only_section: ?[]const u8,
pad_to: ?u64,
strip: Strip,
compress_debug: bool,

pub const Options = struct {
    basename: ?[]const u8 = null,
    format: ?RawFormat = null,
    only_section: ?[]const u8 = null,
    pad_to: ?u64 = null,

    compress_debug: bool = false,
    strip: Strip = .none,

    /// Put the stripped out debug sections in a separate file.
    /// note: the `basename` is baked into the elf file to specify the link to the separate debug file.
    /// see https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
    extract_to_separate_file: bool = false,
};

pub fn create(
    owner: *std.Build,
    input_file: std.Build.LazyPath,
    options: Options,
) *ObjCopy {
    const objcopy_target = owner.allocator.create(ObjCopy) catch @panic("OOM");
    objcopy_target.* = ObjCopy{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("objcopy {s}", .{input_file.getDisplayName()}),
            .owner = owner,
            .makeFn = make,
        }),
        .input_file = input_file,
        .basename = options.basename orelse input_file.getDisplayName(),
        .output_file = std.Build.GeneratedFile{ .step = &objcopy_target.step },
        .output_file_debug = if (options.strip != .none and options.extract_to_separate_file) std.Build.GeneratedFile{ .step = &objcopy_target.step } else null,
        .format = options.format,
        .only_section = options.only_section,
        .pad_to = options.pad_to,
        .strip = options.strip,
        .compress_debug = options.compress_debug,
    };
    input_file.addStepDependencies(&objcopy_target.step);
    return objcopy_target;
}

pub fn getOutput(self: *const ObjCopy) std.Build.LazyPath {
    return .{ .generated = .{ .file = &self.output_file } };
}

pub fn getOutputSeparatedDebug(self: *const ObjCopy) ?std.Build.LazyPath {
    return if (self.output_file_debug) |*file| .{ .generated = .{ .file = file } } else null;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;

    const b = step.owner;
    const objcopy_target: *ObjCopy = @fieldParentPtr("step", step);
    try step.singleUnchangingWatchInput(objcopy_target.input_file);

    var man = b.graph.cache.obtain();
    defer man.deinit();

    // ============
    // TODO: based on ObjCopy.zig in std lib => update hashing
    const in_file_path = objcopy_target.input_file.getPath2(b, step);

    _ = try man.addFile(in_file_path, null);

    man.hash.addOptionalBytes(objcopy_target.only_section);
    man.hash.addOptional(objcopy_target.pad_to);
    man.hash.addOptional(objcopy_target.format);
    man.hash.add(objcopy_target.compress_debug);
    man.hash.add(objcopy_target.strip);
    man.hash.add(objcopy_target.output_file_debug != null);

    if (try step.cacheHit(&man)) {
        // Cache hit, skip subprocess execution.
        const digest = man.final();
        objcopy_target.output_file.path = try b.cache_root.join(b.allocator, &.{
            "o", &digest, objcopy_target.basename,
        });
        if (objcopy_target.output_file_debug) |*file| {
            file.path = try b.cache_root.join(b.allocator, &.{
                "o", &digest, b.fmt("{s}.debug", .{objcopy_target.basename}),
            });
        }
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ fs.path.sep_str ++ digest;

    const out_file_path = try b.cache_root.join(b.allocator, &.{ cache_path, objcopy_target.basename });
    defer objcopy_target.output_file.path = out_file_path;

    const full_dest_path_debug = try b.cache_root.join(b.allocator, &.{ cache_path, b.fmt("{s}.debug", .{objcopy_target.basename}) });
    defer {
        if (objcopy_target.output_file_debug) |*file| file.path = full_dest_path_debug;
    }

    b.cache_root.handle.makePath(cache_path) catch |err| {
        return step.fail("unable to make path {s}: {s}", .{ cache_path, @errorName(err) });
    };
    // =============

    defer man.writeManifest() catch @panic("failed writing manifiest");

    defer {
        if (objcopy_target.output_file_debug) |*file| file.path = full_dest_path_debug;
    }

    var opt = objcopy.ObjCopyOptions{
        .in_file_path = in_file_path,
        .out_file_path = out_file_path,
    };

    // TODO: translate options or expose them directly
    opt.strip_all = true;

    objcopy.objcopy(b.allocator, opt);
}
