const std = @import("std");

const objcopy = @import("../../objcopy.zig");

/// Zig build step integration
pub const ObjCopy = @This();

pub const base_id: std.Build.Step.Id = .objcopy;

step: std.Build.Step,
input_file: std.Build.LazyPath,
output_file: std.Build.GeneratedFile,
output_debug_file: ?std.Build.GeneratedFile,
options: Options,

pub const AddSectionOption = struct {
    section_name: []const u8,
    file_path: std.Build.LazyPath,
};

pub const Options = struct {
    output_target: objcopy.OutputTarget = .elf,
    only_section: ?objcopy.OnlySectionOption = null,
    pad_to: ?objcopy.PadToOption = null,
    strip_debug: bool = false,
    strip_all: bool = false,
    only_keep_debug: bool = false,
    add_gnu_debuglink: ?objcopy.AddGnuDebugLinkOption = null,
    compress_debug_sections: bool = false,
    set_section_alignment: ?objcopy.SetSectionAlignmentOption = null,
    set_section_flags: ?objcopy.SetSectionFlagsOption = null,
    add_section: ?AddSectionOption = null,

    /// Put the stripped debug sections in a separate file.
    /// Creates or overwrites the .gnu_debuglink section which contains a reference to the debug file and adds it to the output file.
    /// The debug file path is relative to the input file directory. Absolute paths are supported as well.
    /// This is a combination of the --only-keep-debug and --add-gnu-debuglink options.
    extract_to_separate_file: ?[]const u8 = null,
};

pub fn create(owner: *std.Build, input_file: std.Build.LazyPath, options: Options) *@This() {
    const target = owner.allocator.create(ObjCopy) catch @panic("OOM");
    target.* = .{
        .step = std.Build.Step.init(.{
            .id = base_id,
            .name = owner.fmt("objcopy {s}", .{input_file.getDisplayName()}),
            .owner = owner,
            .makeFn = selectMakeFunction(),
        }),
        .input_file = input_file,
        .output_file = std.Build.GeneratedFile{ .step = &target.step },
        .output_debug_file = if (options.extract_to_separate_file != null) std.Build.GeneratedFile{ .step = &target.step } else null,
        .options = options,
    };
    input_file.addStepDependencies(&target.step);
    return target;
}

pub fn getOutput(self: *const @This()) std.Build.LazyPath {
    return .{ .generated = .{ .file = &self.output_file } };
}

pub fn getOutputSeparatedDebug(self: *const @This()) ?std.Build.LazyPath {
    return if (self.output_debug_file) |*file| .{ .generated = .{ .file = file } } else null;
}

// Select make function for v0.13.0 backward compatibility.
fn selectMakeFunction() std.Build.Step.MakeFn {
    return comptime if (@import("builtin").zig_version.minor >= 14) make_v14 else make_v13;
}

fn make_v14(step: *std.Build.Step, options: std.Build.Step.MakeOptions) !void {
    return try make_v13(step, options.progress_node);
}

fn make_v13(step: *std.Build.Step, prog_node: std.Progress.Node) !void {
    _ = prog_node;

    const b = step.owner;
    const target: *ObjCopy = @fieldParentPtr("step", step);
    if (@import("builtin").zig_version.minor >= 14) try step.singleUnchangingWatchInput(target.input_file);

    var manifest = b.graph.cache.obtain();
    defer manifest.deinit();

    const in_file_path = target.input_file.getPath2(b, step);

    _ = try manifest.addFile(in_file_path, null);

    manifest.hash.add(target.options.output_target);

    manifest.hash.add(target.options.only_section != null);
    if (target.options.only_section) |o| manifest.hash.addBytes(o.section_name);

    manifest.hash.add(target.options.pad_to != null);
    if (target.options.pad_to) |o| manifest.hash.add(o.address);

    manifest.hash.add(target.options.strip_debug);

    manifest.hash.add(target.options.strip_all);

    manifest.hash.add(target.options.only_keep_debug);

    manifest.hash.add(target.options.add_gnu_debuglink != null);
    if (target.options.add_gnu_debuglink) |o| manifest.hash.addBytes(o.link);

    manifest.hash.add(target.options.compress_debug_sections);

    manifest.hash.add(target.options.set_section_alignment != null);
    if (target.options.set_section_alignment) |o| {
        manifest.hash.addBytes(o.section_name);
        manifest.hash.add(o.alignment);
    }

    manifest.hash.add(target.options.set_section_flags != null);
    if (target.options.set_section_flags) |o| {
        manifest.hash.addBytes(o.section_name);
        manifest.hash.add(@as(u14, @bitCast(o.flags)));
    }

    manifest.hash.add(target.options.add_section != null);
    const add_section = if (target.options.add_section) |o| blk: {
        manifest.hash.addBytes(o.section_name);
        const path = o.file_path.getPath2(b, null);
        manifest.hash.addBytes(path);
        break :blk objcopy.AddSectionOption{
            .section_name = o.section_name,
            .file_path = path,
        };
    } else null;

    manifest.hash.add(target.options.extract_to_separate_file != null);
    if (target.options.extract_to_separate_file) |o| manifest.hash.addBytes(o);

    const CACHE_BIN_DIR_PREFIX = "o"; // hardcoded in a few places in zig std.lib, did not find constant

    if (try step.cacheHit(&manifest)) {
        const digest = manifest.final();
        const out_file_path = try b.cache_root.join(b.allocator, &.{ CACHE_BIN_DIR_PREFIX, &digest, target.input_file.getDisplayName() });
        target.output_file.path = out_file_path;

        if (target.options.extract_to_separate_file) |o| {
            const out_debug_file_path = try b.cache_root.join(b.allocator, &.{ CACHE_BIN_DIR_PREFIX, &digest, o });
            target.output_debug_file.?.path = out_debug_file_path;
        }

        return;
    }

    const digest = manifest.final();
    const out_file_dir = CACHE_BIN_DIR_PREFIX ++ std.fs.path.sep_str ++ digest;
    b.cache_root.handle.makePath(out_file_dir) catch |err| {
        return step.fail("unable to make path {s}: {s}", .{ out_file_dir, @errorName(err) });
    };

    const out_file_path = try b.cache_root.join(b.allocator, &.{
        out_file_dir,
        target.input_file.getDisplayName(),
    });
    target.output_file.path = out_file_path;

    if (target.options.extract_to_separate_file) |extract_to_separate_file| {
        const debug_file_path = try b.cache_root.join(b.allocator, &.{
            out_file_dir,
            extract_to_separate_file,
        });
        target.output_debug_file.?.path = debug_file_path;

        // strip debug
        objcopy.objcopy(b.allocator, .{
            .in_file_path = in_file_path,
            .out_file_path = out_file_path,
            .strip_debug = true,
        });

        // only debug
        objcopy.objcopy(b.allocator, .{
            .in_file_path = in_file_path,
            .out_file_path = debug_file_path,
            .only_keep_debug = true,
        });

        // add debuglink
        objcopy.objcopy(b.allocator, .{
            .in_file_path = out_file_path,
            .out_file_path = out_file_path,
            .add_gnu_debuglink = .{ .link = extract_to_separate_file },
        });

        return;
    }

    objcopy.objcopy(b.allocator, .{
        .in_file_path = in_file_path,
        .out_file_path = out_file_path,
        .output_target = target.options.output_target,
        .only_section = target.options.only_section,
        .pad_to = target.options.pad_to,
        .strip_debug = target.options.strip_debug,
        .strip_all = target.options.strip_all,
        .only_keep_debug = target.options.only_keep_debug,
        .add_gnu_debuglink = target.options.add_gnu_debuglink,
        .compress_debug_sections = target.options.compress_debug_sections,
        .set_section_alignment = target.options.set_section_alignment,
        .set_section_flags = target.options.set_section_flags,
        .add_section = add_section,
    });
}
