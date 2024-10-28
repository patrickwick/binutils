const std = @import("std");

const objcopy = @import("../../objcopy.zig");

/// Zig build step integration
pub const ObjCopy = @This();

pub const base_id: std.Build.Step.Id = .objcopy;

step: std.Build.Step,
input_file: std.Build.LazyPath,
output_file: std.Build.GeneratedFile,
options: Options,

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
    add_section: ?objcopy.AddSectionOption = null,
};

pub fn create(owner: *std.Build, input_file: std.Build.LazyPath, options: Options) *@This() {
    const target = owner.allocator.create(ObjCopy) catch @panic("OOM");
    target.* = .{
        .step = std.Build.Step.init(.{
            .id = base_id,
            .name = owner.fmt("objcopy {s}", .{input_file.getDisplayName()}),
            .owner = owner,
            .makeFn = make,
        }),
        .input_file = input_file,
        .output_file = std.Build.GeneratedFile{ .step = &target.step },
        .options = options,
    };
    input_file.addStepDependencies(&target.step);
    return target;
}

pub fn getOutput(self: *const @This()) std.Build.LazyPath {
    return .{ .generated = .{ .file = &self.output_file } };
}

pub fn getOutputSeparatedDebug(self: *const @This()) ?std.Build.LazyPath {
    return if (self.output_file_debug) |*file| .{ .generated = .{ .file = file } } else null;
}

fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) !void {
    _ = options;

    const b = step.owner;
    const target: *ObjCopy = @fieldParentPtr("step", step);
    try step.singleUnchangingWatchInput(target.input_file);

    var man = b.graph.cache.obtain();
    defer man.deinit();

    const in_file_path = target.input_file.getPath2(b, step);
    _ = try man.addFile(in_file_path, null);

    // TODO: update hash
    man.hash.add(target.options.output_target);
    man.hash.add(target.options.only_section != null);
    // man.hash.addOptional(target.options.only_section);
    man.hash.add(target.options.pad_to != null);
    // man.hash.addOptional(target.options.pad_to);
    man.hash.add(target.options.strip_debug);
    man.hash.add(target.options.strip_all);
    man.hash.add(target.options.only_keep_debug);
    man.hash.add(target.options.add_gnu_debuglink != null);
    // man.hash.addOptional(target.options.add_gnu_debuglink);
    man.hash.add(target.options.compress_debug_sections);
    man.hash.add(target.options.set_section_alignment != null);
    // man.hash.addOptional(target.options.set_section_alignment);
    man.hash.add(target.options.set_section_flags != null);
    // man.hash.addOptional(target.options.set_section_flags);
    man.hash.add(target.options.add_section != null);
    // man.hash.addOptional(target.options.add_section);

    if (try step.cacheHit(&man)) {
        const digest = man.final();
        // TODO: remove hardcoded "o" cache path if zig provides this
        const out_file_path = try b.cache_root.join(b.allocator, &.{ "o", &digest, target.input_file.getDisplayName() });
        target.output_file.path = out_file_path;
        return;
    }

    const digest = man.final();
    // TODO: remove hardcoded "o" cache path if zig provides this
    const out_file_dir = "o" ++ std.fs.path.sep_str ++ digest;
    b.cache_root.handle.makePath(out_file_dir) catch |err| {
        return step.fail("unable to make path {s}: {s}", .{ out_file_dir, @errorName(err) });
    };

    const out_file_path = try b.cache_root.join(b.allocator, &.{ out_file_dir, target.input_file.getDisplayName() });
    target.output_file.path = out_file_path;

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
        .add_section = target.options.add_section,
    });

    try man.writeManifest();
}
