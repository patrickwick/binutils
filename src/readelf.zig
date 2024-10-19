const std = @import("std");
const builtin = @import("builtin");

const Elf = @import("Elf.zig").Elf;

const FATAL_EXIT_CODE = 1;

pub const ReadElfOptions = struct {
    file_path: []const u8,
};

pub fn readelf(allocator: std.mem.Allocator, options: ReadElfOptions) void {
    const out = std.io.getStdOut();

    var file = std.fs.cwd().openFile(options.file_path, .{}) catch |err| fatal("unable to open '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer file.close();

    var elf = Elf.read(allocator, file) catch |err| fatal("failed reading ELF file '{s}': {s}", .{ options.file_path, @errorName(err) });
    defer elf.deinit();

    // TODO: add -h / --file-header option
    // if (options.header) printElfHeader();

    printElfHeader(out.writer().any(), &elf) catch |err| fatal("failed writing to output: {s}", .{@errorName(err)});
}

fn printElfHeader(out: std.io.AnyWriter, elf: *const Elf) !void {
    const eb = elf.e_ident.toBuffer();

    const class = switch (elf.e_ident.ei_class) {
        .elfclass64 => "ELF64",
        .elfclass32 => "ELF32",
    };

    const data = switch (elf.e_ident.ei_data) {
        .little => "2's complement, little endian",
        .big => "2's complement, big endian",
    };

    const version = switch (elf.e_ident.ei_version) {
        .ev_current => "1 (current)",
    };

    const os_abi = switch (elf.e_ident.ei_osabi) {
        .NONE => "UNIX - System V",
        // TODO: add all verbose names
        else => |abi| @tagName(abi),
    };

    const file_type = switch (elf.e_type) {
        .DYN => "DYN (Position-Independent Executable file)",
        // TODO: add all verbose names
        else => |file_type| @tagName(file_type),
    };

    const machine = switch (elf.e_machine) {
        .X86_64 => "Advanced Micro Devices X86-64",
        // TODO: add all verbose names
        else => |machine| @tagName(machine),
    };

    // TODO: print leading zeroes in hex values for constant width and adapt test
    try out.print(
        \\ELF Header:
        \\  Magic:   {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x} {x}
        \\
    , .{ eb[0], eb[1], eb[2], eb[3], eb[4], eb[5], eb[6], eb[7], eb[8], eb[9], eb[10], eb[11], eb[12], eb[13], eb[14], eb[15] });

    try out.print(
        \\  Class:                             {s}
        \\  Data:                              {s}
        \\  Version:                           {s}
        \\  OS/ABI:                            {s}
        \\  ABI Version:                       {d}
        \\  Type:                              {s}
        \\  Machine:                           {s}
        \\  Version:                           0x{x}
        \\  Entry point address:               0x{x}
        \\  Start of program headers:          {d} (bytes into file)
        \\  Start of section headers:          {d} (bytes into file)
        \\  Flags:                             0x{x}
        \\  Size of this header:               {d} (bytes)
        \\  Size of program headers:           {d} (bytes)
        \\  Number of program headers:         {d}
        \\  Size of section headers:           {d} (bytes)
        \\  Number of section headers:         {d}
        \\  Section header string table index: {d}
        \\
    , .{
        class,
        data,
        version,
        os_abi,
        elf.e_ident.ei_abiversion,
        file_type,
        machine,
        @intFromEnum(elf.e_version),
        elf.e_entry,
        elf.e_phoff,
        elf.e_shoff,
        elf.e_flags,
        elf.e_ehsize,
        elf.e_phentsize,
        elf.e_phnum,
        elf.e_shentsize,
        elf.e_shnum,
        elf.e_shstrndx,
    });
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const context = "binutils readelf";
    if (!builtin.is_test) std.log.err(context ++ ": " ++ format, args);
    std.process.exit(FATAL_EXIT_CODE);
}

const t = std.testing;

test printElfHeader {
    const expected =
        \\ELF Header:
        \\  Magic:   7f 45 4c 46 2 1 1 0 0 0 0 0 0 0 0 0
        \\  Class:                             ELF64
        \\  Data:                              2's complement, little endian
        \\  Version:                           1 (current)
        \\  OS/ABI:                            UNIX - System V
        \\  ABI Version:                       0
        \\  Type:                              DYN (Position-Independent Executable file)
        \\  Machine:                           Advanced Micro Devices X86-64
        \\  Version:                           0x1
        \\  Entry point address:               0x128
        \\  Start of program headers:          64 (bytes into file)
        \\  Start of section headers:          800 (bytes into file)
        \\  Flags:                             0x0
        \\  Size of this header:               64 (bytes)
        \\  Size of program headers:           56 (bytes)
        \\  Number of program headers:         0
        \\  Size of section headers:           64 (bytes)
        \\  Number of section headers:         2
        \\  Section header string table index: 1
        \\
    ;

    var out_buffer = [_]u8{0} ** expected.len;
    var out_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &out_buffer, .pos = 0 };

    const elf = .{
        .e_ident = .{
            .ei_class = .elfclass64,
            .ei_data = .little,
            .ei_version = .ev_current,
            .ei_osabi = std.elf.OSABI.NONE,
            .ei_abiversion = 0,
        },
        .e_type = std.elf.ET.DYN,
        .e_machine = std.elf.EM.X86_64,
        .e_version = .ev_current,
        .e_entry = 0x128,
        .e_phoff = 64,
        .e_shoff = 800,
        .e_flags = 0,
        .e_ehsize = @sizeOf(std.elf.Ehdr),
        .e_phentsize = @sizeOf(std.elf.Phdr),
        .e_phnum = 0,
        .e_shentsize = @sizeOf(std.elf.Shdr),
        .e_shnum = 2,
        .e_shstrndx = 1,
        .sections = Elf.Sections.init(t.allocator),
        .program_segments = Elf.ProgramSegments.init(t.allocator),
        .allocator = t.allocator,
    };
    try printElfHeader(out_buffer_stream.writer().any(), &elf);

    try t.expectEqualStrings(expected, &out_buffer);
}
