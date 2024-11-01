# Binutils

binutils implementation aiming to improve the current zig objcopy ELF to ELF copying implementation in terms of robustness and limitations.
This implementation focusses on simple, robust and well tested code instead of providing a large feature set.
It supports all features that the current zig objcopy implementation provides and more with a backward compatibile interface.

All features are available within the `build.zig` build system and using the command line.

## build.zig Usage

```zig
const exe = b.addExecutable(.{
    .name = "exe",
    .root_source_file = "exe.zig",
    .target = target,
    .optimize = optimize,
});
b.installArtifact(exe);

const exe_stripped = binutils.Build.Step.ObjCopy.create(b, exe.getEmittedBin(), .{
    .strip_all = true,
});
const exe_stripped_install = b.addInstallBinFile(exe_stripped.getOutput(), "exe_stripped");
b.getInstallStep().dependOn(&exe_stripped_install.step);
```

Please refer to [build.zig](build.zig) for more examples.

## Command Line Usage

```
Usage: binutils command [options]

Commands:

  readelf          Display information about ELF files
  objcopy          Copy and translate object files

General Options:

  -h, --help       Print command-specific usage
```

### Readelf Usage

```
Usage: binutils readelf [options] elf-file

Options:

  -h, --file-headers
      Display file headers.

  -S, --section-headers
      Display section headers.

  -l, --program-headers, --segments
      Display program headers.

  -e, --headers
      Display file, section and program headers. Equivalent to -S -h -l.

  -s, --symbols, --syms
      Display the symbol table.

General Options:

  --help
      Print command-specific usage
```

### Objcopy Usage

```
Usage: binutils objcopy [options] in-file [out-file]

Options:
  in-file
  out-file
      Input and output file paths. If you do not specify out-file or if is equivalent to in-file, a temporary file is used and the input file is only overwritten on success.

  -j <section>, --only-section=<section>
      Remove all sections except <section> and the section name table section (.shstrtab).

  --pad-to <addr>
      Pad the last section up to address <addr>. The address accepts decimal values, hex value with a "0x" prefix or binary values with a "0b" prefix.

  -g, strip-debug
      Remove all debug sections from the output.

  -S, --strip-all
      Remove all debug sections and symbol table from the output.

  --only-keep-debug
      Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact.

  --add-gnu-debuglink=<file>
      Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.
      The <file> path is relative to the in-file directory. Absolute paths are supported as well.

  --extract-to <file>
      Extract the removed sections into <file>, and add a .gnu-debuglink section.

  --compress-debug-sections
      Compress DWARF debug sections with zlib

  --set-section-alignment <name>=<align>
      Set alignment of section <name> to <align> bytes. Must be a power of two.

  --set-section-flags <name>=<flags>
      Set flags of section <name> to <flags> represented as a comma separated set of flags.

  --add-section <name>=<file>
      Add file content from <file> with the a new section named <name>.

General Options:

  -h, --help
      Print command-specific usage
```

## Limitations

* ELF to ELF copying only
    * Mach-O maybe at some point
    * PE/COFF: maybe if someone else wants to add it but I won't touch Windows with a ten foot pole
* not tested: running objcopy on a 32bit system on 64bit ELF files. It should work but may not
* OS or processor specific ELF types are not supported (std.elf.ET is exhaustive, would need an own implementation)

### Current Zig Limitations

Zig objcopy currently has strict limitations:

* all input file sections must be ordered ascending by file offsets
    * does not work on ELF files created with zig itself
* input file path cannot match output file path
* target endianness must match native endianness
* no section or program header can be relocated, meaning:
    * shstrtab must be the last section, otherwise adding a new section name may corrupt the headers or section content (undected corruption?)
    * changing section alignment may corrupt headers that are not relocated by shifting sections contents into the header offset due to increased alignment
    * sections cannot be resized
    * sections cannot be reordered
* gnu_debuglink paths are relative to working directory but should be relative to modified binary
* testing is difficult due to scattered use of the file system and nested code with scattered assumptions
* -j / --only-section and --pad-to are not supported for ELF to ELF copying
* no support for multiple single character arguments with single dash, e.g. `-gS`

