# Binutils

binutils implementation aiming to improve the current zig objcopy ELF to ELF copying implementation in terms of robustness and limitations.
This implementation focusses on simple, robust and well tested code instead of providing a large feature set.
It supports all features of the current zig objcopy implementation except `--extract-to` with a backward compatible interface and more.

All features are available within the `build.zig` build system and using the command line.

## build.zig Usage

Strip executable:

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

Split the debug sections into a separate file:

```zig
// objcopy: debug split convenience function equivalent to:
// * objcopy in exe --strip-debug
// * objcopy in exe.debug --only-keep-debug
// * objcopy out --add-gnu-debuglink=exe.debug
const objcopy_target = binutils.Build.Step.ObjCopy.create(b, exe.getEmittedBin(), .{
    .extract_to_separate_file = "exe_debug_only",
});

const objcopy_install = b.addInstallBinFile(objcopy_target.getOutput(), "exe");
b.getInstallStep().dependOn(&objcopy_install.step);

const objcopy_debug_install = b.addInstallBinFile(exe_stripped.getOutputSeparatedDebug().?, "exe.debug");
b.getInstallStep().dependOn(&objcopy_debug_install.step);
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
      Remove all sections except <section> and the section name table section (.shstrtab). Compacts the ELF file after removal.
      NOTE: supports only a section name. Section patterns are not supported yet.

  -R <section>, --remove-section=<section>
      Remove section <section>. Compacts the ELF file after removal.
      Does not allow the removal of the section name table section (.shstrtab) and first null section.
      NOTE: supports only a section name. Section patterns are not supported yet.

  --pad-to <addr>
      Pad the last section up to address <addr>. The address accepts decimal values, hex value with a "0x" prefix or binary values with a "0b" prefix.

  -g, strip-debug
      Remove all debug sections from the output. Compacts the ELF file after removal.

  -S, --strip-all
      Remove all debug sections and symbol table from the output.

  --only-keep-debug
      Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact. Compacts the ELF file after removal.

  --add-gnu-debuglink=<file>
      Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.
      The <file> path is relative to the in-file directory. Absolute paths are supported as well.

  --compress-debug-sections
      Compress DWARF debug sections with zlib. Compacts the ELF file after compression.

  --set-section-alignment <name>=<align>
      Set address alignment of section <name> to <align> bytes. Must be a power of two.
      This only affects the section address, not the section offset within the file.

  --set-section-flags <name>=<flags>
      Set flags of section <name> to <flags> represented as a comma separated set of flags.

  --add-section <name>=<file>
      Add file content from <file> with the a new section named <name>.
      The address alginment (sh_addralign) is set to 4 byte by default but can be overwritten using the --set-section-alignment option.

General Options:

  -h, --help
      Print command-specific usage
```

## Limitations

* `zig objcopy --extract-to <file>` is not supported. Justification:
    * it's neither a GNU nor LLVM binutil option
    * can easily achieved by combining --add-gnu-debuglink and --only-keep-debug
        * e.g., see the `extract_to_separate_file` helper for `build.zig`
        * adding this option complicates the code too much since it's adding hard to test combinations between options
* ELF to ELF copying only
    * Mach-O maybe at some point
    * PE/COFF: maybe if someone else wants to add it but I won't touch Windows with a ten foot pole
* not tested: running objcopy on a 32bit system on 64bit ELF files. It should work but may not
* OS or processor specific ELF types are not supported (std.elf.ET is exhaustive, would need an own implementation)
* requires zig 0.14.0-dev.2051+b1361f237 or later. A zig 0.13.0 backport will follow

### Current Zig Limitations

Zig objcopy currently has strict limitations:

* most importantly, all input file sections must be ordered ascending by file offsets
    * does not work on ELF files created with zig itself
* input file path cannot match output file path
* target endianness must match native endianness
* shstrtab must be the last section, otherwise adding a new section name may corrupt the headers or section content (undected corruption?)
* gnu_debuglink paths are relative to working directory but should be relative to modified binary
* testing is difficult due to scattered use of the file system and nested code with scattered assumptions
* -j / --only-section and --pad-to are not supported for ELF to ELF copying
* no support for multiple single character arguments with single dash, e.g. `-gS`

