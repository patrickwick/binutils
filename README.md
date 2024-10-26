# Binutils

binutils implementation aiming to improve the current zig objcopy ELF to ELF copying implementation in terms of robustness and limitations.
This implementation focusses on simple, robust and well tested code instead of providing a large feature set.

## Usage

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

  -l, --program-headers, segments
      Display program headers.

  -e, --headers
      Display file, section and program headers. Equivalent to -S -h -l.

  -s, --symbols, syms
      Display the symbol table.

General Options:

  --help
      Print command-specific usage
```

### Objcopy Usage

```
Usage: binutils objcopy [options] in-file out-file

Options:

  -j <section>, --only-section=<section>
      Remove all sections except <section> and the section name table section (.shstrtab).

  --pad-to <addr>
      Pad the last section up to address <addr>.

  -g, strip-debug
      Remove all debug sections from the output.

  -S, --strip-all
      Remove all debug sections and symbol table from the output.

  --only-keep-debug
      Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact.

  --add-gnu-debuglink=<file>
      Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.

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

* rejects input if program header loads a subset of a section. It has to load entire sections.
* ELF to ELF copying only
    * not planned to support PE/COFF ever
    * Mach-O maybe at some point

## TODO

* raw and hex output not support yet
* 64bit ELF files only due to compiler bug in inline else

### Current Zig Limitations

Zig objcopy currently has strict limitations:

* all input file sections must be ordered ascending by file offsets
    * does not work on ELF files created with zig itself
* target endianness must match native endianness
* no section or program header can be relocated, meaning:
    * shstrtab must be the last section, otherwise adding a new section name may corrupt the headers or section content (undected corruption?)
    * changing section alignment may corrupt headers that are not relocated by shifting sections contents into the header offset due to increased alignment
    * sections cannot be resized
    * sections cannot be reordered
* testing is difficult due to scattered use of the file system and nested code
* -j / --only-section and --pad-to are not supported for ELF to ELF copying
* no support for multiple single character arguments with single dash, e.g. `-gS`

There are many possible optimizations that won't be done before the existing zig objcopy ELF to ELF feature set without the limitations is achieved.
Input file modifications are avoided as much as possible, i.e.: sections and headers are only relocated when necessary.
