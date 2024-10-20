# Binutils

Experimental objcopy implementation aiming to improve the current zig objcopy implementation in terms of robustness and limitations.

I may create a PR to the zig compiler **if** this turns out to be worthy to be reviewed by the zig team.

Zig objcopy currently has strict limitations:

* all input file sections must be ordered ascending by file offsets
* target endianness must match native endianness
* no section or program header can be relocated, meaning:
    * shstrtab must be the last section, otherwise adding a new section name may corrupt the headers or section content (undected corruption?)
    * changing section alignment may corrupt headers that are not relocated by shifting sections contents into the header offset due to increased alignment
    * sections cannot be resized
    * sections cannot be reordered
* testing is difficult due to scattered use of the file system and nested code

## Usage

```
Usage: binutils command [options]

Commands:

  readelf          Display information about ELF files
  objdump          Display information from object files
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

General Options:

  --help
      Print command-specific usage

```

### Objcopy Usage

```
Usage: binutils objcopy [options] in-file out-file

Options:

General Options:

  -h, --help
      Print command-specific usage

```

## Limitations

* rejects input if program header loads a subset of a section. It has to load the entire section or nothing at all.

