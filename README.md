# Binutils

Experimental binutils readelf and objcopy implementation.

Zig currently only has little support for binutils and the existing zig objcopy has very strict limitations:

* all sections must be ordered ascending by file offsets
* target endianness must match native endianness
* no section or program header can be relocated, meaning:
    * shstrtab must be the last section, otherwise adding a new seciton name may corrupt the headers (undected corruption?)
    * changing section alignment may corrupt headers that are not relocated by shifting sections contents into the header offset due to an increase alignment
    * sections cannot be resized
    * sections cannot be reordered
* testing is not viable due to scattered use of the file system and nested code

I may create a PR to the zig compiler **if** this turns out to be worthy to be reviewed by the zig team.

