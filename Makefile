# Convenience targets for temporary tests that are not meant to be part of build.zig
all:
	${MAKE} test
	${MAKE} test_integration
	${MAKE} build
	${MAKE} readelf
	${MAKE} readelf-args
	${MAKE} readelf-symbols
	${MAKE} objcopy
	${MAKE} objcopy-single-argument
	${MAKE} objcopy-add-section
	${MAKE} objcopy-only-section
	${MAKE} objcopy-pad-to-small
	${MAKE} objcopy-pad-to
	${MAKE} objcopy-set-section-flags
	${MAKE} objcopy-add-gnu-debuglink
	${MAKE} objcopy-add-gnu-debuglink-strip-debug
	${MAKE} objcopy-strip-debug
	${MAKE} objcopy-only-keep-debug
	${MAKE} objcopy-strip-all
	${MAKE} objcopy-compress-debug

.PHONY: release
release:
	zig build -Doptimize=ReleaseFast

.PHONY: watch
watch:
	zig build test --summary all --watch

.PHONY: build
build:
	zig build

.PHONY: test
test:
	zig build test --summary all

.PHONY: test_integration
test_integration:
	zig build test_integration --summary all

./reproduction/ls:
	mkdir -p ./reproduction
	cp /usr/bin/ls ./reproduction/ls

.PHONY: readelf
readelf: ./reproduction/ls
	zig build run -- readelf ./reproduction/ls

.PHONY: readelf-args
readelf-args: ./reproduction/ls
	zig build run -- readelf --file-header ./reproduction/ls --file-header --sections --segments -Shl

.PHONY: readelf-symbols
readelf-symbols: ./reproduction/ls
	zig build run -- readelf ./zig-out/bin/binutils --symbols

.PHONY: objcopy
objcopy: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_no_args
	zig build run -- readelf ./reproduction/ls_objcopy_no_args -hSl
	./reproduction/ls_objcopy_no_args

.PHONY: objcopy-single-argument
objcopy-single-argument: ./reproduction/ls
	cp ./reproduction/ls ./reproduction/ls_single_argument
	zig build run -- objcopy ./reproduction/ls_single_argument
	zig build run -- readelf ./reproduction/ls_single_argument -hSl
	./reproduction/ls_single_argument

.PHONY: objcopy-add-section
objcopy-add-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_add_section --add-section .abc=./reproduction/ls
	zig build run -- readelf ./reproduction/ls_objcopy_add_section -hSl
	./reproduction/ls_objcopy_add_section

.PHONY: objcopy-only-section
objcopy-only-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_only_section_text --only-section=.text
	# zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_only_section_text -j .text
	zig build run -- readelf ./reproduction/ls_objcopy_only_section_text -hSl

.PHONY: objcopy-pad-to-small
objcopy-pad-to-small: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_pad_to_small --pad-to 100
	zig build run -- readelf ./reproduction/ls_objcopy_pad_to_small -hSl
	./reproduction/ls_objcopy_pad_to_small

.PHONY: objcopy-pad-to
objcopy-pad-to: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_pad_to --pad-to 200000
	zig build run -- readelf ./reproduction/ls_objcopy_pad_to -hSl
	./reproduction/ls_objcopy_pad_to

.PHONY: objcopy-set-section-flags
objcopy-set-section-flags: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_set_section_flags --set-section-flags .text=alloc,load,readonly,code
	zig build run -- readelf ./reproduction/ls_objcopy_set_section_flags -hSl
	./reproduction/ls_objcopy_set_section_flags

.PHONY: objcopy-add-gnu-debuglink
objcopy-add-gnu-debuglink: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	objcopy ./reproduction/binutils ./reproduction/binutils.debug --only-keep-debug
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_add_gnu_debuglink --add-gnu-debuglink=binutils.debug
	readelf ./reproduction/binutils_add_gnu_debuglink -wA
	objdump ./reproduction/binutils_add_gnu_debuglink -Wk
	./reproduction/binutils_add_gnu_debuglink --help

.PHONY: objcopy-add-gnu-debuglink-strip-debug
objcopy-add-gnu-debuglink-strip-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	objcopy ./reproduction/binutils ./reproduction/binutils.debug --only-keep-debug
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_add_gnu_debuglink --add-gnu-debuglink=binutils.debug
	zig build run -- objcopy ./reproduction/binutils_add_gnu_debuglink ./reproduction/binutils_add_gnu_debuglink_stripped_debug --strip-debug
	readelf ./reproduction/binutils_add_gnu_debuglink_stripped_debug -wA
	objdump ./reproduction/binutils_add_gnu_debuglink_stripped_debug -Wk
	./reproduction/binutils_add_gnu_debuglink --help

.PHONY: objcopy-strip-debug
objcopy-strip-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_strip_debug --strip-debug
	zig build run -- readelf ./reproduction/binutils_strip_debug -hSl
	./reproduction/binutils_strip_debug --help
	@du -h ./reproduction/binutils
	@du -h ./reproduction/binutils_strip_debug

.PHONY: objcopy-only-keep-debug
objcopy-only-keep-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_only_keep_debug --only-keep-debug
	zig build run -- readelf ./reproduction/binutils_only_keep_debug -hSl
	readelf ./reproduction/binutils_only_keep_debug -S
	@du -h ./reproduction/binutils
	@du -h ./reproduction/binutils_only_keep_debug

.PHONY: objcopy-strip-all
objcopy-strip-all: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_strip_all --strip-all
	zig build run -- readelf ./reproduction/binutils_strip_all -hSl
	./reproduction/binutils_strip_all --help
	objcopy --strip-all ./reproduction/binutils ./reproduction/binutils_strip_all_gnu --strip-all
	zig build run -- readelf ./reproduction/binutils_strip_all -S
	zig build run -- readelf ./reproduction/binutils_strip_all_gnu -S
	@du -h ./reproduction/binutils
	@du -h ./reproduction/binutils_strip_all
	@du -h ./reproduction/binutils_strip_all_gnu

.PHONY: objcopy-compress-debug
objcopy-compress-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_compress_debug --compress-debug-sections
	zig build run -- readelf ./reproduction/binutils_compress_debug -hSl
	./reproduction/binutils_compress_debug --help
	@du -h ./reproduction/binutils
	@du -h ./reproduction/binutils_compress_debug
