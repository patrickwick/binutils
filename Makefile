# Convenience targets for temporary tests that are not meant to be part of build.zig
all:
	${MAKE} activate_master
	${MAKE} all_tests
	${MAKE} activate_v13
	${MAKE} all_tests

.PHONY: all_tests
all_tests:
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
	${MAKE} objcopy-remove-section
	${MAKE} objcopy-pad-to-small
	${MAKE} objcopy-pad-to
	${MAKE} objcopy-set-section-flags
	${MAKE} objcopy-add-gnu-debuglink
	${MAKE} objcopy-add-gnu-debuglink-strip-debug
	${MAKE} objcopy-strip-debug
	${MAKE} objcopy-only-keep-debug
	${MAKE} objcopy-strip-all
	${MAKE} objcopy-compress-debug
	${MAKE} release

.PHONY: activate_master
activate_master:
	zigup default master

.PHONY: activate_v13
activate_v13:
	zigup default 0.13.0

.PHONY: release
release:
	zig build -Doptimize=ReleaseFast --prefix zig-out-release

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
	eu-elflint ./reproduction/ls_objcopy_no_args --strict

.PHONY: objcopy-single-argument
objcopy-single-argument: ./reproduction/ls
	cp ./reproduction/ls ./reproduction/ls_single_argument
	zig build run -- objcopy ./reproduction/ls_single_argument
	zig build run -- readelf ./reproduction/ls_single_argument -hSl
	./reproduction/ls_single_argument
	eu-elflint ./reproduction/ls_single_argument --strict

.PHONY: objcopy-add-section
objcopy-add-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_add_section --add-section .abc=./reproduction/ls
	zig build run -- readelf ./reproduction/ls_objcopy_add_section -hSl
	readelf ./reproduction/ls_objcopy_add_section -x .shstrtab
	./reproduction/ls_objcopy_add_section
	eu-elflint ./reproduction/ls_objcopy_add_section --strict

.PHONY: objcopy-only-section
objcopy-only-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_only_section_text --only-section=.text
	zig build run -- readelf ./reproduction/ls_objcopy_only_section_text -hSl
	# eu-elflint ./reproduction/ls_objcopy_only_section_text --strict

.PHONY: objcopy-remove-section
objcopy-remove-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_remove_section --remove-section=.eh_frame
	zig build run -- readelf ./reproduction/ls_objcopy_remove_section -hSl
	eu-elflint ./reproduction/ls_objcopy_remove_section --strict

.PHONY: objcopy-pad-to-small
objcopy-pad-to-small: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_pad_to_small --pad-to 0x80
	zig build run -- readelf ./reproduction/ls_objcopy_pad_to_small -hSl
	./reproduction/ls_objcopy_pad_to_small
	eu-elflint ./reproduction/ls_objcopy_pad_to_small --strict
	@du -b ./reproduction/ls
	@du -b ./reproduction/ls_objcopy_pad_to_small

.PHONY: objcopy-pad-to
objcopy-pad-to: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_pad_to --pad-to 200000
	zig build run -- readelf ./reproduction/ls_objcopy_pad_to -hSl
	./reproduction/ls_objcopy_pad_to
	eu-elflint ./reproduction/ls_objcopy_pad_to --strict
	@du -b ./reproduction/ls
	@du -b ./reproduction/ls_objcopy_pad_to

.PHONY: objcopy-set-section-flags
objcopy-set-section-flags: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_set_section_flags --set-section-flags .text=alloc,load,readonly,code
	zig build run -- readelf ./reproduction/ls_objcopy_set_section_flags -hSl
	./reproduction/ls_objcopy_set_section_flags
	eu-elflint ./reproduction/ls_objcopy_set_section_flags --strict

.PHONY: objcopy-add-gnu-debuglink
objcopy-add-gnu-debuglink: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	objcopy ./reproduction/binutils ./reproduction/binutils.debug --only-keep-debug
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_add_gnu_debuglink --add-gnu-debuglink=binutils.debug
	readelf ./reproduction/binutils_add_gnu_debuglink -wA
	objdump ./reproduction/binutils_add_gnu_debuglink -Wk
	./reproduction/binutils_add_gnu_debuglink --help
	# eu-elflint ./reproduction/binutils_add_gnu_debuglink --strict

.PHONY: objcopy-add-gnu-debuglink-strip-debug
objcopy-add-gnu-debuglink-strip-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils.debug --only-keep-debug
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_add_gnu_debuglink --add-gnu-debuglink=binutils.debug
	zig build run -- objcopy ./reproduction/binutils_add_gnu_debuglink ./reproduction/binutils_add_gnu_debuglink_stripped_debug --strip-debug
	readelf ./reproduction/binutils_add_gnu_debuglink_stripped_debug -wA
	objdump ./reproduction/binutils_add_gnu_debuglink_stripped_debug -Wk
	./reproduction/binutils_add_gnu_debuglink --help
	# eu-elflint ./reproduction/binutils.debug --strict
	# FIXME: st_shndx should already be updated in STT_SECTION symbols
	# eu-elflint ./reproduction/binutils_add_gnu_debuglink_stripped_debug --strict
	# eu-elflint ./reproduction/binutils_add_gnu_debuglink --strict

.PHONY: objcopy-strip-debug
objcopy-strip-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_strip_debug --strip-debug
	zig build run -- readelf ./reproduction/binutils_strip_debug -hSl
	./reproduction/binutils_strip_debug --help
	# FIXME: st_shndx should already be updated in STT_SECTION symbols
	# eu-elflint ./reproduction/binutils_strip_debug --strict
	objcopy --strip-all ./reproduction/binutils ./reproduction/binutils_strip_debug_gnu --strip-all
	@du -b ./reproduction/binutils
	@du -b ./reproduction/binutils_strip_debug
	@du -b ./reproduction/binutils_strip_debug_gnu

.PHONY: objcopy-only-keep-debug
objcopy-only-keep-debug: ./reproduction/ls
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_only_keep_debug --only-keep-debug
	zig build run -- readelf ./reproduction/binutils_only_keep_debug -hSl
	readelf ./reproduction/binutils_only_keep_debug -S
	# TODO: update st_value
	# eu-elflint ./reproduction/binutils_only_keep_debug --strict
	@du -b ./reproduction/binutils
	@du -b ./reproduction/binutils_only_keep_debug

.PHONY: objcopy-strip-all
objcopy-strip-all: ./zig-out/bin/binutils
	cp ./zig-out/bin/binutils ./reproduction/binutils
	zig build run -- objcopy ./reproduction/binutils ./reproduction/binutils_strip_all --strip-all
	zig build run -- readelf ./reproduction/binutils_strip_all -hSl
	./reproduction/binutils_strip_all --help
	# NOTE: elflint does not like how zig creates NOBITS sections => not related to objcopy
	# eu-elflint ./reproduction/binutils_strip_all --strict
	objcopy --strip-all ./reproduction/binutils ./reproduction/binutils_strip_all_gnu --strip-all
	@du -b ./reproduction/binutils
	@du -b ./reproduction/binutils_strip_all
	@du -b ./reproduction/binutils_strip_all_gnu

.PHONY: objcopy-compress-debug
objcopy-compress-debug: ./zig-out/test/test_base_x86_64
	cp ./zig-out/test/test_base_x86_64 ./reproduction/test_base_x86_64
	zig build run -- objcopy ./reproduction/test_base_x86_64 ./reproduction/test_base_x86_64_compress_debug --compress-debug-sections
	zig build run -- readelf ./reproduction/test_base_x86_64_compress_debug -hSl
	./reproduction/test_base_x86_64_compress_debug --help
	# NOTE: elflint does not like how zig creates NOBITS sections => not related to objcopy
	# eu-elflint ./reproduction/test_base_x86_64_compress_debug --strict
	readelf ./reproduction/test_base_x86_64_compress_debug --debug-dump | head
	objcopy ./reproduction/test_base_x86_64 ./reproduction/test_base_x86_64_compress_debug_gnu --compress-debug-sections
	@du -b ./reproduction/test_base_x86_64
	@du -b ./reproduction/test_base_x86_64_compress_debug
	@du -b ./reproduction/test_base_x86_64_compress_debug_gnu
