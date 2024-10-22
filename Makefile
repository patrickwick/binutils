# Convenience targets for temporary tests that are not meant to be part of build.zig
all:
	${MAKE} test
	${MAKE} build
	${MAKE} readelf
	${MAKE} readelf-args
	${MAKE} objcopy
	${MAKE} objcopy-add-section
	${MAKE} objcopy-only-section

.PHONY: watch
watch:
	zig build test --summary all --watch

.PHONY: build
build:
	zig build

.PHONY: test
test:
	zig build test --summary all

./reproduction/ls:
	mkdir -p ./reproduction
	cp /usr/bin/ls ./reproduction/ls

.PHONY: readelf
readelf: ./reproduction/ls
	zig build run -- readelf ./reproduction/ls

.PHONY: readelf-args
readelf-args: ./reproduction/ls
	zig build run -- readelf --file-header ./reproduction/ls --file-header --sections --segments -Shl

.PHONY: objcopy
objcopy: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_objcopy_no_args
	zig build run -- readelf ./reproduction/ls_objcopy_no_args -hSl
	./reproduction/ls_objcopy_no_args

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
