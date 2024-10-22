# Convenience targets for temporary tests that are not meant to be part of build.zig
all:
	${MAKE} test
	${MAKE} build
	${MAKE} readelf
	${MAKE} readelf-args
	${MAKE} objcopy
	${MAKE} objcopy-add-section

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
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_out
	zig build run -- readelf ./reproduction/ls_out -hSl
	./reproduction/ls_out

.PHONY: objcopy-add-section
objcopy-add-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_out --add-section .abc=./reproduction/ls
	zig build run -- readelf ./reproduction/ls_out -hSl
	./reproduction/ls_out

.PHONY: objcopy-only-section
objcopy-only-section: ./reproduction/ls
	zig build run -- objcopy ./reproduction/ls ./reproduction/ls_out --only-section=.shstrtab
	zig build run -- readelf ./reproduction/ls_out -hSl
	./reproduction/ls_out
