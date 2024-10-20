# Convenience targets for temporary tests that are not meant to be part of build.zig
all:
	${MAKE} build
	${MAKE} test
	${MAKE} readelf
	${MAKE} readelf-args
	${MAKE} objcopy

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
