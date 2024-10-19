# Convenience targets for temporary tests that are not meant to be part of build.zig
all: test

.PHONY: watch
watch:
	zig build test --summary all --watch

.PHONY: test
test:
	zig build test --summary all

./reproduction/ls:
	mkdir -p ./reproduction
	cp /usr/bin/ls ./reproduction/ls

.PHONY: readelf
readelf: ./reproduction/ls
	zig build run -- readelf ./reproduction/ls

