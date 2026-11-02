.PHONY: build test lint audit fuzz

FUZZ_TOOLCHAIN := nightly-2025-12-01
FUZZ_TARGET ?= frame
FUZZ_SECONDS ?= 60
# cargo-fuzz builds for its own triple, which is musl when it comes from cargo-binstall.
FUZZ_TRIPLE = $(shell rustc +$(FUZZ_TOOLCHAIN) -vV | sed -n 's/^host: //p')

build:
	cargo build
test:
	cargo test
lint: audit
	cargo fmt --check && cargo clippy --all-targets -- -D warnings
audit:
	cargo audit
# ASan hangs before main on recent macOS, so local runs there use no sanitizer.
fuzz:
	mkdir -p fuzz/corpus/$(FUZZ_TARGET)
	cargo +$(FUZZ_TOOLCHAIN) fuzz run --target $(FUZZ_TRIPLE) \
		$(if $(filter Darwin,$(shell uname -s)),-s none,) \
		$(FUZZ_TARGET) fuzz/corpus/$(FUZZ_TARGET) fuzz/seeds/$(FUZZ_TARGET) \
		-- -max_total_time=$(FUZZ_SECONDS) -max_len=4096 -timeout=25
