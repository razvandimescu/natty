.PHONY: build test lint audit fuzz fuzz-cmin

FUZZ_TOOLCHAIN := nightly-2025-12-01
FUZZ_TARGET ?= frame
FUZZ_SECONDS ?= 60
# --target: cargo-fuzz defaults to the triple it was built for, which is musl
# when it comes from cargo-binstall or install-action. -s none: ASan hangs
# before main on recent macOS.
FUZZ_FLAGS = --target $(shell rustc +$(FUZZ_TOOLCHAIN) --print host-tuple) \
	$(if $(filter Darwin,$(shell uname -s)),-s none)

build:
	cargo build
test:
	cargo test
lint: audit
	cargo fmt --check
	cargo fmt --check --manifest-path fuzz/Cargo.toml
	cargo clippy --all-targets -- -D warnings
audit:
	cargo audit
# New inputs go to the first directory, so fuzz/seeds stays as committed.
fuzz:
	mkdir -p fuzz/corpus/$(FUZZ_TARGET)
	cargo +$(FUZZ_TOOLCHAIN) fuzz run $(FUZZ_FLAGS) $(FUZZ_TARGET) \
		fuzz/corpus/$(FUZZ_TARGET) fuzz/seeds/$(FUZZ_TARGET) \
		-- -max_total_time=$(FUZZ_SECONDS) -max_len=4096 -timeout=25
fuzz-cmin:
	cargo +$(FUZZ_TOOLCHAIN) fuzz cmin $(FUZZ_FLAGS) $(FUZZ_TARGET) -- -timeout=25
