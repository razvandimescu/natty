.PHONY: build test lint audit version check-version fuzz fuzz-cmin

FUZZ_TOOLCHAIN := nightly-2025-12-01
FUZZ_TARGET ?= frame
FUZZ_SECONDS ?= 60
# --target: cargo-fuzz defaults to the triple it was built for, which is musl
# when it comes from cargo-binstall or install-action. -s none: ASan hangs
# before main on recent macOS.
FUZZ_FLAGS = --target $(shell rustc +$(FUZZ_TOOLCHAIN) --print host-tuple) \
	$(if $(filter Darwin,$(shell uname -s)),-s none)

# --all-features: the tunnel module and the natty binary are behind features.
build:
	cargo build --all-features
test:
	cargo test --all-features
lint: audit
	cargo fmt --check
	cargo fmt --check --manifest-path fuzz/Cargo.toml
	cargo clippy --all-targets --all-features -- -D warnings
audit:
	cargo audit
version:
	perl scripts/version.pl set $(V)
check-version:
	perl scripts/version.pl check
# New inputs go to the first directory, so fuzz/seeds stays as committed.
fuzz:
	mkdir -p fuzz/corpus/$(FUZZ_TARGET)
	cargo +$(FUZZ_TOOLCHAIN) fuzz run $(FUZZ_FLAGS) $(FUZZ_TARGET) \
		fuzz/corpus/$(FUZZ_TARGET) fuzz/seeds/$(FUZZ_TARGET) \
		-- -max_total_time=$(FUZZ_SECONDS) -max_len=4096 -timeout=25
fuzz-cmin:
	cargo +$(FUZZ_TOOLCHAIN) fuzz cmin $(FUZZ_FLAGS) $(FUZZ_TARGET) -- -timeout=25
