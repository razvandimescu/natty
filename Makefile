.PHONY: build test lint
build:
	cargo build
test:
	cargo test
lint:
	cargo fmt --check && cargo clippy --all-targets -- -D warnings
