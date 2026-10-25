.PHONY: build test lint audit
build:
	cargo build
test:
	cargo test
lint: audit
	cargo fmt --check && cargo clippy --all-targets -- -D warnings
audit:
	cargo audit
