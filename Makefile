.PHONY: build run test clean fmt lint

build:
	cargo build --release

run:
	cargo run -- --help

test:
	cargo test

clean:
	cargo clean

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings