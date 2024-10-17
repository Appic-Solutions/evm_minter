# Makefile

# Load environment variables from .env
include .env

# Build target
build:
	@echo "Building Rust project..."
	cargo build --release --target wasm32-unknown-unknown --package evm_minter


