# Makefile

# Load environment variables from .env
include .env
export $(shell sed 's/=.*//' .env) # Export all variables from .env


# Build target
build:
	@echo "Building Rust project..."
	@echo "Ankr_Api_Key = $(Ankr_Api_Key)"
	@echo "Alchemy_Api_Key = $(Alchemy_Api_Key)"
	cargo build --release --target wasm32-unknown-unknown --package evm_minter


