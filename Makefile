.PHONY: help test test-all test-wasm build build-wasm build-node test-node clean

CARGO ?= cargo

help:
	@echo "Available targets:"
	@echo "  make test         # run native Rust tests (core, node, proxy)"
	@echo "  make test-wasm    # cargo check ratls-wasm for wasm32 target"
	@echo "  make test-node    # run Node.js binding tests"
	@echo "  make test-all     # run all tests (native + node)"
	@echo ""
	@echo "  make build        # build all native crates"
	@echo "  make build-wasm   # build WASM package with wasm-pack"
	@echo "  make build-node   # build Node.js native bindings"
	@echo ""
	@echo "  make clean        # clean all build artifacts"

# Native Rust tests (excludes WASM crate which needs special toolchain)
test:
	$(CARGO) test --workspace --exclude ratls-wasm

# Check WASM crate compiles for wasm32 target
test-wasm:
	$(CARGO) check -p ratls-wasm --target wasm32-unknown-unknown

# Node.js binding tests
test-node:
	cd node && pnpm test

# All tests
test-all: test test-node

# Build all native crates
build:
	$(CARGO) build --workspace --exclude ratls-wasm

# Build WASM package
build-wasm:
	wasm/build-wasm.sh

# Build Node.js bindings
build-node:
	cd node && pnpm build

# Clean all artifacts
clean:
	$(CARGO) clean
	rm -rf wasm/pkg
	rm -rf node/*.node node/index.cjs
