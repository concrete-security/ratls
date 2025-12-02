.PHONY: help test test-wasm build-wasm

CARGO ?= cargo
WASM_ARGS ?=

help:
	@echo "Available targets:"
	@echo "  make test         # run all native Rust tests (workspace, excluding wasm crate)"
	@echo "  make test-wasm    # cargo check ratls-wasm"
	@echo "  make build-wasm   # run wasm-pack build (see build-wasm.sh for overrides)"

test:
	$(CARGO) test --workspace --exclude ratls-wasm

test-wasm:
	$(CARGO) check -p ratls-wasm --target wasm32-unknown-unknown

build-wasm:
	./build-wasm.sh $(WASM_ARGS)
