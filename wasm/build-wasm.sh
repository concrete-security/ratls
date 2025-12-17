#!/usr/bin/env bash
set -euo pipefail

WASM_DIR="$(cd -- "$(dirname "$0")" && pwd)"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found in PATH. Install it via 'cargo install wasm-pack'." >&2
  exit 1
fi

TARGET="${WASM_TARGET:-web}"
OUT_DIR="${WASM_OUT_DIR:-pkg}"

echo "Building ratls-wasm (target=${TARGET}, out-dir=${OUT_DIR})"
cd "$WASM_DIR"
wasm-pack build --target "$TARGET" --out-dir "$OUT_DIR" "$@"

cp -f "$WASM_DIR/src/ratls-fetch.js" "$WASM_DIR/$OUT_DIR/" 2>/dev/null || true
cp -f "$WASM_DIR/src/ratls-fetch.d.ts" "$WASM_DIR/$OUT_DIR/" 2>/dev/null || true
