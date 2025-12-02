# wasm (browser client)

wasm-bindgen wrapper around the Rust core to expose a TypeScript-friendly API for browsers. Carries TLS 1.3 inside WASM and uses WebSocket/WebTransport tunnels.

## Targets
- Expose `run_attestation_check(url, server_name)` for quick diagnostics.
- Provide `httpRequest` for HTTP/1.1 over RA-TLS with streaming bodies.
- Implement WebSocket transport (binary frames) first; abstract to allow WebTransport later.
- Use `crypto.getRandomValues` for RNG seeding; rely on `Date.now` for wall clock.

## Building the bindings

The crate is set up for `wasm-pack`:

```sh
cd ratls/wasm
wasm-pack build --target web --out-dir pkg
```

You can also run `make build-wasm` (or `./build-wasm.sh`) from the repo root, which wraps the same command and accepts the usual `WASM_TARGET`/`WASM_OUT_DIR` overrides.

This produces `pkg/ratls_wasm.{js,wasm}`. Building on macOS requires a Clang toolchain with WebAssembly targets enabled (e.g. `brew install llvm` and make sure `clang --target=wasm32-unknown-unknown` works). If your default Xcode clang lacks the wasm backend the build will fail before linking `ring`.

### Using the bindings

Once the bundle is built you can import it from any ESM environment (Next.js, plain `<script type="module">`, etc.):

```ts
import init, { httpRequest, run_attestation_check } from "ratls-wasm";

await init(); // load the wasm module

// 1. Fire-and-forget attestation check (returns the AttestationResult JSON)
const attestation = await run_attestation_check("ws://secure-enclave.com:443", "secure-enclave.com");
console.log(attestation);

// 2. Manual HTTP/1.1 over RA-TLS with a streaming body
const ratlsResponse = await httpRequest(
  "ws://secure-enclave.com:443",
  "secure-enclave.com",
  "secure-enclave.com:443", // Host header
  "POST",
  "/v1/chat/completions?stream=true",
  [{ name: "Content-Type", value: "application/json" }],
  new TextEncoder().encode(JSON.stringify({ hello: "world" }))
);
// Read with await ratlsResponse.readChunk() until it returns an empty Uint8Array, then await ratlsResponse.close().
// ratlsResponse.attestation() gives you the attestation result for logging/metrics.
```

`run_attestation_check` is ideal for diagnostics (fetch quote → verify → close). `httpRequest` returns a `RatlsResponse` that exposes `status`, `statusText`, `headers()`, `readChunk()`, and `close()` for streaming use cases.
