# Node examples

- `ai-sdk-openai-demo.mjs`: direct TCP aTLS request to `vllm.concrete-security.com` using the native `atlas-node` binding and `@ai-sdk/openai`. Requires Rust 1.88+ (`cargo build -p atlas-node --release`) and dev deps (`pnpm add -D @ai-sdk/openai ai ws zod@^4`).
