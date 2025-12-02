#!/usr/bin/env node

import { createRatlsFetch } from "./ratls-fetch.js"
import binding from "./index.js"

console.log("Testing ratls-node module...\n")

let testsPassed = 0
let testsFailed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`✓ ${name}`)
    testsPassed++
  } catch (error) {
    console.error(`✗ ${name}: ${error.message}`)
    testsFailed++
  }
}

try {
  test("Module imports successfully", () => {
    if (!createRatlsFetch) throw new Error("createRatlsFetch not exported")
  })
  
  test("Native binding loads", () => {
    if (!binding) throw new Error("Binding not loaded")
    if (typeof binding.httpRequest !== "function" && typeof binding.http_request !== "function") {
      throw new Error("httpRequest function not available")
    }
  })
  
  test("createRatlsFetch with string target", () => {
    const fetch = createRatlsFetch("example.com")
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
  })
  
  test("createRatlsFetch with options object", () => {
    let attestationCalled = false
    const fetch = createRatlsFetch({
      target: "example.com:443",
      headers: { "X-Test": "value" },
      onAttestation: (att) => {
        attestationCalled = true
      }
    })
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
  })
  
  test("createRatlsFetch with port in target", () => {
    const fetch = createRatlsFetch("example.com:8443")
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
  })
  
  test("createRatlsFetch error handling - missing target", () => {
    try {
      createRatlsFetch({})
      throw new Error("Should have thrown error for missing target")
    } catch (e) {
      if (!e.message.includes("target is required")) {
        throw new Error(`Wrong error: ${e.message}`)
      }
    }
  })
  
  test("Streaming API available", () => {
    const hasStreaming = 
      (typeof binding.httpStreamRequest === "function" || typeof binding.http_stream_request === "function") &&
      (typeof binding.streamRead === "function" || typeof binding.stream_read === "function") &&
      (typeof binding.streamClose === "function" || typeof binding.stream_close === "function")
    if (!hasStreaming) {
      console.log("  (Streaming API not available, using buffered mode)")
    }
  })
  
  test("Low-level bindings available from binding export", async () => {
    const bindingExports = await import("./index.js")
    if (typeof bindingExports.httpRequest !== "function") {
      throw new Error("httpRequest not exported from index.js")
    }
    if (typeof bindingExports.httpStreamRequest !== "function") {
      throw new Error("httpStreamRequest not exported from index.js")
    }
    if (typeof bindingExports.streamRead !== "function") {
      throw new Error("streamRead not exported from index.js")
    }
    if (typeof bindingExports.streamClose !== "function") {
      throw new Error("streamClose not exported from index.js")
    }
  })
  
  test("Main entry point only exports high-level API", async () => {
    const mainExports = await import("./ratls-fetch.js")
    if (typeof mainExports.createRatlsFetch !== "function") {
      throw new Error("createRatlsFetch not exported from ratls-fetch.js")
    }
    if (typeof mainExports.httpRequest === "function") {
      throw new Error("httpRequest should not be exported from main entry point - use 'ratls-node/binding' instead")
    }
  })
  
  console.log(`\n✅ Tests passed: ${testsPassed}`)
  if (testsFailed > 0) {
    console.error(`❌ Tests failed: ${testsFailed}`)
    process.exit(1)
  }
  
  console.log("\nNote: Full functionality test requires a valid TEE endpoint.")
  console.log("Run: node examples/ai-sdk-openai-demo.mjs for end-to-end test.")
  
} catch (error) {
  console.error("❌ Test suite failed:", error.message)
  console.error(error.stack)
  process.exit(1)
}

