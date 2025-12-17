/**
 * Minimal RA-TLS Demo - Shows TEE attestation requirement
 */
import { init, createRatlsFetch } from "../pkg/ratls-fetch.js";

const PROXY = "ws://127.0.0.1:9000";
const output = document.getElementById("output");

function log(msg) {
  console.log(msg);
  output.textContent += msg + "\n";
}

async function run() {
  log("Initializing WASM...");
  await init();
  log("WASM ready.\n");

  // 1. Try connecting to a non-TEE server (will fail attestation)
  log("--- Attempting connection to google.com (non-TEE) ---");
  try {
    const badFetch = createRatlsFetch({ proxyUrl: PROXY, targetHost: "google.com" });
    await badFetch("/");
    log("Unexpected success!");
  } catch (error) {
    log("Expected failure: " + error.message);
  }

  // 2. Connect to a real TEE server (will succeed)
  log("\n--- Connecting to TEE server ---");
  try {
    const fetch = createRatlsFetch({ proxyUrl: PROXY, targetHost: "vllm.concrete-security.com" });

    const response = await fetch("/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "openai/gpt-oss-120b",
        messages: [{ role: "user", content: "Say hello in 10 words or less" }],
        max_tokens: 50
      })
    });

    log("Attestation: " + JSON.stringify(response.attestation, null, 2));
    const data = await response.json();
    log("Response: " + JSON.stringify(data, null, 2));
  } catch (error) {
    log("Error: " + error.message);
  }
}

run().catch(e => log("Fatal error: " + e.message));
