/**
 * Unit tests for atls-fetch.js TTL functionality
 *
 * These tests verify session TTL without requiring actual TEE connections
 * by testing the TTL helper functions directly.
 *
 * Run with: node atls-fetch.test.js
 */

import { strict as assert } from "assert";
import { getSessionTTL, isConnectionExpired } from "./atls-fetch.js";

// Test helpers
let passed = 0;
let failed = 0;

function test(name, fn) {
  return async () => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(`    Error: ${err.message}`);
      failed++;
    }
  };
}

// ============================================================================
// Tests
// ============================================================================

const tests = [
  test("TTL defaults to 30 minutes", async () => {
    delete process.env.ATLS_SESSION_TTL_MINUTES;
    const ttl = getSessionTTL();
    assert.strictEqual(ttl, 30 * 60 * 1000, "Default TTL should be 30 minutes");
  }),

  test("TTL can be set via environment variable", async () => {
    process.env.ATLS_SESSION_TTL_MINUTES = "5";
    const ttl = getSessionTTL();
    assert.strictEqual(ttl, 5 * 60 * 1000, "TTL should be 5 minutes from env");
    delete process.env.ATLS_SESSION_TTL_MINUTES;
  }),

  test("TTL supports fractional minutes", async () => {
    process.env.ATLS_SESSION_TTL_MINUTES = "0.5";
    const ttl = getSessionTTL();
    assert.strictEqual(ttl, 30 * 1000, "TTL should be 30 seconds (0.5 minutes)");
    delete process.env.ATLS_SESSION_TTL_MINUTES;
  }),

  test("TTL ignores invalid environment values", async () => {
    process.env.ATLS_SESSION_TTL_MINUTES = "invalid";
    const ttl = getSessionTTL();
    assert.strictEqual(ttl, 30 * 60 * 1000, "TTL should fall back to default");
    delete process.env.ATLS_SESSION_TTL_MINUTES;
  }),

  test("TTL ignores zero or negative values", async () => {
    process.env.ATLS_SESSION_TTL_MINUTES = "0";
    let ttl = getSessionTTL();
    assert.strictEqual(ttl, 30 * 60 * 1000, "TTL should fall back to default for zero");

    process.env.ATLS_SESSION_TTL_MINUTES = "-5";
    ttl = getSessionTTL();
    assert.strictEqual(ttl, 30 * 60 * 1000, "TTL should fall back to default for negative");
    delete process.env.ATLS_SESSION_TTL_MINUTES;
  }),

  test("Connection is not expired immediately", async () => {
    delete process.env.ATLS_SESSION_TTL_MINUTES;
    const connectedAt = Date.now();
    assert.strictEqual(
      isConnectionExpired(connectedAt),
      false,
      "Connection should not be expired immediately"
    );
  }),

  test("Connection is not expired within TTL window", async () => {
    delete process.env.ATLS_SESSION_TTL_MINUTES; // 30 min default
    const connectedAt = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    assert.strictEqual(
      isConnectionExpired(connectedAt),
      false,
      "Connection should not be expired after 10 minutes (within 30 min TTL)"
    );
  }),

  test("Connection expires after TTL (short TTL test)", async () => {
    // Use 0.033 minutes = ~2 seconds for fast test
    process.env.ATLS_SESSION_TTL_MINUTES = "0.033";

    const connectedAt = Date.now();

    // Should not be expired immediately
    assert.strictEqual(
      isConnectionExpired(connectedAt),
      false,
      "Connection should not be expired immediately"
    );

    // Wait 2.5 seconds
    await new Promise((resolve) => setTimeout(resolve, 2500));

    // Should be expired now
    assert.strictEqual(
      isConnectionExpired(connectedAt),
      true,
      "Connection should be expired after 2.5 seconds with ~2 second TTL"
    );

    delete process.env.ATLS_SESSION_TTL_MINUTES;
  }),

  test("Old connection is correctly identified as expired", async () => {
    delete process.env.ATLS_SESSION_TTL_MINUTES; // 30 min default
    const connectedAt = Date.now() - 31 * 60 * 1000; // 31 minutes ago
    assert.strictEqual(
      isConnectionExpired(connectedAt),
      true,
      "Connection should be expired after 31 minutes (exceeds 30 min TTL)"
    );
  }),
];

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log("\nWASM aTLS TTL Tests\n");
  console.log("================================\n");

  for (const runTest of tests) {
    await runTest();
  }

  console.log("\n================================");
  console.log(`Results: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
