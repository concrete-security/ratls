/**
 * RA-TLS Fetch - A fetch-compatible API for attested TLS connections.
 *
 * This module handles HTTP/1.1 in JavaScript, delegating only TLS+attestation
 * to the WASM module. Uses native ReadableStream for efficient response streaming.
 */

import init, { AttestedStream } from "./ratls_wasm.js";

// ============================================================================
// WASM Initialization
// ============================================================================

let wasmReady;

async function ensureWasm() {
  if (!wasmReady) {
    wasmReady = init();
  }
  return wasmReady;
}

// ============================================================================
// URL Helpers
// ============================================================================

function isLoopbackHostname(host) {
  const value = host?.toLowerCase?.() || "";
  return value === "localhost" || value === "127.0.0.1" || value === "::1" || value.startsWith("127.");
}

function normalizeProxyUrl(raw) {
  if (!raw) return "";
  const candidate = /^wss?:\/\//i.test(raw) ? raw : `ws://${raw.replace(/^\/+/, "")}`;
  try {
    const url = new URL(candidate);
    const isProd = typeof process !== "undefined" && process?.env?.NODE_ENV === "production";
    if (isProd && url.protocol !== "wss:" && !isLoopbackHostname(url.hostname)) {
      throw new Error("RA-TLS proxy URL must use wss:// in production");
    }
    return url.toString();
  } catch (error) {
    if (error instanceof Error && /must use wss/i.test(error.message || "")) {
      throw error;
    }
    return candidate;
  }
}

function normalizeTarget(value) {
  if (!value) return "";
  return value.includes(":") ? value : `${value}:443`;
}

function buildProxyUrl(base, target) {
  const url = new URL(normalizeProxyUrl(base));
  if (target) {
    url.searchParams.set("target", target);
  }
  return url.toString();
}

// ============================================================================
// HTTP/1.1 Helpers
// ============================================================================

function buildHttpRequest(method, path, host, headers, body) {
  let request = `${method} ${path || "/"} HTTP/1.1\r\n`;
  request += `Host: ${host}\r\n`;
  request += `Connection: close\r\n`;

  for (const [name, value] of headers) {
    if (name.toLowerCase() !== "host") {
      request += `${name}: ${value}\r\n`;
    }
  }

  if (body && body.length > 0) {
    request += `Content-Length: ${body.length}\r\n`;
  }

  request += "\r\n";
  return request;
}

function parseHttpHeaders(text) {
  const lines = text.split("\r\n");
  const statusLine = lines[0];
  const match = statusLine.match(/^HTTP\/\d\.\d (\d+)(?: (.*))?$/);

  if (!match) {
    throw new Error(`Invalid HTTP response: ${statusLine}`);
  }

  const status = parseInt(match[1], 10);
  const statusText = match[2] || "";

  const headers = new Headers();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) break;
    const colonIndex = line.indexOf(":");
    if (colonIndex > 0) {
      const name = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      headers.append(name, value);
    }
  }

  return { status, statusText, headers };
}

/**
 * Create a TransformStream that separates HTTP headers from body.
 * Buffers until \r\n\r\n is found, parses headers, then passes through body.
 */
function createHeaderSeparator() {
  const endMarker = new Uint8Array([13, 10, 13, 10]); // \r\n\r\n
  let buffer = new Uint8Array(0);
  let headersParsed = false;
  let parsedHeaders = null;

  return {
    transform: new TransformStream({
      transform(chunk, controller) {
        if (headersParsed) {
          controller.enqueue(chunk);
          return;
        }

        // Append to buffer
        const newBuffer = new Uint8Array(buffer.length + chunk.length);
        newBuffer.set(buffer);
        newBuffer.set(chunk, buffer.length);
        buffer = newBuffer;

        // Search for header end
        const endIndex = findSequence(buffer, endMarker);
        if (endIndex !== -1) {
          // Parse headers
          const headerBytes = buffer.slice(0, endIndex);
          const headerText = new TextDecoder().decode(headerBytes);
          parsedHeaders = parseHttpHeaders(headerText);
          headersParsed = true;

          // Pass through remaining body data
          const bodyStart = endIndex + 4;
          if (bodyStart < buffer.length) {
            controller.enqueue(buffer.slice(bodyStart));
          }
          buffer = new Uint8Array(0);
        }
      },
      flush(controller) {
        if (!headersParsed && buffer.length > 0) {
          controller.error(new Error("Incomplete HTTP response headers"));
        }
      }
    }),
    getHeaders: () => parsedHeaders
  };
}

function findSequence(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

// ============================================================================
// Main API
// ============================================================================

/**
 * Create a fetch-compatible function for attested TLS connections.
 *
 * @param {Object} options
 * @param {string} options.proxyUrl - WebSocket proxy URL (e.g., "ws://127.0.0.1:9000")
 * @param {string} options.targetHost - Target TEE server (e.g., "vllm.example.com:443")
 * @param {string} [options.serverName] - TLS server name (defaults to hostname from targetHost)
 * @param {Object} [options.defaultHeaders] - Default headers to include in all requests
 * @param {Function} [options.onAttestation] - Callback when attestation is received
 * @returns {Function} A fetch-compatible async function
 */
export function createRatlsFetch(options) {
  const { proxyUrl, targetHost, serverName, defaultHeaders, onAttestation } = options;

  if (!proxyUrl || !targetHost) {
    throw new Error("proxyUrl and targetHost are required for RA-TLS fetch");
  }

  const normalizedTarget = normalizeTarget(targetHost);
  const sni = serverName || normalizedTarget.split(":")[0];
  const host = normalizedTarget.split(":")[1] === "443"
    ? normalizedTarget.split(":")[0]
    : normalizedTarget;
  const wsUrl = buildProxyUrl(proxyUrl, normalizedTarget);
  const base = new URL(`https://${normalizedTarget}`);

  return async function ratlsFetch(input, init = {}) {
    await ensureWasm();

    // Connect and get attested stream
    const stream = await AttestedStream.connect(wsUrl, sni);

    // Get attestation and notify callback
    const attestation = stream.attestation();
    if (onAttestation && typeof onAttestation === "function") {
      try {
        onAttestation(attestation);
      } catch (e) {
        console.warn("[ratls-fetch] onAttestation callback failed:", e);
      }
    }

    // Build request
    const request = new Request(input, init);
    const url = new URL(request.url, base);
    const path = `${url.pathname}${url.search}`;

    // Merge headers
    const headers = new Headers(defaultHeaders);
    request.headers.forEach((value, name) => headers.set(name, value));

    // Get body as Uint8Array
    let body = null;
    if (request.body) {
      body = new Uint8Array(await request.arrayBuffer());
    }

    // Build and send HTTP request
    const httpRequest = buildHttpRequest(
      request.method,
      path,
      host,
      headers.entries(),
      body
    );

    await stream.send(new TextEncoder().encode(httpRequest));
    if (body && body.length > 0) {
      await stream.send(body);
    }

    // Use the native ReadableStream from the WASM module
    // Pipe through header separator to extract HTTP headers
    const separator = createHeaderSeparator();
    const bodyStream = stream.readable.pipeThrough(separator.transform);

    // Read until headers are parsed
    const reader = bodyStream.getReader();
    const chunks = [];

    while (!separator.getHeaders()) {
      const { done, value } = await reader.read();
      if (done) {
        throw new Error("Stream ended before headers were complete");
      }
      if (value) {
        chunks.push(value);
      }
    }

    const parsedHeaders = separator.getHeaders();

    // Create response body that includes any leftover data from header parsing
    const responseBody = new ReadableStream({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(chunk);
        }
      },
      async pull(controller) {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
        } else {
          controller.enqueue(value);
        }
      },
      cancel() {
        reader.cancel();
      }
    });

    // Create Response object with attestation
    const response = new Response(responseBody, {
      status: parsedHeaders.status,
      statusText: parsedHeaders.statusText,
      headers: parsedHeaders.headers
    });

    // Attach attestation as non-enumerable property
    Object.defineProperty(response, "attestation", {
      value: attestation,
      enumerable: false,
      configurable: false,
      writable: false
    });

    return response;
  };
}

// Re-export AttestedStream for advanced usage
export { AttestedStream };

