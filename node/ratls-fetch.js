/**
 * RA-TLS Fetch - Elegant fetch wrapper for attested TLS connections
 *
 * @example Simple usage
 * ```js
 * import { createRatlsFetch } from "ratls-node"
 * const fetch = createRatlsFetch("vllm.example.com")
 * ```
 *
 * @example With options
 * ```js
 * const fetch = createRatlsFetch({
 *   target: "vllm.example.com",
 *   headers: { Authorization: "Bearer ..." },
 *   onAttestation: (att) => console.log("TEE:", att.teeType)
 * })
 * ```
 */

import binding from "./index.js"

const ATTESTATION_HEADER = "x-ratls-attestation"

// Resolve binding functions (handle both snake_case and camelCase exports)
const httpRequest = binding.http_request || binding.httpRequest
const streamRequest = binding.http_stream_request || binding.httpStreamRequest
const streamRead = binding.stream_read || binding.streamRead
const streamClose = binding.stream_close || binding.streamClose

/**
 * Parse target host string into host:port format
 * @param {string} target - Host with optional port
 * @returns {{ host: string, port: string, hostPort: string, serverName: string }}
 */
function parseTarget(target) {
  const trimmed = target.trim()
  // Remove protocol prefix if present
  const withoutProtocol = trimmed.replace(/^https?:\/\//, "")
  // Remove path if present
  const hostPart = withoutProtocol.split("/")[0]

  const [host, port = "443"] = hostPart.split(":")
  return {
    host,
    port,
    hostPort: `${host}:${port}`,
    serverName: host,
  }
}

/**
 * Create an RA-TLS enabled fetch function
 *
 * @param {string | RatlsFetchOptions} optionsOrTarget - Target host or options object
 * @returns {RatlsFetch} A fetch-compatible function with attestation support
 *
 * @example
 * // Simple: just provide the target
 * const fetch = createRatlsFetch("enclave.example.com")
 *
 * @example
 * // Full options
 * const fetch = createRatlsFetch({
 *   target: "enclave.example.com:8443",
 *   headers: { Authorization: `Bearer ${token}` },
 *   onAttestation: (attestation) => {
 *     if (!attestation.trusted) throw new Error("Untrusted enclave!")
 *   }
 * })
 */
export function createRatlsFetch(optionsOrTarget) {
  // Normalize options: accept string shorthand or full options object
  const options =
    typeof optionsOrTarget === "string"
      ? { target: optionsOrTarget }
      : optionsOrTarget

  // Support both 'target' (new) and 'targetHost' (legacy) for backwards compatibility
  const targetRaw = options.target || options.targetHost
  if (!targetRaw) {
    throw new Error("target is required (e.g., 'enclave.example.com' or 'enclave.example.com:443')")
  }

  const parsed = parseTarget(targetRaw)
  const targetHost = parsed.hostPort
  // Infer serverName (SNI) from target if not explicitly provided
  const serverName = options.serverName || parsed.serverName
  const defaultHeaders = options.headers || options.defaultHeaders
  const onAttestation = options.onAttestation

  // Validate binding availability
  if (typeof httpRequest !== "function") {
    throw new Error(
      `ratls-node binding not loaded correctly. Available exports: ${Object.keys(binding).join(", ")}`
    )
  }

  const useStreaming =
    typeof streamRequest === "function" &&
    typeof streamRead === "function" &&
    typeof streamClose === "function"

  /**
   * Fetch function with RA-TLS attestation
   * @param {RequestInfo | URL} input
   * @param {RequestInit} [init]
   * @returns {Promise<Response & { attestation: RatlsAttestation }>}
   */
  return async function ratlsFetch(input, init = {}) {
    const req = new Request(input, init)
    const url = new URL(req.url, `https://${targetHost}`)

    // Merge default headers with request headers
    const headers = new Headers(defaultHeaders || undefined)
    req.headers.forEach((value, name) => headers.set(name, value))
    const headerEntries = Array.from(headers.entries()).map(([name, value]) => ({
      name,
      value,
    }))

    const body =
      req.body === null ? undefined : Buffer.from(await req.arrayBuffer())

    const path = `${url.pathname}${url.search}`
    const method = req.method || "GET"

    // Use streaming API if available (preferred for SSE/chunked responses)
    if (useStreaming) {
      const resp = await streamRequest(
        targetHost,
        serverName,
        method,
        path,
        headerEntries,
        body
      )

      const attestation = normalizeAttestation(resp.attestation)

      // Fire attestation callback
      if (onAttestation) {
        try {
          onAttestation(attestation)
        } catch (err) {
          // Don't let callback errors break the request
          console.warn("[ratls] onAttestation callback error:", err)
        }
      }

      const responseHeaders = new Headers()
      resp.headers.forEach(({ name, value }) => responseHeaders.append(name, value))
      responseHeaders.set(ATTESTATION_HEADER, JSON.stringify(attestation))

      const streamId = resp.stream_id || resp.streamId || 0
      let done = !streamId
      const bodyStream = new ReadableStream({
        async pull(controller) {
          if (done) {
            controller.close()
            return
          }
          const chunk = await streamRead(streamId, 4096)
          if (!chunk || chunk.length === 0) {
            done = true
            await streamClose(streamId).catch(() => {})
            controller.close()
            return
          }
          controller.enqueue(chunk)
        },
        async cancel() {
          if (streamId) {
            await streamClose(streamId).catch(() => {})
          }
        },
      })

      return createResponse(bodyStream, resp.status, resp.status_text || resp.statusText, responseHeaders, attestation)
    }

    // Fallback to buffered request
    const resp = await httpRequest(
      targetHost,
      serverName,
      method,
      path,
      headerEntries,
      body
    )

    const attestation = normalizeAttestation(resp.attestation)

    // Fire attestation callback
    if (onAttestation) {
      try {
        onAttestation(attestation)
      } catch (err) {
        console.warn("[ratls] onAttestation callback error:", err)
      }
    }

    const responseHeaders = new Headers()
    resp.headers.forEach(({ name, value }) => responseHeaders.append(name, value))
    responseHeaders.set(ATTESTATION_HEADER, JSON.stringify(attestation))

    // Stream the body in chunks for consistency with streaming path
    const bodyBuf = new Uint8Array(resp.body)
    const chunkSize = 2048
    let offset = 0
    const bodyStream = new ReadableStream({
      pull(controller) {
        if (offset >= bodyBuf.length) {
          controller.close()
          return
        }
        const end = Math.min(offset + chunkSize, bodyBuf.length)
        controller.enqueue(bodyBuf.slice(offset, end))
        offset = end
      },
    })

    return createResponse(bodyStream, resp.status, resp.status_text || resp.statusText, responseHeaders, attestation)
  }
}

/**
 * Normalize attestation object to consistent shape
 */
function normalizeAttestation(raw) {
  if (!raw) {
    return {
      trusted: false,
      teeType: "unknown",
      measurement: null,
      tcbStatus: "unknown",
      advisoryIds: [],
    }
  }
  return {
    trusted: raw.trusted ?? false,
    teeType: raw.tee_type || raw.teeType || "unknown",
    measurement: raw.measurement ?? null,
    tcbStatus: raw.tcb_status || raw.tcbStatus || "unknown",
    advisoryIds: raw.advisory_ids || raw.advisoryIds || [],
  }
}

/**
 * Create a Response with attestation property
 */
function createResponse(body, status, statusText, headers, attestation) {
  const response = new Response(body, {
    status,
    statusText: statusText || "",
    headers,
  })

  // Attach attestation as enumerable property for easy access
  Object.defineProperty(response, "attestation", {
    value: attestation,
    enumerable: true,
    configurable: false,
    writable: false,
  })

  // Keep ratlsAttestation for backwards compatibility
  Object.defineProperty(response, "ratlsAttestation", {
    value: attestation,
    enumerable: false,
    configurable: false,
    writable: false,
  })

  return response
}

// Default export for convenience
export default createRatlsFetch
