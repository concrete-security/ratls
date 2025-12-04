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

import {
  httpRequest,
  httpStreamRequest,
  streamRead,
  streamClose,
} from "./index.js"

const ATTESTATION_HEADER = "x-ratls-attestation"

/**
 * Parse target host string into host:port format
 * @param {string} target - Host with optional port
 * @returns {{ host: string, port: string, hostPort: string, serverName: string }}
 */
function parseTarget(target) {
  const trimmed = target.trim()
  const withoutProtocol = trimmed.replace(/^https?:\/\//, "")
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
  const options =
    typeof optionsOrTarget === "string"
      ? { target: optionsOrTarget }
      : optionsOrTarget

  const targetRaw = options.target
  if (!targetRaw) {
    throw new Error("target is required (e.g., 'enclave.example.com' or 'enclave.example.com:443')")
  }

  const parsed = parseTarget(targetRaw)
  const targetHost = parsed.hostPort
  const serverName = options.serverName || parsed.serverName
  const defaultHeaders = options.headers
  const onAttestation = options.onAttestation

  if (typeof httpRequest !== "function") {
    throw new Error("ratls-node binding not loaded correctly")
  }

  const useStreaming =
    typeof httpStreamRequest === "function" &&
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

    if (useStreaming) {
      const resp = await httpStreamRequest(
        targetHost,
        serverName,
        method,
        path,
        headerEntries,
        body
      )

      const attestation = normalizeAttestation(resp.attestation)

      if (onAttestation) {
        onAttestation(attestation)
      }

      const responseHeaders = new Headers()
      resp.headers.forEach(({ name, value }) => responseHeaders.append(name, value))
      responseHeaders.set(ATTESTATION_HEADER, JSON.stringify(attestation))

      const streamId = resp.streamId || 0
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

      return createResponse(bodyStream, resp.status, resp.statusText, responseHeaders, attestation)
    }

    const resp = await httpRequest(
      targetHost,
      serverName,
      method,
      path,
      headerEntries,
      body
    )

    const attestation = normalizeAttestation(resp.attestation)

    if (onAttestation) {
      onAttestation(attestation)
    }

    const responseHeaders = new Headers()
    resp.headers.forEach(({ name, value }) => responseHeaders.append(name, value))
    responseHeaders.set(ATTESTATION_HEADER, JSON.stringify(attestation))

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

    return createResponse(bodyStream, resp.status, resp.statusText, responseHeaders, attestation)
  }
}

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
    teeType: raw.teeType || "unknown",
    measurement: raw.measurement ?? null,
    tcbStatus: raw.tcbStatus || "unknown",
    advisoryIds: raw.advisoryIds || [],
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

  Object.defineProperty(response, "attestation", {
    value: attestation,
    enumerable: true,
    configurable: false,
    writable: false,
  })

  return response
}

export default createRatlsFetch
