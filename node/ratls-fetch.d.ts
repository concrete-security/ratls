/**
 * RA-TLS Node.js Bindings - High-level API
 *
 * Provides attested TLS connections to Trusted Execution Environments (TEEs)
 * with a fetch-compatible API that works seamlessly with AI SDKs.
 */

/**
 * Attestation result from the TEE
 */
export interface RatlsAttestation {
  /** Whether the attestation was successfully verified */
  trusted: boolean
  /** Type of TEE (e.g., "tdx", "sgx") */
  teeType: string
  /** Measurement/MRENCLAVE of the TEE workload */
  measurement: string | null
  /** TCB (Trusted Computing Base) status */
  tcbStatus: string
  /** Security advisory IDs that apply to this platform */
  advisoryIds: string[]
}

/**
 * Options for creating an RA-TLS fetch function
 */
export interface RatlsFetchOptions {
  /**
   * Target host to connect to
   * @example "enclave.example.com" or "enclave.example.com:8443"
   */
  target?: string

  /**
   * @deprecated Use `target` instead
   */
  targetHost?: string

  /**
   * Server Name Indication (SNI) for TLS
   * @default Derived from target hostname
   */
  serverName?: string

  /**
   * Default headers to include in all requests
   * @example { Authorization: "Bearer token" }
   */
  headers?: Record<string, string>

  /**
   * @deprecated Use `headers` instead
   */
  defaultHeaders?: Record<string, string>

  /**
   * Callback fired after each successful attestation verification
   * Use this for logging, metrics, or security policy enforcement
   *
   * @example
   * onAttestation: (att) => {
   *   if (att.tcbStatus !== "UpToDate") {
   *     console.warn("TEE platform needs updates")
   *   }
   * }
   */
  onAttestation?: (attestation: RatlsAttestation) => void
}

/**
 * Response type with attestation data
 */
export interface RatlsResponse extends Response {
  /** Attestation result from the TEE (enumerable) */
  readonly attestation: RatlsAttestation
  /** @deprecated Use `attestation` instead */
  readonly ratlsAttestation: RatlsAttestation
}

/**
 * Fetch function type with attestation support
 */
export type RatlsFetch = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<RatlsResponse>

/**
 * Create an RA-TLS enabled fetch function
 *
 * The returned fetch function establishes attested TLS connections directly
 * to TEE endpoints. Each request performs attestation verification and
 * exposes the result on the response.
 *
 * @param optionsOrTarget - Target host string or options object
 * @returns A fetch-compatible function with attestation support
 *
 * @example Simple usage
 * ```typescript
 * import { createRatlsFetch } from "ratls-node"
 *
 * const fetch = createRatlsFetch("enclave.example.com")
 * const response = await fetch("/api/data")
 * console.log(response.attestation.trusted) // true
 * ```
 *
 * @example With AI SDK
 * ```typescript
 * import { createRatlsFetch } from "ratls-node"
 * import { createOpenAI } from "@ai-sdk/openai"
 *
 * const openai = createOpenAI({
 *   baseURL: "https://enclave.example.com/v1",
 *   fetch: createRatlsFetch({
 *     target: "enclave.example.com",
 *     headers: { Authorization: `Bearer ${apiKey}` },
 *     onAttestation: (att) => console.log(`TEE: ${att.teeType}`)
 *   })
 * })
 * ```
 */
export function createRatlsFetch(optionsOrTarget: string | RatlsFetchOptions): RatlsFetch

export default createRatlsFetch

