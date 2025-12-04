/**
 * RA-TLS Node.js Bindings - Low-level API
 *
 * For most use cases, import from "ratls-node" directly to get the high-level
 * createRatlsFetch function. These low-level bindings are for advanced use cases.
 *
 * @example
 * import { httpRequest } from "ratls-node/binding"
 */

export interface HeaderEntry {
  name: string
  value: string
}

export interface RatlsAttestation {
  trusted: boolean
  teeType: string
  measurement: string | null
  tcbStatus: string
  advisoryIds: string[]
}

export interface HttpResponse {
  attestation: RatlsAttestation
  status: number
  statusText: string
  headers: HeaderEntry[]
  body: Buffer
}

export interface StreamingResponse {
  attestation: RatlsAttestation
  status: number
  statusText: string
  headers: HeaderEntry[]
  streamId: number
}

export function httpRequest(
  targetHost: string,
  serverName: string,
  method: string,
  path: string,
  headers: HeaderEntry[],
  body?: Buffer
): Promise<HttpResponse>

export function httpStreamRequest(
  targetHost: string,
  serverName: string,
  method: string,
  path: string,
  headers: HeaderEntry[],
  body?: Buffer
): Promise<StreamingResponse>

export function streamRead(streamId: number, maxBytes?: number): Promise<Buffer>

export function streamClose(streamId: number): Promise<void>

declare const binding: {
  httpRequest: typeof httpRequest
  httpStreamRequest: typeof httpStreamRequest
  streamRead: typeof streamRead
  streamClose: typeof streamClose
}

export default binding
