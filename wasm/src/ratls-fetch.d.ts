export interface AttestationResult {
  trusted: boolean;
  teeType: string;
  tcbStatus: string;
}

export interface RatlsFetchOptions {
  proxyUrl: string;
  targetHost: string;
  serverName?: string;
  defaultHeaders?: Record<string, string>;
  onAttestation?: (attestation: AttestationResult) => void;
}

export interface RatlsResponse extends Response {
  readonly attestation: AttestationResult;
}

export type RatlsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<RatlsResponse>;

export function createRatlsFetch(options: RatlsFetchOptions): RatlsFetch;

export { AttestedStream } from "./ratls_wasm.js";

