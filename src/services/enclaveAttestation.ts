/**
 * Live enclave identity attestation for public PCR0 display.
 * Independent of ENCLAVE_ENABLED — report crypto may stay on LocalCryptoClient
 * while this path only asks the co-located enclave for an NSM document.
 *
 * Only PCR0 leaves this module. The raw NSM document also carries module_id
 * (the host instance ID) and PCR3/PCR4 (hashes of the host IAM role ARN and
 * instance ID), none of which belong on a public endpoint.
 */

import crypto from 'node:crypto';
import {
  EnclaveCryptoClient,
  EnclaveRpcError,
  EnclaveUnreachableError,
  defaultEnclaveConnect,
  type EnclaveTransportOptions,
} from './cryptoClient';
import { extractPcr0FromAttestationDocument } from '../utils/nsmAttestationPcr0';
import { logger } from '../utils/logger';

const VSOCK_PORT = 5000;
const ATTEST_TIMEOUT_MS = 10_000;
// Fixed user_data the enclave's NSM helper binds into identity documents.
const IDENTITY_CONTEXT = 'VERA-ENCLAVE-IDENTITY-v1';

/**
 * `available: false` means there is no enclave to ask: the bridge is absent or
 * refuses connections, the enclave does not answer in time, or the running
 * enclave build predates the attestIdentity verb (JSON-RPC -32601). That is an
 * expected deployment state, not a server fault.
 */
export type EnclaveAttestationResult =
  | { available: true; pcr0: string }
  | { available: false };

export function createEnclaveAttestationClient(opts: EnclaveTransportOptions = {}): EnclaveCryptoClient {
  const port = parseInt(process.env.ENCLAVE_PORT || String(VSOCK_PORT), 10);
  return new EnclaveCryptoClient(16, port, {
    connect: opts.connect ?? defaultEnclaveConnect(port),
    timeoutMs: opts.timeoutMs ?? ATTEST_TIMEOUT_MS,
  });
}

// Any JSON-RPC error reply means this enclave will not attest. Builds without
// attestIdentity answer -32601, and the EIF prod runs today (65f78e51) refuses
// every method but health on Nitro hardware with -32000 "Enclave operation
// unavailable". Neither is a server fault; only a returned document that fails
// the checks below is.
function isEnclaveUnavailable(error: unknown): boolean {
  if (error instanceof EnclaveUnreachableError) return true;
  if (error instanceof EnclaveRpcError) {
    logger.warn(`[ENCLAVE_ATTESTATION] Enclave declined attestIdentity: ${error.message}`);
    return true;
  }
  return false;
}

/**
 * Challenge the enclave and extract PCR0 from the returned document.
 *
 * Resolves `{ available: false }` when no enclave can answer or the enclave
 * replies with a JSON-RPC error. Rejects only when a returned document is
 * malformed or has a stale/mismatched nonce or the wrong identity context. Those mean the enclave or bridge is misbehaving (or a
 * reply is being replayed), which operators should see as a 5xx.
 */
export async function fetchLiveEnclaveAttestation(
  opts: EnclaveTransportOptions = {},
): Promise<EnclaveAttestationResult> {
  const nonce = crypto.randomBytes(32).toString('hex');
  const client = createEnclaveAttestationClient(opts);
  let document: string;
  try {
    ({ document } = await client.attestIdentity(nonce));
  } catch (error) {
    if (isEnclaveUnavailable(error)) return { available: false };
    throw error;
  }
  const pcr0 = extractPcr0FromAttestationDocument(document, nonce, IDENTITY_CONTEXT);
  return { available: true, pcr0 };
}

// The enclave serves one attestation at a time, so concurrent callers share a
// single in-flight request and reuse the result briefly. Unavailable results
// and failures are cached for less time so a restarted enclave reappears
// quickly without letting public traffic retry against it on every request.
const CACHE_TTL_MS = 30_000;
const FAILURE_TTL_MS = 5_000;

let cached: { expires: number; result?: EnclaveAttestationResult; error?: unknown } | undefined;
let inFlight: Promise<EnclaveAttestationResult> | undefined;

export function getCachedEnclaveAttestation(
  fetchLive: () => Promise<EnclaveAttestationResult> = fetchLiveEnclaveAttestation,
  now: () => number = Date.now,
): Promise<EnclaveAttestationResult> {
  if (cached && cached.expires > now()) {
    return cached.result ? Promise.resolve(cached.result) : Promise.reject(cached.error);
  }
  if (!inFlight) {
    inFlight = fetchLive()
      .then((result) => {
        cached = { expires: now() + (result.available ? CACHE_TTL_MS : FAILURE_TTL_MS), result };
        return result;
      }, (error: unknown) => {
        cached = { expires: now() + FAILURE_TTL_MS, error };
        logger.error(`[ENCLAVE_ATTESTATION] ${error instanceof Error ? error.message : 'Unknown error'}`);
        throw error;
      })
      .finally(() => {
        inFlight = undefined;
      });
  }
  return inFlight;
}

/** Test hook: forget the cached attestation. */
export function resetEnclaveAttestationCache(): void {
  cached = undefined;
  inFlight = undefined;
}
