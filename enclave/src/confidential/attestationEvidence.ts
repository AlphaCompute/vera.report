import { decodeAttestationCbor } from './attestationCbor.ts';
import { CLOCK_SKEW_MS } from './clockSkew.ts';
import { AttestationCertificateSizeError, MAX_ATTESTATION_CERTIFICATE_BYTES } from './attestationCertificateLimit.ts';

const DOMAIN = new TextEncoder().encode('VERA-CONFIDENTIAL-CHANNEL-v1');
function invalid(): never { throw new Error('Invalid application attestation evidence'); }
function bytes(value: unknown, min: number, max = min): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.length < min || value.length > max) invalid();
  return new Uint8Array(value);
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function byteString(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const length = value.length;
  if (length > 16384) invalid();
  return concat([new Uint8Array(length < 24 ? [0x40 + length] : length < 256 ?
    [0x58, length] : [0x59, length >> 8, length & 255]), value]);
}

/** Evidence must be at most one minute old, allowing the shared clock-skew
 * tolerance (clockSkew.ts) either way between the enclave and verifier clocks.
 * Freshness itself comes from the verifier's one-use nonce; this window only
 * bounds clock disagreement. */
const MAX_EVIDENCE_AGE = 60_000 + CLOCK_SKEW_MS, MAX_EVIDENCE_LEAD = CLOCK_SKEW_MS;
export function attestationTimeFits(timestamp: number, now: number): boolean {
  return timestamp >= now - MAX_EVIDENCE_AGE && timestamp <= now + MAX_EVIDENCE_LEAD;
}

/** Diagnostics only: the NSM timestamp an evidence document CLAIMS, without
 * any verification, or null when it cannot be read. Never use it to authorize,
 * pin or trust anything; callers use it to tell a wrong device clock apart
 * from a failed verification when choosing an error message. */
export function attestationTimestamp(document: Uint8Array): number | null {
  try {
    const cose = decodeAttestationCbor(bytes(document, 1, 16384), true);
    if (!Array.isArray(cose) || cose.length !== 4) return null;
    const body = decodeAttestationCbor(bytes(cose[2], 1, 16384));
    const timestamp = body instanceof Map ? body.get('timestamp') : null;
    return typeof timestamp === 'number' && Number.isSafeInteger(timestamp) && timestamp > 0 ? timestamp : null;
  } catch { return null; }
}

export type ApplicationAttestationPolicy = {
  /** Fresh locally generated challenge, never taken from the evidence response. */
  nonce: Uint8Array;
  /** From independently authenticated, exact owner-approved release metadata. */
  expectedPcrs: ReadonlyMap<number, Uint8Array>;
  /** Trusted caller clock in UTC milliseconds. */
  now: number;
};

export type UnverifiedApplicationAttestation = {
  status: 'unverified';
  channelPublicKey: Uint8Array<ArrayBuffer>;
  signedBytes: Uint8Array<ArrayBuffer>;
  signature: Uint8Array<ArrayBuffer>;
  certificate: Uint8Array<ArrayBuffer>;
  cabundle: Uint8Array<ArrayBuffer>[];
  timestamp: number;
};

/** Validates structure/policy and constructs the COSE signature input. This does
 * NOT verify the certificate chain or signature and MUST NOT authorize a channel.
 * Keep this intermediate result internal to the eventual complete verifier. */
export async function prepareApplicationAttestation(
  document: Uint8Array, channelPublicKey: Uint8Array, policy: ApplicationAttestationPolicy,
): Promise<UnverifiedApplicationAttestation> {
  try {
    const wire = bytes(document, 1, 16384), publicKey = bytes(channelPublicKey, 1, 1024);
    const nonce = bytes(policy.nonce, 32), now = policy.now;
    if (!Number.isSafeInteger(now) || now <= 0 || now > 8640000000000000 ||
        !(policy.expectedPcrs instanceof Map) || policy.expectedPcrs.size < 3 || policy.expectedPcrs.size > 32) invalid();
    const pins = new Map<number, Uint8Array>();
    for (const [index, value] of policy.expectedPcrs) {
      if (!Number.isInteger(index) || index < 0 || index > 31) invalid();
      const pcr = bytes(value, 48);
      if (!pcr.some(value => value !== 0)) invalid();
      pins.set(index, pcr);
    }
    for (const index of [0, 1, 2]) if (!pins.has(index)) invalid();
    const cose = decodeAttestationCbor(wire, true);
    if (!Array.isArray(cose) || cose.length !== 4) invalid();
    const protectedBytes = bytes(cose[0], 1, 16384), payload = bytes(cose[2], 1, 16384);
    const signature = bytes(cose[3], 96);
    const headers = decodeAttestationCbor(protectedBytes);
    if (!(headers instanceof Map) || headers.size !== 1 || headers.get(1) !== -35 ||
        !(cose[1] instanceof Map) || cose[1].size !== 0) invalid();
    const body = decodeAttestationCbor(payload);
    if (!(body instanceof Map)) invalid();
    const required = ['module_id', 'timestamp', 'digest', 'pcrs', 'certificate', 'cabundle', 'nonce', 'user_data'];
    if (required.some(key => !body.has(key)) ||
        [...body.keys()].some(key => typeof key !== 'string' || (!required.includes(key) && key !== 'public_key'))) invalid();
    const moduleId = body.get('module_id'), timestamp = body.get('timestamp');
    if (body.get('digest') !== 'SHA384' || typeof moduleId !== 'string' || !moduleId.length ||
        new TextEncoder().encode(moduleId).length > 1024 || typeof timestamp !== 'number' ||
        !Number.isSafeInteger(timestamp) || timestamp <= 0 || !attestationTimeFits(timestamp, now) ||
        (body.has('public_key') && body.get('public_key') !== null) || !equal(bytes(body.get('nonce'), 32), nonce)) invalid();
    const pcrs = body.get('pcrs');
    if (!(pcrs instanceof Map) || pcrs.size < 3 || pcrs.size > 32) invalid();
    for (const [index, value] of pcrs) {
      if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index > 31) invalid();
      bytes(value, 48);
    }
    for (const [index, pin] of pins) if (!equal(bytes(pcrs.get(index), 48), pin)) invalid();
    const sized = (value: unknown) => {
      if (value instanceof Uint8Array && value.length > MAX_ATTESTATION_CERTIFICATE_BYTES) throw new AttestationCertificateSizeError();
      return bytes(value, 1, MAX_ATTESTATION_CERTIFICATE_BYTES);
    };
    const certificate = sized(body.get('certificate')), chain = body.get('cabundle');
    if (!Array.isArray(chain) || !chain.length || chain.length > 10) invalid();
    const cabundle = chain.map(sized);
    const context = bytes(body.get('user_data'), DOMAIN.length + 32);
    // All caller input/policy has been snapshotted before this asynchronous step.
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', publicKey));
    if (!equal(context, concat([DOMAIN, digest]))) invalid();
    const signedBytes = concat([new Uint8Array([0x84, 0x6a]), new TextEncoder().encode('Signature1'),
      byteString(protectedBytes), new Uint8Array([0x40]), byteString(payload)]);
    return { status: 'unverified', channelPublicKey: publicKey, signedBytes, signature, certificate, cabundle, timestamp };
  } catch (error) { if (error instanceof AttestationCertificateSizeError) throw error; return invalid(); }
}
