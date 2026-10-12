import { createMessage, readSignature, sign, verify } from './pgp.ts';
import { CLOCK_SKEW_MS } from './clockSkew.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';

/** Key-possession authentication for confidential service operations.
 * The participant signs one exact operation, request body digest and a
 * service-issued single-use challenge. A login cookie, legacy reporter code,
 * internal secret or copied grant cannot produce this signature. The service
 * must consume the challenge atomically; this module only verifies the proof.
 */
const FORMAT = 'vera-participant-request/v2';
export const PARTICIPANT_OPERATIONS = [
  'publish-case', 'commit-transition', 'read-inbox', 'update-recovery',
  'request-access', 'withdraw-request', 'request-status', 'decline-request', 'open-case', 'acknowledge-report-open', 'send-message', 'read-messages',
  'unlock-case', 'read-state-keys', 'read-owner-envelopes', 'read-legal-roster', 'read-state', 'read-object',
  // Organization-scoped (caseId carries the organization ID): member devices and batched status reads.
  'manage-members', 'request-status-batch',
] as const;
export type ParticipantOperation = typeof PARTICIPANT_OPERATIONS[number];
export type ParticipantRole = 'owner' | 'organization';
export type ParticipantRequest = {
  format: typeof FORMAT; audience: string; role: ParticipantRole; caseId: string;
  organizationId: string | null; operation: ParticipantOperation; bodyDigest: string;
  challenge: string; issuedAt: number;
  nonce: string; serverKeyId: string;
};
export type ParticipantExpectation = {
  audience: string; role: ParticipantRole; caseId: string; organizationId: string | null;
  operation: ParticipantOperation; body: Uint8Array; challenge: string; now: number;
  /** Actual verified application-channel session, never host-supplied headers. */
  nonce: string; serverKeyId: string;
};

/** issuedAt is the participant's clock; `now` is the enclave's. Replay is
 * prevented by the single-use challenge (120 s lifetime) and the session nonce,
 * so the issue-time window only has to reject clearly wrong clocks. */
const MAX_SKEW = CLOCK_SKEW_MS;
const MAX_AGE = 120_000 + CLOCK_SKEW_MS;
function invalid(): never { throw new Error('Participant authentication required'); }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value as string;
}
function canonical(input: unknown): ParticipantRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  const fields = ['format', 'audience', 'role', 'caseId', 'organizationId', 'operation', 'bodyDigest', 'challenge', 'issuedAt', 'nonce', 'serverKeyId'];
  if (Object.keys(value).length !== fields.length || Object.keys(value).some(key => !fields.includes(key)) ||
      value.format !== FORMAT || typeof value.audience !== 'string' || !/^[a-z0-9][a-z0-9.:-]{0,127}$/.test(value.audience) ||
      (value.role !== 'owner' && value.role !== 'organization') ||
      !PARTICIPANT_OPERATIONS.includes(value.operation as ParticipantOperation) ||
      !Number.isSafeInteger(value.issuedAt) || (value.issuedAt as number) <= 0) invalid();
  const organizationId = value.organizationId === null ? null : identifier(value.organizationId);
  if ((value.role === 'owner') !== (organizationId === null)) invalid();
  return { format: FORMAT, audience: value.audience as string, role: value.role as ParticipantRole,
    caseId: identifier(value.caseId), organizationId, operation: value.operation as ParticipantOperation,
    bodyDigest: identifier(value.bodyDigest), challenge: identifier(value.challenge), issuedAt: value.issuedAt as number,
    nonce: identifier(value.nonce), serverKeyId: identifier(value.serverKeyId) };
}
export async function requestBodyDigest(body: Uint8Array): Promise<string> {
  if (!(body instanceof Uint8Array)) invalid();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(body));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Participant-device operation. Returns a compact wire value for a request header/body field. */
export async function signParticipantRequest(expectation: Omit<ParticipantExpectation, 'now'> & { issuedAt: number },
  key: PrivateKey): Promise<string> {
  try {
    const body = new Uint8Array(expectation.body);
    const request = canonical({ format: FORMAT, audience: expectation.audience, role: expectation.role,
      caseId: expectation.caseId, organizationId: expectation.organizationId, operation: expectation.operation,
      bodyDigest: '0'.repeat(64), challenge: expectation.challenge, issuedAt: expectation.issuedAt,
      nonce: expectation.nonce, serverKeyId: expectation.serverKeyId });
    if (!key.isDecrypted()) invalid();
    request.bodyDigest = await requestBodyDigest(body);
    const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(request)) }),
      signingKeys: key, detached: true, format: 'armored' });
    return JSON.stringify({ request, signature });
  } catch { return invalid(); }
}

/** Service operation. `key` is the owner key from case genesis or the pinned
 * organization key, never a key supplied with the request. */
export async function verifyParticipantRequest(wire: string, expected: ParticipantExpectation,
  key: PublicKey): Promise<ParticipantRequest> {
  try {
    if (typeof wire !== 'string' || wire.length > 20_000 || key.isPrivate()) invalid();
    const value = JSON.parse(wire);
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).length !== 2 || typeof value.signature !== 'string' || value.signature.length > 16_384) invalid();
    const request = canonical(value.request);
    const now = expected.now;
    if (!Number.isSafeInteger(now) || request.audience !== expected.audience || request.role !== expected.role ||
        request.caseId !== expected.caseId || request.organizationId !== expected.organizationId ||
        request.operation !== expected.operation || request.challenge !== identifier(expected.challenge) ||
        request.nonce !== identifier(expected.nonce) || request.serverKeyId !== identifier(expected.serverKeyId) ||
        request.issuedAt > now + MAX_SKEW || request.issuedAt < now - MAX_AGE ||
        request.bodyDigest !== await requestBodyDigest(expected.body)) invalid();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(request)) }),
      signature: await readSignature({ armoredSignature: value.signature }), verificationKeys: key,
      expectSigned: true, format: 'binary' });
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
    return request;
  } catch { return invalid(); }
}
