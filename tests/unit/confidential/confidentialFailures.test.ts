import { webcrypto } from 'node:crypto';

// Only the AWS quote check is mocked; the channel encryption is real, so a reply
// that does not open under the verified session key is exercised for real.
let attestationFails = false;
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) => {
    if (attestationFails) throw new Error('Application channel attestation verification failed');
    return { publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() };
  },
}));

import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import {
  ConfidentialUnavailableError, channelFailure, fetchRelay, publicCaseOperation, verifiedSession,
} from '../../../lib/confidential/client';
import type { ConfidentialFailureReason } from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';
import { ConfidentialRollbackError } from '../../../lib/confidential/ownerCase';
import { OWNER_FAILURE_COPY, ownerFailureOf } from '../../../lib/confidential/failureCopy';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

type Behaviour = { open?: (nonce: string) => Promise<Response>; call?: (nonce: string, ciphertext: string) => Promise<Response> };
let sessions: ReturnType<typeof createSessionCore>;
let behaviour: Behaviour = {};
const realOpen = async (nonce: string) => json(200, await sessions.open(nonce));
const realCall = async (nonce: string, ciphertext: string) => json(200, { ciphertext: await sessions.execute(nonce, ciphertext) });

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  const keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
  // Echo dispatcher: the reply is sealed to the browser's session like any real reply.
  sessions = createSessionCore(async () => new TextEncoder().encode(JSON.stringify({ releases: [] })),
    async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: Buffer.from('synthetic').toString('base64') }), () => 1);
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (url.endsWith('/open')) return (behaviour.open ?? realOpen)(body.nonce);
    if (url.endsWith('/call')) return (behaviour.call ?? realCall)(body.nonce, body.ciphertext);
    throw new Error('unexpected url');
  }) as typeof fetch;
});
beforeEach(() => { behaviour = {}; attestationFails = false; });
afterEach(() => { delete (globalThis as { navigator?: unknown }).navigator; });

async function reasonOf(): Promise<ConfidentialFailureReason | 'ok'> {
  try {
    await publicCaseOperation({ relay: fetchRelay(), releaseManifest: MANIFEST, now: Date.now(),
      request: { operation: 'case.release-approvals', caseId: hex(1) } });
    return 'ok';
  } catch (error) {
    expect(error).toBeInstanceOf(ConfidentialUnavailableError);
    return (error as ConfidentialUnavailableError).reason;
  }
}

describe('confidential failures are distinguished by where they happened', () => {
  test('a verified round trip succeeds', async () => {
    expect(await reasonOf()).toBe('ok');
  });

  test('no network, or a browser that reports offline, is "offline"', async () => {
    behaviour.open = async () => { throw new TypeError('Failed to fetch'); };
    expect(await reasonOf()).toBe('offline');
    behaviour = {};
    Object.defineProperty(globalThis, 'navigator', { value: { onLine: false }, configurable: true });
    expect(await reasonOf()).toBe('offline');
  });

  test('a relay that cannot open a secure session is "unavailable"', async () => {
    for (const status of [502, 503, 504, 404]) {
      behaviour.open = async () => json(status, { error: 'Secure connection unavailable' });
      expect(await reasonOf()).toBe('unavailable');
    }
    behaviour.open = async () => new Response('<html>captive portal</html>', { status: 200 });
    expect(await reasonOf()).toBe('unavailable');
    // A 503 that carries Retry-After is load shedding.
    behaviour.open = async () => json(503, {}, { 'Retry-After': '5' });
    expect(await reasonOf()).toBe('busy');
  });

  test('rate limiting is "busy" at the operation boundary but stays retryable inside a step', async () => {
    behaviour.open = async () => json(429, {}, { 'Retry-After': '5' });
    expect(await reasonOf()).toBe('busy');
    await expect(verifiedSession(fetchRelay(), MANIFEST, Date.now())).rejects.toBeInstanceOf(ConfidentialRateLimitError);
  });

  test('evidence that fails attestation is "verification"', async () => {
    attestationFails = true;
    expect(await reasonOf()).toBe('verification');
  });

  test('a reply that does not open under the verified session key is "verification"', async () => {
    behaviour.call = async (nonce, ciphertext) => {
      const genuine = await sessions.execute(nonce, ciphertext);
      const bytes = Buffer.from(genuine, 'base64'); bytes[bytes.length - 5] ^= 0xff;
      return json(200, { ciphertext: bytes.toString('base64') });
    };
    expect(await reasonOf()).toBe('verification');
    behaviour.call = async () => json(200, { unexpected: true });
    expect(await reasonOf()).toBe('verification');
  });

  test('an HTTP error after a verified open is "unavailable" (HTTP status is not authenticated)', async () => {
    behaviour.call = async () => json(503, { error: 'Secure connection unavailable' });
    expect(await reasonOf()).toBe('unavailable');
    behaviour.call = async () => json(502, {});
    expect(await reasonOf()).toBe('unavailable');
  });

  test('reasons survive re-wrapping and map to distinct owner-facing copy', () => {
    const verification = new ConfidentialUnavailableError('verification');
    expect(channelFailure(verification)).toBe(verification);
    expect(channelFailure(new ConfidentialRateLimitError('1')).reason).toBe('busy');
    // An unexplained failure is never downgraded to harmless unavailability.
    expect(channelFailure(new Error('x')).reason).toBe('verification');
    expect(new ConfidentialUnavailableError().reason).toBe('verification');
    expect(ownerFailureOf(new ConfidentialUnavailableError('clock'), true)).toBe('clock');
    expect(ownerFailureOf(verification, true)).toBe('verification');
    expect(ownerFailureOf(new ConfidentialRollbackError(), true)).toBe('rollback');
    expect(ownerFailureOf(new Error('Unable to restore confidential case recovery'), false)).toBe('recovery');
    expect(ownerFailureOf(new Error('late failure'), true)).toBe('refused');
    const titles = Object.values(OWNER_FAILURE_COPY).map(copy => copy.title);
    expect(new Set(titles).size).toBe(titles.length);
    const actions = Object.values(OWNER_FAILURE_COPY).map(copy => copy.action);
    expect(new Set(actions).size).toBe(actions.length);
    const messages = (['offline', 'unavailable', 'busy', 'verification', 'clock'] as const)
      .map(reason => new ConfidentialUnavailableError(reason).message);
    expect(new Set(messages).size).toBe(messages.length);
    // Only a failed verification or a history mismatch is presented as a possible attack.
    expect(Object.entries(OWNER_FAILURE_COPY).filter(([, copy]) => copy.severity === 'danger').map(([reason]) => reason).sort())
      .toEqual(['rollback', 'verification']);
  });
});
