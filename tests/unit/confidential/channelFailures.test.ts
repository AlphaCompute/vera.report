import { webcrypto } from 'node:crypto';

// The attestation verifier is real unless a test supplies a verified result;
// the failure classification and attested-time offset are the subject here.
let verified: null | ((document: Uint8Array, key: Uint8Array) => { publicKey: Uint8Array; timestamp: number; verifiedAt: number }) = null;
jest.mock('../../../enclave/src/confidential/attestation', () => {
  const actual = jest.requireActual('../../../enclave/src/confidential/attestation');
  return {
    ...actual,
    verifyApplicationAttestation: (document: Uint8Array, key: Uint8Array, policy: unknown) =>
      verified ? Promise.resolve(verified(document, key)) : actual.verifyApplicationAttestation(document, key, policy),
  };
});

import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { ChannelClockError, openChannelRequest, sealChannelResponse } from '../../../enclave/src/confidential/channelMessage';
import { attestationTimeFits, attestationTimestamp } from '../../../enclave/src/confidential/attestationEvidence';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import {
  ConfidentialUnavailableError, channelFailure, fetchRelay, resetTrustedTime, synchronizeTrustedTime, trustedTime, verifiedSession,
} from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';

function cbor(value: unknown): Buffer {
  function head(major: number, n: number): Buffer {
    if (n < 24) return Buffer.from([major * 32 + n]);
    if (n < 256) return Buffer.from([major * 32 + 24, n]);
    if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
    const bytes = Buffer.alloc(9); bytes[0] = major * 32 + 27; bytes.writeBigUInt64BE(BigInt(n), 1); return bytes;
  }
  if (typeof value === 'number') return head(0, value);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error('unsupported fixture');
}
/** Structurally readable evidence with a chosen timestamp and no valid signature. */
const evidenceAt = (timestamp: number) => new Uint8Array(cbor([Buffer.from('a10138', 'hex'), new Map(),
  cbor(new Map<string, unknown>([['module_id', 'synthetic'], ['timestamp', timestamp]])), Buffer.alloc(96)]));

const hex = (n: number) => n.toString(16).padStart(64, '0');
test('maps an out-of-budget channel key to clock guidance without network interception advice', () => {
  const failure = channelFailure(new ChannelClockError());
  expect(failure.reason).toBe('clock');
  expect(failure.message).not.toContain('intercepted');
});
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });

function relayOpening(document: Uint8Array, publicKey = new Uint8Array([1])): ChannelRelay {
  return { stage: async () => { throw new Error(); }, call: async () => { throw new Error(); },
    open: async () => ({ document, publicKey }) };
}

/** A relay whose "enclave" answers `case.challenge` on the session it opened. */
function challengeRelay(publicKey: Uint8Array, privateKey: PrivateKey, calls: string[]): ChannelRelay {
  return { stage: async () => { throw new Error(); },
    open: async () => ({ document: new Uint8Array([1]), publicKey }),
    call: async (nonce, ciphertext) => {
      const request = await openChannelRequest(ciphertext, nonce, privateKey);
      calls.push(JSON.parse(new TextDecoder().decode(request.body)).operation);
      return sealChannelResponse(request, new TextEncoder().encode(JSON.stringify({ challenge: 'e'.repeat(64) })), privateKey);
    } };
}

describe('confidential channel failures are distinguishable and never quote internals', () => {
  const originalFetch = globalThis.fetch;
  beforeAll(() => { if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });
  afterEach(() => { globalThis.fetch = originalFetch; verified = null; resetTrustedTime(); });

  test('relay transport failure is offline, a server error is unavailable, 429 is busy', async () => {
    globalThis.fetch = jest.fn(async () => { throw new TypeError('Failed to fetch https://internal.example/secret'); }) as typeof fetch;
    const offline = await fetchRelay().open('a'.repeat(64)).catch(error => channelFailure(error));
    expect(offline).toBeInstanceOf(ConfidentialUnavailableError);
    expect(offline.reason).toBe('offline');
    expect(offline.message).not.toContain('internal.example');

    globalThis.fetch = jest.fn(async () => new Response('{"error":"x"}', { status: 503 })) as typeof fetch;
    await expect(fetchRelay().call('a'.repeat(64), 'ciphertext').catch(error => { throw channelFailure(error); }))
      .rejects.toMatchObject({ reason: 'unavailable' });

    globalThis.fetch = jest.fn(async () => new Response('', { status: 429, headers: { 'Retry-After': '2' } })) as typeof fetch;
    await expect(fetchRelay().stage('ciphertext')).rejects.toBeInstanceOf(ConfidentialRateLimitError);
    expect(channelFailure(new ConfidentialRateLimitError('2')).reason).toBe('busy');
    // Each request omits credentials and the referrer.
    const init = (globalThis.fetch as jest.Mock).mock.calls[0][1];
    expect(init).toMatchObject({ credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store' });
  });

  test('a failed verification with a plausible clock is reported as a verification failure', async () => {
    const now = Date.now();
    const error = await verifiedSession(relayOpening(evidenceAt(now)), MANIFEST, now).catch(caught => caught);
    expect(error).toMatchObject({ name: 'ConfidentialUnavailableError', reason: 'verification' });
    expect(error.message).toMatch(/did not prove it runs the approved software/);
    // Unreadable evidence is also a verification failure, not a clock problem.
    await expect(verifiedSession(relayOpening(new Uint8Array([0xff])), MANIFEST, now)).rejects.toMatchObject({ reason: 'verification' });
  });

  test('evidence far from the device clock is reported as a clock problem', async () => {
    const now = Date.now();
    for (const skew of [-10 * 60_000, 60 * 60_000]) {
      const error = await verifiedSession(relayOpening(evidenceAt(now + skew)), MANIFEST, now).catch(caught => caught);
      expect(error.reason).toBe('clock');
      expect(error.message).toMatch(/date and time/);
    }
    expect(attestationTimestamp(evidenceAt(now))).toBe(now);
    expect(attestationTimestamp(new Uint8Array([1, 2, 3]))).toBeNull();
    expect(attestationTimeFits(now - 360_000, now)).toBe(true);
    expect(attestationTimeFits(now - 360_001, now)).toBe(false);
    expect(attestationTimeFits(now + 300_000, now)).toBe(true);
    expect(attestationTimeFits(now + 300_001, now)).toBe(false);
  });

  test('signing time follows the attested enclave clock, not a fast or slow device clock', async () => {
    // A real enclave key necessarily exists before the NSM quote about it.
    const channel = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic' }],
      date: new Date(Date.now() - 60_000), format: 'object' });
    const publicKey = new Uint8Array(channel.publicKey.write());
    expect(trustedTime(1000)).toBe(1000);
    verified = (_document, key) => ({ publicKey: new Uint8Array(key), timestamp: Date.now() - 40_000, verifiedAt: Date.now() });
    const calls: string[] = [];
    await synchronizeTrustedTime(challengeRelay(publicKey, channel.privateKey, calls), MANIFEST, Date.now());
    // The one-use session is consumed rather than left holding an enclave slot.
    expect(calls).toEqual(['case.challenge']);
    const lag = Date.now() - trustedTime(Date.now());
    expect(lag).toBeGreaterThanOrEqual(39_000);
    expect(lag).toBeLessThanOrEqual(41_000);
    verified = (_document, key) => ({ publicKey: new Uint8Array(key), timestamp: Date.now() + 3_000, verifiedAt: Date.now() });
    await verifiedSession(relayOpening(new Uint8Array([1]), publicKey), MANIFEST, Date.now());
    expect(trustedTime(Date.now()) - Date.now()).toBeGreaterThanOrEqual(2_000);
    // A failed verification never moves the clock.
    verified = null;
    const before = trustedTime(0);
    await expect(synchronizeTrustedTime(relayOpening(evidenceAt(Date.now() + 3_600_000)), MANIFEST, Date.now()))
      .rejects.toMatchObject({ reason: 'clock' });
    expect(trustedTime(0)).toBe(before);
  });

  test('wrapping keeps a known reason and hides anything else', () => {
    expect(channelFailure(new ConfidentialUnavailableError('clock')).reason).toBe('clock');
    // An unexplained failure (for example a reply that does not decrypt) is treated
    // as a verification failure, never as harmless unavailability.
    const wrapped = channelFailure(new Error(`store failed ${'c3'.repeat(32)}`));
    expect(wrapped.reason).toBe('verification');
    expect(wrapped.message).not.toContain('c3c3');
  });
});
