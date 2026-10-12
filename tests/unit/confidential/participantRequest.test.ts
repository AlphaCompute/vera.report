import { webcrypto } from 'node:crypto';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { createMessage, generateKey, sign } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { PARTICIPANT_OPERATIONS, signParticipantRequest, verifyParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantExpectation } from '../../../enclave/src/confidential/participantRequest';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const body = new TextEncoder().encode('{"ciphertext":"opaque"}');
const expected: ParticipantExpectation = { audience: 'vera-confidential-cases', role: 'owner', caseId: hex(1),
  organizationId: null, operation: 'read-inbox', body, challenge: hex(2), now, nonce: hex(4), serverKeyId: hex(5) };
let owner: PrivateKey, other: PrivateKey;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, other] = await Promise.all(['owner', 'other'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }],
      format: 'object' })).privateKey));
});

describe('participant key-possession authentication', () => {
  test('verifies exactly one owner operation, body and challenge', async () => {
    const wire = await signParticipantRequest({ ...expected, issuedAt: now }, owner);
    await expect(verifyParticipantRequest(wire, expected, owner.toPublic())).resolves.toMatchObject({
      operation: 'read-inbox', caseId: hex(1), challenge: hex(2) });
  });

  test.each([
    ['audience', { audience: 'other-service' }], ['case', { caseId: hex(9) }], ['operation', { operation: 'commit-transition' }],
    ['challenge', { challenge: hex(9) }], ['body', { body: new TextEncoder().encode('{"ciphertext":"changed"}') }],
    ['role', { role: 'organization', organizationId: hex(3) }], ['stale time', { now: now + 120_000 + CLOCK_SKEW_MS + 1 }],
    ['future time', { now: now - CLOCK_SKEW_MS - 1 }],
    ['channel nonce', { nonce: hex(9) }], ['channel key', { serverKeyId: hex(9) }],
  ])('rejects a valid signature used for a different %s', async (_name, change) => {
    const wire = await signParticipantRequest({ ...expected, issuedAt: now }, owner);
    await expect(verifyParticipantRequest(wire, { ...expected, ...change } as ParticipantExpectation, owner.toPublic()))
      .rejects.toThrow('Participant authentication required');
  });

  test.each([
    ['a device clock ahead of the enclave', -(CLOCK_SKEW_MS - 1_000)],
    ['a device clock behind the enclave', CLOCK_SKEW_MS - 1_000],
    ['a proof signed just before a slow upload finished', 120_000 + CLOCK_SKEW_MS - 1_000],
  ])('accepts %s within the tolerated skew', async (_name, offset) => {
    const wire = await signParticipantRequest({ ...expected, issuedAt: now }, owner);
    await expect(verifyParticipantRequest(wire, { ...expected, now: now + (offset as number) }, owner.toPublic())).resolves.toBeTruthy();
  });

  test('another key, a public key in place of proof, or a tampered request fails', async () => {
    const wire = await signParticipantRequest({ ...expected, issuedAt: now }, owner);
    await expect(verifyParticipantRequest(wire, expected, other.toPublic())).rejects.toThrow();
    await expect(verifyParticipantRequest(wire, expected, owner as never)).rejects.toThrow();
    const value = JSON.parse(wire);
    value.request.operation = 'publish-case';
    await expect(verifyParticipantRequest(JSON.stringify(value), { ...expected, operation: 'publish-case' },
      owner.toPublic())).rejects.toThrow();
    await expect(verifyParticipantRequest(JSON.stringify({ ...value, admin: true }), expected, owner.toPublic())).rejects.toThrow();
  });

  test('organization requests must name the organization and owners must not', async () => {
    await expect(signParticipantRequest({ ...expected, role: 'organization', organizationId: null, issuedAt: now }, owner)).rejects.toThrow();
    await expect(signParticipantRequest({ ...expected, organizationId: hex(3), issuedAt: now }, owner)).rejects.toThrow();
    const orgExpected = { ...expected, role: 'organization' as const, organizationId: hex(3), operation: 'open-case' as const };
    const wire = await signParticipantRequest({ ...orgExpected, issuedAt: now }, other);
    await expect(verifyParticipantRequest(wire, orgExpected, other.toPublic())).resolves.toMatchObject({ organizationId: hex(3) });
  });

  test('unbound legacy requests and missing channel binding fail closed', async () => {
    const wire = await signParticipantRequest({ ...expected, issuedAt: now }, owner);
    const legacy = JSON.parse(wire);
    legacy.request.format = 'vera-participant-request/v1';
    delete legacy.request.nonce;
    delete legacy.request.serverKeyId;
    await expect(verifyParticipantRequest(JSON.stringify(legacy), expected, owner.toPublic())).rejects.toThrow();
    await expect(signParticipantRequest({ ...expected, nonce: undefined, issuedAt: now } as never, owner)).rejects.toThrow();
    await expect(verifyParticipantRequest(wire, { ...expected, serverKeyId: undefined } as never, owner.toPublic())).rejects.toThrow();
  });

  test('is the only proof format: the retired legal-operation proof is refused and its operations are covered', async () => {
    // Retired `vera-legal-operation/v1`: case.request-access, case.read, case.write-message.
    expect(PARTICIPANT_OPERATIONS).toEqual(expect.arrayContaining(['request-access', 'open-case', 'send-message']));
    const orgExpected = { ...expected, role: 'organization' as const, organizationId: hex(3), operation: 'open-case' as const };
    const context = { format: 'vera-legal-operation/v1', nonce: hex(4), serverKeyId: hex(5), organizationId: hex(3),
      recipientKeyId: hex(6), providerOrganizationId: 'org_firm', subject: 'auth0|lawyer', caseId: hex(1),
      operation: 'case.read', issuedAt: now, expiresAt: now + 60_000 };
    const detached = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(context)) }),
      signingKeys: other, detached: true, format: 'armored' });
    await expect(verifyParticipantRequest(detached, orgExpected, other.toPublic())).rejects.toThrow('Participant authentication required');
    await expect(verifyParticipantRequest(JSON.stringify({ request: context, signature: detached }), orgExpected, other.toPublic()))
      .rejects.toThrow('Participant authentication required');
    await expect(signParticipantRequest({ ...orgExpected, operation: 'read' as never, issuedAt: now }, other)).rejects.toThrow();
  });
});
