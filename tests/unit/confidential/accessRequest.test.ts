import { reviewOwnerRequests } from '../../../lib/confidential/ownerCase';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import type { OwnerInbox, OwnerSession, VerifiedOrganization } from '../../../lib/confidential/ownerCase';
import { requestRoutingTag } from '../../../enclave/src/confidential/requestRouting';
import { webcrypto } from 'node:crypto';
import { createMessage, encrypt, readMessage } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { createLegalAccessRequest, openLegalAccessRequest, openDeliveredLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import type { AccessRequestInput, LegalAccessRequest, TrustedLegalOrganization } from '../../../enclave/src/confidential/accessRequest';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const input: AccessRequestInput = { requestId: hex(1), scopes: ['narrative', 'evidence'],
  objectRevisionLimit: null, purpose: 'PRIVATE-REQUEST: We would like to review the underlying evidence.',
  issuedAt: now - 1000, expiresAt: now + 60_000 };
let owner: Awaited<ReturnType<typeof createCaseOwner>>;
let firm: Awaited<ReturnType<typeof createCaseOwner>>;
let intruder: Awaited<ReturnType<typeof createCaseOwner>>;
let directory: TrustedLegalOrganization[], ciphertext: string, request: LegalAccessRequest;
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, firm, intruder] = await Promise.all([createCaseOwner(), createCaseOwner(), createCaseOwner()]);
  directory = [{ organizationId: hex(2), publicKey: firm.trust.ownerPublicKey, approved: true }];
  ciphertext = await createLegalAccessRequest(input, hex(2), firm.privateKey, owner.trust);
  request = await openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, directory, now);
});

async function raw(value: unknown, signer?: PrivateKey): Promise<string> {
  return encrypt({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
    encryptionKeys: owner.trust.ownerPublicKey, ...(signer ? { signingKeys: signer } : {}), format: 'armored' });
}

describe('encrypted legal access requests', () => {
  function delivery() {
    return { caseId: owner.trust.caseId, requestId: input.requestId, organizationId: hex(2),
      recipientKeyId: request.recipientKeyId, expiresAt: input.expiresAt, status: 'pending' as const, ciphertext };
  }
  test('owner inbox verifies the encrypted request against its current delivery record', async () => {
    expect(await openDeliveredLegalAccessRequest(delivery(), owner.trust.caseId, owner.privateKey, directory, now)).toEqual(request);
  });
  test('owner resolves blinded commitments only from a verified owner-encrypted request', async () => {
    const row = { ...delivery(), routing: 'blinded-v1' as const,
      requestId: await requestRoutingTag('request', input.requestId),
      organizationId: await requestRoutingTag('organization', input.requestId, hex(2)),
      recipientKeyId: await requestRoutingTag('recipient', input.requestId, request.recipientKeyId) };
    expect(await openDeliveredLegalAccessRequest(row, owner.trust.caseId, owner.privateKey, directory, now)).toEqual(request);
    for (const field of ['requestId', 'organizationId', 'recipientKeyId'] as const) {
      await expect(openDeliveredLegalAccessRequest({ ...row, [field]: hex(99) }, owner.trust.caseId,
        owner.privateKey, directory, now)).rejects.toThrow();
    }
    await expect(openDeliveredLegalAccessRequest(row, owner.trust.caseId, owner.privateKey,
      [{ ...directory[0], publicKey: intruder.trust.ownerPublicKey }], now)).rejects.toThrow();
  });
  test('an answered blinded request is not counted as unverifiable; tampered requests still are', async () => {
    const row = { ...delivery(), routing: 'blinded-v1' as const,
      requestId: await requestRoutingTag('request', input.requestId),
      organizationId: await requestRoutingTag('organization', input.requestId, hex(2)),
      recipientKeyId: await requestRoutingTag('recipient', input.requestId, request.recipientKeyId) };
    const session = { trust: owner.trust, owner: owner.privateKey } as OwnerSession;
    const roster = directory.map(item => ({ ...item, displayName: 'Counsel', domain: 'counsel.example' })) as VerifiedOrganization[];
    const inbox = { deliveries: [row], statements: {} } as OwnerInbox;
    expect((await reviewOwnerRequests(session, inbox, roster, now)).requests).toHaveLength(1);
    inbox.statements = { [hex(101)]: JSON.stringify({ statement: { kind: 'grant', organizationId: hex(2), grantId: input.requestId } }) };
    expect(await reviewOwnerRequests(session, inbox, roster, now)).toEqual({ requests: [], unverified: 0 });
    inbox.deliveries.push({ ...row, ciphertext: 'tampered' });
    expect(await reviewOwnerRequests(session, inbox, roster, now)).toEqual({ requests: [], unverified: 1 });
  });
  test.each([
    { requestId: hex(99) }, { organizationId: hex(99) }, { recipientKeyId: hex(99) },
    { expiresAt: input.expiresAt + 1 }, { caseId: hex(99) }, { status: 'withdrawn' },
    { status: 'expired' }, { adminOverride: true },
  ])('owner inbox rejects mismatched or ineligible delivery metadata %#', async change => {
    await expect(openDeliveredLegalAccessRequest({ ...delivery(), ...change } as ReturnType<typeof delivery>,
      owner.trust.caseId, owner.privateKey, directory, now)).rejects.toThrow('Invalid confidential access request');
  });
  test('owner inbox snapshots metadata before awaiting signature verification', async () => {
    const row = delivery();
    const pending = openDeliveredLegalAccessRequest(row, owner.trust.caseId, owner.privateKey, directory, now);
    row.requestId = hex(99); row.organizationId = hex(99); row.ciphertext = 'changed';
    expect(await pending).toEqual(request);
  });
  test('owner reads the exact request and scope from an approved independently pinned organization', () => {
    expect(request).toMatchObject(input);
    expect(request.caseId).toBe(owner.trust.caseId);
    expect(request.organizationId).toBe(hex(2));
    expect(request.ownerFingerprint).toBe(owner.trust.ownerFingerprint);
  });

  test('the request body and case/firm relationship are not exposed in the stored envelope', async () => {
    for (const secret of [input.purpose, input.requestId, owner.trust.caseId, hex(2), request.recipientKeyId, 'narrative']) {
      expect(ciphertext).not.toContain(secret);
    }
    const message = await readMessage({ armoredMessage: ciphertext });
    expect(message.getEncryptionKeyIDs().every(id => /^0+$/.test(id.toHex()))).toBe(true);
  });

  test('platform key cannot decrypt the request', async () => {
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, intruder.privateKey, directory, now)).rejects.toThrow('Invalid confidential access request');
  });

  test('request creation checks the independently supplied owner-key pin', async () => {
    await expect(createLegalAccessRequest(input, hex(2), firm.privateKey,
      { ...owner.trust, ownerPublicKey: intruder.trust.ownerPublicKey })).rejects.toThrow();
  });

  test('another firm cannot claim the approved organization id', async () => {
    const forged = await createLegalAccessRequest(input, hex(2), intruder.privateKey, owner.trust);
    await expect(openLegalAccessRequest(forged, owner.trust.caseId, owner.privateKey, directory, now)).rejects.toThrow();
  });

  test('even the exact approved payload signed by another key is rejected', async () => {
    const forged = await raw(request, intruder.privateKey);
    await expect(openLegalAccessRequest(forged, owner.trust.caseId, owner.privateKey, directory, now)).rejects.toThrow();
  });

  test('unsigned encrypted requests are rejected', async () => {
    await expect(openLegalAccessRequest(await raw(request), owner.trust.caseId, owner.privateKey, directory, now)).rejects.toThrow();
  });

  test('a known firm without current whitelist approval cannot make an eligible request', async () => {
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey,
      [{ ...directory[0], approved: false }], now)).rejects.toThrow();
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, [], now)).rejects.toThrow();
  });

  test('ambiguous or substituted directory keys are rejected', async () => {
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey,
      [...directory, ...directory], now)).rejects.toThrow();
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey,
      [{ ...directory[0], publicKey: intruder.trust.ownerPublicKey }], now)).rejects.toThrow();
  });

  test('signed requests cannot be transplanted between cases or used outside their validity interval', async () => {
    await expect(openLegalAccessRequest(ciphertext, hex(99), owner.privateKey, directory, now)).rejects.toThrow();
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, directory, input.expiresAt)).rejects.toThrow();
    await expect(openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, directory, input.issuedAt - CLOCK_SKEW_MS - 1)).rejects.toThrow();
  });

  test('signed spoofed owner binding and unknown fields fail after decryption', async () => {
    for (const value of [{ ...request, ownerFingerprint: intruder.trust.ownerFingerprint },
      { ...request, format: 'vera-legal-access-request/v2' }, { ...request, adminOverride: true }]) {
      await expect(openLegalAccessRequest(await raw(value, firm.privateKey), owner.trust.caseId,
        owner.privateKey, directory, now)).rejects.toThrow('Invalid confidential access request');
    }
  });

  test.each([
    { ...input, scopes: [] }, { ...input, scopes: ['*'] }, { ...input, scopes: ['identity', 'identity'] },
    { ...input, purpose: '' }, { ...input, purpose: 'x'.repeat(1001) }, { ...input, objectRevisionLimit: 0 },
    { ...input, expiresAt: input.issuedAt }, { ...input, expiresAt: input.issuedAt + 31 * 24 * 60 * 60 * 1000 },
    { ...input, recipientKeyId: hex(99) }, { ...input, adminOverride: true },
  ])('rejects malformed or overbroad request input %#', async value => {
    await expect(createLegalAccessRequest(value as AccessRequestInput, hex(2), firm.privateKey, owner.trust)).rejects.toThrow();
  });

  test('creation snapshots requested scopes before asynchronous key operations', async () => {
    const mutable = { ...input, scopes: [...input.scopes] };
    const pending = createLegalAccessRequest(mutable, hex(2), firm.privateKey, owner.trust);
    mutable.scopes.push('identity'); mutable.purpose = 'Changed after approval';
    const result = await openLegalAccessRequest(await pending, owner.trust.caseId, owner.privateKey, directory, now);
    expect(result.scopes).toEqual(input.scopes);
    expect(result.purpose).toBe(input.purpose);
  });

  test('malformed and oversized ciphertext yields a generic error without request text', async () => {
    for (const value of ['PRIVATE-SENTINEL', 'x'.repeat(16_385)]) {
      await expect(openLegalAccessRequest(value, owner.trust.caseId, owner.privateKey, directory, now))
        .rejects.toThrow('Invalid confidential access request');
    }
  });
});
