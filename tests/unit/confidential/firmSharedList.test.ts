import { webcrypto } from 'node:crypto';
import { createMessage, generateKey, sign } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { rotateOrganizationKey } from '../../../enclave/src/confidential/firmMembers';
import {
  FIRM_SHARED_LIST_BUCKET, FIRM_SHARED_REQUEST_LIMIT, FirmSharedListKeyChanged, openFirmSharedList, sealFirmSharedList, validFirmSharedList,
  verifyFirmSharedListWrite,
} from '../../../enclave/src/confidential/firmSharedList';
import type { FirmSharedList, SharedRequest } from '../../../enclave/src/confidential/firmSharedList';
import { requestOutcome } from '../../../lib/confidential/firmSharedRequests';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const key = async (name: string) => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey;
const ORG = hex(0xf1), now = Date.now();

describe('organization shared request list', () => {
  let organization: PrivateKey, other: PrivateKey, keyId: string, entry: SharedRequest, list: FirmSharedList;
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    [organization, other] = await Promise.all([key('Synthetic org'), key('Synthetic other')]);
    keyId = await caseRecipientKeyId(organization.toPublic());
    entry = { caseId: hex(1), requestId: hex(2), ownerPublicKey: other.toPublic().armor(), summary: 'Synthetic summary',
      requestedAt: now, expiresAt: now + 86_400_000, recipientKeyId: keyId, state: 'requested', updatedAt: now, grantExpiresAt: null };
    list = { keyEpoch: 1, requests: [entry] };
  });
  const expected = () => ({ organizationId: ORG, recipientKeyId: keyId, publicKey: organization.toPublic().armor() });

  test('members read what a member wrote; the enclave checks the registered signer and version', async () => {
    const wire = await sealFirmSharedList(list, { organizationId: ORG, version: 3 }, organization);
    expect(wire).not.toContain('Synthetic summary');
    expect(wire).not.toContain(hex(2));
    await expect(verifyFirmSharedListWrite(wire, expected())).resolves.toMatchObject({ version: 3, organizationId: ORG, recipientKeyId: keyId });
    const opened = await openFirmSharedList(wire, { organizationId: ORG, minimumVersion: 3 }, organization);
    expect(opened.list).toEqual(list);
    expect(opened.version).toBe(3);
  });

  test('a replayed older version, another organization or another key is refused', async () => {
    const wire = await sealFirmSharedList(list, { organizationId: ORG, version: 2 }, organization);
    await expect(openFirmSharedList(wire, { organizationId: ORG, minimumVersion: 3 }, organization)).rejects.toThrow('Invalid organization request list');
    await expect(openFirmSharedList(wire, { organizationId: hex(0xf2), minimumVersion: 0 }, organization)).rejects.toThrow();
    await expect(verifyFirmSharedListWrite(wire, { ...expected(), organizationId: hex(0xf2) })).rejects.toThrow();
    const forged = await sealFirmSharedList(list, { organizationId: ORG, version: 4 }, other, organization.toPublic(),
      { publicKey: other.toPublic().armor(), continuity: '{}' });
    await expect(verifyFirmSharedListWrite(forged, expected())).rejects.toThrow();
    await expect(openFirmSharedList(forged, { organizationId: ORG, minimumVersion: 0 }, organization)).rejects.toThrow();
  });

  test('ciphertext or header tampering breaks the signature', async () => {
    const wire = JSON.parse(await sealFirmSharedList(list, { organizationId: ORG, version: 5 }, organization));
    const bumped = JSON.stringify({ ...wire, header: { ...wire.header, version: 6 } });
    await expect(verifyFirmSharedListWrite(bumped, expected())).rejects.toThrow();
    const swapped = JSON.stringify({ ...wire, ciphertext: (await sealFirmSharedList({ keyEpoch: 1, requests: [] },
      { organizationId: ORG, version: 5 }, organization).then(text => JSON.parse(text).ciphertext)) });
    await expect(verifyFirmSharedListWrite(swapped, expected())).rejects.toThrow();
    await expect(openFirmSharedList(swapped, { organizationId: ORG, minimumVersion: 0 }, organization)).rejects.toThrow();
  });

  test('after a rotation only the new key reads the list, through continuity signed by both keys', async () => {
    const rotated = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [hex(0xb0)], issuedAt: now }, organization);
    const moved = await sealFirmSharedList({ keyEpoch: 2, requests: [entry] }, { organizationId: ORG, version: 7 },
      organization, rotated.organizationKey.toPublic(), { publicKey: organization.toPublic().armor(), continuity: rotated.continuity });
    // Still written with the registered (old) key.
    await expect(verifyFirmSharedListWrite(moved, expected())).resolves.toMatchObject({ version: 7 });
    const opened = await openFirmSharedList(moved, { organizationId: ORG, minimumVersion: 0 }, rotated.organizationKey);
    expect(opened.list.keyEpoch).toBe(2);
    expect(opened.header.recipientKeyId).toBe(keyId);
    // A device still on the old key, such as the removed member's, cannot read it.
    await expect(openFirmSharedList(moved, { organizationId: ORG, minimumVersion: 0 }, organization)).rejects.toBeInstanceOf(FirmSharedListKeyChanged);
    // A continuity for a different successor does not let an unrelated key in.
    const unrelated = await key('Unrelated');
    await expect(openFirmSharedList(moved, { organizationId: ORG, minimumVersion: 0 }, unrelated)).rejects.toThrow();
    // A predecessor without continuity cannot sign for the new key.
    await expect(sealFirmSharedList(list, { organizationId: ORG, version: 8 }, organization,
      rotated.organizationKey.toPublic(), null)).rejects.toThrow();
  });

  test('the stored wire carries no write time and one more request does not change its size', async () => {
    const one = await sealFirmSharedList(list, { organizationId: ORG, version: 3 }, organization);
    const parsed = JSON.parse(one);
    expect(parsed.header.format).toBe('vera-firm-shared-list/v2');
    expect(Object.keys(parsed.header)).not.toContain('issuedAt');
    expect(one).not.toMatch(/"(issuedAt|updatedAt|createdAt)"/);
    expect(one.length % FIRM_SHARED_LIST_BUCKET).toBe(0);
    const two = await sealFirmSharedList({ keyEpoch: 1, requests: [entry, { ...entry, caseId: hex(3), requestId: hex(4) }] },
      { organizationId: ORG, version: 4 }, organization);
    expect(two.length).toBe(one.length);
    await expect(openFirmSharedList(two, { organizationId: ORG, minimumVersion: 4 }, organization))
      .resolves.toMatchObject({ version: 4 });
    // The enclave refuses an unpadded write, so a client cannot leak the exact size.
    await expect(verifyFirmSharedListWrite(one.trimEnd(), expected())).rejects.toThrow();
  });

  test('a legacy v1 list (with a write time) still opens, but the enclave refuses v1 writes', async () => {
    const current = JSON.parse(await sealFirmSharedList(list, { organizationId: ORG, version: 2 }, organization));
    const legacyHeader = { format: 'vera-firm-shared-list/v1', organizationId: ORG, recipientKeyId: keyId, encryptedToKeyId: keyId,
      version: 2, issuedAt: now, ciphertextDigest: current.header.ciphertextDigest, predecessorDigest: null };
    const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(legacyHeader)) }),
      signingKeys: organization, detached: true, format: 'armored' }) as string;
    const legacy = JSON.stringify({ header: legacyHeader, ciphertext: current.ciphertext, signature, predecessor: null });
    await expect(openFirmSharedList(legacy, { organizationId: ORG, minimumVersion: 2 }, organization))
      .resolves.toMatchObject({ version: 2, list });
    const padded = legacy.padEnd(Math.ceil(legacy.length / FIRM_SHARED_LIST_BUCKET) * FIRM_SHARED_LIST_BUCKET, ' ');
    await expect(verifyFirmSharedListWrite(padded, expected())).rejects.toThrow();
  });

  test('list shape and size are bounded', async () => {
    expect(validFirmSharedList({ keyEpoch: 1, requests: [entry, entry] })).toBe(false);
    expect(validFirmSharedList({ keyEpoch: 1, requests: [{ ...entry, extra: true }] })).toBe(false);
    expect(validFirmSharedList({ keyEpoch: 0, requests: [] })).toBe(false);
    const many = Array.from({ length: FIRM_SHARED_REQUEST_LIMIT + 1 }, (_, index) => ({ ...entry, caseId: hex(1000 + index) }));
    await expect(sealFirmSharedList({ keyEpoch: 1, requests: many }, { organizationId: ORG, version: 1 }, organization)).rejects.toThrow();
  });

  test('outcomes shown to members', () => {
    expect(requestOutcome(entry, keyId, now)).toBe('waiting');
    expect(requestOutcome(entry, keyId, now + 2 * 86_400_000)).toBe('expired');
    expect(requestOutcome({ ...entry, state: 'granted', grantExpiresAt: now + 1000 }, keyId, now)).toBe('allowed');
    expect(requestOutcome({ ...entry, state: 'withdrawn' }, keyId, now)).toBe('withdrawn');
    expect(requestOutcome({ ...entry, state: 'granted', grantExpiresAt: now + 1000 }, hex(0xee), now)).toBe('renew');
  });
});
