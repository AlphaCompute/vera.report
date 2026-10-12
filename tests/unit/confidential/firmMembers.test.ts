import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import {
  firmMemberId, formatDeviceCode, openMemberProfile, rotateOrganizationKey, sealMemberProfile, unwrapOrganizationKey,
  verifyOrganizationKeyContinuity, wrapOrganizationKeyForMember,
} from '../../../enclave/src/confidential/firmMembers';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const key = async (name: string) => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey;
const ORG = hex(0xf1), ALICE = hex(0xa1), BOB = hex(0xb0), now = Date.now();

describe('firm member key distribution', () => {
  let organization: PrivateKey, steward: PrivateKey, alice: PrivateKey, bob: PrivateKey, stranger: PrivateKey;
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    [organization, steward, alice, bob, stranger] = await Promise.all(
      ['Synthetic org', 'Synthetic steward', 'Alice device', 'Bob device', 'Stranger'].map(key));
  });
  const expected = (memberId = ALICE, keyEpoch = 1) => ({ organizationId: ORG, memberId, keyEpoch,
    organizationPublicKey: organization.toPublic(), steward: steward.toPublic() });

  test('the steward wraps the organization key to one member device; only that member opens it', async () => {
    const envelope = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      organization, alice.toPublic(), steward);
    expect(envelope).not.toContain(organization.armor().slice(40, 120));
    const opened = await unwrapOrganizationKey(envelope, expected(), alice);
    expect(opened.organizationKey.getFingerprint()).toBe(organization.getFingerprint());
    expect(opened.binding).toEqual({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now });
    await expect(unwrapOrganizationKey(envelope, expected(), bob)).rejects.toThrow('Invalid firm member key material');
  });

  test('binding, steward signature and organization key identity are all enforced', async () => {
    const envelope = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      organization, alice.toPublic(), steward);
    await expect(unwrapOrganizationKey(envelope, expected(BOB), alice)).rejects.toThrow();
    await expect(unwrapOrganizationKey(envelope, expected(ALICE, 2), alice)).rejects.toThrow();
    await expect(unwrapOrganizationKey(envelope, { ...expected(), organizationId: hex(0xf2) }, alice)).rejects.toThrow();
    await expect(unwrapOrganizationKey(envelope, { ...expected(), steward: stranger.toPublic() }, alice)).rejects.toThrow();
    // Not signed by the pinned steward (e.g. a relay or Vera operator wrapping a key).
    const forged = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      organization, alice.toPublic(), stranger);
    await expect(unwrapOrganizationKey(forged, expected(), alice)).rejects.toThrow();
    // Steward-signed, but a substituted organization key the member does not trust.
    const substituted = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      stranger, alice.toPublic(), steward);
    await expect(unwrapOrganizationKey(substituted, expected(), alice)).rejects.toThrow();
    await expect(wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      organization, alice, steward)).rejects.toThrow();
  });

  test('member removal rotates the organization key with a dual-signed continuity statement', async () => {
    const rotated = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [BOB], issuedAt: now },
      organization);
    const verified = await verifyOrganizationKeyContinuity(rotated.continuity, { organizationId: ORG, previousPublicKey: organization.toPublic() });
    expect(verified.statement).toMatchObject({ keyEpoch: 2, removedMemberIds: [BOB], ownerApproval: 'required',
      previousRecipientKeyId: await caseRecipientKeyId(organization.toPublic()),
      nextRecipientKeyId: await caseRecipientKeyId(rotated.organizationKey.toPublic()) });
    // A new recipient key ID: existing owner grants do not cover it.
    expect(verified.statement.nextRecipientKeyId).not.toBe(verified.statement.previousRecipientKeyId);
    expect(verified.nextPublicKey.getFingerprint()).toBe(rotated.organizationKey.getFingerprint());

    // The steward rewraps the new key for the remaining member only, at the new epoch.
    const next = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 2, issuedAt: now },
      rotated.organizationKey, alice.toPublic(), steward);
    const opened = await unwrapOrganizationKey(next, { ...expected(ALICE, 2), organizationPublicKey: verified.nextPublicKey }, alice);
    expect(opened.organizationKey.getFingerprint()).toBe(rotated.organizationKey.getFingerprint());
    // Bob's old epoch-1 envelope never yields the new key.
    const bobOld = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: BOB, keyEpoch: 1, issuedAt: now },
      organization, bob.toPublic(), steward);
    await expect(unwrapOrganizationKey(bobOld, { ...expected(BOB, 2), organizationPublicKey: verified.nextPublicKey }, bob)).rejects.toThrow();
  });

  test('continuity requires the old key, the new key and exact fields', async () => {
    const rotated = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [BOB], issuedAt: now },
      organization);
    const check = (document: string, previousPublicKey = organization.toPublic(), organizationId = ORG) =>
      verifyOrganizationKeyContinuity(document, { organizationId, previousPublicKey });
    await expect(check(rotated.continuity, stranger.toPublic())).rejects.toThrow();
    await expect(check(rotated.continuity, organization.toPublic(), hex(0xf2))).rejects.toThrow();
    const parsed = JSON.parse(rotated.continuity);
    // A key thief without the old key cannot claim continuity.
    const thief = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: now }, stranger);
    await expect(check(JSON.stringify({ ...parsed, previousSignature: JSON.parse(thief.continuity).previousSignature }))).rejects.toThrow();
    await expect(check(JSON.stringify({ ...parsed, statement: { ...parsed.statement, removedMemberIds: [] } }))).rejects.toThrow();
    await expect(check(JSON.stringify({ ...parsed, statement: { ...parsed.statement, ownerApproval: 'not-required' } }))).rejects.toThrow();
    await expect(check(JSON.stringify({ ...parsed, nextPublicKey: stranger.toPublic().armor() }))).rejects.toThrow();
    await expect(check(JSON.stringify({ ...parsed, nextSignature: parsed.previousSignature }))).rejects.toThrow();
  });
});

describe('member device registration material', () => {
  let organization: PrivateKey, device: PrivateKey, other: PrivateKey;
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    [organization, device, other] = await Promise.all(['Synthetic org', 'Synthetic device', 'Synthetic other'].map(key));
  });

  test('member IDs are derived from the identity-provider organization and subject', async () => {
    const first = await firmMemberId('org_firm', 'auth0|lawyer');
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(await firmMemberId('org_firm', 'auth0|lawyer')).toBe(first);
    expect(await firmMemberId('org_other', 'auth0|lawyer')).not.toBe(first);
    expect(await firmMemberId('org_firm', 'auth0|other')).not.toBe(first);
    await expect(firmMemberId('', 'auth0|lawyer')).rejects.toThrow();
  });

  test('device codes group the fingerprint for reading aloud', () => {
    const code = formatDeviceCode(device.getFingerprint());
    expect(code).toMatch(/^([0-9A-F]{4} )+[0-9A-F]{4}$/);
    expect(code.replace(/ /g, '').toLowerCase()).toBe(device.getFingerprint());
    expect(() => formatDeviceCode('not-a-fingerprint')).toThrow();
  });

  test('the profile is readable only with the organization key and only for the signing device', async () => {
    const sealed = await sealMemberProfile({ organizationId: ORG, profile: { name: '  Synthetic   Lawyer ', contact: 'lawyer@counsel.example' } },
      organization.toPublic(), device);
    expect(sealed).not.toContain('Synthetic');
    await expect(openMemberProfile(sealed, { organizationId: ORG, devicePublicKey: device.toPublic() }, organization))
      .resolves.toEqual({ name: 'Synthetic Lawyer', contact: 'lawyer@counsel.example' });
    await expect(openMemberProfile(sealed, { organizationId: ORG, devicePublicKey: other.toPublic() }, organization)).rejects.toThrow();
    await expect(openMemberProfile(sealed, { organizationId: hex(0xf2), devicePublicKey: device.toPublic() }, organization)).rejects.toThrow();
    await expect(openMemberProfile(sealed, { organizationId: ORG, devicePublicKey: device.toPublic() }, other)).rejects.toThrow();
    await expect(sealMemberProfile({ organizationId: ORG, profile: { name: ' ', contact: '' } }, organization.toPublic(), device)).rejects.toThrow();
    await expect(sealMemberProfile({ organizationId: ORG, profile: { name: 'x'.repeat(81), contact: '' } }, organization.toPublic(), device)).rejects.toThrow();
  });

  test('an envelope signed by the organization key itself opens only to that key', async () => {
    const envelope = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      organization, device.toPublic(), organization);
    const opened = await unwrapOrganizationKey(envelope, { organizationId: ORG, memberId: ALICE, keyEpoch: 1,
      organizationPublicKey: organization.toPublic(), steward: organization.toPublic() }, device);
    expect(opened.organizationKey.getFingerprint()).toBe(organization.getFingerprint());
    // A substituted "organization" key (for example from a hostile relay) is refused.
    const substitute = await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: ALICE, keyEpoch: 1, issuedAt: now },
      other, device.toPublic(), other);
    await expect(unwrapOrganizationKey(substitute, { organizationId: ORG, memberId: ALICE, keyEpoch: 1,
      organizationPublicKey: organization.toPublic(), steward: organization.toPublic() }, device)).rejects.toThrow();
  });
});
