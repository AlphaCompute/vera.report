import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import * as client from '../../../lib/confidential/client';
import { verifyOrganizationKeyContinuity } from '../../../enclave/src/confidential/firmMembers';
import {
  FirmMemberError, joinLink, knownKeyEpoch, prepareOrganizationRotation, publishedOrganizationKey, readJoinTarget, unfinishedRemovals,
} from '../../../lib/confidential/firmMemberDevices';
import type { MemberDevice } from '../../../lib/confidential/firmMemberDevices';
import type { FirmSession } from '../../../lib/confidential/firmCase';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const ORG = hex(0xabc);

function device(memberId: string, state: MemberDevice['state'], keyEpoch: number | null): MemberDevice {
  return { memberId, state, keyEpoch, devicePublicKey: null as never, deviceFingerprint: 'f'.repeat(40), deviceCode: '',
    profile: { name: memberId.slice(-4), contact: '' }, revision: 2, registeredAt: 1, updatedAt: 2, enrolled: false };
}

describe('member device page helpers', () => {
  test('join links carry only the organization ID and domain, and malformed links are refused', () => {
    const link = joinLink('https://vera.example', { organizationId: ORG, domain: 'counsel.example' });
    expect(link).toBe(`https://vera.example/legal/join#organization=${ORG}&domain=counsel.example`);
    expect(readJoinTarget(new URL(link).hash)).toEqual({ organizationId: ORG, domain: 'counsel.example' });
    expect(readJoinTarget(`#organization=${ORG.toUpperCase()}&domain=Counsel.Example`)).toEqual({ organizationId: ORG, domain: 'counsel.example' });
    expect(readJoinTarget(`#organization=${ORG.slice(1)}&domain=counsel.example`)).toBeNull();
    expect(readJoinTarget(`#organization=${ORG}&domain=not a domain`)).toBeNull();
    expect(readJoinTarget('')).toBeNull();
  });

  test('the known key epoch is the newest valid one, never below 1', () => {
    expect(knownKeyEpoch()).toBe(1);
    expect(knownKeyEpoch(undefined, null)).toBe(1);
    expect(knownKeyEpoch(1, 3)).toBe(3);
    expect(knownKeyEpoch(4, 2)).toBe(4);
    expect(knownKeyEpoch(0, -2, 1.5)).toBe(1);
  });

  test('a removal is unfinished only while the removed device held the current key', () => {
    const devices = [device(hex(1), 'removed', 1), device(hex(2), 'removed', null), device(hex(3), 'approved', 1),
      device(hex(4), 'pending', null), device(hex(5), 'removed', 2)];
    expect(unfinishedRemovals(devices, 1).map(item => item.memberId)).toEqual([hex(1), hex(5)]);
    expect(unfinishedRemovals(devices, 2).map(item => item.memberId)).toEqual([hex(5)]);
    expect(unfinishedRemovals(devices, 3)).toEqual([]);
  });

  test('fails closed when the approved-key channel cannot be verified', async () => {
    const verify = jest.spyOn(client, 'verifiedSession').mockRejectedValue(new Error('untrusted enclave'));
    const network = jest.spyOn(global, 'fetch');
    try {
      await expect(publishedOrganizationKey({ organizationId: ORG, domain: 'counsel.example' }, {
        relay: {} as never, releaseManifest: '', accessToken: 'synthetic', now: Date.now(),
      })).rejects.toBeInstanceOf(FirmMemberError);
      expect(network).not.toHaveBeenCalled();
    } finally { verify.mockRestore(); network.mockRestore(); }
  });

});

describe('rotation preparation', () => {
  let organizationKey: PrivateKey;
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    ({ privateKey: organizationKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Synthetic firm' }], format: 'object' }));
  }, 60_000);

  test('accepts only the requested approved organization and domain through the attested channel', async () => {
    const target = { organizationId: ORG, domain: 'counsel.example' };
    const input = { relay: {} as never, releaseManifest: '', accessToken: 'synthetic', now: Date.now() };
    const verify = jest.spyOn(client, 'verifiedSession').mockResolvedValue({} as never);
    const exchange = jest.spyOn(client, 'exchange').mockResolvedValue({ ...target, publicKey: organizationKey.toPublic().armor() });
    const network = jest.spyOn(global, 'fetch');
    try {
      expect((await publishedOrganizationKey(target, input)).getFingerprint()).toBe(organizationKey.getFingerprint());
      expect(network).not.toHaveBeenCalled();
      exchange.mockResolvedValue({ ...target, state: 'awaiting-key' });
      await expect(publishedOrganizationKey(target, input)).rejects.toMatchObject({ name: 'OrganizationKeyPendingError' });
      exchange.mockRejectedValueOnce(new Error('network failed'));
      await expect(publishedOrganizationKey(target, input)).rejects.toMatchObject({ name: 'FirmMemberError' });
      exchange.mockResolvedValue({ ...target, domain: 'other.example', publicKey: organizationKey.toPublic().armor() });
      await expect(publishedOrganizationKey(target, input)).rejects.toBeInstanceOf(FirmMemberError);
      exchange.mockResolvedValue({ ...target, publicKey: organizationKey.armor() });
      await expect(publishedOrganizationKey(target, input)).rejects.toBeInstanceOf(FirmMemberError);
    } finally { verify.mockRestore(); exchange.mockRestore(); network.mockRestore(); }
  });

  test('creates the next key locally with a continuity naming the removed members, and sends nothing', async () => {
    const calls: unknown[] = [];
    const session = { firm: { organizationId: ORG, domain: 'counsel.example', privateKey: organizationKey,
      recipientKeyId: await caseRecipientKeyId(organizationKey.toPublic()) },
    relay: new Proxy({}, { get: (_target, name) => { calls.push(name); throw new Error('no network'); } }) } as unknown as FirmSession;
    const prepared = await prepareOrganizationRotation(session, { keyEpoch: 3, removedMemberIds: [hex(7), hex(7), hex(8)] }, Date.now());
    expect(calls).toEqual([]);
    expect(prepared.statement).toMatchObject({ previousKeyEpoch: 3, keyEpoch: 4, removedMemberIds: [hex(7), hex(8)], ownerApproval: 'required' });
    expect(prepared.next.privateKey.getFingerprint()).not.toBe(organizationKey.getFingerprint());
    expect(prepared.next.recipientKeyId).toBe(await caseRecipientKeyId(prepared.next.privateKey.toPublic()));
    expect(prepared.next).toMatchObject({ organizationId: ORG, domain: 'counsel.example' });
    const verified = await verifyOrganizationKeyContinuity(prepared.continuity, { organizationId: ORG, previousPublicKey: organizationKey.toPublic() });
    expect(verified.nextPublicKey.getFingerprint()).toBe(prepared.next.privateKey.getFingerprint());
  }, 60_000);

  test('refuses an invalid epoch or member ID before creating any key', async () => {
    const session = { firm: { organizationId: ORG, domain: 'counsel.example', privateKey: organizationKey, recipientKeyId: hex(1) } } as unknown as FirmSession;
    await expect(prepareOrganizationRotation(session, { keyEpoch: 0, removedMemberIds: [] }, Date.now())).rejects.toBeInstanceOf(FirmMemberError);
    await expect(prepareOrganizationRotation(session, { keyEpoch: 1, removedMemberIds: ['bob'] }, Date.now())).rejects.toBeInstanceOf(FirmMemberError);
  });
});
