import { createMessage, generateKey, sign } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { readPrivateKey, revokeKey } from 'openpgp';
import { createHash } from 'node:crypto';
import { readKey } from '../../../enclave/src/confidential/pgp';
import { createFirmKeyBinding, verifyFirmKeyBinding as enclaveVerify } from '../../../enclave/src/confidential/firmKeyBinding';
import { verifyFirmKeyBinding as hostVerify } from '../../../src/utils/legalApplicationKey';

const expected = { organizationId: '1'.repeat(64), domain: 'firm.example' };
const profile = { practiceAreas: ['whistleblower' as const], jurisdiction: 'New York', website: 'https://firm.example/', contacts: { email: 'counsel@firm.example' } };
let firm: PrivateKey, other: PrivateKey, document: string;
beforeAll(async () => {
  [firm, other] = await Promise.all(['firm', 'other'].map(async name => (await generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object',
  })).privateKey));
  document = await createFirmKeyBinding({ ...expected, issuedAt: Date.now(), profile }, firm);
});

it.each([false, true])('host intake accepts the same signed public binding as the enclave (profile: %s)', async withProfile => {
  const wire = await createFirmKeyBinding({ ...expected, issuedAt: Date.now(), ...(withProfile ? { profile } : {}) }, firm);
  const host = await hostVerify(wire, expected), enclave = await enclaveVerify(wire, expected);
  expect(host.binding).toEqual(enclave.binding);
  expect(host.profile).toEqual(enclave.profile);
  expect(host.publicKey.armor()).toBe(enclave.publicKey.armor());
});

describe('application key clock skew', () => {
  afterEach(() => jest.useRealTimers());
  it.each([-5_000, 5_000])('accepts a new key from a device %i ms from the intake clock', async skew => {
    const now = Math.floor(Date.now() / 1000) * 1000;
    jest.useFakeTimers({ now: now + skew, doNotFake: ['nextTick', 'setImmediate', 'setTimeout', 'clearTimeout', 'performance'] });
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Synthetic applicant' }], format: 'object' });
    const wire = await createFirmKeyBinding({ ...expected, issuedAt: Date.now(), profile }, privateKey);
    jest.setSystemTime(now);
    for (const verify of [hostVerify, enclaveVerify]) {
      await expect(verify(wire, expected)).resolves.toMatchObject({ binding: { issuedAt: now + skew } });
    }
  });

  it('rejects a signature timestamp beyond the five-minute skew limit', async () => {
    const now = Math.floor(Date.now() / 1000) * 1000;
    jest.useFakeTimers({ now, doNotFake: ['nextTick', 'setImmediate', 'setTimeout', 'clearTimeout', 'performance'] });
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Synthetic applicant' }], date: new Date(now - 60_000), format: 'object' });
    jest.setSystemTime(now + 301_000);
    const wire = await createFirmKeyBinding({ ...expected, issuedAt: Date.now(), profile }, privateKey);
    jest.setSystemTime(now);
    for (const verify of [hostVerify, enclaveVerify]) await expect(verify(wire, expected)).rejects.toThrow('Invalid firm key binding');
  });

  it('does not revive a key that expired since the binding was signed', async () => {
    const now = Math.floor(Date.now() / 1000) * 1000;
    jest.useFakeTimers({ now: now - 120_000, doNotFake: ['nextTick', 'setImmediate', 'setTimeout', 'clearTimeout', 'performance'] });
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Synthetic expiring key' }], keyExpirationTime: 60, format: 'object' });
    const wire = await createFirmKeyBinding({ ...expected, issuedAt: Date.now(), profile }, privateKey);
    jest.setSystemTime(now);
    for (const verify of [hostVerify, enclaveVerify]) await expect(verify(wire, expected)).rejects.toThrow('Invalid firm key binding');
  });

  it('still rejects a revoked key even with a valid binding signature', async () => {
    const revoked = await revokeKey({ key: await readPrivateKey({ armoredKey: firm.armor() }), format: 'armored' });
    const value = JSON.parse(document);
    value.publicKey = revoked.publicKey;
    value.binding.recipientKeyId = createHash('sha256').update((await readKey({ armoredKey: revoked.publicKey })).write()).digest('hex');
    value.signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value.binding)) }),
      signingKeys: firm, detached: true, format: 'armored' });
    for (const verify of [hostVerify, enclaveVerify]) await expect(verify(JSON.stringify(value), expected)).rejects.toThrow('Invalid firm key binding');
  });
});

it.each([
  ['altered domain', (v: any) => { v.binding.domain = 'other.example'; }],
  ['altered organization', (v: any) => { v.binding.organizationId = '2'.repeat(64); }],
  ['altered key ID', (v: any) => { v.binding.recipientKeyId = '2'.repeat(64); }],
  ['substituted public key', (v: any) => { v.publicKey = other.toPublic().armor(); }],
  ['private key in public field', (v: any) => { v.publicKey = firm.armor(); }],
  ['tampered profile', (v: any) => { v.binding.profile.jurisdiction = 'London'; }],
  ['extra statement field', (v: any) => { v.binding.approved = true; }],
  ['extra envelope field', (v: any) => { v.approved = true; }],
] as const)('host and enclave both reject %s', async (_name, alter) => {
  const value = JSON.parse(document); alter(value);
  for (const verify of [hostVerify, enclaveVerify]) await expect(verify(JSON.stringify(value), expected)).rejects.toThrow();
});

it.each([
  ['unapproved website', (v: any) => { v.profile.website = 'https://other.example/'; }],
  ['unknown practice area', (v: any) => { v.profile.practiceAreas = ['unknown']; }],
  ['duplicate practice areas', (v: any) => { v.profile.practiceAreas = ['whistleblower', 'whistleblower']; }],
  ['invalid contact email', (v: any) => { v.profile.contacts.email = 'firm.example'; }],
  ['unknown contact field', (v: any) => { v.profile.contacts.password = 'invalid'; }],
  ['noncanonical jurisdiction', (v: any) => { v.profile.jurisdiction = ' New York '; }],
  ['unknown profile field', (v: any) => { v.profile.approved = true; }],
] as const)('both reject a correctly signed binding with %s', async (_name, alter) => {
  const value = JSON.parse(document); alter(value.binding);
  value.signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value.binding)) }),
    signingKeys: firm, detached: true, format: 'armored' });
  for (const verify of [hostVerify, enclaveVerify]) await expect(verify(JSON.stringify(value), expected)).rejects.toThrow();
});
