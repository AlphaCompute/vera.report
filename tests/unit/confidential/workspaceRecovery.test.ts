import { persistFirmWorkspace, setFirmSession, setFirmVault } from '../../../lib/confidential/firmPortal';
import { webcrypto } from 'node:crypto';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { ownerWorkspace, readOwnerWorkspace } from '../../../lib/confidential/deviceWorkspace';
import { assertFirmWorkspaceCapacity, firmWorkspace, readFirmWorkspace } from '../../../lib/confidential/firmWorkspace';
import { generateFirmIdentity } from '../../../lib/confidential/firmKey';
import { createDeviceVault, readVaultBackup } from '../../../lib/confidential/deviceVault';
import type { VaultRecord, VaultStore } from '../../../lib/confidential/deviceVault';
import type { OwnerSession } from '../../../lib/confidential/ownerCase';
import type { FirmSession } from '../../../lib/confidential/firmCase';

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });
async function fixture() {
  const owner = await createCaseOwner();
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1,
    previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: Date.now() }, owner.privateKey);
  const recovery = await createOwnerRecovery(owner, checkpoint);
  return { owner, checkpoint, recovery };
}

test('owner workspace re-download restores the same owner and verifies the saved checkpoint', async () => {
  const { owner, checkpoint, recovery } = await fixture();
  const session = { owner: owner.privateKey, recoveryCode: recovery.recoveryCode,
    pinnedCheckpoint: checkpoint, pin: recovery.pin } as OwnerSession;
  const payload = await ownerWorkspace(session);
  expect(await readOwnerWorkspace(payload)).toEqual(payload);
  await expect(readOwnerWorkspace({ ...payload, pin: { ...payload.pin, digest: 'a'.repeat(64) } })).rejects.toThrow();
  await expect(readOwnerWorkspace({ ...payload, recoveryCode: 'wrong' })).rejects.toThrow();
});

test('legal workspace preserves key, unlisted case references, owner anchors and anti-replay floors', async () => {
  const { owner, recovery } = await fixture();
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const caseId = owner.trust.caseId;
  const session = { firm, owners: new Map([[caseId, owner.trust]]), pins: new Map([[caseId, recovery.pin]]),
    sequences: new Map([[caseId, { owner: 4, organization: 2 }]]) } as FirmSession;
  const requests = [{ caseId, requestId: 'b'.repeat(64), ownerPublicKey: owner.trust.ownerPublicKey.armor(),
    summary: 'No longer listed publicly', requestedAt: Date.now() }];
  const payload = firmWorkspace(session, requests);
  const restored = await readFirmWorkspace(payload);
  expect(restored.firm.privateKey.getFingerprint()).toBe(firm.privateKey.getFingerprint());
  expect(restored.requests).toEqual(requests);
  expect(restored.owners.get(caseId)?.ownerFingerprint).toBe(owner.trust.ownerFingerprint);
  expect(restored.pins.get(caseId)).toEqual(recovery.pin);
  expect(restored.sequences.get(caseId)).toEqual({ owner: 4, organization: 2 });
  await expect(readFirmWorkspace({ ...payload, recipientKeyId: 'c'.repeat(64) })).rejects.toThrow();
  await expect(readFirmWorkspace({ ...payload, pins: [{ ...recovery.pin, ownerFingerprint: 'd'.repeat(40) }] })).rejects.toThrow();
  await expect(readFirmWorkspace({ ...payload, requests: [...requests, ...requests] })).rejects.toThrow();
  await expect(readFirmWorkspace({ ...payload, owners: [{ caseId, ownerPublicKey: firm.privateKey.toPublic().armor() }] })).rejects.toThrow();
  // Workspaces saved before organization profiles existed still restore.
  expect(payload).not.toHaveProperty('profile');
  expect(restored.profile).toBeNull();
  const profile = { practiceAreas: ['Employment'], jurisdiction: 'Ontario', website: 'https://counsel.example/' };
  const withProfile = firmWorkspace(session, requests, { profile });
  expect((await readFirmWorkspace(withProfile)).profile).toEqual(profile);
  for (const bad of [{ ...profile, website: 'http://counsel.example/' }, { ...profile, extra: 1 }, { ...profile, practiceAreas: ['a\nb'] }]) {
    await expect(readFirmWorkspace({ ...withProfile, profile: bad })).rejects.toThrow('invalid');
    expect(() => firmWorkspace(session, requests, { profile: bad as typeof profile })).toThrow();
  }
});

test('encrypted workspace export restores without opting a new device into persistence', async () => {
  const records = new Map<string, VaultRecord>();
  const store: VaultStore = { generation: async () => 0, list: async () => [...records.values()],
    get: async id => records.get(id) ?? null, put: async record => { records.set(record.id, record); },
    remove: async id => { records.delete(id); }, clear: async () => { records.clear(); } };
  const payload = { caseIndex: ['PRIVATE-CASE-INDEX'], privateKey: 'PRIVATE-KEY-SENTINEL' };
  const handle = await createDeviceVault(store, 'legal', 'a long backup passphrase', payload);
  const exported = await handle.exportBackup();
  expect(exported).not.toContain('PRIVATE');
  await store.clear(); handle.lock();
  expect(await readVaultBackup(exported, 'legal', 'a long backup passphrase')).toEqual(payload);
  expect(records.size).toBe(0);
  await expect(readVaultBackup(exported, 'owner', 'a long backup passphrase')).rejects.toThrow();
  await expect(readVaultBackup(exported, 'legal', 'wrong long backup passphrase')).rejects.toThrow();
});

test('a newer file-read checkpoint persists in the legal vault and save failures are surfaced', async () => {
  const { owner, recovery } = await fixture();
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const caseId = owner.trust.caseId;
  const session = { firm, owners: new Map([[caseId, owner.trust]]), pins: new Map([[caseId, recovery.pin]]),
    sequences: new Map() } as FirmSession;
  let failWrite = false;
  const records = new Map<string, VaultRecord>();
  const store: VaultStore = { generation: async () => 0, list: async () => [...records.values()],
    get: async id => records.get(id) ?? null, put: async record => {
      if (failWrite) throw new Error('synthetic storage failure');
      records.set(record.id, record);
    }, remove: async id => { records.delete(id); }, clear: async () => { records.clear(); } };
  setFirmSession(session);
  const vault = await createDeviceVault(store, 'legal', 'a long backup passphrase', firmWorkspace(session, []));
  setFirmVault(vault, []);
  try {
    const newer = { ...recovery.pin, revision: 2, digest: 'e'.repeat(64) };
    session.pins.set(caseId, newer);
    await persistFirmWorkspace();
    expect((await readFirmWorkspace(vault.read())).pins.get(caseId)).toEqual(newer);
    failWrite = true;
    session.pins.set(caseId, { ...newer, revision: 3, digest: 'f'.repeat(64) });
    await expect(persistFirmWorkspace()).rejects.toThrow('synthetic storage failure');
    expect((await readFirmWorkspace(vault.read())).pins.get(caseId)).toEqual(newer);
  } finally { setFirmSession(null); }
});

test('withdrawn case anchors still count toward capacity and oversized workspaces cannot be exported', async () => {
  const { owner } = await fixture();
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const owners = new Map(Array.from({ length: 200 }, (_, index) => {
    const caseId = index.toString(16).padStart(64, '0');
    return [caseId, { ...owner.trust, caseId }] as const;
  }));
  const session = { firm, owners, pins: new Map(), sequences: new Map() } as FirmSession;
  // All requests may have been withdrawn; historical pins/anchors must remain.
  expect(() => firmWorkspace(session, [])).not.toThrow();
  expect(() => assertFirmWorkspaceCapacity(session, [], '0'.repeat(64))).not.toThrow();
  const newCaseId = 'f'.repeat(64);
  expect(() => assertFirmWorkspaceCapacity(session, [], newCaseId)).toThrow('saved-case limit');
  const { requestCaseAccess } = await import('../../../lib/confidential/firmCase');
  await expect(requestCaseAccess(session, { caseId: newCaseId, summary: 'Summary', owner: { ...owner.trust, caseId: newCaseId } },
    { purpose: 'Review', scopes: ['narrative'] }, Date.now())).rejects.toThrow('saved-case limit');
  expect(session.owners.size).toBe(200);
  owners.set(newCaseId, { ...owner.trust, caseId: newCaseId });
  expect(() => firmWorkspace(session, [])).toThrow('saved-case limit');
});
