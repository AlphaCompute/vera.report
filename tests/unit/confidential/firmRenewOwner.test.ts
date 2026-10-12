import { webcrypto } from 'node:crypto';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { ownerFromRequest } from '../../../lib/confidential/firmPortal';
import type { FirmSession } from '../../../lib/confidential/firmCase';

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

async function owner() {
  const created = await createCaseOwner();
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: created.trust.caseId, revision: 1, keyEpoch: 1,
    previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: Date.now() }, created.privateKey);
  const recovery = await createOwnerRecovery(created, checkpoint);
  return { created, pin: recovery.pin };
}
const session = (extra: Partial<FirmSession> = {}) => ({ owners: new Map(), pins: new Map(), ...extra }) as FirmSession;

describe('reporter key for a renewal request', () => {
  test('an unpinned session (key file unlock, or another lawyer\'s request) takes the key from the request row', async () => {
    const { created } = await owner();
    const caseId = created.trust.caseId;
    const target = session();
    const trust = await ownerFromRequest(target, { caseId, ownerPublicKey: created.trust.ownerPublicKey.armor() });
    expect(trust?.ownerFingerprint).toBe(created.trust.ownerFingerprint);
    expect(target.owners.get(caseId)?.ownerFingerprint).toBe(created.trust.ownerFingerprint);
  });

  test('a key that differs from the pinned owner or saved checkpoint is refused and not replaced', async () => {
    const first = await owner();
    const other = await owner();
    const caseId = first.created.trust.caseId;
    const pinnedOwner = session({ owners: new Map([[caseId, first.created.trust]]) });
    expect(await ownerFromRequest(pinnedOwner, { caseId, ownerPublicKey: other.created.trust.ownerPublicKey.armor() })).toBeNull();
    expect(pinnedOwner.owners.get(caseId)).toBe(first.created.trust);

    const pinnedCheckpoint = session({ pins: new Map([[caseId, first.pin]]) });
    expect(await ownerFromRequest(pinnedCheckpoint, { caseId, ownerPublicKey: other.created.trust.ownerPublicKey.armor() })).toBeNull();
    expect(pinnedCheckpoint.owners.has(caseId)).toBe(false);
    expect(await ownerFromRequest(pinnedCheckpoint, { caseId, ownerPublicKey: first.created.trust.ownerPublicKey.armor() }))
      .toMatchObject({ ownerFingerprint: first.created.trust.ownerFingerprint });
  });

  test('private or unreadable keys are refused', async () => {
    const { created } = await owner();
    const target = session();
    expect(await ownerFromRequest(target, { caseId: created.trust.caseId, ownerPublicKey: created.privateKey.armor() })).toBeNull();
    expect(await ownerFromRequest(target, { caseId: created.trust.caseId, ownerPublicKey: 'not a key' })).toBeNull();
    expect(target.owners.size).toBe(0);
  });
});
