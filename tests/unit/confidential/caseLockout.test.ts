import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { webcrypto } from 'node:crypto';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import type { PreparedSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { encodeBase64, findCaseStateKey, generateCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation } from '../../../enclave/src/confidential/participantRequest';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { createCaseService } from '../../../enclave/src/cases/service';
import type { CaseRecord, CaseStore } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02) };
const AUDIENCE = 'vera-confidential-cases';
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

/** TEST-ONLY persistent store shared across simulated enclave restarts. */
const staged = new Map<string, string>(), cases = new Map<string, CaseRecord>();
const inner = {
  async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
  putObjects: jest.fn(async () => { /* content-addressed; record admission only */ }),
  async createCase(record: CaseRecord) {
    if (cases.has(record.caseId)) return false;
    cases.set(record.caseId, JSON.parse(JSON.stringify(record))); return true;
  },
  async getCase(caseId: string) { const value = cases.get(caseId); return value ? JSON.parse(JSON.stringify(value)) : null; },
} as unknown as CaseStore;

/** A fresh enclave process: new empty keyring over the same persistent store. */
async function boot() {
  const keyring = createCaseKeyring({ clock: () => now });
  const store = createSealedCaseStore(inner, keyring);
  const service = createCaseService({ channel: { ...CHANNEL, challenges: createSessionChallenges() }, store, keyring, clock: () => now, audience: AUDIENCE,
    releaseDigest: (await readReleaseManifest(MANIFEST)).digest });
  const call = async (operation: ParticipantOperation, caseId: string, body: Uint8Array, key: PrivateKey) => {
    const { challenge } = await service.issueChallenge();
    return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: 'owner', caseId, organizationId: null,
      operation, body, challenge, issuedAt: now }, key);
  };
  return { keyring, store, service, call };
}
async function publish(enclave: Awaited<ReturnType<typeof boot>>, prepared: PreparedSubmission, caseId = prepared.caseId,
  body = prepared.publishBody) {
  for (const item of prepared.stagedObjects) staged.set(item.digest, item.ciphertext);
  return enclave.service.publishCase(body, await enclave.call('publish-case', caseId, body, prepared.owner.privateKey));
}
/** A well-formed publish of `victimCaseId`, signed by an unrelated attacker key with its own state key. */
async function hostilePublish(victimCaseId: string): Promise<{ attacker: PreparedSubmission; body: Uint8Array }> {
  const attacker = await prepareConfidentialSubmission({ summary: 'Attacker summary', narrative: { description: 'x' },
    contact: null, identity: null, files: [] }, MANIFEST, now);
  const own = JSON.parse(new TextDecoder().decode(attacker.publishBody));
  const trust = { ...attacker.owner.trust, caseId: victimCaseId };
  const signed = async (statement: OwnerStatement) => {
    const wire = await signOwnerStatement(statement, attacker.owner.privateKey);
    return { wire, digest: (await verifyOwnerStatement(wire, trust)).digest };
  };
  const listing = await signed({ kind: 'listing', caseId: victimCaseId, revision: 1, summary: 'Attacker summary' });
  const release = await signed({ kind: 'release', caseId: victimCaseId, revision: 1,
    releaseDigest: (await readReleaseManifest(MANIFEST)).digest, issuedAt: now });
  const checkpoint = await signed({ kind: 'checkpoint', caseId: victimCaseId, revision: 1, keyEpoch: 1, previousDigest: null,
    listingDigest: listing.digest, manifestDigest: null, grantDigests: [], releaseDigests: [release.digest], issuedAt: now });
  const body = encode({ ...own, caseId: victimCaseId, statements: [listing.wire, release.wire], checkpoint: checkpoint.wire,
    objects: [], stateKey: encodeBase64(generateCaseStateKey(1).key), stateEpoch: 1 });
  return { attacker, body };
}
async function ownerUnlock(enclave: Awaited<ReturnType<typeof boot>>, victim: PreparedSubmission) {
  const caseId = victim.caseId, owner = victim.owner.privateKey;
  const keysBody = encode({ caseId });
  const { stateEnvelopes } = await enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', caseId, keysBody, owner), null);
  const state = await findCaseStateKey(stateEnvelopes, caseId, owner, victim.owner.trust.ownerPublicKey);
  const unlock = encode({ caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch });
  return enclave.service.unlockCase(unlock, await enclave.call('unlock-case', caseId, unlock, owner), null);
}
async function ownerReadState(enclave: Awaited<ReturnType<typeof boot>>, victim: PreparedSubmission) {
  const body = encode({ caseId: victim.caseId, afterCheckpoint: null });
  return enclave.service.readState(body, await enclave.call('read-state', victim.caseId, body, victim.owner.privateKey));
}

describe('a publish of an existing case ID never touches the in-memory keyring', () => {
  let victim: PreparedSubmission;
  beforeAll(async () => {
    victim = await prepareConfidentialSubmission({ summary: 'Victim summary', narrative: { description: 'PRIVATE-SENTINEL' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publish(await boot(), victim);
  }, 60_000);

  test('after a restart, a hostile publish with the victim case ID leaves the victim able to recover and unlock', async () => {
    const enclave = await boot();
    const { attacker, body } = await hostilePublish(victim.caseId);
    const writes = (inner.putObjects as jest.Mock).mock.calls.length;
    await expect(publish(enclave, attacker, victim.caseId, body)).rejects.toThrow('conflict');
    expect(inner.putObjects).toHaveBeenCalledTimes(writes);
    expect(enclave.keyring.get(victim.caseId)).toBeNull();
    // Reads see an ordinary locked case, not a permanent failure.
    expect(await enclave.store.getCase(victim.caseId)).toMatchObject({ locked: true });
    await expect(enclave.service.getRecoveryPackage(victim.caseId)).resolves.toEqual({ recoveryPackage: victim.recoveryPackage });
    await expect(enclave.service.releaseApprovals(victim.caseId)).resolves.toMatchObject({ releases: expect.any(Array) });
    // The owner's own unlock works immediately, and a second hostile publish changes nothing.
    await expect(ownerUnlock(enclave, victim)).resolves.toEqual({ unlocked: true });
    await expect(publish(enclave, attacker, victim.caseId, body)).rejects.toThrow('conflict');
    expect(inner.putObjects).toHaveBeenCalledTimes(writes);
    await expect(ownerReadState(enclave, victim)).resolves.toMatchObject({ checkpoints: expect.any(Array) });
  }, 60_000);

  test('the genuine owner can still retry its exact publish after a restart without caching its key', async () => {
    const enclave = await boot();
    await expect(publish(enclave, victim)).resolves.toMatchObject({ caseId: victim.caseId });
    expect(enclave.keyring.get(victim.caseId)).toBeNull();
    await expect(ownerUnlock(enclave, victim)).resolves.toEqual({ unlocked: true });
  }, 60_000);

  test('a stale initial existence check still reaches the atomic owner conflict check', async () => {
    const enclave = await boot();
    const { attacker, body } = await hostilePublish(victim.caseId);
    const lookup = jest.spyOn(inner, 'getCase').mockResolvedValueOnce(null);
    try {
      await expect(publish(enclave, attacker, victim.caseId, body)).rejects.toThrow('conflict');
      expect(enclave.keyring.get(victim.caseId)).toBeNull();
      await expect(ownerUnlock(enclave, victim)).resolves.toEqual({ unlocked: true });
    } finally { lookup.mockRestore(); }
  }, 60_000);

  test('a cached key that cannot open the sealed history reads as locked and is evicted', async () => {
    const enclave = await boot();
    // The state a pre-fix hostile publish left behind: a wrong key at the current epoch.
    enclave.keyring.set(victim.caseId, generateCaseStateKey(1));
    expect(await enclave.store.getCase(victim.caseId)).toMatchObject({ locked: true, checkpoints: [] });
    expect(enclave.keyring.get(victim.caseId)).toBeNull();
    await expect(ownerUnlock(enclave, victim)).resolves.toEqual({ unlocked: true });
    await expect(ownerReadState(enclave, victim)).resolves.toMatchObject({ checkpoints: expect.any(Array) });
  }, 60_000);

  test('a brand-new case caches its key only once the store confirms creation', async () => {
    const enclave = await boot();
    const fresh = await prepareConfidentialSubmission({ summary: 'Fresh summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publish(enclave, fresh);
    expect(enclave.keyring.get(fresh.caseId)).not.toBeNull();
    await expect(ownerReadState(enclave, fresh)).resolves.toMatchObject({ checkpoints: expect.any(Array) });
    expect(JSON.stringify(cases.get(fresh.caseId))).not.toContain('initialStateKey');
  }, 60_000);
});
