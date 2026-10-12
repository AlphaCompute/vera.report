import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import type { PreparedSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import * as authorization from '../../../enclave/src/confidential/authorization';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint } from '../../../enclave/src/confidential/authorization';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { encodeBase64, findCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation } from '../../../enclave/src/confidential/participantRequest';
import { createCaseService } from '../../../enclave/src/cases/service';
import type { CaseRecord, CaseStore, OrganizationContext } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';

// Defense-in-depth checks in the enclave case service, over the sealed store and
// an in-memory keyring as in production. Synthetic keys and data only.
const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const CHANNEL = { nonce: hex(0xd01), serverKeyId: hex(0xd02) };
const AUDIENCE = 'vera-confidential-cases';
const manifest = (commit: string) => canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: commit.repeat(40),
  eifSha256: hex(21), imageSha256: hex(22), configurationSha256: hex(23), provenanceSha256: hex(24),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const APPROVED = manifest('1'), UNAPPROVED = manifest('2');
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

/** TEST-ONLY host store, shared across simulated enclave restarts; freely rewritable
 * by the test to play a malicious host. */
const stored = new Map<string, unknown>(), staged = new Map<string, string>(), cases = new Map<string, CaseRecord>();
const inner = {
  async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
  async putObjects(caseId: string, objects: { objectId: string; ciphertextDigest: string }[]) {
    for (const item of objects) stored.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item));
  },
  async getObjects(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]) {
    return refs.flatMap(ref => { const item = stored.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`); return item ? [clone(item)] : []; });
  },
  async createCase(record: CaseRecord) {
    if (cases.has(record.caseId)) return false;
    cases.set(record.caseId, clone(record)); return true;
  },
  async getCase(caseId: string) { const value = cases.get(caseId); return value ? clone(value) : null; },
  async commitTransition(caseId: string, expected: string, update: Record<string, unknown>) {
    const record = cases.get(caseId);
    if (!record || record.currentCheckpointDigest !== expected) return false;
    cases.set(caseId, { ...record, statements: { ...record.statements, ...(update.statements as Record<string, string>) },
      checkpoints: [...record.checkpoints, update.checkpoint as string], currentCheckpointDigest: update.checkpointDigest as string,
      listingDigest: update.listingDigest as string | null,
      recoveryPackage: (update.recoveryPackage as string | null) ?? record.recoveryPackage });
    return true;
  },
} as unknown as CaseStore;

async function boot(release = APPROVED) {
  const keyring = createCaseKeyring({ clock: () => now });
  const store = createSealedCaseStore(inner, keyring);
  const service = createCaseService({ channel: { ...CHANNEL, challenges: createSessionChallenges() }, store, keyring, clock: () => now, audience: AUDIENCE,
    releaseDigest: (await readReleaseManifest(release)).digest });
  const call = async (operation: ParticipantOperation, caseId: string, body: Uint8Array, key: PrivateKey,
    organizationId: string | null = null) => {
    const { challenge } = await service.issueChallenge();
    return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: organizationId ? 'organization' : 'owner', caseId,
      organizationId, operation, body, challenge, issuedAt: now }, key);
  };
  return { keyring, service, call };
}
type Enclave = Awaited<ReturnType<typeof boot>>;

let victim: PreparedSubmission;
async function stateKey(enclave: Enclave) {
  const caseId = victim.caseId, body = encode({ caseId });
  const { stateEnvelopes } = await enclave.service.getStateEnvelopes(body,
    await enclave.call('read-state-keys', caseId, body, victim.owner.privateKey), null);
  return findCaseStateKey(stateEnvelopes, caseId, victim.owner.privateKey, victim.owner.trust.ownerPublicKey);
}
async function ownerUnlock(enclave: Enclave) {
  const state = await stateKey(enclave);
  const body = encode({ caseId: victim.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch });
  return enclave.service.unlockCase(body, await enclave.call('unlock-case', victim.caseId, body, victim.owner.privateKey), null);
}
async function readState(enclave: Enclave) {
  const body = encode({ caseId: victim.caseId, afterCheckpoint: null });
  return enclave.service.readState(body, await enclave.call('read-state', victim.caseId, body, victim.owner.privateKey));
}

beforeAll(async () => {
  victim = await prepareConfidentialSubmission({ summary: 'Defense summary', narrative: { description: 'PRIVATE-SENTINEL' },
    contact: null, identity: null, files: [] }, APPROVED, now);
  for (const item of victim.stagedObjects) staged.set(item.digest, item.ciphertext);
  const enclave = await boot();
  await enclave.service.publishCase(victim.publishBody,
    await enclave.call('publish-case', victim.caseId, victim.publishBody, victim.owner.privateKey));
}, 60_000);

test('a firm key is refused and not kept by a release the current checkpoint does not approve', async () => {
  const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic firm' }], format: 'object' })).privateKey;
  const org: OrganizationContext = { organizationId: hex(0xf01), recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
    publicKey: firm.toPublic().armor() };
  const unlockAsFirm = async (enclave: Enclave) => {
    const state = await stateKey(await boot());
    const body = encode({ caseId: victim.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch });
    return enclave.service.unlockCase(body, await enclave.call('unlock-case', victim.caseId, body, firm, org.organizationId), org);
  };
  const unapproved = await boot(UNAPPROVED);
  await expect(unlockAsFirm(unapproved)).rejects.toThrow('release-not-approved');
  expect(unapproved.keyring.get(victim.caseId)).toBeNull();
  // On the approved release the same firm still needs a current grant.
  const approved = await boot();
  await expect(unlockAsFirm(approved)).rejects.toThrow('not-found');
  expect(approved.keyring.get(victim.caseId)).toBeNull();
}, 60_000);

test('the enclave refuses a host rollback to an older checkpoint within its lifetime', async () => {
  const enclave = await boot();
  await expect(ownerUnlock(enclave)).resolves.toEqual({ unlocked: true });
  const before = clone(cases.get(victim.caseId)!);
  const { checkpoints } = await readState(enclave);
  const tip = await verifyOwnerStatement(checkpoints[checkpoints.length - 1], victim.owner.trust);
  const current = tip.statement as CaseCheckpoint;
  // The owner approves the release again: a new release statement and checkpoint.
  const release = await signOwnerStatement({ kind: 'release', caseId: victim.caseId, revision: current.revision + 1,
    releaseDigest: (await readReleaseManifest(APPROVED)).digest, issuedAt: now }, victim.owner.privateKey);
  const releaseDigest = (await verifyOwnerStatement(release, victim.owner.trust)).digest;
  const next = await signOwnerStatement({ ...current, revision: current.revision + 1, previousDigest: tip.digest,
    releaseDigests: [...current.releaseDigests, releaseDigest] }, victim.owner.privateKey);
  const body = encode({ caseId: victim.caseId, statements: [release], checkpoint: next, objects: [], envelopes: [],
    recoveryPackage: null, stateEnvelopes: null, stateKeyRotation: null });
  await enclave.service.commitTransition(body, await enclave.call('commit-transition', victim.caseId, body, victim.owner.privateKey));
  await expect(readState(enclave)).resolves.toMatchObject({ checkpoints: expect.any(Array) });
  // The host serves the previous, validly signed state again: refused, not served.
  const after = clone(cases.get(victim.caseId)!);
  cases.set(victim.caseId, before);
  await expect(readState(enclave)).rejects.toThrow('conflict');
  cases.set(victim.caseId, after);
  await expect(readState(enclave)).resolves.toMatchObject({ checkpoints: expect.any(Array) });
}, 60_000);

test('public release approvals verify a bounded number of signatures', async () => {
  const verify = jest.spyOn(authorization, 'verifyOwnerStatement');
  const record = cases.get(victim.caseId)!;
  const saved = clone(record);
  // A host stuffs the public statements with forged release rows.
  for (let index = 0; index < 300; index += 1) {
    record.statements[hex(0x10000 + index)] = JSON.stringify({ protocol: 'x', ownerFingerprint: 'x', signature: 'x',
      statement: { kind: 'release', caseId: victim.caseId, revision: 1000 + index, releaseDigest: hex(1), issuedAt: now } });
    record.statements[hex(0x20000 + index)] = JSON.stringify({ statement: { kind: 'grant', revision: 5000 } });
  }
  try {
    const locked = await boot();
    verify.mockClear();
    await expect(locked.service.releaseApprovals(victim.caseId)).resolves.toEqual({ releases: [] });
    // One owner-key/trust check plus at most 64 release candidates; never the 600 rows.
    expect(verify.mock.calls.length).toBeLessThanOrEqual(64 + 2);
    // Unlocked, only the current checkpoint's approvals are verified.
    const unlocked = await boot();
    await ownerUnlock(unlocked);
    verify.mockClear();
    const { releases } = await unlocked.service.releaseApprovals(victim.caseId);
    expect(releases.length).toBeGreaterThan(0);
    expect(verify.mock.calls.length).toBeLessThanOrEqual(releases.length + 2);
  } finally {
    cases.set(victim.caseId, saved);
    verify.mockRestore();
  }
}, 60_000);
