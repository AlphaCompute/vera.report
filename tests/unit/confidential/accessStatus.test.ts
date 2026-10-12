import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint, OwnerStatement, OwnerTrust } from '../../../enclave/src/confidential/authorization';
import { caseObjectDigest, caseRecipientKeyId, sealCaseObject } from '../../../enclave/src/confidential/caseObject';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { prepareGrantRenewal, prepareOwnerGrant } from '../../../enclave/src/confidential/ownerGrant';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation, ParticipantRole } from '../../../enclave/src/confidential/participantRequest';
import { createCaseService } from '../../../enclave/src/cases/service';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import type {
  CaseRecord, CaseService, CaseStore, OrganizationContext, StoredAccessRequest, StoredEnvelope, StoredObject,
} from '../../../enclave/src/cases/service';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases', RELEASE = hex(0xabc);
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() }; // Synthetic test session.
const DAY = 86_400_000;
let clock = Date.now();

/** TEST-ONLY store: just what publish, commit, requests and status need. */
function memoryStore() {
  const challenges = new Map<string, number>(), cases = new Map<string, CaseRecord>();
  const objects = new Map<string, StoredObject>(), envelopes = new Map<string, StoredEnvelope>(), requests: StoredAccessRequest[] = [];
  const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
  const store: CaseStore = {
    async putChallenge(challenge, expiresAt) { challenges.set(challenge, expiresAt); },
    async consumeChallenge(challenge, now) { const expiry = challenges.get(challenge); challenges.delete(challenge); return expiry !== undefined && expiry > now; },
    async putObjects(caseId, items) { for (const item of items) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item)); },
    async getObjects(caseId, refs) { return refs.map(ref => objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`)).filter(Boolean).map(clone) as StoredObject[]; },
    async getEnvelopes() { return []; },
    async readGrantedObjects() { return null; },
    async createCase(record) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, clone(record)); return true; },
    async getCase(caseId) { const value = cases.get(caseId); return value ? clone(value) : null; },
    async commitTransition(caseId, expected, update) {
      const record = cases.get(caseId);
      if (!record || record.currentCheckpointDigest !== expected) return false;
      for (const item of update.envelopes) envelopes.set(`${caseId}:${item.objectId}:${item.recipientKeyId}`, clone(item));
      cases.set(caseId, { ...record, statements: { ...record.statements, ...update.statements },
        checkpoints: [...record.checkpoints, update.checkpoint], currentCheckpointDigest: update.checkpointDigest, listingDigest: update.listingDigest });
      return true;
    },
    async listListedCases() { return []; },
    async putAccessRequest() { return false; },
    async listAccessRequests(caseId) { return requests.filter(item => item.caseId === caseId).map(clone); },
    async insertAccessRequestAtCheckpoint(request, guard) {
      const record = cases.get(request.caseId);
      if (!record || record.currentCheckpointDigest !== guard.checkpointDigest) return 'conflict';
      if (requests.some(item => item.caseId === request.caseId && item.organizationId === request.organizationId &&
          (item.state === 'pending' || item.requestId === request.requestId))) return 'conflict';
      requests.push(clone(request)); return 'stored';
    },
    async expireAccessRequests() { /* Status derives expiry itself. */ },
    async countAccessRequests() { return 0; },
    async withdrawAccessRequest(caseId, organizationId, requestId) {
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId && item.state === 'pending');
      if (found) found.state = 'withdrawn';
      return !!found;
    },
    async declineAccessRequest(caseId, organizationId, requestId) {
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId);
      if (!found) return 'not-found';
      found.state = 'declined'; return 'declined';
    },
    async answerAccessRequest(caseId, organizationId, requestId, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return 'conflict';
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId &&
        item.requestId === requestId && (item.state === 'pending' || item.state === 'approved'));
      if (!found) return 'not-found';
      found.state = 'approved'; return 'approved';
    },
    async appendMessage() { return 'stored'; },
    async listMessages() { return []; },
    async readInboxAtCheckpoint() { return { requests: [], messages: [] }; },
    async readMessagesAtCheckpoint() { return []; },
    async countMessages() { return 0; },
  };
  return { store, requests };
}

let service: CaseService, backing: ReturnType<typeof memoryStore>;
let owner: Awaited<ReturnType<typeof createCaseOwner>>, trust: OwnerTrust;
let firm: PrivateKey, rotated: PrivateKey, stranger: PrivateKey, org: OrganizationContext;
let narrative: { objectId: string; ciphertext: string; ownerEnvelope: string };
let manifest: { wire: string; digest: string }, release: { wire: string; digest: string };
let checkpoint: { wire: string; digest: string };

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
async function proof(role: ParticipantRole, operation: ParticipantOperation, body: Uint8Array, key: PrivateKey, organizationId: string | null = null) {
  const { challenge } = await service.issueChallenge();
  return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role, caseId: trust.caseId, organizationId, operation, body, challenge,
    issuedAt: clock }, key);
}
async function signed(statement: OwnerStatement) {
  const wire = await signOwnerStatement(statement, owner.privateKey);
  return { wire, digest: (await verifyOwnerStatement(wire, trust)).digest };
}
async function commit(body: { checkpoint: string; statements?: string[]; envelopes?: unknown[] }) {
  const raw = encode({ caseId: trust.caseId, statements: [], objects: [], envelopes: [], recoveryPackage: null, ...body });
  const result = await service.commitTransition(raw, await proof('owner', 'commit-transition', raw, owner.privateKey));
  checkpoint = { wire: body.checkpoint, digest: result.checkpointDigest };
}
async function request(requestId: string, key = firm, expiresAt = clock + DAY) {
  const ciphertext = await createLegalAccessRequest({ requestId, scopes: ['narrative'], objectRevisionLimit: null, purpose: 'Review',
    issuedAt: clock, expiresAt }, org.organizationId, key, trust);
  const body = encode({ caseId: trust.caseId, requestId, ciphertext, expiresAt });
  await service.submitAccessRequest(body, await proof('organization', 'request-access', body, key, org.organizationId), org);
  return { caseId: trust.caseId, organizationId: org.organizationId, requestId, recipientKeyId: org.recipientKeyId, ciphertext, expiresAt,
    status: 'pending' as const };
}
async function status(requestIds: string[], context = org, key = firm) {
  const body = encode({ caseId: trust.caseId, requestIds });
  return service.requestStatus(body, await proof('organization', 'request-status', body, key, context.organizationId), context);
}
const grantInput = () => ({ trust, owner: owner.privateKey, checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest,
  manifest: manifest.wire, release: release.wire, releaseDigest: RELEASE, now: clock,
  objects: [{ objectId: narrative.objectId, ownerEnvelope: narrative.ownerEnvelope }] });

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  backing = memoryStore();
  service = createCaseService({ channel: CHANNEL, store: backing.store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
  owner = await createCaseOwner();
  trust = owner.trust;
  [firm, rotated, stranger] = await Promise.all(['firm', 'rotated', 'stranger'].map(async name => (await generateKey({ type: 'ecc',
    curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  org = { organizationId: hex(0xf1), recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };
  const context = { caseId: trust.caseId, objectId: hex(0x101), scope: 'narrative' as const, keyEpoch: 1, objectRevision: 1 };
  narrative = { objectId: context.objectId, ...await sealCaseObject(context, new TextEncoder().encode('PRIVATE'), owner.privateKey) };
  const listing = await signed({ kind: 'listing', caseId: trust.caseId, revision: 1, summary: 'Summary' });
  release = await signed({ kind: 'release', caseId: trust.caseId, revision: 1, releaseDigest: RELEASE, issuedAt: clock });
  manifest = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 1, objects: [{ objectId: context.objectId, scope: 'narrative',
    objectRevision: 1, keyEpoch: 1, ciphertextDigest: await caseObjectDigest(narrative.ciphertext) }] });
  checkpoint = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
    listingDigest: listing.digest, manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: clock });
  const recovery = await createOwnerRecovery(owner, checkpoint.wire);
  const raw = encode({ caseId: trust.caseId, ownerPublicKey: trust.ownerPublicKey.armor(), statements: [listing.wire, release.wire, manifest.wire],
    checkpoint: checkpoint.wire, objects: [narrative], recoveryPackage: recovery.encryptedPackage });
  await service.publishCase(raw, await proof('owner', 'publish-case', raw, owner.privateKey));
}, 120_000);

describe('organization request outcomes and access status', () => {
  let delivery: Awaited<ReturnType<typeof request>>, grantWire: string;

  test('a pending request reads "requested"; unknown IDs reveal nothing', async () => {
    delivery = await request(hex(0x201));
    await expect(status([hex(0x201), hex(0x999)])).resolves.toEqual({
      access: { state: 'none', expiresAt: null, scopes: [], contactShared: false, releaseApproved: true },
      requests: [{ requestId: hex(0x201), state: 'requested', expiresAt: expect.any(Number) }, { requestId: hex(0x999), state: 'unknown' }] });
  });

  test('only the authenticated organization key can ask, with a bounded ID list', async () => {
    const body = encode({ caseId: trust.caseId, requestIds: [hex(0x201)] });
    await expect(service.requestStatus(body, await proof('organization', 'request-status', body, stranger, org.organizationId), org))
      .rejects.toThrow('unauthorized');
    await expect(service.requestStatus(body, await proof('organization', 'open-case', body, firm, org.organizationId), org))
      .rejects.toThrow('unauthorized');
    await expect(status([], org, stranger)).rejects.toThrow('unauthorized');
    await expect(status([])).resolves.toMatchObject({ access: { state: 'none' }, requests: [] });
    for (const requestIds of [[hex(1), hex(1)], Array.from({ length: 17 }, (_, index) => hex(index + 1)), ['nope']]) {
      await expect(status(requestIds as string[])).rejects.toThrow('invalid');
    }
  });

  test('an owner grant closes the request as approved; access carries its end date', async () => {
    const prepared = await prepareOwnerGrant({ ...grantInput(), delivery,
      directory: [{ organizationId: org.organizationId, publicKey: firm.toPublic(), approved: true }],
      decision: { grantId: hex(0x201), scopes: ['narrative'], objectRevisionLimit: null, expiresAt: clock + 2 * DAY } });
    await commit(prepared.body);
    grantWire = prepared.grant;
    expect(backing.requests.find(item => item.requestId === hex(0x201))?.state).toBe('approved');
    await expect(status([hex(0x201)])).resolves.toEqual({
      access: { state: 'active', expiresAt: clock + 2 * DAY, scopes: ['narrative'], contactShared: false, releaseApproved: true },
      requests: [{ requestId: hex(0x201), state: 'approved' }] });
    await expect(status([])).resolves.toEqual({
      access: { state: 'active', expiresAt: clock + 2 * DAY, scopes: ['narrative'], contactShared: false, releaseApproved: true }, requests: [] });
    await expect(status([], { organizationId: hex(0xf2), recipientKeyId: await caseRecipientKeyId(stranger.toPublic()),
      publicKey: stranger.toPublic().armor() }, stranger)).resolves.toMatchObject({ access: { state: 'none' }, requests: [] });
    await expect(status([], { ...org, recipientKeyId: await caseRecipientKeyId(rotated.toPublic()),
      publicKey: rotated.toPublic().armor() }, rotated)).resolves.toMatchObject({ access: { state: 'key-changed' }, requests: [] });
    // The organization may now send another request (for example a renewal).
    await expect(request(hex(0x202))).resolves.toBeDefined();
    await service.withdrawAccessRequest(encode({ caseId: trust.caseId, requestId: hex(0x202) }),
      await proof('organization', 'withdraw-request', encode({ caseId: trust.caseId, requestId: hex(0x202) }), firm, org.organizationId), org);
    expect((await status([hex(0x202)])).requests).toEqual([{ requestId: hex(0x202), state: 'withdrawn' }]);
  });

  test('access that reached its end reads "expired"; renewal makes it open-ended', async () => {
    clock += 3 * DAY;
    expect((await status([hex(0x201)])).access).toMatchObject({ state: 'expired', expiresAt: clock - DAY });
    expect((await status([])).access).toMatchObject({ state: 'expired', expiresAt: clock - DAY });
    const renewal = await prepareGrantRenewal({ ...grantInput(), organization: { organizationId: org.organizationId, publicKey: firm.toPublic() },
      grants: [grantWire], expiresAt: null });
    await commit(renewal.body);
    grantWire = renewal.body.statements[0];
    expect((await status([hex(0x201)])).access).toMatchObject({ state: 'active', expiresAt: null });
  });

  test('a rotated organization key sees "key-changed", not the old grant', async () => {
    const rotatedOrg = { ...org, recipientKeyId: await caseRecipientKeyId(rotated.toPublic()), publicKey: rotated.toPublic().armor() };
    expect((await status([hex(0x201)], rotatedOrg, rotated)).access.state).toBe('key-changed');
  });

  test('a locked case still reports request outcomes, with access unknown', async () => {
    const original = backing.store.getCase.bind(backing.store);
    const spy = jest.spyOn(backing.store, 'getCase').mockImplementation(async caseId => {
      const record = await original(caseId);
      return record && { ...record, checkpoints: [], locked: true };
    });
    try {
      await expect(status([hex(0x201)])).resolves.toMatchObject({ access: { state: 'unknown', releaseApproved: null },
        requests: [{ requestId: hex(0x201), state: 'approved' }] });
    } finally { spy.mockRestore(); }
  });

  test('a failing request close never undoes the owner grant commit', async () => {
    const pending = await request(hex(0x204));
    const spy = jest.spyOn(backing.store, 'answerAccessRequest').mockRejectedValue(new Error('storage down'));
    try {
      const prepared = await prepareOwnerGrant({ ...grantInput(), delivery: pending, replacedGrants: [grantWire],
        directory: [{ organizationId: org.organizationId, publicKey: firm.toPublic(), approved: true }],
        decision: { grantId: hex(0x204), scopes: ['narrative'], objectRevisionLimit: null, expiresAt: null } });
      await commit(prepared.body);
      expect(spy).toHaveBeenCalledTimes(1);
      grantWire = prepared.grant;
    } finally { spy.mockRestore(); }
    // The row stayed pending, but the signed grant still answers the request.
    expect(backing.requests.find(item => item.requestId === hex(0x204))?.state).toBe('pending');
    expect((await status([hex(0x204)])).requests).toEqual([{ requestId: hex(0x204), state: 'approved' }]);
    await service.withdrawAccessRequest(encode({ caseId: trust.caseId, requestId: hex(0x204) }),
      await proof('organization', 'withdraw-request', encode({ caseId: trust.caseId, requestId: hex(0x204) }), firm, org.organizationId), org);
  });

  test('a host-marked "approved" row without an owner grant is not reported as approved', async () => {
    await request(hex(0x205));
    const row = backing.requests.find(item => item.requestId === hex(0x205))!;
    row.state = 'approved';
    expect((await status([hex(0x205)])).requests).toEqual([{ requestId: hex(0x205), state: 'unknown' }]);
    row.state = 'withdrawn';
  });

  test('revocation reads "revoked"; an unanswered request past its end reads "expired"', async () => {
    const current = (await verifyOwnerStatement(checkpoint.wire, trust)).statement as CaseCheckpoint;
    const next = await signed({ ...current, revision: current.revision + 1, previousDigest: checkpoint.digest, issuedAt: clock, grantDigests: [] });
    await commit({ checkpoint: next.wire });
    await request(hex(0x203), firm, clock + DAY);
    clock += 2 * DAY;
    await expect(status([hex(0x203), hex(0x201)])).resolves.toEqual({
      access: { state: 'revoked', expiresAt: null, scopes: [], contactShared: false, releaseApproved: true },
      requests: [{ requestId: hex(0x203), state: 'expired' }, { requestId: hex(0x201), state: 'approved' }] });
    await expect(status([])).resolves.toMatchObject({ access: { state: 'revoked' }, requests: [] });
  });
});
