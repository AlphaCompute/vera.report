import { webcrypto } from 'node:crypto';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { createMessage, generateKey, readKey, sign } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint, OwnerStatement, OwnerTrust } from '../../../enclave/src/confidential/authorization';
import {
  caseObjectDigest, caseRecipientKeyId, grantCaseObject, openGrantedCaseObject, sealCaseObject,
} from '../../../enclave/src/confidential/caseObject';
import type { ObjectContext } from '../../../enclave/src/confidential/caseObject';
import { advanceOwnerCheckpoint, createCaseOwner, createOwnerRecovery, restoreOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { createLegalAccessRequest, openDeliveredLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { openCaseMessage, sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import { prepareOwnerGrant } from '../../../enclave/src/confidential/ownerGrant';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation, ParticipantRole } from '../../../enclave/src/confidential/participantRequest';
import { createCaseKeyring } from '../../../enclave/src/cases/sealedStore';
import { createCaseService } from '../../../enclave/src/cases/service';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { sealChannelRequest } from '../../../enclave/src/confidential/channelMessage';
import type {
  CaseRecord, CaseService, CaseStore, OrganizationContext, StoredAccessRequest, StoredEnvelope, StoredMessage, StoredObject,
} from '../../../enclave/src/cases/service';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases';
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() }; // Synthetic test session.
const RELEASE = hex(0xabc);
const SENTINEL = 'PRIVATE-SENTINEL-NARRATIVE';
let clock = Date.now();

/** TEST-ONLY store. No await between compare and mutation, emulating a transaction. */
function memoryStore(): CaseStore & { dump(): string } {
  const cases = new Map<string, CaseRecord>();
  const objects = new Map<string, StoredObject>(), envelopes = new Map<string, StoredEnvelope>();
  const requests: StoredAccessRequest[] = [], messages: StoredMessage[] = [];
  const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
  return {
    async putObjects(caseId, items) { for (const item of items) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item)); },
    async getObjects(caseId, refs) { return refs.map(ref => objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`)).filter(Boolean).map(clone) as StoredObject[]; },
    async getEnvelopes(caseId, recipientKeyId) {
      return [...envelopes.entries()].filter(([key]) => key.startsWith(`${caseId}:`) && key.endsWith(`:${recipientKeyId}`))
        .map(([, value]) => clone(value));
    },
    async readGrantedObjects(caseId, recipientKeyId, checkpointDigest, refs) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      const result = [];
      for (const ref of refs) {
        const item = objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`);
        const envelope = envelopes.get(`${caseId}:${ref.objectId}:${recipientKeyId}`);
        if (!item || !envelope) return null;
        result.push({ objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest,
          ciphertext: item.ciphertext, recipientEnvelope: envelope.envelope });
      }
      return clone(result);
    },
    async createCase(record) {
      if (cases.has(record.caseId)) return false;
      cases.set(record.caseId, clone(record));
      return true;
    },
    async getCase(caseId) {
      const value = cases.get(caseId);
      return value ? clone(value) : null;
    },
    async commitTransition(caseId, expected, update) {
      const record = cases.get(caseId);
      if (!record || record.currentCheckpointDigest !== expected) return false;
      for (const item of update.objects) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item));
      for (const item of update.envelopes) envelopes.set(`${caseId}:${item.objectId}:${item.recipientKeyId}`, clone(item));
      cases.set(caseId, { ...record, statements: { ...record.statements, ...update.statements },
        checkpoints: [...record.checkpoints, update.checkpoint], currentCheckpointDigest: update.checkpointDigest,
        listingDigest: update.listingDigest, recoveryPackage: update.recoveryPackage ?? record.recoveryPackage });
      return true;
    },
    async listListedCases(limit, after) {
      return [...cases.values()].filter(item => item.listingDigest !== null)
        .sort((a, b) => a.caseId.localeCompare(b.caseId)).filter(item => after === null || item.caseId > after)
        .slice(0, limit).map(clone);
    },
    async putAccessRequest(request) {
      if (requests.some(item => item.caseId === request.caseId && item.organizationId === request.organizationId &&
        (item.state === 'pending' || item.requestId === request.requestId))) return false;
      requests.push(clone(request));
      return true;
    },
    async getAccessRequest(caseId: string, organizationId: string, requestId: string) {
      return requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId) ?? null;
    },
    async listAccessRequests(caseId) { return requests.filter(item => item.caseId === caseId).map(clone); },
    async insertAccessRequestAtCheckpoint(request, guard) {
      const record = cases.get(request.caseId);
      if (!record || record.currentCheckpointDigest !== guard.checkpointDigest || record.listingDigest === null) return 'conflict';
      for (const item of requests) if (item.caseId === request.caseId && item.state === 'pending' && item.expiresAt <= guard.now) item.state = 'expired';
      const existing = requests.find(item => item.caseId === request.caseId && item.organizationId === request.organizationId && item.requestId === request.requestId);
      if (existing) return existing.state === 'pending' && existing.ciphertext === request.ciphertext &&
        existing.recipientKeyId === request.recipientKeyId && existing.expiresAt === request.expiresAt ? 'stored' : 'conflict';
      if (requests.filter(item => item.organizationId === request.organizationId && item.createdAt >= guard.since).length >= guard.organizationLimit ||
          requests.filter(item => item.caseId === request.caseId && item.state === 'pending').length >= guard.caseLimit) return 'rate-limited';
      if (requests.some(item => item.caseId === request.caseId && item.organizationId === request.organizationId &&
          (item.state === 'pending' || item.requestId === request.requestId))) return 'conflict';
      requests.push(clone(request));
      return 'stored';
    },
    async expireAccessRequests(caseId, now) {
      for (const request of requests) if (request.caseId === caseId && request.state === 'pending' && request.expiresAt <= now) request.state = 'expired';
    },
    async countAccessRequests(filter) {
      return requests.filter(item => (!filter.organizationId || item.organizationId === filter.organizationId) &&
        (!filter.caseId || item.caseId === filter.caseId) && item.createdAt >= filter.since &&
        (!filter.state || item.state === filter.state)).length;
    },
    async withdrawAccessRequest(caseId, organizationId, requestId) {
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId &&
        item.requestId === requestId && item.state === 'pending');
      if (!found) return false;
      found.state = 'withdrawn';
      return true;
    },
    async declineAccessRequest(caseId, organizationId, requestId, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return 'conflict';
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId &&
        item.requestId === requestId && (item.state === 'pending' || item.state === 'declined'));
      if (!found) return 'not-found';
      found.state = 'declined';
      return 'declined';
    },
    async appendMessage(message, guard) {
      if (cases.get(message.caseId)?.currentCheckpointDigest !== guard.checkpointDigest) return 'conflict';
      // Unsealed stand-in for the sealed store's per-firm receipt tag.
      if (message.kind === 'report-open' && messages.some(item => item.caseId === message.caseId &&
          item.organizationId === message.organizationId && item.kind === 'report-open')) return 'stored';
      if (messages.filter(item => item.caseId === message.caseId && item.organizationId === message.organizationId &&
          item.createdAt >= guard.since).length >= guard.limit) return 'rate-limited';
      messages.push(clone(message)); return 'stored';
    },
    async listMessages(caseId, organizationId, limit) {
      return messages.filter(item => item.caseId === caseId && (organizationId === null || item.organizationId === organizationId))
        .slice(-limit).map(clone);
    },
    async readMessagesAtCheckpoint(caseId, organizationId, limit, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return messages.filter(item => item.caseId === caseId && item.organizationId === organizationId).slice(-limit).map(clone);
    },
    async readInboxAtCheckpoint(caseId, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return { requests: requests.filter(item => item.caseId === caseId && item.state === 'pending').map(clone),
        messages: messages.filter(item => item.caseId === caseId).slice(-500).map(clone) };
    },
    async countMessages(filter) {
      return messages.filter(item => item.caseId === filter.caseId && item.organizationId === filter.organizationId &&
        item.createdAt >= filter.since).length;
    },
    dump() { return JSON.stringify({ cases: [...cases.values()], objects: [...objects.values()], envelopes: [...envelopes.values()], requests, messages }); },
  };
}

let service: CaseService, store: ReturnType<typeof memoryStore>;
let owner: Awaited<ReturnType<typeof createCaseOwner>>, trust: OwnerTrust;
let firm: PrivateKey, otherFirm: PrivateKey, org: OrganizationContext, otherOrg: OrganizationContext;
let recoveryCode: string, narrativeContext: ObjectContext, contactContext: ObjectContext;
let narrative: { ciphertext: string; ownerEnvelope: string }, contact: { ciphertext: string; ownerEnvelope: string };
let checkpointDigest: string, checkpointRevision = 1;
let releaseWire: string, releaseDigestSigned: string, listingDigest: string, manifestWire: string, manifestDigest: string;

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
async function authorized(role: ParticipantRole, operation: ParticipantOperation, caseId: string, body: Uint8Array,
  key: PrivateKey, organizationId: string | null = null) {
  const { challenge } = await service.issueChallenge();
  return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role, caseId, organizationId, operation, body, challenge,
    issuedAt: clock }, key);
}
async function signed(statement: OwnerStatement) {
  const wire = await signOwnerStatement(statement, owner.privateKey);
  return { wire, ...await verifyOwnerStatement(wire, trust) };
}
async function nextCheckpoint(change: Partial<CaseCheckpoint>) {
  checkpointRevision += 1;
  const next = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: checkpointRevision, keyEpoch: 1,
    previousDigest: checkpointDigest, listingDigest, manifestDigest, grantDigests: [],
    releaseDigests: [releaseDigestSigned], issuedAt: clock, ...change });
  return next;
}
async function commit(body: Record<string, unknown>) {
  const raw = encode({ caseId: trust.caseId, statements: [], objects: [], envelopes: [], recoveryPackage: null, ...body });
  const result = await service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId, raw, owner.privateKey));
  checkpointDigest = result.checkpointDigest;
  return result;
}

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  store = memoryStore();
  service = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
  owner = await createCaseOwner();
  trust = owner.trust;
  [firm, otherFirm] = await Promise.all(['firm', 'other-firm'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }],
      format: 'object' })).privateKey));
  org = { organizationId: hex(0x0f1), recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };
  otherOrg = { organizationId: hex(0x0f2), recipientKeyId: await caseRecipientKeyId(otherFirm.toPublic()),
    publicKey: otherFirm.toPublic().armor() };

  // --- Whistleblower browser: encrypt, sign, create recovery, then publish. ---
  narrativeContext = { caseId: trust.caseId, objectId: hex(0x101), scope: 'narrative', keyEpoch: 1, objectRevision: 1 };
  contactContext = { caseId: trust.caseId, objectId: hex(0x102), scope: 'contact', keyEpoch: 1, objectRevision: 1 };
  narrative = await sealCaseObject(narrativeContext, new TextEncoder().encode(SENTINEL), owner.privateKey);
  contact = await sealCaseObject(contactContext, new TextEncoder().encode('PRIVATE-SENTINEL-CONTACT'), owner.privateKey);
  const listing = await signed({ kind: 'listing', caseId: trust.caseId, revision: 1, summary: 'Approved public summary' });
  const release = await signed({ kind: 'release', caseId: trust.caseId, revision: 1, releaseDigest: RELEASE, issuedAt: clock });
  const manifest = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 1, objects: await Promise.all(
    [[narrativeContext, narrative], [contactContext, contact]].map(async ([context, object]) => ({
      objectId: (context as ObjectContext).objectId, scope: (context as ObjectContext).scope, objectRevision: 1, keyEpoch: 1,
      ciphertextDigest: await caseObjectDigest((object as { ciphertext: string }).ciphertext) }))) });
  const first = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
    listingDigest: listing.digest, manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: clock });
  [releaseWire, releaseDigestSigned, listingDigest, manifestWire, manifestDigest] =
    [release.wire, release.digest, listing.digest, manifest.wire, manifest.digest];
  const recovery = await createOwnerRecovery(owner, first.wire);
  recoveryCode = recovery.recoveryCode;
  const raw = encode({ caseId: trust.caseId, ownerPublicKey: trust.ownerPublicKey.armor(),
    statements: [listing.wire, release.wire, manifest.wire], checkpoint: first.wire,
    objects: [{ objectId: narrativeContext.objectId, ...narrative }, { objectId: contactContext.objectId, ...contact }],
    recoveryPackage: recovery.encryptedPackage });
  const published = await service.publishCase(raw, await authorized('owner', 'publish-case', trust.caseId, raw, owner.privateKey));
  checkpointDigest = published.checkpointDigest;
  expect(checkpointDigest).toBe(first.digest);
}, 120_000);

describe('confidential case service', () => {
  test('admins and organizations see exactly the approved summary projection', async () => {
    for (const reader of [{ kind: 'admin' } as const, { kind: 'organization', ...org } as const]) {
      const { listings } = await service.listListings(reader, null);
      expect(listings).toEqual([{ caseId: trust.caseId, summary: 'Approved public summary' }]);
      expect(JSON.stringify(listings)).not.toContain(SENTINEL);
    }
    await expect(service.listListings({ kind: 'employee' } as never, null)).rejects.toThrow();
  });

  test('directory projects only the summary from the signed listing', async () => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const listing = await signed({ kind: 'listing', caseId: trust.caseId, revision: current.revision,
      summary: 'Approved public summary' });
    const changed = await signed({ ...current, listingDigest: listing.digest });
    const replacement = { ...record, statements: { ...record.statements, [listing.digest]: listing.wire },
      checkpoints: [...record.checkpoints.slice(0, -1), changed.wire], currentCheckpointDigest: changed.digest,
      listingDigest: listing.digest };
    const rows = jest.spyOn(store, 'listListedCases').mockResolvedValue([replacement]);
    try {
      for (const reader of [{ kind: 'admin' } as const, { kind: 'organization', ...org } as const]) {
        expect((await service.listListings(reader, null)).listings).toEqual([{ caseId: trust.caseId,
          summary: 'Approved public summary' }]);
      }
      const [signedRow] = (await service.signedListings({ kind: 'organization', ...org }, null)).listings;
      expect(signedRow).toMatchObject({ listing: listing.wire });
      expect(JSON.stringify(signedRow)).not.toContain(SENTINEL);
    } finally { rows.mockRestore(); }
    // Unpublished fields are omitted, never serialized as empty values.
    const [plain] = (await service.listListings({ kind: 'admin' }, null)).listings;
    expect(Object.keys(plain).sort()).toEqual(['caseId', 'summary']);
  });

  test.each(['checkpoint-digest', 'listing-digest', 'future-checkpoint', 'future-listing'])('directory omits inconsistent %s rows', async defect => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const listing = await signed({ kind: 'listing', caseId: trust.caseId, revision: current.revision + 1, summary: 'Unapproved revision' });
    const changed = await signed({ ...current,
      ...(defect === 'future-checkpoint' ? { issuedAt: clock + CLOCK_SKEW_MS + 1000 } : {}),
      ...(defect === 'future-listing' ? { listingDigest: listing.digest } : {}) });
    const replacement = { ...record,
      statements: { ...record.statements, [listing.digest]: listing.wire },
      checkpoints: [...record.checkpoints.slice(0, -1), changed.wire],
      currentCheckpointDigest: defect === 'checkpoint-digest' ? hex(0xbad) : changed.digest,
      listingDigest: defect === 'listing-digest' ? hex(0xbad) : changed.statement.listingDigest };
    const rows = jest.spyOn(store, 'listListedCases').mockResolvedValue([replacement]);
    try { expect((await service.listListings({ kind: 'admin' }, null)).listings).toEqual([]); }
    finally { rows.mockRestore(); }
  });

  test.each([{ nonce: hex(0xc03) }, { serverKeyId: hex(0xc04) }])('participant proof cannot cross application channels: %j', async change => {
    const forwarded = createCaseService({ channel: { ...CHANNEL, ...change }, store, clock: () => clock,
      audience: AUDIENCE, releaseDigest: RELEASE });
    const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
    const proof = await authorized('owner', 'read-inbox', trust.caseId, body, owner.privateKey);
    await expect(forwarded.readInbox(body, proof)).rejects.toThrow('unauthorized');
    // A failed forward cannot consume the owner's real challenge.
    await expect(service.readInbox(body, proof)).resolves.toBeDefined();
  });

  test('case service has no unbound channel fallback', () => {
    expect(() => createCaseService({ store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE } as never)).toThrow('invalid');
  });

  test('stored state is ciphertext and signatures only; no private sentinel or recovery code', () => {
    const dump = store.dump();
    for (const secret of [SENTINEL, 'PRIVATE-SENTINEL-CONTACT', recoveryCode, recoveryCode.replace(/-/g, '')]) {
      expect(dump).not.toContain(secret);
    }
  });

  test('publish requires owner key possession and a fresh single-use challenge', async () => {
    const raw = encode({ caseId: hex(0x999) });
    await expect(service.publishCase(raw, await authorized('owner', 'publish-case', hex(0x999), raw, firm))).rejects.toThrow();
    const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
    const auth = await authorized('owner', 'read-inbox', trust.caseId, body, owner.privateKey);
    await expect(service.readInbox(body, auth)).resolves.toBeDefined();
    await expect(service.readInbox(body, auth)).rejects.toThrow('unauthorized');
  });

  test('publish refuses a genesis checkpoint dated beyond bounded device clock skew', async () => {
    const other = await createCaseOwner();
    const sign = (statement: OwnerStatement) => signOwnerStatement(statement, other.privateKey);
    const release = await sign({ kind: 'release', caseId: other.trust.caseId, revision: 1, releaseDigest: RELEASE, issuedAt: clock });
    const releaseDigest = (await verifyOwnerStatement(release, other.trust)).digest;
    const genesis = async (issuedAt: number) => sign({ kind: 'checkpoint', caseId: other.trust.caseId, revision: 1, keyEpoch: 1,
      previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [releaseDigest], issuedAt });
    const publish = async (checkpoint: string) => {
      const raw = encode({ caseId: other.trust.caseId, ownerPublicKey: other.trust.ownerPublicKey.armor(), statements: [release],
        checkpoint, objects: [], recoveryPackage: (await createOwnerRecovery(other, checkpoint)).encryptedPackage });
      return service.publishCase(raw, await authorized('owner', 'publish-case', other.trust.caseId, raw, other.privateKey));
    };
    const create = jest.spyOn(store, 'createCase');
    try {
      await expect(publish(await genesis(clock + 300_001))).rejects.toThrow('invalid');
      expect(create).not.toHaveBeenCalled();
      const accepted = await genesis(clock + 300_000);
      await expect(publish(accepted)).resolves.toEqual({ caseId: other.trust.caseId,
        checkpointDigest: (await verifyOwnerStatement(accepted, other.trust)).digest });
    } finally { create.mockRestore(); }
  });

  test('challenges are session-bound: another session\'s ledger refuses them, and a batch is bounded', async () => {
    const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
    const auth = await authorized('owner', 'read-inbox', trust.caseId, body, owner.privateKey);
    // Same nonce and key, but a different session ledger (as after a restart or in a parallel session).
    const elsewhere = createCaseService({ channel: { ...CHANNEL, challenges: createSessionChallenges() }, store, clock: () => clock,
      audience: AUDIENCE, releaseDigest: RELEASE });
    await expect(elsewhere.readInbox(body, auth)).rejects.toThrow('unauthorized');
    await expect(service.readInbox(body, auth)).resolves.toBeDefined();
    const batch = await service.issueChallenges(3);
    expect(batch.challenges).toHaveLength(3);
    for (const count of [0, 9, 1.5]) await expect(service.issueChallenges(count)).rejects.toThrow('invalid');
    // Unused challenges are bounded per session.
    const bounded = createCaseService({ channel: { ...CHANNEL, challenges: createSessionChallenges() }, store, clock: () => clock,
      audience: AUDIENCE, releaseDigest: RELEASE });
    await bounded.issueChallenges(8); await bounded.issueChallenges(8);
    await expect(bounded.issueChallenge()).rejects.toThrow('rate-limited');
    for (const challenge of batch.challenges) CHANNEL.challenges.consume(challenge, clock);
  });

  test('full request -> owner grant -> firm opens flow; contact scope stays sealed', async () => {
    // Firm browser: request narrative access, encrypted to the owner.
    const requestCiphertext = await createLegalAccessRequest({ requestId: hex(0x201), scopes: ['narrative', 'messages'],
      objectRevisionLimit: null, purpose: 'Conflict-checked counsel review', issuedAt: clock, expiresAt: clock + 86_400_000 },
      org.organizationId, firm, trust);
    const requestBody = encode({ caseId: trust.caseId, requestId: hex(0x201), ciphertext: requestCiphertext, expiresAt: clock + 86_400_000 });
    await service.submitAccessRequest(requestBody, await authorized('organization', 'request-access', trust.caseId,
      requestBody, firm, org.organizationId), org);
    // A lost receipt can be retried with a fresh proof and the same ciphertext.
    await expect(service.submitAccessRequest(requestBody, await authorized('organization', 'request-access', trust.caseId,
      requestBody, firm, org.organizationId), org)).resolves.toEqual({ state: 'requested' });
    // Duplicate pending requests are suppressed.
    const duplicate = encode({ caseId: trust.caseId, requestId: hex(0x202), ciphertext: requestCiphertext, expiresAt: clock + 86_400_000 });
    await expect(service.submitAccessRequest(duplicate, await authorized('organization', 'request-access', trust.caseId,
      duplicate, firm, org.organizationId), org)).rejects.toThrow('conflict');
    // Before a grant the firm gets nothing.
    const openBody = encode({ caseId: trust.caseId });
    await expect(service.openCase(openBody, await authorized('organization', 'open-case', trust.caseId, openBody, firm,
      org.organizationId), org)).rejects.toThrow('not-found');

    // Owner browser: read inbox, verify request against a pinned roster, sign grant, wrap keys.
    const inboxBody = encode({ caseId: trust.caseId, afterCheckpoint: null });
    const inbox = await service.readInbox(inboxBody, await authorized('owner', 'read-inbox', trust.caseId, inboxBody, owner.privateKey));
    expect(inbox.requests).toHaveLength(1);
    const request = await openDeliveredLegalAccessRequest(inbox.requests[0], trust.caseId, owner.privateKey,
      [{ organizationId: org.organizationId, publicKey: await readKey({ armoredKey: org.publicKey }), approved: true }], clock);
    const prepared = await prepareOwnerGrant({ delivery: inbox.requests[0],
      directory: [{ organizationId: org.organizationId, publicKey: firm.toPublic(), approved: true }],
      trust, owner: owner.privateKey, checkpoint: inbox.checkpoints[inbox.checkpoints.length - 1], checkpointDigest,
      manifest: manifestWire, release: releaseWire, releaseDigest: RELEASE, now: clock,
      decision: { grantId: hex(0x301), scopes: request.scopes, objectRevisionLimit: request.objectRevisionLimit,
        expiresAt: clock + 30 * 86_400_000 }, objects: [{ objectId: narrativeContext.objectId, ...narrative }] });
    const grant = { wire: prepared.grant };
    const checkpoint = { wire: prepared.body.checkpoint, digest: prepared.checkpointDigest };
    checkpointRevision += 1;
    const auth = { trust, grant: grant.wire, release: releaseWire, manifest: manifestWire, checkpoint: checkpoint.wire,
      checkpointDigest: checkpoint.digest, request: { organizationId: org.organizationId, recipientKeyId: org.recipientKeyId,
        objectId: narrativeContext.objectId, ciphertextDigest: await caseObjectDigest(narrative.ciphertext),
        scope: 'narrative' as const, releaseDigest: RELEASE, keyEpoch: 1, objectRevision: 1, now: clock } };
    // The owner client cannot wrap the contact object under a narrative grant.
    await expect(grantCaseObject(contact, contactContext, owner.privateKey, firm.toPublic(), { ...auth,
      request: { ...auth.request, objectId: contactContext.objectId, scope: 'contact',
        ciphertextDigest: await caseObjectDigest(contact.ciphertext) } })).rejects.toThrow();
    await commit(prepared.body);

    // Firm browser: open and decrypt locally.
    const opened = await service.openCase(openBody, await authorized('organization', 'open-case', trust.caseId, openBody,
      firm, org.organizationId), org);
    expect(opened.objects.map(item => item.objectId)).toEqual([narrativeContext.objectId]);
    const ownerKey = await readKey({ armoredKey: opened.ownerPublicKey });
    const firmTrust = { caseId: trust.caseId, ownerFingerprint: ownerKey.getFingerprint(), ownerPublicKey: ownerKey };
    const item = opened.objects[0];
    const plaintext = await openGrantedCaseObject({ ciphertext: item.ciphertext, recipientEnvelope: item.recipientEnvelope },
      narrativeContext, firm, { trust: firmTrust, grant: opened.grants[0], release: opened.release, manifest: opened.manifest,
        checkpoint: opened.checkpoint, checkpointDigest: opened.checkpointDigest, request: { ...auth.request, now: clock } });
    expect(new TextDecoder().decode(plaintext)).toBe(SENTINEL);

    // Another onboarded firm without a grant, or with the right org but wrong key, gets nothing.
    await expect(service.openCase(openBody, await authorized('organization', 'open-case', trust.caseId, openBody,
      otherFirm, otherOrg.organizationId), otherOrg)).rejects.toThrow();
    await expect(service.openCase(openBody, await authorized('organization', 'open-case', trust.caseId, openBody,
      otherFirm, org.organizationId), { ...org, publicKey: otherFirm.toPublic().armor() })).rejects.toThrow('unauthorized');
  });

  test('first-open confirmation needs current narrative access and does not arise from status checks', async () => {
    const { sealReportOpenReceipt } = await import('../../../enclave/src/confidential/reportOpenReceipt');
    const participants = { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } };
    const ciphertext = await sealReportOpenReceipt({ checkpointDigest, openedAt: clock }, participants, firm);
    const raw = encode({ caseId: trust.caseId, checkpointDigest, ciphertext });
    const before = await store.listMessages(trust.caseId, org.organizationId, 100);
    expect(before.filter(item => item.kind === 'report-open')).toHaveLength(0);
    const ack = async (context = org, key = firm, body = raw) => service.acknowledgeReportOpen(body,
      await authorized('organization', 'acknowledge-report-open', trust.caseId, body, key, context.organizationId), context);
    await expect(ack(otherOrg, otherFirm)).rejects.toThrow();
    await expect(ack(org, otherFirm)).rejects.toThrow();
    await expect(ack(org, firm, encode({ caseId: trust.caseId, checkpointDigest: hex(999), ciphertext }))).rejects.toThrow('conflict');
    const originalTime = clock;
    try {
      clock += 30 * 86_400_000;
      await expect(ack()).rejects.toThrow('unauthorized');
    } finally { clock = originalTime; }
    expect(await ack()).toEqual({ recorded: true });
    expect(await ack()).toEqual({ recorded: true });
    const rows = await store.listMessages(trust.caseId, org.organizationId, 100);
    expect(rows.filter(item => item.kind === 'report-open')).toHaveLength(1);
    expect(rows.find(item => item.kind === 'report-open')?.ciphertext).toBe(ciphertext);
  });

  test('request status tolerates bounded issue-time skew but never extends grant expiry', async () => {
    const originalTime = clock;
    const body = encode({ caseId: trust.caseId, requestIds: [hex(0x201)] });
    const status = async () => service.requestStatus(body, await authorized('organization', 'request-status',
      trust.caseId, body, firm, org.organizationId), org);
    try {
      clock = originalTime - 60_000;
      await expect(status()).resolves.toMatchObject({ access: { state: 'active', releaseApproved: true } });
      clock = originalTime - 6 * 60_000;
      await expect(status()).rejects.toThrow('unauthorized');
      clock = originalTime + 30 * 86_400_000;
      await expect(status()).resolves.toMatchObject({ access: { state: 'expired' } });
    } finally { clock = originalTime; }
  });

  test.each(['conflict', 'expiry'])('case object reads suppress %s during retrieval', async defect => {
    const original = store.readGrantedObjects.bind(store), previousTime = clock;
    const read = jest.spyOn(store, 'readGrantedObjects').mockImplementation(async (...args) => {
      if (defect === 'conflict') return null;
      const result = await original(...args); clock += 31 * 86_400_000; return result;
    });
    try {
      const body = encode({ caseId: trust.caseId });
      await expect(service.openCase(body, await authorized('organization', 'open-case', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow('conflict');
    } finally { read.mockRestore(); clock = previousTime; }
  });

  test('firm freshness pin: a stored chain missing the firm pin is refused; the chain after the pin is returned', async () => {
    const plain = encode({ caseId: trust.caseId });
    const baseline = await service.openCase(plain, await authorized('organization', 'open-case', trust.caseId, plain,
      firm, org.organizationId), org);
    // Pin at the genesis checkpoint: the returned chain links forward to the current digest.
    const genesis = (await verifyOwnerStatement(baseline.checkpoints[0], trust)).digest;
    const pinned = encode({ caseId: trust.caseId, minimumCheckpoint: genesis });
    const fresh = await service.openCase(pinned, await authorized('organization', 'open-case', trust.caseId, pinned,
      firm, org.organizationId), org);
    expect(fresh.checkpoints.length).toBe(baseline.checkpoints.length - 1);
    const pin = { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint,
      revision: ((await verifyOwnerStatement(baseline.checkpoints[0], trust)).statement as CaseCheckpoint).revision,
      keyEpoch: 1, digest: genesis };
    expect((await advanceOwnerCheckpoint(fresh.checkpoints, trust, pin)).digest).toBe(fresh.checkpointDigest);
    // A pin the store does not have (e.g. after an old-backup restore) fails closed.
    for (const operation of ['open-case', 'read-messages'] as const) {
      const unknown = encode({ caseId: trust.caseId, minimumCheckpoint: hex(0x5a1e) });
      const call = operation === 'open-case' ? service.openCase : service.readMessages;
      await expect(call(unknown, await authorized('organization', operation, trust.caseId, unknown, firm, org.organizationId), org))
        .rejects.toThrow('conflict');
    }
  });

  test('granted firm and owner exchange end-to-end encrypted messages through the relay', async () => {
    const participants = { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } };
    const ciphertext = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: clock, body: 'PRIVATE-SENTINEL-QUESTION' },
      participants, firm);
    const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext });
    await service.sendMessage(body, await authorized('organization', 'send-message', trust.caseId, body, firm, org.organizationId), org);
    const reply = await sealCaseMessage({ sender: 'owner', sequence: 1, sentAt: clock, body: 'Owner reply' }, participants, owner.privateKey);
    const replyBody = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext: reply });
    await service.sendMessage(replyBody, await authorized('owner', 'send-message', trust.caseId, replyBody, owner.privateKey), null);
    const readBody = encode({ caseId: trust.caseId });
    const { messages } = await service.readMessages(readBody, await authorized('organization', 'read-messages', trust.caseId,
      readBody, firm, org.organizationId), org);
    const conversation = messages.filter(item => !item.kind);
    expect(conversation.map(item => item.sender)).toEqual(['organization', 'owner']);
    const opened = await openCaseMessage(conversation[0].ciphertext, participants, owner.privateKey, { owner: 0, organization: 0 });
    expect(opened.body).toBe('PRIVATE-SENTINEL-QUESTION');
    expect(store.dump()).not.toContain('PRIVATE-SENTINEL-QUESTION');
    // An ungranted organization cannot inject into the thread.
    const spam = encode({ caseId: trust.caseId, organizationId: otherOrg.organizationId, ciphertext });
    await expect(service.sendMessage(spam, await authorized('organization', 'send-message', trust.caseId, spam, otherFirm,
      otherOrg.organizationId), otherOrg)).rejects.toThrow('unauthorized');
  });

  test.each(['case.read-notifications', 'case.set-notifications'])('rejects removed reporter contact operation %s before storage', async operation => {
    const get = jest.spyOn(store, 'getCase');
    const before = get.mock.calls.length;
    const dispatch = createOwnerCaseControlDispatcher({ store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
    const body = encode({ caseId: trust.caseId, address: 'PRIVATE-CONTACT@example.org' });
    try {
      await expect(dispatch(encode({ operation, proof: 'obsolete-proof', body: Buffer.from(body).toString('base64') }),
        { ...CHANNEL, requestId: hex(0x777), requestDigest: hex(0x778), signal: new AbortController().signal })).rejects.toThrow();
      expect(get.mock.calls).toHaveLength(before);
    } finally { get.mockRestore(); }
  });

  test('checkpoint floor survives separate owner dispatcher instances sharing one keyring', async () => {
    const keyring = createCaseKeyring({ clock: () => clock });
    const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
    const dispatch = () => createOwnerCaseControlDispatcher({ store, keyring, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
    const invoke = async () => dispatch()(encode({ operation: 'case.read-state',
      proof: await authorized('owner', 'read-state', trust.caseId, body, owner.privateKey), body: Buffer.from(body).toString('base64') }),
      { ...CHANNEL, requestId: hex(0x777), requestDigest: hex(0x778), signal: new AbortController().signal });
    await invoke();
    const record = (await store.getCase(trust.caseId))!;
    const checkpoint = record.checkpoints[0];
    const rollback = { ...record, checkpoints: [checkpoint], currentCheckpointDigest: (await verifyOwnerStatement(checkpoint, trust)).digest };
    const get = jest.spyOn(store, 'getCase').mockResolvedValue(rollback);
    try { await expect(invoke()).rejects.toThrow('unavailable'); }
    finally { get.mockRestore(); }
  });

  test.each([false, true])('failed firm unlock removes only a newly admitted key (already unlocked: %s)', async already => {
    const keyring = createCaseKeyring({ clock: () => clock });
    const state = { key: new Uint8Array(32).fill(7), stateEpoch: 1 };
    const original = { key: new Uint8Array(32).fill(8), stateEpoch: 2 };
    if (already) keyring.set(trust.caseId, original);
    const originalGet = store.getCase.bind(store);
    const scoped = { ...store, unlockCase: async () => { keyring.set(trust.caseId, state); return true; } };
    const get = jest.spyOn(scoped, 'getCase').mockImplementationOnce(originalGet).mockRejectedValue(new Error('synthetic post-unlock load failure'));
    const service = createCaseService({ channel: CHANNEL, store: scoped, keyring, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
    const body = encode({ caseId: trust.caseId, stateKey: Buffer.from(state.key).toString('base64'), stateEpoch: 1 });
    try {
      await expect(service.unlockCase(body, await authorized('organization', 'unlock-case', trust.caseId, body, firm, org.organizationId), org))
        .rejects.toThrow('synthetic post-unlock load failure');
      expect(keyring.get(trust.caseId)).toEqual(already ? original : null);
    } finally { get.mockRestore(); }
  });

  test('failed firm unlock preserves a concurrently installed newer key', async () => {
    const keyring = createCaseKeyring({ clock: () => clock });
    const state = { key: new Uint8Array(32).fill(7), stateEpoch: 1 };
    const newer = { key: new Uint8Array(32).fill(9), stateEpoch: 3 };
    keyring.set(trust.caseId, { key: new Uint8Array(32).fill(8), stateEpoch: 2 });
    const scoped = { ...store, unlockCase: async () => { keyring.set(trust.caseId, state); return true; } };
    const get = jest.spyOn(scoped, 'getCase').mockImplementationOnce(store.getCase.bind(store)).mockImplementation(async () => {
      keyring.set(trust.caseId, newer);
      throw new Error('synthetic concurrent transition');
    });
    const service = createCaseService({ channel: CHANNEL, store: scoped, keyring, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
    const body = encode({ caseId: trust.caseId, stateKey: Buffer.from(state.key).toString('base64'), stateEpoch: 1 });
    try {
      await expect(service.unlockCase(body, await authorized('organization', 'unlock-case', trust.caseId, body, firm, org.organizationId), org))
        .rejects.toThrow('synthetic concurrent transition');
      expect(keyring.get(trust.caseId)).toEqual(newer);
    } finally { get.mockRestore(); }
  });

  test('concurrent sends through separate service instances cannot consume the other sender allowance', async () => {
    const participants = { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } };
    const rows = (JSON.parse(store.dump()).messages as StoredMessage[]).filter(item => item.caseId === trust.caseId && item.organizationId === org.organizationId);
    const cap = rows.filter(item => item.sender === 'organization').length + 1;
    const make = () => createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE,
      limits: { messagesPerSenderPerHour: cap, messagesPerThreadPerHour: cap * 2 + rows.length } });
    const ciphertext = await sealCaseMessage({ sender: 'organization', sequence: 999, sentAt: clock, body: 'race' }, participants, firm);
    const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext });
    const proofs = await Promise.all([1, 2].map(() => authorized('organization', 'send-message', trust.caseId, body, firm, org.organizationId)));
    const results = await Promise.allSettled(proofs.map(proof => make().sendMessage(body, proof, org)));
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
    const ownerBody = encode({ caseId: trust.caseId, organizationId: org.organizationId,
      ciphertext: await sealCaseMessage({ sender: 'owner', sequence: 999, sentAt: clock, body: 'still available' }, participants, owner.privateKey) });
    await expect(make().sendMessage(ownerBody, await authorized('owner', 'send-message', trust.caseId, ownerBody, owner.privateKey), null))
      .resolves.toEqual({ sent: true });
  });

  test('owner and firm have separate hourly message allowances', async () => {
    const participants = { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } };
    const thread = () => (JSON.parse(store.dump()).messages as { caseId: string; organizationId: string; sender: string }[])
      .filter(item => item.caseId === trust.caseId && item.organizationId === org.organizationId);
    const count = (sender: string) => thread().filter(item => item.sender === sender).length;
    const perSender = Math.max(count('owner'), count('organization')) + 2;
    const limited = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE,
      limits: { messagesPerSenderPerHour: perSender, messagesPerThreadPerHour: perSender * 2 } });
    let sequence = 100;
    const send = async (role: 'owner' | 'organization') => {
      const ciphertext = await sealCaseMessage({ sender: role, sequence: ++sequence, sentAt: clock, body: 'quota' }, participants,
        role === 'owner' ? owner.privateKey : firm);
      const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext });
      return limited.sendMessage(body, role === 'owner'
        ? await authorized('owner', 'send-message', trust.caseId, body, owner.privateKey)
        : await authorized('organization', 'send-message', trust.caseId, body, firm, org.organizationId), role === 'owner' ? null : org);
    };
    while (count('organization') < perSender) await expect(send('organization')).resolves.toEqual({ sent: true });
    // The firm has used its allowance; the owner's is untouched.
    await expect(send('organization')).rejects.toThrow('rate-limited');
    await expect(send('owner')).resolves.toEqual({ sent: true });
    expect(count('organization')).toBe(perSender);
  });

  test('the rolling-hour thread total uses exact sealed times when the host counts only the current clock hour', async () => {
    const participants = { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } };
    const lastHour = () => (JSON.parse(store.dump()).messages as StoredMessage[]).filter(item => item.caseId === trust.caseId &&
      item.organizationId === org.organizationId && item.createdAt >= clock - 3_600_000).length;
    const cap = lastHour() + 1;
    const limited = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE,
      limits: { messagesPerSenderPerHour: cap + 10, messagesPerThreadPerHour: cap } });
    // Host rows carry the UTC hour, so just after a clock-hour boundary the host
    // counts none of the previous hour's rows.
    const append = store.appendMessage.bind(store);
    const quota = jest.spyOn(store, 'countMessages').mockResolvedValue(0);
    const write = jest.spyOn(store, 'appendMessage')
      .mockImplementation((message, guard) => append(message, { ...guard, limit: Number.MAX_SAFE_INTEGER }));
    const send = async (sequence: number) => {
      const ciphertext = await sealCaseMessage({ sender: 'organization', sequence, sentAt: clock, body: 'thread total' }, participants, firm);
      const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext });
      return limited.sendMessage(body, await authorized('organization', 'send-message', trust.caseId, body, firm, org.organizationId), org);
    };
    try {
      await expect(send(700)).resolves.toEqual({ sent: true });
      await expect(send(701)).rejects.toThrow('rate-limited');
      expect(lastHour()).toBe(cap);
    } finally { quota.mockRestore(); write.mockRestore(); }
  });

  test('authenticated requests and messages reject plaintext before persistence', async () => {
    const requestWrite = jest.spyOn(store, 'insertAccessRequestAtCheckpoint');
    const messageWrite = jest.spyOn(store, 'appendMessage');
    const literal = (await createMessage({ text: 'PRIVATE-SENTINEL-UNENCRYPTED' })).armor();
    try {
      for (const ciphertext of ['PRIVATE-SENTINEL-UNENCRYPTED', literal,
        '-----BEGIN PGP MESSAGE-----\ninvalid\n-----END PGP MESSAGE-----']) {
        const request = encode({ caseId: trust.caseId, requestId: hex(0x299), ciphertext, expiresAt: clock + 86_400_000 });
        await expect(service.submitAccessRequest(request, await authorized('organization', 'request-access', trust.caseId,
          request, firm, org.organizationId), org)).rejects.toThrow('invalid');
        for (const role of ['owner', 'organization'] as const) {
          const message = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext });
          await expect(service.sendMessage(message, await authorized(role, 'send-message', trust.caseId,
            message, role === 'owner' ? owner.privateKey : firm, role === 'owner' ? null : org.organizationId),
          role === 'owner' ? null : org)).rejects.toThrow('invalid');
        }
      }
      expect(requestWrite).not.toHaveBeenCalled();
      expect(messageWrite).not.toHaveBeenCalled();
      expect(store.dump()).not.toContain('PRIVATE-SENTINEL-UNENCRYPTED');
    } finally { requestWrite.mockRestore(); messageWrite.mockRestore(); }
  });

  test.each(['ciphertext', 'ownerEnvelope', 'recipientEnvelope'])('rejects plaintext %s before a case transition is persisted', async defect => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const next = await signed({ ...current, revision: current.revision + 1, previousDigest: record.currentCheckpointDigest });
    const manifest = await verifyOwnerStatement(record.statements[current.manifestDigest!], trust);
    if (manifest.statement.kind !== 'manifest') throw new Error('Missing fixture manifest');
    const ref = manifest.statement.objects[0];
    const [stored] = await store.getObjects(trust.caseId, [ref]);
    const object = { objectId: stored.objectId, ciphertext: stored.ciphertext, ownerEnvelope: stored.ownerEnvelope,
      ...(defect === 'recipientEnvelope' ? {} : { [defect]: 'PRIVATE-SENTINEL-UNENCRYPTED' }) };
    const raw = encode({ caseId: trust.caseId, statements: [], checkpoint: next.wire, objects: [object],
      envelopes: defect === 'recipientEnvelope' ? [{ objectId: stored.objectId,
        recipientKeyId: org.recipientKeyId, envelope: 'PRIVATE-SENTINEL-UNENCRYPTED' }] : [], recoveryPackage: null });
    const commit = jest.spyOn(store, 'commitTransition');
    try {
      await expect(service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId,
        raw, owner.privateKey))).rejects.toThrow('invalid');
      expect(commit).not.toHaveBeenCalled();
      expect(store.dump()).not.toContain('PRIVATE-SENTINEL-UNENCRYPTED');
    } finally { commit.mockRestore(); }
  });

  test('stale or forked transitions are rejected by compare-and-set and hash chaining', async () => {
    const forked = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 50, keyEpoch: 1,
      previousDigest: hex(0x777), listingDigest, manifestDigest, grantDigests: [], releaseDigests: [releaseDigestSigned], issuedAt: clock });
    const raw = encode({ caseId: trust.caseId, statements: [], checkpoint: forked.wire, objects: [], envelopes: [], recoveryPackage: null });
    await expect(service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId, raw, owner.privateKey)))
      .rejects.toThrow('conflict');
    // A transition signed by a non-owner key is unauthorized even with a valid body.
    await expect(service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId, raw, firm)))
      .rejects.toThrow('unauthorized');
  });

  test.each(['revoked', 'release-withdrawn', 'wrong-epoch', 'expired', 'racing-revocation'])('message reads reject %s consent', async defect => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const changed = await signed({ ...current, revision: current.revision + 1, previousDigest: record.currentCheckpointDigest,
      ...(defect === 'release-withdrawn' ? { releaseDigests: [] } :
        defect === 'wrong-epoch' ? { keyEpoch: current.keyEpoch + 1 } : { grantDigests: [] }) });
    const replacement = { ...record, currentCheckpointDigest: changed.digest, checkpoints: [...record.checkpoints, changed.wire] };
    const originalGet = store.getCase.bind(store), originalList = store.readMessagesAtCheckpoint.bind(store), originalTime = clock;
    const get = jest.spyOn(store, 'getCase');
    const list = jest.spyOn(store, 'readMessagesAtCheckpoint');
    let retrieved = false;
    get.mockImplementation(async caseId => defect === 'expired' || (defect === 'racing-revocation' && !retrieved)
      ? originalGet(caseId) : replacement);
    list.mockImplementation(async (...args) => { retrieved = true; return originalList(...args); });
    try {
      if (defect === 'expired') clock += 31 * 86_400_000;
      const body = encode({ caseId: trust.caseId });
      await expect(service.readMessages(body, await authorized('organization', 'read-messages', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow();
      expect(list).toHaveBeenCalledTimes(defect === 'racing-revocation' ? 1 : 0);
    } finally { get.mockRestore(); list.mockRestore(); clock = originalTime; }
  });

  test.each(['unapproved', 'withdrawn', 'racing-withdrawal', 'transaction-conflict'])('owner inbox rejects %s release state', async defect => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const changed = await signed({ ...current, revision: current.revision + 1,
      previousDigest: record.currentCheckpointDigest, releaseDigests: [] });
    const replacement = { ...record, currentCheckpointDigest: changed.digest, checkpoints: [...record.checkpoints, changed.wire] };
    const originalGet = store.getCase.bind(store), originalRead = store.readInboxAtCheckpoint.bind(store);
    let read = false;
    const get = jest.spyOn(store, 'getCase').mockImplementation(async caseId =>
      defect === 'withdrawn' || (defect === 'racing-withdrawal' && read) ? replacement : originalGet(caseId));
    const inbox = jest.spyOn(store, 'readInboxAtCheckpoint').mockImplementation(async (...args) => {
      read = true;
      return defect === 'transaction-conflict' ? null : originalRead(...args);
    });
    try {
      const target = defect === 'unapproved'
        ? createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: hex(0xdef) }) : service;
      const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
      await expect(target.readInbox(body, await authorized('owner', 'read-inbox', trust.caseId,
        body, owner.privateKey))).rejects.toThrow(defect === 'transaction-conflict' ? 'conflict' : 'release-not-approved');
      expect(inbox).toHaveBeenCalledTimes(['unapproved', 'withdrawn'].includes(defect) ? 0 : 1);
    } finally { get.mockRestore(); inbox.mockRestore(); }
  });

  test('message read transaction conflicts return no thread', async () => {
    const read = jest.spyOn(store, 'readMessagesAtCheckpoint').mockResolvedValue(null);
    try {
      const body = encode({ caseId: trust.caseId });
      await expect(service.readMessages(body, await authorized('organization', 'read-messages', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow('conflict');
    } finally { read.mockRestore(); }
  });

  test.each(['owner', 'organization'] as const)('an unapproved backend cannot accept a %s message', async role => {
    const upgraded = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: hex(0xdef) });
    const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext: 'synthetic ciphertext' });
    const append = jest.spyOn(store, 'appendMessage');
    try {
      const auth = await authorized(role, 'send-message', trust.caseId, body,
        role === 'owner' ? owner.privateKey : firm, role === 'owner' ? null : org.organizationId);
      await expect(upgraded.sendMessage(body, auth, role === 'owner' ? null : org)).rejects.toThrow('release-not-approved');
      expect(append).not.toHaveBeenCalled();
    } finally { append.mockRestore(); }
  });

  test('a consent change while checking message quota prevents the write', async () => {
    const record = (await store.getCase(trust.caseId))!;
    const current = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
    const changed = await signed({ ...current, revision: current.revision + 1,
      previousDigest: record.currentCheckpointDigest, grantDigests: [] });
    const originalGet = store.getCase.bind(store);
    let revoked = false;
    const get = jest.spyOn(store, 'getCase').mockImplementation(async caseId => revoked
      ? { ...record, currentCheckpointDigest: changed.digest, checkpoints: [...record.checkpoints, changed.wire] }
      : originalGet(caseId));
    const quota = jest.spyOn(store, 'countMessages').mockImplementation(async () => { revoked = true; return 0; });
    const append = jest.spyOn(store, 'appendMessage');
    try {
      const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, ciphertext: 'synthetic ciphertext' });
      await expect(service.sendMessage(body, await authorized('organization', 'send-message', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow('unauthorized');
      expect(append).not.toHaveBeenCalled();
    } finally { get.mockRestore(); quota.mockRestore(); append.mockRestore(); }
  });

  test('envelopes can only be addressed to currently granted recipients', async () => {
    const checkpoint = await nextCheckpoint({});
    const raw = encode({ caseId: trust.caseId, statements: [], checkpoint: checkpoint.wire, objects: [],
      envelopes: [{ objectId: narrativeContext.objectId, recipientKeyId: otherOrg.recipientKeyId, envelope: 'opaque' }],
      recoveryPackage: null });
    await expect(service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId, raw, owner.privateKey)))
      .rejects.toThrow('invalid');
    checkpointRevision -= 1;
  });

  test('only the owner can decline an exact request; retries do not alter grants or resurrect it', async () => {
    const before = await store.getCase(trust.caseId);
    const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, requestId: hex(0x201) });
    await expect(service.declineAccessRequest(body, await authorized('owner', 'decline-request', trust.caseId,
      body, firm))).rejects.toThrow('unauthorized');
    const upgraded = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: hex(0xdef) });
    await expect(upgraded.declineAccessRequest(body, await authorized('owner', 'decline-request', trust.caseId,
      body, owner.privateKey))).rejects.toThrow('release-not-approved');
    const altered = encode({ caseId: trust.caseId, organizationId: otherOrg.organizationId, requestId: hex(0x201) });
    await expect(service.declineAccessRequest(altered, await authorized('owner', 'decline-request', trust.caseId,
      body, owner.privateKey))).rejects.toThrow('unauthorized');
    const proof = await authorized('owner', 'decline-request', trust.caseId, body, owner.privateKey);
    await expect(service.declineAccessRequest(body, proof)).resolves.toEqual({ state: 'declined' });
    await expect(service.declineAccessRequest(body, proof)).rejects.toThrow('unauthorized');
    await expect(service.declineAccessRequest(body, await authorized('owner', 'decline-request', trust.caseId,
      body, owner.privateKey))).resolves.toEqual({ state: 'declined' });
    expect(await store.getCase(trust.caseId)).toEqual(before);
    const [request] = await store.listAccessRequests(trust.caseId);
    expect(request.state).toBe('declined');
    expect(await store.putAccessRequest({ ...request, state: 'pending' })).toBe(false);
    const inboxBody = encode({ caseId: trust.caseId, afterCheckpoint: null });
    expect((await service.readInbox(inboxBody, await authorized('owner', 'read-inbox', trust.caseId,
      inboxBody, owner.privateKey))).requests).toEqual([]);
  });

  test('expired requests leave the inbox, retain identity and allow a new request', async () => {
    const originalTime = clock;
    const submit = async (id: string, expiresAt: number) => {
      const ciphertext = await createLegalAccessRequest({ requestId: id, scopes: ['narrative'], objectRevisionLimit: null,
        purpose: 'Synthetic review', issuedAt: clock, expiresAt }, otherOrg.organizationId, otherFirm, trust);
      const body = encode({ caseId: trust.caseId, requestId: id, ciphertext, expiresAt });
      return service.submitAccessRequest(body, await authorized('organization', 'request-access', trust.caseId,
        body, otherFirm, otherOrg.organizationId), otherOrg);
    };
    try {
      await submit(hex(0x701), clock + 100);
      clock += 100;
      const body = encode({ caseId: trust.caseId, afterCheckpoint: null });
      const inbox = await service.readInbox(body, await authorized('owner', 'read-inbox', trust.caseId, body, owner.privateKey));
      expect(inbox.requests.some(item => item.requestId === hex(0x701))).toBe(false);
      expect((await store.listAccessRequests(trust.caseId)).find(item => item.requestId === hex(0x701))!.state).toBe('expired');
      await expect(submit(hex(0x701), clock + 100)).rejects.toThrow('conflict');
      await expect(submit(hex(0x702), clock + 100)).resolves.toEqual({ state: 'requested' });
    } finally { clock = originalTime; }
  });

  test.each([0, -1, 30 * 86_400_000 + 1])('request deadline offset %s is rejected before persistence', async offset => {
    const body = encode({ caseId: trust.caseId, requestId: hex(0x799), ciphertext: 'synthetic', expiresAt: clock + offset });
    const insert = jest.spyOn(store, 'insertAccessRequestAtCheckpoint');
    try {
      await expect(service.submitAccessRequest(body, await authorized('organization', 'request-access', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow('invalid');
      expect(insert).not.toHaveBeenCalled();
    } finally { insert.mockRestore(); }
  });

  test('decline transaction conflicts do not report success', async () => {
    const decline = jest.spyOn(store, 'declineAccessRequest').mockResolvedValue('conflict');
    try {
      const body = encode({ caseId: trust.caseId, organizationId: org.organizationId, requestId: hex(0x201) });
      await expect(service.declineAccessRequest(body, await authorized('owner', 'decline-request', trust.caseId,
        body, owner.privateKey))).rejects.toThrow('conflict');
    } finally { decline.mockRestore(); }
  });

  test.each(['pending', 'withdrawn', 'declined', 'expired'] as const)('request status returns only this firm request state: %s', async state => {
    const body = encode({ caseId: trust.caseId, requestIds: [hex(0x888)] });
    const lookup = jest.spyOn(store, 'getAccessRequest').mockResolvedValue({
      caseId: trust.caseId, organizationId: org.organizationId, recipientKeyId: org.recipientKeyId,
      requestId: hex(0x888), state, expiresAt: clock + 1000, createdAt: clock, ciphertext: 'PRIVATE-CIPHERTEXT',
    });
    try {
      const status = await service.requestStatus(body, await authorized('organization', 'request-status', trust.caseId,
        body, firm, org.organizationId), org) as { requests: unknown[]; access: { state: string } };
      expect(status.requests).toEqual([state === 'pending' ? { requestId: hex(0x888), state: 'requested', expiresAt: clock + 1000 }
        : { requestId: hex(0x888), state }]);
      expect(['active', 'expired', 'revoked', 'key-changed', 'none', 'unknown']).toContain(status.access.state);
      expect(JSON.stringify(status)).not.toContain('PRIVATE-CIPHERTEXT');
      expect(lookup).toHaveBeenCalledWith(trust.caseId, org.organizationId, hex(0x888));
    } finally { lookup.mockRestore(); }
  });

  test('request status computes expiry without mutating the mailbox', async () => {
    const body = encode({ caseId: trust.caseId, requestIds: [hex(0x889)] });
    const lookup = jest.spyOn(store, 'getAccessRequest').mockResolvedValue({ caseId: trust.caseId,
      organizationId: org.organizationId, recipientKeyId: org.recipientKeyId, requestId: hex(0x889),
      state: 'pending', expiresAt: clock, createdAt: clock - 1, ciphertext: 'PRIVATE-CIPHERTEXT' });
    const expire = jest.spyOn(store, 'expireAccessRequests');
    try {
      await expect(service.requestStatus(body, await authorized('organization', 'request-status', trust.caseId,
        body, firm, org.organizationId), org)).resolves.toMatchObject({ requests: [{ requestId: hex(0x889), state: 'expired' }] });
      expect(expire).not.toHaveBeenCalled();
    } finally { lookup.mockRestore(); expire.mockRestore(); }
  });

  test('request status rejects a substituted firm row and an unrelated signing key', async () => {
    const body = encode({ caseId: trust.caseId, requestIds: [hex(0x890)] });
    const lookup = jest.spyOn(store, 'getAccessRequest').mockResolvedValue({ caseId: trust.caseId,
      organizationId: otherOrg.organizationId, recipientKeyId: otherOrg.recipientKeyId, requestId: hex(0x890),
      state: 'pending', expiresAt: clock + 1000, createdAt: clock, ciphertext: 'PRIVATE-CIPHERTEXT' });
    try {
      await expect(service.requestStatus(body, await authorized('organization', 'request-status', trust.caseId,
        body, firm, org.organizationId), org)).rejects.toThrow();
      lookup.mockClear();
      await expect(service.requestStatus(body, await authorized('organization', 'request-status', trust.caseId,
        body, otherFirm, org.organizationId), org)).rejects.toThrow();
      expect(lookup).not.toHaveBeenCalled();
    } finally { lookup.mockRestore(); }
  });

  test('revocation removes official delivery; a new unapproved backend release is refused', async () => {
    const openBody = encode({ caseId: trust.caseId });
    await commit({ checkpoint: (await nextCheckpoint({ grantDigests: [] })).wire });
    await expect(service.openCase(openBody, await authorized('organization', 'open-case', trust.caseId, openBody,
      firm, org.organizationId), org)).rejects.toThrow('not-found');
    // A new release deployment cannot serve this case until the owner approves its exact digest.
    const upgraded = createCaseService({ channel: CHANNEL, store, clock: () => clock, audience: AUDIENCE, releaseDigest: hex(0xdef) });
    const grant = await signed({ kind: 'grant', caseId: trust.caseId, revision: checkpointRevision + 1, grantId: hex(0x302),
      organizationId: org.organizationId, recipientKeyId: org.recipientKeyId, scopes: ['narrative'], keyEpoch: 1,
      objectRevisionLimit: null, issuedAt: clock, expiresAt: clock + 86_400_000 });
    await commit({ statements: [grant.wire], checkpoint: (await nextCheckpoint({ grantDigests: [grant.digest] })).wire });
    const { challenge } = await upgraded.issueChallenge();
    const auth = await signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: 'organization', caseId: trust.caseId,
      organizationId: org.organizationId, operation: 'open-case', body: openBody, challenge, issuedAt: clock }, firm);
    await expect(upgraded.openCase(openBody, auth, org)).rejects.toThrow('release-not-approved');
  });

  test('withdrawn summary disappears from the directory', async () => {
    await commit({ checkpoint: (await nextCheckpoint({ listingDigest: null })).wire });
    expect((await service.listListings({ kind: 'admin' }, null)).listings).toHaveLength(0);
  });

  test('account-free recovery restores the owner and the service chain verifies from the device pin', async () => {
    const { recoveryPackage } = await service.getRecoveryPackage(trust.caseId);
    const restored = await restoreOwnerRecovery(recoveryCode, recoveryPackage);
    expect(restored.trust.ownerFingerprint).toBe(trust.ownerFingerprint);
    const body = encode({ caseId: trust.caseId, afterCheckpoint: restored.pin.digest });
    const inbox = await service.readInbox(body, await authorized('owner', 'read-inbox', trust.caseId, body, restored.privateKey));
    expect(inbox.checkpoints.length).toBe(checkpointRevision - 1);
  });

  test('owner control operations use actual encrypted channel context and reject forwarding', async () => {
    const keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
    const dispatch = createOwnerCaseControlDispatcher({ store, clock: () => clock, audience: AUDIENCE, releaseDigest: RELEASE });
    const sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => 1);
    const opened = new Set<string>();
    const invoke = async (nonce: string, body: unknown) => {
      // Sessions admit several sequential calls; open each nonce once.
      if (!opened.has(nonce)) { opened.add(nonce); await sessions.open(nonce); }
      const pending = await sealChannelRequest(keys.publicKey, nonce, encode(body));
      const response = await sessions.execute(nonce, pending.ciphertext);
      expect(response).not.toContain('checkpointDigest');
      return JSON.parse(new TextDecoder().decode(await pending.openResponse(response)));
    };
    const serverKeyId = await caseRecipientKeyId(keys.publicKey);
    try {
      const nonce = hex(0xd02), body = encode({ caseId: trust.caseId, organizationId: org.organizationId, requestId: hex(0x201) });
      // A challenge from another session is refused even with a proof bound to this session.
      const foreign = await invoke(hex(0xd01), { operation: 'case.challenge' });
      const foreignProof = await signParticipantRequest({ audience: AUDIENCE, role: 'owner', caseId: trust.caseId, organizationId: null,
        operation: 'decline-request', body, challenge: foreign.challenge, issuedAt: clock, nonce, serverKeyId }, owner.privateKey);
      await expect(invoke(nonce, { operation: 'case.decline-request', proof: foreignProof, body: Buffer.from(body).toString('base64') }))
        .rejects.toThrow('Confidential channel unavailable');
      opened.delete(nonce); // That failure ended the session.
      const challenge = await invoke(nonce, { operation: 'case.challenge' });
      const proof = await signParticipantRequest({ audience: AUDIENCE, role: 'owner', caseId: trust.caseId, organizationId: null,
        operation: 'decline-request', body, challenge: challenge.challenge, issuedAt: clock, nonce, serverKeyId }, owner.privateKey);
      const request = { operation: 'case.decline-request', proof, body: Buffer.from(body).toString('base64') };
      await expect(invoke(hex(0xd03), request)).rejects.toThrow('Confidential channel unavailable');
      // Same session: challenge, then the operation.
      await expect(invoke(nonce, request)).resolves.toEqual({ state: 'declined' });
      // The spent challenge cannot be used again in the same session (a fresh sealing of the same proof).
      await expect(invoke(nonce, request)).rejects.toThrow('Confidential channel unavailable');
      await expect(invoke(hex(0xd04), { operation: 'admin.read-private', body: 'PRIVATE-SENTINEL' })).rejects.toThrow('Confidential channel unavailable');
      await expect(invoke(hex(0xd05), { operation: 'case.challenge', nonce: CHANNEL.nonce })).rejects.toThrow('Confidential channel unavailable');
      await expect(invoke(hex(0xd0a), { operation: 'case.challenge', count: 9 })).rejects.toThrow('Confidential channel unavailable');
      await expect(invoke(hex(0xd0b), { operation: 'case.challenge', count: 0 })).rejects.toThrow('Confidential channel unavailable');
      const current = (await store.getCase(trust.caseId))!;
      const previous = (await verifyOwnerStatement(current.checkpoints[current.checkpoints.length - 1], trust)).statement as CaseCheckpoint;
      const next = await signed({ ...previous, revision: previous.revision + 1, previousDigest: current.currentCheckpointDigest });
      const commitBody = encode({ caseId: trust.caseId, statements: [], checkpoint: next.wire, objects: [], envelopes: [], recoveryPackage: null });
      // A batch: several single-use challenges for the next operations of this session.
      const batch = await invoke(hex(0xd07), { operation: 'case.challenge', count: 3 });
      expect(batch.challenges).toHaveLength(3);
      expect(new Set(batch.challenges).size).toBe(3);
      const commitProof = await signParticipantRequest({ audience: AUDIENCE, role: 'owner', caseId: trust.caseId, organizationId: null,
        operation: 'commit-transition', body: commitBody, challenge: batch.challenges[1], issuedAt: clock,
        nonce: hex(0xd07), serverKeyId }, owner.privateKey);
      await expect(invoke(hex(0xd07), { operation: 'case.commit-transition', proof: commitProof,
        body: Buffer.from(commitBody).toString('base64') })).resolves.toEqual({ checkpointDigest: next.digest });
      expect((await store.getCase(trust.caseId))!.currentCheckpointDigest).toBe(next.digest);
      await expect(invoke(hex(0xd08), { operation: 'case.commit-transition', proof: commitProof, body: 'not base64' }))
        .rejects.toThrow('Confidential channel unavailable');
      const abort = new AbortController(); abort.abort();
      await expect(dispatch(encode({ operation: 'case.challenge' }), { nonce: hex(0xd09), serverKeyId: hex(0xd10),
        requestId: hex(0xd11), requestDigest: hex(0xd12), signal: abort.signal, challenges: createSessionChallenges() }))
        .rejects.toThrow('Owner case operation unavailable');
    } finally { sessions.close(); }
  });

  test('previousDigest is the single history link: retired transition records, forks and replays are refused', async () => {
    const record = (await store.getCase(trust.caseId))!;
    const tip = await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], trust);
    const current = tip.statement as CaseCheckpoint;
    const next = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest });
    const sibling = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest, listingDigest: null });
    // A record in the retired draft format, genuinely signed by the owner key.
    const legacyStatement = { kind: 'transition', caseId: trust.caseId, revision: current.revision + 1,
      previousDigest: tip.digest, checkpointDigest: next.digest, issuedAt: clock };
    const legacyPayload = JSON.stringify({ protocol: 'vera-owner-authorization/v1', ownerFingerprint: trust.ownerFingerprint,
      statement: legacyStatement });
    const legacy = JSON.stringify({ protocol: 'vera-owner-authorization/v1', ownerFingerprint: trust.ownerFingerprint,
      statement: legacyStatement, signature: await sign({ message: await createMessage({ binary: new TextEncoder().encode(legacyPayload) }),
        signingKeys: owner.privateKey, detached: true, format: 'armored' }) });
    await expect(verifyOwnerStatement(legacy, trust)).rejects.toThrow();
    await expect(signOwnerStatement(legacyStatement as unknown as OwnerStatement, owner.privateKey)).rejects.toThrow();
    const tampered = JSON.parse(next.wire);
    tampered.statement.previousDigest = hex(0x999);
    const send = async (checkpoint: string, statements: string[] = []) => {
      const raw = encode({ caseId: trust.caseId, statements, checkpoint, objects: [], envelopes: [], recoveryPackage: null });
      return service.commitTransition(raw, await authorized('owner', 'commit-transition', trust.caseId, raw, owner.privateKey));
    };
    // Successor sanity that the retired transition check carried is enforced on the
    // mounted commit path: bounded key-epoch step, no signed time regression or lead.
    const epochJump = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest,
      keyEpoch: current.keyEpoch + 2 });
    const backdated = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest,
      issuedAt: current.issuedAt - 1 });
    const futureDated = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest,
      issuedAt: clock + 300_001 });
    const persist = jest.spyOn(store, 'commitTransition');
    try {
      for (const bad of [epochJump, backdated, futureDated]) await expect(send(bad.wire)).rejects.toThrow('invalid');
      await expect(send(next.wire, [legacy])).rejects.toThrow('invalid');
      await expect(send(JSON.stringify(tampered))).rejects.toThrow('invalid');
      expect(persist).not.toHaveBeenCalled();
      // The owner-signed checkpoint alone authorizes exactly one successor of the tip.
      await expect(send(next.wire)).resolves.toEqual({ checkpointDigest: next.digest });
      await expect(send(sibling.wire)).rejects.toThrow('conflict');
      await expect(send(next.wire)).rejects.toThrow('conflict');
      expect(persist).toHaveBeenCalledTimes(1);
    } finally { persist.mockRestore(); }
    checkpointDigest = next.digest;
    checkpointRevision = (next.statement as CaseCheckpoint).revision;
    // Stored state carries no other link record, and a device verifies it from the chain alone.
    const after = (await store.getCase(trust.caseId))!;
    expect(Object.values(after.statements).map(wire => JSON.parse(wire).statement.kind)).not.toContain('transition');
    const chain = await Promise.all(after.checkpoints.map(wire => verifyOwnerStatement(wire, trust)));
    chain.forEach((item, index) => expect((item.statement as CaseCheckpoint).previousDigest)
      .toBe(index ? chain[index - 1].digest : null));
    const genesis = chain[0].statement as CaseCheckpoint;
    const pin = { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint, revision: genesis.revision,
      keyEpoch: genesis.keyEpoch, digest: chain[0].digest };
    await expect(advanceOwnerCheckpoint(after.checkpoints.slice(1), trust, pin)).resolves.toMatchObject({ digest: next.digest });
    await expect(advanceOwnerCheckpoint([...after.checkpoints.slice(1, -1), legacy, after.checkpoints[after.checkpoints.length - 1]],
      trust, pin)).rejects.toThrow();
    await expect(advanceOwnerCheckpoint(after.checkpoints.slice(2), trust, pin)).rejects.toThrow();
  });

  test('malformed bodies fail closed without echoing input', async () => {
    const raw = new TextEncoder().encode('PRIVATE-SENTINEL');
    await expect(service.readInbox(raw, '{}')).rejects.toThrow('Confidential case request failed: invalid');
    await expect(service.getRecoveryPackage('../etc')).rejects.toThrow('invalid');
  });
});
