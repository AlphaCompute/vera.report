import { createHash, webcrypto } from 'node:crypto';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { BSON, MongoClient, ObjectId } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createCaseService } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { generateCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import type { CaseRecord, CaseStore } from '../../../enclave/src/cases/service';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { caseObjectDigest, sealCaseObject } from '../../../enclave/src/confidential/caseObject';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases';
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() }; // Synthetic test session.
const RELEASE = hex(0xabc);
const HOUR = 3_600_000, DAY_MS = 24 * HOUR;
/** End of the UTC hour (unchanged on a boundary): the stored staging expiry. */
const hourCeil = (time: number) => time % HOUR === 0 ? time : time - (time % HOUR) + HOUR;

describe('MongoConfidentialCaseStore with the enclave case service', () => {
  let server: MongoMemoryReplSet, client: MongoClient, store: MongoConfidentialCaseStore;
  const now = Date.now();

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(server.getUri(), { monitorCommands: true });
    store = await MongoConfidentialCaseStore.fromDatabase(client.db('test_confidential'), client);
  }, 120_000);
  afterAll(async () => { await client?.close(); await server?.stop(); });

  test('case creation does not queue Slack alerts and hides retired alert state', async () => {
    const isolated = await MongoConfidentialCaseStore.fromDatabase(client.db('test_admin_alerts'), client);
    const record = { caseId: hex(0xabb), ownerPublicKey: 'public', ownerFingerprint: hex(1), statements: {},
      checkpoints: [], currentCheckpointDigest: hex(2), listingDigest: null, recoveryPackage: 'encrypted', createdAt: now };
    expect(await isolated.createCase(record)).toBe(true);
    expect(await isolated.createCase(record)).toBe(false);
    const cases = client.db('test_admin_alerts').collection('confidential_cases');
    expect(await cases.findOne({ _id: record.caseId } as never)).not.toHaveProperty('adminAlert');
    // Old pending alerts remain internal and have no delivery worker.
    await cases.updateOne({ _id: record.caseId } as never,
      { $set: { adminAlert: { dueAt: now, attempts: 0, sent: false } } });
    expect(await isolated.getCase(record.caseId)).not.toHaveProperty('adminAlert');
  });

  test('publish, compare-and-set transition and stale-writer rejection persist only ciphertext', async () => {
    // Structural check: the host adapter satisfies the enclave store contract.
    const typed: CaseStore = store;
    const service = createCaseService({ channel: CHANNEL, store: typed, clock: () => now, audience: AUDIENCE, releaseDigest: RELEASE });
    const owner = await createCaseOwner(), trust = owner.trust;
    const signed = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner.privateKey);
      return { wire, ...await verifyOwnerStatement(wire, trust) };
    };
    const auth = async (operation: 'publish-case' | 'commit-transition', body: Uint8Array) => {
      const { challenge } = await service.issueChallenge();
      return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: 'owner', caseId: trust.caseId, organizationId: null,
        operation, body, challenge, issuedAt: now }, owner.privateKey);
    };
    const context = { caseId: trust.caseId, objectId: hex(1), scope: 'narrative' as const, keyEpoch: 1, objectRevision: 1 };
    const object = await sealCaseObject(context, new TextEncoder().encode('PRIVATE-SENTINEL'), owner.privateKey);
    const listing = await signed({ kind: 'listing', caseId: trust.caseId, revision: 1, summary: 'Public summary' });
    const release = await signed({ kind: 'release', caseId: trust.caseId, revision: 1, releaseDigest: RELEASE, issuedAt: now });
    const manifest = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 1, objects: [{ objectId: hex(1),
      scope: 'narrative', objectRevision: 1, keyEpoch: 1, ciphertextDigest: await caseObjectDigest(object.ciphertext) }] });
    const first = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
      listingDigest: listing.digest, manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: now });
    const recovery = await createOwnerRecovery(owner, first.wire);
    const body = new TextEncoder().encode(JSON.stringify({ caseId: trust.caseId, ownerPublicKey: trust.ownerPublicKey.armor(),
      statements: [listing.wire, release.wire, manifest.wire], checkpoint: first.wire,
      objects: [{ objectId: hex(1), ...object }], recoveryPackage: recovery.encryptedPackage }));
    await service.publishCase(body, await auth('publish-case', body));
    // Idempotent retry of the same publish succeeds without a second case.
    await service.publishCase(body, await auth('publish-case', body));
    expect((await service.listListings({ kind: 'admin' }, null)).listings).toHaveLength(1);

    const withdraw = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 2, keyEpoch: 1,
      previousDigest: first.digest, listingDigest: null, manifestDigest: manifest.digest, grantDigests: [],
      releaseDigests: [release.digest], issuedAt: now });
    const transition = (checkpoint: string) => new TextEncoder().encode(JSON.stringify({ caseId: trust.caseId,
      statements: [], checkpoint, objects: [], envelopes: [], recoveryPackage: null }));
    const next = transition(withdraw.wire);
    await service.commitTransition(next, await auth('commit-transition', next));
    expect((await service.listListings({ kind: 'admin' }, null)).listings).toHaveLength(0);
    // A second writer holding the old tip is refused by compare-and-set.
    const fork = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 2, keyEpoch: 1,
      previousDigest: first.digest, listingDigest: listing.digest, manifestDigest: manifest.digest, grantDigests: [],
      releaseDigests: [release.digest], issuedAt: now + 1 });
    const stale = transition(fork.wire);
    await expect(service.commitTransition(stale, await auth('commit-transition', stale))).rejects.toThrow('conflict');

    const raw = JSON.stringify(await client.db('test_confidential').collections().then(list =>
      Promise.all(list.map(collection => collection.find().toArray()))));
    expect(raw).not.toContain('PRIVATE-SENTINEL');
    expect(raw).not.toContain(recovery.recoveryCode.replace(/-/g, ''));
  }, 120_000);

  test('pending requests are unique per organization; the host store holds no challenges', async () => {
    // Challenges live only in enclave memory (session-challenges.ts), never in host storage.
    expect((store as unknown as Record<string, unknown>).putChallenge).toBeUndefined();
    expect(await client.db('test_confidential').listCollections({ name: 'confidential_challenges' }).toArray()).toEqual([]);
    const request = { caseId: hex(1), organizationId: hex(2), requestId: hex(3), recipientKeyId: hex(9), expiresAt: now + 1000, ciphertext: 'opaque', state: 'pending' as const, createdAt: now };
    expect(await store.putAccessRequest(request)).toBe(true);
    expect(await store.getAccessRequest(request.caseId, request.organizationId, request.requestId)).toEqual(request);
    expect(await store.getAccessRequest(request.caseId, hex(99999), request.requestId)).toBeNull();
    expect(await store.getAccessRequest(request.caseId, request.organizationId, hex(99999))).toBeNull();
    expect(await store.putAccessRequest({ ...request, requestId: hex(4) })).toBe(false);
    expect(await store.withdrawAccessRequest(hex(1), hex(2), hex(3))).toBe(true);
    expect(await store.putAccessRequest(request)).toBe(false);
    expect((await store.listAccessRequests(hex(1)))[0].state).toBe('withdrawn');
    expect(await store.putAccessRequest({ ...request, requestId: hex(4) })).toBe(true);
  });

  test('concurrent retries cannot restore a withdrawn request identity', async () => {
    const request = { caseId: hex(401), organizationId: hex(402), requestId: hex(403),
      recipientKeyId: hex(9), expiresAt: now + 1000, ciphertext: 'opaque', state: 'pending' as const, createdAt: now };
    expect(await store.putAccessRequest(request)).toBe(true);
    expect(await store.withdrawAccessRequest(request.caseId, request.organizationId, request.requestId)).toBe(true);
    expect(await Promise.all(Array.from({ length: 4 }, () => store.putAccessRequest(request)))).toEqual([false, false, false, false]);
    expect(await store.listAccessRequests(request.caseId)).toEqual([{ ...request, state: 'withdrawn' }]);
  });

  test('message append atomically enforces checkpoint and quota under concurrent writers', async () => {
    const caseId = hex(101), checkpointDigest = hex(102);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const row = { caseId, organizationId: hex(103), sender: 'organization' as const, ciphertext: 'opaque', createdAt: now };
    const guard = { checkpointDigest, since: now - 3600000, limit: 1 };
    const outcomes = await Promise.all(Array.from({ length: 4 }, () => store.appendMessage(row, guard)));
    expect(outcomes.filter(value => value === 'stored')).toHaveLength(1);
    expect(outcomes.filter(value => value === 'rate-limited')).toHaveLength(3);
    expect(await store.listMessages(caseId, row.organizationId, 10)).toHaveLength(1);
    await client.db('test_confidential').collection('confidential_messages').updateMany({ caseId },
      { $set: { unexpectedPrivateField: 'SYNTHETIC-EXTRA-FIELD' } });
    const read = await store.readMessagesAtCheckpoint(caseId, row.organizationId, 10, checkpointDigest);
    expect(read).toEqual([row]);
    expect(await store.readMessagesAtCheckpoint(caseId, hex(999), 10, checkpointDigest)).toEqual([]);
    await client.db('test_confidential').collection<{ _id: string; currentCheckpointDigest: string }>('confidential_cases').updateOne({ _id: caseId },
      { $set: { currentCheckpointDigest: hex(104) } });
    expect(await store.appendMessage(row, { ...guard, limit: 10 })).toBe('conflict');
    expect(await store.readMessagesAtCheckpoint(caseId, row.organizationId, 10, checkpointDigest)).toBeNull();
    expect(await store.readMessagesAtCheckpoint(caseId, row.organizationId, 10, hex(104))).toEqual([row]);
    expect(await store.listMessages(caseId, row.organizationId, 10)).toHaveLength(1);
    expect(await store.getCase(caseId)).not.toHaveProperty('messageWriteSequence');
  });

  test('a repeated idempotency tag is stored once per case under concurrent writers', async () => {
    const caseId = hex(811), checkpointDigest = hex(812);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const row = { caseId, organizationId: hex(813), sender: 'owner' as const, ciphertext: 'original sealed message',
      createdAt: now, dedupeTag: hex(815) };
    const { dedupeTag: _tag, ...visible } = row;
    const guard = { checkpointDigest, since: now - 3600000, limit: 10 };
    expect(await Promise.all(Array.from({ length: 5 }, () => store.appendMessage(row, guard)))).toEqual(Array(5).fill('stored'));
    await store.appendMessage({ ...row, createdAt: now + 500, ciphertext: 'later sealed message' }, guard);
    // A writer whose snapshot missed the first copy hits the unique index instead: still 'stored', no second row.
    const missed = jest.spyOn((store as any).messages, 'findOne').mockResolvedValueOnce(null);
    expect(await store.appendMessage({ ...row, createdAt: now + 400, ciphertext: 'racing sealed message' }, guard)).toBe('stored');
    missed.mockRestore();
    expect(await store.listMessages(caseId, row.organizationId, 10)).toEqual([visible]);
    expect((await store.readInboxAtCheckpoint(caseId, checkpointDigest))?.messages).toEqual([visible]);
    expect((await store.readMailboxPageAtCheckpoint(caseId, null, checkpointDigest, null))?.messages).toEqual([visible]);
    // Other tags (and rows without one) are ordinary appends under the same quota.
    await store.appendMessage({ ...row, organizationId: hex(814), dedupeTag: hex(816) }, guard);
    await store.appendMessage(visible, guard);
    expect((await store.readInboxAtCheckpoint(caseId, checkpointDigest))?.messages).toHaveLength(3);
    expect(await store.appendMessage({ ...row, dedupeTag: hex(817) }, { ...guard, limit: 2 })).toBe('rate-limited');
    await expect(store.appendMessage({ ...row, dedupeTag: 'report-open' }, guard)).rejects.toThrow('idempotency tag');
    expect(await store.appendMessage(row, { ...guard, checkpointDigest: hex(888) })).toBe('conflict');
  });

  test('expiry frees a pending slot while retaining its identity and isolating other cases', async () => {
    const request = { caseId: hex(801), organizationId: hex(802), requestId: hex(803), recipientKeyId: hex(804),
      ciphertext: 'opaque', state: 'pending' as const, createdAt: now, expiresAt: now + 1000 };
    await store.putAccessRequest(request);
    await store.putAccessRequest({ ...request, caseId: hex(805) });
    await store.expireAccessRequests(request.caseId, now + 999);
    expect((await store.listAccessRequests(request.caseId))[0].state).toBe('pending');
    await store.expireAccessRequests(request.caseId, now + 1000);
    expect((await store.listAccessRequests(request.caseId))[0].state).toBe('expired');
    expect((await store.listAccessRequests(hex(805)))[0].state).toBe('pending');
    expect(await store.putAccessRequest({ ...request, expiresAt: now + 2000 })).toBe(false);
    expect(await store.putAccessRequest({ ...request, requestId: hex(806), expiresAt: now + 2000 })).toBe(true);
  });

  test.each(['organization', 'case'])('concurrent request insertion enforces the %s quota atomically', async quota => {
    const base = quota === 'organization' ? 900 : 1000, checkpointDigest = hex(base + 1);
    const caseIds = Array.from({ length: 4 }, (_, index) => hex(base + 10 + index));
    for (const caseId of caseIds) await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic',
      statements: {}, checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: hex(base + 2), recoveryPackage: 'opaque', createdAt: now });
    const guard = { checkpointDigest, now, since: now - 86400000,
      organizationLimit: quota === 'organization' ? 1 : 10, caseLimit: quota === 'case' ? 1 : 10 };
    const requests = caseIds.map((caseId, index) => ({ caseId: quota === 'case' ? caseIds[0] : caseId,
      organizationId: hex(base + 30 + (quota === 'case' ? index : 0)), requestId: hex(base + 40 + index), recipientKeyId: hex(base + 50),
      ciphertext: 'opaque', state: 'pending' as const, createdAt: now, expiresAt: now + 1000 }));
    const results = await Promise.all(requests.map(request => store.insertAccessRequestAtCheckpoint(request, guard)));
    expect(results.filter(result => result === 'stored')).toHaveLength(1);
    expect(results.filter(result => result === 'rate-limited')).toHaveLength(3);
    const stored = (await Promise.all(caseIds.map(caseId => store.listAccessRequests(caseId)))).flat();
    expect(stored).toHaveLength(1);
    const winner = stored[0];
    expect(await store.insertAccessRequestAtCheckpoint({ ...winner, requestId: hex(base + 60) },
      { ...guard, checkpointDigest: hex(base + 99) })).toBe('conflict');
    const collection = client.db('test_confidential').collection<{ _id: string; listingDigest: string | null }>('confidential_cases');
    await collection.updateOne({ _id: winner.caseId }, { $set: { listingDigest: null } });
    expect(await store.insertAccessRequestAtCheckpoint({ ...winner, requestId: hex(base + 61) }, guard)).toBe('conflict');
  });

  test('at rest, a shared-list row and a blinded request row share no time finer than a UTC day', async () => {
    // A request sent 13:37:21.123 UTC, announced by the firm's shared-list write a
    // few milliseconds earlier. No stored field may let a snapshot pair the two.
    const DAY = 86_400_000, sent = Date.UTC(2026, 8, 28, 13, 37, 21, 123), expires = sent + 30 * DAY - 300_000;
    const caseId = hex(1801), checkpointDigest = hex(1802), organizationId = hex(1803);
    const sealed = createSealedCaseStore(store as unknown as CaseStore, createCaseKeyring({ clock: () => sent }));
    const state = generateCaseStateKey();
    expect(await sealed.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: ['synthetic checkpoint'], currentCheckpointDigest: checkpointDigest, listingDigest: hex(1804),
      recoveryPackage: 'opaque', createdAt: sent, stateEnvelopes: [],
      initialStateKey: { stateEpoch: state.stateEpoch, key: new Uint8Array(state.key) } } as unknown as CaseRecord)).toBe(true);
    expect(await store.putFirmSharedList(organizationId, 0, { version: 1, record: 'sealed list v1' })).toBe(true);
    expect(await sealed.insertAccessRequestAtCheckpoint({ caseId, organizationId, requestId: hex(1805), recipientKeyId: hex(1806),
      ciphertext: 'opaque', state: 'pending', createdAt: sent, expiresAt: expires },
    { checkpointDigest, now: sent, since: sent - DAY, organizationLimit: 5, caseLimit: 5 })).toBe('stored');
    expect(await store.putFirmSharedList(organizationId, 1, { version: 2, record: 'sealed list v2' })).toBe(true);
    // A row written before this change carried updatedAt; the next write drops it.
    const db = client.db('test_confidential');
    await db.collection('confidential_legal_shared_lists').updateOne({ _id: organizationId } as never, { $set: { updatedAt: new Date(sent) } });
    expect(await store.putFirmSharedList(organizationId, 2, { version: 3, record: 'sealed list v3' })).toBe(true);

    const times: number[] = [];
    const walk = (value: unknown): void => {
      if (value instanceof ObjectId) throw new Error('A driver ObjectId embeds its insertion second');
      if (value instanceof Date) times.push(value.getTime());
      else if (typeof value === 'number' && value > 1e12) times.push(value);
      else if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === 'object') Object.values(value).forEach(walk);
    };
    const list = await db.collection('confidential_legal_shared_lists').findOne({ _id: organizationId } as never);
    expect(Object.keys(list!).sort()).toEqual(['_id', 'record', 'version']);
    const rows = await db.collection('confidential_access_requests').find({ caseId } as never).toArray();
    expect(rows).toHaveLength(1);
    for (const row of [list, ...rows]) walk(row);
    expect(times.length).toBeGreaterThan(0);
    for (const time of times) expect(time % DAY).toBe(0);
    expect(rows[0].createdAt).toBe(sent - (sent % DAY));
    expect(rows[0].expiresAt).toBe(expires - (expires % DAY));
    expect(JSON.stringify(rows)).not.toContain(organizationId);
  });

  test('blinded requests keep one pending request per firm pseudonym per case, even concurrently', async () => {
    const caseId = hex(1301), otherCase = hex(1302), checkpointDigest = hex(1303);
    for (const id of [caseId, otherCase]) await store.createCase({ caseId: id, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic',
      statements: {}, checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: hex(1304), recoveryPackage: 'opaque', createdAt: now });
    const guard = { checkpointDigest, now, since: now - 86400000, organizationLimit: 25, caseLimit: 50 };
    // Every blinded row has its own organization and request tags; only the
    // per-case quota tag says "same firm".
    const blinded = (index: number, quotaTag: string, id = caseId) => ({ caseId: id, organizationId: hex(1400 + index),
      requestId: hex(1500 + index), recipientKeyId: hex(1600 + index), ciphertext: 'opaque', state: 'pending' as const,
      createdAt: now, expiresAt: now + 1000, quotaTag });
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) =>
      store.insertAccessRequestAtCheckpoint(blinded(index, hex(1700)), guard)));
    expect(results.filter(result => result === 'stored')).toHaveLength(1);
    expect(results.filter(result => result === 'conflict')).toHaveLength(5);
    // Another firm on the same case, and the same pseudonym on another case, are independent.
    expect(await store.insertAccessRequestAtCheckpoint(blinded(10, hex(1701)), guard)).toBe('stored');
    expect(await store.insertAccessRequestAtCheckpoint(blinded(11, hex(1700), otherCase), guard)).toBe('stored');
    // The rule survives restarts because it is stored, and frees on withdrawal.
    const pending = (await store.listAccessRequests(caseId)).find(row => row.quotaTag === hex(1700))!;
    await store.withdrawAccessRequest(caseId, pending.organizationId, pending.requestId);
    expect(await store.insertAccessRequestAtCheckpoint(blinded(12, hex(1700)), guard)).toBe('stored');
    // Identical retries of the stored request still return its receipt.
    expect(await store.insertAccessRequestAtCheckpoint(blinded(12, hex(1700)), guard)).toBe('stored');
    // A malformed pseudonym is refused outright.
    await expect(store.insertAccessRequestAtCheckpoint(blinded(13, 'not-a-tag'), guard)).rejects.toThrow('Invalid request insertion guard');
  });

  test('guarded insertion expires the previous request without losing replay protection', async () => {
    const caseId = hex(1101), checkpointDigest = hex(1102);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {}, checkpoints: [],
      currentCheckpointDigest: checkpointDigest, listingDigest: hex(1103), recoveryPackage: 'opaque', createdAt: now });
    const old = { caseId, organizationId: hex(1104), requestId: hex(1105), recipientKeyId: hex(1106),
      ciphertext: 'opaque', state: 'pending' as const, createdAt: now - 1000, expiresAt: now };
    await store.putAccessRequest(old);
    const guard = { checkpointDigest, now, since: now - 86400000, organizationLimit: 10, caseLimit: 1 };
    const next = { ...old, requestId: hex(1107), createdAt: now, expiresAt: now + 1000 };
    expect(await store.insertAccessRequestAtCheckpoint(next, guard)).toBe('stored');
    expect((await store.listAccessRequests(caseId)).map(request => request.state)).toEqual(['expired', 'pending']);
    await store.withdrawAccessRequest(caseId, next.organizationId, next.requestId);
    expect(await store.insertAccessRequestAtCheckpoint({ ...next, requestId: old.requestId }, guard)).toBe('conflict');
  });

  test('identical concurrent retries return one receipt without quota or payload changes', async () => {
    const caseId = hex(1201), checkpointDigest = hex(1202);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {}, checkpoints: [],
      currentCheckpointDigest: checkpointDigest, listingDigest: hex(1203), recoveryPackage: 'opaque', createdAt: now });
    const request = { caseId, organizationId: hex(1204), requestId: hex(1205), recipientKeyId: hex(1206),
      ciphertext: 'opaque', state: 'pending' as const, createdAt: now, expiresAt: now + 1000 };
    const guard = { checkpointDigest, now, since: now - 86400000, organizationLimit: 1, caseLimit: 1 };
    expect(await Promise.all(Array.from({ length: 4 }, () => store.insertAccessRequestAtCheckpoint(request, guard))))
      .toEqual(['stored', 'stored', 'stored', 'stored']);
    expect(await store.insertAccessRequestAtCheckpoint({ ...request, createdAt: now + 1 }, { ...guard, now: now + 1 })).toBe('stored');
    for (const change of [{ ciphertext: 'changed' }, { recipientKeyId: hex(1207) }, { expiresAt: now + 2000 }]) {
      expect(await store.insertAccessRequestAtCheckpoint({ ...request, ...change }, guard)).toBe('conflict');
    }
    expect(await store.listAccessRequests(caseId)).toEqual([request]);
    expect(await store.countAccessRequests({ organizationId: request.organizationId, since: guard.since })).toBe(1);
    await store.declineAccessRequest(caseId, request.organizationId, request.requestId, checkpointDigest);
    expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('conflict');
    expect((await store.listAccessRequests(caseId))[0].state).toBe('declined');
  });

  test('owner decline is checkpoint-bound, isolated, durable and idempotent', async () => {
    const caseId = hex(601), checkpointDigest = hex(602);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const request = { caseId, organizationId: hex(603), requestId: hex(604), ciphertext: 'opaque',
      recipientKeyId: hex(9), expiresAt: now + 1000, state: 'pending' as const, createdAt: now };
    await store.putAccessRequest(request);
    expect(await store.declineAccessRequest(caseId, request.organizationId, request.requestId, hex(605))).toBe('conflict');
    expect(await store.declineAccessRequest(caseId, hex(606), request.requestId, checkpointDigest)).toBe('not-found');
    expect((await store.listAccessRequests(caseId))[0].state).toBe('pending');
    expect(await Promise.all(Array.from({ length: 3 }, () =>
      store.declineAccessRequest(caseId, request.organizationId, request.requestId, checkpointDigest))))
      .toEqual(['declined', 'declined', 'declined']);
    expect(await store.putAccessRequest(request)).toBe(false);
    expect((await store.readInboxAtCheckpoint(caseId, checkpointDigest))!.requests).toEqual([]);
    const newer = { ...request, requestId: hex(607) };
    expect(await store.putAccessRequest(newer)).toBe(true);
    await store.withdrawAccessRequest(caseId, newer.organizationId, newer.requestId);
    expect(await store.declineAccessRequest(caseId, newer.organizationId, newer.requestId, checkpointDigest)).toBe('not-found');
  });

  test('an owner grant closes its request as approved, checkpoint-bound and without reopening', async () => {
    const caseId = hex(611), checkpointDigest = hex(612);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const request = { caseId, organizationId: hex(613), requestId: hex(614), ciphertext: 'opaque',
      recipientKeyId: hex(9), expiresAt: now + 1000, state: 'pending' as const, createdAt: now };
    await store.putAccessRequest(request);
    expect(await store.answerAccessRequest(caseId, request.organizationId, request.requestId, hex(615))).toBe('conflict');
    expect(await store.answerAccessRequest(caseId, hex(616), request.requestId, checkpointDigest)).toBe('not-found');
    expect(await store.answerAccessRequest(caseId, request.organizationId, request.requestId, checkpointDigest)).toBe('approved');
    expect(await store.answerAccessRequest(caseId, request.organizationId, request.requestId, checkpointDigest)).toBe('approved');
    expect((await store.listAccessRequests(caseId))[0].state).toBe('approved');
    // Answered requests leave the owner inbox and free the one-pending-request slot.
    expect((await store.readInboxAtCheckpoint(caseId, checkpointDigest))!.requests).toEqual([]);
    expect(await store.putAccessRequest({ ...request, requestId: hex(617) })).toBe(true);
    // A withdrawn or declined request is never turned into an approval.
    await store.withdrawAccessRequest(caseId, request.organizationId, hex(617));
    expect(await store.answerAccessRequest(caseId, request.organizationId, hex(617), checkpointDigest)).toBe('not-found');
    expect((await store.listAccessRequests(caseId)).find(item => item.requestId === hex(617))?.state).toBe('withdrawn');
  });

  test('a transaction cannot silently fall back to an unguarded append', async () => {
    const withoutClient = await MongoConfidentialCaseStore.fromDatabase(client.db('test_confidential'));
    await expect(withoutClient.appendMessage({ caseId: hex(201), organizationId: hex(202), sender: 'owner',
      ciphertext: 'opaque', createdAt: now }, { checkpointDigest: hex(203), since: now - 1000, limit: 1 }))
      .rejects.toThrow('require a Mongo client');
    await expect(withoutClient.readMessagesAtCheckpoint(hex(201), hex(202), 1, hex(203)))
      .rejects.toThrow('require a Mongo client');
    await expect(withoutClient.readInboxAtCheckpoint(hex(201), hex(203)))
      .rejects.toThrow('require a Mongo client');
    await expect(withoutClient.declineAccessRequest(hex(201), hex(202), hex(204), hex(203)))
      .rejects.toThrow('require a Mongo client');
    await expect(withoutClient.answerAccessRequest(hex(201), hex(202), hex(204), hex(203)))
      .rejects.toThrow('require a Mongo client');
    await expect(withoutClient.insertAccessRequestAtCheckpoint({ caseId: hex(201), organizationId: hex(202),
      requestId: hex(204), recipientKeyId: hex(205), ciphertext: 'opaque', state: 'pending', createdAt: now, expiresAt: now + 1000 },
    { checkpointDigest: hex(203), now, since: now - 1000, organizationLimit: 1, caseLimit: 1 }))
      .rejects.toThrow('require a Mongo client');
  });

  test('owner inbox binds checkpoint, excludes withdrawn and unrelated requests and projects fields', async () => {
    const caseId = hex(501), checkpointDigest = hex(502);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const request = { caseId, organizationId: hex(503), requestId: hex(504), ciphertext: 'opaque',
      recipientKeyId: hex(9), expiresAt: now + 1000, state: 'pending' as const, createdAt: now };
    await store.putAccessRequest(request);
    await store.putAccessRequest({ ...request, organizationId: hex(505), state: 'withdrawn' });
    await store.putAccessRequest({ ...request, caseId: hex(506) });
    await client.db('test_confidential').collection('confidential_access_requests').updateMany({ caseId },
      { $set: { unexpectedPrivateField: 'SYNTHETIC-EXTRA-FIELD' } });
    const message = { caseId, organizationId: request.organizationId, sender: 'owner' as const, ciphertext: 'opaque', createdAt: now };
    await store.appendMessage(message, { checkpointDigest, since: now - 1000, limit: 1 });
    expect(await store.readInboxAtCheckpoint(caseId, checkpointDigest)).toEqual({ requests: [request], messages: [message] });
    expect(await store.readInboxAtCheckpoint(caseId, hex(507))).toBeNull();
    expect(await store.readInboxAtCheckpoint(hex(508), checkpointDigest)).toBeNull();
  });

  test('object reads bind checkpoint, exact ciphertext and recipient envelope without owner metadata', async () => {
    const caseId = hex(301), previous = hex(302), current = hex(303), recipient = hex(304);
    const ref = { objectId: hex(305), ciphertextDigest: hex(306) };
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {}, checkpoints: [],
      currentCheckpointDigest: previous, listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    await store.commitTransition(caseId, previous, { statements: {}, checkpoint: 'synthetic', checkpointDigest: current,
      listingDigest: null, recoveryPackage: null, objects: [{ ...ref, ciphertext: 'encrypted object', ownerEnvelope: 'owner-only envelope' }],
      envelopes: [{ objectId: ref.objectId, recipientKeyId: recipient, envelope: 'firm envelope' }] });
    expect(await store.readGrantedObjects(caseId, recipient, current, [ref])).toEqual([
      { ...ref, ciphertext: 'encrypted object', recipientEnvelope: 'firm envelope' },
    ]);
    // Test-only command names, never payload logging. A batch size of one can
    // require getMore just to discover EOF, which DocumentDB transactions reject.
    const commands: string[] = [];
    const observe = (event: { commandName: string }) => { commands.push(event.commandName); };
    client.on('commandStarted', observe);
    try {
      expect(await store.readGrantedObjects(caseId, recipient, current, [ref], { offset: 0, length: 0 })).toEqual([
        { ...ref, ciphertext: '', recipientEnvelope: 'firm envelope', totalBytes: 16 },
      ]);
      expect(await store.readGrantedObjects(caseId, recipient, current, [ref], { offset: 4, length: 5 })).toEqual([
        { ...ref, ciphertext: 'ypted', recipientEnvelope: 'firm envelope', totalBytes: 16 },
      ]);
      expect(commands.filter(command => command === 'aggregate')).toHaveLength(2);
      expect(commands).not.toContain('getMore');
    } finally { client.off('commandStarted', observe); }
    await expect(store.readGrantedObjects(caseId, recipient, current, [ref], { offset: -1, length: 1 })).rejects.toThrow();
    await expect(store.readGrantedObjects(caseId, recipient, current, [ref], { offset: 0, length: 131073 })).rejects.toThrow();
    expect(await store.readGrantedObjects(caseId, recipient, previous, [ref], { offset: 0, length: 5 })).toBeNull();
    expect(await store.readGrantedObjects(caseId, recipient, previous, [ref])).toBeNull();
    expect(await store.readGrantedObjects(caseId, hex(999), current, [ref])).toBeNull();
    expect(await store.readGrantedObjects(caseId, recipient, current, [{ ...ref, ciphertextDigest: hex(999) }])).toBeNull();
    await expect(store.readGrantedObjects(caseId, recipient, current, [ref, ref])).rejects.toThrow('Invalid object read guard');
  });

  test('commits append history and envelopes outside the case document, which stays a fixed size', async () => {
    const caseId = hex(0x7001), recipient = hex(0x7002), db = client.db('test_confidential');
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: ['genesis'], currentCheckpointDigest: hex(0x7100), listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const size = async () => Buffer.byteLength(JSON.stringify(await db.collection('confidential_cases').findOne({ _id: caseId } as never)));
    const before = await size();
    for (let index = 1; index <= 40; index++) {
      expect(await store.commitTransition(caseId, hex(0x7100 + index - 1), { statements: {}, checkpoint: `checkpoint-${index}`,
        checkpointDigest: hex(0x7100 + index), listingDigest: null, recoveryPackage: null, objects: [],
        envelopes: [{ objectId: hex(0x7300 + index), recipientKeyId: recipient, envelope: `envelope-${index}`.padEnd(2048, '.') }] })).toBe(true);
    }
    // Only counters and the current digest changed: no per-commit growth.
    expect(await size()).toBeLessThan(before + 200);
    const record = await store.getCase(caseId);
    expect(record!.checkpoints).toEqual(['genesis', ...Array.from({ length: 40 }, (_, index) => `checkpoint-${index + 1}`)]);
    expect(record).not.toHaveProperty('historyCount');
    expect(record).not.toHaveProperty('envelopes');
    expect(await store.getEnvelopes(caseId, recipient)).toHaveLength(40);
    // A stale writer changes nothing, including the history collection.
    expect(await store.commitTransition(caseId, hex(0x7100), { statements: {}, checkpoint: 'stale', checkpointDigest: hex(0x7999),
      listingDigest: null, recoveryPackage: null, objects: [], envelopes: [] })).toBe(false);
    expect((await store.getCase(caseId))!.checkpoints).toHaveLength(41);
    expect(await db.collection('confidential_case_history').countDocuments({ caseId })).toBe(40);
  });

  test('concurrent commits on one case append exactly one history entry', async () => {
    const caseId = hex(0x7401);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: ['genesis'], currentCheckpointDigest: hex(0x7402), listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    const results = await Promise.all(Array.from({ length: 5 }, (_, index) => store.commitTransition(caseId, hex(0x7402), {
      statements: {}, checkpoint: `racer-${index}`, checkpointDigest: hex(0x7410 + index), listingDigest: null,
      recoveryPackage: null, objects: [], envelopes: [] })));
    expect(results.filter(Boolean)).toHaveLength(1);
    const record = await store.getCase(caseId);
    expect(record!.checkpoints).toHaveLength(2);
    expect(record!.currentCheckpointDigest).toBe(hex(0x7410 + results.indexOf(true)));
  });

  test('legacy documents with an embedded chain and envelopes keep working and extend in segments', async () => {
    const caseId = hex(0x7501), recipient = hex(0x7502), ref = { objectId: hex(0x7503), ciphertextDigest: hex(0x7504) };
    const db = client.db('test_confidential');
    // The pre-segmentation shape: every checkpoint and envelope in the document.
    await db.collection('confidential_cases').insertOne({ _id: caseId, caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic',
      statements: {}, checkpoints: ['legacy-0', 'legacy-1', 'legacy-2'], currentCheckpointDigest: hex(0x7510), listingDigest: null,
      recoveryPackage: 'opaque', createdAt: now,
      envelopes: { [`${ref.objectId}_${recipient}`]: { objectId: ref.objectId, recipientKeyId: recipient, envelope: 'legacy envelope' } } } as never);
    await store.putObjects(caseId, [{ ...ref, ciphertext: 'legacy object', ownerEnvelope: 'owner' }]);
    expect((await store.getCase(caseId))!.checkpoints).toEqual(['legacy-0', 'legacy-1', 'legacy-2']);
    expect(await store.readGrantedObjects(caseId, recipient, hex(0x7510), [ref])).toEqual([
      { ...ref, ciphertext: 'legacy object', recipientEnvelope: 'legacy envelope' }]);
    const added = { objectId: hex(0x7505), ciphertextDigest: hex(0x7506) };
    expect(await store.commitTransition(caseId, hex(0x7510), { statements: {}, checkpoint: 'segmented-3', checkpointDigest: hex(0x7511),
      listingDigest: null, recoveryPackage: null, objects: [{ ...added, ciphertext: 'new object', ownerEnvelope: 'owner' }],
      envelopes: [{ objectId: added.objectId, recipientKeyId: recipient, envelope: 'new envelope' }] })).toBe(true);
    expect(await store.commitTransition(caseId, hex(0x7511), { statements: {}, checkpoint: 'segmented-4', checkpointDigest: hex(0x7512),
      listingDigest: null, recoveryPackage: null, objects: [], envelopes: [] })).toBe(true);
    expect((await store.getCase(caseId))!.checkpoints).toEqual(['legacy-0', 'legacy-1', 'legacy-2', 'segmented-3', 'segmented-4']);
    expect((await store.getEnvelopes(caseId, recipient)).map(item => item.envelope).sort()).toEqual(['legacy envelope', 'new envelope']);
    expect(await store.readGrantedObjects(caseId, recipient, hex(0x7512), [ref, added])).toEqual([
      { ...ref, ciphertext: 'legacy object', recipientEnvelope: 'legacy envelope' },
      { ...added, ciphertext: 'new object', recipientEnvelope: 'new envelope' }]);
    const rows = await db.collection('confidential_case_history').find({ caseId } as never).sort({ index: 1 }).toArray();
    expect(rows.map(row => row.index)).toEqual([3, 4]);
  });

  test('a missing history segment fails closed instead of returning a shortened chain', async () => {
    const caseId = hex(0x7601), db = client.db('test_confidential');
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {},
      checkpoints: ['genesis'], currentCheckpointDigest: hex(0x7602), listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    for (let index = 1; index <= 3; index++) await store.commitTransition(caseId, hex(0x7601 + index), { statements: {},
      checkpoint: `c${index}`, checkpointDigest: hex(0x7602 + index), listingDigest: null, recoveryPackage: null, objects: [], envelopes: [] });
    await db.collection('confidential_case_history').deleteOne({ caseId, index: 2 } as never);
    await expect(store.getCase(caseId)).rejects.toThrow('history incomplete');
  });

  describe('segmented statements', () => {
    const wire = (kind: string, revision: number, tag = '') => JSON.stringify({ statement: { kind, revision, tag } });
    const bsonSize = async (caseId: string) => BSON.calculateObjectSize(
      (await client.db('test_confidential').collection('confidential_cases').findOne({ _id: caseId } as never))!);
    const genesis = (caseId: string, first: number) => store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic',
      statements: { [hex(first)]: wire('listing', 1), [hex(first + 1)]: wire('release', 1) }, checkpoints: ['genesis'],
      currentCheckpointDigest: hex(first + 0x100), listingDigest: hex(first), recoveryPackage: 'opaque', createdAt: now });

    test('listing edits and release approvals commit as rows and never grow the case document', async () => {
      const caseId = hex(0x8001), db = client.db('test_confidential');
      await genesis(caseId, 0x8100);
      const before = await bsonSize(caseId);
      let tip = hex(0x8200), listing = hex(0x8100);
      const expected: Record<string, string> = { [hex(0x8100)]: wire('listing', 1), [hex(0x8101)]: wire('release', 1) };
      for (let revision = 2; revision <= 61; revision++) {
        const statements: Record<string, string> = { [hex(0x8300 + revision)]: wire('listing', revision) };
        if (revision % 2) statements[hex(0x8400 + revision)] = wire('release', revision, 'x'.repeat(revision));
        listing = hex(0x8300 + revision);
        Object.assign(expected, statements);
        expect(await store.commitTransition(caseId, tip, { statements, checkpoint: `checkpoint-${revision}`,
          checkpointDigest: hex(0x8500 + revision), listingDigest: listing, recoveryPackage: null, objects: [], envelopes: [] })).toBe(true);
        tip = hex(0x8500 + revision);
      }
      // Counters and fixed-width digests only: byte-for-byte the same size.
      expect(await bsonSize(caseId)).toBe(before);
      const raw = await db.collection('confidential_cases').findOne({ _id: caseId } as never);
      expect(Object.keys(raw!.statements).sort()).toEqual([hex(0x8100), hex(0x8101)]);
      expect(await db.collection('confidential_case_statements').countDocuments({ caseId })).toBe(90);
      // A full read returns every statement exactly; no bookkeeping leaks out.
      const record = await store.getCase(caseId);
      expect(record!.statements).toEqual(expected);
      expect(record).not.toHaveProperty('statementCount');
      // Bounded view: the current listing and the newest releases only.
      const bounded = await store.getCase(caseId, { releaseLimit: 3 });
      expect(Object.keys(bounded!.statements).sort()).toEqual([listing, hex(0x8400 + 57), hex(0x8400 + 59), hex(0x8400 + 61)].sort());
      expect(Object.keys((await store.getCase(caseId, { releaseLimit: 0 }))!.statements)).toEqual([listing]);
      await expect(store.getCase(caseId, { releaseLimit: 10_000 })).rejects.toThrow('Invalid case read view');
      await expect(store.getCase(caseId, { releaseLimit: 1, extra: 1 } as never)).rejects.toThrow('Invalid case read view');
      // Directory reads: exactly the listing named by the pointer.
      const listed = (await store.listListedCases(100, null)).find(item => item.caseId === caseId)!;
      expect(listed.statements).toEqual({ [listing]: wire('listing', 61) });
      expect((await store.listListingWires(100, null)).find(item => item.caseId === caseId)!.listingWire).toBe(wire('listing', 61));
      // A stale writer adds no rows.
      expect(await store.commitTransition(caseId, hex(0x8200), { statements: { [hex(0x8999)]: wire('listing', 99) }, checkpoint: 'stale',
        checkpointDigest: hex(0x8998), listingDigest: hex(0x8999), recoveryPackage: null, objects: [], envelopes: [] })).toBe(false);
      expect(await db.collection('confidential_case_statements').countDocuments({ caseId })).toBe(90);
      // Re-committing a known digest keeps its position and count.
      expect(await store.commitTransition(caseId, tip, { statements: { [listing]: wire('listing', 61) }, checkpoint: 'again',
        checkpointDigest: hex(0x8600), listingDigest: listing, recoveryPackage: null, objects: [], envelopes: [] })).toBe(true);
      expect(Object.keys((await store.getCase(caseId))!.statements)).toHaveLength(92);
    });

    test('concurrent commits with statements append exactly one set', async () => {
      const caseId = hex(0x8701);
      await genesis(caseId, 0x8710);
      const results = await Promise.all(Array.from({ length: 5 }, (_, index) => store.commitTransition(caseId, hex(0x8810), {
        statements: { [hex(0x8900 + index)]: wire('listing', 2, String(index)) }, checkpoint: `racer-${index}`,
        checkpointDigest: hex(0x8a00 + index), listingDigest: hex(0x8900 + index), recoveryPackage: null, objects: [], envelopes: [] })));
      expect(results.filter(Boolean)).toHaveLength(1);
      const winner = results.indexOf(true);
      expect((await store.getCase(caseId))!.statements).toEqual({ [hex(0x8710)]: wire('listing', 1), [hex(0x8711)]: wire('release', 1),
        [hex(0x8900 + winner)]: wire('listing', 2, String(winner)) });
    });

    test('a missing or foreign statement segment fails closed', async () => {
      const caseId = hex(0x8b01), db = client.db('test_confidential');
      await genesis(caseId, 0x8b10);
      let tip = hex(0x8c10);
      for (let revision = 2; revision <= 4; revision++) {
        await store.commitTransition(caseId, tip, {
          statements: { [hex(0x8d00 + revision)]: wire('listing', revision) }, checkpoint: `c${revision}`,
          checkpointDigest: hex(0x8c10 + revision), listingDigest: hex(0x8d00 + revision), recoveryPackage: null, objects: [], envelopes: [] });
        tip = hex(0x8c10 + revision);
      }
      expect(Object.keys((await store.getCase(caseId))!.statements)).toHaveLength(5);
      const row = await db.collection('confidential_case_statements').findOne({ caseId, index: 1 } as never);
      await db.collection('confidential_case_statements').deleteOne({ _id: row!._id } as never);
      await expect(store.getCase(caseId)).rejects.toThrow('statements incomplete');
      // A row copied in from another case, at the missing position, is refused too.
      await db.collection('confidential_case_statements').insertOne({ ...row!, _id: `${hex(0x8b02)}:${row!.digest}` } as never);
      await expect(store.getCase(caseId)).rejects.toThrow('statements incomplete');
      // The bounded directory read simply lacks the missing listing (the enclave omits the row).
      await db.collection('confidential_case_statements').deleteOne({ caseId, index: 2 } as never);
      expect((await store.getCase(caseId, { releaseLimit: 4 }))!.statements[hex(0x8d04)]).toBeUndefined();
    });

    test('legacy documents with every statement embedded keep reading and extend in segments', async () => {
      const caseId = hex(0x8e01), db = client.db('test_confidential');
      const legacy = { [hex(0x8e10)]: wire('listing', 1), [hex(0x8e11)]: wire('release', 1), [hex(0x8e12)]: wire('listing', 2),
        [hex(0x8e13)]: wire('release', 2) };
      // The pre-segmentation shape: no statementCount, statements all in the document.
      await db.collection('confidential_cases').insertOne({ _id: caseId, caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic',
        statements: legacy, checkpoints: ['legacy-0', 'legacy-1'], currentCheckpointDigest: hex(0x8e20), listingDigest: hex(0x8e12),
        recoveryPackage: 'opaque', createdAt: now, envelopes: {} } as never);
      expect((await store.getCase(caseId))!.statements).toEqual(legacy);
      expect((await store.listListingWires(100, null)).find(item => item.caseId === caseId)!.listingWire).toBe(wire('listing', 2));
      expect(Object.keys((await store.getCase(caseId, { releaseLimit: 1 }))!.statements).sort()).toEqual([hex(0x8e12), hex(0x8e13)]);
      expect(await store.commitTransition(caseId, hex(0x8e20), { statements: { [hex(0x8e14)]: wire('listing', 3), [hex(0x8e15)]: wire('release', 3) },
        checkpoint: 'segmented-2', checkpointDigest: hex(0x8e21), listingDigest: hex(0x8e14), recoveryPackage: null, objects: [], envelopes: [] })).toBe(true);
      const raw = await db.collection('confidential_cases').findOne({ _id: caseId } as never);
      expect(raw!.statements).toEqual(legacy);
      expect((await store.getCase(caseId))!.statements).toEqual({ ...legacy, [hex(0x8e14)]: wire('listing', 3), [hex(0x8e15)]: wire('release', 3) });
      expect(Object.keys((await store.getCase(caseId, { releaseLimit: 2 }))!.statements).sort()).toEqual([hex(0x8e13), hex(0x8e14), hex(0x8e15)]);
      expect((await store.listListingWires(100, null)).find(item => item.caseId === caseId)!.listingWire).toBe(wire('listing', 3));
    });
  });

  test('staged ciphertext is retrievable by digest and staging is idempotent', async () => {
    await store.stageObject(hex(77), 'CIPHERTEXT-A', now);
    await store.stageObject(hex(77), 'CIPHERTEXT-B', now + 1);
    expect(await store.getStagedObject(hex(77))).toBe('CIPHERTEXT-A');
    expect(await store.getStagedObject(hex(78))).toBeNull();
    const collection = client.db('test_confidential').collection('confidential_staged_objects');
    const row = await collection.findOne({ _id: hex(77) } as never);
    // Rounded up to the UTC hour: never earlier than the exact lifetime, never finer than the hour.
    expect(row!.expiresAt.getTime()).toBe(hourCeil(now + DAY_MS));
    expect(row!.expiresAt.getTime() % HOUR).toBe(0);
    expect(row!.expiresAt.getTime()).toBeGreaterThanOrEqual(now + DAY_MS);
    await collection.updateOne({ _id: hex(77) } as never, { $set: { expiresAt: new Date(Date.now() - 1) } });
    expect(await store.getStagedObject(hex(77))).toBeNull();
    const restagedAt = Date.now();
    await store.stageObject(hex(77), 'RESTAGED-CIPHERTEXT', restagedAt);
    expect(await store.getStagedObject(hex(77))).toBe('RESTAGED-CIPHERTEXT');
    expect((await collection.findOne({ _id: hex(77) } as never))!.expiresAt.getTime()).toBe(hourCeil(restagedAt + DAY_MS));
  });
  test('evidence chunks: staged with expiry, promoted only at the indexed sizes, read only at the checkpoint', async () => {
    const digestOf = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
    const full = new Uint8Array(512 * 1024 + 16).fill(1), final = new Uint8Array(4096 + 16).fill(2);
    const [fullDigest, finalDigest] = [digestOf(full), digestOf(final)];
    await expect(store.stageChunk(fullDigest, new Uint8Array(100), now)).rejects.toThrow('Invalid chunk');
    await store.stageChunk(fullDigest, full, now);
    await store.stageChunk(fullDigest, full, now + 5);
    await store.stageChunk(finalDigest, final, now);
    const collection = client.db('test_confidential').collection('confidential_object_chunks');
    expect((await collection.findOne({ _id: fullDigest } as never))!.expiresAt.getTime()).toBe(hourCeil(now + 5 + DAY_MS));
    const objectDigest = hex(0x4401), caseId = hex(0x4402), checkpoint = hex(0x4403), recipient = hex(0x4404);
    // Wrong order means wrong sizes for each position; a missing chunk fails too.
    expect(await store.promoteChunks(caseId, objectDigest, [finalDigest, fullDigest], 4096)).toBe(false);
    expect(await store.promoteChunks(caseId, objectDigest, [fullDigest, hex(0x4499)], 4096)).toBe(false);
    expect(await store.promoteChunks(caseId, objectDigest, [fullDigest, finalDigest], 8192)).toBe(false);
    expect(await collection.countDocuments({ _id: { $in: [fullDigest, finalDigest] }, expiresAt: { $exists: true } } as never)).toBe(2);
    expect(await store.promoteChunks(caseId, objectDigest, [fullDigest, finalDigest], 4096)).toBe(true);
    expect(await store.promoteChunks(caseId, objectDigest, [fullDigest, finalDigest], 4096)).toBe(true); // Idempotent.
    expect(await collection.countDocuments({ _id: { $in: [fullDigest, finalDigest] }, expiresAt: { $exists: true } } as never)).toBe(0);
    // Re-staging a promoted chunk never makes it expire again.
    await store.stageChunk(finalDigest, final, now);
    expect((await collection.findOne({ _id: finalDigest } as never))!.expiresAt).toBeUndefined();

    const index = JSON.stringify({ format: 'vera-case-object/v2', chunkBytes: 512 * 1024, chunkCount: 2, finalBytes: 4096,
      header: 'sealed', chunks: [fullDigest, finalDigest] });
    const ref = { objectId: hex(0x4405), ciphertextDigest: objectDigest };
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: 'synthetic', statements: {}, checkpoints: [],
      currentCheckpointDigest: hex(0x4406), listingDigest: null, recoveryPackage: 'opaque', createdAt: now });
    await store.commitTransition(caseId, hex(0x4406), { statements: {}, checkpoint: 'synthetic', checkpointDigest: checkpoint,
      listingDigest: null, recoveryPackage: null, objects: [{ ...ref, ciphertext: index, ownerEnvelope: 'owner envelope' }],
      envelopes: [{ objectId: ref.objectId, recipientKeyId: recipient, envelope: 'firm envelope' }] });
    expect(await store.readObjectChunk(caseId, recipient, checkpoint, ref, 0)).toEqual({ chunk: Buffer.from(full).toString('base64') });
    expect(await store.readObjectChunk(caseId, null, checkpoint, ref, 1)).toEqual({ chunk: Buffer.from(final).toString('base64') });
    expect(await store.readObjectChunk(caseId, recipient, checkpoint, ref, 2)).toBeNull();
    expect(await store.readObjectChunk(caseId, recipient, hex(0x4406), ref, 0)).toBeNull();
    expect(await store.readObjectChunk(caseId, hex(0x4407), checkpoint, ref, 0)).toBeNull();
    expect(await store.readObjectChunk(caseId, recipient, checkpoint, { ...ref, ciphertextDigest: hex(0x4408) }, 0)).toBeNull();
    await expect(store.readObjectChunk(caseId, recipient, checkpoint, ref, 512)).rejects.toThrow('Invalid chunk read guard');
    // The owner's range read returns the owner envelope, never a recipient's.
    expect(await store.readGrantedObjects(caseId, null, checkpoint, [ref], { offset: 0, length: 12 })).toEqual([
      { ...ref, ciphertext: index.slice(0, 12), recipientEnvelope: 'owner envelope', totalBytes: index.length }]);
    // A staged but never promoted chunk is not readable through a committed index.
    const loose = new Uint8Array(8192 + 16).fill(3);
    await store.stageChunk(digestOf(loose), loose, now);
    const other = { objectId: hex(0x4409), ciphertextDigest: hex(0x4410) };
    await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'synthetic', checkpointDigest: hex(0x4411),
      listingDigest: null, recoveryPackage: null, objects: [{ ...other, ciphertext: JSON.stringify({ format: 'vera-case-object/v2',
        chunkBytes: 512 * 1024, chunkCount: 1, finalBytes: 8192, header: 'sealed', chunks: [digestOf(loose)] }), ownerEnvelope: 'owner' }],
      envelopes: [] });
    expect(await store.readObjectChunk(caseId, null, hex(0x4411), other, 0)).toBeNull();
  });

  test('mailbox pages exceed 500 messages without truncation and reject concurrent writes/withdrawals', async () => {
    const caseId = hex(0x9001), org = hex(0x9002), checkpointDigest = hex(0x9003);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: hex(1), statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: hex(3), recoveryPackage: '', createdAt: now });
    const db = client.db('test_confidential');
    await db.collection('confidential_messages').insertMany(Array.from({ length: 520 }, (_, index) => ({
      caseId, organizationId: org, sender: 'owner', createdAt: now + index,
      ciphertext: `ciphertext-${index}-` + 'x'.repeat(9000),
    })));
    let page = await store.readMailboxPageAtCheckpoint(caseId, org, checkpointDigest, null);
    expect(page?.next).not.toBeNull();
    const collected = [...page!.messages];
    // Unrelated reads may advance the transaction fence, never the mailbox revision.
    await store.readMessagesAtCheckpoint(caseId, org, 1, checkpointDigest);
    while (page!.next) {
      page = await store.readMailboxPageAtCheckpoint(caseId, org, checkpointDigest, page!.next);
      expect(page).not.toBeNull();
      expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThan(160 * 1024);
      collected.push(...page!.messages);
    }
    expect(collected).toHaveLength(520);
    expect(collected.map(item => item.createdAt)).toEqual(Array.from({ length: 520 }, (_, index) => now + index));
    const stale = await store.readMailboxPageAtCheckpoint(caseId, org, checkpointDigest, null);
    await store.appendMessage({ caseId, organizationId: org, sender: 'owner', createdAt: now + 600,
      ciphertext: 'later' }, { checkpointDigest, since: now, limit: 1000 });
    expect(await store.readMailboxPageAtCheckpoint(caseId, org, checkpointDigest, stale!.next)).toBeNull();
    await store.insertAccessRequestAtCheckpoint({ caseId, organizationId: org, requestId: hex(0x9004), recipientKeyId: hex(0x9005),
      ciphertext: 'opaque', createdAt: now, expiresAt: now + 1000, state: 'pending' }, {
      checkpointDigest, now, since: now - 1000, organizationLimit: 25, caseLimit: 50,
    });
    const beforeWithdrawal = await store.readMailboxPageAtCheckpoint(caseId, null, checkpointDigest, null);
    await store.withdrawAccessRequest(caseId, org, hex(0x9004));
    expect(await store.readMailboxPageAtCheckpoint(caseId, null, checkpointDigest, beforeWithdrawal!.next)).toBeNull();
  });

  test('message rows have a random id and a write sequence; order holds within one hour and after older exact rows', async () => {
    const caseId = hex(0x9101), org = hex(0x9102), checkpointDigest = hex(0x9103);
    const sent = Date.UTC(2026, 8, 28, 13, 37, 21, 123), hour = sent - (sent % HOUR);
    await store.createCase({ caseId, ownerPublicKey: 'synthetic', ownerFingerprint: hex(1), statements: {},
      checkpoints: [], currentCheckpointDigest: checkpointDigest, listingDigest: null, recoveryPackage: '', createdAt: hour });
    const db = client.db('test_confidential');
    // Rows written before this change, earlier in the same hour: exact times
    // (later than the new rows' hour value), driver ObjectIds, no sequence.
    await db.collection('confidential_messages').insertMany([0, 1].map(index => ({
      caseId, organizationId: org, sender: 'owner', createdAt: hour + 30 * 60_000 + index, ciphertext: `legacy-${index}` })));
    // New rows all carry the same UTC hour; inserted out of id order on purpose.
    const guard = { checkpointDigest, since: hour - HOUR, limit: 100 };
    for (const index of [0, 1, 2, 3, 4]) {
      expect(await store.appendMessage({ caseId, organizationId: org, sender: 'owner', createdAt: hour,
        ciphertext: `sealed-${index}` }, guard)).toBe('stored');
    }
    const order = ['legacy-0', 'legacy-1', 'sealed-0', 'sealed-1', 'sealed-2', 'sealed-3', 'sealed-4'];
    const rows = await db.collection('confidential_messages').find({ caseId, sequence: { $exists: true } } as never).toArray();
    expect(rows).toHaveLength(5);
    for (const row of rows) {
      expect(row._id).not.toBeInstanceOf(ObjectId);
      expect(row._id).toMatch(/^[a-f0-9]{32}$/);
      expect(Number.isSafeInteger(row.sequence)).toBe(true);
    }
    expect(new Set(rows.map(row => row.sequence)).size).toBe(5);
    const texts = (messages: { ciphertext: string }[]) => messages.map(item => item.ciphertext);
    expect(texts(await store.listMessages(caseId, org, 10))).toEqual(order);
    expect(texts(await store.listMessages(caseId, org, 3))).toEqual(order.slice(-3));
    expect(texts((await store.readMessagesAtCheckpoint(caseId, org, 3, checkpointDigest))!)).toEqual(order.slice(-3));
    expect(texts((await store.readInboxAtCheckpoint(caseId, checkpointDigest))!.messages)).toEqual(order);
    const page = await store.readMailboxPageAtCheckpoint(caseId, org, checkpointDigest, null);
    expect(texts(page!.messages)).toEqual(order);
    // Participants never see the sequence or the row id.
    for (const item of page!.messages) expect(Object.keys(item).sort()).toEqual(['caseId', 'ciphertext', 'createdAt', 'organizationId', 'sender']);
  });

  test('member count for the onboarding checklist counts only active, unexpired members of one firm key', async () => {
    const members = client.db('test_confidential').collection('confidential_legal_members');
    const organizationId = hex(0x7001), recipientKeyId = hex(0x7002);
    const row = (subject: string, overrides: Record<string, unknown> = {}) => ({ _id: `org_count/${subject}`, subject,
      providerOrganizationId: 'org_count', organizationId, recipientKeyId, revision: 1, active: true, updatedAt: new Date(now),
      enrollment: { challenge: { expiresAt: now + 86_400_000 } }, ...overrides });
    await members.insertMany([row('auth0|a'), row('auth0|b'), row('auth0|removed', { active: false }),
      row('auth0|expired', { enrollment: { challenge: { expiresAt: now - 1 } } }), row('auth0|old-key', { recipientKeyId: hex(0x7003) }),
      row('auth0|unenrolled', { enrollment: undefined })] as never[]);
    expect(await store.countMembers(organizationId, recipientKeyId, now)).toBe(2);
    expect(await store.countMembers(hex(0x7009), recipientKeyId, now)).toBe(0);
    expect(await store.countMembers({ $ne: null } as never, recipientKeyId, now)).toBe(0);
    // The organization-setup candidates are the same rows, as member rows the enclave re-verifies.
    const listed = await store.listMembers(organizationId, recipientKeyId, now);
    expect(listed.map(item => item.subject).sort()).toEqual(['auth0|a', 'auth0|b']);
    expect(Object.keys(listed[0]).sort()).toEqual(['active', 'enrollment', 'organizationId', 'providerOrganizationId', 'recipientKeyId', 'revision', 'subject']);
    expect(await store.listMembers({ $ne: null } as never, recipientKeyId, now)).toEqual([]);
  });

  test('organization setup statements are kept with a live organization row only', async () => {
    const organizations = client.db('test_confidential').collection('confidential_legal_organizations');
    const live = hex(0x7101), revoked = hex(0x7102), unapproved = hex(0x7103);
    await organizations.insertMany([{ _id: live, approved: true }, { _id: revoked, approved: true, revokedAt: new Date(now) },
      { _id: unapproved, approved: false }] as never[]);
    expect(await store.getOrganizationSetup(live)).toEqual({ custody: null, terms: null });
    expect(await store.putOrganizationSetup(live, 'terms', '{"statement":1}')).toBe(true);
    expect(await store.putOrganizationSetup(live, 'custody', '{"statement":2}')).toBe(true);
    expect(await store.putOrganizationSetup(live, 'terms', '{"statement":3}')).toBe(true);
    expect(await store.getOrganizationSetup(live)).toEqual({ custody: '{"statement":2}', terms: '{"statement":3}' });
    expect(await store.putOrganizationSetup(revoked, 'terms', 'x')).toBe(false);
    expect(await store.putOrganizationSetup(unapproved, 'terms', 'x')).toBe(false);
    expect(await store.putOrganizationSetup(live, 'owner' as never, 'x')).toBe(false);
    expect(await store.putOrganizationSetup(live, 'terms', 'x'.repeat(8193))).toBe(false);
    expect(await store.getOrganizationSetup(hex(0x7109))).toBeNull();
    expect(await store.getOrganizationSetup({ $ne: null } as never)).toBeNull();
  });

  test('device removal rolls back membership failure and concurrent retries retire both rows once', async () => {
    const org = hex(0xf11), memberId = hex(0xa11), subject = 'auth0|atomic-removal';
    const device = { organizationId: org, memberId, providerOrganizationId: 'org_atomic', subject,
      devicePublicKey: 'public', deviceFingerprint: 'a'.repeat(40), profile: 'sealed', state: 'approved' as const,
      envelope: 'wrapped-key', keyEpoch: 1, continuity: null, revision: 1, registeredAt: now, updatedAt: now };
    expect(await store.putFirmDevice(device, 0)).toBe(true);
    await store.upsertLegalMember({ subject, providerOrganizationId: 'org_atomic', organizationId: org,
      recipientKeyId: hex(0x1d), active: true }, now);
    const removed = { ...device, state: 'removed' as const, envelope: null, revision: 2, updatedAt: now + 1 };
    // Fail after the device write inside the real replica-set transaction.
    const write = jest.spyOn((store as any).members, 'updateOne').mockRejectedValueOnce(new Error('membership unavailable'));
    await expect(store.removeFirmDevice(removed, 1)).rejects.toThrow('membership unavailable');
    write.mockRestore();
    expect(await store.getFirmDevice(org, memberId)).toEqual(device);
    expect((await store.getMember(subject, 'org_atomic'))?.active).toBe(true);
    const results = await Promise.all([store.removeFirmDevice(removed, 1), store.removeFirmDevice(removed, 1)]);
    expect(results.sort()).toEqual([false, true]);
    expect(await store.getFirmDevice(org, memberId)).toEqual(removed);
    expect((await store.getMember(subject, 'org_atomic'))?.active).toBe(false);
    expect(await client.db('test_confidential').collection('confidential_legal_audit').countDocuments({
      organizationId: org, subject, action: 'member_removed' })).toBe(1);
  });

  test('old removals cannot hide live devices, and recent high-epoch removals remain visible', async () => {
    const org = hex(0xf555);
    const rows = Array.from({ length: 132 }, (_, i) => ({ _id: `${org}/${hex(i)}`, organizationId: org,
      memberId: hex(i), providerOrganizationId: 'org_history', subject: `auth0|history-${i}`,
      devicePublicKey: 'public', deviceFingerprint: 'a'.repeat(40), profile: 'sealed',
      state: i < 130 ? 'removed' : i === 130 ? 'pending' : 'approved', envelope: null,
      keyEpoch: i === 129 ? 50 : i < 130 ? 1 : null, continuity: null, revision: 1,
      registeredAt: now + i, updatedAt: now + i }));
    await client.db('test_confidential').collection('confidential_legal_devices').insertMany(rows);
    const listed = await store.listFirmDevices(org);
    expect(listed.length).toBeLessThanOrEqual(128);
    expect(listed.filter(row => row.state !== 'removed').map(row => row.memberId)).toEqual([hex(130), hex(131)]);
    expect(listed.find(row => row.memberId === hex(129))).toMatchObject({ state: 'removed', keyEpoch: 50 });
    expect(await store.getFirmDevice(org, hex(0))).toMatchObject({ state: 'removed' });
  });

  test('concurrent registrations cannot spend the same last live-device slot', async () => {
    const org = hex(0xf556), db = client.db('test_confidential');
    await db.collection('confidential_legal_organizations').insertOne({ _id: org as any, approved: true });
    const device = (i: number) => ({ organizationId: org, memberId: hex(i), providerOrganizationId: 'org_quota',
      subject: `auth0|quota-${i}`, devicePublicKey: 'public', deviceFingerprint: 'a'.repeat(40), profile: 'sealed',
      state: 'pending' as const, envelope: null, keyEpoch: null, continuity: null, revision: 1, registeredAt: now, updatedAt: now });
    await db.collection('confidential_legal_devices').insertMany(Array.from({ length: 63 }, (_, i) =>
      ({ _id: `${org}/${hex(i)}`, ...device(i) })));
    // Both enclave requests can observe 63 rows before either insert finishes.
    const outcomes = await Promise.all([store.putFirmDevice(device(63), 0), store.putFirmDevice(device(64), 0)]);
    expect(outcomes.sort()).toEqual([false, true]);
    expect(await db.collection('confidential_legal_devices').countDocuments({ organizationId: org, state: { $ne: 'removed' } })).toBe(64);
    // An existing live device can replace its key without consuming another slot.
    expect(await store.putFirmDevice({ ...device(0), revision: 2 }, 1)).toBe(true);
    await db.collection('confidential_legal_devices').updateOne({ _id: `${org}/${hex(1)}` as any }, { $set: { state: 'removed' } });
    expect(await store.putFirmDevice(device(65), 0)).toBe(true);
  });

  test('member devices and the shared request list use compare-and-set, and removal deactivates the member row', async () => {
    const org = hex(0xf1), memberId = hex(0xa1);
    await client.db('test_confidential').collection('confidential_legal_organizations').insertOne({ _id: org as any, approved: true });
    const device = { organizationId: org, memberId, providerOrganizationId: 'org_firm', subject: 'auth0|lawyer',
      devicePublicKey: 'public', deviceFingerprint: 'a'.repeat(40), profile: 'sealed', state: 'pending' as const,
      envelope: null, keyEpoch: null, continuity: null, revision: 1, registeredAt: now, updatedAt: now };
    expect(await store.putFirmDevice(device, 0)).toBe(true);
    expect(await store.putFirmDevice(device, 0)).toBe(false); // Already inserted.
    const approved = { ...device, state: 'approved' as const, envelope: 'env', keyEpoch: 1, revision: 2 };
    expect(await store.putFirmDevice({ ...approved, revision: 3 }, 1)).toBe(false); // Revision must advance by one.
    expect(await store.putFirmDevice(approved, 1)).toBe(true);
    expect(await store.putFirmDevice(approved, 1)).toBe(false); // Stale writer.
    expect(await store.getFirmDevice(org, memberId)).toEqual(approved);
    expect(await store.listFirmDevices(org)).toEqual([approved]);
    expect(await store.listFirmDevices(hex(0xf2))).toEqual([]);
    expect(await store.getFirmDevice(org, 'not-an-id')).toBeNull();

    await store.upsertLegalMember({ subject: 'auth0|lawyer', providerOrganizationId: 'org_firm', organizationId: org,
      recipientKeyId: hex(0x1d), active: true }, now);
    const before = await store.getMember('auth0|lawyer', 'org_firm');
    await store.deactivateFirmMember(hex(0xf2), 'org_firm', 'auth0|lawyer', now); // Other organization: no effect.
    expect((await store.getMember('auth0|lawyer', 'org_firm'))?.active).toBe(true);
    await store.deactivateFirmMember(org, 'org_firm', 'auth0|lawyer', now);
    const after = await store.getMember('auth0|lawyer', 'org_firm');
    expect(after).toMatchObject({ active: false, revision: before!.revision + 1 });
    expect((await client.db('test_confidential').collection('confidential_legal_members')
      .findOne({ subject: 'auth0|lawyer', providerOrganizationId: 'org_firm' }))?.removedAt).toEqual(new Date(now));

    expect(await store.getFirmSharedList(org)).toBeNull();
    expect(await store.putFirmSharedList(org, 0, { version: 1, record: 'one' })).toBe(true);
    expect(await store.putFirmSharedList(org, 0, { version: 1, record: 'again' })).toBe(false);
    expect(await store.putFirmSharedList(org, 1, { version: 3, record: 'skip' })).toBe(false);
    expect(await store.putFirmSharedList(org, 1, { version: 2, record: 'two' })).toBe(true);
    expect(await store.getFirmSharedList(org)).toEqual({ version: 2, record: 'two' });
  });
});
