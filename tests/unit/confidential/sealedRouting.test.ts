import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { generateCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import type { CaseRecord, CaseStore, StoredMessage, StoredAccessRequest } from '../../../enclave/src/cases/service';

/** Request times: realistic epoch milliseconds, not on a day boundary. */
const DAY = 86_400_000, T = Date.UTC(2026, 8, 28, 13, 37, 21, 123), EXPIRES = T + 20 * DAY + 4_321;
const caseId = '11'.repeat(32), organizationId = '22'.repeat(32), checkpoint = '33'.repeat(32);
function fixture() {
  let record: CaseRecord | null = null;
  const rows: StoredMessage[] = [];
  const requests: StoredAccessRequest[] = [];
  const inner = {
    async createCase(value: CaseRecord) { record = value; return true; },
    async getCase() { return record; },
    async commitTransition(_case: string, _expected: string, update: { checkpoint: string; stateEpoch: number }) {
      record = { ...record!, checkpoints: [...record!.checkpoints, update.checkpoint], stateEpoch: update.stateEpoch };
      return true;
    },
    async insertAccessRequestAtCheckpoint(row: StoredAccessRequest, guard: { caseLimit: number }) {
      const existing = requests.find(item => item.requestId === row.requestId && item.organizationId === row.organizationId);
      if (existing) return existing.state === 'pending' && existing.ciphertext === row.ciphertext ? 'stored' : 'conflict';
      if (requests.filter(item => item.caseId === row.caseId && item.state === 'pending').length >= guard.caseLimit) return 'rate-limited';
      requests.push(row); return 'stored';
    },
    async getAccessRequest(caseId: string, organizationId: string, requestId: string) {
      return requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId) ?? null;
    },
    async listAccessRequests() { return requests; },
    async withdrawAccessRequest(_case: string, org: string, id: string) {
      const row = requests.find(item => item.organizationId === org && item.requestId === id && item.state === 'pending');
      if (!row) return false; row.state = 'withdrawn'; return true;
    },
    async declineAccessRequest(_case: string, org: string, id: string) {
      const row = requests.find(item => item.organizationId === org && item.requestId === id && item.state === 'pending');
      if (!row) return 'not-found'; row.state = 'declined'; return 'declined';
    },
    async appendMessage(row: StoredMessage) { rows.push(row); return 'stored'; },
    async listMessages(_case: string, org: string | null) { return rows.filter(row => !org || row.organizationId === org); },
    async readMessagesAtCheckpoint(_case: string, org: string) { return rows.filter(row => row.organizationId === org); },
    async readInboxAtCheckpoint() { return { requests: [], messages: rows }; },
    async countMessages(filter: { organizationId: string }) { return rows.filter(row => row.organizationId === filter.organizationId).length; },
  } as unknown as CaseStore;
  const keyring = createCaseKeyring({ clock: () => 10 });
  const state = generateCaseStateKey();
  const store = createSealedCaseStore(inner, keyring);
  return { rows, requests, inner, store, keyring, state };
}
async function setup() {
  const f = fixture();
  await f.store.createCase({ caseId, checkpoints: ['synthetic checkpoint'], statements: {}, stateEnvelopes: [],
    initialStateKey: { stateEpoch: f.state.stateEpoch, key: new Uint8Array(f.state.key) } } as unknown as CaseRecord);
  return f;
}
const message: StoredMessage = { caseId, organizationId, sender: 'organization', ciphertext: 'opaque participant ciphertext', createdAt: 10 };

test('sealed message storage hides firm and sender, and all read paths restore authenticated routing', async () => {
  const { store, rows } = await setup();
  await store.appendMessage(message, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  expect(rows[0].organizationId).not.toBe(organizationId);
  expect(JSON.stringify(rows)).not.toContain(organizationId);
  expect(rows[0].sender).toBe('owner');
  expect(rows[0].ciphertext).not.toContain(message.ciphertext);
  expect(await store.listMessages(caseId, organizationId, 10)).toEqual([message]);
  expect(await store.readMessagesAtCheckpoint(caseId, organizationId, 10, checkpoint)).toEqual([message]);
  expect((await store.readInboxAtCheckpoint(caseId, checkpoint))?.messages).toEqual([message]);
  expect(await store.countMessages({ caseId, organizationId, since: 0 })).toBe(1);
  expect(await store.listMessages(caseId, '44'.repeat(32), 10)).toEqual([]);
});

test('opening receipts are stored in the same shape as any message and keep their type sealed', async () => {
  const { store, rows } = await setup();
  const receipt = { ...message, kind: 'report-open' as const };
  const guard = { checkpointDigest: checkpoint, since: 0, limit: 60 };
  await store.appendMessage(message, guard);
  await store.appendMessage(message, guard);
  await store.appendMessage(receipt, guard);
  await store.appendMessage({ ...receipt, createdAt: 11 }, guard);
  await store.appendMessage({ ...receipt, organizationId: '44'.repeat(32) }, guard);
  const [plain, again, first, repeat, other] = rows;
  for (const row of rows) {
    expect(Object.keys(row).sort()).toEqual(['caseId', 'ciphertext', 'createdAt', 'dedupeTag', 'organizationId', 'sender']);
    expect(row.sender).toBe('owner');
    expect(row.dedupeTag).toMatch(/^[a-f0-9]{64}$/);
  }
  expect(JSON.stringify(rows)).not.toContain('report-open');
  expect(JSON.stringify(rows)).not.toContain(organizationId);
  expect(first.ciphertext).not.toContain(message.ciphertext);
  // Random for ordinary messages; stable per case and firm for receipts, so
  // the host can keep the first one by equality alone.
  expect(new Set([plain.dedupeTag, again.dedupeTag, first.dedupeTag, other.dedupeTag]).size).toBe(4);
  expect(repeat.dedupeTag).toBe(first.dedupeTag);
  expect(first.dedupeTag).not.toBe(first.organizationId);
  expect((await store.readInboxAtCheckpoint(caseId, checkpoint))?.messages.slice(2, 4)).toEqual([receipt, { ...receipt, createdAt: 11 }]);
  // Another case's mailbox key gives the same firm an unrelated tag.
  const elsewhere = await setup();
  await elsewhere.store.appendMessage(receipt, guard);
  expect(elsewhere.rows[0].dedupeTag).not.toBe(first.dedupeTag);
  // Only the sealed kind counts: a readable one on a host row is ignored, and an unknown kind is never sealed.
  rows.splice(0, rows.length, { ...plain, kind: 'report-open' } as StoredMessage);
  expect((await store.listMessages(caseId, null, 10))[0]).not.toHaveProperty('kind');
  await expect(store.appendMessage({ ...message, kind: 'other' } as unknown as StoredMessage, guard)).rejects.toThrow();
});

test('host cannot substitute timestamp, thread, or unsealed message rows', async () => {
  const { store, rows } = await setup();
  await store.appendMessage(message, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  const saved = { ...rows[0] };
  rows[0].createdAt++;
  await expect(store.listMessages(caseId, null, 10)).rejects.toThrow();
  rows[0] = { ...saved, organizationId: '44'.repeat(32) };
  await expect(store.listMessages(caseId, null, 10)).rejects.toThrow();
  rows[0] = { ...message };
  await expect(store.listMessages(caseId, null, 10)).rejects.toThrow();
});

test('restart requires participant key and restored case key opens prior message routing', async () => {
  const { store, keyring, state } = await setup();
  await store.appendMessage(message, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  keyring.delete(caseId);
  await expect(store.listMessages(caseId, null, 10)).rejects.toThrow();
  expect(await store.unlockCase!(caseId, state)).toBe(true);
  expect(await store.listMessages(caseId, null, 10)).toEqual([message]);
});

const request: StoredAccessRequest = { caseId, organizationId, requestId: '55'.repeat(32), recipientKeyId: '66'.repeat(32),
  ciphertext: 'owner-encrypted signed request', createdAt: T, expiresAt: EXPIRES, state: 'pending' };
const guard = { checkpointDigest: checkpoint, now: T, since: 0, organizationLimit: 1, caseLimit: 50 };
test('locked requests hide all firm identity and original request ID; withdrawal binds to authenticated firm and secret ID', async () => {
  const { store, keyring, requests } = await setup();
  keyring.delete(caseId);
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('stored');
  for (const hidden of [request.organizationId, request.recipientKeyId, request.requestId]) {
    expect(JSON.stringify(requests)).not.toContain(hidden);
  }
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('stored');
  expect(await store.withdrawAccessRequest(caseId, '77'.repeat(32), request.requestId)).toBe(false);
  expect(await store.withdrawAccessRequest(caseId, organizationId, requests[0].requestId)).toBe(false);
  expect(await store.withdrawAccessRequest(caseId, organizationId, request.requestId)).toBe(true);
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('conflict');
});
test('in-memory firm quota survives case locking, resets on service restart; durable pending and tombstone bounds remain', async () => {
  const { store, inner, keyring } = await setup();
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('stored');
  const next = { ...request, requestId: '77'.repeat(32) };
  keyring.delete(caseId);
  expect(await store.insertAccessRequestAtCheckpoint(next, guard)).toBe('rate-limited');
  const restarted = createSealedCaseStore(inner, keyring);
  expect(await restarted.insertAccessRequestAtCheckpoint(next, { ...guard, caseLimit: 1 })).toBe('rate-limited');
  expect(await restarted.insertAccessRequestAtCheckpoint(next, guard)).toBe('stored');
  expect(await restarted.declineAccessRequest(caseId, organizationId, next.requestId, checkpoint)).toBe('declined');
  expect(await restarted.insertAccessRequestAtCheckpoint(next, guard)).toBe('conflict');
});
test('message routing after rotation needs newest key and historical routing remains readable', async () => {
  const { store, rows, keyring, state } = await setup();
  await store.appendMessage(message, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  const rotated = generateCaseStateKey(2);
  await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'second synthetic checkpoint',
    envelopes: [], objects: [], nextStateKey: rotated } as never);
  await store.appendMessage({ ...message, createdAt: 20 }, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  expect(JSON.parse(rows[0].ciphertext).stateEpoch).toBe(1);
  expect(JSON.parse(rows[1].ciphertext).stateEpoch).toBe(2);
  expect(await store.listMessages(caseId, null, 10)).toEqual([message, { ...message, createdAt: 20 }]);
  keyring.delete(caseId);
  expect(await store.unlockCase!(caseId, state)).toBe(false);
  expect(await store.unlockCase!(caseId, rotated)).toBe(true);
  expect(await store.listMessages(caseId, null, 10)).toHaveLength(2);
});

test('locked request lookup blinds routing and cannot inspect another firm or guessed secret', async () => {
  const { store, inner, keyring } = await setup();
  keyring.delete(caseId);
  await store.insertAccessRequestAtCheckpoint(request, guard);
  const lookup = jest.spyOn(inner, 'getAccessRequest');
  expect(await store.getAccessRequest!(caseId, organizationId, request.requestId)).toMatchObject({ state: 'pending', routing: 'blinded-v1' });
  for (const hidden of [organizationId, request.requestId]) expect(JSON.stringify(lookup.mock.calls)).not.toContain(hidden);
  expect(await store.getAccessRequest!(caseId, '77'.repeat(32), request.requestId)).toBeNull();
  expect(await store.getAccessRequest!(caseId, organizationId, '88'.repeat(32))).toBeNull();
});

test('request quota tags are stable per firm within a case, differ across firms and cases, and never reach participants', async () => {
  const { store, requests } = await setup();
  const guard = { checkpointDigest: checkpoint, now: T, since: 0, organizationLimit: 25, caseLimit: 50 };
  const request = (org: string, id: string) => ({ caseId, organizationId: org, requestId: id, recipientKeyId: '44'.repeat(32),
    ciphertext: 'opaque', state: 'pending' as const, createdAt: T, expiresAt: EXPIRES });
  await store.insertAccessRequestAtCheckpoint(request(organizationId, '55'.repeat(32)), guard);
  await store.insertAccessRequestAtCheckpoint(request(organizationId, '66'.repeat(32)), guard);
  await store.insertAccessRequestAtCheckpoint(request('77'.repeat(32), '88'.repeat(32)), guard);
  const [first, second, other] = requests;
  expect(first.quotaTag).toMatch(/^[a-f0-9]{64}$/);
  expect(second.quotaTag).toBe(first.quotaTag);
  expect(other.quotaTag).not.toBe(first.quotaTag);
  // Blinded organization tags still differ per request; the host sees no firm ID.
  expect(first.organizationId).not.toBe(second.organizationId);
  expect(JSON.stringify(requests)).not.toContain(organizationId);
  const delivered = await store.listAccessRequests(caseId);
  expect(delivered.every(row => !('quotaTag' in row))).toBe(true);
});

test('the same firm gets unrelated quota tags on different cases', async () => {
  const a = await setup(), b = fixture();
  const otherCase = '99'.repeat(32);
  await b.store.createCase({ caseId: otherCase, checkpoints: ['synthetic checkpoint'], statements: {}, stateEnvelopes: [],
    initialStateKey: { stateEpoch: b.state.stateEpoch, key: new Uint8Array(b.state.key) } } as unknown as CaseRecord);
  const guard = { checkpointDigest: checkpoint, now: T, since: 0, organizationLimit: 25, caseLimit: 50 };
  const row = { organizationId, requestId: '55'.repeat(32), recipientKeyId: '44'.repeat(32), ciphertext: 'opaque',
    state: 'pending' as const, createdAt: T, expiresAt: EXPIRES };
  await a.store.insertAccessRequestAtCheckpoint({ ...row, caseId }, guard);
  await b.store.insertAccessRequestAtCheckpoint({ ...row, caseId: otherCase }, guard);
  expect(a.requests[0].quotaTag).not.toBe(b.requests[0].quotaTag);
});

test('a request to a locked case is stored without a pseudonym and still counted in the enclave', async () => {
  const { store, keyring, requests } = await setup();
  keyring.delete(caseId);
  const guard = { checkpointDigest: checkpoint, now: T, since: 0, organizationLimit: 1, caseLimit: 50 };
  const row = { caseId, organizationId, requestId: '55'.repeat(32), recipientKeyId: '44'.repeat(32), ciphertext: 'opaque',
    state: 'pending' as const, createdAt: T, expiresAt: EXPIRES };
  expect(await store.insertAccessRequestAtCheckpoint(row, guard)).toBe('stored');
  expect(requests[0]).not.toHaveProperty('quotaTag');
  expect(await store.insertAccessRequestAtCheckpoint({ ...row, requestId: '66'.repeat(32) }, guard)).toBe('rate-limited');
});

test('repeated reads reuse the opened history and a commit opens only the new entry', async () => {
  const { store, inner, keyring } = await setup();
  for (const index of [1, 2, 3]) {
    await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: `synthetic checkpoint ${index}`,
      envelopes: [], objects: [] } as never);
  }
  const first = await store.getCase(caseId);
  expect(first!.checkpoints).toEqual(['synthetic checkpoint', 'synthetic checkpoint 1', 'synthetic checkpoint 2', 'synthetic checkpoint 3']);
  // Corrupt an earlier sealed entry but keep the tail. A store that re-opened
  // the whole history would fail; this one serves what it already authenticated.
  const stored = await inner.getCase(caseId);
  stored!.checkpoints[1] = stored!.checkpoints[1].replace(/.{8}$/, 'AAAAAAA=');
  expect((await store.getCase(caseId))!.checkpoints).toEqual(first!.checkpoints);
  // A new commit appends and opens only the new entry.
  await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'synthetic checkpoint 4', envelopes: [], objects: [] } as never);
  expect((await store.getCase(caseId))!.checkpoints.at(-1)).toBe('synthetic checkpoint 4');
  // A fresh enclave process has no cache: it opens everything and the
  // corrupted entry makes the case read as locked, as before.
  const restarted = createSealedCaseStore(inner, keyring);
  expect((await restarted.getCase(caseId))!.locked).toBe(true);
});

test('a key rotation reopens the history rather than trusting the cache', async () => {
  const { store } = await setup();
  await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'before rotation', envelopes: [], objects: [] } as never);
  await store.getCase(caseId);
  const rotated = generateCaseStateKey(2);
  await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'after rotation', envelopes: [], objects: [],
    nextStateKey: rotated } as never);
  expect((await store.getCase(caseId))!.checkpoints).toEqual(['synthetic checkpoint', 'before rotation', 'after rotation']);
});


test('concurrent readers append a new sealed entry exactly once per returned history', async () => {
  const { store } = await setup();
  await store.getCase(caseId);
  await store.commitTransition(caseId, checkpoint, { statements: {}, checkpoint: 'concurrent addition',
    envelopes: [], objects: [] } as never);
  const reads = await Promise.all(Array.from({ length: 8 }, () => store.getCase(caseId)));
  for (const record of reads) expect(record!.checkpoints).toEqual(['synthetic checkpoint', 'concurrent addition']);
  expect((await store.getCase(caseId))!.checkpoints).toEqual(['synthetic checkpoint', 'concurrent addition']);
});

test('blinded request rows keep only the UTC day of creation and expiry, never later than the signed expiry', async () => {
  const { store, requests } = await setup();
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('stored');
  expect(requests[0].createdAt).toBe(T - (T % DAY));
  expect(requests[0].expiresAt).toBe(EXPIRES - (EXPIRES % DAY));
  expect(requests[0].expiresAt).toBeLessThanOrEqual(request.expiresAt);
  expect(JSON.stringify(requests)).not.toContain(String(T));
  expect(JSON.stringify(requests)).not.toContain(String(EXPIRES));
  // An idempotent retry maps to the same row.
  expect(await store.insertAccessRequestAtCheckpoint(request, guard)).toBe('stored');
  expect(requests).toHaveLength(1);
  // A request whose day-rounded expiry is already past is refused, not stored dead.
  const late = { ...request, requestId: '99'.repeat(32), expiresAt: T + 60_000 };
  expect(await store.insertAccessRequestAtCheckpoint(late, { ...guard, organizationLimit: 5 })).toBe('conflict');
  expect(requests).toHaveLength(1);
});

test('message rows keep only the UTC hour; the exact time stays sealed and older exact rows still open', async () => {
  const HOUR = 3_600_000, sent = Date.UTC(2026, 8, 28, 13, 37, 21, 123);
  const { store, rows } = await setup();
  const exact = { ...message, createdAt: sent };
  await store.appendMessage(exact, { checkpointDigest: checkpoint, since: 0, limit: 60 });
  expect(rows[0].createdAt).toBe(sent - (sent % HOUR));
  expect(JSON.stringify(rows)).not.toContain(String(sent));
  expect(await store.listMessages(caseId, null, 10)).toEqual([exact]);
  // A row written before the hour cut stored the exact time; it still opens.
  rows[0] = { ...rows[0], createdAt: sent };
  expect(await store.readInboxAtCheckpoint(caseId, checkpoint)).toEqual({ requests: [], messages: [exact] });
  // Any other time is a substitution and fails closed, including a neighbouring hour.
  for (const other of [sent + 1, sent - (sent % HOUR) - HOUR, sent - (sent % HOUR) + HOUR]) {
    rows[0] = { ...rows[0], createdAt: other };
    await expect(store.listMessages(caseId, null, 10)).rejects.toThrow();
  }
});
