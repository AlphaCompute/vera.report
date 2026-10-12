import { requestRoutingTag, requestTimeBucket } from '../confidential/requestRouting.js';
import { storedMessageTime } from '../confidential/storedTime.js';
import {
  caseMailboxTag, decodeBase64, encodeBase64, openCaseDelta, padStateEnvelopes, sealCaseDelta, sealedDeltaHeader,
} from '../confidential/caseStateKey.js';
import type { CaseStateKey } from '../confidential/caseStateKey.js';
import type { CaseRecord, CaseStore, StoredAccessRequest, StoredEnvelope, StoredMessage, TransitionUpdate } from './service.js';

/** In-enclave memory only. Keys arrive from a participant unlock or publish and
 * are dropped on expiry or restart; nothing here is persisted or logged. */
export type CaseKeyring = {
  get(caseId: string): CaseStateKey | null;
  set(caseId: string, state: CaseStateKey): void;
  delete(caseId: string): void;
  /** Zero and drop every key (fatal shutdown). */
  clear(): void;
};
export function createCaseKeyring(options: { clock: () => number; ttlMs?: number; maxCases?: number }): CaseKeyring {
  const ttl = options.ttlMs ?? 24 * 60 * 60 * 1000, max = options.maxCases ?? 10_000;
  const keys = new Map<string, { state: CaseStateKey; expiresAt: number }>();
  const copy = (state: CaseStateKey) => ({ stateEpoch: state.stateEpoch, key: new Uint8Array(state.key) });
  return {
    get(caseId) {
      const entry = keys.get(caseId);
      if (!entry) return null;
      if (entry.expiresAt <= options.clock()) { entry.state.key.fill(0); keys.delete(caseId); return null; }
      return copy(entry.state);
    },
    set(caseId, state) {
      const previous = keys.get(caseId);
      previous?.state.key.fill(0);
      keys.delete(caseId);
      if (keys.size >= max) {
        const oldest = keys.keys().next().value as string;
        keys.get(oldest)?.state.key.fill(0);
        keys.delete(oldest);
      }
      keys.set(caseId, { state: copy(state), expiresAt: options.clock() + ttl });
    },
    delete(caseId) { keys.get(caseId)?.state.key.fill(0); keys.delete(caseId); },
    clear() { for (const entry of keys.values()) entry.state.key.fill(0); keys.clear(); },
  };
}

type Delta = { statements: Record<string, string>; checkpoint: string; previousKey?: string; mailboxKey?: string };
type Unsealed = { statements: Record<string, string>; checkpoints: string[]; mailboxKey: Uint8Array };

function invalid(): never { throw new Error('Confidential case state unavailable'); }
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
/** A message row's plaintext time is the UTC hour of the sealed exact time. Rows
 * written before the hour cut carry the exact time itself; both still bind the
 * row to its ciphertext. */
function storedTimeMatches(sealed: unknown, stored: unknown): boolean {
  if (!Number.isSafeInteger(sealed) || (sealed as number) < 0) return false;
  return stored === sealed || stored === storedMessageTime(sealed as number);
}
/** Public statements read from the untrusted store per case: the listing named by
 * the pointer plus at most this many release approvals (newest claimed revision
 * first). Matches the service's default `maxReleaseVerifications`, the most a
 * locked `releaseApprovals` call verifies. Unlocked reads use the sealed
 * history's statements and read no public ones beyond this bound. */
const PUBLIC_RELEASE_READ = 64;
/** Reads that need only checkpoints, state envelopes or the epoch. */
const NO_RELEASES = { releaseLimit: 0 } as const;
function statementKind(wire: string): string | null {
  try { const value = JSON.parse(wire); return typeof value?.statement?.kind === 'string' ? value.statement.kind : null; }
  catch { return null; }
}

/** Decorates an untrusted ciphertext store so private metadata never reaches it
 * in readable form. The inner store keeps: case ID, owner public key, current
 * checkpoint digest (opaque), listing digest, the owner-approved public listing and
 * signed backend-release approvals,
 * the encrypted recovery package, state epoch, unlabeled state-key envelopes,
 * sealed history deltas, object ciphertext and recipient envelopes keyed by an
 * HMAC tag it cannot compute. Message firm/sender routing is encrypted with per-case opaque thread tags.
 * Request routing uses commitments to participant-random IDs; actual routing is
 * inside owner-encrypted signed requests, including while the case is locked.
 *
 * Without a participant-supplied key the case reads as `locked`; the service
 * refuses private operations but can still serve the recovery package and the
 * public listing.
 */
export function createSealedCaseStore(inner: CaseStore, keyring: CaseKeyring): CaseStore {
  async function unseal(caseId: string, deltas: string[], latest: CaseStateKey): Promise<Unsealed> {
    const headers = deltas.map(sealedDeltaHeader);
    if (!headers.length || headers.some((header, index) => header.sequence !== index ||
        (index > 0 && header.stateEpoch < headers[index - 1].stateEpoch)) ||
        headers[headers.length - 1].stateEpoch !== latest.stateEpoch) invalid();
    // Walk the key chain backwards: the first delta of each epoch carries the previous key.
    const keys = new Map<number, CaseStateKey>([[latest.stateEpoch, latest]]);
    for (let epoch = latest.stateEpoch; epoch > headers[0].stateEpoch; epoch--) {
      const first = headers.findIndex(header => header.stateEpoch === epoch);
      if (first < 0) invalid();
      const bytes = await openCaseDelta(caseId, keys.get(epoch)!, first, deltas[first]);
      try {
        const delta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Delta;
        if (typeof delta.previousKey !== 'string') invalid();
        keys.set(epoch - 1, { stateEpoch: epoch - 1, key: decodeBase64(delta.previousKey, 32) });
      } finally { bytes.fill(0); }
    }
    const result: Unsealed = { statements: {}, checkpoints: [], mailboxKey: new Uint8Array(0) };
    for (const [index, wire] of deltas.entries()) {
      const key = keys.get(headers[index].stateEpoch);
      if (!key) invalid();
      const bytes = await openCaseDelta(caseId, key!, index, wire);
      try {
        const delta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Delta;
        if (!delta || typeof delta.checkpoint !== 'string' || !delta.statements || typeof delta.statements !== 'object') invalid();
        Object.assign(result.statements, delta.statements);
        result.checkpoints.push(delta.checkpoint);
        if (index === 0) {
          if (typeof delta.mailboxKey !== 'string') invalid();
          result.mailboxKey = decodeBase64(delta.mailboxKey, 32);
        }
      } finally { bytes.fill(0); }
    }
    for (const key of keys.values()) if (key !== latest) key.key.fill(0);
    return result;
  }
  /** A cached key that cannot open the stored history is useless to every caller:
   * evict it (only if it is still the cached one) so the case reads as `locked` and
   * a participant can re-unlock, instead of every read throwing until the TTL. */
  /** Opened history per case, so repeated reads of an unchanged case (one
   * evidence download is ~128 range reads) decrypt nothing, and a commit only
   * decrypts the new entries. Keyed by the exact state key (by digest) and the
   * last opened wire. A host that changes an earlier entry but keeps the tail
   * only gets the previously authenticated content back. Bounded and dropped on
   * any failure. The mailbox key is copied out per call because callers wipe it. */
  const opened = new Map<string, { epoch: number; keyDigest: string; length: number; last: string;
    statements: Record<string, string>; checkpoints: string[]; mailboxKey: Uint8Array }>();
  const OPENED_CASES = 256;
  async function keyDigest(key: CaseStateKey): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(key.key)));
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function forget(caseId: string) { opened.get(caseId)?.mailboxKey.fill(0); opened.delete(caseId); }
  function view(entry: { statements: Record<string, string>; checkpoints: string[]; mailboxKey: Uint8Array }): Unsealed {
    return { statements: { ...entry.statements }, checkpoints: [...entry.checkpoints], mailboxKey: new Uint8Array(entry.mailboxKey) };
  }
  async function unsealCached(caseId: string, deltas: string[], key: CaseStateKey): Promise<Unsealed> {
    const digest = await keyDigest(key), cached = opened.get(caseId);
    if (cached && cached.epoch === key.stateEpoch && cached.keyDigest === digest && deltas.length >= cached.length &&
        deltas[cached.length - 1] === cached.last) {
      const added = deltas.slice(cached.length);
      if (added.every(wire => sealedDeltaHeader(wire).stateEpoch === key.stateEpoch)) {
        // Concurrent readers must not append into the same mutable cache entry.
        // Snapshot before awaiting decryption and publish only the complete view.
        const next = { ...cached, ...view(cached) };
        for (const [offset, wire] of added.entries()) {
          const index = cached.length + offset;
          if (sealedDeltaHeader(wire).sequence !== index) invalid();
          const bytes = await openCaseDelta(caseId, key, index, wire);
          try {
            const delta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Delta;
            if (!delta || typeof delta.checkpoint !== 'string' || !delta.statements || typeof delta.statements !== 'object') invalid();
            Object.assign(next.statements, delta.statements);
            next.checkpoints.push(delta.checkpoint);
          } finally { bytes.fill(0); }
        }
        next.length = deltas.length; next.last = deltas[deltas.length - 1];
        forget(caseId); opened.set(caseId, next); // Most recently used last.
        return view(next);
      }
    }
    forget(caseId);
    const state = await unseal(caseId, deltas, key);
    if (opened.size >= OPENED_CASES) forget(opened.keys().next().value as string);
    opened.set(caseId, { epoch: key.stateEpoch, keyDigest: digest, length: deltas.length, last: deltas[deltas.length - 1],
      statements: { ...state.statements }, checkpoints: [...state.checkpoints], mailboxKey: new Uint8Array(state.mailboxKey) });
    return state;
  }
  async function unsealOrEvict(caseId: string, stored: CaseRecord, key: CaseStateKey): Promise<Unsealed | null> {
    try { return await unsealCached(caseId, stored.checkpoints, key); }
    catch {
      forget(caseId);
      const cached = keyring.get(caseId);
      if (cached && cached.stateEpoch === key.stateEpoch && cached.key.every((byte, index) => byte === key.key[index])) keyring.delete(caseId);
      cached?.key.fill(0); key.key.fill(0);
      return null;
    }
  }
  async function current(caseId: string): Promise<{ stored: CaseRecord; state: Unsealed; key: CaseStateKey } | null> {
    const stored = await inner.getCase(caseId, NO_RELEASES);
    if (!stored || stored.stateEpoch === undefined) return null;
    const key = keyring.get(caseId);
    if (!key || key.stateEpoch !== stored.stateEpoch) return null;
    const state = await unsealOrEvict(caseId, stored, key);
    return state ? { stored, state, key } : null;
  }
  async function tag(caseId: string, recipientKeyId: string): Promise<string> {
    const found = await current(caseId);
    if (!found) invalid();
    try { return await caseMailboxTag(found!.state.mailboxKey, caseId, recipientKeyId); }
    finally { found!.state.mailboxKey.fill(0); found!.key.key.fill(0); }
  }
  async function messageKey(caseId: string, targetEpoch?: number): Promise<CaseStateKey> {
    const found = await current(caseId);
    if (!found) invalid();
    let key = found!.key;
    try {
      const epoch = targetEpoch ?? key.stateEpoch;
      if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > key.stateEpoch) invalid();
      // Retain readable history across rotations, but never encrypt future routing
      // under the stable mailbox key an old/revoked participant could know.
      while (key.stateEpoch > epoch) {
        const index = found!.stored.checkpoints.findIndex(wire => sealedDeltaHeader(wire).stateEpoch === key.stateEpoch);
        if (index < 0) invalid();
        const bytes = await openCaseDelta(caseId, key, index, found!.stored.checkpoints[index]);
        try {
          const delta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Delta;
          const previous = decodeBase64(delta.previousKey, 32);
          if (previous.length !== 32) invalid();
          key.key.fill(0); key = { stateEpoch: key.stateEpoch - 1, key: previous };
        } finally { bytes.fill(0); }
      }
      const prefix = new TextEncoder().encode('vera-message-routing/v1');
      const material = new Uint8Array(prefix.length + 32);
      material.set(prefix); material.set(key.key, prefix.length);
      try { return { stateEpoch: epoch, key: new Uint8Array(await crypto.subtle.digest('SHA-256', material)) }; }
      finally { material.fill(0); }
    } finally { found!.state.mailboxKey.fill(0); key.key.fill(0); }
  }
  /** Every sealed row carries one. A report-open receipt gets a stable per-case
   * pseudonym of its firm (HMAC under the case's mailbox key, domain-separated
   * from thread and request-quota tags), so the host keeps only the first by
   * equality alone and cannot compute or link it across cases. Any other
   * message gets a random tag, so the field does not mark a receipt. */
  async function messageDedupeTag(message: StoredMessage): Promise<string> {
    if (message.kind === undefined) return hex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    if (message.kind !== 'report-open') invalid();
    const found = await current(message.caseId);
    if (!found) invalid();
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(['vera-report-open-dedupe/v1', message.organizationId]));
      const identity = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
      return await caseMailboxTag(found!.state.mailboxKey, message.caseId, identity);
    } finally { found!.state.mailboxKey.fill(0); found!.key.key.fill(0); }
  }
  async function sealMessage(message: StoredMessage): Promise<StoredMessage> {
    const { dedupeTag: _dedupe, ...plain } = message;
    const key = await messageKey(message.caseId);
    const bytes = new TextEncoder().encode(JSON.stringify({ format: 'vera-private-message-routing/v1', ...plain }));
    try {
      // Fixed host shape for every message: the receipt kind stays inside the ciphertext.
      return { caseId: message.caseId, organizationId: await tag(message.caseId, message.organizationId),
        // Constant placeholder: actual sender and firm identity are authenticated inside the ciphertext.
        sender: 'owner', ciphertext: await sealCaseDelta(message.caseId, key, 0, bytes),
        // Exact time sealed above; the host keeps only the UTC hour.
        createdAt: storedMessageTime(message.createdAt), dedupeTag: await messageDedupeTag(message) };
    } finally { key.key.fill(0); bytes.fill(0); }
  }
  async function openMessage(row: StoredMessage): Promise<StoredMessage> {
    const key = await messageKey(row.caseId, sealedDeltaHeader(row.ciphertext).stateEpoch);
    let bytes: Uint8Array | undefined;
    try {
      bytes = await openCaseDelta(row.caseId, key, 0, row.ciphertext);
      const message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (message.format !== 'vera-private-message-routing/v1' || message.caseId !== row.caseId ||
          !storedTimeMatches(message.createdAt, row.createdAt) || ![undefined, 'report-open'].includes(message.kind) ||
          typeof message.organizationId !== 'string' ||
          !/^[a-f0-9]{64}$/.test(message.organizationId) ||
          !['owner', 'organization'].includes(message.sender) || typeof message.ciphertext !== 'string' ||
          await tag(row.caseId, message.organizationId) !== row.organizationId) invalid();
      const { format: _format, ...result } = message;
      return result as StoredMessage;
    } finally { key.key.fill(0); bytes?.fill(0); }
  }
  /** Listings are public by design. Release approvals stay readable too, so an
   * owner device can confirm a backend release is one it approved (checked against
   * its own pinned checkpoint) BEFORE handing that release the state key. */
  function publicStatements(statements: Record<string, string>): Record<string, string> {
    return Object.fromEntries(Object.entries(statements).filter(([, wire]) =>
      ['listing', 'release'].includes(statementKind(wire) ?? '')));
  }

  // Enclave-local authenticated-firm abuse counters. They reset on enclave restart;
  // host persistence must not correlate a public firm identifier with case mailboxes.
  // A full cache rejects new firms rather than evicting live counters.
  const firmRequests = new Map<string, Map<string, number>>();
  function reserveRequest(request: StoredAccessRequest, since: number, limit: number): boolean {
    for (const [firm, requests] of firmRequests) {
      for (const [id, createdAt] of requests) if (createdAt < since) requests.delete(id);
      if (!requests.size) firmRequests.delete(firm);
    }
    let requests = firmRequests.get(request.organizationId);
    const id = `${request.caseId}:${request.requestId}`;
    if (requests?.has(id)) return true;
    if (requests && requests.size >= limit || !requests && firmRequests.size >= 10_000) return false;
    if (!requests) { requests = new Map(); firmRequests.set(request.organizationId, requests); }
    requests.set(id, request.createdAt);
    return true;
  }
  /** Routing commitments replace every identifier, and the times are cut to the
   * UTC day (the expiry rounded down, so it never outlives the signed one). */
  async function blindRequest(request: StoredAccessRequest): Promise<StoredAccessRequest> {
    return { ...request, createdAt: requestTimeBucket(request.createdAt), expiresAt: requestTimeBucket(request.expiresAt),
      requestId: await requestRoutingTag('request', request.requestId),
      organizationId: await requestRoutingTag('organization', request.requestId, request.organizationId),
      recipientKeyId: await requestRoutingTag('recipient', request.requestId, request.recipientKeyId) };
  }
  function deliveredRequest(request: StoredAccessRequest): StoredAccessRequest {
    const { quotaTag: _quota, ...rest } = request;
    return { ...rest, routing: 'blinded-v1' };
  }
  /** Stable per-case pseudonym for the requesting firm, used by the host only to
   * keep one pending request per firm per case, durably. Keyed by the case's
   * mailbox key (participants and enclave only), so the host cannot compute it
   * for a known firm or link it across cases; domain-separated from the message
   * thread tag, so it does not link a request to a later thread. While a case is
   * locked (after an enclave restart, before a participant unlocks it) the key is
   * not in memory: the request is stored without a pseudonym and only the
   * enclave-local counters above apply to it. */
  async function requestQuotaTag(caseId: string, organizationId: string): Promise<string | undefined> {
    const found = await current(caseId);
    if (!found) return undefined;
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(['vera-request-quota/v1', organizationId]));
      const identity = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
        byte => byte.toString(16).padStart(2, '0')).join('');
      return await caseMailboxTag(found.state.mailboxKey, caseId, identity);
    } finally { found.state.mailboxKey.fill(0); found.key.key.fill(0); }
  }
  const overrides: Partial<CaseStore> = {
    /** The genesis key comes with the record, never from the keyring, and is cached
     * only after the untrusted store confirms it inserted a NEW case. A duplicate
     * case ID leaves any cached key (or the locked state) untouched. */
    async createCase(record: CaseRecord): Promise<boolean> {
      const { initialStateKey: key, ...rest } = record;
      if (!key || key.key.length !== 32 || rest.checkpoints.length !== 1 || !Array.isArray(rest.stateEnvelopes)) invalid();
      const mailboxKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
      const delta = new TextEncoder().encode(JSON.stringify({ statements: rest.statements,
        checkpoint: rest.checkpoints[0], mailboxKey: encodeBase64(mailboxKey) } satisfies Delta));
      let created: boolean;
      try {
        // Padded once and stored, so repeated reads cannot separate real envelopes from decoys.
        const stateEnvelopes = await padStateEnvelopes(rest.stateEnvelopes!, rest.caseId, key!.stateEpoch);
        created = await inner.createCase({ ...rest, statements: publicStatements(rest.statements), stateEnvelopes,
          checkpoints: [await sealCaseDelta(rest.caseId, key!, 0, delta)], stateEpoch: key!.stateEpoch });
      } finally { delta.fill(0); mailboxKey.fill(0); }
      if (created) keyring.set(rest.caseId, key!);
      return created;
    },

    async getCase(caseId: string): Promise<CaseRecord | null> {
      const stored = await inner.getCase(caseId, { releaseLimit: PUBLIC_RELEASE_READ });
      if (!stored || stored.stateEpoch === undefined) return stored;
      const key = keyring.get(caseId);
      const state = key && key.stateEpoch === stored.stateEpoch ? await unsealOrEvict(caseId, stored, key) : null;
      if (!state) {
        // Locked view: public fields only.
        return { ...stored, statements: publicStatements(stored.statements), checkpoints: [], locked: true };
      }
      state.mailboxKey.fill(0);
      return { ...stored, statements: state.statements, checkpoints: state.checkpoints };
    },

    async commitTransition(caseId: string, expected: string, update: TransitionUpdate): Promise<boolean> {
      const found = await current(caseId);
      if (!found) invalid();
      const { stored, state, key } = found!;
      const rotation = update.nextStateKey;
      if (rotation && rotation.stateEpoch !== key.stateEpoch + 1) invalid();
      const sealing = rotation ?? key;
      const delta = new TextEncoder().encode(JSON.stringify({ statements: update.statements, checkpoint: update.checkpoint,
        ...(rotation ? { previousKey: encodeBase64(key.key) } : {}) } satisfies Delta));
      let sealed: string;
      try { sealed = await sealCaseDelta(caseId, sealing, stored.checkpoints.length, delta); } finally { delta.fill(0); }
      const envelopes: StoredEnvelope[] = await Promise.all(update.envelopes.map(async item => ({ ...item,
        recipientKeyId: await caseMailboxTag(state.mailboxKey, caseId, item.recipientKeyId) })));
      state.mailboxKey.fill(0);
      const stateEnvelopes = update.stateEnvelopes ? await padStateEnvelopes(update.stateEnvelopes, caseId, sealing.stateEpoch)
        : update.stateEnvelopes;
      const committed = await inner.commitTransition(caseId, expected, { ...update, envelopes, stateEnvelopes,
        statements: publicStatements(update.statements), checkpoint: sealed, nextStateKey: undefined,
        stateEpoch: sealing.stateEpoch });
      if (committed && rotation) keyring.set(caseId, rotation);
      return committed;
    },

    async putAccessRequest() { throw new Error('Use guarded private request insertion'); },
    async insertAccessRequestAtCheckpoint(request, guard) {
      const blinded = await blindRequest(request);
      // A request whose day-rounded expiry has already passed would never be
      // shown to the reporter; refuse it rather than store a dead row.
      if (blinded.expiresAt <= guard.now) return 'conflict';
      if (!reserveRequest(request, guard.since, guard.organizationLimit)) return 'rate-limited';
      const quotaTag = await requestQuotaTag(request.caseId, request.organizationId);
      return inner.insertAccessRequestAtCheckpoint({ ...blinded, ...(quotaTag ? { quotaTag } : {}) }, guard);
    },
    async getAccessRequest(caseId, organizationId, requestId) {
      if (!inner.getAccessRequest) invalid();
      const row = await inner.getAccessRequest!(caseId, await requestRoutingTag('organization', requestId, organizationId),
        await requestRoutingTag('request', requestId));
      return row ? deliveredRequest(row) : null;
    },
    async listAccessRequests(caseId) {
      return (await inner.listAccessRequests(caseId)).map(deliveredRequest);
    },
    async countAccessRequests(filter) {
      if (filter.organizationId) throw new Error('Firm request counts are enclave-local');
      return inner.countAccessRequests(filter);
    },
    async withdrawAccessRequest(caseId, organizationId, requestId) {
      return inner.withdrawAccessRequest(caseId, await requestRoutingTag('organization', requestId, organizationId),
        await requestRoutingTag('request', requestId));
    },
    async declineAccessRequest(caseId, organizationId, requestId, checkpointDigest) {
      return inner.declineAccessRequest(caseId, await requestRoutingTag('organization', requestId, organizationId),
        await requestRoutingTag('request', requestId), checkpointDigest);
    },
    async answerAccessRequest(caseId, organizationId, requestId, checkpointDigest) {
      if (!inner.answerAccessRequest) return 'not-found';
      return inner.answerAccessRequest(caseId, await requestRoutingTag('organization', requestId, organizationId),
        await requestRoutingTag('request', requestId), checkpointDigest);
    },
    async appendMessage(message, guard) {
      return inner.appendMessage(await sealMessage(message), guard);
    },
    async listMessages(caseId, organizationId, limit) {
      const rows = await inner.listMessages(caseId, organizationId ? await tag(caseId, organizationId) : null, limit);
      return Promise.all(rows.map(openMessage));
    },
    async readMessagesAtCheckpoint(caseId, organizationId, limit, checkpointDigest) {
      const rows = await inner.readMessagesAtCheckpoint(caseId, await tag(caseId, organizationId), limit, checkpointDigest);
      return rows === null ? null : Promise.all(rows.map(openMessage));
    },
    async countMessages(filter) {
      return inner.countMessages({ ...filter, organizationId: await tag(filter.caseId, filter.organizationId) });
    },
    async readMailboxPageAtCheckpoint(caseId, organizationId, checkpointDigest, cursor) {
      if (!inner.readMailboxPageAtCheckpoint) {
        if (cursor) invalid();
        // Test/embedded stores without paging support must fail rather than truncate.
        const inbox = organizationId === null ? await inner.readInboxAtCheckpoint(caseId, checkpointDigest)
          : { requests: [], messages: await inner.readMessagesAtCheckpoint(caseId, await tag(caseId, organizationId), 500, checkpointDigest) };
        if (!inbox || !inbox.messages) return null;
        return { requests: inbox.requests.map(deliveredRequest), messages: await Promise.all(inbox.messages.map(openMessage)), next: null };
      }
      const page = await inner.readMailboxPageAtCheckpoint(caseId, organizationId ? await tag(caseId, organizationId) : null,
        checkpointDigest, cursor);
      return page === null ? null : { ...page, requests: page.requests.map(deliveredRequest),
        messages: await Promise.all(page.messages.map(openMessage)) };
    },
    async readInboxAtCheckpoint(caseId, checkpointDigest) {
      const inbox = await inner.readInboxAtCheckpoint(caseId, checkpointDigest);
      return inbox === null ? null : { ...inbox, requests: inbox.requests.map(deliveredRequest), messages: await Promise.all(inbox.messages.map(openMessage)) };
    },

    async getEnvelopes(caseId: string, recipientKeyId: string) {
      return inner.getEnvelopes(caseId, await tag(caseId, recipientKeyId));
    },
    async readGrantedObjects(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
      refs: { objectId: string; ciphertextDigest: string }[], range?: { offset: number; length: number }) {
      // Owner reads (null) use the owner envelope stored with the object.
      return inner.readGrantedObjects(caseId, recipientKeyId === null ? null : await tag(caseId, recipientKeyId),
        checkpointDigest, refs, range);
    },
    async readObjectChunk(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
      ref: { objectId: string; ciphertextDigest: string }, chunkIndex: number) {
      if (!inner.readObjectChunk) return null;
      // The host never sees a firm's recipient key ID, only its opaque per-case tag.
      return inner.readObjectChunk(caseId, recipientKeyId === null ? null : await tag(caseId, recipientKeyId),
        checkpointDigest, ref, chunkIndex);
    },
    async listListedCases(limit: number, after: string | null) {
      return (await inner.listListedCases(limit, after)).map(record => record.stateEpoch === undefined ? record
        : { ...record, statements: publicStatements(record.statements), checkpoints: [], locked: true });
    },

    /** Verify a participant-supplied key by opening the full sealed history, then cache it. */
    async unlockCase(caseId: string, state: CaseStateKey): Promise<boolean> {
      const stored = await inner.getCase(caseId, NO_RELEASES);
      if (!stored || stored.stateEpoch !== state.stateEpoch) return false;
      try { (await unseal(caseId, stored.checkpoints, state)).mailboxKey.fill(0); } catch { return false; }
      keyring.set(caseId, state);
      return true;
    },
    async getStateEnvelopes(caseId: string): Promise<string[] | null> {
      const stored = await inner.getCase(caseId, NO_RELEASES);
      return stored?.stateEnvelopes ? [...stored.stateEnvelopes] : null;
    },
  };
  // Every other operation (requests, challenges, objects) passes through.
  return new Proxy(inner, {
    get(target, property, receiver) {
      if (Object.prototype.hasOwnProperty.call(overrides, property)) return overrides[property as keyof CaseStore];
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
