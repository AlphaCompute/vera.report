import { REQUEST_STATUS_BATCH_LIMIT } from '../confidential/requestStatusBatch.js';
import { issuedNotAfter } from '../confidential/clockSkew.js';
import { statePage } from './statePage.js';
import { RECOVERY_PACKAGE_FORMATS } from '../confidential/recoveryFormats.js';
import { requestRoutingTag } from '../confidential/requestRouting.js';
import { storedCaseTime } from '../confidential/storedTime.js';
import { readKey } from '../confidential/pgp.js';
import { requireEncryptedPayload } from '../confidential/encryptedPayload.js';
import type { PublicKey } from '../confidential/pgp.js';
import { createCaseReadAuthorizer, grantActiveAt, verifyOwnerStatement } from '../confidential/authorization.js';
import type { AccessGrant, CaseCheckpoint, CaseListing, CaseManifest, OwnerStatement, OwnerTrust } from '../confidential/authorization.js';
import { caseObjectDigest, caseRecipientKeyId } from '../confidential/caseObject.js';
import {
  MAX_CHUNKS_PER_OBJECT, MAX_CHUNKS_PER_UPLOAD, MAX_CHUNK_CIPHERTEXT_BYTES,
  chunkedIndexDigest, isChunkCiphertextLength, parseChunkedIndex,
} from '../confidential/caseChunks.js';
import type { CaseStateKey } from '../confidential/caseStateKey.js';
import { decodeBase64 } from '../confidential/caseStateKey.js';
import type { CaseKeyring } from './sealedStore.js';
import { verifyParticipantRequest } from '../confidential/participantRequest.js';
import type { ParticipantOperation, ParticipantRole } from '../confidential/participantRequest.js';
import { CASE_CHALLENGE_BATCH } from '../session-challenges.js';
import type { SessionChallenges } from '../session-challenges.js';

/** Confidential case service core: a ciphertext-and-signature relay.
 * It never receives participant private keys, content keys or plaintext beyond
 * the owner-approved public summary. Every state change is authorized by a
 * participant key signature over the exact request body and a single-use
 * challenge, and every case transition is an owner-signed, hash-chained
 * checkpoint committed by compare-and-set. There is no admin, role, internal
 * secret or legacy-reporter-code path to any operation here.
 *
 * Security relies on signatures, not on the store: a hostile store can withhold
 * or roll back data (availability/freshness), but cannot make a verifying client
 * accept a forged listing, grant, manifest, object or message.
 */

export type StoredObject = { objectId: string; ciphertextDigest: string; ciphertext: string; ownerEnvelope: string };
export type StoredEnvelope = { objectId: string; recipientKeyId: string; envelope: string };
export type CaseRecord = {
  caseId: string; ownerPublicKey: string; ownerFingerprint: string;
  /** Owner-signed statements keyed by canonical payload digest. */
  statements: Record<string, string>;
  /** Hash-chained checkpoint wires, oldest first. */
  checkpoints: string[];
  currentCheckpointDigest: string;
  /** Present only while the current checkpoint names a listing. */
  listingDigest: string | null;
  recoveryPackage: string;
  createdAt: number;  /** Sealed-storage fields (participant-held state key). Absent for unsealed test stores. */
  stateEpoch?: number;
  /** Unlabeled state-key envelopes for the owner and current grantees. */
  stateEnvelopes?: string[];
  /** Set by the sealing decorator when no participant key is in memory; never persisted. */
  locked?: boolean;
  /** Sealed storage, decorator-only (never persisted): the genesis state key. It
   * reaches the in-memory keyring only if this record is actually created. */
  initialStateKey?: CaseStateKey;
};
export type TransitionUpdate = {
  statements: Record<string, string>; checkpoint: string; checkpointDigest: string;
  listingDigest: string | null; objects: StoredObject[]; envelopes: StoredEnvelope[];
  recoveryPackage: string | null;  /** Sealed storage: replacement envelope set and epoch; decorator-only next key on rotation. */
  stateEnvelopes?: string[];
  stateEpoch?: number;
  nextStateKey?: CaseStateKey;
};
export type StoredAccessRequest = {
  caseId: string; organizationId: string; requestId: string; ciphertext: string;
  recipientKeyId: string; expiresAt: number;
  /** `approved`: answered by an owner grant whose grantId is this request ID. */
  state: 'pending' | 'withdrawn' | 'declined' | 'expired' | 'approved'; createdAt: number;
  /** Sealed-store delivery marker, never a host authorization assertion. */
  routing?: 'blinded-v1';
  /** Sealed stores: keyed per-case firm pseudonym for the host's one-pending-
   * request-per-firm-per-case rule. Never returned to participants. */
  quotaTag?: string;
};
export type MailboxCursor = { version: number; requestOffset: number; messageOffset: number; checkpointDigest: string };
export type MailboxPage = { requests: StoredAccessRequest[]; messages: StoredMessage[]; next: MailboxCursor | null };
export type StoredMessage = {
  caseId: string; organizationId: string; sender: ParticipantRole; ciphertext: string; createdAt: number;
  /** Fixed-purpose receipt; absent on conversation messages. Sealed inside the
   * routing ciphertext, never stored in readable form. */
  kind?: 'report-open';
  /** Opaque idempotency tag set by the sealed store; the host compares it for
   * equality only. Never part of the enclave's own message view. */
  dedupeTag?: string;
};
export interface CaseStore {
  /** Content-addressed, immutable. Unreferenced objects are harmless orphans. */
  putObjects(caseId: string, objects: StoredObject[]): Promise<void>;
  /** Chunked objects: make exactly these staged chunk ciphertexts (SHA-256 digests,
   * in index order) permanent. False when any is missing, expired or not the size
   * the index implies (full chunks, then `finalBytes` plus the tag). Idempotent. */
  promoteChunks?(caseId: string, objectDigest: string, chunks: string[], finalBytes: number): Promise<boolean>;
  /** Atomically, at the checked checkpoint: the exact object reference exists and
   * (for a recipient) this recipient holds an envelope for it; then chunk
   * `chunkIndex` of its stored index, base64. `recipientKeyId` null is the owner. */
  readObjectChunk?(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
    ref: { objectId: string; ciphertextDigest: string }, chunkIndex: number): Promise<{ chunk: string } | null>;
  /** Ciphertext uploaded by digest before publish/commit (expiring staging area).
   * Returns the exact stored text; the service re-hashes it. */
  getStagedObject?(ciphertextDigest: string): Promise<string | null>;
  /** Owner key envelopes for exact manifest references (no ciphertext). */
  getOwnerEnvelopes?(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]):
    Promise<{ objectId: string; ciphertextDigest: string; ownerEnvelope: string }[]>;
  /** Onboarded legal organizations (public roster data; each key is bound to its
   * organization by the onboarding authority's signed registration). */
  listLegalOrganizations?(): Promise<LegalOrganization[]>;
  /** Sealed stores only: verify a participant-supplied state key against the sealed history. */
  unlockCase?(caseId: string, state: CaseStateKey): Promise<boolean>;
  /** Sealed stores only: unlabeled state-key envelopes (readable while locked). */
  getStateEnvelopes?(caseId: string): Promise<string[] | null>;
  /** Exact (objectId, ciphertextDigest) references from a signed manifest. */
  getObjects(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]): Promise<StoredObject[]>;
  getEnvelopes(caseId: string, recipientKeyId: string): Promise<StoredEnvelope[]>;
  /** Atomically read exact authorized object references and this recipient's
   * envelopes at the checked checkpoint; null on stale state or missing data.
   * `recipientKeyId` null is the owner: the owner envelope is returned instead. */
  readGrantedObjects(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
    refs: { objectId: string; ciphertextDigest: string }[], range?: { offset: number; length: number }): Promise<{
      objectId: string; ciphertextDigest: string; ciphertext: string; recipientEnvelope: string; totalBytes?: number;
    }[] | null>;
  /** Insert only if absent. Returns false when a case with this ID already exists. */
  createCase(record: CaseRecord): Promise<boolean>;
  /** Without `view`, the whole record with every statement (a store that cannot
   * return all of them must fail, never return fewer). With `{ releaseLimit }`,
   * a store may bound `statements` to the listing named by `listingDigest` and the
   * newest `releaseLimit` release approvals by claimed revision (the sealed store
   * asks for this: its private statements live in sealed checkpoints, and the
   * public map grows with every listing edit and release approval). Stores may
   * ignore the view and return everything. */
  getCase(caseId: string, view?: { releaseLimit: number }): Promise<CaseRecord | null>;
  /** One transaction: compare currentCheckpointDigest, append checkpoint, merge
   * statements/envelopes, insert objects, update listing and optional recovery package. */
  commitTransition(caseId: string, expectedCheckpointDigest: string, update: TransitionUpdate): Promise<boolean>;
  listListedCases(limit: number, after: string | null): Promise<CaseRecord[]>;
  /** Insert only if there is no pending request for this (case, organization)
   * and this (case, organization, requestId) has never existed, even withdrawn. */
  putAccessRequest(request: StoredAccessRequest): Promise<boolean>;
  /** Atomic checkpoint/listing check, expiry, per-case and cross-case firm quotas,
   * then insertion. An identical pending request returns the same receipt without
   * consuming quota; changed or closed requests conflict. All live request
   * delivery must use this guarded operation. */
  insertAccessRequestAtCheckpoint(request: StoredAccessRequest, guard: {
    checkpointDigest: string; now: number; since: number; organizationLimit: number; caseLimit: number;
  }): Promise<'stored' | 'conflict' | 'rate-limited'>;
  listAccessRequests(caseId: string): Promise<StoredAccessRequest[]>;
  /** Bounded lookup of one organization's own request by its participant-random ID
   * (sealed stores match routing commitments). Request state is advisory host
   * state, never an access grant. Stores may omit it; a filtered
   * `listAccessRequests` is used instead. */
  getAccessRequest?(caseId: string, organizationId: string, requestId: string): Promise<StoredAccessRequest | null>;
  /** Retain request identity tombstones; never delete them to expire a request. */
  expireAccessRequests(caseId: string, now: number): Promise<void>;
  countAccessRequests(filter: { organizationId?: string; caseId?: string; since: number; state?: 'pending' }): Promise<number>;
  withdrawAccessRequest(caseId: string, organizationId: string, requestId: string): Promise<boolean>;
  /** Owner decision, serialized against case state changes. Repeated decline is
   * idempotent, but a withdrawn or unknown request must not be changed. */
  declineAccessRequest(caseId: string, organizationId: string, requestId: string, checkpointDigest: string):
    Promise<'declined' | 'not-found' | 'conflict'>;
  /** Close a pending request answered by an owner grant committed at
   * `checkpointDigest` (pending -> approved), so the organization can later send
   * a renewal request. Never reopens or changes a closed request. */
  answerAccessRequest?(caseId: string, organizationId: string, requestId: string, checkpointDigest: string):
    Promise<'approved' | 'not-found' | 'conflict'>;
  /** Atomically compare case checkpoint, reserve the rolling thread quota and
   * append. Serialize against checkpoint commits and concurrent message writes.
   * A row whose `dedupeTag` the case already holds is not appended again and
   * reports 'stored', so a report-open receipt is kept only once per firm.
   * This does not replace independently witnessed freshness or membership checks. */
  appendMessage(message: StoredMessage, guard: { checkpointDigest: string; since: number; limit: number }):
    Promise<'stored' | 'conflict' | 'rate-limited'>;
  listMessages(caseId: string, organizationId: string | null, limit: number): Promise<StoredMessage[]>;
  /** Bounded mailbox page, fenced against every concurrent mailbox mutation. */
  readMailboxPageAtCheckpoint?(caseId: string, organizationId: string | null, checkpointDigest: string,
    cursor: MailboxCursor | null): Promise<MailboxPage | null>;
  /** Owner delivery: one snapshot bound to the authorized checkpoint. */
  readInboxAtCheckpoint(caseId: string, checkpointDigest: string):
    Promise<{ requests: StoredAccessRequest[]; messages: StoredMessage[] } | null>;
  /** Legal delivery: atomically compare the authorized checkpoint and read only
   * this organization's thread, serialized against checkpoint commits. */
  readMessagesAtCheckpoint(caseId: string, organizationId: string, limit: number,
    checkpointDigest: string): Promise<StoredMessage[] | null>;
  countMessages(filter: { caseId: string; organizationId: string; since: number }): Promise<number>;
}

export type LegalOrganization = {
  organizationId: string; displayName: string; domain: string; publicKey: string; approved: boolean; bindingDocument?: string;
};
/** Verified organization member context resolved from the separate legal identity
 * boundary and enrollment store. `publicKey` is the independently bound firm key. */
export type OrganizationContext = { organizationId: string; recipientKeyId: string; publicKey: string };
export type DirectoryReader = { kind: 'admin' } | ({ kind: 'organization' } & OrganizationContext);

export type CaseServiceOptions = {
  store: CaseStore;
  /** Create a service for the actual decrypted channel dispatch context. Never
   * reuse across sessions or copy this binding from the request body.
   * `challenges` is that session's enclave-memory ledger: a proof is accepted only
   * with a challenge issued in the same session and not yet used. */
  channel: { nonce: string; serverKeyId: string; authenticated?: () => void; challenges: SessionChallenges; signal?: AbortSignal };
  /** Trusted time in UTC milliseconds. */
  clock: () => number;
  /** Participant-request audience; distinct per deployment. */
  audience: string;
  /** Measured digest of the running confidential release manifest. */
  releaseDigest: string;
  /** Sealed production mode: in-memory participant state keys; `store` must be
   * `createSealedCaseStore(inner, keyring)`. Publishing and grant-set changes then
   * carry state-key material from the owner device. */
  keyring?: CaseKeyring;
  limits?: Partial<typeof DEFAULT_LIMITS>;
};

const DEFAULT_LIMITS = {
  maxBody: 40 * 1024 * 1024, maxObjectsPerCommit: 64, maxStatementsPerCommit: 32,
  /** Sixteen maximum-size staged objects (12 MiB each at the staging route). */
  maxStagedBytesPerCommit: 16 * 12 * 1024 * 1024,
  /** Evidence bytes per submission/commit: 256 MiB of files in 512 KiB chunks,
   * plus chunk-count padding (caseChunks.ts). */
  maxChunksPerCommit: MAX_CHUNKS_PER_UPLOAD,
  challengeLifetime: 120_000, requestsPerOrganizationPerDay: 25, pendingRequestsPerCase: 50,
  /** Per sender (owner, firm) and per thread; the thread total is their sum. */
  messagesPerSenderPerHour: 60, messagesPerThreadPerHour: 120, listingPage: 50,
  /** Release statements whose signatures a public releaseApprovals call checks. */
  maxReleaseVerifications: 64,
  /** Cases whose newest served checkpoint this process remembers (rollback floor). */
  checkpointFloors: 100_000,
};
const DAY = 86_400_000;

export class CaseServiceError extends Error {
  constructor(readonly code: 'invalid' | 'unauthorized' | 'not-found' | 'conflict' | 'rate-limited' | 'release-not-approved' | 'locked') {
    super(`Confidential case request failed: ${code}`);
  }
}
function fail(code: CaseServiceError['code'] = 'invalid'): never { throw new CaseServiceError(code); }
/** Unverified pre-filter: the claimed revision of a release statement wire, or
 * null. Only used to choose which wires get signature verification. */
function claimedReleaseRevision(wire: unknown): number | null {
  if (typeof wire !== 'string' || wire.length > 65_536) return null;
  try {
    const statement = JSON.parse(wire)?.statement;
    return statement?.kind === 'release' && Number.isSafeInteger(statement.revision) ? statement.revision : null;
  } catch { return null; }
}
function hex64(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail();
  return value as string;
}
function text(value: unknown, max: number): string {
  if (typeof value !== 'string' || !value.length || value.length > max) fail();
  return value as string;
}
function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>, keys = Object.keys(record);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) fail();
  return record;
}
function array(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) fail();
  return value;
}
function recoveryPackage(value: unknown): string {
  const wire = text(value, 132 * 1024);
  let parsed: unknown;
  try { parsed = JSON.parse(wire); } catch { fail(); }
  const record = object(parsed, ['format', 'nonce', 'ciphertext']);
  // v1 packages belong to legacy long codes; v2 to the short secret-only codes.
  if (!RECOVERY_PACKAGE_FORMATS.includes(record.format as string) || typeof record.nonce !== 'string' || typeof record.ciphertext !== 'string') fail();
  return wire;
}
function parseBody(raw: Uint8Array, max: number): unknown {
  if (!(raw instanceof Uint8Array) || !raw.length || raw.length > max) fail();
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { return fail(); }
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

type Verified = { statement: OwnerStatement; digest: string; wire: string };
type UploadedRef = { objectId: string; ciphertextDigest: string };

type ProcessState = {
  floors: Map<string, { revision: number; digest: string }>;
  messageWrites: Set<string>;
  unlocks: Set<string>;
};
// Dispatchers construct services per request; share only within the same enclave
// keyring (or unsealed test store), never across restarts or independent enclaves.
const processStates = new WeakMap<object, ProcessState>();
function processState(identity: object): ProcessState {
  let state = processStates.get(identity);
  if (!state) { state = { floors: new Map(), messageWrites: new Set(), unlocks: new Set() }; processStates.set(identity, state); }
  return state;
}
type ChunkedUpload = { digest: string; chunks: string[]; finalBytes: number };

export function createCaseService(options: CaseServiceOptions) {
  const store = options.store, audience = options.audience, releaseDigest = hex64(options.releaseDigest);
  const keyring = options.keyring;
  const channel = { nonce: hex64(options.channel?.nonce), serverKeyId: hex64(options.channel?.serverKeyId) };
  const sessionChallenges = options.channel?.challenges;
  if (!sessionChallenges || typeof sessionChallenges.add !== 'function' || typeof sessionChallenges.consume !== 'function') {
    throw new Error('Confidential case service requires a session challenge ledger');
  }
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  if (typeof audience !== 'string' || !/^[a-z0-9][a-z0-9.:-]{0,127}$/.test(audience)) throw new Error('Invalid case service audience');
  function now(): number {
    const value = options.clock();
    if (!Number.isSafeInteger(value) || value <= 0) fail();
    return value;
  }
  async function trustFor(record: Pick<CaseRecord, 'caseId' | 'ownerPublicKey' | 'ownerFingerprint'>): Promise<OwnerTrust> {
    const key = await readKey({ armoredKey: record.ownerPublicKey });
    if (key.isPrivate() || key.getFingerprint() !== record.ownerFingerprint) fail();
    return { caseId: record.caseId, ownerFingerprint: record.ownerFingerprint, ownerPublicKey: key };
  }
  async function verified(wire: unknown, trust: OwnerTrust): Promise<Verified> {
    try {
      const value = text(wire, 65_536);
      return { ...await verifyOwnerStatement(value, trust), wire: value };
    } catch { return fail(); }
  }
  async function authenticate(raw: Uint8Array, auth: string, role: ParticipantRole, caseId: string,
    organizationId: string | null, operation: ParticipantOperation, key: PublicKey): Promise<void> {
    let challenge: string;
    try {
      const parsed = JSON.parse(auth);
      challenge = hex64(parsed?.request?.challenge);
      await verifyParticipantRequest(auth, { audience, role, caseId, organizationId, operation, body: raw,
        challenge, now: now(), ...channel }, key);
    } catch { return fail('unauthorized'); }
    // Consume only after the signature verifies so an attacker cannot burn challenges.
    // Single use is enforced in enclave memory by the session's ledger; the
    // untrusted host store never holds challenges (it could re-insert them).
    if (!sessionChallenges!.consume(challenge, now())) fail('unauthorized');
    // Lets the session layer keep this attested session for the participant's
    // next request; anonymous sessions stay on the short idle window.
    options.channel.authenticated?.();
  }
  /** Per-case checkpoint floor for this enclave's lifetime: the newest checkpoint
   * this process has served. The host cannot roll a case back to an older
   * checkpoint, or fork it at the same revision, between calls. Participant pins
   * cover restarts, which clear this map. Bounded; the oldest entries go first.
   * Active with a keyring (the sealed production store); an unsealed test store
   * is freely rewritten by its harness. */
  const shared = processState(keyring ?? store);
  const floors = shared.floors;
  function checkFloor(caseId: string, checkpoint: CaseCheckpoint, digest: string): void {
    if (!keyring) return;
    const floor = floors.get(caseId);
    if (floor && (checkpoint.revision < floor.revision || (checkpoint.revision === floor.revision && digest !== floor.digest))) {
      fail('conflict');
    }
    // Re-insert even at the same revision: a case that is still being read stays
    // most recently used, so a flood of newly created cases cannot evict its floor.
    floors.delete(caseId);
    floors.set(caseId, { revision: checkpoint.revision, digest });
    if (floors.size > limits.checkpointFloors) floors.delete(floors.keys().next().value!);
  }
  async function loadCase(caseId: string): Promise<{ record: CaseRecord; trust: OwnerTrust; current: CaseCheckpoint }> {
    const stored = await store.getCase(hex64(caseId));
    if (!stored) fail('not-found');
    const record = { ...stored! };
    if (record.caseId !== caseId) fail('not-found');
    // Sealed and no participant key in memory: the owner or a granted firm must unlock.
    if (record.locked) fail('locked');
    const trust = await trustFor(record);
    const tip = record.checkpoints[record.checkpoints.length - 1];
    const current = await verified(tip, trust);
    if (current.statement.kind !== 'checkpoint' || current.digest !== record.currentCheckpointDigest) fail('conflict');
    checkFloor(record.caseId, current.statement, current.digest);
    return { record, trust, current: current.statement };
  }
  /** Public fields only (owner key, listing pointer, current digest); works while locked. */
  async function loadPublic(caseId: string): Promise<{ record: CaseRecord; trust: OwnerTrust }> {
    const stored = await store.getCase(hex64(caseId));
    if (!stored || stored.caseId !== caseId) fail('not-found');
    const record = { ...stored! };
    return { record, trust: await trustFor(record) };
  }
  function stateKeyFrom(key: unknown, stateEpoch: unknown): CaseStateKey {
    if (typeof stateEpoch !== 'number' || !Number.isSafeInteger(stateEpoch) || stateEpoch <= 0) fail();
    try { return { stateEpoch: stateEpoch as number, key: decodeBase64(key, 32) }; } catch { return fail(); }
  }
  async function stateEnvelopesFrom(value: unknown): Promise<string[]> {
    const list = array(value, 128);
    if (!list.length) fail();
    return Promise.all(list.map(async item => {
      try { return await requireEncryptedPayload(item, 1, 16_384); } catch { return fail(); }
    }));
  }
  /** Participant freshness pin (owner decision 2026-09-27): the caller's newest
   * verified checkpoint must be in the stored chain, else the store is stale or
   * forked and the read is refused. Returns the chain after the pin so the client
   * can verify the hash links itself. `null` means the device has no pin yet. */
  async function chainSince(record: CaseRecord, trust: OwnerTrust, pin: string | null): Promise<string[]> {
    if (pin === null) return record.checkpoints;
    const digests = await Promise.all(record.checkpoints.map(async wire => (await verified(wire, trust)).digest));
    const index = digests.indexOf(pin);
    if (index < 0) fail('conflict');
    return record.checkpoints.slice(index + 1);
  }
  function mailboxCursor(value: unknown, checkpointDigest: string): MailboxCursor | null {
    if (value === null || value === undefined) return null;
    const cursor = object(value, ['version', 'requestOffset', 'messageOffset', 'checkpointDigest']);
    if (cursor.checkpointDigest !== checkpointDigest || [cursor.version, cursor.requestOffset, cursor.messageOffset]
      .some(item => typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0)) fail('conflict');
    return cursor as MailboxCursor;
  }
  /** Firm reads accept `{caseId}` or `{caseId, minimumCheckpoint}`. */
  function pinnedBody(raw: Uint8Array): { caseId: string; pin: string | null } {
    const value = parseBody(raw, 4096);
    const pinned = !!value && typeof value === 'object' && !Array.isArray(value) && 'minimumCheckpoint' in value;
    const body = object(value, pinned ? ['caseId', 'minimumCheckpoint'] : ['caseId']);
    return { caseId: hex64(body.caseId),
      pin: !pinned || body.minimumCheckpoint === null ? null : hex64(body.minimumCheckpoint) };
  }
  async function resolve(record: CaseRecord, trust: OwnerTrust, digest: string | null,
    extra: Map<string, Verified>): Promise<Verified | null> {
    if (digest === null) return null;
    const fresh = extra.get(digest);
    if (fresh) return fresh;
    const wire = record.statements[digest];
    if (!wire) fail();
    const result = await verified(wire, trust);
    if (result.digest !== digest) fail();
    return result;
  }
  /** Objects arrive inline, as a reference to ciphertext previously staged by
   * digest outside the size-bounded channel, or as a chunked-object index whose
   * chunks were staged separately. Staged bytes are re-validated and re-hashed
   * here; the owner-signed manifest decides whether they are used.
   *
   * Memory: every entry is shape-checked first, duplicate object IDs, staged
   * digests or chunked indexes are refused and the chunk budget is enforced
   * before any staged object is fetched. Staged objects are then fetched one at a
   * time, validated and written at once (content-addressed, so an object the
   * manifest later rejects is a harmless orphan), so the enclave holds at most one
   * staged ciphertext at a time. Only inline objects and chunked indexes, already
   * inside the bounded request body, are returned for the caller to write. Total
   * staged bytes per request are capped. Staged chunks stay unreferenced until
   * `promote` runs after the manifest check. */
  async function objectsFrom(caseId: string, value: unknown): Promise<{
    inline: StoredObject[]; uploaded: UploadedRef[]; chunked: ChunkedUpload[];
  }> {
    const entries = await Promise.all(array(value, limits.maxObjectsPerCommit).map(async item => {
      const kind = !!item && typeof item === 'object' && 'chunkedIndex' in item ? 'chunkedIndex'
        : !!item && typeof item === 'object' && 'stagedDigest' in item ? 'stagedDigest' : 'ciphertext';
      const entry = object(item, ['objectId', kind, 'ownerEnvelope']);
      let chunked: ChunkedUpload | null = null;
      if (kind === 'chunkedIndex') {
        // Index text holds only chunk digests, sizes and a sealed file header.
        let index: ReturnType<typeof parseChunkedIndex>;
        try { index = parseChunkedIndex(entry.chunkedIndex); } catch { return fail(); }
        chunked = { digest: await chunkedIndexDigest(entry.chunkedIndex as string), chunks: index.chunks, finalBytes: index.finalBytes };
      }
      return { objectId: hex64(entry.objectId), stagedDigest: kind === 'stagedDigest' ? hex64(entry.stagedDigest) : null,
        ciphertext: kind === 'ciphertext' ? entry.ciphertext : kind === 'chunkedIndex' ? entry.chunkedIndex : null,
        ownerEnvelope: entry.ownerEnvelope, chunked };
    }));
    const ids = new Set(entries.map(entry => entry.objectId));
    const stagedDigests = entries.flatMap(entry => entry.stagedDigest === null ? [] : [entry.stagedDigest]);
    const chunked = entries.flatMap(entry => entry.chunked === null ? [] : [entry.chunked]);
    if (ids.size !== entries.length || new Set(stagedDigests).size !== stagedDigests.length ||
        new Set(chunked.map(item => item.digest)).size !== chunked.length) fail();
    // Server-side upload limit: at most 256 MiB of evidence (plus one padded final
    // chunk per file and under 25% chunk-count padding) per commit, whatever the
    // client claims about plaintext size.
    if (chunked.reduce((sum, item) => sum + item.chunks.length, 0) > limits.maxChunksPerCommit ||
        chunked.some(item => item.chunks.length > MAX_CHUNKS_PER_OBJECT)) fail();
    if (stagedDigests.length && !store.getStagedObject) fail('not-found');
    if (chunked.length && !store.promoteChunks) fail('not-found');
    const inline: StoredObject[] = [], uploaded: UploadedRef[] = [];
    let stagedBytes = 0;
    for (const entry of entries) {
      let ciphertext: string, ownerEnvelope: string;
      if (entry.chunked !== null) {
        try { ownerEnvelope = await requireEncryptedPayload(entry.ownerEnvelope, 1, 16_384); } catch { return fail(); }
        const stored = { objectId: entry.objectId, ciphertext: entry.ciphertext as string, ownerEnvelope,
          ciphertextDigest: entry.chunked.digest };
        inline.push(stored);
        uploaded.push({ objectId: stored.objectId, ciphertextDigest: stored.ciphertextDigest });
        continue;
      }
      let raw = entry.ciphertext;
      if (entry.stagedDigest !== null) {
        const found = await store.getStagedObject!(entry.stagedDigest);
        if (found === null || typeof found !== 'string') fail('not-found');
        stagedBytes += found!.length;
        if (stagedBytes > limits.maxStagedBytesPerCommit) fail();
        if (await caseObjectDigest(found!) !== entry.stagedDigest) fail();
        raw = found;
      }
      try {
        ciphertext = await requireEncryptedPayload(raw, 0, 17 * 1024 * 1024);
        ownerEnvelope = await requireEncryptedPayload(entry.ownerEnvelope, 1, 16_384);
      } catch { return fail(); }
      const stored = { objectId: entry.objectId, ciphertext, ownerEnvelope, ciphertextDigest: await caseObjectDigest(ciphertext) };
      if (entry.stagedDigest !== null) await store.putObjects(caseId, [stored]); else inline.push(stored);
      uploaded.push({ objectId: stored.objectId, ciphertextDigest: stored.ciphertextDigest });
    }
    return { inline, uploaded, chunked };
  }
  /** Chunks become permanent only for objects the verified manifest lists. */
  async function promote(caseId: string, chunked: ChunkedUpload[]): Promise<void> {
    if (!chunked.length) return;
    if (!store.promoteChunks) fail('not-found');
    for (const item of chunked) {
      if (!await store.promoteChunks!(caseId, item.digest, [...item.chunks], item.finalBytes)) fail('not-found');
    }
  }
  /** Every manifest entry must resolve to an uploaded or already stored object with the signed digest. */
  async function checkManifest(caseId: string, manifest: CaseManifest | null, uploaded: UploadedRef[]): Promise<void> {
    const byId = new Map(uploaded.map(item => [item.objectId, item]));
    if (byId.size !== uploaded.length) fail();
    const listed = new Set(manifest?.objects.map(entry => entry.objectId) ?? []);
    if (uploaded.some(item => !listed.has(item.objectId))) fail();
    if (!manifest) return;
    const missing = manifest.objects.filter(entry => !byId.has(entry.objectId))
      .map(entry => ({ objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest }));
    const stored = missing.length ? await store.getObjects(caseId, missing) : [];
    const storedById = new Map(stored.map(item => [item.objectId, item]));
    for (const entry of manifest.objects) {
      const found = byId.get(entry.objectId) ?? storedById.get(entry.objectId);
      if (!found || found.ciphertextDigest !== entry.ciphertextDigest) fail();
    }
  }
  /** One stored chunk of an authorized chunked object, as bounded base64. The
   * participant checks it against the owner-signed index; this is transport only. */
  async function readChunk(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
    entry: { objectId: string; ciphertextDigest: string }, chunkIndex: number): Promise<string> {
    if (!store.readObjectChunk) fail('not-found');
    const found = await store.readObjectChunk!(caseId, recipientKeyId, checkpointDigest,
      { objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest }, chunkIndex);
    if (!found) fail('conflict');
    const chunk = found!.chunk;
    if (typeof chunk !== 'string' || chunk.length > 4 * Math.ceil(MAX_CHUNK_CIPHERTEXT_BYTES / 3) ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(chunk) || chunk.length % 4 !== 0) fail();
    const length = chunk.length / 4 * 3 - (chunk.endsWith('==') ? 2 : chunk.endsWith('=') ? 1 : 0);
    if (!isChunkCiphertextLength(length)) fail();
    return chunk;
  }
  async function currentGrants(record: CaseRecord, trust: OwnerTrust, checkpoint: CaseCheckpoint,
    extra = new Map<string, Verified>()): Promise<Verified[]> {
    return Promise.all(checkpoint.grantDigests.map(async digest => {
      const grant = await resolve(record, trust, digest, extra);
      if (!grant || grant.statement.kind !== 'grant') fail();
      return grant!;
    }));
  }

  /** This enclave's release is approved by an owner statement listed in the
   * current checkpoint (not merely somewhere in the history). */
  async function currentReleaseApproved(state: { record: CaseRecord; trust: OwnerTrust; current: CaseCheckpoint },
    time: number): Promise<boolean> {
    const releases = await Promise.all(state.current.releaseDigests.map(digest =>
      resolve(state.record, state.trust, digest, new Map())));
    return releases.some(item => item?.statement.kind === 'release' &&
      item.statement.releaseDigest === releaseDigest && item.statement.revision <= state.current.revision &&
      issuedNotAfter(item.statement.issuedAt, time));
  }

  async function authorizeMessages(caseId: string, org?: { organizationId: string; recipientKeyId: string }) {
    const state = await loadCase(caseId);
    const grants = await currentGrants(state.record, state.trust, state.current);
    const time = now();
    if (!issuedNotAfter(state.current.issuedAt, time)) fail('unauthorized');
    if (org && !grants.some(item => {
      const grant = item.statement as AccessGrant;
      return grant.organizationId === org.organizationId && grant.recipientKeyId === org.recipientKeyId &&
        grant.revision <= state.current.revision && grant.keyEpoch === state.current.keyEpoch && grant.scopes.includes('messages') &&
        grantActiveAt(grant, time);
    })) fail('unauthorized');
    if (!await currentReleaseApproved(state, time)) fail('release-not-approved');
    return state;
  }

  async function signedListings(reader: DirectoryReader, after: string | null) {
    if (!reader || (reader.kind !== 'admin' && reader.kind !== 'organization')) fail('unauthorized');
    const cursor = after === null ? null : hex64(after);
    const records = await store.listListedCases(limits.listingPage, cursor);
    const listings: ({ caseId: string; summary: string; publishedAt?: number; hasAttachments?: boolean; ownerPublicKey: string; listing: string })[] = [];
    for (const record of records) {
      try {
        const trust = await trustFor(record);
        let listing: Verified | null;
        if (record.locked) {
          // Sealed case without a cached key: the owner-signed listing named by the
          // public pointer is served. Its currency is the host's claim; the summary
          // is public by design, so this reveals nothing the host lacks.
          if (record.listingDigest === null) continue;
          listing = await resolve(record, trust, record.listingDigest, new Map());
          if (!listing || listing.statement.kind !== 'listing') continue;
        } else {
          const checkpoint = record.checkpoints[record.checkpoints.length - 1];
          const current = await verified(checkpoint, trust);
          if (current.statement.kind !== 'checkpoint' || current.statement.listingDigest === null ||
              current.digest !== record.currentCheckpointDigest || current.statement.listingDigest !== record.listingDigest ||
              !issuedNotAfter(current.statement.issuedAt, now())) continue;
          listing = await resolve(record, trust, current.statement.listingDigest, new Map());
          if (!listing || listing.statement.kind !== 'listing' || listing.statement.revision > current.statement.revision) continue;
          // A checkpoint exposes private grant/manifest/release commitments.
          // Verify it inside the enclave; never serialize it into the directory.
        }
        // Optional owner-published fields come only from the verified signed listing.
        const { summary, publishedAt, hasAttachments } = listing.statement as CaseListing;
        listings.push({ caseId: record.caseId, summary, ...(publishedAt !== undefined ? { publishedAt } : {}), ...(hasAttachments !== undefined ? { hasAttachments } : {}),
          ownerPublicKey: trust.ownerPublicKey.armor(), listing: listing.wire });
      } catch { /* Unverifiable rows are omitted, never repaired or partially serialized. */ }
    }
    return { listings, next: records.length === limits.listingPage ? records[records.length - 1].caseId : null };
  }

  async function issueChallenges(count: number): Promise<{ challenges: string[]; expiresAt: number }> {
    if (!Number.isSafeInteger(count) || count < 1 || count > CASE_CHALLENGE_BATCH) fail();
    const issuedAt = now(), expiresAt = issuedAt + limits.challengeLifetime;
    const challenges: string[] = [];
    for (let index = 0; index < count; index++) {
      const challenge = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      // The first challenge is about to be signed by the browser. Spare read
      // stock must not pin the session after that immediate proof is consumed.
      try { sessionChallenges!.add(challenge, expiresAt, issuedAt, index === 0); } catch { return fail('rate-limited'); }
      challenges.push(challenge);
    }
    return { challenges, expiresAt };
  }

  return {
    /** Public, unauthenticated: issues a random single-use challenge bound to this
     * session. Rate-limit at transport. */
    async issueChallenge(): Promise<{ challenge: string; expiresAt: number }> {
      const { challenges: [challenge], expiresAt } = await issueChallenges(1);
      return { challenge, expiresAt };
    },
    /** A small batch of single-use challenges for the next operations of this
     * session, so a participant signs each operation without an extra round trip.
     * Each one is still usable once, only in this session, and expires. */
    issueChallenges,

    /** Owner publishes a new case: genesis key, statements, encrypted objects and recovery package.
     * The initial checkpoint must approve THIS release and start the hash chain. */
    async publishCase(raw: Uint8Array, auth: string): Promise<{ caseId: string; checkpointDigest: string }> {
      const body = object(parseBody(raw, limits.maxBody),
        ['caseId', 'ownerPublicKey', 'statements', 'checkpoint', 'objects', 'recoveryPackage',
          ...(keyring ? ['stateKey', 'stateEpoch', 'stateEnvelopes'] : [])]);
      const caseId = hex64(body.caseId);
      const key = await readKey({ armoredKey: text(body.ownerPublicKey, 16_384) }).catch(() => fail());
      if (key.isPrivate()) fail();
      const genesis = { caseId, ownerPublicKey: key.armor(), ownerFingerprint: key.getFingerprint() };
      await authenticate(raw, auth, 'owner', caseId, null, 'publish-case', key);
      // Avoid orphan object writes for a known conflicting owner. The host is
      // untrusted and creation can race this read, so the atomic create and
      // post-conflict checks below remain authoritative.
      const existingOwner = await store.getCase(caseId);
      if (existingOwner && (existingOwner.caseId !== caseId || existingOwner.ownerFingerprint !== genesis.ownerFingerprint)) fail('conflict');
      const trust = await trustFor(genesis);
      const statements = await Promise.all(array(body.statements, limits.maxStatementsPerCommit).map(wire => verified(wire, trust)));
      const checkpoint = await verified(body.checkpoint, trust);
      const byDigest = new Map(statements.map(item => [item.digest, item]));
      if (byDigest.size !== statements.length || checkpoint.statement.kind !== 'checkpoint') fail();
      const cp = checkpoint.statement;
      if (cp.previousDigest !== null || cp.grantDigests.length || !cp.releaseDigests.length ||
          !issuedNotAfter(cp.issuedAt, now())) fail();
      const releases = cp.releaseDigests.map(digest => byDigest.get(digest));
      if (releases.some(item => !item || item.statement.kind !== 'release') ||
          !releases.some(item => item!.statement.kind === 'release' && item!.statement.releaseDigest === releaseDigest)) {
        fail('release-not-approved');
      }
      const listing = cp.listingDigest === null ? null : byDigest.get(cp.listingDigest);
      const manifest = cp.manifestDigest === null ? null : byDigest.get(cp.manifestDigest);
      if ((cp.listingDigest !== null && listing?.statement.kind !== 'listing') ||
          (cp.manifestDigest !== null && manifest?.statement.kind !== 'manifest')) fail();
      const referenced = new Set([cp.listingDigest, cp.manifestDigest, ...cp.releaseDigests].filter(Boolean));
      if (statements.some(item => !referenced.has(item.digest) || item.statement.revision > cp.revision)) fail();
      const { inline: objects, uploaded, chunked } = await objectsFrom(caseId, body.objects);
      await checkManifest(caseId, (manifest?.statement ?? null) as CaseManifest | null, uploaded);
      await promote(caseId, chunked);
      const record: CaseRecord = { ...genesis,
        statements: Object.fromEntries(statements.map(item => [item.digest, item.wire])),
        checkpoints: [checkpoint.wire], currentCheckpointDigest: checkpoint.digest,
        listingDigest: cp.listingDigest, recoveryPackage: recoveryPackage(body.recoveryPackage),
        // Stored in plaintext and never read back: the UTC day only (see storedTime.ts).
        createdAt: storedCaseTime(now()) };
      await store.putObjects(caseId, objects);
      if (keyring) {
        const state = stateKeyFrom(body.stateKey, body.stateEpoch);
        if (state.stateEpoch !== 1) { state.key.fill(0); fail(); }
        try { record.stateEnvelopes = await stateEnvelopesFrom(body.stateEnvelopes); } catch (error) { state.key.fill(0); throw error; }
        // The key travels with the record; the sealed store caches it only if THIS
        // publish creates the case. A duplicate (including a hostile publish of a
        // known case ID after an enclave restart) never touches the keyring.
        record.initialStateKey = state;
      }
      let created: boolean;
      try { created = await store.createCase(record); } finally { record.initialStateKey?.key.fill(0); delete record.initialStateKey; }
      if (!created) {
        // Idempotent retry of the exact same genesis and first checkpoint. A locked
        // case exposes no checkpoint wires, so compare the opaque current digest.
        const existing = await store.getCase(caseId);
        const same = !!existing && existing.ownerFingerprint === record.ownerFingerprint &&
          (existing.locked ? existing.currentCheckpointDigest === record.currentCheckpointDigest
            : existing.checkpoints[0] === record.checkpoints[0]);
        if (!same) fail('conflict');
      }
      return { caseId, checkpointDigest: checkpoint.digest };
    },

    /** Owner state transition: listing edit/withdrawal, new evidence, grant, revocation,
     * release approval/withdrawal. The new checkpoint must directly extend the current one. */
    async commitTransition(raw: Uint8Array, auth: string): Promise<{ checkpointDigest: string }> {
      const body = object(parseBody(raw, limits.maxBody),
        ['caseId', 'statements', 'checkpoint', 'objects', 'envelopes', 'recoveryPackage',
          ...(keyring ? ['stateEnvelopes', 'stateKeyRotation'] : [])]);
      const { record, trust, current } = await loadCase(hex64(body.caseId));
      await authenticate(raw, auth, 'owner', record.caseId, null, 'commit-transition', trust.ownerPublicKey);
      const statements = await Promise.all(array(body.statements, limits.maxStatementsPerCommit).map(wire => verified(wire, trust)));
      const extra = new Map(statements.map(item => [item.digest, item]));
      if (extra.size !== statements.length || statements.some(item => item.statement.kind === 'checkpoint')) fail();
      const next = await verified(body.checkpoint, trust);
      if (next.statement.kind !== 'checkpoint') fail();
      const cp = next.statement;
      if (cp.previousDigest !== record.currentCheckpointDigest || cp.revision <= current.revision ||
          cp.keyEpoch < current.keyEpoch) fail('conflict');
      // Successor sanity carried over from the retired separate transition check:
      // the object key epoch advances by at most one, and signed time never runs
      // backwards or ahead of trusted enclave time (beyond bounded device skew). A
      // checkpoint dated further ahead would silently hide the listing and grants
      // until that time, so it is refused here (and for the first one at publish).
      if (cp.keyEpoch > current.keyEpoch + 1 || cp.issuedAt < current.issuedAt ||
          !issuedNotAfter(cp.issuedAt, now())) fail();
      const referenced = new Set([cp.listingDigest, cp.manifestDigest, ...cp.grantDigests, ...cp.releaseDigests]);
      if (statements.some(item => !referenced.has(item.digest) || item.statement.revision > cp.revision)) fail();
      const listing = await resolve(record, trust, cp.listingDigest, extra);
      const manifest = await resolve(record, trust, cp.manifestDigest, extra);
      if ((listing && listing.statement.kind !== 'listing') || (manifest && manifest.statement.kind !== 'manifest')) fail();
      for (const digest of cp.releaseDigests) {
        const release = await resolve(record, trust, digest, extra);
        if (!release || release.statement.kind !== 'release') fail();
      }
      const grants = await currentGrants(record, trust, cp, extra);
      if (grants.some(grant => (grant.statement as AccessGrant).keyEpoch !== cp.keyEpoch)) fail();
      const { inline: objects, uploaded, chunked } = await objectsFrom(record.caseId, body.objects);
      await checkManifest(record.caseId, (manifest?.statement ?? null) as CaseManifest | null, uploaded);
      await promote(record.caseId, chunked);
      const manifestIds = new Set((manifest?.statement as CaseManifest | undefined)?.objects.map(entry => entry.objectId) ?? []);
      const recipients = new Set(grants.map(grant => (grant.statement as AccessGrant).recipientKeyId));
      const envelopes = await Promise.all(array(body.envelopes, limits.maxObjectsPerCommit * 8).map(async item => {
        const entry = object(item, ['objectId', 'recipientKeyId', 'envelope']);
        const value = { objectId: hex64(entry.objectId), recipientKeyId: hex64(entry.recipientKeyId),
          envelope: text(entry.envelope, 16_384) };
        // Envelopes are delivered only to currently granted recipients for listed objects.
        if (!manifestIds.has(value.objectId) || !recipients.has(value.recipientKeyId)) fail();
        try { await requireEncryptedPayload(value.envelope, 1, 16_384); } catch { return fail(); }
        return value;
      }));
      const update: TransitionUpdate = {
        statements: Object.fromEntries(statements.map(item => [item.digest, item.wire])),
        checkpoint: next.wire, checkpointDigest: next.digest, listingDigest: cp.listingDigest,
        objects, envelopes,
        recoveryPackage: body.recoveryPackage === null ? null : recoveryPackage(body.recoveryPackage),
      };
      if (keyring) {
        // Grant-set changes must redistribute the state key; removing any recipient
        // must rotate it so the removed firm's copy opens no later history.
        const before = new Set((await currentGrants(record, trust, current)).map(grant => (grant.statement as AccessGrant).recipientKeyId));
        const removed = [...before].some(recipient => !recipients.has(recipient));
        const added = [...recipients].some(recipient => !before.has(recipient));
        const rotation = body.stateKeyRotation;
        if (rotation !== null) {
          const value = object(rotation, ['stateKey', 'stateEpoch']);
          update.nextStateKey = stateKeyFrom(value.stateKey, value.stateEpoch);
        }
        if (body.stateEnvelopes !== null) update.stateEnvelopes = await stateEnvelopesFrom(body.stateEnvelopes);
        if ((removed && !update.nextStateKey) || ((removed || added || update.nextStateKey) && !update.stateEnvelopes)) fail();
      }
      if (!await store.commitTransition(record.caseId, record.currentCheckpointDigest, update)) fail('conflict');
      // Close the requests these new grants answer (grantId = request ID), so the
      // organization sees "approved" and may later ask to renew. Best effort: the
      // grant is already committed and a still-pending row only delays a renewal
      // request until it expires. Nothing about the outcome is logged.
      if (store.answerAccessRequest) {
        const previous = new Set(current.grantDigests);
        for (const grant of grants) {
          if (previous.has(grant.digest)) continue;
          const statement = grant.statement as AccessGrant;
          try { await store.answerAccessRequest(record.caseId, statement.organizationId, statement.grantId, next.digest); }
          catch { /* The owner's commit stands; see above. */ }
        }
      }
      return { checkpointDigest: next.digest };
    },

    /** Participant-held key unlock (owner decision 2026-09-27). The owner, or a firm
     * holding a current grant, supplies the state key it unwrapped locally. The key
     * is verified by opening the full sealed history and then kept in memory only. */
    async unlockCase(raw: Uint8Array, auth: string, organization: OrganizationContext | null) {
      if (!keyring || !store.unlockCase) fail('not-found');
      const body = object(parseBody(raw, 4096), ['caseId', 'stateKey', 'stateEpoch']);
      const { record, trust } = await loadPublic(hex64(body.caseId));
      const org = organization ? await organizationKey(organization) : null;
      await authenticate(raw, auth, org ? 'organization' : 'owner', record.caseId, org?.organizationId ?? null,
        'unlock-case', org ? org.key : trust.ownerPublicKey);
      const state = stateKeyFrom(body.stateKey, body.stateEpoch);
      if (shared.unlocks.has(record.caseId) || shared.unlocks.size >= 1024) { state.key.fill(0); fail('rate-limited'); }
      shared.unlocks.add(record.caseId);
      const cached = keyring!.get(record.caseId);
      try {
        if (!await store.unlockCase!(record.caseId, state)) fail('unauthorized');
        if (org) {
          // A firm may unlock only while it holds a current grant, and only a release
          // the owner lists as approved in the current checkpoint may keep its key.
          // (An owner unlock is not release-gated: approving a new release needs the
          // case unlocked on that release, and the owner holds the key anyway.)
          const loaded = await loadCase(record.caseId);
          const time = now();
          if (!await currentReleaseApproved(loaded, time)) {
            fail('release-not-approved');
          }
          const granted = (await currentGrants(loaded.record, loaded.trust, loaded.current)).some(grant => {
            const g = grant.statement as AccessGrant;
            return g.organizationId === org.organizationId && g.recipientKeyId === org.recipientKeyId &&
              grantActiveAt(g, time);
          });
          // No current grant: the same refusal as open-case and read-state-keys
          // (`not-found`, answered to the firm as `not-granted`). A key that does
          // not open the sealed state, or a bad proof, stays `unauthorized`.
          if (!granted) fail('not-found');
        }
      } catch (error) {
        // Any post-unlock failure (including rollback/signature/storage failure)
        // must remove a newly admitted key. Preserve an existing valid cache.
        const current = keyring!.get(record.caseId);
        try {
          // A concurrent transition may have installed a newer epoch. Never
          // evict or roll back that unrelated successful operation's key.
          if (current && current.stateEpoch === state.stateEpoch && current.key.length === state.key.length &&
              current.key.every((byte, index) => byte === state.key[index])) {
            if (cached) keyring!.set(record.caseId, cached);
            else keyring!.delete(record.caseId);
          }
        } finally { current?.key.fill(0); }
        throw error;
      } finally { state.key.fill(0); cached?.key.fill(0); shared.unlocks.delete(record.caseId); }
      return { unlocked: true as const };
    },

    /** Public: signed backend-release approvals (readable while locked). The owner
     * device accepts one only if its digest is in the device's pinned checkpoint.
     * Unauthenticated, so signature work is bounded: at most the current
     * checkpoint's digests when unlocked, else `maxReleaseVerifications`. */
    async releaseApprovals(caseId: string) {
      const { record, trust } = await loadPublic(hex64(caseId));
      const approval = async (wire: string): Promise<Verified | null> => {
        try { const item = await verified(wire, trust); return item.statement.kind === 'release' ? item : null; }
        catch { return null; }
      };
      // Unlocked: exactly the current checkpoint's approvals, in checkpoint order.
      if (!record.locked && record.checkpoints.length) {
        try {
          const tip = await verified(record.checkpoints[record.checkpoints.length - 1], trust);
          if (tip.statement.kind === 'checkpoint' && tip.digest === record.currentCheckpointDigest) {
            const releases: string[] = [];
            for (const digest of tip.statement.releaseDigests) {
              const wire = Object.hasOwn(record.statements, digest) ? record.statements[digest] : undefined;
              const item = typeof wire === 'string' ? await approval(wire) : null;
              if (item && item.digest === digest) releases.push(item.wire);
            }
            return { releases };
          }
        } catch { /* fall through to the order-independent selection */ }
      }
      // Locked (checkpoint sealed): the newest owner-signed approval of each backend
      // release, newest first. Order comes from signed revisions, never from the
      // host's storage order. Owner devices keep a small recent set in each
      // checkpoint (the newest approval per release), so it is always included.
      // Only release statements are verified, newest claimed revision first and
      // at most maxReleaseVerifications of them; a host that inflates forged
      // revisions can only withhold approvals, which it can do anyway.
      const candidates = Object.values(record.statements).flatMap(wire => {
        const revision = claimedReleaseRevision(wire);
        return revision === null ? [] : [{ wire, revision }];
      }).sort((a, b) => b.revision - a.revision || (a.wire < b.wire ? -1 : a.wire > b.wire ? 1 : 0))
        .slice(0, limits.maxReleaseVerifications);
      const approvals = new Map<string, Verified>();
      for (const candidate of candidates) {
        const item = await approval(candidate.wire);
        if (item) approvals.set(item.digest, item);
      }
      const newer = (a: Verified, b: Verified) => b.statement.revision - a.statement.revision ||
        (a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0);
      const newest = new Map<string, Verified>();
      for (const item of approvals.values()) {
        const release = (item.statement as { releaseDigest: string }).releaseDigest, seen = newest.get(release);
        if (!seen || newer(item, seen) < 0) newest.set(release, item);
      }
      const first = [...newest.values()].sort(newer), firstSet = new Set(first);
      // Older approvals fill any remaining room, for devices pinned at an older checkpoint.
      const rest = [...approvals.values()].filter(item => !firstSet.has(item)).sort(newer);
      return { releases: [...first, ...rest].slice(0, 32).map(item => item.wire) };
    },

    /** Owner-only, unlocked, NOT release-gated: current chain and statements, used
     * right after the owner explicitly approves a new backend release. */
    async readState(raw: Uint8Array, auth: string) {
      const value = parseBody(raw, 4096) as Record<string, unknown>;
      const body = object(value, value && 'stateCursor' in value ? ['caseId', 'afterCheckpoint', 'stateCursor'] : ['caseId', 'afterCheckpoint']);
      const { record, trust } = await loadCase(hex64(body.caseId));
      await authenticate(raw, auth, 'owner', record.caseId, null, 'read-state', trust.ownerPublicKey);
      const checkpoints = await chainSince(record, trust, body.afterCheckpoint === null ? null : hex64(body.afterCheckpoint));
      return statePage(record.currentCheckpointDigest, checkpoints, record.statements, body.stateCursor);
    },

    /** Owner-only: this case's owner key envelopes for the current manifest, so the
     * owner can wrap keys for a grant without downloading evidence ciphertext. */
    async readOwnerEnvelopes(raw: Uint8Array, auth: string) {
      if (!store.getOwnerEnvelopes) fail('not-found');
      const body = object(parseBody(raw, 4096), ['caseId']);
      const { record, trust, current } = await loadCase(hex64(body.caseId));
      await authenticate(raw, auth, 'owner', record.caseId, null, 'read-owner-envelopes', trust.ownerPublicKey);
      const manifest = await resolve(record, trust, current.manifestDigest, new Map());
      if (!manifest || manifest.statement.kind !== 'manifest') return { envelopes: [] };
      const refs = (manifest.statement as CaseManifest).objects.map(({ objectId, ciphertextDigest }) => ({ objectId, ciphertextDigest }));
      const envelopes = await store.getOwnerEnvelopes!(record.caseId, refs);
      if (envelopes.length !== refs.length || envelopes.some(item =>
        !refs.some(ref => ref.objectId === item.objectId && ref.ciphertextDigest === item.ciphertextDigest))) fail('conflict');
      return { envelopes: envelopes.map(({ objectId, ownerEnvelope }) => ({ objectId, ownerEnvelope })) };
    },

    /** Owner-only: read the owner's own stored objects to download evidence.
     * `offset/length` returns a slice (at most 128 KiB) of the stored object text,
     * a whole-buffer ciphertext or a chunked index, with the owner's key envelope;
     * `chunkIndex` returns one chunk of a chunked object. Bound to the caller's
     * current checkpoint and, like every private owner read, to the owner's
     * approval of this exact release. Returns ciphertext only. */
    async readObject(raw: Uint8Array, auth: string) {
      const value = parseBody(raw, 4096) as Record<string, unknown>;
      const chunkMode = !!value && typeof value === 'object' && !Array.isArray(value) && 'chunkIndex' in value;
      const body = object(value, chunkMode ? ['caseId', 'objectId', 'checkpointDigest', 'chunkIndex']
        : ['caseId', 'objectId', 'checkpointDigest', 'offset', 'length']);
      const { record, trust, current } = await loadCase(hex64(body.caseId));
      const objectId = hex64(body.objectId);
      await authenticate(raw, auth, 'owner', record.caseId, null, 'read-object', trust.ownerPublicKey);
      if (hex64(body.checkpointDigest) !== record.currentCheckpointDigest) fail('conflict');
      const approved = await authorizeMessages(record.caseId);
      if (approved.record.currentCheckpointDigest !== record.currentCheckpointDigest) fail('conflict');
      const manifest = await resolve(record, trust, current.manifestDigest, new Map());
      if (!manifest || manifest.statement.kind !== 'manifest') fail('not-found');
      const entry = (manifest!.statement as CaseManifest).objects.find(item => item.objectId === objectId);
      if (!entry) fail('not-found');
      const ref = { objectId: entry!.objectId, ciphertextDigest: entry!.ciphertextDigest };
      const confirm = async () => {
        const latest = await loadCase(record.caseId);
        if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
            latest.trust.ownerFingerprint !== trust.ownerFingerprint) fail('conflict');
      };
      if (chunkMode) {
        const chunkIndex = body.chunkIndex;
        if (typeof chunkIndex !== 'number' || !Number.isSafeInteger(chunkIndex) || chunkIndex < 0 ||
            chunkIndex >= MAX_CHUNKS_PER_OBJECT) fail();
        const chunk = await readChunk(record.caseId, null, record.currentCheckpointDigest, ref, chunkIndex as number);
        await confirm();
        return { objectId, ciphertextDigest: ref.ciphertextDigest, chunkIndex: chunkIndex as number, chunk };
      }
      const offset = body.offset, length = body.length;
      if (typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset < 0 || offset > 16 * 1024 * 1024 ||
          typeof length !== 'number' || !Number.isSafeInteger(length) || length < 1 || length > 128 * 1024) fail();
      const found = await store.readGrantedObjects(record.caseId, null, record.currentCheckpointDigest, [ref],
        { offset: offset as number, length: length as number });
      if (!found || found.length !== 1 || found[0].objectId !== ref.objectId || found[0].ciphertextDigest !== ref.ciphertextDigest) fail('conflict');
      const item = found![0];
      const totalBytes = item.totalBytes ?? Buffer.byteLength(item.ciphertext, 'utf8');
      if (!Number.isSafeInteger(totalBytes) || totalBytes < 1 || totalBytes > 16 * 1024 * 1024 || (offset as number) >= totalBytes) fail();
      const expected = Math.min(length as number, totalBytes - (offset as number));
      let bytes = Buffer.from(item.ciphertext, 'utf8');
      try {
        // Compatibility for bounded adapters without database-side slicing.
        if (item.totalBytes === undefined) bytes = bytes.subarray(offset as number, (offset as number) + expected);
        if (bytes.length !== expected || typeof item.recipientEnvelope !== 'string' || !item.recipientEnvelope.length ||
            item.recipientEnvelope.length > 16_384) fail();
        await confirm();
        return { objectId, ciphertextDigest: ref.ciphertextDigest, totalBytes, offset: offset as number,
          chunk: bytes.toString('base64'), ownerEnvelope: item.recipientEnvelope };
      } finally { bytes.fill(0); }
    },

    /** Owner-only: approved organizations. Public data; each row carries the
     * onboarding authority's signed registration, verified before it is served. */
    async legalRoster(raw: Uint8Array, auth: string) {
      if (!store.listLegalOrganizations) fail('not-found');
      const body = object(parseBody(raw, 4096), ['caseId']);
      const { record, trust } = await loadPublic(hex64(body.caseId));
      await authenticate(raw, auth, 'owner', record.caseId, null, 'read-legal-roster', trust.ownerPublicKey);
      const organizations = (await store.listLegalOrganizations!()).filter(item => item.approved === true).slice(0, 256);
      return { organizations: organizations.map(({ organizationId, displayName, domain, publicKey, bindingDocument }) =>
        ({ organizationId: hex64(organizationId), displayName: text(displayName, 200), domain: text(domain, 253), publicKey: text(publicKey, 65_536),
          ...(bindingDocument ? { bindingDocument: text(bindingDocument, 65_536) } : {}) })) };
    },

    /** Unlabeled state-key envelopes; the participant finds its own by trial decryption.
     *
     * The list is access metadata: its length and changes follow the grant set.
     * An organization therefore gets it only while it holds a current grant
     * (`not-found`, shown as `not-granted`, otherwise), checked whenever the case
     * is unlocked. A locked case's grants are sealed, so there the enclave cannot
     * tell grantees apart and serves the stored list, which the sealed store pads
     * with indistinguishable decoys to a fixed size; nothing changes while locked. */
    async getStateEnvelopes(raw: Uint8Array, auth: string, organization: OrganizationContext | null) {
      if (!store.getStateEnvelopes) fail('not-found');
      const body = object(parseBody(raw, 4096), ['caseId']);
      const { record, trust } = await loadPublic(hex64(body.caseId));
      const org = organization ? await organizationKey(organization) : null;
      await authenticate(raw, auth, org ? 'organization' : 'owner', record.caseId, org?.organizationId ?? null,
        'read-state-keys', org ? org.key : trust.ownerPublicKey);
      if (org && !record.locked) {
        let loaded: Awaited<ReturnType<typeof loadCase>> | null = null;
        // Locked between the two reads: fall through to the locked (padded) answer.
        try { loaded = await loadCase(record.caseId); }
        catch (error) { if (!(error instanceof CaseServiceError && error.code === 'locked')) throw error; }
        if (loaded) {
          const { current } = loaded;
          const time = now();
          if (!issuedNotAfter(current.issuedAt, time)) fail('unauthorized');
          const granted = (await currentGrants(loaded.record, loaded.trust, current)).some(grant => {
            const statement = grant.statement as AccessGrant;
            return statement.organizationId === org.organizationId && statement.recipientKeyId === org.recipientKeyId &&
              statement.revision <= current.revision && statement.keyEpoch === current.keyEpoch && grantActiveAt(statement, time);
          });
          if (!granted) fail('not-found');
        }
      }
      const envelopes = await store.getStateEnvelopes!(record.caseId);
      if (!envelopes) fail('not-found');
      return { stateEnvelopes: envelopes };
    },

    /** Account-free recovery: the package is AES-256-GCM under a 256-bit participant secret. */
    async getRecoveryPackage(caseId: string): Promise<{ recoveryPackage: string }> {
      const record = await store.getCase(hex64(caseId));
      if (!record) fail('not-found');
      return { recoveryPackage: record!.recoveryPackage };
    },

    /** Owner-only: current checkpoint chain, statements, encrypted requests and message threads. */
    async readInbox(raw: Uint8Array, auth: string) {
      const value = parseBody(raw, 4096) as Record<string, unknown>;
      const body = object(value, value && 'mailboxCursor' in value ? ['caseId', 'afterCheckpoint', 'mailboxCursor'] : ['caseId', 'afterCheckpoint']);
      const { record, trust } = await loadCase(hex64(body.caseId));
      await authenticate(raw, auth, 'owner', record.caseId, null, 'read-inbox', trust.ownerPublicKey);
      const approved = await authorizeMessages(record.caseId);
      if (approved.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
          approved.trust.ownerFingerprint !== trust.ownerFingerprint) fail('conflict');
      const checkpoints = await chainSince(record, trust, body.afterCheckpoint === null ? null : hex64(body.afterCheckpoint));
      await store.expireAccessRequests(record.caseId, now());
      const inbox = store.readMailboxPageAtCheckpoint ? await store.readMailboxPageAtCheckpoint(record.caseId, null,
        record.currentCheckpointDigest, mailboxCursor(body.mailboxCursor, record.currentCheckpointDigest))
        : await store.readInboxAtCheckpoint(record.caseId, record.currentCheckpointDigest);
      if (!inbox) fail('conflict');
      const latest = await authorizeMessages(record.caseId);
      if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
          latest.trust.ownerFingerprint !== trust.ownerFingerprint) fail('conflict');
      const time = now();
      const requests = inbox.requests.filter(item => item.state === 'pending' && item.expiresAt > time);
      return { ...statePage(record.currentCheckpointDigest, checkpoints, record.statements), requests: requests.map(item => ({
        caseId: record.caseId, organizationId: item.organizationId, requestId: item.requestId,
        recipientKeyId: item.recipientKeyId, expiresAt: item.expiresAt, status: 'pending' as const,
        ciphertext: item.ciphertext, ...(item.routing ? { routing: item.routing } : {}) })),
        messages: inbox.messages, next: 'next' in inbox ? inbox.next : null };
    },

    /** Directory for platform admins and onboarded organizations: the approved
     * summary and opaque reference only. */
    async listListings(reader: DirectoryReader, after: string | null) {
      const page = await signedListings(reader, after);
      return { listings: page.listings.map(({ caseId, summary, publishedAt, hasAttachments }) =>
        ({ caseId, summary, ...(publishedAt !== undefined ? { publishedAt } : {}), ...(hasAttachments !== undefined ? { hasAttachments } : {}) })), next: page.next };
    },

    /** Same projection plus the owner public key and owner-signed listing wire, so a
     * firm can verify the summary itself and encrypt a request to that key. Never
     * checkpoints, grants, manifests or relationships. */
    signedListings(reader: DirectoryReader, after: string | null) { return signedListings(reader, after); },

    /** Organization member submits an access request encrypted to the owner. */
    async submitAccessRequest(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const body = object(parseBody(raw, 32_768), ['caseId', 'requestId', 'ciphertext', 'expiresAt']);
      const org = await organizationKey(organization);
      // Works while the case is locked: firms can ask while the owner is offline.
      const { record } = await loadPublic(hex64(body.caseId));
      if (record.listingDigest === null) fail('not-found');
      await authenticate(raw, auth, 'organization', record.caseId, org.organizationId, 'request-access', org.key);
      const time = now();
      const expiresAt = body.expiresAt;
      if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= time || expiresAt - time > 30 * DAY) fail();
      let ciphertext: string;
      try { ciphertext = await requireEncryptedPayload(body.ciphertext, 1, 16_384); } catch { return fail(); }
      const writeTime = now();
      if (expiresAt <= writeTime) fail();
      const stored = await store.insertAccessRequestAtCheckpoint({ caseId: record.caseId, organizationId: org.organizationId,
        requestId: hex64(body.requestId), recipientKeyId: org.recipientKeyId, expiresAt,
        ciphertext, state: 'pending', createdAt: writeTime }, {
        checkpointDigest: record.currentCheckpointDigest, now: writeTime, since: writeTime - DAY,
        organizationLimit: limits.requestsPerOrganizationPerDay, caseLimit: limits.pendingRequestsPerCase,
      });
      if (stored !== 'stored') fail(stored === 'rate-limited' ? 'rate-limited' : 'conflict');
      return { state: 'requested' as const };
    },

    async withdrawAccessRequest(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const body = object(parseBody(raw, 4096), ['caseId', 'requestId']);
      const org = await organizationKey(organization);
      const caseId = hex64(body.caseId);
      await authenticate(raw, auth, 'organization', caseId, org.organizationId, 'withdraw-request', org.key);
      if (!await store.withdrawAccessRequest(caseId, org.organizationId, hex64(body.requestId))) fail('not-found');
      return { state: 'withdrawn' as const };
    },

    /** One organization-key proof binds the complete ordered list of reports.
     * Authenticate once before any case lookup; each result still applies the
     * same current grant, release and request-routing checks as requestStatus. */
    async requestStatusBatch(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const body = object(parseBody(raw, 64 * 1024), ['cases']);
      const targets = array(body.cases, REQUEST_STATUS_BATCH_LIMIT).map(value => {
        const target = object(value, ['caseId', 'requestId']);
        return { caseId: hex64(target.caseId), requestId: target.requestId === null ? null : hex64(target.requestId) };
      });
      if (!targets.length || new Set(targets.map(target => target.caseId)).size !== targets.length) fail();
      const org = await organizationKey(organization);
      await authenticate(raw, auth, 'organization', org.organizationId, org.organizationId, 'request-status-batch', org.key);
      const statuses = [];
      for (const target of targets) {
        options.channel.signal?.throwIfAborted();
        try {
          const { record } = await loadPublic(target.caseId);
          const status = await requestStatusFor(record, org, target.requestId === null ? [] : [target.requestId]);
          statuses.push({ caseId: target.caseId, status });
        } catch {
          // A missing or unverifiable case does not hide the rest of the board,
          // and never becomes an affirmative "no access" answer.
          statuses.push({ caseId: target.caseId, error: 'unavailable' as const });
        }
      }
      options.channel.signal?.throwIfAborted();
      return { statuses };
    },

    /** Organization-only outcome of its own requests (at most 16) and its own
     * current access to one case. Request rows are host-held and advisory: each
     * is matched through its routing commitments (request, organization and
     * recipient key) and never grants anything. Access comes only from sealed
     * owner grants in a fresh checkpoint, so it reads `unknown` while the case is
     * locked; the firm must open the case to verify access. Reveals only what the
     * organization would learn by trying to open the case, plus a generic
     * `declined` with no time or reason; never other organizations, owner
     * activity times or case content. Nothing is mutated. */
    async requestStatus(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const body = object(parseBody(raw, 4096), ['caseId', 'requestIds']);
      const requestIds = array(body.requestIds, 16).map(hex64);
      // An empty list checks current access only, including reporter-initiated
      // sharing where the organization never sent an access request.
      if (new Set(requestIds).size !== requestIds.length) fail();
      const org = await organizationKey(organization);
      const { record } = await loadPublic(hex64(body.caseId));
      await authenticate(raw, auth, 'organization', record.caseId, org.organizationId, 'request-status', org.key);
      return requestStatusFor(record, org, requestIds);
    },

    /** Explicit owner decision; does not change grants or disclose any case data. */
    async declineAccessRequest(raw: Uint8Array, auth: string) {
      const body = object(parseBody(raw, 4096), ['caseId', 'organizationId', 'requestId']);
      const { record, trust } = await loadCase(hex64(body.caseId));
      const organizationId = hex64(body.organizationId), requestId = hex64(body.requestId);
      await authenticate(raw, auth, 'owner', record.caseId, null, 'decline-request', trust.ownerPublicKey);
      const approved = await authorizeMessages(record.caseId);
      if (approved.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
          approved.trust.ownerFingerprint !== trust.ownerFingerprint) fail('conflict');
      await store.expireAccessRequests(record.caseId, now());
      const result = await store.declineAccessRequest(record.caseId, organizationId, requestId, record.currentCheckpointDigest);
      if (result !== 'declined') fail(result === 'not-found' ? 'not-found' : 'conflict');
      return { state: 'declined' as const };
    },

    /** Returns ciphertext and this recipient's envelopes only while a current, unexpired
     * owner grant exists AND the owner approved this exact backend release. The client
     * decrypts locally and re-runs authorizeCaseRead; this is defense in depth. */
    async openCase(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const request = parseBody(raw, 4096) as Record<string, unknown>;
      const mode = request?.mode;
      if (mode !== undefined && mode !== 'index' && mode !== 'range' && mode !== 'history' && mode !== 'chunk') fail();
      if (mode) object(request, mode === 'index' ? ['caseId', 'minimumCheckpoint', 'mode']
        : mode === 'history' ? ['caseId', 'minimumCheckpoint', 'mode', 'historyCursor']
        : mode === 'chunk' ? ['caseId', 'minimumCheckpoint', 'mode', 'objectId', 'chunkIndex', 'checkpointDigest']
        : ['caseId', 'minimumCheckpoint', 'mode', 'objectId', 'offset', 'length', 'checkpointDigest']);
      const body = mode ? { caseId: hex64(request.caseId), pin: request.minimumCheckpoint === null ? null : hex64(request.minimumCheckpoint) }
        : pinnedBody(raw);
      if (mode === 'range' && (typeof request.offset !== 'number' || !Number.isSafeInteger(request.offset) || request.offset < 0 ||
          typeof request.length !== 'number' || !Number.isSafeInteger(request.length) || request.length < 1 || request.length > 128 * 1024)) fail();
      if (mode === 'chunk' && (typeof request.chunkIndex !== 'number' || !Number.isSafeInteger(request.chunkIndex) ||
          request.chunkIndex < 0 || request.chunkIndex >= MAX_CHUNKS_PER_OBJECT)) fail();
      const selectedObject = mode === 'range' || mode === 'chunk' ? hex64(request.objectId) : null;
      const org = await organizationKey(organization);
      const { record, trust, current } = await loadCase(body.caseId);
      await authenticate(raw, auth, 'organization', record.caseId, org.organizationId, 'open-case', org.key);
      const checkpoints = await chainSince(record, trust, body.pin);
      if ((mode === 'range' || mode === 'chunk') && hex64(request.checkpointDigest) !== record.currentCheckpointDigest) fail('conflict');
      const time = now();
      if (!issuedNotAfter(current.issuedAt, time)) fail('unauthorized');
      const grants = (await currentGrants(record, trust, current)).filter(grant => {
        const statement = grant.statement as AccessGrant;
        return statement.organizationId === org.organizationId && statement.recipientKeyId === org.recipientKeyId &&
          statement.revision <= current.revision && statement.keyEpoch === current.keyEpoch && grantActiveAt(statement, time);
      });
      if (!grants.length) fail('not-found');
      const releases = await Promise.all(current.releaseDigests.map(digest => resolve(record, trust, digest, new Map())));
      const release = releases.find(item => item?.statement.kind === 'release' && item.statement.releaseDigest === releaseDigest &&
        item.statement.revision <= current.revision && issuedNotAfter(item.statement.issuedAt, time));
      if (!release) fail('release-not-approved');
      if (mode === 'history') {
        const page = statePage(record.currentCheckpointDigest, checkpoints, {}, request.historyCursor);
        const latest = await loadCase(record.caseId);
        if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
            grants.some(grant => !grantActiveAt(grant.statement as AccessGrant, now()))) fail('conflict');
        return { checkpoints: page.checkpoints, historyNext: page.stateNext, checkpointDigest: record.currentCheckpointDigest };
      }
      const manifest = await resolve(record, trust, current.manifestDigest, new Map());
      if (!manifest || manifest.statement.kind !== 'manifest') fail('not-found');
      const checkpointWire = record.checkpoints[record.checkpoints.length - 1];
      const authorized: { objectId: string; ciphertextDigest: string; grantDigest: string }[] = [];
      const authorizeRead = createCaseReadAuthorizer(trust);
      for (const entry of (manifest!.statement as CaseManifest).objects) {
        if (selectedObject && entry.objectId !== selectedObject) continue;
        for (const grant of grants) {
          try {
            await authorizeRead({ grant: grant.wire, release: release!.wire, manifest: manifest!.wire,
              checkpoint: checkpointWire, checkpointDigest: record.currentCheckpointDigest,
              request: { organizationId: org.organizationId, recipientKeyId: org.recipientKeyId,
                objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest, scope: entry.scope,
                releaseDigest, keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, now: time } });
            authorized.push({ objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest, grantDigest: grant.digest });
            break;
          } catch { /* Try the next current grant; unauthorized objects are omitted. */ }
        }
      }
      if (selectedObject && authorized.length !== 1) fail('not-found');
      if (mode === 'chunk') {
        const entry = (manifest!.statement as CaseManifest).objects.find(item => item.objectId === selectedObject)!;
        const chunk = await readChunk(record.caseId, org.recipientKeyId, record.currentCheckpointDigest, entry, request.chunkIndex as number);
        const latest = await loadCase(record.caseId);
        if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest || latest.trust.ownerFingerprint !== trust.ownerFingerprint ||
            !grantActiveAt(grants.find(grant => grant.digest === authorized[0].grantDigest)!.statement as AccessGrant, now())) fail('conflict');
        return { caseId: record.caseId, objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest, scope: entry.scope,
          keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, chunkIndex: request.chunkIndex as number, chunk };
      }
      const objects: { objectId: string; ciphertextDigest: string; ciphertext: string; recipientEnvelope: string; totalBytes?: number }[] = [];
      // Read one bounded object at a time. Index replies never aggregate file
      // payloads; range replies never exceed the channel's ciphertext bound.
      for (const ref of authorized) {
        const found = await store.readGrantedObjects(record.caseId, org.recipientKeyId, record.currentCheckpointDigest,
          [{ objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest }], mode ? { offset: mode === 'range' ? request.offset as number : 0, length: mode === 'range' ? request.length as number : 0 } : undefined);
        if (!found || found.length !== 1 || found[0].objectId !== ref.objectId || found[0].ciphertextDigest !== ref.ciphertextDigest) fail('conflict');
        const item = found![0], totalBytes = item.totalBytes ?? Buffer.byteLength(item.ciphertext, 'utf8');
        if (!Number.isSafeInteger(totalBytes) || totalBytes < 1 || totalBytes > 16 * 1024 * 1024) fail();
        if (!mode && objects.reduce((sum, item) => sum + (item.totalBytes ?? 0), totalBytes) > 40 * 1024 * 1024) fail();
        let ciphertext = item.ciphertext;
        if (mode === 'range' && item.totalBytes === undefined) {
          // Compatibility for bounded adapters without database-side slicing.
          const bytes = Buffer.from(ciphertext, 'utf8');
          try { ciphertext = bytes.subarray(request.offset as number,
            (request.offset as number) + (request.length as number)).toString('utf8'); }
          finally { bytes.fill(0); }
        }
        objects.push({ ...item, ciphertext: mode === 'index' ? '' : ciphertext,
          recipientEnvelope: mode === 'index' ? '' : item.recipientEnvelope, totalBytes });
      }
      const latest = await loadCase(record.caseId);
      if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest || latest.trust.ownerFingerprint !== trust.ownerFingerprint ||
          authorized.some(entry => !grantActiveAt(grants.find(grant => grant.digest === entry.grantDigest)!.statement as AccessGrant, now()))) fail('conflict');
      if (mode === 'range') {
        const item = objects[0], offset = request.offset as number, length = request.length as number;
        const entry = (manifest!.statement as CaseManifest).objects.find(item => item.objectId === selectedObject)!;
        const bytes = Buffer.from(item.ciphertext, 'utf8');
        try {
          if (offset >= item.totalBytes! || length > item.totalBytes! - offset || bytes.length !== length) fail();
          return { caseId: record.caseId, objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest,
            scope: entry.scope, keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision,
            totalBytes: item.totalBytes!, offset, chunk: bytes.toString('base64'),
            recipientEnvelope: item.recipientEnvelope };
        } finally { bytes.fill(0); }
      }
      return {
        caseId: record.caseId, ownerPublicKey: record.ownerPublicKey, checkpoint: checkpointWire,
        checkpointDigest: record.currentCheckpointDigest,
        checkpoints: mode === 'index' ? statePage(record.currentCheckpointDigest, checkpoints, {}).checkpoints : checkpoints,
        ...(mode === 'index' ? { historyNext: statePage(record.currentCheckpointDigest, checkpoints, {}).stateNext } : {}),
        manifest: manifest!.wire, release: release!.wire,
        grants: grants.map(grant => grant.wire),
        objects: objects.map(item => ({ objectId: item.objectId,
          ...(mode === 'index' ? { totalBytes: item.totalBytes } : { ciphertext: item.ciphertext, recipientEnvelope: item.recipientEnvelope }),
          grantDigest: authorized.find(entry => entry.objectId === item.objectId)!.grantDigest })),
      };
    },

    /** A browser acknowledges a successfully decrypted narrative. A current
     * narrative grant, approved release and member signature are all required.
     * The sealed mailbox keeps only the first receipt per case and organization. */
    async acknowledgeReportOpen(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const body = object(parseBody(raw, 20 * 1024), ['caseId', 'checkpointDigest', 'ciphertext']);
      const org = await organizationKey(organization);
      const state = await loadCase(hex64(body.caseId));
      await authenticate(raw, auth, 'organization', state.record.caseId, org.organizationId, 'acknowledge-report-open', org.key);
      if (hex64(body.checkpointDigest) !== state.record.currentCheckpointDigest) fail('conflict');
      const time = now();
      const grants = await currentGrants(state.record, state.trust, state.current);
      if (!issuedNotAfter(state.current.issuedAt, time) || !grants.some(item => {
        const grant = item.statement as AccessGrant;
        return grant.organizationId === org.organizationId && grant.recipientKeyId === org.recipientKeyId &&
          grant.revision <= state.current.revision && grant.keyEpoch === state.current.keyEpoch &&
          grant.scopes.includes('narrative') && grantActiveAt(grant, time);
      })) fail('unauthorized');
      if (!await currentReleaseApproved(state, time)) fail('release-not-approved');
      const manifest = await resolve(state.record, state.trust, state.current.manifestDigest, new Map());
      const releases = await Promise.all(state.current.releaseDigests.map(digest => resolve(state.record, state.trust, digest, new Map())));
      const release = releases.find(item => item?.statement.kind === 'release' && item.statement.releaseDigest === releaseDigest);
      if (!manifest || manifest.statement.kind !== 'manifest' || !release) fail('unauthorized');
      let readable = false;
      const authorizeRead = createCaseReadAuthorizer(state.trust);
      narrative: for (const entry of (manifest.statement as CaseManifest).objects.filter(item => item.scope === 'narrative')) {
        for (const grant of grants) {
          try {
            await authorizeRead({ grant: grant.wire, release: release.wire, manifest: manifest.wire,
              checkpoint: state.record.checkpoints[state.record.checkpoints.length - 1],
              checkpointDigest: state.record.currentCheckpointDigest,
              request: { organizationId: org.organizationId, recipientKeyId: org.recipientKeyId,
                objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest, scope: 'narrative', releaseDigest,
                keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, now: time } });
            readable = true;
            break narrative;
          } catch { /* Try the next current grant. */ }
        }
      }
      if (!readable) fail('unauthorized');
      let ciphertext: string;
      try { ciphertext = await requireEncryptedPayload(body.ciphertext, 1, 16 * 1024); } catch { return fail(); }
      const result = await store.appendMessage({ caseId: state.record.caseId, organizationId: org.organizationId,
        sender: 'organization', kind: 'report-open', ciphertext, createdAt: time },
      { checkpointDigest: state.record.currentCheckpointDigest, since: time - 3_600_000,
        limit: limits.messagesPerThreadPerHour });
      if (result !== 'stored') fail(result === 'rate-limited' ? 'rate-limited' : 'conflict');
      return { recorded: true as const };
    },

    /** Owner or granted organization appends an end-to-end encrypted message. */
    async sendMessage(raw: Uint8Array, auth: string, organization: OrganizationContext | null) {
      const value = parseBody(raw, 64 * 1024) as Record<string, unknown>;
      const body = object(value, value && 'requestId' in value
        ? ['caseId', 'organizationId', 'ciphertext', 'requestId'] : ['caseId', 'organizationId', 'ciphertext']);
      const { record, trust, current } = await loadCase(hex64(body.caseId));
      const organizationId = hex64(body.organizationId), time = now();
      let sender: ParticipantRole;
      if (organization) {
        const org = await organizationKey(organization);
        if (org.organizationId !== organizationId) fail('unauthorized');
        await authenticate(raw, auth, 'organization', record.caseId, organizationId, 'send-message', org.key);
        await authorizeMessages(record.caseId, org);
        sender = 'organization';
      } else {
        await authenticate(raw, auth, 'owner', record.caseId, null, 'send-message', trust.ownerPublicKey);
        const grants = await currentGrants(record, trust, current);
        const routingId = body.requestId === undefined ? null : await requestRoutingTag('organization', hex64(body.requestId), organizationId);
        const pending = (await store.listAccessRequests(record.caseId))
          .some(item => item.organizationId === (item.routing === 'blinded-v1' ? routingId : organizationId) &&
            item.state === 'pending' && item.expiresAt > now());
        if (!pending && !grants.some(grant => (grant.statement as AccessGrant).organizationId === organizationId)) fail('unauthorized');
        sender = 'owner';
      }
      const thread = `${record.caseId}:${organizationId}`;
      // A bounded non-queuing critical section: concurrent callers retry rather
      // than observing the same sender count or retaining unbounded pending work.
      if (shared.messageWrites.has(thread) || shared.messageWrites.size >= 1024) fail('rate-limited');
      shared.messageWrites.add(thread);
      try {
        // Owner and firm have separate hourly allowances, so one side cannot use up
        // the other's. The host sees only the thread total (sender is sealed), so it
        // enforces the combined cap transactionally; the per-sender share is counted
        // here from the opened routing of this hour's rows.
        const since = time - 3_600_000;
        if (await store.countMessages({ caseId: record.caseId, organizationId, since }) >= limits.messagesPerThreadPerHour) {
          fail('rate-limited');
        }
        const recent = await store.readMessagesAtCheckpoint(record.caseId, organizationId, limits.messagesPerThreadPerHour,
          record.currentCheckpointDigest);
        if (recent === null) fail('conflict');
        // Host rows carry only the UTC hour, so the host's count above covers the
        // current clock hour. The exact rolling-hour totals come from the opened
        // sealed times of the newest rows.
        const lastHour = recent!.filter(message => message.createdAt >= since);
        if (lastHour.length >= limits.messagesPerThreadPerHour ||
            lastHour.filter(message => message.sender === sender).length >= limits.messagesPerSenderPerHour) {
          fail('rate-limited');
        }
        const latest = await authorizeMessages(record.caseId, organization ?? undefined);
        if (latest.record.currentCheckpointDigest !== record.currentCheckpointDigest ||
            latest.trust.ownerFingerprint !== trust.ownerFingerprint) fail('conflict');
        let ciphertext: string;
        try { ciphertext = await requireEncryptedPayload(body.ciphertext, 2, 48 * 1024); } catch { return fail(); }
        const result = await store.appendMessage({ caseId: record.caseId, organizationId, sender,
          ciphertext, createdAt: time },
        { checkpointDigest: latest.record.currentCheckpointDigest, since, limit: limits.messagesPerThreadPerHour });
        if (result !== 'stored') fail(result === 'rate-limited' ? 'rate-limited' : 'conflict');
        return { sent: true as const };
      } finally { shared.messageWrites.delete(thread); }
    },

    /** Organization reads its own thread with the owner (owner threads come from readInbox). */
    async readMessages(raw: Uint8Array, auth: string, organization: OrganizationContext) {
      const value = parseBody(raw, 4096) as Record<string, unknown>;
      const cursor = value?.mailboxCursor;
      if (cursor !== undefined) delete value.mailboxCursor;
      const body = pinnedBody(new TextEncoder().encode(JSON.stringify(value)));
      const org = await organizationKey(organization);
      const caseId = body.caseId;
      await authenticate(raw, auth, 'organization', caseId, org.organizationId, 'read-messages', org.key);
      const initial = await authorizeMessages(caseId, org);
      await chainSince(initial.record, initial.trust, body.pin);
      const page = store.readMailboxPageAtCheckpoint ? await store.readMailboxPageAtCheckpoint(caseId, org.organizationId,
        initial.record.currentCheckpointDigest, mailboxCursor(cursor, initial.record.currentCheckpointDigest)) : null;
      const messages = store.readMailboxPageAtCheckpoint ? page?.messages ?? null
        : await store.readMessagesAtCheckpoint(caseId, org.organizationId, 500, initial.record.currentCheckpointDigest);
      if (messages === null) fail('conflict');
      const current = await authorizeMessages(caseId, org);
      // Suppress consent changes since the storage snapshot. The transaction
      // cannot establish independently witnessed freshness or current membership.
      if (current.record.currentCheckpointDigest !== initial.record.currentCheckpointDigest ||
          current.trust.ownerFingerprint !== initial.trust.ownerFingerprint) fail('conflict');
      return { messages, next: page?.next ?? null };
    },
  };

  /** Read-only status logic shared by single-case and organization-signed batch reads. */
  async function requestStatusFor(record: Awaited<ReturnType<typeof loadPublic>>['record'],
    org: Awaited<ReturnType<typeof organizationKey>>, requestIds: string[]) {
    const time = now();
    type AccessState = 'active' | 'expired' | 'revoked' | 'key-changed' | 'none' | 'unknown';
    let access: { state: AccessState; expiresAt: number | null; scopes: string[]; contactShared: boolean;
      releaseApproved: boolean | null } = { state: 'unknown', expiresAt: null, scopes: [], contactShared: false, releaseApproved: null };
    const answered = new Set<string>();
    let locked = record.locked;
    if (!locked) {
      let loaded: Awaited<ReturnType<typeof loadCase>> | null = null;
      // A case locked between the two reads reports access as unknown.
      try { loaded = await loadCase(record.caseId); }
      catch (error) { if (!(error instanceof CaseServiceError && error.code === 'locked')) throw error; locked = true; }
      if (loaded) {
        const { record: unsealed, trust, current } = loaded;
        if (!issuedNotAfter(current.issuedAt, time)) fail('unauthorized');
        const grants = (await currentGrants(unsealed, trust, current)).map(item => item.statement as AccessGrant)
          .filter(grant => grant.organizationId === org.organizationId && grant.revision <= current.revision);
        const mine = grants.filter(grant => grant.recipientKeyId === org.recipientKeyId && grant.keyEpoch === current.keyEpoch);
        for (const wire of Object.values(unsealed.statements)) {
          // Cheap pre-filter on the claimed kind and firm before verifying a signature.
          let claimed: { kind?: unknown; organizationId?: unknown } | undefined;
          try { claimed = JSON.parse(wire)?.statement; } catch { continue; }
          if (claimed?.kind !== 'grant' || claimed.organizationId !== org.organizationId) continue;
          const verifiedGrant = await verified(wire, trust).catch(() => null);
          if (verifiedGrant?.statement.kind === 'grant') answered.add(verifiedGrant.statement.grantId);
        }
        const active = mine.filter(grant => grantActiveAt(grant, time));
        const releases = await Promise.all(current.releaseDigests.map(digest => resolve(unsealed, trust, digest, new Map())));
        const releaseApproved = releases.some(item => item?.statement.kind === 'release' && item.statement.releaseDigest === releaseDigest &&
          item.statement.revision <= current.revision && issuedNotAfter(item.statement.issuedAt, time));
        if (active.length) {
          access = { state: 'active', expiresAt: active.some(grant => grant.expiresAt === null) ? null
            : Math.max(...active.map(grant => grant.expiresAt as number)),
          scopes: [...new Set(active.flatMap(grant => grant.scopes))].sort(),
          contactShared: active.some(grant => grant.scopes.includes('contact') || grant.scopes.includes('identity')), releaseApproved };
        } else if (mine.length) {
          access = { state: 'expired', expiresAt: Math.max(...mine.map(grant => grant.expiresAt ?? 0)), scopes: [], contactShared: false, releaseApproved };
        } else {
          access = { state: grants.length ? 'key-changed' : answered.size ? 'revoked' : 'none', expiresAt: null, scopes: [],
            contactShared: false, releaseApproved };
        }
      }
    }
    let listed: StoredAccessRequest[] | null = null;
    const lookup = async (requestId: string): Promise<StoredAccessRequest | null> => {
      const [requestTag, organizationTag, recipientTag] = await Promise.all([
        requestRoutingTag('request', requestId), requestRoutingTag('organization', requestId, org.organizationId),
        requestRoutingTag('recipient', requestId, org.recipientKeyId)]);
      let found: StoredAccessRequest | null;
      if (store.getAccessRequest) found = await store.getAccessRequest(record.caseId, org.organizationId, requestId);
      else {
        listed ??= await store.listAccessRequests(record.caseId);
        found = listed.find(item => item.routing === 'blinded-v1'
          ? item.requestId === requestTag && item.organizationId === organizationTag
          : item.requestId === requestId && item.organizationId === org.organizationId) ?? null;
      }
      if (!found) return null;
      // Every routing commitment must match this organization, key and request.
      const blinded = found.routing === 'blinded-v1';
      if (found.caseId !== record.caseId || found.requestId !== (blinded ? requestTag : requestId) ||
          found.organizationId !== (blinded ? organizationTag : org.organizationId) ||
          !Number.isSafeInteger(found.expiresAt) || found.expiresAt <= 0 ||
          !['pending', 'withdrawn', 'declined', 'expired', 'approved'].includes(found.state)) fail();
      // A request sent under an earlier organization key is not this key's request.
      return found.recipientKeyId === (blinded ? recipientTag : org.recipientKeyId) ? found : null;
    };
    const requests = [];
    for (const requestId of requestIds) {
      const row = await lookup(requestId);
      let state: 'requested' | 'approved' | 'declined' | 'expired' | 'withdrawn' | 'unknown';
      // A row's `approved` is a host claim. While the case is unlocked only an
      // owner-signed grant answering this request counts; while it is locked the
      // claim is shown, and opening the case still requires a current grant.
      if (answered.has(requestId) || (locked && row?.state === 'approved')) state = 'approved';
      else if (!row || row.state === 'approved') state = 'unknown';
      else if (row.state === 'pending') state = row.expiresAt > time ? 'requested' : 'expired';
      else state = row.state;
      requests.push({ requestId, state, ...(state === 'requested' ? { expiresAt: row!.expiresAt } : {}) });
    }
    return { access, requests };
  }

  async function organizationKey(context: OrganizationContext): Promise<{ organizationId: string; recipientKeyId: string; key: PublicKey }> {
    try {
      const value = object({ ...context }, ['organizationId', 'recipientKeyId', 'publicKey']);
      const key = await readKey({ armoredKey: text(value.publicKey, 65_536) });
      if (key.isPrivate() || await caseRecipientKeyId(key) !== hex64(value.recipientKeyId)) fail();
      return { organizationId: hex64(value.organizationId), recipientKeyId: value.recipientKeyId as string, key };
    } catch { return fail('unauthorized'); }
  }
}

export type CaseService = ReturnType<typeof createCaseService>;
