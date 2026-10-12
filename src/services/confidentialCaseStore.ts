import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { LegalApplications } from './legalApplications';
import type { LegalApplicationSource } from './legalApplications';
import { Auth0LegalApplications } from './auth0LegalApplications';
import type { ApplicationOrganizations } from './legalApplicationOrganizations';
import { LegalAuth0Memberships } from './legalAuth0Memberships';
import type { LegalMembershipApproval } from './legalAuth0Memberships';
import type { ApplicationIdentityProvider } from './legalApplicationAuth0';
import { Binary, MongoClient } from 'mongodb';
import type { ClientSession, Collection, Db, MongoClientOptions } from 'mongodb';
import { LegalOnboardingConflict } from '../utils/legalOnboarding';
import { CHUNK_TAG_BYTES, MAX_CHUNKS_PER_OBJECT, MAX_CHUNK_BYTES, isChunkSize } from '../utils/confidentialChunks';
import { storedHourCeil, storedHourFloor } from '../utils/storedTime';
import type { SummaryPeriod, Delivery, SummaryRecord, ClaimedSummary, WeeklySubmissionSummaryStorage } from './weeklySubmissionSummary';

// Host-side mirror of the enclave `CaseStore` contract (enclave/src/cases/service.ts).
// The server build cannot import enclave sources; tests pass this adapter to the
// enclave service to keep the two shapes structurally identical.
export type StoredObject = { objectId: string; ciphertextDigest: string; ciphertext: string; ownerEnvelope: string };
export type StoredEnvelope = { objectId: string; recipientKeyId: string; envelope: string };
export type CaseRecord = {
  caseId: string; ownerPublicKey: string; ownerFingerprint: string; statements: Record<string, string>;
  checkpoints: string[]; currentCheckpointDigest: string; listingDigest: string | null;
  recoveryPackage: string; createdAt: number;
  /** Sealed mode: state epoch and unlabeled participant state-key envelopes. */
  stateEpoch?: number; stateEnvelopes?: string[];
};
/** Optional bounded read for sealed callers (see `getCase`). */
export type CaseReadView = { releaseLimit: number };
export type TransitionUpdate = {
  statements: Record<string, string>; checkpoint: string; checkpointDigest: string; listingDigest: string | null;
  objects: StoredObject[]; envelopes: StoredEnvelope[]; recoveryPackage: string | null;
  stateEnvelopes?: string[]; stateEpoch?: number;
};
export type StoredAccessRequest = {
  caseId: string; organizationId: string; requestId: string; ciphertext: string;
  recipientKeyId: string; expiresAt: number;
  state: 'pending' | 'withdrawn' | 'declined' | 'expired' | 'approved'; createdAt: number;
  /** Enclave-computed per-case firm pseudonym (sealed rows on unlocked cases). */
  quotaTag?: string;
};
export type MailboxCursor = { version: number; requestOffset: number; messageOffset: number; checkpointDigest: string };
export type MailboxPage = { requests: StoredAccessRequest[]; messages: StoredMessage[]; next: MailboxCursor | null };
export type StoredMessage = {
  caseId: string; organizationId: string; sender: 'owner' | 'organization'; ciphertext: string; createdAt: number;
  /** Opaque enclave-computed tag, compared for equality only: a second row with
   * the same tag in a case is not stored. Older rows have none. */
  dedupeTag?: string;
};

/** Untrusted host-side persistence used behind the enclave storage RPC.
 * Production case operations wrap this adapter with createSealedCaseStore
 * inside the enclave before writing private state. This adapter itself does
 * not encrypt or establish confidentiality; direct callers can persist raw
 * authorization statements and checkpoints.
 * The sealed path retains public listings and release approvals, owner public
 * keys, opaque state/routing identifiers, ciphertext, and operational metadata.
 * Collection separation does not prevent administrator observation, traffic
 * correlation, or rollback; participant pins provide the available freshness check.
 *
 * Atomicity: a transition is a transaction whose compare-and-set on the case
 * document's `currentCheckpointDigest` serializes it. The case document holds the
 * genesis checkpoint and public fields; later checkpoints go to
 * `confidential_case_history` (one row per entry) and recipient envelopes to
 * `confidential_case_envelopes` and statements committed after publication to
 * `confidential_case_statements` (one row per (case, digest)), so the case
 * document no longer grows toward the 16 MB BSON limit with every commit.
 * Documents written before this layout keep their embedded
 * `checkpoints`/`envelopes`/`statements`; reads combine both, embedded first
 * (a segmented statement with the same digest wins). Large objects live in a content-addressed collection
 * written before the commit; an object absent from the committed manifest is an
 * unreferenced orphan that no read path serves.
 */
type CaseDocument = CaseRecord & { directoryHidden?: boolean; _id: string; envelopes: Record<string, StoredEnvelope>; messageWriteSequence?: number; mailboxRevision?: number;
  /** Checkpoints kept in the document itself (genesis, or the whole chain for legacy documents). */
  embeddedHistoryLength?: number;
  /** Checkpoints appended to `confidential_case_history`. */
  historyCount?: number;
  /** Statements appended to `confidential_case_statements` (the embedded
   * `statements` map holds only the genesis set, or everything for legacy documents). */
  statementCount?: number;
  /** Retired alert state on older records; stripped from participant reads. */
  adminAlert?: { dueAt: number; lease?: string; attempts: number; sent?: boolean };
};
type HistoryDocument = { _id: string; caseId: string; index: number; checkpoint: string };
type EnvelopeDocument = StoredEnvelope & { _id: string; caseId: string };
/** One committed statement, `_id` `${caseId}:${digest}`. `index` is its position
 * in commit order (contiguous from 0, counted by the case's `statementCount`), so a
 * full read detects a missing row. `kind`/`revision` are the claimed values parsed
 * from the wire here on the host: unverified sort hints for the bounded release
 * read, never an authority (the enclave verifies every wire it uses). In sealed
 * mode only public listings and release approvals ever reach this collection. */
type StatementDocument = { _id: string; caseId: string; digest: string; index: number; wire: string;
  kind: string | null; revision: number | null };
/** Unverified claimed kind and revision of a statement wire (host-side hint only). */
function claimedStatement(wire: string): { kind: string | null; revision: number | null } {
  try {
    const statement = JSON.parse(wire)?.statement;
    const kind = typeof statement?.kind === 'string' && /^[a-z]{1,32}$/.test(statement.kind) ? statement.kind : null;
    return { kind, revision: Number.isSafeInteger(statement?.revision) ? statement.revision : null };
  } catch { return { kind: null, revision: null }; }
}
const statementRowId = (caseId: string, digest: string) => `${caseId}:${digest}`;
/** Bounded public read size limit for `getCase` views. */
const MAX_RELEASE_VIEW = 256;
type ObjectDocument = StoredObject & { _id: string; caseId: string };
/** `_id` is random: a driver-generated ObjectId embeds the insertion second,
 * which would undo the day-granularity timestamps of blinded request rows. */
type RequestDocument = StoredAccessRequest & { _id?: string };
const requestRowId = () => randomBytes(16).toString('hex');
/** `createdAt` arrives from the sealed store as the UTC hour (older rows: exact).
 * Order within a case is `sequence`, the case's `messageWriteSequence` taken in
 * the same transaction (absent on older rows, which sort first by `createdAt`).
 * `_id` is random: a driver ObjectId would put the insertion second back. */
type MessageDocument = StoredMessage & { _id?: string; sequence?: number };
const messageRowId = () => randomBytes(16).toString('hex');
/** Oldest first; legacy rows (no sequence) predate every sequenced row. */
const MESSAGE_ORDER = { sequence: 1, createdAt: 1, _id: 1 } as const;
const MESSAGE_ORDER_NEWEST = { sequence: -1, createdAt: -1, _id: -1 } as const;
/** Pre-publish ciphertext staging, keyed by SHA-256 of the exact armored text.
 * `expiresAt` is rounded up to the UTC hour (see `stagedExpiry`). */
type StagedDocument = { _id: string; ciphertext: string; expiresAt: Date };
/** Chunked-evidence ciphertext, keyed by SHA-256 of the exact chunk bytes. A
 * staged chunk carries `expiresAt` (TTL); promotion by a committed index removes
 * it. Chunks are opaque AES-GCM output; the index naming them is stored with the
 * object row. */
type ChunkDocument = { _id: string; data: Binary; size: number; expiresAt?: Date };
/** Chunk digests named by a stored chunked-object index (non-secret metadata). */
function indexChunks(text: unknown): string[] | null {
  // v2 (older) and v3 (count-padded) chunked indexes share this shape.
  if (typeof text !== 'string' || !/^\{"format":"vera-case-object\/v[23]"/.test(text) || text.length > 40 * 1024) return null;
  try {
    const chunks = JSON.parse(text)?.chunks;
    return Array.isArray(chunks) && chunks.length <= MAX_CHUNKS_PER_OBJECT &&
      chunks.every(item => typeof item === 'string' && /^[a-f0-9]{64}$/.test(item)) ? chunks : null;
  } catch { return null; }
}
/** Onboarded legal organization roster row (public data, written by admin onboarding). */
export type LegalOrganizationDocument = {
  _id: string; displayName: string; domain: string; publicKey: string; approved: boolean; updatedAt: Date;
  /** Auth0 organization and firm recipient key ID; required for firm operations. */
  providerOrganizationId?: string; recipientKeyId?: string; registration?: string; bindingDocument?: string;
  /** Admin onboarding record. A revoked organization is final: it is never re-approved. */
  createdAt?: Date; createdBy?: string; registeredAt?: Date; revokedAt?: Date; revokedBy?: string;
  /** Unique (partial-index) claims so two live organizations cannot share an identity-provider
   * organization or domain. Removed on revocation. */
  providerClaim?: string; domainClaim?: string; invitationRevision?: number;
  /** Serializes live-device admission across concurrent enclave requests. */
  deviceAdmissionRevision?: number;
  /** Public, self-signed candidate; never an authorization or replacement for the registered key. */
  candidateBindingDocument?: string; candidateSubject?: string; candidateRecipientKeyId?: string;
  /** Continuity statement signed by the registered key, present only for a registered organization's key change. */
  candidateContinuity?: string;
  memberInvitationWindow?: number; memberInvitationAttempts?: number;
  memberInvitationLeases?: Record<string, { id: string; until: number; sent: boolean }>;
  /** Exact addresses approved by a steward, hashed and consumed after sign-in. */
  memberSignInApprovals?: Record<string, number>;
  /** Organization-key-signed setup statements (key custody, onboarding terms).
   * Public statements, verified by the enclave on every read; never an authority here. */
  setup?: { custody?: string; terms?: string };
};
/** Onboarding audit trail: organization/invitation/member lifecycle only. It never
 * names a case, a grant, a request or any case content. */
export const LEGAL_AUDIT_ACTIONS = ['organization_created', 'organization_registered', 'organization_revoked',
  'invitation_issued', 'invitation_redeemed', 'invitation_revoked', 'member_removed'] as const;
/** Audit actor for removals the organization's steward makes through the enclave. */
const STEWARD_ACTOR = 'organization steward';
export type LegalAuditAction = typeof LEGAL_AUDIT_ACTIONS[number];
export type LegalAuditDocument = {
  _id: string; at: Date; action: LegalAuditAction; organizationId: string; actor: string;
  invitationId?: string; subject?: string;
};

/** Enrolled legal member. `revision` increases on every change so the enclave
 * can detect removal or key change during an operation. */
export type LegalMemberDocument = {
  _id: string; subject: string; providerOrganizationId: string; organizationId: string;
  recipientKeyId: string; revision: number; active: boolean; updatedAt: Date;
  /** Durable removal cutoff survives deliberate re-enrollment. */
  removedAt?: Date; invitationRevision?: number;
  enrollment?: { challenge: { format: 'vera-legal-enrollment/v1'; invitationId: string; organizationId: string;
    providerOrganizationId: string; subject: string; recipientKeyId: string; nonce: string; expiresAt: number }; proof: string; authorization: string; delegation?: { memberId: string; deviceFingerprint: string; deviceProof: string } };
};
/** Pending/redeemed invitation, keyed by SHA-256 of the raw token (never stored). */
export type LegalInvitationDocument = {
  _id: string; format: 'vera-legal-enrollment/v1'; invitationId: string; organizationId: string;
  providerOrganizationId: string; subject: string; recipientKeyId: string; nonce: string; expiresAt: number;
  authorization: string; tokenDigest: string; createdAt: number; createdBy: string; version: number; state: 'pending' | 'redeemed' | 'revoked';
  revokedAt?: number; revokedBy?: string;
};
/** Member device row (enclave `FirmDevice`). The public device key, an encrypted
 * profile and an organization-key envelope encrypted to that device; the host
 * can read none of the private parts. `revision` is a compare-and-set counter. */
export type FirmDeviceDocument = {
  _id: string; organizationId: string; memberId: string; providerOrganizationId: string; subject: string;
  devicePublicKey: string; deviceFingerprint: string; profile: string; state: 'pending' | 'approved' | 'removed';
  envelope: string | null; keyEpoch: number | null; continuity: string | null;
  revision: number; registeredAt: number; updatedAt: number; membershipAdmissionRevision?: number;
};
/** Organization-key-encrypted shared request list, one row per organization. */
/** No write time: with request rows kept at day granularity (see the sealed
 * store), a timestamp here would let a database snapshot or backup match an
 * organization's list write to the request row it announced. */
export type FirmSharedListDocument = { _id: string; version: number; record: string };
const FIRM_DEVICE_FIELDS = ['organizationId', 'memberId', 'providerOrganizationId', 'subject', 'devicePublicKey',
  'deviceFingerprint', 'profile', 'state', 'envelope', 'keyEpoch', 'continuity', 'revision', 'registeredAt', 'updatedAt'] as const;
const deviceKey = (organizationId: string, memberId: string) => `${organizationId}/${memberId}`;
const HEX64 = /^[a-f0-9]{64}$/;
function deviceRow(row: FirmDeviceDocument) {
  return Object.fromEntries(FIRM_DEVICE_FIELDS.map(field => [field, row[field]])) as Omit<FirmDeviceDocument, '_id'>;
}
const memberKey = (providerOrganizationId: string, subject: string) => `${providerOrganizationId}/${subject}`;
const auditId = () => randomBytes(16).toString('hex');
const duplicateKey = (error: unknown) => (error as { code?: number })?.code === 11000;
/** E11000 from `message_dedupe_tag` only (DocumentDB may omit keyPattern, so the index name is checked too). */
const duplicateDedupeTag = (error: unknown) => duplicateKey(error) &&
  ('dedupeTag' in ((error as { keyPattern?: Record<string, unknown> }).keyPattern ?? {}) ||
    String((error as { message?: unknown }).message ?? '').includes('message_dedupe_tag'));
function claimConflict(error: unknown): LegalOnboardingConflict {
  const pattern = (error as { keyPattern?: Record<string, unknown> })?.keyPattern ?? {};
  const message = String((error as { message?: unknown })?.message ?? '');
  return new LegalOnboardingConflict('providerClaim' in pattern || message.includes('providerClaim')
    ? 'duplicate-provider-organization' : 'duplicate-domain');
}
export const STAGED_OBJECT_LIFETIME_MS = 24 * 60 * 60 * 1000;
/** Upload time plus the lifetime would date the upload to the millisecond; the
 * end of that UTC hour keeps it to the hour and never expires early. */
const stagedExpiry = (now: number) => new Date(storedHourCeil(now + STAGED_OBJECT_LIFETIME_MS));

const envelopeKey = (objectId: string, recipientKeyId: string) => `${objectId}_${recipientKeyId}`;

/** Driver options for the confidential database. Command documents hold case
 * IDs, sealed routing, ciphertext and staged objects, so driver logging and
 * command monitoring are pinned off in code: client options take precedence
 * over MONGODB_LOG_* environment variables, so an operator setting
 * MONGODB_LOG_ALL=debug for the legacy store cannot turn them on here. */
export const CONFIDENTIAL_MONGO_LOG_SEVERITIES = { default: 'off', command: 'off', topology: 'off',
  serverSelection: 'off', connection: 'off', client: 'off' } as const;
export function confidentialMongoClientOptions(tlsCAFile?: string): MongoClientOptions {
  // DocumentDB does not support retryable writes; the driver enables them by default.
  return { readPreference: 'primary', serverSelectionTimeoutMS: 10000, writeConcern: { w: 'majority', j: true }, retryWrites: false,
    monitorCommands: false, mongodbLogComponentSeverities: { ...CONFIDENTIAL_MONGO_LOG_SEVERITIES },
    ...(tlsCAFile ? { tlsCAFile } : {}) };
}

export class MongoConfidentialCaseStore {
  private constructor(
    private readonly client: MongoClient | null,
    private readonly cases: Collection<CaseDocument>,
    private readonly objects: Collection<ObjectDocument>,
    private readonly requests: Collection<RequestDocument>,
    private readonly messages: Collection<MessageDocument>,
    private readonly requestLocks: Collection<{ _id: string; sequence: number }>,
    private readonly staged: Collection<StagedDocument>,
    private readonly chunks: Collection<ChunkDocument>,
    private readonly organizations: Collection<LegalOrganizationDocument>,
    private readonly members: Collection<LegalMemberDocument>,
    private readonly invitations: Collection<LegalInvitationDocument>,
    private readonly history: Collection<HistoryDocument>,
    private readonly caseEnvelopes: Collection<EnvelopeDocument>,
    private readonly caseStatements: Collection<StatementDocument>,
    private readonly legalAudit: Collection<LegalAuditDocument>,
    private readonly devices: Collection<FirmDeviceDocument>,
    private readonly sharedLists: Collection<FirmSharedListDocument>,
    readonly applications: LegalApplicationSource,
    private readonly auth0Memberships: LegalAuth0Memberships,
    readonly weeklySubmissionSummaries: WeeklySubmissionSummaryStore,
  ) {}

  static async fromDatabase(db: Db, client: MongoClient | null = null, applicationDirectory?: ApplicationOrganizations | null): Promise<MongoConfidentialCaseStore> {
    const cases = db.collection<CaseDocument>('confidential_cases');
    const objects = db.collection<ObjectDocument>('confidential_case_objects');
    const requests = db.collection<RequestDocument>('confidential_access_requests');
    const messages = db.collection<MessageDocument>('confidential_messages');
    const requestLocks = db.collection<{ _id: string; sequence: number }>('confidential_request_locks');
    const staged = db.collection<StagedDocument>('confidential_staged_objects');
    const chunks = db.collection<ChunkDocument>('confidential_object_chunks');
    const organizations = db.collection<LegalOrganizationDocument>('confidential_legal_organizations');
    const members = db.collection<LegalMemberDocument>('confidential_legal_members');
    const invitations = db.collection<LegalInvitationDocument>('confidential_legal_invitations');
    const history = db.collection<HistoryDocument>('confidential_case_history');
    const caseEnvelopes = db.collection<EnvelopeDocument>('confidential_case_envelopes');
    const caseStatements = db.collection<StatementDocument>('confidential_case_statements');
    const legalAudit = db.collection<LegalAuditDocument>('confidential_legal_audit');
    const devices = db.collection<FirmDeviceDocument>('confidential_legal_devices');
    const sharedLists = db.collection<FirmSharedListDocument>('confidential_legal_shared_lists');
    await Promise.all([
      db.collection('confidential_listing_moderation_audit').createIndex({ caseId: 1, at: -1 }),
      history.createIndex({ caseId: 1, index: 1 }, { unique: true }),
      caseEnvelopes.createIndex({ caseId: 1, recipientKeyId: 1 }),
      // Exact reassembly in commit order; the unique index also rejects a second
      // row claiming the same position.
      caseStatements.createIndex({ caseId: 1, index: 1 }, { unique: true, name: 'statement_position' }),
      // Bounded release-approval read: newest claimed revision first.
      caseStatements.createIndex({ caseId: 1, kind: 1, revision: -1, _id: 1 }, { name: 'statement_by_kind_revision' }),
      devices.createIndex({ organizationId: 1, memberId: 1 }),
      cases.createIndex({ listingDigest: 1, _id: 1 }),
      objects.createIndex({ caseId: 1, objectId: 1 }),
      requests.createIndex({ caseId: 1, organizationId: 1 }, { unique: true,
        // Explicit $eq: DocumentDB 5.0 partial indexes accept $eq, $exists, $gt,
        // $gte, $lt, $lte and top-level $and.
        partialFilterExpression: { state: { $eq: 'pending' } }, name: 'one_pending_request_per_org' }),
      // Retain identity uniqueness across withdrawal: a retry cannot resurrect
      // an old request. A genuinely new request needs a new signed request ID.
      requests.createIndex({ caseId: 1, organizationId: 1, requestId: 1 },
        { unique: true, name: 'access_request_identity' }),
      requests.createIndex({ organizationId: 1, createdAt: 1 }),
      requests.createIndex({ caseId: 1, quotaTag: 1, state: 1 }, { name: 'pending_request_by_case_firm_pseudonym' }),
      messages.createIndex({ caseId: 1, organizationId: 1, createdAt: 1 }),
      // Message reads sort by MESSAGE_ORDER, per thread and per case.
      messages.createIndex({ caseId: 1, organizationId: 1, sequence: 1, createdAt: 1, _id: 1 }, { name: 'message_order_by_thread' }),
      messages.createIndex({ caseId: 1, sequence: 1, createdAt: 1, _id: 1 }, { name: 'message_order_by_case' }),
      messages.createIndex({ caseId: 1, dedupeTag: 1 }, { unique: true,
        partialFilterExpression: { dedupeTag: { $exists: true } }, name: 'message_dedupe_tag' }),
      staged.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      members.createIndex({ organizationId: 1, recipientKeyId: 1, active: 1 }),
      // Claims are $unset on revocation; a partial index (DocumentDB 5.0 accepts $exists)
      // keeps uniqueness to live rows the same way a sparse index would.
      organizations.createIndex({ providerClaim: 1 }, { unique: true,
        partialFilterExpression: { providerClaim: { $exists: true } }, name: 'one_live_provider_organization' }),
      organizations.createIndex({ domainClaim: 1 }, { unique: true,
        partialFilterExpression: { domainClaim: { $exists: true } }, name: 'one_live_domain' }),
      invitations.createIndex({ invitationId: 1 }, { unique: true, name: 'invitation_identity' }),
      invitations.createIndex({ organizationId: 1, createdAt: -1 }),
      members.createIndex({ organizationId: 1 }),
      legalAudit.createIndex({ organizationId: 1, at: -1 }),
      legalAudit.createIndex({ at: -1 }),
      // Only staged chunks carry expiresAt; promoted chunks never expire.
      chunks.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    ]);
    const store = new MongoConfidentialCaseStore(client, cases, objects, requests, messages, requestLocks, staged, chunks,
      organizations, members, invitations, history, caseEnvelopes, caseStatements, legalAudit, devices, sharedLists,
      applicationDirectory !== undefined ? await Auth0LegalApplications.fromDatabase(db, applicationDirectory) : await LegalApplications.fromDatabase(db),
      await LegalAuth0Memberships.fromDatabase(db), new WeeklySubmissionSummaryStore(db));
    // Complete uniqueness migration before exposing any live admin mutation.
    // The indexes above reject collisions, including across concurrent startups.
    if (client) await store.migrateLegalOrganizationClaims();
    return store;
  }

  /** Separate connection settings from the legacy report store. */
  static async connect(uri: string, dbName: string, tlsCAFile?: string, applicationDirectory: ApplicationOrganizations | null = null): Promise<MongoConfidentialCaseStore> {
    const client = new MongoClient(uri, confidentialMongoClientOptions(tlsCAFile));
    try {
      await client.connect();
      return await MongoConfidentialCaseStore.fromDatabase(client.db(dbName), client, applicationDirectory);
    } catch (error) {
      await client.close().catch(() => {});
      throw error;
    }
  }

  async close(): Promise<void> { await this.client?.close(); }

  /** Store already-encrypted ciphertext by digest. Idempotent; expires unless published. */
  async stageObject(ciphertextDigest: string, ciphertext: string, now: number): Promise<void> {
    // Retries never extend retained ciphertext indefinitely. Expired records can
    // be restaged even while Mongo's asynchronous TTL cleanup is still pending.
    await this.staged.deleteOne({ _id: ciphertextDigest, expiresAt: { $lte: new Date(now) } });
    await this.staged.updateOne({ _id: ciphertextDigest },
      { $setOnInsert: { ciphertext, expiresAt: stagedExpiry(now) } }, { upsert: true });
  }
  /** Stage one chunk ciphertext by digest. Idempotent; a re-upload refreshes the
   * expiry of a still-staged chunk but never makes a promoted chunk expire. */
  async stageChunk(digest: string, data: Uint8Array, now: number): Promise<void> {
    if (!/^[a-f0-9]{64}$/.test(digest) || !(data instanceof Uint8Array) || !isChunkSize(data.length) ||
        !Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid chunk');
    const expiresAt = stagedExpiry(now);
    try {
      await this.chunks.updateOne({ _id: digest }, { $setOnInsert: { data: new Binary(Buffer.from(data)), size: data.length,
        expiresAt } }, { upsert: true });
    } catch (error) { if ((error as { code?: number }).code !== 11000) throw error; }
    await this.chunks.updateOne({ _id: digest, expiresAt: { $exists: true } }, { $set: { expiresAt } });
  }
  /** Enclave call after the owner-signed manifest verified: every chunk the index
   * names must be staged (or already permanent) with the size its position implies. */
  async promoteChunks(caseId: string, objectDigest: string, chunkDigests: string[], finalBytes: number): Promise<boolean> {
    if (![caseId, objectDigest].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)) ||
        !Array.isArray(chunkDigests) || !chunkDigests.length || chunkDigests.length > MAX_CHUNKS_PER_OBJECT ||
        chunkDigests.some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) ||
        !isChunkSize(finalBytes + CHUNK_TAG_BYTES)) return false;
    const ids = [...new Set(chunkDigests)];
    const rows = await this.chunks.find({ _id: { $in: ids } }, { projection: { _id: 1, size: 1 } }).toArray();
    const sizes = new Map(rows.map(row => [row._id, row.size]));
    const last = chunkDigests.length - 1;
    if (chunkDigests.some((digest, position) => sizes.get(digest) !==
        (position === last ? finalBytes : MAX_CHUNK_BYTES - CHUNK_TAG_BYTES) + CHUNK_TAG_BYTES)) return false;
    await this.chunks.updateMany({ _id: { $in: ids }, expiresAt: { $exists: true } }, { $unset: { expiresAt: '' } });
    // A chunk that expired between the check and the update is simply missing now.
    return await this.chunks.countDocuments({ _id: { $in: ids }, expiresAt: { $exists: false } }) === ids.length;
  }
  async getOwnerEnvelopes(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]) {
    if (!refs.length) return [];
    const rows = await this.objects.find({ _id: { $in: refs.map(ref => `${caseId}_${ref.objectId}_${ref.ciphertextDigest}`) } },
      { projection: { objectId: 1, ciphertextDigest: 1, ownerEnvelope: 1 } }).toArray();
    return rows.map(({ objectId, ciphertextDigest, ownerEnvelope }) => ({ objectId, ciphertextDigest, ownerEnvelope }));
  }
  async listLegalOrganizations() {
    const rows = await this.organizations.find({ approved: true }, { limit: 256, sort: { displayName: 1 } }).toArray();
    return rows.map(row => ({ organizationId: row._id, displayName: row.displayName, domain: row.domain,
      publicKey: row.publicKey, approved: row.approved, registration: row.registration, bindingDocument: row.bindingDocument }));
  }
  /** Enclave registration (via `issueInvitation`) writes the onboarding-signed roster
   * row; this grants no case access. A revoked organization is never re-approved, and
   * a registration must match the admin-created record's domain and identity-provider
   * organization. Two live organizations cannot share either. */
  async upsertLegalOrganization(value: { organizationId: string; displayName: string; domain: string;
    publicKey: string; approved: boolean; providerOrganizationId?: string; recipientKeyId?: string; registration?: string; bindingDocument?: string }, now: number): Promise<void> {
    const existing = await this.organizations.findOne({ _id: value.organizationId },
      { projection: { revokedAt: 1, domain: 1, providerOrganizationId: 1, registration: 1 } });
    if (existing?.revokedAt) throw new LegalOnboardingConflict('revoked');
    if (existing && (existing.domain !== value.domain || (existing.providerOrganizationId && value.providerOrganizationId &&
        existing.providerOrganizationId !== value.providerOrganizationId))) throw new LegalOnboardingConflict('mismatch');
    const registering = value.approved && typeof value.registration === 'string' && existing?.registration !== value.registration;
    try {
      await this.transaction(async session => {
        await this.organizations.updateOne({ _id: value.organizationId, revokedAt: { $exists: false } }, { $set: {
          displayName: value.displayName, domain: value.domain, publicKey: value.publicKey, approved: value.approved,
          updatedAt: new Date(now), domainClaim: value.domain,
          ...(value.providerOrganizationId ? { providerOrganizationId: value.providerOrganizationId, providerClaim: value.providerOrganizationId } : {}),
          ...(value.recipientKeyId ? { recipientKeyId: value.recipientKeyId } : {}),
          ...(value.registration ? { registration: value.registration } : {}),
          ...(value.bindingDocument ? { bindingDocument: value.bindingDocument } : {}),
          ...(registering ? { registeredAt: new Date(now) } : {}) } }, { upsert: true, session });
        if (value.bindingDocument) await this.organizations.updateOne({ _id: value.organizationId,
          candidateRecipientKeyId: value.recipientKeyId, candidateBindingDocument: value.bindingDocument },
        { $unset: { candidateBindingDocument: '', candidateSubject: '', candidateRecipientKeyId: '', candidateContinuity: '' } }, { session });
        if (registering) await this.audit({ action: 'organization_registered', organizationId: value.organizationId,
          actor: 'onboarding authority' }, now, session);
      });
    } catch (error) {
      if (!duplicateKey(error)) throw error;
      const pattern = (error as { keyPattern?: Record<string, unknown> }).keyPattern;
      throw pattern && '_id' in pattern ? new LegalOnboardingConflict('revoked') : claimConflict(error);
    }
  }
  /** Enclave `LegalMembershipStore`: untrusted rows, re-checked against the token and firm key. */
  async getOrganization(organizationId: string) {
    if (typeof organizationId !== 'string' || !/^[a-f0-9]{64}$/.test(organizationId)) return null;
    const row = await this.organizations.findOne({ _id: organizationId });
    if (!row || typeof row.providerOrganizationId !== 'string' || typeof row.recipientKeyId !== 'string') return null;
    return { organizationId: row._id, providerOrganizationId: row.providerOrganizationId,
      recipientKeyId: row.recipientKeyId, publicKey: row.publicKey, approved: row.approved, registration: row.registration, bindingDocument: row.bindingDocument };
  }
  async getMember(subject: string, providerOrganizationId: string) {
    if (typeof subject !== 'string' || typeof providerOrganizationId !== 'string') return null;
    const row = await this.members.findOne({ _id: memberKey(providerOrganizationId, subject) });
    if (!row || row.subject !== subject || row.providerOrganizationId !== providerOrganizationId) return null;
    return { subject: row.subject, providerOrganizationId: row.providerOrganizationId, organizationId: row.organizationId,
      recipientKeyId: row.recipientKeyId, revision: row.revision, active: row.active, enrollment: row.enrollment };
  }
  /** Informational member count for the firm onboarding checklist; never an authority. */
  async countMembers(organizationId: string, recipientKeyId: string, now: number): Promise<number> {
    if (![organizationId, recipientKeyId].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)) ||
        !Number.isSafeInteger(now) || now <= 0) return 0;
    return this.members.countDocuments({ organizationId, recipientKeyId, active: true,
      'enrollment.challenge.expiresAt': { $gt: now } }, { limit: 1000 });
  }
  /** Candidate key holders for the enclave's organization-setup check: active,
   * unexpired members enrolled against this key. The enclave verifies each row. */
  async listMembers(organizationId: string, recipientKeyId: string, now: number) {
    if (![organizationId, recipientKeyId].every(value => typeof value === 'string' && HEX64.test(value)) ||
        !Number.isSafeInteger(now) || now <= 0) return [];
    const rows = await this.members.find({ organizationId, recipientKeyId, active: true,
      'enrollment.challenge.expiresAt': { $gt: now } }, { limit: 16, sort: { updatedAt: 1, _id: 1 } }).toArray();
    return rows.map(row => ({ subject: row.subject, providerOrganizationId: row.providerOrganizationId, organizationId: row.organizationId,
      recipientKeyId: row.recipientKeyId, revision: row.revision, active: row.active, enrollment: row.enrollment }));
  }
  /** Enclave `LegalFirmStore`: signed setup statements kept with the organization row. */
  async getOrganizationSetup(organizationId: string) {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId)) return null;
    const row = await this.organizations.findOne({ _id: organizationId }, { projection: { setup: 1 } });
    if (!row) return null;
    return { custody: typeof row.setup?.custody === 'string' ? row.setup.custody : null,
      terms: typeof row.setup?.terms === 'string' ? row.setup.terms : null };
  }
  async putOrganizationSetup(organizationId: string, kind: 'custody' | 'terms', statement: string): Promise<boolean> {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId) || (kind !== 'custody' && kind !== 'terms') ||
        typeof statement !== 'string' || !statement.length || statement.length > 8192) return false;
    const result = await this.organizations.updateOne({ _id: organizationId, approved: true, revokedAt: { $exists: false } },
      { $set: { [`setup.${kind}`]: statement } });
    return result.matchedCount === 1;
  }
  /** Admin onboarding: the enclave's `issueInvitation` calls this over the storage
   * RPC (it is on CASE_STORE_RPC_METHODS). The row is untrusted; redemption
   * re-verifies the onboarding signature and token digest inside the enclave.
   * Stores only the token digest. */
  private invitationAfterRemoval(invitation: Omit<LegalInvitationDocument, '_id'>, member: LegalMemberDocument | null): boolean {
    if (!member?.removedAt) return true;
    const cutoff = member.removedAt.getTime();
    try {
      // The enclave verifies this signature. This host-side check only narrows
      // admission and cannot confer membership authority.
      const issuedAt = JSON.parse(invitation.authorization).statement.issuedAt;
      return Number.isSafeInteger(cutoff) && Number.isSafeInteger(issuedAt) && issuedAt > cutoff && invitation.createdAt > cutoff;
    } catch { return false; }
  }
  async insertInvitation(invitation: Omit<LegalInvitationDocument, '_id'>): Promise<void> {
    await this.transaction(async session => {
      // Writes serialize issuance with organization revocation/key replacement.
      const organization = await this.organizations.updateOne({ _id: invitation.organizationId, approved: true,
        revokedAt: { $exists: false }, recipientKeyId: invitation.recipientKeyId,
        providerOrganizationId: invitation.providerOrganizationId }, { $inc: { invitationRevision: 1 } }, { session });
      if (organization.matchedCount !== 1) throw new LegalOnboardingConflict('revoked');
      // Touch an existing member even when inactive. A concurrent removal forces
      // a transaction retry, which observes the persistent authorization cutoff.
      const member = await this.members.findOneAndUpdate({ _id: memberKey(invitation.providerOrganizationId, invitation.subject) },
        { $inc: { invitationRevision: 1 } }, { session });
      if (!this.invitationAfterRemoval(invitation, member)) throw new LegalOnboardingConflict('not-pending');
      await this.invitations.insertOne({ ...invitation, _id: invitation.tokenDigest }, { session });
      await this.audit({ action: 'invitation_issued', organizationId: invitation.organizationId, actor: invitation.createdBy,
        invitationId: invitation.invitationId, subject: invitation.subject }, invitation.createdAt, session);
    });
  }
  async getInvitation(tokenDigest: string) {
    if (typeof tokenDigest !== 'string' || !/^[a-f0-9]{64}$/.test(tokenDigest)) return null;
    const row = await this.invitations.findOne({ _id: tokenDigest });
    if (!row) return null;
    const { _id: _ignored, ...invitation } = row;
    return invitation;
  }
  /** One transaction: consume the exact pending invitation, recheck the approved
   * organization/key binding and write the member row. False changes nothing. */
  async commitEnrollment(expected: Omit<LegalInvitationDocument, '_id'>,
    member: { organizationId: string; subject: string; recipientKeyId: string; enrollment?: LegalMemberDocument['enrollment'] }, now: number): Promise<boolean> {
    if (!this.client) throw new Error('Confidential enrollment transactions require a Mongo client');
    const invitation = { ...expected }, row = { ...member };
    if ([invitation.tokenDigest, invitation.invitationId, row.organizationId, row.recipientKeyId].some(value =>
      typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) || typeof row.subject !== 'string' ||
        !Number.isSafeInteger(invitation.version) || !Number.isSafeInteger(now) || now <= 0) return false;
    const abort = new Error('enrollment conflict'), session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const previousMember = await this.members.findOne({ _id: memberKey(invitation.providerOrganizationId, row.subject) }, { session });
        if (!this.invitationAfterRemoval(invitation, previousMember)) throw abort;
        const consumed = await this.invitations.updateOne({ _id: invitation.tokenDigest, invitationId: invitation.invitationId,
          version: invitation.version, state: 'pending', expiresAt: { $gt: now }, organizationId: row.organizationId,
          subject: row.subject, recipientKeyId: row.recipientKeyId, providerOrganizationId: invitation.providerOrganizationId },
        { $set: { state: 'redeemed' }, $inc: { version: 1 } }, { session });
        const organization = await this.organizations.findOne({ _id: row.organizationId, approved: true,
          recipientKeyId: row.recipientKeyId, providerOrganizationId: invitation.providerOrganizationId }, { session });
        if (consumed.modifiedCount !== 1 || !organization) throw abort;
        await this.members.updateOne({ _id: memberKey(invitation.providerOrganizationId, row.subject) }, {
          $set: { subject: row.subject, providerOrganizationId: invitation.providerOrganizationId, organizationId: row.organizationId,
            recipientKeyId: row.recipientKeyId, enrollment: row.enrollment, active: true, updatedAt: new Date(now) }, $inc: { revision: 1 } }, { session, upsert: true });
        await this.audit({ action: 'invitation_redeemed', organizationId: row.organizationId, actor: row.subject,
          invitationId: invitation.invitationId, subject: row.subject }, now, session);
        return true;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } catch (error) {
      if (error === abort) return false;
      throw error;
    } finally { await session.endSession(); }
  }
  /** Enclave `LegalFirmStore`: untrusted rows, re-validated in the enclave. */
  async listFirmDevices(organizationId: string) {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId)) return [];
    // Retain removal history without letting it crowd live devices out of the
    // bounded enclave response. Read one extra live row so overflow fails closed
    // at the enclave instead of silently hiding a live device from its quota.
    const live = await this.devices.find({ organizationId, state: { $ne: 'removed' } },
      { limit: 129, sort: { registeredAt: 1, _id: 1 } }).toArray();
    if (live.length >= 128) return live.map(deviceRow);
    // Highest epochs preserve the warning that a removed keyholder still needs
    // a rotation. Old rows remain available for direct lookup and revocation.
    // Exclude live IDs in case a device was removed between these reads.
    const removed = await this.devices.find({ organizationId, state: 'removed', _id: { $nin: live.map(row => row._id) } },
      { limit: 128 - live.length, sort: { keyEpoch: -1, updatedAt: -1, _id: 1 } }).toArray();
    return [...live, ...removed].map(deviceRow);
  }
  async getFirmDevice(organizationId: string, memberId: string) {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId) || typeof memberId !== 'string' || !HEX64.test(memberId)) return null;
    const row = await this.devices.findOne({ _id: deviceKey(organizationId, memberId) });
    return row ? deviceRow(row) : null;
  }
  async putFirmDevice(device: Omit<FirmDeviceDocument, '_id'>, expectedRevision: number): Promise<boolean> {
    const row = deviceRow({ ...device, _id: '' });
    if (!HEX64.test(row.organizationId) || !HEX64.test(row.memberId) || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0 ||
        row.revision !== expectedRevision + 1) return false;
    const _id = deviceKey(row.organizationId, row.memberId);
    try {
      const write = async (session?: ClientSession) => {
        if (expectedRevision === 0) { await this.devices.insertOne({ _id, ...row }, { session }); return true; }
        const result = await this.devices.replaceOne({ _id, revision: expectedRevision }, row, { session });
        return result.modifiedCount === 1;
      };
      if (row.state !== 'pending') return await write();
      return await this.transaction(async session => {
        // The enclave's early count is a user-facing check, not an atomic quota.
        // Contend on one organization row before counting/inserting: a racing
        // transaction retries its snapshot and sees the slot already consumed.
        const locked = await this.organizations.updateOne({ _id: row.organizationId, approved: true,
          revokedAt: { $exists: false } }, { $inc: { deviceAdmissionRevision: 1 } }, { session });
        if (locked.matchedCount !== 1) return false;
        const count = await this.devices.countDocuments({ organizationId: row.organizationId,
          state: { $ne: 'removed' }, _id: { $ne: _id } }, { session, limit: 64 });
        if (count >= 64) return false;
        return write(session);
      });
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
  }
  /** Device state and authorization must commit together: a failed membership
   * update must not strand a removed device with an active enrollment. */
  async putFirmDeviceMembership(value: { organizationId: string; subject: string; providerOrganizationId: string;
    recipientKeyId: string; enrollment: NonNullable<LegalMemberDocument['enrollment']> & {
      delegation: { memberId: string; deviceFingerprint: string; deviceProof: string } } }, now: number): Promise<boolean> {
    if (!this.client || ![value.organizationId, value.recipientKeyId, value.enrollment.delegation.memberId].every(id => HEX64.test(id)) ||
        !Number.isSafeInteger(now) || value.enrollment.challenge.expiresAt <= now) return false;
    const session = this.client.startSession(), abort = new Error('Device enrollment changed');
    try {
      return await session.withTransaction(async () => {
        const device = await this.devices.findOne({ _id: deviceKey(value.organizationId, value.enrollment.delegation.memberId),
          state: 'approved', subject: value.subject, providerOrganizationId: value.providerOrganizationId,
          deviceFingerprint: value.enrollment.delegation.deviceFingerprint }, { session });
        if (!device) throw abort;
        const memberId = memberKey(value.providerOrganizationId, value.subject);
        const previous = await this.members.findOne({ _id: memberId }, { session });
        if (previous?.removedAt && previous.removedAt.getTime() >= device.updatedAt) throw abort;
        const organization = await this.organizations.updateOne({ _id: value.organizationId, approved: true,
          revokedAt: { $exists: false }, providerOrganizationId: value.providerOrganizationId, recipientKeyId: value.recipientKeyId },
        { $inc: { deviceAdmissionRevision: 1 } }, { session });
        if (organization.matchedCount !== 1) throw abort;
        // Write the device row so removal racing this transaction causes a conflict.
        await this.devices.updateOne({ _id: device._id }, { $inc: { membershipAdmissionRevision: 1 } }, { session });
        await this.members.updateOne({ _id: memberId }, { $set: { organizationId: value.organizationId, subject: value.subject,
          providerOrganizationId: value.providerOrganizationId, recipientKeyId: value.recipientKeyId,
          enrollment: value.enrollment, active: true, updatedAt: new Date(now) }, $inc: { revision: 1 } }, { session, upsert: true });
        return true;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } catch (error) { if (error === abort) return false; throw error; }
    finally { await session.endSession(); }
  }
  async removeFirmDevice(device: Omit<FirmDeviceDocument, '_id'>, expectedRevision: number): Promise<boolean> {
    const row = deviceRow({ ...device, _id: '' });
    if (!HEX64.test(row.organizationId) || !HEX64.test(row.memberId) || row.state !== 'removed' || row.envelope !== null ||
        row.continuity !== null || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1 ||
        row.revision !== expectedRevision + 1 || !Number.isSafeInteger(row.updatedAt) || row.updatedAt <= 0 ||
        typeof row.providerOrganizationId !== 'string' || typeof row.subject !== 'string') return false;
    return this.transaction(async session => {
      const changed = await this.devices.replaceOne({ _id: deviceKey(row.organizationId, row.memberId),
        revision: expectedRevision, state: { $ne: 'removed' }, providerOrganizationId: row.providerOrganizationId,
        subject: row.subject }, row, { session });
      if (changed.modifiedCount !== 1) return false;
      await this.deactivateFirmMemberInTransaction(row.organizationId, row.providerOrganizationId, row.subject, row.updatedAt, session);
      return true;
    });
  }
  /** Removal by the organization's steward, with the same effect as the admin
   * `removeLegalMember`: in one transaction the member row stops authorizing, the
   * durable `removedAt` cutoff is set (so only an approval issued afterwards can
   * re-enroll), the person's pending invitations for this organization are
   * withdrawn and the removal is written to the audit trail. */
  async deactivateFirmMember(organizationId: string, providerOrganizationId: string, subject: string, now: number): Promise<void> {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId) || typeof providerOrganizationId !== 'string' ||
        typeof subject !== 'string' || !Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid member removal');
    await this.transaction(session => this.deactivateFirmMemberInTransaction(organizationId, providerOrganizationId, subject, now, session));
  }
  private async deactivateFirmMemberInTransaction(organizationId: string, providerOrganizationId: string,
    subject: string, now: number, session?: ClientSession): Promise<void> {
      const _id = memberKey(providerOrganizationId, subject);
      const updated = await this.members.updateOne({ _id, organizationId, active: true },
        { $set: { active: false, updatedAt: new Date(now), removedAt: new Date(now) }, $inc: { revision: 1 } }, { session });
      // Already inactive but never cut off (e.g. a lapsed row): still set the cutoff
      // so an earlier invitation cannot bring the person back.
      if (updated.matchedCount !== 1) {
        await this.members.updateOne({ _id, organizationId, removedAt: { $exists: false } },
          { $set: { updatedAt: new Date(now), removedAt: new Date(now) }, $inc: { revision: 1 } }, { session });
      }
      const invitations = await this.invitations.updateMany({ organizationId, subject, state: 'pending' },
        { $set: { state: 'revoked', revokedAt: now, revokedBy: STEWARD_ACTOR }, $inc: { version: 1 } }, { session });
      if (updated.matchedCount === 1 || invitations.modifiedCount > 0) {
        await this.audit({ action: 'member_removed', organizationId, actor: STEWARD_ACTOR, subject }, now, session);
      }
  }

  async getFirmSharedList(organizationId: string) {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId)) return null;
    const row = await this.sharedLists.findOne({ _id: organizationId });
    return row ? { version: row.version, record: row.record } : null;
  }
  async putFirmSharedList(organizationId: string, expectedVersion: number, next: { version: number; record: string }): Promise<boolean> {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId) || !Number.isSafeInteger(expectedVersion) ||
        expectedVersion < 0 || next.version !== expectedVersion + 1 || typeof next.record !== 'string') return false;
    try {
      if (expectedVersion === 0) {
        await this.sharedLists.insertOne({ _id: organizationId, version: next.version, record: next.record });
        return true;
      }
      const result = await this.sharedLists.updateOne({ _id: organizationId, version: expectedVersion },
        // Also drops the write time that rows from before this change carried.
        { $set: { version: next.version, record: next.record }, $unset: { updatedAt: '' } });
      return result.modifiedCount === 1;
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
  }
  /** Member removal / re-binding (host admin path, not on the enclave RPC allowlist). */
  async upsertLegalMember(value: { subject: string; providerOrganizationId: string; organizationId: string;
    recipientKeyId: string; active: boolean }, now: number): Promise<void> {
    await this.members.updateOne({ _id: memberKey(value.providerOrganizationId, value.subject) }, {
      $set: { subject: value.subject, providerOrganizationId: value.providerOrganizationId, organizationId: value.organizationId,
        recipientKeyId: value.recipientKeyId, active: value.active, updatedAt: new Date(now) },
      $inc: { revision: 1 } }, { upsert: true });
  }
  // ---- Admin onboarding (host admin routes only; none of these is on the enclave RPC allowlist) ----

  private async transaction<T>(work: (session?: ClientSession) => Promise<T>): Promise<T> {
    if (!this.client) throw new Error('Legal onboarding transactions require a Mongo client');
    const session = this.client.startSession();
    try {
      let result!: T;
      await session.withTransaction(async () => { result = await work(session); },
        { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
      return result;
    } finally { await session.endSession(); }
  }
  private async audit(event: Omit<LegalAuditDocument, '_id' | 'at'>, now: number, session?: ClientSession): Promise<void> {
    await this.legalAudit.insertOne({ _id: auditId(), at: new Date(now), ...event }, { session });
  }

  private async migrateLegalOrganizationClaims(): Promise<void> {
    const rows = this.organizations.find({ revokedAt: { $exists: false } }, { projection: { _id: 1 } });
    for await (const row of rows) {
      try {
        await this.transaction(async session => {
          const current = await this.organizations.findOne({ _id: row._id, revokedAt: { $exists: false } }, { session });
          if (!current) return;
          if (typeof current.domain !== 'string' || !current.domain ||
              (current.providerOrganizationId !== undefined && typeof current.providerOrganizationId !== 'string')) {
            throw new Error('Invalid legacy legal organization claims');
          }
          await this.organizations.updateOne({ _id: current._id, revokedAt: { $exists: false } }, {
            $set: { domainClaim: current.domain,
              ...(current.providerOrganizationId ? { providerClaim: current.providerOrganizationId } : {}) },
          }, { session });
        });
      } catch (error) {
        if (duplicateKey(error)) throw claimConflict(error);
        throw error;
      }
    }
  }

  /** Creates the organization record the firm binds its key to. Not approved and
   * not usable by any firm operation until the onboarding authority registers it. */
  async createLegalOrganization(value: { organizationId: string; displayName: string; domain: string; providerOrganizationId: string },
    actor: string, now: number): Promise<void> {
    try {
      await this.transaction(async session => {
        await this.organizations.insertOne({ _id: value.organizationId, displayName: value.displayName, domain: value.domain,
          publicKey: '', approved: false, providerOrganizationId: value.providerOrganizationId, createdAt: new Date(now),
          createdBy: actor, updatedAt: new Date(now), providerClaim: value.providerOrganizationId, domainClaim: value.domain }, { session });
        await this.audit({ action: 'organization_created', organizationId: value.organizationId, actor }, now, session);
      });
    } catch (error) {
      if (duplicateKey(error)) throw claimConflict(error);
      throw error;
    }
  }
  async listLegalOrganizationRecords(): Promise<LegalOrganizationDocument[]> {
    return this.organizations.find({}, { limit: 500, sort: { createdAt: -1, displayName: 1 },
      projection: { providerClaim: 0, domainClaim: 0 } }).toArray();
  }
  async getLegalOrganizationRecord(organizationId: string): Promise<LegalOrganizationDocument | null> {
    return this.organizations.findOne({ _id: organizationId }, { projection: { providerClaim: 0, domainClaim: 0 } });
  }
  /** Retire cryptographic roster claims only after Auth0 confirms deletion. An
   * outage, disabled organization or denied application is never a deletion. */
  async retireDeletedLegalOrganizations(domain: string, directory: ApplicationOrganizations, signal: AbortSignal): Promise<void> {
    const rows = await this.organizations.find({ domainClaim: domain, revokedAt: { $exists: false } }).toArray();
    for (const row of rows) {
      if (!row.providerOrganizationId || await directory.getById(row.providerOrganizationId, signal)) continue;
      signal.throwIfAborted();
      await this.revokeLegalOrganization(row._id, 'system:auth0-organization-deleted', Date.now());
    }
  }
  private legalMemberProvider: ApplicationIdentityProvider | null = null;
  configureLegalMemberInvitations(provider: ApplicationIdentityProvider | null): void { this.legalMemberProvider = provider; }
  async queueLegalAuth0Membership(approval: LegalMembershipApproval): Promise<void> {
    await this.auth0Memberships.queue(approval);
  }
  async legalAuth0MembershipPrepared(approval: LegalMembershipApproval): Promise<boolean> {
    return this.auth0Memberships.prepared(approval.organizationId, approval.email, approval.approvalId);
  }
  async provisionLegalAuth0Membership(): Promise<boolean> {
    if (!this.legalMemberProvider?.nativeEntry) return false;
    return this.auth0Memberships.runOne(this.legalMemberProvider, async (target, subject) => {
      const organization = await this.getLegalOrganizationRecord(target.organizationId);
      if (!organization || organization.revokedAt || organization.domain !== target.domain ||
          organization.providerOrganizationId !== target.providerOrganizationId) return false;
      return !subject || !await this.members.findOne({ organizationId: target.organizationId, subject,
        removedAt: { $exists: true } }, { projection: { _id: 1 } });
    }, Date.now(), async target => {
      // Re-confirms the deletion by id before revoking the roster entry.
      const directory = this.legalMemberProvider?.applicationOrganizations;
      if (directory) await this.retireDeletedLegalOrganizations(target.domain, directory, AbortSignal.timeout(30_000));
    });
  }
  async inviteLegalOrganizationMember(value: { organizationId: string; providerOrganizationId: string;
    domain: string; email: string }, now: number): Promise<{ invited: true }> {
    const provider = this.legalMemberProvider;
    if (!provider?.inviteMember || !/^[a-f0-9]{64}$/.test(value.organizationId) || !Number.isSafeInteger(now))
      throw new LegalOnboardingConflict('mismatch');
    const row = await this.getLegalOrganizationRecord(value.organizationId);
    if (!row || row.revokedAt || !row.approved || !row.registration || row.domain !== value.domain ||
        row.providerOrganizationId !== value.providerOrganizationId || typeof value.email !== 'string' ||
        value.email.length > 254 || value.email !== value.email.toLowerCase() ||
        !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(value.email) || value.email.split('@')[1] !== row.domain)
      throw new LegalOnboardingConflict('mismatch');
    // Reserve before the email side effect. All instances share the same quota
    // and per-address lease; an ambiguous provider timeout retains its cooldown.
    const emailDigest = createHash('sha256').update(value.email).digest('hex'), leaseId = randomBytes(16).toString('hex');
    const reserved = await this.transaction(async session => {
      if (!session) throw new LegalOnboardingConflict('mismatch');
      const current = await this.organizations.findOne({ _id: value.organizationId, approved: true,
        revokedAt: { $exists: false }, domain: value.domain, providerOrganizationId: value.providerOrganizationId }, { session });
      if (!current) throw new LegalOnboardingConflict('mismatch');
      const leases = Object.fromEntries(Object.entries(current.memberInvitationLeases ?? {}).filter(([, lease]) => lease.until > now));
      if (leases[emailDigest]) {
        if (leases[emailDigest].sent) return false;
        throw new Error('Legal invitation already pending; try again later');
      }
      const window = typeof current.memberInvitationWindow === 'number' && current.memberInvitationWindow + 3_600_000 > now
        ? current.memberInvitationWindow : now;
      const attempts = window === current.memberInvitationWindow ? current.memberInvitationAttempts ?? 0 : 0;
      if (attempts >= 20) throw new Error('Legal invitation limit reached; try again later');
      leases[emailDigest] = { id: leaseId, until: now + 600_000, sent: false };
      await this.organizations.updateOne({ _id: value.organizationId }, { $set: {
        memberInvitationWindow: window, memberInvitationAttempts: attempts + 1, memberInvitationLeases: leases } }, { session });
      return true;
    });
    if (!reserved) return { invited: true };
    if (provider.nativeEntry) {
      await this.queueLegalAuth0Membership({ ...value,
        approvalId: createHash('sha256').update(leaseId).digest('hex'), expires: now + 7 * 86_400_000 });
    } else {
      await this.organizations.updateOne({ _id: value.organizationId, approved: true, revokedAt: { $exists: false } },
        { $set: { [`memberSignInApprovals.${emailDigest}`]: now + 7 * 86_400_000 } });
      await provider.inviteMember({ providerOrganizationId: value.providerOrganizationId, domain: value.domain, email: value.email }, AbortSignal.timeout(25_000));
    }
    await this.organizations.updateOne({ _id: value.organizationId, [`memberInvitationLeases.${emailDigest}.id`]: leaseId },
      { $set: { [`memberInvitationLeases.${emailDigest}.sent`]: true } });
    return { invited: true };
  }
  /** An exact pending approval, or a current Auth0 member, may use native OTP.
   * Same-domain addresses alone never qualify. This grants no report authority. */
  async legalSignInTarget(email: string, providerOrganizationId?: string) {
    const domain = email.split('@')[1];
    const rows = await this.organizations.find({ domain, revokedAt: { $exists: false },
      ...(providerOrganizationId ? { providerOrganizationId } : {}) }).limit(2).toArray();
    if (rows.length !== 1) return null;
    const row = rows[0];
    if (!row?.providerOrganizationId) return null;
    const digest = createHash('sha256').update(email).digest('hex');
    // A rollback to the legacy callback must not replay a native grant that
    // may already have succeeded (and subsequently been removed in Auth0).
    const pending = !await this.auth0Memberships.consumed(row._id, email) &&
      (await this.applications.firstSignInApproved(row._id, email) ||
      (row.approved && (row.memberSignInApprovals?.[digest] ?? 0) > Date.now()));
    return { organizationId: row._id, providerOrganizationId: row.providerOrganizationId, domain, email, pending };
  }
  async consumeLegalSignInApproval(organizationId: string, email: string, subject: string) {
    await this.applications.consumeFirstSignIn(organizationId, email, subject);
    const digest = createHash('sha256').update(email).digest('hex');
    await this.organizations.updateOne({ _id: organizationId }, { $unset: { [`memberSignInApprovals.${digest}`]: '' } });
  }
  async registerFirstApplicationKey(value: { organizationId: string; providerOrganizationId: string; recipientKeyId: string;
    publicKey: string; displayName: string; domain: string; registration?: string; bindingDocument?: string; approved: boolean }, now: number) {
    if (!value.approved || !value.registration || !value.bindingDocument || !HEX64.test(value.organizationId) || !HEX64.test(value.recipientKeyId)) throw new LegalOnboardingConflict('mismatch');
    await this.transaction(async session => {
      // An activation retry must not roll back a newer, same-key public profile
      // or increment the device admission revision a second time.
      const existing = await this.organizations.findOne({ _id: value.organizationId }, { session });
      if (existing?.approved && existing.revokedAt === undefined && existing.domain === value.domain &&
          existing.providerOrganizationId === value.providerOrganizationId && existing.registration === value.registration &&
          existing.publicKey === value.publicKey && existing.recipientKeyId === value.recipientKeyId) return;
      const filter = { _id: value.organizationId, domain: value.domain, providerOrganizationId: value.providerOrganizationId,
        revokedAt: { $exists: false }, registration: { $exists: false }, $or: [{ publicKey: '' }, { publicKey: { $exists: false } }] };
      const result = await this.organizations.updateOne(filter, { $set: { approved: true, publicKey: value.publicKey,
        recipientKeyId: value.recipientKeyId, registration: value.registration, bindingDocument: value.bindingDocument,
        displayName: value.displayName, updatedAt: new Date(now) }, $inc: { deviceAdmissionRevision: 1 } }, { session });
      if (result.matchedCount !== 1) throw new LegalOnboardingConflict('mismatch');
      await this.audit({ action: 'organization_registered', organizationId: value.organizationId, actor: 'combined Slack approval authority' }, now, session);
    });
  }
  async getApplicationApproval(organizationId: string) {
    if (!HEX64.test(organizationId)) return null;
    return this.applications.getCombinedApproval(organizationId);
  }
  async queueFirstApplicationKeyReview(organizationId: string, providerOrganizationId: string, enrollment: {
    organizationId: string; recipientKeyId: string; bindingDocument: string }, now: number) {
    const row = await this.organizations.findOne({ _id: organizationId, providerOrganizationId, approved: false,
      revokedAt: { $exists: false }, registration: { $exists: false }, candidateRecipientKeyId: enrollment.recipientKeyId,
      candidateBindingDocument: enrollment.bindingDocument });
    if (!row || enrollment.organizationId !== organizationId) throw new LegalOnboardingConflict('mismatch');
    await this.applications.queueFirstKeyReview(organizationId, providerOrganizationId, enrollment, now);
  }
  async getLegalOrganizationKeySetup(organizationId: string) {
    if (typeof organizationId !== 'string' || !HEX64.test(organizationId)) return null;
    return this.organizations.findOne({ _id: organizationId },
      // `approved` lets the enclave tell a first-time applicant (awaiting its key)
      // from a failure; it is not secret and grants nothing on its own.
      { projection: { _id: 1, domain: 1, providerOrganizationId: 1, revokedAt: 1, approved: 1 } });
  }
  async submitLegalOrganizationKeyCandidate(value: { organizationId: string; providerOrganizationId: string;
    domain: string; bindingDocument: string; subject: string; recipientKeyId: string;
    previousRecipientKeyId?: string; continuity?: string }, now: number): Promise<void> {
    const change = value.previousRecipientKeyId !== undefined || value.continuity !== undefined;
    if (!/^[a-f0-9]{64}$/.test(value.organizationId) || !/^[a-f0-9]{64}$/.test(value.recipientKeyId) ||
        typeof value.bindingDocument !== 'string' || value.bindingDocument.length > 65_536 ||
        value.bindingDocument.includes('PRIVATE KEY') || !Number.isSafeInteger(now) ||
        (change && (typeof value.previousRecipientKeyId !== 'string' || !/^[a-f0-9]{64}$/.test(value.previousRecipientKeyId) ||
          value.previousRecipientKeyId === value.recipientKeyId || typeof value.continuity !== 'string' ||
          value.continuity.length > 65_536 || value.continuity.includes('PRIVATE KEY')))) throw new LegalOnboardingConflict('mismatch');
    // A profile signed by the already registered key may be refreshed directly.
    // It never changes the recipient key or its authority-signed registration.
    const profile = value.previousRecipientKeyId === undefined && await this.organizations.updateOne({ _id: value.organizationId, approved: true,
      providerOrganizationId: value.providerOrganizationId, domain: value.domain, recipientKeyId: value.recipientKeyId,
      revokedAt: { $exists: false } }, { $set: { bindingDocument: value.bindingDocument, updatedAt: new Date(now) } });
    if (profile && profile.matchedCount === 1) {
      await this.organizations.updateOne({ _id: value.organizationId, candidateRecipientKeyId: value.recipientKeyId },
        { $unset: { candidateBindingDocument: '', candidateSubject: '', candidateRecipientKeyId: '', candidateContinuity: '' } });
      return;
    }
    // A candidate is public metadata only; activation still requires the
    // onboarding authority. Without a continuity statement only a never-registered
    // organization accepts one, so a colleague cannot plant a replacement. A
    // replacement arrives only through the enclave's enrolled-member operation with
    // a fresh proof and continuity from the registered key; compare that key
    // atomically so an intervening registration cannot accept a stale submission.
    const state = change
      ? { approved: true, recipientKeyId: value.previousRecipientKeyId, registration: { $exists: true } }
      : { approved: false, registration: { $exists: false }, $or: [{ publicKey: '' }, { publicKey: { $exists: false } }] };
    const result = await this.organizations.updateOne({ _id: value.organizationId,
      providerOrganizationId: value.providerOrganizationId, domain: value.domain, revokedAt: { $exists: false }, ...state },
    { $set: { candidateBindingDocument: value.bindingDocument, candidateSubject: value.subject,
      candidateRecipientKeyId: value.recipientKeyId, updatedAt: new Date(now),
      ...(change ? { candidateContinuity: value.continuity } : {}) },
    ...(change ? {} : { $unset: { candidateContinuity: '' } }) });
    if (result.matchedCount !== 1) throw new LegalOnboardingConflict('mismatch');
  }
  /** Pending (unexpired) invitations and currently active members, per organization.
   * A member counts as active only while enrolled with the organization's current
   * key: after a key replacement the enclave denies members bound to the old key
   * (`verifiedOrganization` requires a match), so they need a new invitation. */
  async countLegalOnboarding(now: number): Promise<Record<string, { pendingInvitations: number; activeMembers: number }>> {
    const [invitations, members] = await Promise.all([
      this.invitations.aggregate<{ _id: string; n: number }>([{ $match: { state: 'pending', expiresAt: { $gt: now } } },
        { $group: { _id: '$organizationId', n: { $sum: 1 } } }]).toArray(),
      this.members.aggregate<{ _id: { organizationId: string; recipientKeyId: string }; n: number }>([
        { $match: { active: true, 'enrollment.challenge.expiresAt': { $gt: now } } },
        { $group: { _id: { organizationId: '$organizationId', recipientKeyId: '$recipientKeyId' }, n: { $sum: 1 } } }]).toArray(),
    ]);
    const organizationIds = [...new Set(members.map(row => row._id.organizationId))];
    const currentKeys = new Map<string, string>();
    if (organizationIds.length) {
      for (const row of await this.organizations.find({ _id: { $in: organizationIds } }, { projection: { recipientKeyId: 1 } }).toArray()) {
        if (typeof row.recipientKeyId === 'string') currentKeys.set(row._id, row.recipientKeyId);
      }
    }
    const counts: Record<string, { pendingInvitations: number; activeMembers: number }> = {};
    const entry = (id: string) => (counts[id] ??= { pendingInvitations: 0, activeMembers: 0 });
    for (const row of invitations) entry(row._id).pendingInvitations = row.n;
    for (const row of members) {
      const current = currentKeys.get(row._id.organizationId);
      if (current !== undefined && row._id.recipientKeyId === current) entry(row._id.organizationId).activeMembers += row.n;
    }
    return counts;
  }
  /** Never returns the token digest, nonce or signed authorization. */
  async listLegalInvitationRecords(organizationId: string) {
    return this.invitations.find({ organizationId }, { limit: 200, sort: { createdAt: -1 },
      projection: { _id: 0, invitationId: 1, organizationId: 1, subject: 1, createdAt: 1, createdBy: 1, expiresAt: 1,
        state: 1, revokedAt: 1, revokedBy: 1 } }).toArray() as Promise<Pick<LegalInvitationDocument,
        'invitationId' | 'organizationId' | 'subject' | 'createdAt' | 'createdBy' | 'expiresAt' | 'state' | 'revokedAt' | 'revokedBy'>[]>;
  }
  /** Never returns the enrollment proof or authorization. `keyReplaced` marks a
   * person enrolled with a key the organization has since replaced: the enclave
   * denies them until they accept a new invitation bound to the current key. */
  async listLegalMemberRecords(organizationId: string) {
    const [organization, rows] = await Promise.all([
      this.organizations.findOne({ _id: organizationId }, { projection: { recipientKeyId: 1 } }),
      this.members.find({ organizationId }, { limit: 500, sort: { updatedAt: -1 },
        projection: { _id: 0, subject: 1, active: 1, updatedAt: 1, recipientKeyId: 1, 'enrollment.challenge.expiresAt': 1,
          'enrollment.challenge.invitationId': 1 } }).toArray(),
    ]);
    const current = typeof organization?.recipientKeyId === 'string' ? organization.recipientKeyId : null;
    return rows.map(row => ({ subject: row.subject, active: row.active, updatedAt: row.updatedAt,
      leaseExpiresAt: row.enrollment?.challenge?.expiresAt ?? null, invitationId: row.enrollment?.challenge?.invitationId ?? null,
      keyReplaced: current === null || row.recipientKeyId !== current }));
  }
  /** Pending invitations only (expired or not). A revoked invitation can never be
   * redeemed: `commitEnrollment` requires `state: 'pending'`. */
  async revokeLegalInvitation(invitationId: string, actor: string, now: number): Promise<void> {
    await this.transaction(async session => {
      const found = await this.invitations.findOneAndUpdate({ invitationId, state: 'pending' },
        { $set: { state: 'revoked', revokedAt: now, revokedBy: actor }, $inc: { version: 1 } },
        { session, projection: { organizationId: 1, subject: 1 } });
      if (!found) {
        const exists = await this.invitations.findOne({ invitationId }, { session, projection: { _id: 1 } });
        throw new LegalOnboardingConflict(exists ? 'not-pending' : 'not-found');
      }
      await this.audit({ action: 'invitation_revoked', organizationId: found.organizationId, actor, invitationId,
        subject: found.subject }, now, session);
    });
  }
  /** Final. Removes the organization from the owner roster and every firm operation
   * (the enclave requires `approved`), withdraws pending invitations and deactivates
   * members. Keys or plaintext already downloaded by the firm cannot be recalled. */
  async revokeLegalOrganization(organizationId: string, actor: string, now: number): Promise<{ invitationsRevoked: number; membersRemoved: number }> {
    return this.transaction(async session => {
      const updated = await this.organizations.updateOne({ _id: organizationId, revokedAt: { $exists: false } },
        { $set: { approved: false, revokedAt: new Date(now), revokedBy: actor, updatedAt: new Date(now) },
          $unset: { providerClaim: '', domainClaim: '' } }, { session });
      if (updated.matchedCount !== 1) {
        const exists = await this.organizations.findOne({ _id: organizationId }, { session, projection: { _id: 1 } });
        throw new LegalOnboardingConflict(exists ? 'revoked' : 'not-found');
      }
      const invitations = await this.invitations.updateMany({ organizationId, state: 'pending' },
        { $set: { state: 'revoked', revokedAt: now, revokedBy: actor }, $inc: { version: 1 } }, { session });
      const members = await this.members.updateMany({ organizationId, active: true },
        { $set: { active: false, updatedAt: new Date(now) }, $inc: { revision: 1 } }, { session });
      await this.audit({ action: 'organization_revoked', organizationId, actor }, now, session);
      return { invitationsRevoked: invitations.modifiedCount, membersRemoved: members.modifiedCount };
    });
  }
  /** Deactivates one member, sets the durable `removedAt` cutoff and withdraws that
   * person's pending invitations so a forwarded or earlier link cannot re-enroll
   * them. Mirrors the steward's `deactivateFirmMember`: a row that is already
   * inactive but was never cut off still gets the cutoff. `not-found` only when
   * there was nothing left to remove. */
  async removeLegalMember(organizationId: string, subject: string, actor: string, now: number): Promise<void> {
    await this.transaction(async session => {
      const updated = await this.members.updateOne({ organizationId, subject, active: true },
        { $set: { active: false, updatedAt: new Date(now), removedAt: new Date(now) }, $inc: { revision: 1 } }, { session });
      const cutoff = updated.matchedCount === 1 ? updated
        : await this.members.updateOne({ organizationId, subject, removedAt: { $exists: false } },
          { $set: { active: false, updatedAt: new Date(now), removedAt: new Date(now) }, $inc: { revision: 1 } }, { session });
      const invitations = await this.invitations.updateMany({ organizationId, subject, state: 'pending' },
        { $set: { state: 'revoked', revokedAt: now, revokedBy: actor }, $inc: { version: 1 } }, { session });
      if (cutoff.matchedCount !== 1 && invitations.modifiedCount === 0) throw new LegalOnboardingConflict('not-found');
      await this.audit({ action: 'member_removed', organizationId, actor, subject }, now, session);
    });
  }
  /** Newest first. `before` is the cursor of the last event already shown. */
  async listLegalAudit(input: { organizationId?: string; before?: { at: number; id: string }; limit: number }): Promise<LegalAuditDocument[]> {
    const filter: Record<string, unknown> = {};
    if (input.organizationId) filter.organizationId = input.organizationId;
    if (input.before) {
      const at = new Date(input.before.at);
      filter.$or = [{ at: { $lt: at } }, { at, _id: { $lt: input.before.id } }];
    }
    return this.legalAudit.find(filter, { sort: { at: -1, _id: -1 }, limit: input.limit }).toArray();
  }

  async getStagedObject(ciphertextDigest: string): Promise<string | null> {
    const found = await this.staged.findOne({ _id: ciphertextDigest, expiresAt: { $gt: new Date() } }, { projection: { ciphertext: 1 } });
    return found?.ciphertext ?? null;
  }

  async putObjects(caseId: string, objects: StoredObject[]): Promise<void> {
    if (!objects.length) return;
    // Content-addressed by digest: retries and duplicates are idempotent.
    await this.objects.bulkWrite(objects.map(item => ({ updateOne: {
      filter: { _id: `${caseId}_${item.objectId}_${item.ciphertextDigest}` },
      update: { $setOnInsert: { caseId, objectId: item.objectId, ciphertextDigest: item.ciphertextDigest,
        ciphertext: item.ciphertext, ownerEnvelope: item.ownerEnvelope } },
      upsert: true } })), { ordered: false });
  }
  async getObjects(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]): Promise<StoredObject[]> {
    if (!refs.length) return [];
    const rows = await this.objects.find({ _id: { $in: refs.map(ref => `${caseId}_${ref.objectId}_${ref.ciphertextDigest}`) } }).toArray();
    return rows.map(({ objectId, ciphertextDigest, ciphertext, ownerEnvelope }) =>
      ({ objectId, ciphertextDigest, ciphertext, ownerEnvelope }));
  }
  async getEnvelopes(caseId: string, recipientKeyId: string): Promise<StoredEnvelope[]> {
    const record = await this.cases.findOne({ _id: caseId }, { projection: { envelopes: 1 } });
    const byKey = new Map(Object.values(record?.envelopes ?? {}).filter(item => item.recipientKeyId === recipientKeyId)
      .map(item => [envelopeKey(item.objectId, item.recipientKeyId), item]));
    for (const row of await this.caseEnvelopes.find({ caseId, recipientKeyId }).toArray()) {
      byKey.set(envelopeKey(row.objectId, row.recipientKeyId), { objectId: row.objectId, recipientKeyId: row.recipientKeyId, envelope: row.envelope });
    }
    return [...byKey.values()];
  }
  /** Segmented checkpoints after the embedded ones, bounded by the counts read
   * with the case document so a concurrent commit cannot add a trailing entry. */
  private async historyAfter(record: CaseDocument, session?: ClientSession): Promise<string[]> {
    const embedded = Array.isArray(record.checkpoints) ? record.checkpoints.length : 0;
    const count = record.historyCount ?? 0;
    if (!count) return [];
    const rows = await this.history.find({ caseId: record._id, index: { $gte: embedded, $lt: embedded + count } },
      { session, sort: { index: 1 }, projection: { index: 1, checkpoint: 1 } }).toArray();
    if (rows.length !== count || rows.some((row, offset) => row.index !== embedded + offset)) {
      throw new Error('Confidential case history incomplete');
    }
    return rows.map(row => row.checkpoint);
  }
  /** Every segmented statement, exactly: positions 0..statementCount-1 as counted
   * on the case document read, each row bound to its case and digest. A missing,
   * duplicated or foreign row fails closed instead of returning a smaller map. */
  private async statementsAfter(record: CaseDocument): Promise<Record<string, string>> {
    const count = record.statementCount ?? 0;
    if (!count) return {};
    const rows = await this.caseStatements.find({ caseId: record._id, index: { $gte: 0, $lt: count } },
      { sort: { index: 1 }, projection: { _id: 1, caseId: 1, digest: 1, index: 1, wire: 1 } }).toArray();
    if (rows.length !== count || rows.some((row, offset) => !this.statementRowValid(record._id, row) || row.index !== offset)) {
      throw new Error('Confidential case statements incomplete');
    }
    return Object.fromEntries(rows.map(row => [row.digest, row.wire]));
  }
  private statementRowValid(caseId: string, row: Pick<StatementDocument, '_id' | 'caseId' | 'digest' | 'wire'>): boolean {
    return row.caseId === caseId && typeof row.digest === 'string' && HEX64.test(row.digest) &&
      row._id === statementRowId(caseId, row.digest) && typeof row.wire === 'string';
  }
  /** Exact segmented rows for these digests of one case (bounded by the caller). */
  private async statementRows(caseId: string, digests: string[]): Promise<Map<string, string>> {
    const wanted = [...new Set(digests.filter(digest => HEX64.test(digest)))];
    if (!wanted.length) return new Map();
    const rows = await this.caseStatements.find({ _id: { $in: wanted.map(digest => statementRowId(caseId, digest)) } },
      { projection: { _id: 1, caseId: 1, digest: 1, wire: 1 } }).toArray();
    return new Map(rows.filter(row => this.statementRowValid(caseId, row)).map(row => [row.digest, row.wire]));
  }
  /** Bounded public statements of one case: the listing named by the pointer and
   * at most `releaseLimit` release approvals, newest claimed revision first. The
   * genesis (or legacy) embedded map is read with the document; segmented rows are
   * read by exact key or through the kind/revision index, never all of them. */
  private async boundedStatements(record: CaseDocument, releaseLimit: number): Promise<Record<string, string>> {
    const embedded = record.statements ?? {};
    const statements: Record<string, string> = {};
    const listing = typeof record.listingDigest === 'string' && HEX64.test(record.listingDigest) ? record.listingDigest : null;
    if (listing) {
      const segmented = (record.statementCount ?? 0) === 0 ? undefined : (await this.statementRows(record._id, [listing])).get(listing);
      const wire = segmented ??
        (Object.prototype.hasOwnProperty.call(embedded, listing) ? embedded[listing] : undefined);
      if (typeof wire === 'string') statements[listing] = wire;
    }
    if (releaseLimit > 0) {
      const releases = new Map<string, { wire: string; revision: number | null }>();
      for (const [digest, wire] of Object.entries(embedded)) {
        const claimed = typeof wire === 'string' ? claimedStatement(wire) : null;
        if (claimed?.kind === 'release') releases.set(digest, { wire, revision: claimed.revision });
      }
      const rows = (record.statementCount ?? 0) === 0 ? [] : await this.caseStatements.find({ caseId: record._id, kind: 'release' },
        { sort: { revision: -1, _id: 1 }, limit: releaseLimit, projection: { _id: 1, caseId: 1, digest: 1, wire: 1, revision: 1 } }).toArray();
      for (const row of rows) if (this.statementRowValid(record._id, row)) releases.set(row.digest, { wire: row.wire, revision: row.revision });
      const newest = [...releases.entries()].sort(([a, x], [b, y]) => (y.revision ?? -1) - (x.revision ?? -1) || (a < b ? -1 : a > b ? 1 : 0))
        .slice(0, releaseLimit);
      for (const [digest, item] of newest) statements[digest] = item.wire;
    }
    return statements;
  }

  async createCase(record: CaseRecord): Promise<boolean> {
    try {
      // The genesis statements (bounded per commit) stay embedded, like the genesis
      // checkpoint; every later statement is a segment row.
      await this.cases.insertOne({ ...record, _id: record.caseId, envelopes: {},
        embeddedHistoryLength: record.checkpoints.length, historyCount: 0, statementCount: 0 });
      return true;
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
  }
  /** `recipientKeyId` null is the authenticated owner: the object's owner
   * envelope is returned instead of a recipient envelope. */
  async readGrantedObjects(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
    refs: { objectId: string; ciphertextDigest: string }[], range?: { offset: number; length: number }): Promise<{
      objectId: string; ciphertextDigest: string; ciphertext: string; recipientEnvelope: string; totalBytes?: number;
    }[] | null> {
    if (!this.client) throw new Error('Confidential object transactions require a Mongo client');
    if ([caseId, checkpointDigest, ...(recipientKeyId === null ? [] : [recipientKeyId])].some(value => !/^[a-f0-9]{64}$/.test(value)) ||
        !Array.isArray(refs) || refs.length > 256 || new Set(refs.map(ref => ref.objectId)).size !== refs.length ||
        refs.some(ref => !/^[a-f0-9]{64}$/.test(ref.objectId) || !/^[a-f0-9]{64}$/.test(ref.ciphertextDigest))) throw new Error('Invalid object read guard');
    if (range && (Object.keys(range).sort().join(',') !== 'length,offset' || refs.length !== 1 ||
        !Number.isSafeInteger(range.offset) || range.offset < 0 || range.offset > 16 * 1024 * 1024 ||
        !Number.isSafeInteger(range.length) || range.length < 0 || range.length > 128 * 1024 ||
        (range.length === 0 && range.offset !== 0))) throw new Error('Invalid object range');
    const window = range ? { ...range } : undefined;
    const expected = refs.map(ref => ({ ...ref })), session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const record = await this.cases.findOneAndUpdate({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1 } }, { session, returnDocument: 'after', projection: { envelopes: 1 } });
        if (!record) return null;
        const result = [];
        let totalBytes = 0;
        for (const ref of expected) {
          // null recipient is the authenticated owner: the object's owner envelope.
          let envelope: StoredEnvelope | null = null;
          if (recipientKeyId !== null) {
            envelope = await this.recipientEnvelope(session, record, caseId, ref.objectId, recipientKeyId);
            if (!envelope) return null;
          }
          const id = `${caseId}_${ref.objectId}_${ref.ciphertextDigest}`;
          const ownerField = recipientKeyId === null ? { ownerEnvelope: 1 } : {};
          // DocumentDB 5.0 accepts only inclusion/exclusion, $, $elemMatch and
          // $slice in find projections, so the byte window is computed in an
          // aggregation $project, where $substrBytes and $strLenBytes are
          // supported. Limit to one but request room for two so EOF is observed
          // in the first batch; batchSize:1 otherwise triggers getMore even for
          // one result, which DocumentDB transactions do not support.
          const item = window ? (await this.objects.aggregate<{ objectId: string; ciphertextDigest: string; ciphertext: string; totalBytes: number; ownerEnvelope?: string }>([
            { $match: { _id: id } },
            { $limit: 1 },
            { $project: { _id: 0, objectId: 1, ciphertextDigest: 1, ...ownerField, totalBytes: { $strLenBytes: '$ciphertext' },
              ciphertext: { $substrBytes: ['$ciphertext', window.offset, window.length] } } },
          ], { session, batchSize: 2 }).toArray())[0] ?? null
            : await this.objects.findOne({ _id: id }, { session, projection: { objectId: 1, ciphertextDigest: 1, ciphertext: 1, ...ownerField } });
          const wrapped = recipientKeyId === null ? item?.ownerEnvelope : envelope?.envelope;
          if (!item || item.objectId !== ref.objectId || item.ciphertextDigest !== ref.ciphertextDigest ||
              typeof item.ciphertext !== 'string' || typeof wrapped !== 'string' || wrapped.length > 16384) return null;
          totalBytes += Buffer.byteLength(item.ciphertext, 'utf8') + Buffer.byteLength(wrapped, 'utf8');
          if (totalBytes > 40 * 1024 * 1024) return null;
          result.push({ objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest,
            ciphertext: item.ciphertext, recipientEnvelope: wrapped,
            ...(window ? { totalBytes: (item as unknown as { totalBytes: number }).totalBytes } : {}) });
        }
        return result;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  /** This recipient's current envelope for an object: the segmented envelope
   * collection first, then the legacy embedded map. Null when not held. */
  private async recipientEnvelope(session: ClientSession, record: Pick<CaseDocument, 'envelopes'>, caseId: string,
    objectId: string, recipientKeyId: string): Promise<StoredEnvelope | null> {
    const segmented = await this.caseEnvelopes.findOne({ _id: `${caseId}_${envelopeKey(objectId, recipientKeyId)}` }, { session });
    const envelope = segmented ? { objectId: segmented.objectId, recipientKeyId: segmented.recipientKeyId, envelope: segmented.envelope }
      : record.envelopes?.[envelopeKey(objectId, recipientKeyId)];
    if (!envelope || envelope.objectId !== objectId || envelope.recipientKeyId !== recipientKeyId) return null;
    return envelope as StoredEnvelope;
  }
  /** One chunk of a committed chunked object at the checked checkpoint, only when
   * the recipient (null: owner) currently holds an envelope for the object. */
  async readObjectChunk(caseId: string, recipientKeyId: string | null, checkpointDigest: string,
    ref: { objectId: string; ciphertextDigest: string }, chunkIndex: number): Promise<{ chunk: string } | null> {
    if (!this.client) throw new Error('Confidential object transactions require a Mongo client');
    const target = { ...ref };
    if ([caseId, checkpointDigest, target.objectId, target.ciphertextDigest, ...(recipientKeyId === null ? [] : [recipientKeyId])]
      .some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) ||
        !Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= MAX_CHUNKS_PER_OBJECT) throw new Error('Invalid chunk read guard');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const record = await this.cases.findOneAndUpdate({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1 } }, { session, returnDocument: 'after', projection: { envelopes: 1 } });
        if (!record) return null;
        if (recipientKeyId !== null && !await this.recipientEnvelope(session, record, caseId, target.objectId, recipientKeyId)) return null;
        const item = await this.objects.findOne({ _id: `${caseId}_${target.objectId}_${target.ciphertextDigest}` },
          { session, projection: { objectId: 1, ciphertextDigest: 1, ciphertext: 1 } });
        if (!item || item.objectId !== target.objectId || item.ciphertextDigest !== target.ciphertextDigest) return null;
        const digest = indexChunks(item.ciphertext)?.[chunkIndex];
        if (!digest) return null;
        const chunk = await this.chunks.findOne({ _id: digest, expiresAt: { $exists: false } }, { session, projection: { data: 1 } });
        if (!chunk || !isChunkSize(chunk.data.length())) return null;
        return { chunk: Buffer.from(chunk.data.buffer).toString('base64') };
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  private async caseRecord(record: CaseDocument, statements?: Record<string, string>): Promise<CaseRecord> {
    const checkpoints = [...(record.checkpoints ?? []), ...await this.historyAfter(record)];
    const { _id: _ignored, envelopes: _envelopes, messageWriteSequence: _sequence, mailboxRevision: _revision,
      embeddedHistoryLength: _embedded, historyCount: _count, statementCount: _statements, adminAlert: _alert,
      directoryHidden: _hidden, ...rest } = record;
    return { ...rest, checkpoints,
      statements: statements ?? { ...(record.statements ?? {}), ...await this.statementsAfter(record) } } as CaseRecord;
  }
  /** Without a view: the whole record, every statement read back exactly (a
   * missing segment throws). With `{ releaseLimit }` (the sealed enclave store,
   * which keeps private statements inside sealed checkpoints and needs only public
   * ones while a case is locked): `statements` is bounded to the listing named by
   * the pointer and the newest `releaseLimit` release approvals. */
  async getCase(caseId: string, view?: CaseReadView | null): Promise<CaseRecord | null> {
    let releaseLimit: number | null = null;
    if (view !== undefined && view !== null) {
      if (typeof view !== 'object' || Array.isArray(view) || Object.keys(view).join(',') !== 'releaseLimit' ||
          !Number.isSafeInteger(view.releaseLimit) || view.releaseLimit < 0 || view.releaseLimit > MAX_RELEASE_VIEW) {
        throw new Error('Invalid case read view');
      }
      releaseLimit = view.releaseLimit;
    }
    const record = await this.cases.findOne({ _id: caseId }, { projection: { envelopes: 0, messageWriteSequence: 0, mailboxRevision: 0 } });
    if (!record) return null;
    return this.caseRecord(record as CaseDocument,
      releaseLimit === null ? undefined : await this.boundedStatements(record as CaseDocument, releaseLimit));
  }
  async commitTransition(caseId: string, expectedCheckpointDigest: string, update: TransitionUpdate): Promise<boolean> {
    if (!this.client) throw new Error('Confidential case transactions require a Mongo client');
    // The compare-and-set below must be a plain equality on string digests.
    if (typeof caseId !== 'string' || typeof expectedCheckpointDigest !== 'string' || !HEX64.test(expectedCheckpointDigest) ||
        !update || typeof update.checkpointDigest !== 'string' || !HEX64.test(update.checkpointDigest) ||
        !update.statements || typeof update.statements !== 'object' ||
        !Object.keys(update.statements).every(digest => HEX64.test(digest))) throw new Error('Invalid transition');
    await this.putObjects(caseId, update.objects);
    const set: Record<string, unknown> = { currentCheckpointDigest: update.checkpointDigest, listingDigest: update.listingDigest };
    const statements = Object.entries(update.statements);
    if (statements.some(([, wire]) => typeof wire !== 'string')) throw new Error('Invalid transition');
    if (update.recoveryPackage !== null) set.recoveryPackage = update.recoveryPackage;
    if (update.stateEnvelopes) set.stateEnvelopes = update.stateEnvelopes;
    if (update.stateEpoch !== undefined) set.stateEpoch = update.stateEpoch;
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        // The compare-and-set on the case document serializes commits; the history
        // row and envelopes commit or roll back with it.
        const updated = await this.cases.findOneAndUpdate({ _id: caseId, currentCheckpointDigest: expectedCheckpointDigest },
          { $set: set, $inc: { historyCount: 1 } },
          { session, returnDocument: 'after', projection: { embeddedHistoryLength: 1, historyCount: 1, statementCount: 1 } });
        if (!updated) return false;
        let embedded = updated.embeddedHistoryLength;
        if (embedded === undefined) {
          // Legacy document: its whole chain is embedded. Record the length once.
          const legacy = await this.cases.findOne({ _id: caseId }, { session, projection: { checkpoints: 1 } });
          embedded = Array.isArray(legacy?.checkpoints) ? legacy!.checkpoints.length : 0;
          await this.cases.updateOne({ _id: caseId }, { $set: { embeddedHistoryLength: embedded } }, { session });
        }
        const index = embedded + (updated.historyCount ?? 1) - 1;
        await this.history.insertOne({ _id: `${caseId}:${index}`, caseId, index, checkpoint: update.checkpoint }, { session });
        if (update.envelopes.length) {
          await this.caseEnvelopes.bulkWrite(update.envelopes.map(item => ({ replaceOne: {
            filter: { _id: `${caseId}_${envelopeKey(item.objectId, item.recipientKeyId)}` },
            replacement: { caseId, objectId: item.objectId, recipientKeyId: item.recipientKeyId, envelope: item.envelope },
            upsert: true } })), { session, ordered: true });
        }
        if (statements.length) {
          // One row per (case, digest). A digest already segmented keeps its
          // position and takes the new wire (as the embedded map's $set did); new
          // digests take the next positions and the count advances with them.
          const existing = new Set((await this.caseStatements.find({ _id: { $in: statements.map(([digest]) => statementRowId(caseId, digest)) } },
            { session, projection: { digest: 1 } }).toArray()).map(row => row.digest));
          const base = updated.statementCount ?? 0;
          const added = statements.filter(([digest]) => !existing.has(digest));
          const writes = statements.map(([digest, wire]) => existing.has(digest)
            ? { updateOne: { filter: { _id: statementRowId(caseId, digest), caseId }, update: { $set: { wire, ...claimedStatement(wire) } } } }
            : { insertOne: { document: { _id: statementRowId(caseId, digest), caseId, digest, wire, ...claimedStatement(wire),
              index: base + added.findIndex(([item]) => item === digest) } } });
          await this.caseStatements.bulkWrite(writes, { session, ordered: true });
          if (added.length) await this.cases.updateOne({ _id: caseId }, { $inc: { statementCount: added.length } }, { session });
        }
        return true;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  /** Directory page. `statements` holds only the listing named by each row's
   * pointer (the one statement the directory verifies and serves), read by exact
   * key; a missing listing leaves it empty, so the enclave omits the row. */
  async listListedCases(limit: number, after: string | null): Promise<CaseRecord[]> {
    const rows = await this.cases.find({ listingDigest: { $ne: null }, directoryHidden: { $ne: true }, ...(after ? { _id: { $gt: after } } : {}) },
      { projection: { envelopes: 0, messageWriteSequence: 0, mailboxRevision: 0 }, sort: { _id: 1 }, limit }).toArray();
    const listings = await this.listingWires(rows.map(row => ({ caseId: row._id, listingDigest: row.listingDigest,
      embedded: row.statements && typeof row.listingDigest === 'string' && Object.prototype.hasOwnProperty.call(row.statements, row.listingDigest)
        ? row.statements[row.listingDigest] : undefined })));
    return Promise.all(rows.map(row => {
      const wire = listings.get(row._id);
      return this.caseRecord(row as CaseDocument, typeof wire === 'string' ? { [row.listingDigest as string]: wire } : {});
    }));
  }
  /** The listing wire per case: the segmented row by exact (case, digest) key, else
   * the embedded (genesis or legacy) entry. One query for the whole page. */
  private async listingWires(rows: { caseId: string; listingDigest: unknown; embedded: unknown }[]): Promise<Map<string, string>> {
    const keyed = rows.filter(row => typeof row.listingDigest === 'string' && HEX64.test(row.listingDigest));
    const found = keyed.length ? await this.caseStatements.find({ _id: { $in: keyed.map(row => statementRowId(row.caseId, row.listingDigest as string)) } },
      { projection: { _id: 1, caseId: 1, digest: 1, wire: 1 } }).toArray() : [];
    const segmented = new Map(found.filter(row => this.statementRowValid(row.caseId, row)).map(row => [row._id, row.wire]));
    const result = new Map<string, string>();
    for (const row of keyed) {
      const wire = segmented.get(statementRowId(row.caseId, row.listingDigest as string)) ?? row.embedded;
      if (typeof wire === 'string') result.set(row.caseId, wire);
    }
    return result;
  }

  /** Only public directory visibility changes; signed statements and private case
   * material are never rewritten. Audit and visibility commit atomically. */
  async moderateListing(caseId: string, hidden: boolean, actor: string, now: number): Promise<boolean> {
    if (!HEX64.test(caseId) || typeof hidden !== 'boolean' || typeof actor !== 'string' || !actor.trim() ||
        actor.length > 254 || /[\r\n]/.test(actor) || !Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid moderation');
    return this.transaction(async session => {
      const result = await this.cases.updateOne({ _id: caseId, listingDigest: { $type: 'string' } },
        { $set: { directoryHidden: hidden } }, { session });
      if (result.matchedCount !== 1) return false;
      if (result.modifiedCount === 1) await this.client!.db(this.cases.dbName).collection('confidential_listing_moderation_audit')
        .insertOne({ caseId, hidden, actor, at: new Date(now) }, { session });
      return true;
    });
  }

  /** Admin directory source: per listed case, the owner key and ONLY the single
   * statement wire named by the listing pointer. The projection runs in MongoDB so
   * checkpoints, envelopes, other statements (grants/manifests in unsealed stores),
   * state envelopes and recovery packages never leave the database for this read.
   * A listing committed after publication is a segmented statement row, fetched by
   * its exact (case, digest) key for the page's rows in one query. */
  async listListingWires(limit: number, after: string | null): Promise<{
    caseId: string; ownerPublicKey: string; ownerFingerprint: string; listingDigest: string; listingWire: string | null; hidden?: boolean;
  }[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || (after !== null && !/^[a-f0-9]{64}$/.test(after))) {
      throw new Error('Invalid listing page guard');
    }
    const rows = await this.cases.aggregate<{ _id: string; ownerPublicKey: unknown; ownerFingerprint: unknown;
      listingDigest: unknown; directoryHidden?: boolean; listing: { k: string; v: unknown } | null }>([
      { $match: { listingDigest: { $type: 'string' }, ...(after ? { _id: { $gt: after } } : {}) } },
      { $sort: { _id: 1 } },
      { $limit: limit },
      { $project: { _id: 1, ownerPublicKey: 1, ownerFingerprint: 1, listingDigest: 1, directoryHidden: 1, listing: { $arrayElemAt: [{ $filter: {
        input: { $objectToArray: { $ifNull: ['$statements', {}] } }, as: 'entry',
        cond: { $eq: ['$$entry.k', '$listingDigest'] } } }, 0] } } },
    ]).toArray();
    const wires = await this.listingWires(rows.map(row => ({ caseId: row._id, listingDigest: row.listingDigest, embedded: row.listing?.v })));
    return rows.map(row => ({ caseId: row._id, ownerPublicKey: String(row.ownerPublicKey ?? ''),
      ownerFingerprint: String(row.ownerFingerprint ?? ''), listingDigest: String(row.listingDigest ?? ''),
      listingWire: wires.get(row._id) ?? null, ...(row.directoryHidden === true ? { hidden: true } : {}) }));
  }

  async putAccessRequest(request: StoredAccessRequest): Promise<boolean> {
    try {
      await this.requests.insertOne({ ...request, _id: requestRowId() });
      return true;
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
  }
  async listAccessRequests(caseId: string): Promise<StoredAccessRequest[]> {
    return (await this.requests.find({ caseId }, { projection: { _id: 0 }, sort: { createdAt: 1 } }).toArray()) as StoredAccessRequest[];
  }
  async insertAccessRequestAtCheckpoint(request: StoredAccessRequest, guard: {
    checkpointDigest: string; now: number; since: number; organizationLimit: number; caseLimit: number;
  }): Promise<'stored' | 'conflict' | 'rate-limited'> {
    if (!this.client) throw new Error('Confidential request transactions require a Mongo client');
    const row = { ...request }, policy = { ...guard };
    if ([row.caseId, row.organizationId, row.requestId, row.recipientKeyId, policy.checkpointDigest]
      .some(value => !/^[a-f0-9]{64}$/.test(value)) || row.state !== 'pending' ||
      (row.quotaTag !== undefined && (typeof row.quotaTag !== 'string' || !/^[a-f0-9]{64}$/.test(row.quotaTag))) ||
      !Number.isSafeInteger(policy.now) || policy.now <= 0 || !Number.isSafeInteger(policy.since) || policy.since > policy.now ||
      // createdAt may be the write time or its UTC-day bucket (blinded rows: see the sealed store).
      !Number.isSafeInteger(row.expiresAt) || row.expiresAt <= policy.now || !Number.isSafeInteger(row.createdAt) ||
      row.createdAt > policy.now || policy.now - row.createdAt >= 86_400_000 ||
      [policy.organizationLimit, policy.caseLimit].some(value => !Number.isSafeInteger(value) || value < 1)) {
      throw new Error('Invalid request insertion guard');
    }
    // Provision an empty serialization row, not an authorization record. A
    // per-case fence alone cannot enforce one firm's quota across many cases.
    // Blinded (sealed-store) rows carry a fresh organization tag per request, so
    // a lock keyed on it would only add one garbage row per request. Their
    // per-firm rule is per case (quotaTag), serialized by the case-row update.
    const lockId = row.quotaTag === undefined ? row.organizationId : `quota:${row.caseId}:${row.quotaTag}`;
    try { await this.requestLocks.updateOne({ _id: lockId }, { $setOnInsert: { sequence: 0 } }, { upsert: true }); }
    catch (error) { if ((error as { code?: number }).code !== 11000) throw error; }
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const organization = await this.requestLocks.updateOne({ _id: lockId }, { $inc: { sequence: 1 } }, { session });
        if (organization.matchedCount !== 1) return 'conflict' as const;
        const current = await this.cases.findOneAndUpdate({ _id: row.caseId, currentCheckpointDigest: policy.checkpointDigest },
          { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } }, { session, returnDocument: 'after', projection: { listingDigest: 1 } });
        if (!current || typeof current.listingDigest !== 'string') return 'conflict' as const;
        await this.requests.updateMany({ caseId: row.caseId, state: 'pending', expiresAt: { $lte: policy.now } },
          { $set: { state: 'expired' } }, { session });
        const existing = await this.requests.findOne({ caseId: row.caseId, organizationId: row.organizationId,
          requestId: row.requestId }, { session });
        if (existing) {
          // The receipt is stable across fresh authentication and delivery time.
          // Never replace ciphertext, extend expiry or reopen a closed request.
          return existing.state === 'pending' && existing.ciphertext === row.ciphertext &&
            existing.recipientKeyId === row.recipientKeyId && existing.expiresAt === row.expiresAt
            ? 'stored' as const : 'conflict' as const;
        }
        // One pending request per firm per case, durable across enclave restarts.
        // For blinded rows the firm is known here only as a per-case pseudonym.
        if (row.quotaTag !== undefined && await this.requests.countDocuments({ caseId: row.caseId, quotaTag: row.quotaTag,
          state: 'pending' }, { session, limit: 1 })) return 'conflict' as const;
        const organizationCount = await this.requests.countDocuments({ organizationId: row.organizationId,
          createdAt: { $gte: policy.since } }, { session });
        const caseCount = await this.requests.countDocuments({ caseId: row.caseId, state: 'pending' }, { session });
        if (organizationCount >= policy.organizationLimit || caseCount >= policy.caseLimit) return 'rate-limited' as const;
        await this.requests.insertOne({ ...row, _id: requestRowId() }, { session });
        return 'stored' as const;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return 'conflict';
      throw error;
    } finally { await session.endSession(); }
  }
  async getAccessRequest(caseId: string, organizationId: string, requestId: string): Promise<StoredAccessRequest | null> {
    if ([caseId, organizationId, requestId].some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)))
      throw new Error('Invalid request lookup');
    return this.requests.findOne({ caseId, organizationId, requestId }, { projection: {
      _id: 0, caseId: 1, organizationId: 1, requestId: 1, recipientKeyId: 1,
      ciphertext: 1, state: 1, expiresAt: 1, createdAt: 1,
    } });
  }
  async expireAccessRequests(caseId: string, now: number): Promise<void> {
    if (!this.client || !/^[a-f0-9]{64}$/.test(caseId) || !Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid request expiry guard');
    const session = this.client.startSession();
    try { await session.withTransaction(async () => {
      const result = await this.requests.updateMany({ caseId, state: 'pending', expiresAt: { $lte: now } },
        { $set: { state: 'expired' } }, { session });
      if (result.modifiedCount) await this.cases.updateOne({ _id: caseId }, { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } }, { session });
    }); } finally { await session.endSession(); }
  }
  async countAccessRequests(filter: { organizationId?: string; caseId?: string; since: number; state?: 'pending' }): Promise<number> {
    return this.requests.countDocuments({ createdAt: { $gte: filter.since },
      ...(filter.organizationId ? { organizationId: filter.organizationId } : {}),
      ...(filter.caseId ? { caseId: filter.caseId } : {}), ...(filter.state ? { state: filter.state } : {}) });
  }
  async withdrawAccessRequest(caseId: string, organizationId: string, requestId: string): Promise<boolean> {
    if (!this.client) throw new Error('Confidential request transactions require a Mongo client');
    const session = this.client.startSession();
    try { return await session.withTransaction(async () => {
      await this.cases.updateOne({ _id: caseId }, { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } }, { session });
      const result = await this.requests.updateOne({ caseId, organizationId, requestId, state: 'pending' },
        { $set: { state: 'withdrawn' } }, { session });
      return result.modifiedCount === 1;
    }); } finally { await session.endSession(); }
  }

  async appendMessage(message: StoredMessage, guard: { checkpointDigest: string; since: number; limit: number }):
    Promise<'stored' | 'conflict' | 'rate-limited'> {
    if (!this.client) throw new Error('Confidential message transactions require a Mongo client');
    if (!/^[a-f0-9]{64}$/.test(guard.checkpointDigest) || !Number.isSafeInteger(guard.limit) ||
        guard.limit < 1 || !Number.isSafeInteger(guard.since)) throw new Error('Invalid message transaction guard');
    if (message.dedupeTag !== undefined && (typeof message.dedupeTag !== 'string' || !/^[a-f0-9]{64}$/.test(message.dedupeTag))) {
      throw new Error('Invalid message idempotency tag');
    }
    const row = { ...message }, policy = { ...guard }, session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        // An actual write (not just a snapshot read) conflicts with revocation
        // and serializes quota checks by concurrent writers for the same case.
        const locked = await this.cases.findOneAndUpdate({ _id: row.caseId, currentCheckpointDigest: policy.checkpointDigest },
          { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } },
          { session, returnDocument: 'after', projection: { messageWriteSequence: 1 } });
        if (!locked || !Number.isSafeInteger(locked.messageWriteSequence)) return 'conflict' as const;
        if (row.dedupeTag !== undefined && await this.messages.findOne({ caseId: row.caseId, dedupeTag: row.dedupeTag },
          { session, projection: { _id: 1 } })) return 'stored' as const;
        const count = await this.messages.countDocuments({ caseId: row.caseId, organizationId: row.organizationId,
          createdAt: { $gte: policy.since } }, { session });
        if (count >= policy.limit) return 'rate-limited' as const;
        await this.messages.insertOne({ ...row, _id: messageRowId(), sequence: locked.messageWriteSequence }, { session });
        return 'stored' as const;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } catch (error) {
      // The tag is already held for this case: the first copy stands, so this
      // append is the idempotent outcome. Any other duplicate key still throws.
      if (row.dedupeTag !== undefined && duplicateDedupeTag(error)) return 'stored';
      throw error;
    } finally { await session.endSession(); }
  }
  async declineAccessRequest(caseId: string, organizationId: string, requestId: string, checkpointDigest: string):
    Promise<'declined' | 'not-found' | 'conflict'> {
    if (!this.client) throw new Error('Confidential request transactions require a Mongo client');
    if ([caseId, organizationId, requestId, checkpointDigest].some(value => !/^[a-f0-9]{64}$/.test(value))) {
      throw new Error('Invalid request decision guard');
    }
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const locked = await this.cases.updateOne({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } }, { session });
        if (locked.matchedCount !== 1) return 'conflict' as const;
        const result = await this.requests.updateOne({ caseId, organizationId, requestId, state: { $in: ['pending', 'declined'] } },
          { $set: { state: 'declined' } }, { session });
        return result.matchedCount === 1 ? 'declined' as const : 'not-found' as const;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  /** Pending -> approved after the owner's grant commit at `checkpointDigest`.
   * Fenced on that checkpoint so a later revocation cannot race it. */
  async answerAccessRequest(caseId: string, organizationId: string, requestId: string, checkpointDigest: string):
    Promise<'approved' | 'not-found' | 'conflict'> {
    if (!this.client) throw new Error('Confidential request transactions require a Mongo client');
    if ([caseId, organizationId, requestId, checkpointDigest].some(value => !/^[a-f0-9]{64}$/.test(value))) {
      throw new Error('Invalid request decision guard');
    }
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const locked = await this.cases.updateOne({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1, mailboxRevision: 1 } }, { session });
        if (locked.matchedCount !== 1) return 'conflict' as const;
        const result = await this.requests.updateOne({ caseId, organizationId, requestId, state: { $in: ['pending', 'approved'] } },
          { $set: { state: 'approved' } }, { session });
        return result.matchedCount === 1 ? 'approved' as const : 'not-found' as const;
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  async listMessages(caseId: string, organizationId: string | null, limit: number): Promise<StoredMessage[]> {
    const rows = await this.messages.find({ caseId, ...(organizationId ? { organizationId } : {}) },
      { projection: { _id: 0, caseId: 1, organizationId: 1, sender: 1, ciphertext: 1, createdAt: 1 }, sort: MESSAGE_ORDER_NEWEST, limit }).toArray();
    return (rows as StoredMessage[]).reverse();
  }
  async readMessagesAtCheckpoint(caseId: string, organizationId: string, limit: number,
    checkpointDigest: string): Promise<StoredMessage[] | null> {
    if (!this.client) throw new Error('Confidential message transactions require a Mongo client');
    if ([caseId, organizationId, checkpointDigest].some(value => !/^[a-f0-9]{64}$/.test(value)) ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error('Invalid message read guard');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const locked = await this.cases.updateOne({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1 } }, { session });
        if (locked.matchedCount !== 1) return null;
        const rows = await this.messages.find({ caseId, organizationId }, { session, limit, batchSize: limit, sort: MESSAGE_ORDER_NEWEST,
          projection: { _id: 0, caseId: 1, organizationId: 1, sender: 1, ciphertext: 1, createdAt: 1 } }).toArray();
        return (rows as StoredMessage[]).reverse();
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
  async countMessages(filter: { caseId: string; organizationId: string; since: number }): Promise<number> {
    return this.messages.countDocuments({ caseId: filter.caseId, organizationId: filter.organizationId,
      createdAt: { $gte: filter.since } });
  }

  async readMailboxPageAtCheckpoint(caseId: string, organizationId: string | null, checkpointDigest: string,
    cursor: MailboxCursor | null): Promise<MailboxPage | null> {
    if (!this.client) throw new Error('Confidential mailbox transactions require a Mongo client');
    if ([caseId, checkpointDigest, ...(organizationId ? [organizationId] : [])].some(value => !/^[a-f0-9]{64}$/.test(value)) ||
        (cursor && (Object.keys(cursor).sort().join(',') !== 'checkpointDigest,messageOffset,requestOffset,version' ||
          cursor.checkpointDigest !== checkpointDigest || [cursor.version, cursor.requestOffset, cursor.messageOffset]
            .some(value => !Number.isSafeInteger(value) || value < 0)))) throw new Error('Invalid mailbox page guard');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const current = await this.cases.findOneAndUpdate({ _id: caseId, currentCheckpointDigest: checkpointDigest,
          ...(cursor ? (cursor.version === 0 ? { $or: [{ mailboxRevision: 0 }, { mailboxRevision: { $exists: false } }] }
            : { mailboxRevision: cursor.version }) : {}) }, { $inc: { messageWriteSequence: 1 } },
          { session, returnDocument: 'after', projection: { mailboxRevision: 1 } });
        if (!current) return null;
        // Bound total serialized ciphertext per page, with one look-ahead row to
        // detect continuation without imposing a global mailbox cap.
        const requestOffset = cursor?.requestOffset ?? 0, messageOffset = cursor?.messageOffset ?? 0;
        const requests = organizationId ? [] : await this.requests.find({ caseId, state: 'pending' }, { session,
          sort: { createdAt: 1, requestId: 1 }, skip: requestOffset, limit: 26, batchSize: 26,
          projection: { _id: 0, caseId: 1, organizationId: 1, requestId: 1, recipientKeyId: 1,
            expiresAt: 1, ciphertext: 1, state: 1, createdAt: 1 } }).toArray();
        const messages = await this.messages.find({ caseId, ...(organizationId ? { organizationId } : {}) }, { session,
          sort: MESSAGE_ORDER, skip: messageOffset, limit: 26, batchSize: 26,
          projection: { _id: 0, caseId: 1, organizationId: 1, sender: 1, ciphertext: 1, createdAt: 1 } }).toArray();
        let budget = 150 * 1024;
        function take<T>(rows: T[]): T[] {
          const picked: T[] = [];
          for (const row of rows.slice(0, 25)) {
            const bytes = Buffer.byteLength(JSON.stringify(row), 'utf8') + 1;
            if (bytes > budget) break;
            picked.push(row); budget -= bytes;
          }
          return picked;
        }
        const selectedRequests = take(requests), selectedMessages = take(messages);
        if ((requests.length || messages.length) && !selectedRequests.length && !selectedMessages.length) {
          throw new Error('Confidential mailbox item exceeds page capacity');
        }
        return { requests: selectedRequests as StoredAccessRequest[], messages: selectedMessages as StoredMessage[],
          next: requests.length > selectedRequests.length || messages.length > selectedMessages.length ? {
            checkpointDigest, version: current.mailboxRevision ?? 0, requestOffset: requestOffset + selectedRequests.length,
            messageOffset: messageOffset + selectedMessages.length } : null };

      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }

  async readInboxAtCheckpoint(caseId: string, checkpointDigest: string):
    Promise<{ requests: StoredAccessRequest[]; messages: StoredMessage[] } | null> {
    if (!this.client) throw new Error('Confidential inbox transactions require a Mongo client');
    if ([caseId, checkpointDigest].some(value => !/^[a-f0-9]{64}$/.test(value))) throw new Error('Invalid inbox read guard');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        const locked = await this.cases.updateOne({ _id: caseId, currentCheckpointDigest: checkpointDigest },
          { $inc: { messageWriteSequence: 1 } }, { session });
        if (locked.matchedCount !== 1) return null;
        const requests = await this.requests.find({ caseId, state: 'pending' }, { session,
          sort: { createdAt: 1, requestId: 1 }, limit: 501, batchSize: 501,
          projection: { _id: 0, caseId: 1, organizationId: 1, requestId: 1, recipientKeyId: 1,
            expiresAt: 1, ciphertext: 1, state: 1, createdAt: 1 } }).toArray();
        // Never silently hide pending requests. Pagination is required before
        // increasing the bounded prototype inbox capacity.
        if (requests.length > 500) throw new Error('Confidential inbox capacity exceeded');
        const messages = await this.messages.find({ caseId }, { session, limit: 500, batchSize: 500, sort: MESSAGE_ORDER_NEWEST,
          projection: { _id: 0, caseId: 1, organizationId: 1, sender: 1, ciphertext: 1, createdAt: 1 } }).toArray();
        return { requests: requests as StoredAccessRequest[], messages: (messages as StoredMessage[]).reverse() };
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority', j: true }, readPreference: 'primary' });
    } finally { await session.endSession(); }
  }
}

const LEASE_MS = 60_000;
const MAX_ATTEMPTS = 5;

/** Host-only aggregate over committed case rows. The enclave already stores
 * createdAt at UTC-day precision. No new per-report telemetry is recorded. */
export class WeeklySubmissionSummaryStore implements WeeklySubmissionSummaryStorage {
  private readonly cases: Collection<{ createdAt: number }>;
  private readonly summaries: Collection<SummaryRecord>;
  private initialized?: Promise<unknown>;
  constructor(db: Db) {
    this.cases = db.collection('confidential_cases');
    this.summaries = db.collection('confidential_weekly_submission_summaries');
  }
  initialize(): Promise<unknown> {
    // Lazy: disabled deployments do not create the aggregate index or job rows.
    return this.initialized ??= this.cases.createIndex({ createdAt: 1 }).catch(error => {
      this.initialized = undefined; throw error;
    });
  }
  async claim(period: SummaryPeriod, now: number): Promise<ClaimedSummary | null> {
    const _id = `staging:${new Date(period.start).toISOString().slice(0, 10)}`;
    try {
      await this.summaries.updateOne({ _id }, { $setOnInsert: {
        ...period, state: 'pending', attempts: 0, nextAttemptAt: 0,
      } }, { upsert: true });
    } catch (error) { if ((error as { code?: number }).code !== 11000) throw error; }
    await this.summaries.updateOne({ _id, state: 'sending', attempts: { $gte: MAX_ATTEMPTS }, nextAttemptAt: { $lte: now } },
      { $set: { state: 'failed' }, $unset: { leaseId: '' } });
    return await this.summaries.findOneAndUpdate({ _id, state: { $in: ['pending', 'sending'] },
      nextAttemptAt: { $lte: now }, attempts: { $lt: MAX_ATTEMPTS } }, {
      $set: { state: 'sending', leaseId: randomUUID(), nextAttemptAt: now + LEASE_MS }, $inc: { attempts: 1 },
    }, { returnDocument: 'after' }) as ClaimedSummary | null;
  }
  count(period: SummaryPeriod): Promise<number> {
    // Count all accepted cases, including unlisted/hidden ones. Upload staging,
    // access requests, edits and retries never insert a second case row.
    return this.cases.countDocuments({ createdAt: { $gte: period.start, $lt: period.end } }, { maxTimeMS: 5000 });
  }
  async saveTotal(claim: ClaimedSummary, total: number, now: number): Promise<boolean> {
    const result = await this.summaries.updateOne({ _id: claim._id, state: 'sending', leaseId: claim.leaseId,
      nextAttemptAt: { $gt: now } }, { $set: { total, nextAttemptAt: now + LEASE_MS } });
    return result.matchedCount === 1;
  }
  async finish(claim: ClaimedSummary, result: Delivery, now: number): Promise<void> {
    const limited = typeof result === 'object';
    await this.summaries.updateOne({ _id: claim._id, state: 'sending', leaseId: claim.leaseId }, {
      $set: result === 'delivered' ? { state: 'sent', sentAt: now } : {
        state: !limited && claim.attempts >= MAX_ATTEMPTS ? 'failed' : 'pending',
        nextAttemptAt: now + (limited ? Math.max(60_000, result.retryAfterMs) : 60_000 * 2 ** (claim.attempts - 1)),
      }, ...(limited ? { $inc: { attempts: -1 } } : {}), $unset: { leaseId: '' },
    });
  }
}
