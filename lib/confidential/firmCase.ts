import { REQUEST_STATUS_BATCH_LIMIT } from '../../enclave/src/confidential/requestStatusBatch';
import type { RequestStatusTarget } from '../../enclave/src/confidential/requestStatusBatch';
import { issuedNotAfter } from '../../enclave/src/confidential/clockSkew';
import { assertFirmWorkspaceCapacity } from './firmWorkspace';
import { reportCheckCode } from './reportCheckCode';
import { confidentialPageBudget } from './pageBudget';
import { LegalSignInRequired } from './legalAuth';
import { ConfidentialRateLimitError, retryConfidentialRead } from './readRetry';
import { collectGrantedCaseRanges } from '../../enclave/src/confidential/caseRanges';
import type { CaseCiphertextRange } from '../../enclave/src/confidential/caseRanges';
import { readKey } from '../../enclave/src/confidential/pgp';
import { authorizeCaseRead, grantActiveAt, verifyOwnerStatement } from '../../enclave/src/confidential/authorization';
import type { AccessGrant, CaseManifest, CaseScope, OwnerTrust } from '../../enclave/src/confidential/authorization';
import { advanceOwnerCheckpoint } from '../../enclave/src/confidential/recovery';
import type { CheckpointPin } from '../../enclave/src/confidential/recovery';
import { readReleaseManifest } from '../../enclave/src/confidential/releaseManifest';
import { encodeBase64, findCaseStateKey } from '../../enclave/src/confidential/caseStateKey';
import { createLegalAccessRequest } from '../../enclave/src/confidential/accessRequest';
import type { AccessRequestDetails } from '../../enclave/src/confidential/accessRequest';
import { openGrantedCaseObject } from '../../enclave/src/confidential/caseObject';
import {
  MAX_CHUNKED_INDEX_BYTES, isChunkedIndexText, openGrantedChunkedObject,
} from '../../enclave/src/confidential/caseChunks';
import { decodeChunk } from './evidenceTransfer';
import type { OpenedChunkedEvidence } from './evidenceTransfer';
import { openCaseMessage, sealCaseMessage } from '../../enclave/src/confidential/caseMessage';
import type { CaseMessage } from '../../enclave/src/confidential/caseMessage';
import { unpackCaseFile } from '../../enclave/src/confidential/ownerSubmission';
import { signEnrollmentChallenge } from '../../enclave/src/confidential/enrollmentProof';
import type { EnrollmentChallenge } from '../../enclave/src/confidential/enrollmentProof';
import { signParticipantRequest } from '../../enclave/src/confidential/participantRequest';
import {
  CHANNEL_BODY_LIMIT, CONFIDENTIAL_AUDIENCE, ConfidentialUnavailableError, authenticatedOperation, base64, unavailable,
  ChannelSessions, channelSessionsFor, publicCaseOperation, trustedClock, trustedNow, trustedTime,
} from './client';
import type { ChannelRelay } from './client';
import type { FirmIdentity } from './firmKey';
import { parseSetupMissing, readFirmSetup, setupIncompleteMessage } from './firmSetup';
import type { FirmSetupRequirement } from './firmSetup';

/** Legal-organization browser client for the attested confidential-case channel.
 *
 * Every private step happens on this device: access requests are encrypted to
 * the case owner, the case state key is unwrapped here and only handed to a
 * backend release the owner approved, returned checkpoint chains are verified
 * against a per-case freshness pin, and objects are decrypted and checked
 * against the owner's grant/manifest/release locally. The service returns
 * ciphertext and signatures only. There is no plaintext or legacy fallback.
 *
 * Channel frames (inside the encrypted session; one attested session carries
 * several sequential frames, see ChannelSessions):
 *   {operation:'legal.challenge', count?} -> {challenge, expiresAt} | {challenges, expiresAt}
 *   {operation:'legal.directory', accessToken, after, limit} -> {listings, next}
 *   {operation:'legal.<op>', accessToken, proof, body} (base64 body)
 *   {operation:'legal.enrollment-challenge', accessToken, body:base64({token})} -> EnrollmentChallenge
 *   {operation:'legal.enroll', accessToken, body:base64({token,proof})} -> {organizationId, subject, recipientKeyId}
 */
export type FirmOperation = 'request-access' | 'withdraw-request' | 'request-status' | 'request-status-batch' | 'read-state-keys' | 'unlock-case' |
  'open-case' | 'read-messages' | 'send-message' | 'acknowledge-report-open';
/** Outcome of one of this organization's requests, as the service reports it. */
export type FirmRequestOutcome = 'requested' | 'approved' | 'declined' | 'expired' | 'withdrawn' | 'unknown';
/** This organization's own current access to one case. `unknown` while the case
 * is locked (nobody has opened it since the secure service restarted). */
export type FirmAccessStatus = {
  state: 'active' | 'expired' | 'revoked' | 'key-changed' | 'none' | 'unknown';
  expiresAt: number | null; scopes: CaseScope[]; contactShared: boolean; releaseApproved: boolean | null;
};
/** The service's `request-status` answer. `expiresAt` is set only on a request
 * still waiting for the reporter. */
export type FirmStatusReply = { access: FirmAccessStatus;
  requests: { requestId: string; state: FirmRequestOutcome; expiresAt?: number }[] };
export type FirmSession = {
  relay: ChannelRelay; releaseManifest: string; releaseDigest: string; firm: FirmIdentity;
  /** Returns a current legal access token (Auth0 legal application); never logged. */
  accessToken: () => Promise<string>;
  /** Per-case owner key pin, from the directory listing the firm requested access to. */
  owners: Map<string, OwnerTrust>;
  /** Per-case freshness pin: the newest owner checkpoint this device verified (memory only). */
  pins: Map<string, CheckpointPin>;
  /** Per-case backend release approvals listed in the pinned checkpoint (keyed by
   * case; `digest` is the pin it was read from). Absent for a pin restored from a
   * workspace saved before this existed. */
  pinReleases?: Map<string, PinnedReleases>;
  /** Highest accepted message sequence per sender, per case. */
  sequences: Map<string, { owner: number; organization: number }>;
};
/** The owner-signed release approval digests of one verified checkpoint. */
export type PinnedReleases = { digest: string; releaseDigests: string[] };
export type DirectoryListing = { caseId: string; summary: string; publishedAt?: number; hasAttachments?: boolean; owner: OwnerTrust | null;
  /** Out-of-band owner key check (reportCheckCode.ts); null without an owner key. */
  checkCode?: string | null;
  /** The directory served a different owner key than this workspace pinned
   * earlier for the report. Requests are refused; the row is kept visible. */
  ownerKeyChanged?: boolean };
export type OpenedEvidence = { objectId: string; name: string; type: string; bytes: Uint8Array };
/** An evidence file not yet downloaded. Chunked files carry their decrypted name,
 * type and size (from the owner-signed index); older whole files do not. */
export type DeferredEvidence = {
  objectId: string;
  /** Stored ciphertext size, an approximation of the file size (exact size is `size` for chunked files). */
  encryptedBytes: number;
  name?: string; type?: string; size?: number; chunked?: true;
};
export type OpenedCase = {
  caseId: string; checkpointDigest: string; scopes: CaseScope[];
  /** Earliest end of this organization's current grants; `null` = until revoked. */
  grantExpiresAt: number | null;
  narrative: Record<string, string | boolean | null> | null;
  evidence: OpenedEvidence[];
  /** Files to download one at a time (see DeferredEvidence). */
  deferredEvidence: DeferredEvidence[];
  /** This organization's current owner grants (verified): the basis of the firm timeline. */
  grants: { issuedAt: number; expiresAt: number | null; scopes: CaseScope[] }[];
  /** When the reporter approved the secure-service version that served this read. */
  releaseApprovedAt: number;
  /** Other granted structured objects (for example contact), shown as text only. */
  records: { scope: CaseScope; fields: Record<string, string | boolean | null> }[];
};
export class FirmCaseError extends Error {
  constructor(readonly code: 'release-not-approved' | 'owner-key-unavailable' | 'wrong-firm-key' | 'owner-key-changed' | 'not-granted' | 'setup-incomplete',
    /** For `setup-incomplete`: the organization setup steps the service still requires. */
    readonly missing: readonly FirmSetupRequirement[] = []) {
    super(code === 'setup-incomplete' ? setupIncompleteMessage(missing)
      : code === 'release-not-approved'
      ? 'The reporter has not yet approved the current version of the secure service. The report stays closed until they do.'
      : code === 'owner-key-changed' ? 'This report is signed with a different reporter key from the one in your saved workspace. Access was stopped and nothing was sent. Keep your backup and do not send a new request unless the reporter confirms the new report check code with you directly.'
      : code === 'wrong-firm-key' ? 'This invitation is for a different organization key.'
        : code === 'not-granted' ? 'Your organization does not have access to this report right now.'
          : 'This report cannot be opened from this browser. Request access from the list of available reports first.');
  }
}
/** What this organization can learn about its own request and access. */
export type FirmRequestState = 'pending' | 'approved' | 'declined' | 'withdrawn' | 'expired' | 'unknown';
export type FirmRequestStatus =
  /** `expiresAt: null` = until the reporter revokes it. */
  | { access: 'granted'; request: FirmRequestState; releaseApproved: boolean; expiresAt: number | null; contactShared: boolean }
  /** `ended` says why there is no access now (`none`: never had any with this key). */
  | { access: 'none'; request: FirmRequestState; requestExpiresAt: number | null; ended?: 'expired' | 'revoked' | 'key-changed' | 'none' }
  /** A missing verified release approval explains the lock, not current authorization. */
  | { access: 'unknown'; request: FirmRequestState; requestExpiresAt: number | null; releaseApproved?: false };

const DIRECTORY_PAGE = 20;
const REQUEST_LIFETIME = 30 * 86_400_000 - 5 * 60_000;
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
function hex64(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function randomId(): string {
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ConfidentialUnavailableError();
  return value as Record<string, unknown>;
}

export async function createFirmSession(input: { relay: ChannelRelay; releaseManifest: string; firm: FirmIdentity;
  accessToken: () => Promise<string> }): Promise<FirmSession> {
  const { digest } = await readReleaseManifest(input.releaseManifest);
  return { relay: input.relay, releaseManifest: input.releaseManifest, releaseDigest: digest, firm: input.firm,
    accessToken: input.accessToken, owners: new Map(), pins: new Map(), pinReleases: new Map(), sequences: new Map() };
}
/** Firm operations that only read (or re-supply the same unlock key). Only these
 * may sign a challenge stocked earlier in the session and be repeated once on a
 * fresh session after an ambiguous relay failure; changes never are. */
const FIRM_READS: ReadonlySet<FirmOperation> = new Set<FirmOperation>(['request-status-batch', 'read-state-keys', 'unlock-case', 'open-case', 'read-messages']);
/** Evidence arrives in many sequential range reads: fetch challenges in the
 * largest batch the enclave issues so fewer calls are spent on them. */
const RANGE_CHALLENGE_BATCH = 8;

/** One firm-authenticated operation: a challenge and a proof bound to the same
 * verified session, reused across this workspace's sequential operations (one
 * session serves a whole ranged evidence download). The login token and proof
 * travel only inside the encrypted channel. */
async function operate(session: FirmSession, operation: FirmOperation, caseId: string, body: unknown,
  now?: number, batch?: number, signal?: AbortSignal): Promise<Record<string, unknown>> {
  signal?.throwIfAborted();
  const accessToken = await session.accessToken(); // Sign-in errors surface as themselves.
  signal?.throwIfAborted();
  const bytes = encode(body);
  let reply: Record<string, unknown>;
  try {
    if (bytes.length > CHANNEL_BODY_LIMIT) throw new Error();
    reply = record(await authenticatedOperation(channelSessionsFor(session, session.relay, session.releaseManifest), {
      challengeOperation: 'legal.challenge', clock: trustedClock(now), idempotent: FIRM_READS.has(operation), batch, signal,
      sign: (challenge, channel, issuedAt) => signParticipantRequest({ audience: CONFIDENTIAL_AUDIENCE, role: 'organization', caseId,
        organizationId: session.firm.organizationId, operation, body: bytes, challenge,
        issuedAt, nonce: channel.nonce, serverKeyId: channel.serverKeyId }, session.firm.privateKey),
      request: proof => ({ operation: `legal.${operation}`, accessToken, proof, body: base64(bytes) }) }));
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof ConfidentialRateLimitError) throw error;
    throw unavailable(error);
  } finally { bytes.fill(0); }
  // The service refuses requests and case reads until organization setup is done.
  if (reply.error === 'setup-incomplete') {
    const missing = Object.keys(reply).sort().join(',') === 'error,missing' ? parseSetupMissing(reply.missing) : null;
    if (!missing) throw new ConfidentialUnavailableError();
    throw new FirmCaseError('setup-incomplete', missing);
  }
  return reply;
}

/** Approved summaries only. A row may carry the owner's public key and signed
 * listing (needed to encrypt a request to the owner); when present they must
 * verify and name exactly this summary, or the row is dropped. */
export async function readLegalDirectory(session: FirmSession, after: string | null, now: number): Promise<{
  listings: DirectoryListing[]; next: string | null;
}> {
  const accessToken = await session.accessToken();
  let reply: Record<string, unknown>;
  try {
    reply = record(await channelSessionsFor(session, session.relay, session.releaseManifest)
      .run(send => send({ operation: 'legal.directory', accessToken, after, limit: DIRECTORY_PAGE })));
  } catch (error) { throw unavailable(error); }
  if (!Array.isArray(reply.listings) || reply.listings.length > 50 || (reply.next !== null && !hex64(reply.next))) {
    throw new ConfidentialUnavailableError();
  }
  const seen = new Set<string>(), listings: DirectoryListing[] = [];
  for (const item of reply.listings) {
    const row = record(item);
    if (!hex64(row.caseId) || seen.has(row.caseId) || typeof row.summary !== 'string' || !row.summary.trim() ||
        row.summary.length > 600) throw new ConfidentialUnavailableError();
    seen.add(row.caseId);
    let owner: OwnerTrust | null = null, ownerKeyChanged = false;
    let publishedAt: number | undefined, hasAttachments: boolean | undefined;
    if (row.ownerPublicKey !== undefined || row.listing !== undefined) {
      try {
        if (typeof row.ownerPublicKey !== 'string' || row.ownerPublicKey.length > 65_536 || typeof row.listing !== 'string') throw new Error();
        const key = await readKey({ armoredKey: row.ownerPublicKey });
        if (key.isPrivate()) throw new Error();
        const trust = { caseId: row.caseId, ownerFingerprint: key.getFingerprint(), ownerPublicKey: key };
        const { statement } = await verifyOwnerStatement(row.listing, trust);
        if (statement.kind !== 'listing' || statement.summary !== row.summary ||
            statement.publishedAt !== row.publishedAt || statement.hasAttachments !== row.hasAttachments) throw new Error();
        ({ publishedAt, hasAttachments } = statement);
        // Filters use only fields inside the verified owner signature.
        // Trust on first use per workspace: a pinned owner key never silently
        // changes. The row stays visible, without an owner key, so requests stop.
        const pinned = session.owners.get(row.caseId);
        if (pinned && pinned.ownerFingerprint !== trust.ownerFingerprint) ownerKeyChanged = true;
        else owner = trust;
      } catch { continue; } // An inconsistent owner key/listing is never shown.
    }
    listings.push({ caseId: row.caseId, summary: row.summary, ...(publishedAt !== undefined ? { publishedAt } : {}), ...(hasAttachments !== undefined ? { hasAttachments } : {}), owner, ownerKeyChanged,
      checkCode: owner ? await reportCheckCode(row.caseId, owner.ownerFingerprint) : null });
  }
  return { listings, next: (reply.next as string | null) };
}

/** Portal pre-check before a request is saved to the organization's shared list,
 * so a request the service would refuse for incomplete setup leaves no entry
 * behind. Best effort: the service enforces setup again on delivery, so an
 * unreadable status just proceeds to that check. */
export async function assertFirmSetupComplete(session: FirmSession, now: number): Promise<void> {
  const setup = await readFirmSetup(session, now).catch(error => {
    if (error instanceof LegalSignInRequired) throw error;
    return null;
  });
  if (setup && !setup.complete) throw new FirmCaseError('setup-incomplete', setup.missing);
}

/** Encrypts the request (purpose and scopes) to the owner and delivers it.
 * Pins the owner key used for this case in the session. */
export async function requestCaseAccess(session: FirmSession, listing: DirectoryListing,
  input: { purpose: string; scopes: CaseScope[]; details: AccessRequestDetails }, now: number,
  beforeSend?: (request: { requestId: string; expiresAt: number }) => Promise<void>): Promise<{ requestId: string; expiresAt: number }> {
  if (!listing.owner) throw new FirmCaseError(listing.ownerKeyChanged ? 'owner-key-changed' : 'owner-key-unavailable');
  const pinned = session.owners.get(listing.caseId);
  if (listing.owner.caseId !== listing.caseId || listing.owner.ownerPublicKey.getFingerprint() !== listing.owner.ownerFingerprint ||
      (pinned && pinned.ownerFingerprint !== listing.owner.ownerFingerprint)) throw new FirmCaseError('owner-key-changed');
  assertFirmWorkspaceCapacity(session, [], listing.caseId);
  const issuedAt = trustedTime(now), requestId = randomId(), expiresAt = issuedAt + REQUEST_LIFETIME;
  const ciphertext = await createLegalAccessRequest({ requestId, scopes: [...input.scopes], objectRevisionLimit: null,
    purpose: input.purpose, issuedAt, expiresAt, details: input.details },
  session.firm.organizationId, session.firm.privateKey, listing.owner);
  // Retain the owner anchor and routing secret before an ambiguous network result.
  // A failed backup callback prevents transmission; callers can safely recover or withdraw.
  const latestPin = session.owners.get(listing.caseId);
  if (latestPin && latestPin.ownerFingerprint !== listing.owner.ownerFingerprint) throw new FirmCaseError('owner-key-changed');
  session.owners.set(listing.caseId, listing.owner);
  await beforeSend?.({ requestId, expiresAt });
  const reply = await operate(session, 'request-access', listing.caseId, { caseId: listing.caseId, requestId, ciphertext, expiresAt }, now);
  if (reply.state !== 'requested') throw new ConfidentialUnavailableError();
  session.owners.set(listing.caseId, listing.owner);
  return { requestId, expiresAt };
}

const REQUEST_OUTCOMES: readonly FirmRequestOutcome[] = ['requested', 'approved', 'declined', 'expired', 'withdrawn', 'unknown'];
const ACCESS_STATES: readonly FirmAccessStatus['state'][] = ['active', 'expired', 'revoked', 'key-changed', 'none', 'unknown'];
const SCOPES: readonly CaseScope[] = ['narrative', 'evidence', 'messages', 'identity', 'contact', 'rewards'];

/** Outcomes of this organization's requests for one case (at most 16 IDs) and
 * its current access. The reply is encrypted to this device; nothing is cached.
 * Request rows are advisory; access is verified again when the report opens. */
export async function readCaseStatus(session: FirmSession, caseId: string, requestIds: readonly string[],
  now: number, options: StatusReadOptions = {}): Promise<FirmStatusReply> {
  const ids = [...new Set(requestIds)];
  if (!hex64(caseId) || ids.length > 16 || !ids.every(hex64)) throw new ConfidentialUnavailableError();
  const reply = await operate(session, 'request-status', caseId, { caseId, requestIds: ids }, now, undefined, options.signal);
  return parseCaseStatus(reply, ids);
}

function parseCaseStatus(reply: Record<string, unknown>, ids: string[]): FirmStatusReply {
  try {
    const access = record(reply.access), requests = reply.requests;
    if (Object.keys(reply).sort().join(',') !== 'access,requests' || !Array.isArray(requests) || requests.length !== ids.length ||
        Object.keys(access).sort().join(',') !== 'contactShared,expiresAt,releaseApproved,scopes,state' ||
        !ACCESS_STATES.includes(access.state as FirmAccessStatus['state']) ||
        !(access.expiresAt === null || (Number.isSafeInteger(access.expiresAt) && (access.expiresAt as number) >= 0)) ||
        !Array.isArray(access.scopes) || access.scopes.some(scope => !SCOPES.includes(scope as CaseScope)) ||
        typeof access.contactShared !== 'boolean' || !(access.releaseApproved === null || typeof access.releaseApproved === 'boolean')) throw new Error();
    return {
      access: { state: access.state as FirmAccessStatus['state'], expiresAt: access.expiresAt as number | null,
        scopes: [...access.scopes as CaseScope[]], contactShared: access.contactShared as boolean,
        releaseApproved: access.releaseApproved as boolean | null },
      requests: requests.map((item, index) => {
        const row = record(item);
        const waiting = row.state === 'requested';
        if (Object.keys(row).sort().join(',') !== (waiting ? 'expiresAt,requestId,state' : 'requestId,state') ||
            row.requestId !== ids[index] || !REQUEST_OUTCOMES.includes(row.state as FirmRequestOutcome) ||
            (waiting && !(Number.isSafeInteger(row.expiresAt) && (row.expiresAt as number) > 0))) throw new Error();
        return { requestId: ids[index], state: row.state as FirmRequestOutcome,
          ...(waiting ? { expiresAt: row.expiresAt as number } : {}) };
      }),
    };
  } catch { throw new ConfidentialUnavailableError(); }
}

/** Advisory request state only, in the older `{state, expiresAt}` form; it is not
 * proof of approval. Content access still verifies owner grants. Derived from
 * readRequestStatus, so it uses the same single `request-status` operation. */
export type RequestStatus = { state: 'pending' | 'approved' | 'withdrawn' | 'declined' | 'expired' | 'not-found'; expiresAt: number | null };
export async function readCaseRequestStatus(session: FirmSession, caseId: string, requestId: string, now: number): Promise<RequestStatus> {
  const status = await readRequestStatus(session, caseId, requestId, now);
  if (status.request === 'unknown') return { state: 'not-found', expiresAt: null };
  return { state: status.request, expiresAt: status.access !== 'granted' ? status.requestExpiresAt : null };
}

/** This organization's advisory request state and current access for one report,
 * in the single-request form the portal list uses. Sealed grants cannot be
 * checked while the case is locked. A state-key envelope proves neither grant
 * expiry nor current authorization, so access stays unknown until opening the
 * report verifies the current owner grants. A null request ID checks access
 * only; it does not create or infer a request for a reporter-initiated share. */
export async function readRequestStatus(session: FirmSession, caseId: string, requestId: string | null, now: number,
  options: StatusReadOptions = {}): Promise<FirmRequestStatus> {
  const reply = await readCaseStatus(session, caseId, requestId === null ? [] : [requestId], now, options);
  return requestStatusFromReply(reply);
}

function requestStatusFromReply(reply: FirmStatusReply): FirmRequestStatus {
  const row = reply.requests[0];
  const request: FirmRequestState = row?.state === 'requested' ? 'pending' : row?.state ?? 'unknown';
  const requestExpiresAt = row?.expiresAt ?? null;
  const { access } = reply;
  if (access.state === 'active') {
    if (typeof access.releaseApproved !== 'boolean') throw new ConfidentialUnavailableError();
    return { access: 'granted', request, releaseApproved: access.releaseApproved, expiresAt: access.expiresAt,
      contactShared: access.contactShared };
  }
  if (access.state === 'unknown') return { access: 'unknown', request, requestExpiresAt };
  return { access: 'none', request, requestExpiresAt, ended: access.state };
}

/** Resolve a locked report using only this firm's key and the reporter's signed
 * release approval, then check current grants. Does not read report contents or
 * create an access request. The directory must have verified the owner key. */
export async function checkReportAccess(session: FirmSession, caseId: string, requestId: string | null, now: number,
  verifiedOwner?: OwnerTrust | null): Promise<FirmRequestStatus> {
  pinStatusOwner(session, caseId, verifiedOwner);
  const status = await readRequestStatus(session, caseId, requestId, now);
  return resolveReportAccess(session, caseId, requestId, now, status);
}

function pinStatusOwner(session: FirmSession, caseId: string, verifiedOwner?: OwnerTrust | null): void {
  if (verifiedOwner) {
    const pinned = session.owners.get(caseId);
    if (verifiedOwner.caseId !== caseId || (pinned && pinned.ownerFingerprint !== verifiedOwner.ownerFingerprint)) {
      throw new FirmCaseError('owner-key-unavailable');
    }
    session.owners.set(caseId, verifiedOwner);
  }
}

async function resolveReportAccess(session: FirmSession, caseId: string, requestId: string | null, now: number,
  status: FirmRequestStatus): Promise<FirmRequestStatus> {
  if (status.access !== 'unknown' || !session.owners.has(caseId)) return status;
  try { await unlockFirmCase(session, caseId, now); }
  catch (error) {
    if (error instanceof FirmCaseError && error.code === 'not-granted') {
      return { access: 'none', request: status.request, requestExpiresAt: status.requestExpiresAt };
    }
    // A release that the reporter has not approved must never receive the key.
    if (error instanceof FirmCaseError && error.code === 'release-not-approved') {
      return { ...status, releaseApproved: false };
    }
    throw error;
  }
  return readRequestStatus(session, caseId, requestId, now);
}

export type ReportAccessTarget = RequestStatusTarget & { owner?: OwnerTrust | null };

/** One encrypted status operation for the whole board (bounded at 256 cases per
 * frame), or per-report reads once the enclave refuses the batched one. Null
 * means that case could not be verified, never "access denied".
 * Locked reports stay unknown until the user opens them; no per-report unlocks. */
export async function checkReportAccessBatch(session: FirmSession, targets: readonly ReportAccessTarget[], now: number,
  signal?: AbortSignal): Promise<Map<string, FirmRequestStatus | null>> {
  const results = new Map<string, FirmRequestStatus | null>();
  if (new Set(targets.map(target => target.caseId)).size !== targets.length ||
      targets.some(target => !hex64(target.caseId) || (target.requestId !== null && !hex64(target.requestId)))) {
    throw new ConfidentialUnavailableError();
  }
  const valid: ReportAccessTarget[] = [];
  for (const target of targets) {
    try { pinStatusOwner(session, target.caseId, target.owner); valid.push(target); }
    catch { results.set(target.caseId, null); }
  }
  for (let offset = 0; offset < valid.length; offset += REQUEST_STATUS_BATCH_LIMIT) {
    signal?.throwIfAborted();
    const batch = valid.slice(offset, offset + REQUEST_STATUS_BATCH_LIMIT);
    if (BATCH_REFUSED.has(session)) {
      const statuses = await readStatusesSingly(session, batch, now, signal, new ConfidentialUnavailableError('unavailable'));
      batch.forEach((target, index) => results.set(target.caseId, statuses[index]));
      continue;
    }
    let reply: Record<string, unknown>;
    try {
      reply = await operate(session, 'request-status-batch', session.firm.organizationId,
        { cases: batch.map(({ caseId, requestId }) => ({ caseId, requestId })) }, now, undefined, signal);
    } catch (error) {
      signal?.throwIfAborted();
      if (!(error instanceof ConfidentialUnavailableError)) throw error;
      // An enclave release older than the batched read refuses the whole frame.
      // Every release serves the per-report read, which never unlocks a case.
      // A channel that is down fails those too, and then this error stands.
      const statuses = await readStatusesSingly(session, batch, now, signal, error);
      // Each refusal is a relay 5xx, so this session stops asking until reload.
      if (statuses.some(status => status !== null)) BATCH_REFUSED.add(session);
      batch.forEach((target, index) => results.set(target.caseId, statuses[index]));
      continue;
    }
    signal?.throwIfAborted();
    if (Object.keys(reply).join(',') !== 'statuses' || !Array.isArray(reply.statuses) || reply.statuses.length !== batch.length) {
      throw new ConfidentialUnavailableError();
    }
    // Validate the entire response before publishing results, including the
    // exact report order, so a malformed batch cannot mislabel another report.
    const statuses = reply.statuses.map((value, index) => {
      const row = record(value), target = batch[index];
      if (row.caseId !== target.caseId) throw new ConfidentialUnavailableError();
      if (Object.keys(row).sort().join(',') === 'caseId,error' && row.error === 'unavailable') return null;
      if (Object.keys(row).sort().join(',') !== 'caseId,status') throw new ConfidentialUnavailableError();
      return requestStatusFromReply(parseCaseStatus(record(row.status), target.requestId === null ? [] : [target.requestId]));
    });
    for (let index = 0; index < batch.length; index++) {
      results.set(batch[index].caseId, statuses[index]);
    }
  }
  return results;
}

type StatusReadOptions = { signal?: AbortSignal };
const BATCH_REFUSED = new WeakSet<FirmSession>();
/** Failed per-report reads, before any succeeds, that mean the channel itself is down. */
const SINGLE_STATUS_PROBES = 3;

/** Per-report status reads for a refused batch, in turn (the session carries one
 * request at a time), as the board read every report before batching. A report
 * whose read fails stays unverified (null), as a failed row in a batch reply does.
 * If the first reads all fail, `failure` is thrown instead, so an outage is not
 * multiplied across the board. */
async function readStatusesSingly(session: FirmSession, targets: readonly RequestStatusTarget[], now: number,
  signal: AbortSignal | undefined, failure: unknown): Promise<(FirmRequestStatus | null)[]> {
  const statuses: (FirmRequestStatus | null)[] = [];
  let succeeded = false;
  for (const target of targets) {
    signal?.throwIfAborted();
    try {
      statuses.push(await readRequestStatus(session, target.caseId, target.requestId, now, { signal }));
      succeeded = true;
    } catch (error) {
      signal?.throwIfAborted();
      if (!(error instanceof ConfidentialUnavailableError)) throw error;
      statuses.push(null);
      if (!succeeded && statuses.length >= SINGLE_STATUS_PROBES) throw failure;
    }
  }
  return statuses;
}

export async function withdrawCaseRequest(session: FirmSession, caseId: string, requestId: string, now: number): Promise<void> {
  const reply = await operate(session, 'withdraw-request', caseId, { caseId, requestId }, now);
  if (reply.state !== 'withdrawn') throw new ConfidentialUnavailableError();
}

function ownerFor(session: FirmSession, caseId: string): OwnerTrust {
  const trust = session.owners.get(caseId);
  if (!trust || trust.caseId !== caseId) throw new FirmCaseError('owner-key-unavailable');
  return trust;
}

/** The owner must have signed an approval of exactly the bundled release before
 * this device hands that backend the case state key. While the case is locked its
 * checkpoint is sealed and the service answers with older approvals too, so the
 * approval must also be listed in the newest checkpoint this device verified
 * (its pin). An approval the owner has since dropped from its checkpoint is
 * therefore refused here, not only by the enclave's own current-approval check.
 * Trust-on-first-use gap: with no pinned approvals for this case (a first open
 * on this device, or a pin restored from a workspace saved before approvals
 * were pinned) any verified owner approval of the release is accepted, and only
 * the attested enclave's check stands between the key and a dropped approval.
 * An approval the owner signed after this device's pin is not visible until the
 * case is open again (the reporter opening it unlocks it). */
export async function ensureReleaseApproved(session: FirmSession, caseId: string, now: number): Promise<void> {
  const trust = ownerFor(session, caseId);
  const reply = await publicCaseOperation({ relay: session.relay, releaseManifest: session.releaseManifest, now,
    request: { operation: 'case.release-approvals', caseId },
    sessions: channelSessionsFor(session, session.relay, session.releaseManifest) }) as { releases?: unknown };
  if (!Array.isArray(reply?.releases)) throw new ConfidentialUnavailableError();
  const pin = session.pins.get(caseId), pinned = session.pinReleases?.get(caseId);
  // Approvals kept for a different checkpoint than the pin are never trusted.
  const allowed = pin && pinned ? new Set(pinned.digest === pin.digest ? pinned.releaseDigests : []) : null;
  for (const wire of reply.releases) {
    try {
      const { statement, digest } = await verifyOwnerStatement(wire, trust);
      if (statement.kind === 'release' && statement.releaseDigest === session.releaseDigest &&
          (allowed === null || allowed.has(digest)) && issuedNotAfter(statement.issuedAt, trustedNow())) return;
    } catch { /* Unverifiable rows are ignored. */ }
  }
  throw new FirmCaseError('release-not-approved');
}

/** Reads the envelopes first so "no access" and "waiting for the reporter to
 * approve an update" are told apart; the key is still handed only to a release
 * the reporter approved. */
export async function unlockFirmCase(session: FirmSession, caseId: string, now: number): Promise<void> {
  const trust = ownerFor(session, caseId);
  const keys = await operate(session, 'read-state-keys', caseId, { caseId }, now);
  // The service lists the envelopes only to a current grantee (checked while it can).
  if (keys.error === 'not-granted') throw new FirmCaseError('not-granted');
  if (!Array.isArray(keys.stateEnvelopes)) throw new ConfidentialUnavailableError();
  let state;
  try { state = await findCaseStateKey(keys.stateEnvelopes as string[], caseId, session.firm.privateKey, trust.ownerPublicKey); }
  catch (error) {
    // No envelope opens with this organization's key: not (or no longer) granted.
    if (error instanceof ConfidentialUnavailableError) throw error;
    throw new FirmCaseError('not-granted');
  }
  try { await ensureReleaseApproved(session, caseId, now); }
  catch (error) { state.key.fill(0); throw error; }
  try {
    const reply = await operate(session, 'unlock-case', caseId, { caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }, now);
    // A locked case serves its stored envelopes to anyone, so a firm whose grant
    // ended (expiry alone, no re-key) still opens its own: the enclave checks the
    // grant here and refuses the key.
    if (reply.error === 'not-granted') throw new FirmCaseError('not-granted');
    if (reply.unlocked !== true) throw new ConfidentialUnavailableError();
  } finally { state.key.fill(0); }
}

/** Runs a case read; a `locked` case is unlocked (after the release check) and retried once. */
async function unlocked(session: FirmSession, caseId: string, now: number,
  run: () => Promise<Record<string, unknown>>, progress?: (stage: FirmCaseProgress) => void): Promise<Record<string, unknown>> {
  let reply = await run();
  if (reply.error === 'locked') {
    report(progress, 'unlocking');
    await unlockFirmCase(session, caseId, now);
    report(progress, 'loading');
    reply = await run();
  }
  if (reply.error === 'release-not-approved') throw new FirmCaseError('release-not-approved');
  if (reply.error === 'not-granted') throw new FirmCaseError('not-granted');
  if (reply.error !== undefined) throw new ConfidentialUnavailableError();
  return reply;
}
function pinnedBody(session: FirmSession, caseId: string) {
  const pin = session.pins.get(caseId);
  return pin ? { caseId, minimumCheckpoint: pin.digest } : { caseId };
}

/** Verifies the returned checkpoint chain against this device's pin (or, with no
 * pin yet, from genesis) and returns the advanced pin without storing it. */
async function verifiedChain(session: FirmSession, trust: OwnerTrust, chain: unknown, tip: unknown,
  tipDigest: unknown): Promise<{ pin: CheckpointPin; releaseDigests: string[] }> {
  if (!Array.isArray(chain) || chain.some(item => typeof item !== 'string') || typeof tip !== 'string' || !hex64(tipDigest)) {
    throw new ConfidentialUnavailableError();
  }
  const wires = chain as string[], pinned = session.pins.get(trust.caseId);
  let next: CheckpointPin;
  if (pinned) {
    next = wires.length ? await advanceOwnerCheckpoint(wires, trust, pinned) : pinned;
  } else {
    if (!wires.length) throw new ConfidentialUnavailableError();
    const genesis = await verifyOwnerStatement(wires[0], trust);
    if (genesis.statement.kind !== 'checkpoint' || genesis.statement.previousDigest !== null) throw new ConfidentialUnavailableError();
    next = { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint, revision: genesis.statement.revision,
      keyEpoch: genesis.statement.keyEpoch, digest: genesis.digest };
    if (wires.length > 1) next = await advanceOwnerCheckpoint(wires.slice(1), trust, next);
  }
  const current = await verifyOwnerStatement(tip, trust);
  if (current.statement.kind !== 'checkpoint' || current.digest !== tipDigest || next.digest !== tipDigest) {
    throw new ConfidentialUnavailableError();
  }
  return { pin: next, releaseDigests: [...current.statement.releaseDigests] };
}

function fields(bytes: Uint8Array): Record<string, string | boolean | null> {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  const result: Record<string, string | boolean | null> = {};
  for (const [key, item] of Object.entries(value)) {
    if (item === null || typeof item === 'boolean' || typeof item === 'string') result[key] = item;
  }
  return result;
}

/** Progress while a case opens: 'unlocking' only happens after the secure
 * service restarted and this organization must unlock the case again. */
export type FirmCaseProgress = 'verifying' | 'unlocking' | 'loading';
function report(progress: ((stage: FirmCaseProgress) => void) | undefined, stage: FirmCaseProgress): void {
  try { progress?.(stage); } catch { /* Progress display never blocks the flow. */ }
}

/** Called by the report screen after rendering a decrypted narrative. Directory
 * checks and attachment downloads never send this acknowledgement. */
export async function acknowledgeReportOpen(session: FirmSession, opened: OpenedCase): Promise<void> {
  if (opened.narrative === null) return;
  const { sealReportOpenReceipt } = await import('../../enclave/src/confidential/reportOpenReceipt');
  const ciphertext = await sealReportOpenReceipt({ checkpointDigest: opened.checkpointDigest, openedAt: trustedNow() },
    { owner: ownerFor(session, opened.caseId), organization: { organizationId: session.firm.organizationId,
      publicKey: session.firm.privateKey.toPublic() } }, session.firm.privateKey);
  const reply = await unlocked(session, opened.caseId, Date.now(), () => operate(session, 'acknowledge-report-open',
    opened.caseId, { caseId: opened.caseId, checkpointDigest: opened.checkpointDigest, ciphertext }, Date.now()));
  if (reply.recorded !== true) throw new ConfidentialUnavailableError();
}

/** Opens a granted case: release-approved, chain-verified, locally decrypted. */
export async function openFirmCase(session: FirmSession, caseId: string, now: number,
  options: { deferEvidence?: boolean; evidenceObjectId?: string; onProgress?: (stage: FirmCaseProgress) => void } = {}): Promise<OpenedCase> {
  return (await openFirmCaseWith(session, caseId, now, options)).opened;
}

async function openFirmCaseWith(session: FirmSession, caseId: string, now: number,
  options: { deferEvidence?: boolean; evidenceObjectId?: string; onProgress?: (stage: FirmCaseProgress) => void },
): Promise<{ opened: OpenedCase; chunked: OpenedChunkedEvidence | null }> {
  let chunked: OpenedChunkedEvidence | null = null;
  if (options.evidenceObjectId !== undefined && !hex64(options.evidenceObjectId)) throw new ConfidentialUnavailableError();
  const readBudget = { expiresAt: Date.now() + 15 * 60_000 };
  let signInRequired: LegalSignInRequired | undefined;
  const trust = ownerFor(session, caseId);
  report(options.onProgress, 'verifying');
  // Verify (or reuse) the attested session and stock challenges before the reads.
  try { await channelSessionsFor(session, session.relay, session.releaseManifest).prepare('legal.challenge'); }
  catch (error) { if (error instanceof ConfidentialRateLimitError) throw error; throw unavailable(error); }
  report(options.onProgress, 'loading');
  const reply = await unlocked(session, caseId, now, () => operate(session, 'open-case', caseId,
    { minimumCheckpoint: null, ...pinnedBody(session, caseId), mode: 'index' }, now), options.onProgress);
  try {
    if (reply.caseId !== caseId || typeof reply.ownerPublicKey !== 'string' || typeof reply.manifest !== 'string' ||
        typeof reply.release !== 'string' || !Array.isArray(reply.grants) || !Array.isArray(reply.objects)) throw new Error();
    // The service's copy of the owner key must be the key this firm pinned.
    if ((await readKey({ armoredKey: reply.ownerPublicKey })).getFingerprint() !== trust.ownerFingerprint) throw new Error();
    if (!Array.isArray(reply.checkpoints)) throw new Error();
    const reserveHistoryPage = confidentialPageBudget();
    reserveHistoryPage(reply);
    const seenHistory = new Set<string>();
    let historyNext = reply.historyNext;
    while (historyNext !== null && historyNext !== undefined) {
      const key = JSON.stringify(historyNext);
      if (seenHistory.has(key) || Date.now() >= readBudget.expiresAt) throw new Error();
      seenHistory.add(key);
      const page = await operate(session, 'open-case', caseId, { minimumCheckpoint: null,
        ...pinnedBody(session, caseId), mode: 'history', historyCursor: historyNext }, Date.now());
      reserveHistoryPage(page);
      if (!Array.isArray(page.checkpoints) || page.checkpointDigest !== reply.checkpointDigest) throw new Error();
      reply.checkpoints.push(...page.checkpoints);
      historyNext = page.historyNext;
    }
    const { pin, releaseDigests: pinnedReleases } = await verifiedChain(session, trust, reply.checkpoints, reply.checkpoint, reply.checkpointDigest);
    const manifest = await verifyOwnerStatement(reply.manifest, trust);
    if (manifest.statement.kind !== 'manifest') throw new Error();
    const grants = new Map<string, { wire: string; grant: AccessGrant }>();
    for (const wire of reply.grants) {
      const verified = await verifyOwnerStatement(wire as string, trust);
      const grant = verified.statement;
      if (grant.kind !== 'grant' || grant.organizationId !== session.firm.organizationId ||
          grant.recipientKeyId !== session.firm.recipientKeyId) throw new Error();
      grants.set(verified.digest, { wire: wire as string, grant });
    }
    if (!grants.size) throw new Error();
    const release = await verifyOwnerStatement(reply.release, trust);
    if (release.statement.kind !== 'release') throw new Error();
    const opened: OpenedCase = { caseId, checkpointDigest: pin.digest, narrative: null, evidence: [], deferredEvidence: [], records: [],
      scopes: [...new Set([...grants.values()].flatMap(item => item.grant.scopes))],
      grantExpiresAt: [...grants.values()].every(item => item.grant.expiresAt === null) ? null
        : Math.min(...[...grants.values()].flatMap(item => item.grant.expiresAt === null ? [] : [item.grant.expiresAt])),
      grants: [...grants.values()].map(({ grant }) => ({ issuedAt: grant.issuedAt, expiresAt: grant.expiresAt, scopes: [...grant.scopes] })),
      releaseApprovedAt: release.statement.issuedAt };
    const seen = new Set<string>();
    for (const item of reply.objects) {
      const object = record(item);
      const entry = (manifest.statement as CaseManifest).objects.find(value => value.objectId === object.objectId);
      const grant = grants.get(object.grantDigest as string);
      if (!entry || !grant || seen.has(entry.objectId) || !Number.isSafeInteger(object.totalBytes) ||
          (object.totalBytes as number) < 1 || (object.totalBytes as number) > 16 * 1024 * 1024) throw new Error();
      seen.add(entry.objectId);
      const context = { caseId, objectId: entry.objectId, scope: entry.scope, keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision };
      const authorization = { trust, grant: grant.wire, release: reply.release, manifest: reply.manifest,
        checkpoint: reply.checkpoint as string, checkpointDigest: pin.digest, request: {
          organizationId: session.firm.organizationId, recipientKeyId: session.firm.recipientKeyId, objectId: entry.objectId,
          ciphertextDigest: entry.ciphertextDigest, scope: entry.scope, releaseDigest: session.releaseDigest,
          keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, now: trustedNow() } };
      await authorizeCaseRead(authorization);
      const wanted = options.evidenceObjectId === undefined ? !options.deferEvidence : options.evidenceObjectId === entry.objectId;
      const fetchObject = (totalBytes: number) => collectGrantedCaseRanges({ ...context, ciphertextDigest: entry.ciphertextDigest,
        totalBytes }, async (offset, length) =>
        await retryConfidentialRead(async () => {
          try { return await operate(session, 'open-case', caseId,
            { caseId, minimumCheckpoint: pin.digest, mode: 'range', checkpointDigest: pin.digest,
              objectId: entry.objectId, offset, length }, Date.now(), RANGE_CHALLENGE_BATCH) as CaseCiphertextRange; }
          catch (error) { if (error instanceof LegalSignInRequired) signInRequired = error; throw error; }
        }, undefined, readBudget));
      // A chunked evidence index is small and gives the file name and size, so it is
      // read when listing. Whole-buffer files (up to 8 MB) are fetched only when
      // asked for, and a single-file download skips every other file.
      if (entry.scope === 'evidence' && !wanted &&
          (options.evidenceObjectId !== undefined || (object.totalBytes as number) > MAX_CHUNKED_INDEX_BYTES)) {
        opened.deferredEvidence.push({ objectId: entry.objectId, encryptedBytes: object.totalBytes as number });
        continue;
      }
      const encrypted = await fetchObject(object.totalBytes as number);
      if (entry.scope === 'evidence' && isChunkedIndexText(encrypted.ciphertext)) {
        const reader = await openGrantedChunkedObject(encrypted.ciphertext, encrypted.recipientEnvelope, context,
          session.firm.privateKey, authorization);
        if (options.evidenceObjectId === entry.objectId) {
          chunked = { reader, fetchChunk: position => readFirmChunk(session, caseId, pin.digest, entry, grant.grant, position) };
        } else {
          reader.dispose();
          opened.deferredEvidence.push({ objectId: entry.objectId, encryptedBytes: object.totalBytes as number,
            name: reader.name, type: reader.type, size: reader.size, chunked: true });
        }
        continue;
      }
      if (entry.scope === 'evidence' && !wanted) {
        opened.deferredEvidence.push({ objectId: entry.objectId, encryptedBytes: object.totalBytes as number });
        continue;
      }
      const plaintext = await openGrantedCaseObject(encrypted,
        context, session.firm.privateKey, { trust, grant: grant.wire, release: reply.release, manifest: reply.manifest,
          checkpoint: reply.checkpoint as string, checkpointDigest: pin.digest, request: {
            organizationId: session.firm.organizationId, recipientKeyId: session.firm.recipientKeyId, objectId: entry.objectId,
            ciphertextDigest: entry.ciphertextDigest, scope: entry.scope, releaseDigest: session.releaseDigest,
            keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, now: trustedNow() } });
      try {
        if (entry.scope === 'evidence') {
          const file = unpackCaseFile(plaintext);
          opened.evidence.push({ objectId: entry.objectId, name: file.name, type: file.type, bytes: file.bytes });
        } else if (entry.scope === 'narrative' && !opened.narrative) {
          opened.narrative = fields(plaintext);
        } else {
          opened.records.push({ scope: entry.scope, fields: fields(plaintext) });
        }
      } finally { plaintext.fill(0); }
    }
    // A many-file transfer can outlast a grant. Do not return a partially
    // current batch even when its early files were valid when decrypted.
    if (Date.now() >= readBudget.expiresAt || [...grants.values()].some(item => !grantActiveAt(item.grant, trustedNow()))) throw new Error();
    if (options.evidenceObjectId !== undefined && !chunked &&
        !opened.evidence.some(item => item.objectId === options.evidenceObjectId)) throw new Error();
    session.pins.set(caseId, pin);
    (session.pinReleases ??= new Map()).set(caseId, { digest: pin.digest, releaseDigests: pinnedReleases });
    return { opened, chunked };
  } catch (error) {
    (chunked as OpenedChunkedEvidence | null)?.reader.dispose();
    if (signInRequired) throw signInRequired;
    if (error instanceof FirmCaseError || error instanceof LegalSignInRequired) throw error;
    throw unavailable(error);
  }
}


/** Re-fetches the current signed index, membership and grant at click time. Old
 * page descriptors never grant access. No other evidence file is downloaded. */
export async function openFirmEvidence(session: FirmSession, caseId: string, objectId: string): Promise<OpenedEvidence> {
  const { opened, chunked } = await openFirmCaseWith(session, caseId, Date.now(), { evidenceObjectId: objectId });
  chunked?.reader.dispose();
  const item = opened.evidence.find(value => value.objectId === objectId);
  if (!item || opened.evidence.length !== 1) throw new ConfidentialUnavailableError();
  return item;
}

/** Chunked evidence for a streaming download (EvidenceDownload). Like
 * openFirmEvidence, this re-fetches and re-verifies the signed index, grant,
 * release and checkpoint at call time; every chunk is then its own
 * authenticated read at that checkpoint. */
export async function openFirmChunkedEvidence(session: FirmSession, caseId: string, objectId: string): Promise<OpenedChunkedEvidence> {
  const { chunked } = await openFirmCaseWith(session, caseId, Date.now(), { evidenceObjectId: objectId });
  if (!chunked) throw new ConfidentialUnavailableError();
  return chunked;
}

async function readFirmChunk(session: FirmSession, caseId: string, checkpointDigest: string,
  entry: { objectId: string; ciphertextDigest: string; scope: CaseScope; keyEpoch: number; objectRevision: number },
  grant: AccessGrant, position: number): Promise<Uint8Array> {
  // The owner's grant bounds the whole transfer, not only its start.
  if (!grantActiveAt(grant, trustedNow())) throw new ConfidentialUnavailableError();
  const reply = await operate(session, 'open-case', caseId, { caseId, minimumCheckpoint: checkpointDigest, mode: 'chunk',
    checkpointDigest, objectId: entry.objectId, chunkIndex: position }, Date.now());
  if (Object.keys(reply).sort().join(',') !== 'caseId,chunk,chunkIndex,ciphertextDigest,keyEpoch,objectId,objectRevision,scope' ||
      reply.caseId !== caseId || reply.objectId !== entry.objectId || reply.ciphertextDigest !== entry.ciphertextDigest ||
      reply.scope !== entry.scope || reply.keyEpoch !== entry.keyEpoch || reply.objectRevision !== entry.objectRevision ||
      reply.chunkIndex !== position || typeof reply.chunk !== 'string') throw new ConfidentialUnavailableError();
  return decodeChunk(reply.chunk);
}

function participants(session: FirmSession, trust: OwnerTrust) {
  return { owner: trust, organization: { organizationId: session.firm.organizationId,
    publicKey: session.firm.privateKey.toPublic() } };
}

/** This organization's thread with the owner; unverifiable messages are dropped. */
export async function readFirmMessages(session: FirmSession, caseId: string, now: number): Promise<{
  messages: CaseMessage[]; rejected: number;
}> {
  const trust = ownerFor(session, caseId);
  const reply = await unlocked(session, caseId, now, () => operate(session, 'read-messages', caseId, pinnedBody(session, caseId), now));
  if (!Array.isArray(reply.messages)) throw new ConfidentialUnavailableError();
  const reservePage = confidentialPageBudget();
  reservePage(reply);
  const seenCursors = new Set<string>();
  let next = reply.next;
  while (next !== null && next !== undefined) {
    const key = JSON.stringify(next);
    if (seenCursors.has(key)) throw new ConfidentialUnavailableError();
    seenCursors.add(key);
    const page = await operate(session, 'read-messages', caseId, { ...pinnedBody(session, caseId), mailboxCursor: next }, Date.now());
    reservePage(page);
    if (!Array.isArray(page.messages)) throw new ConfidentialUnavailableError();
    reply.messages.push(...page.messages);
    next = page.next;
  }

  const floors = { owner: 0, organization: 0 }, messages: CaseMessage[] = [];
  let rejected = 0;
  for (const item of reply.messages) {
    try {
      const row = record(item);
      if (row.caseId !== caseId || row.organizationId !== session.firm.organizationId || typeof row.ciphertext !== 'string') throw new Error();
      const message = await openCaseMessage(row.ciphertext, participants(session, trust), session.firm.privateKey, floors);
      if (message.sender !== row.sender) throw new Error();
      floors[message.sender] = message.sequence;
      messages.push(message);
    } catch { rejected += 1; }
  }
  // Display verification starts at genesis; persisted high-water marks must not
  // regress if an untrusted store omits messages or a send completes mid-read.
  const remembered = session.sequences.get(caseId);
  session.sequences.set(caseId, { owner: Math.max(remembered?.owner ?? 0, floors.owner),
    organization: Math.max(remembered?.organization ?? 0, floors.organization) });
  return { messages, rejected };
}

export async function sendFirmMessage(session: FirmSession, caseId: string, body: string, now: number): Promise<void> {
  const trust = ownerFor(session, caseId);
  if (!session.sequences.has(caseId)) await readFirmMessages(session, caseId, now);
  const floors = session.sequences.get(caseId)!;
  const sequence = floors.organization + 1;
  if (!Number.isSafeInteger(sequence)) throw new ConfidentialUnavailableError();
  // Reserve synchronously before encryption/network I/O. Failed or uncertain
  // sends burn a sequence in this session; gaps are safer than reusing one.
  session.sequences.set(caseId, { ...floors, organization: sequence });
  const ciphertext = await sealCaseMessage({ sender: 'organization', sequence, sentAt: trustedTime(now), body },
    participants(session, trust), session.firm.privateKey);
  const reply = await unlocked(session, caseId, now, () => operate(session, 'send-message', caseId,
    { caseId, organizationId: session.firm.organizationId, ciphertext }, now));
  if (reply.sent !== true) throw new ConfidentialUnavailableError();
}

/** Invitation redemption: the enclave issues the invitation's challenge; this
 * device signs it with the firm key registered for the organization. The raw
 * invitation token is sent only inside the encrypted channel. */
export async function redeemInvitation(input: { relay: ChannelRelay; releaseManifest: string; now: number;
  invitation: string; accessToken: string; firm: FirmIdentity }): Promise<{ organizationId: string }> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(input.invitation)) throw new Error('This invitation link is not valid.');
  let challenge: EnrollmentChallenge;
  // Both steps share one attested session; the enrollment challenge itself is
  // single-use and bound to the invitation by the enclave.
  const sessions = new ChannelSessions(input.relay, input.releaseManifest, undefined, true);
  try {
    try {
      challenge = await sessions.run(send => send({ operation: 'legal.enrollment-challenge', accessToken: input.accessToken,
        body: base64(encode({ token: input.invitation })) })) as EnrollmentChallenge;
      record(challenge);
    } catch (error) { throw unavailable(error); }
    if (challenge.organizationId !== input.firm.organizationId || challenge.recipientKeyId !== input.firm.recipientKeyId) {
      throw new FirmCaseError('wrong-firm-key');
    }
    try {
      const proof = await signEnrollmentChallenge(challenge, input.firm.privateKey);
      // Never repeated automatically: a lost reply must not become a second enrollment.
      const reply = record(await sessions.run(send => send({ operation: 'legal.enroll', accessToken: input.accessToken,
        body: base64(encode({ token: input.invitation, proof })) }, { last: true, retry: false })));
      if (reply.organizationId !== input.firm.organizationId || reply.recipientKeyId !== input.firm.recipientKeyId) throw new Error();
      return { organizationId: input.firm.organizationId };
    } catch (error) { throw unavailable(error); }
  } finally { sessions.clear(); }
}
