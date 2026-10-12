import { issuedNotAfter } from '../../enclave/src/confidential/clockSkew';
import { confidentialPageBudget } from './pageBudget';
import { witnessStatus } from './firmKeyWitness';
import type { FirmKeyWitnessEntry, WitnessStatus } from './firmKeyWitness';
import { readKey } from '../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { grantActiveAt, signOwnerStatement, verifyOwnerStatement } from '../../enclave/src/confidential/authorization';
import type {
  AccessGrant, CaseCheckpoint, CaseListing, CaseManifest, ManifestEntry, OwnerStatement, OwnerTrust,
} from '../../enclave/src/confidential/authorization';
import { advanceOwnerCheckpoint, recoveryCaseLocator, refreshOwnerRecovery, restoreOwnerRecovery } from '../../enclave/src/confidential/recovery';
import type { CheckpointPin } from '../../enclave/src/confidential/recovery';
import { readReleaseManifest } from '../../enclave/src/confidential/releaseManifest';
import { encodeBase64, findCaseStateKey, generateCaseStateKey, wrapCaseStateKey } from '../../enclave/src/confidential/caseStateKey';
import type { CaseStateKey } from '../../enclave/src/confidential/caseStateKey';
import { openDeliveredLegalAccessRequest } from '../../enclave/src/confidential/accessRequest';
import type { DeliveredLegalAccessRequest, LegalAccessRequest, TrustedLegalOrganization } from '../../enclave/src/confidential/accessRequest';
import { prepareDirectGrant, prepareGrantRenewal, prepareOwnerGrant } from '../../enclave/src/confidential/ownerGrant';
import type { OwnerGrantDecision } from '../../enclave/src/confidential/ownerGrant';
import { verifyFirmKeyBinding } from '../../enclave/src/confidential/firmKeyBinding';
import type { FirmProfile } from '../../enclave/src/confidential/firmKeyBinding';
import { caseRecipientKeyId, grantCaseObjectEnvelope, openOwnerCaseObject } from '../../enclave/src/confidential/caseObject';
import { openCaseMessage, sealCaseMessage } from '../../enclave/src/confidential/caseMessage';
import type { CaseMessage } from '../../enclave/src/confidential/caseMessage';
import { checkEvidenceSources, sealEvidenceFiles, unpackCaseFile } from '../../enclave/src/confidential/ownerSubmission';
import type { EncryptionProgress } from '../../enclave/src/confidential/ownerSubmission';
import {
  bytesEvidenceSource, chunkedIndexDigest, isChunkedIndexText, openOwnerChunkedObject,
} from '../../enclave/src/confidential/caseChunks';
import type { EvidenceSource, SealedChunkedObject } from '../../enclave/src/confidential/caseChunks';
import {
  ChannelSessions, ConfidentialUnavailableError, adoptChannelSessions, channelSessionsFor, callerClock, createChunkUploadState,
  ownerOperation, publicCaseOperation, trustedNow, trustedTime, uploadChunkedObjects,
} from './client';
import type { ChannelRelay, ChunkUploadState, UploadProgress } from './client';
import { decodeBase64Strict, decodeChunk } from './evidenceTransfer';
import type { OpenedChunkedEvidence } from './evidenceTransfer';

/** Owner (whistleblower) device flows for the status page. Everything private is
 * decrypted and verified here; the service only relays ciphertext and enforces
 * signatures. Keys and the recovery code are held in memory for the session only;
 * the optional device pin (see devicePin.ts) is persisted through `onPinAdvance`. */
export type OwnerSession = {
  relay: ChannelRelay; releaseManifest: string; releaseDigest: string;
  owner: PrivateKey; trust: OwnerTrust; pin: CheckpointPin; pinnedCheckpoint: string;
  /** A pin this device remembered from an earlier visit. The served chain must
   * contain it (otherwise the host rolled back or forked the case); cleared once met. */
  minimumPin?: CheckpointPin | null;
  /** In memory only, to refresh the encrypted recovery package on each commit.
   * Never persist, log or send it (only its public case locator is ever sent). */
  recoveryCode: string;
  /** Freshness (owner decision 2026-09-27, CONFIDENTIAL-FRESHNESS-DECISION.md): no
   * independent recorder. 'unconfirmed' means restored without a remembered pin, so
   * the device cannot tell whether an older backup was restored; the UI must say so. */
  freshness: 'device-pinned' | 'unconfirmed';
  /** Called after every verified pin advance (opt-in device persistence). */
  onPinAdvance?: (pin: CheckpointPin) => void;
  /** Re-check locally retained history before signing/sending a mutation. Must throw (or reject) on conflict. */
  assertDeviceHistory?: () => void | Promise<void>;
  /** Every owner-signed checkpoint from genesis to the pin, oldest first, each
   * verified and hash-linked on this device. Filled by the first state read; the
   * timeline is derived from it. In memory only. */
  history?: OwnerHistoryEntry[];
  /** Progress for the status page: 'unlocking' (then 'unlocked') is reported only
   * when the service lost its in-memory key (for example after a restart) and
   * this device must unlock the report again. */
  onProgress?: (stage: OwnerProgress) => void;
};
export type OwnerHistoryEntry = { digest: string; wire: string; checkpoint: CaseCheckpoint };

/** What the reporter was doing when an organization's key had to be checked.
 * `target` is the organization the reporter acted on; the check that failed can
 * be for another organization that keeps access and is re-sent the report's key. */
export type KeyCheckAction = { operation: 'share' | 'allow' | 'renew' | 'change' | 'contact' | 'message' | 'add'; target?: string };
/** The approved roster did not confirm the recipient key,
 * so nothing was changed. The message is written for the reporter and names
 * the action that did not happen, the organization and domain checked, and
 * the way out. */
export class OrganizationKeyUnconfirmedError extends Error {
  readonly operation: KeyCheckAction['operation'];
  constructor(readonly domain: string, readonly reason: 'failed' | 'not-allowed' = 'failed',
    action: KeyCheckAction = { operation: 'share' }, readonly organizationName?: string) {
    super(organizationKeyUnconfirmedText(domain, reason, action, organizationName));
    this.operation = action.operation;
    this.name = 'OrganizationKeyUnconfirmedError';
  }
}
export function organizationKeyUnconfirmedText(domain: string, reason: 'failed' | 'not-allowed',
  action: KeyCheckAction = { operation: 'share' }, organizationName?: string): string {
  const target = action.target;
  const checked = organizationName ?? 'the legal organization';
  const lead = {
    share: 'Nothing was shared.',
    allow: `Access for ${target ?? 'the legal organization'} was not allowed. Nothing was shared.`,
    renew: `Access for ${target ?? 'the legal organization'} was not renewed. Nothing changed.`,
    change: `What ${target ?? 'the legal organization'} can read was not changed. Nothing was shared.`,
    contact: `Your contact details were not shared with ${target ?? 'the legal organization'}. Nothing was shared.`,
    message: `Your message to ${target ?? 'the legal organization'} was not sent.`,
    add: 'Your files were not added. Nothing was shared.',
  }[action.operation];
  // Allowing access and sharing contact details also give the report's key
  // again to every organization that keeps access: say why another one matters.
  const other = target && organizationName && organizationName !== target
    ? ` This also gives the report's key again to ${organizationName}, which keeps access, so its key is checked too.` : '';
  const way = ` This device could not confirm the approved key of ${checked} (${domain}). ` +
    'The organization may have changed its key or approval. Refresh and try again.';
  // Added files must reach every organization whose access covers files added
  // later; the way to add them without that organization is to change its access.
  const add = action.operation === 'add'
    ? ` To add files without sharing them with ${checked}, first use "Change what they can read" under "Who has access" ` +
      'so its access does not include files you add later.' : '';
  return lead + other + way + add;
}
/** Why a remaining organization kept a revoke from happening: the rotated case
 * key must reach every organization that keeps access, and this device wraps it
 * only to a key it has just confirmed in the approved roster. */
export type RevokeBlocker = { organizationId: string; name: string; domain: string | null;
  reason: 'not-allowed' | 'failed' | 'replaced' };
/** A revoke did not happen because of another organization that keeps access.
 * Nothing was changed; the message names that organization and the way out. */
export class RevokeBlockedError extends Error {
  constructor(readonly revoking: readonly { organizationId: string; name: string }[], readonly blockers: readonly RevokeBlocker[]) {
    super(revokeBlockedText(revoking.map(item => item.name), blockers));
    this.name = 'RevokeBlockedError';
  }
}
const list = (names: readonly string[]) => names.length < 2 ? names.join('')
  : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
export function revokeBlockedText(revoking: readonly string[], blockers: readonly RevokeBlocker[]): string {
  const replaced = blockers.filter(item => item.reason === 'replaced').map(item => item.name);
  const notAllowed = blockers.filter(item => item.reason === 'not-allowed');
  const failed = blockers.filter(item => item.reason === 'failed');
  const lines = [`Access for ${list(revoking)} was not revoked. Nothing changed.`,
    'Revoking gives a new key to every legal organization that keeps access, so it can keep reading.'];
  if (replaced.length) {
    lines.push(`${list(replaced)} replaced ${replaced.length === 1 ? 'its key' : 'their keys'}, so this device cannot give ` +
      `${replaced.length === 1 ? 'it' : 'them'} the new key. Revoke ${list(replaced)} as well, in the same step, or first.`);
  }
  const unconfirmed = [...notAllowed, ...failed];
  if (unconfirmed.length) {
    lines.push(`This device could not confirm the approved key of ${list(unconfirmed.map(item => item.name))}. ` +
      'Refresh and try again; their key or approval may have changed.');
  }
  if (!replaced.length) lines.push(`Or revoke ${list(blockers.map(item => item.name))} at the same time; then no check is needed.`);
  return lines.join(' ');
}
export type OwnerProgress = 'unlocking' | 'unlocked';
export type StoredCaseMessage = { kind?: 'report-open'; organizationId: string; sender: string; ciphertext: string; createdAt: number };
export type OwnerInbox = {
  checkpoint: string; checkpointDigest: string; current: CaseCheckpoint;
  statements: Record<string, string>; summary: string | null;
  deliveries: DeliveredLegalAccessRequest[]; messages: StoredCaseMessage[];
};
export type VerifiedOrganization = TrustedLegalOrganization & { displayName: string; domain: string;
  /** Independent witness of this firm's key binding (firmKeyWitness.ts). */
  witness?: WitnessStatus;
  /** Optional organization-signed profile retained from this session. */
  profile: FirmProfile | null };
export type VerifiedRequest = { delivery: DeliveredLegalAccessRequest; request: LegalAccessRequest; organization: VerifiedOrganization };
/** One organization's current access. `organization` is null when its key is not
 * (or no longer) confirmed by the approved roster; such a grantee cannot receive keys. */
export type CurrentGrantee = { grantDigests: string[]; grants: AccessGrant[]; organizationId: string;
  organization: VerifiedOrganization | null };
export type OwnerThread = { organization: VerifiedOrganization; messages: CaseMessage[]; canSend: boolean; requestId?: string };
export type EvidenceFile = { name: string; type: string; bytes: Uint8Array };

/** The served case history does not contain the checkpoint this device
 * remembered: the host rolled back or forked it. */
export class ConfidentialRollbackError extends Error {
  constructor() {
    super('This report\'s history does not match what this device saw before.');
    this.name = 'ConfidentialRollbackError';
  }
}

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

/** Public case locator from a recovery code (for per-case device settings). */
export async function caseLocator(code: string): Promise<string> { return recoveryCaseLocator(code.trim()); }

/** Restore owner authority locally. The code never leaves this device; only its
 * public case locator is used to fetch the encrypted package (unless the
 * participant supplies the package from their downloaded recovery file). */
export async function restoreOwnerSession(input: { code: string; recoveryPackage?: string | null; relay: ChannelRelay;
  releaseManifest: string; now: number; rememberedPin?: CheckpointPin | null }): Promise<OwnerSession> {
  const caseId = await recoveryCaseLocator(input.code.trim());
  let recoveryPackage = input.recoveryPackage ?? undefined;
  // The attested session verified here is kept for this view's next operations.
  const sessions = new ChannelSessions(input.relay, input.releaseManifest);
  try {
    if (!recoveryPackage) {
      const reply = await publicCaseOperation({ relay: input.relay, releaseManifest: input.releaseManifest, now: input.now,
        request: { operation: 'case.recovery-package', caseId }, sessions }) as { recoveryPackage?: unknown };
      if (typeof reply?.recoveryPackage !== 'string') throw new ConfidentialUnavailableError();
      recoveryPackage = reply.recoveryPackage;
    }
    const restored = await restoreOwnerRecovery(input.code.trim(), recoveryPackage);
    const { digest } = await readReleaseManifest(input.releaseManifest);
    let minimumPin: CheckpointPin | null = null;
    const remembered = input.rememberedPin;
    if (remembered) {
      // A remembered pin for another owner key is not ours to enforce; a pin at the
      // same revision with a different digest is fork evidence.
      if (remembered.caseId !== restored.pin.caseId || remembered.ownerFingerprint !== restored.pin.ownerFingerprint) {
        throw new ConfidentialUnavailableError();
      }
      if (remembered.revision === restored.pin.revision && remembered.digest !== restored.pin.digest) throw new ConfidentialRollbackError();
      if (remembered.revision > restored.pin.revision) minimumPin = { ...remembered };
    }
    const session: OwnerSession = { relay: input.relay, releaseManifest: input.releaseManifest, releaseDigest: digest,
      owner: restored.privateKey, trust: restored.trust, pin: restored.pin, pinnedCheckpoint: restored.checkpoint, minimumPin,
      recoveryCode: input.code.trim(), freshness: remembered ? 'device-pinned' : 'unconfirmed' };
    adoptChannelSessions(session, sessions);
    return session;
  } catch (error) { sessions.clear(); throw error; }
}

/** An exact backend release the owner approved, as recorded in the pinned checkpoint. */
export type ApprovedRelease = { releaseDigest: string; approvedAt: number };
/** Before handing any backend the case key, confirm this device's pinned state
 * names an owner approval of exactly this release. Also returns the earlier
 * approvals this device can verify, for the "Approve update" explanation. */
export async function releaseApprovalReview(session: OwnerSession, now: number): Promise<{
  status: 'approved' | 'needs-approval'; approvals: ApprovedRelease[];
}> {
  const pinned = (await verifyOwnerStatement(session.pinnedCheckpoint, session.trust)).statement as CaseCheckpoint;
  const reply = await publicCaseOperation({ relay: session.relay, releaseManifest: session.releaseManifest, now,
    request: { operation: 'case.release-approvals', caseId: session.trust.caseId },
    sessions: channelSessionsFor(session, session.relay, session.releaseManifest) }) as { releases?: unknown };
  if (!Array.isArray(reply?.releases)) throw new ConfidentialUnavailableError();
  const approvals: ApprovedRelease[] = [];
  for (const wire of reply.releases) {
    try {
      const { statement, digest } = await verifyOwnerStatement(wire, session.trust);
      if (statement.kind === 'release' && pinned.releaseDigests.includes(digest) &&
          !approvals.some(item => item.releaseDigest === statement.releaseDigest)) {
        approvals.push({ releaseDigest: statement.releaseDigest, approvedAt: statement.issuedAt });
      }
    } catch { /* Unverifiable rows are ignored. */ }
  }
  approvals.sort((a, b) => a.approvedAt - b.approvedAt);
  return { status: approvals.some(item => item.releaseDigest === session.releaseDigest) ? 'approved' : 'needs-approval', approvals };
}
export async function releaseApprovalStatus(session: OwnerSession, now: number): Promise<'approved' | 'needs-approval'> {
  return (await releaseApprovalReview(session, now)).status;
}

async function operate(session: OwnerSession, operation: Parameters<typeof ownerOperation>[0]['operation'], body: unknown, now: number) {
  if (!operation.startsWith('read-') && operation !== 'unlock-case') await session.assertDeviceHistory?.();
  // Bodies can carry state keys (unlock, rotation) and wrapped envelopes; clear
  // the encoded copy once sent. JavaScript strings cannot be cleared.
  const bytes = encode(body);
  try {
    return await ownerOperation({ relay: session.relay, releaseManifest: session.releaseManifest, now, caseId: session.trust.caseId,
      owner: session.owner, operation, body: bytes, sessions: channelSessionsFor(session, session.relay, session.releaseManifest) });
  } finally { bytes.fill(0); }
}
async function readStateKey(session: OwnerSession, now: number): Promise<CaseStateKey> {
  const keys = await operate(session, 'read-state-keys', { caseId: session.trust.caseId }, now) as { stateEnvelopes?: string[] };
  if (!Array.isArray(keys?.stateEnvelopes)) throw new ConfidentialUnavailableError();
  return findCaseStateKey(keys.stateEnvelopes, session.trust.caseId, session.owner, session.trust.ownerPublicKey);
}
async function unlock(session: OwnerSession, now: number): Promise<void> {
  try { session.onProgress?.('unlocking'); } catch { /* Progress display never blocks the flow. */ }
  const state = await readStateKey(session, now);
  try {
    const reply = await operate(session, 'unlock-case', { caseId: session.trust.caseId, stateKey: encodeBase64(state.key),
      stateEpoch: state.stateEpoch }, now) as { unlocked?: boolean };
    if (reply?.unlocked !== true) throw new ConfidentialUnavailableError();
  } finally { state.key.fill(0); }
  try { session.onProgress?.('unlocked'); } catch { /* Progress display never blocks the flow. */ }
}
/** Private operations answer `locked` after an enclave restart: unlock once, retry once. */
async function operateUnlocked(session: OwnerSession, operation: Parameters<typeof ownerOperation>[0]['operation'],
  body: unknown, now: number): Promise<unknown> {
  const reply = await operate(session, operation, body, now) as { error?: string };
  if (reply?.error !== 'locked') return reply;
  await unlock(session, now);
  return operate(session, operation, body, now);
}
function advanced(session: OwnerSession, pin: CheckpointPin, checkpoint: string): void {
  session.pin = pin;
  session.pinnedCheckpoint = checkpoint;
  try { session.onPinAdvance?.(pin); } catch { /* Persistence is a convenience; never block the flow. */ }
}
async function currentState(session: OwnerSession, operation: 'read-inbox' | 'read-state', now: number) {
  const basePin = session.pin, baseCheckpoint = session.pinnedCheckpoint;
  const baseHistory = session.history, minimum = session.minimumPin;
  const full = !baseHistory;
  const afterCheckpoint = full ? null : basePin.digest;
  const reply = await operateUnlocked(session, operation, { caseId: session.trust.caseId, afterCheckpoint }, now) as
    { error?: string; checkpoints?: string[]; statements?: Record<string, string>; requests?: DeliveredLegalAccessRequest[]; messages?: unknown[]; next?: unknown; stateNext?: unknown };
  if (reply?.error || !Array.isArray(reply?.checkpoints) || !reply.statements) throw new ConfidentialUnavailableError();
  const reservePage = confidentialPageBudget();
  reservePage(reply);
  if (operation === 'read-inbox') {
    const seenCursors = new Set<string>();
    let next = reply.next;
    while (next !== null && next !== undefined) {
      const key = JSON.stringify(next);
      if (seenCursors.has(key)) throw new ConfidentialUnavailableError();
      seenCursors.add(key);
      const page = await operateUnlocked(session, operation, { caseId: session.trust.caseId,
        afterCheckpoint, mailboxCursor: next }, Date.now()) as typeof reply;
      reservePage(page);
      if (page?.error || !Array.isArray(page.requests) || !Array.isArray(page.messages)) throw new ConfidentialUnavailableError();
      (reply.requests ??= []).push(...page.requests);
      (reply.messages ??= []).push(...page.messages);
      next = page.next;
    }
  }

  const seenStateCursors = new Set<string>();
  let stateNext = reply.stateNext;
  while (stateNext !== null && stateNext !== undefined) {
    const key = JSON.stringify(stateNext);
    if (seenStateCursors.has(key)) throw new ConfidentialUnavailableError();
    seenStateCursors.add(key);
    const page = await operateUnlocked(session, 'read-state', { caseId: session.trust.caseId,
      afterCheckpoint, stateCursor: stateNext }, Date.now()) as typeof reply;
    reservePage(page);
    if (page?.error || !Array.isArray(page.checkpoints) || !page.statements) throw new ConfidentialUnavailableError();
    reply.checkpoints.push(...page.checkpoints);
    Object.assign(reply.statements, page.statements);
    stateNext = page.stateNext;
  }
  // Participant freshness: the returned chain must extend this device's pin, one
  // verified hash link at a time. The first read fetches the whole chain from
  // genesis, so the device holds a verified history, and the recovery pin must lie
  // on it (otherwise the served history differs from what the recovery file saw).
  const history = full ? [] as OwnerHistoryEntry[] : [...baseHistory!];
  const seen = new Map<number, string>(full ? [] : [[basePin.revision, basePin.digest]]);
  let pin: CheckpointPin | null = full ? null : basePin;
  let metPin = !full;
  for (const wire of reply.checkpoints) {
    const next = await linkedCheckpoint(wire, session.trust, pin);
    const checkpoint = (await verifyOwnerStatement(wire, session.trust)).statement as CaseCheckpoint;
    if (next.digest === basePin.digest) {
      if (next.revision !== basePin.revision) throw new ConfidentialRollbackError();
      metPin = true;
    } else if (!metPin && next.revision >= basePin.revision) throw new ConfidentialRollbackError();
    pin = next;
    seen.set(pin.revision, pin.digest);
    history.push({ digest: next.digest, wire, checkpoint });
  }
  if (!metPin || !pin) throw new ConfidentialRollbackError();
  if (minimum && (pin.revision < minimum.revision || seen.get(minimum.revision) !== minimum.digest)) {
    // The host served a chain that does not contain what this device saw before.
    throw new ConfidentialRollbackError();
  }
  const checkpoint = history[history.length - 1]?.wire ?? baseCheckpoint;
  const verified = await verifyOwnerStatement(checkpoint, session.trust);
  if (verified.statement.kind !== 'checkpoint' || verified.digest !== pin.digest) throw new ConfidentialRollbackError();
  // Nothing from a failed or superseded read may mutate the saved history or
  // overwrite a pin advanced by another read/owner commit while verification ran.
  if (session.pin !== basePin || session.pinnedCheckpoint !== baseCheckpoint ||
      session.history !== baseHistory || session.minimumPin !== minimum) throw new ConfidentialRollbackError();
  session.minimumPin = null;
  session.history = history;
  if (pin.digest !== basePin.digest) advanced(session, pin, checkpoint);
  return { reply, checkpoint, checkpointDigest: pin.digest, current: verified.statement };
}
/** Genesis (revision 1, no predecessor) or a direct successor of `previous`. */
async function linkedCheckpoint(wire: string, trust: OwnerTrust, previous: CheckpointPin | null): Promise<CheckpointPin> {
  try {
    if (previous) return await advanceOwnerCheckpoint(wire, trust, previous);
    const { statement, digest } = await verifyOwnerStatement(wire, trust);
    if (statement.kind !== 'checkpoint' || statement.previousDigest !== null || statement.revision !== 1) throw new Error();
    return { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint, revision: 1, keyEpoch: statement.keyEpoch, digest };
  } catch { throw new ConfidentialRollbackError(); }
}
function storedMessages(value: unknown): StoredCaseMessage[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is StoredCaseMessage => !!item && typeof item === 'object' &&
    typeof item.organizationId === 'string' && typeof item.sender === 'string' &&
    typeof item.ciphertext === 'string' && typeof item.createdAt === 'number')
    .map(({ organizationId, sender, ciphertext, createdAt, kind }) => ({ organizationId, sender, ciphertext, createdAt,
      ...(kind === 'report-open' ? { kind } : {}) }));
}

/** Requires an approved release (see releaseApprovalStatus). */
export async function readOwnerInbox(session: OwnerSession, now: number): Promise<OwnerInbox> {
  const { reply, checkpoint, checkpointDigest, current } = await currentState(session, 'read-inbox', now);
  let summary: string | null = null;
  if (current.listingDigest && reply.statements![current.listingDigest]) {
    const listing = await verifyOwnerStatement(reply.statements![current.listingDigest], session.trust);
    if (listing.statement.kind === 'listing' && listing.digest === current.listingDigest) {
      summary = (listing.statement as CaseListing).summary;
    }
  }
  return { checkpoint, checkpointDigest, current, statements: reply.statements!, summary,
    deliveries: Array.isArray(reply.requests) ? reply.requests : [], messages: storedMessages(reply.messages) };
}

/** Approved organizations from the attested enclave roster. The enclave verifies
 * onboarding-authority signed registrations. No legal website is contacted. */
export async function verifiedRoster(session: OwnerSession, now: number,
  witnessList?: readonly FirmKeyWitnessEntry[]): Promise<VerifiedOrganization[]> {
  const reply = await operate(session, 'read-legal-roster', { caseId: session.trust.caseId }, now) as
    { organizations?: { organizationId: string; displayName: string; domain: string; publicKey: string; bindingDocument?: string | null }[] };
  if (!Array.isArray(reply?.organizations)) throw new ConfidentialUnavailableError();
  const verified: VerifiedOrganization[] = [];
  for (const entry of reply.organizations) {
    try {
      if (!entry || typeof entry.organizationId !== 'string' || !/^[a-f0-9]{64}$/.test(entry.organizationId) ||
          typeof entry.displayName !== 'string' || typeof entry.publicKey !== 'string' ||
          typeof entry.domain !== 'string' || entry.domain.length > 253 ||
          !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(entry.domain)) continue;
      const publicKey = await readKey({ armoredKey: entry.publicKey });
      if (publicKey.isPrivate()) continue;
      const recipientKeyId = await caseRecipientKeyId(publicKey);
      // Checked against the bundled, reviewed record only (no network): a
      // recorded organization presenting another key is not trusted until the
      // change is reviewed and re-recorded.
      const witness = witnessStatus({ organizationId: entry.organizationId, domain: entry.domain, recipientKeyId }, witnessList);
      if (witness === 'mismatch') continue;
      let profile: FirmProfile | null = null;
      if (typeof entry.bindingDocument === 'string') {
        try {
          const binding = await verifyFirmKeyBinding(entry.bindingDocument, {
            organizationId: entry.organizationId, domain: entry.domain,
          });
          if (binding.binding.recipientKeyId === recipientKeyId) profile = binding.profile;
        } catch { /* A malformed optional profile never changes the approved key. */ }
      }
      verified.push({ organizationId: entry.organizationId, publicKey, approved: true,
        displayName: entry.displayName, domain: entry.domain, witness, profile });
    } catch { /* An unreadable roster row never becomes a recipient. */ }
  }
  return verified;
}

/** Re-read the attested approved roster before sharing key material. A changed
 * recipient key never inherits an existing grant or an earlier confirmation. */
export async function confirmOrganizationKeys(session: OwnerSession, organizations: readonly VerifiedOrganization[],
  action: KeyCheckAction = { operation: 'share' }): Promise<void> {
  if (!organizations.length) return;
  const roster = await verifiedRoster(session, Date.now()).catch(() => {
    const organization = organizations[0];
    throw new OrganizationKeyUnconfirmedError(organization.domain, 'failed', action, organization.displayName);
  });
  for (const organization of organizations) {
    const current = roster.find(entry => entry.organizationId === organization.organizationId && entry.domain === organization.domain);
    if (!current || await caseRecipientKeyId(current.publicKey) !== await caseRecipientKeyId(organization.publicKey)) {
      throw new OrganizationKeyUnconfirmedError(organization.domain, 'failed', action, organization.displayName);
    }
    organization.profile = current.profile;
  }
}

/** The owner-signed manifest named by the current checkpoint, verified. */
export async function currentManifest(session: OwnerSession, inbox: OwnerInbox): Promise<CaseManifest | null> {
  if (!inbox.current.manifestDigest) return null;
  const verified = await verifyOwnerStatement(inbox.statements[inbox.current.manifestDigest] ?? '', session.trust);
  if (verified.statement.kind !== 'manifest' || verified.digest !== inbox.current.manifestDigest) throw new ConfidentialUnavailableError();
  return verified.statement as CaseManifest;
}

/** Pending deliveries not yet answered by a grant. Callers issue grants with
 * `grantId` = the request ID, so an allowed request is not shown again, including
 * after that grant is revoked (the firm must send a new request). */
export function unansweredDeliveries(inbox: OwnerInbox): DeliveredLegalAccessRequest[] {
  const answered = new Set<string>();
  for (const wire of Object.values(inbox.statements)) {
    try {
      const value = JSON.parse(wire)?.statement;
      if (value?.kind === 'grant' && typeof value.grantId === 'string') answered.add(`${value.organizationId}:${value.grantId}`);
    } catch { /* Not a statement this view needs. */ }
  }
  return inbox.deliveries.filter(delivery => !answered.has(`${delivery.organizationId}:${delivery.requestId}`));
}

/** Classify only after decrypting and verifying blinded delivery commitments.
 * An answered valid request is distinct from an unverifiable request. */
export async function reviewOwnerRequests(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  now: number): Promise<{ requests: VerifiedRequest[]; unverified: number }> {
  const requests: VerifiedRequest[] = [];
  let unverified = 0;
  for (const delivery of inbox.deliveries) {
    try {
      const request = await openDeliveredLegalAccessRequest(delivery, session.trust.caseId, session.owner, roster, trustedNow(now));
      const resolved = { ...delivery, requestId: request.requestId, organizationId: request.organizationId,
        recipientKeyId: request.recipientKeyId };
      delete resolved.routing;
      if (!unansweredDeliveries({ ...inbox, deliveries: [resolved] }).length) continue;
      requests.push({ delivery: resolved, request, organization: roster.find(item => item.organizationId === request.organizationId)! });
    } catch { unverified++; }
  }
  return { requests, unverified };
}
export async function verifiedRequests(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  now: number): Promise<VerifiedRequest[]> {
  return (await reviewOwnerRequests(session, inbox, roster, now)).requests;
}

/** Current grants in the pinned checkpoint, grouped by organization. A grantee is
 * shown by its verified roster name only when the roster key matches the key the
 * grant was issued to. */
export async function currentGrantees(session: OwnerSession, inbox: OwnerInbox,
  roster: VerifiedOrganization[]): Promise<CurrentGrantee[]> {
  const byOrganization = new Map<string, CurrentGrantee>();
  for (const digest of inbox.current.grantDigests) {
    const wire = inbox.statements[digest];
    if (!wire) throw new ConfidentialUnavailableError();
    const verified = await verifyOwnerStatement(wire, session.trust);
    if (verified.statement.kind !== 'grant' || verified.digest !== digest) throw new ConfidentialUnavailableError();
    const grant = verified.statement as AccessGrant;
    let entry = byOrganization.get(grant.organizationId);
    if (!entry) {
      const candidate = roster.find(item => item.organizationId === grant.organizationId) ?? null;
      const organization = candidate && await caseRecipientKeyId(candidate.publicKey) === grant.recipientKeyId ? candidate : null;
      entry = { grantDigests: [], grants: [], organizationId: grant.organizationId, organization };
      byOrganization.set(grant.organizationId, entry);
    }
    entry.grantDigests.push(digest);
    entry.grants.push(grant);
  }
  return [...byOrganization.values()];
}

/** Grantees holding at least one grant still in force at trusted time `now`.
 * Only these receive the case state key: access that has ended keeps no
 * authority, even though it stays in the checkpoint (and in the reporter's
 * list) until it is renewed or revoked. */
export function activeGrantees(grantees: readonly CurrentGrantee[], now: number): CurrentGrantee[] {
  const time = trustedNow(now);
  return grantees.filter(item => item.grants.some(grant => grantActiveAt(grant, time)));
}

async function assertCurrent(session: OwnerSession, inbox: OwnerInbox): Promise<void> {
  await session.assertDeviceHistory?.();
  // A view older than this device's pin would sign a conflicting successor.
  if (inbox.checkpointDigest !== session.pin.digest) throw new ConfidentialUnavailableError();
}
async function successor(session: OwnerSession, inbox: OwnerInbox, changes: Partial<CaseCheckpoint>, now: number) {
  await session.assertDeviceHistory?.();
  const revision = inbox.current.revision + 1;
  // Signed time never runs backwards along the chain, even if this device's clock is behind.
  const wire = await signOwnerStatement({ ...inbox.current, revision, previousDigest: inbox.checkpointDigest,
    issuedAt: Math.max(trustedTime(now), inbox.current.issuedAt), ...changes } as CaseCheckpoint, session.owner);
  return { wire, revision, digest: (await verifyOwnerStatement(wire, session.trust)).digest };
}
async function signed(session: OwnerSession, statement: OwnerStatement) {
  await session.assertDeviceHistory?.();
  const wire = await signOwnerStatement(statement, session.owner);
  return { wire, digest: (await verifyOwnerStatement(wire, session.trust)).digest };
}
/** Success requires the exact checkpoint receipt; only then does the pin advance. */
/** Encrypted recovery package for `nextCheckpoint` (must directly extend the session
 * pin). Every owner commit carries it so a fresh-device restore starts from the
 * newest owner-signed state. */
export async function refreshedRecoveryPackage(session: OwnerSession, nextCheckpoint: string): Promise<string> {
  return (await refreshOwnerRecovery(session.recoveryCode, session.owner, nextCheckpoint, session.pin)).encryptedPackage;
}
async function commit(session: OwnerSession, body: Record<string, unknown>, checkpoint: string, now: number): Promise<void> {
  const expected = (await verifyOwnerStatement(checkpoint, session.trust)).digest;
  const recoveryPackage = await refreshedRecoveryPackage(session, checkpoint);
  const receipt = await operateUnlocked(session, 'commit-transition', { caseId: session.trust.caseId, statements: [],
    objects: [], envelopes: [], stateEnvelopes: null, stateKeyRotation: null, ...body, recoveryPackage, checkpoint }, now) as
    { checkpointDigest?: string };
  if (receipt?.checkpointDigest !== expected) throw new ConfidentialUnavailableError();
  const pin = await advanceOwnerCheckpoint(checkpoint, session.trust, session.pin);
  session.history?.push({ digest: pin.digest, wire: checkpoint,
    checkpoint: (await verifyOwnerStatement(checkpoint, session.trust)).statement as CaseCheckpoint });
  advanced(session, pin, checkpoint);
}
function approvedRelease(session: OwnerSession, inbox: OwnerInbox): string {
  const release = inbox.current.releaseDigests.map(digest => inbox.statements[digest]).find(wire => {
    try { const value = JSON.parse(wire).statement; return value.kind === 'release' && value.releaseDigest === session.releaseDigest; }
    catch { return false; }
  });
  if (!release) throw new ConfidentialUnavailableError();
  return release;
}

/** A grant that shares only contact or identity details ("Share my contact
 * details"). It is managed separately from report/evidence access. */
export function isContactGrant(grant: Pick<AccessGrant, 'scopes'>): boolean {
  return grant.scopes.every(scope => scope === 'contact' || scope === 'identity');
}

async function ownerEnvelopes(session: OwnerSession, now: number) {
  const envelopes = await operateUnlocked(session, 'read-owner-envelopes', { caseId: session.trust.caseId }, now) as
    { envelopes?: { objectId: string; ownerEnvelope: string }[] };
  if (!Array.isArray(envelopes?.envelopes)) throw new ConfidentialUnavailableError();
  return envelopes.envelopes;
}
function grantWires(inbox: OwnerInbox, grantee: CurrentGrantee, keep: (grant: AccessGrant) => boolean): string[] {
  return grantee.grants.flatMap((grant, index) => keep(grant) ? [inbox.statements[grantee.grantDigests[index]]] : []);
}

/** Explicit Allow: owner signature, key wrapping and state-key redistribution
 * happen here; success requires the exact checkpoint receipt. When the
 * organization already holds report/evidence access (a renewal request, or a
 * second request), this decision replaces that access; a separate contact
 * sharing grant is kept, with its end moved to this decision's end. */
export async function allowAccess(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  verified: VerifiedRequest, decision: OwnerGrantDecision, now: number): Promise<void> {
  await assertCurrent(session, inbox);
  // The organization replaced its key (for example after a member left): its
  // current grants name a key the verified roster no longer lists. Access moves
  // to the new key only by this explicit Allow, and first the old key's grants
  // are revoked with a state-key rotation, so the old key opens no later history.
  const replaced = await replacedKeyGrant(session, inbox, roster, verified.request.organizationId);
  if (replaced) {
    // Check every key this Allow needs before revoking the old one, so a roster
    // check fails as "not allowed", not as a revoke the reporter did not ask for.
    const requesting = roster.find(item => item.organizationId === verified.request.organizationId);
    const keeping = activeGrantees(await currentGrantees(session, inbox, roster), now)
      .filter(item => item.organizationId !== verified.request.organizationId && item.organization);
    if (requesting) {
      await confirmOrganizationKeys(session, [requesting, ...keeping.map(item => item.organization!)],
        { operation: 'allow', target: requesting.displayName });
    }
    await revokeAccess(session, inbox, roster, replaced.grantDigests[0], now);
    const fresh = await readOwnerInbox(session, Date.now());
    const again = (await verifiedRequests(session, fresh, roster, Date.now()))
      .find(item => item.delivery.requestId === verified.delivery.requestId &&
        item.request.organizationId === verified.request.organizationId);
    if (!again) throw new ConfidentialUnavailableError();
    return allowAccess(session, fresh, roster, again, decision, Date.now());
  }
  // The requester and every grantee whose access is still in force receive the
  // case state key here; an organization whose access has ended does not.
  const grantees = activeGrantees(await currentGrantees(session, inbox, roster), now);
  if (grantees.some(item => !item.organization)) throw new ConfidentialUnavailableError();
  const requester = roster.find(item => item.organizationId === verified.request.organizationId);
  if (!requester) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [requester, ...grantees.map(item => item.organization!)],
    { operation: 'allow', target: requester.displayName });
  const envelopes = await ownerEnvelopes(session, now);
  const state = await readStateKey(session, now);
  try {
    // Existing grantees keep receiving the (unchanged) state key.
    const current = await currentGrantees(session, inbox, roster);
    const recipients = activeGrantees(current, now);
    // Never silently drop a grantee's key.
    if (recipients.some(item => !item.organization)) throw new ConfidentialUnavailableError();
    if (!inbox.current.manifestDigest) throw new ConfidentialUnavailableError();
    const existing = current.find(item => item.organizationId === verified.request.organizationId);
    // Contact sharing to the requesting key is kept and re-signed to end with
    // this access; anything else of this organization (report access, or contact
    // sharing to an older key or epoch) is replaced.
    const kept = (grant: AccessGrant) => isContactGrant(grant) && grant.recipientKeyId === verified.request.recipientKeyId &&
      grant.keyEpoch === inbox.current.keyEpoch;
    const prepared = await prepareOwnerGrant({ delivery: verified.delivery, directory: roster, trust: session.trust,
      owner: session.owner, checkpoint: inbox.checkpoint, checkpointDigest: inbox.checkpointDigest,
      manifest: inbox.statements[inbox.current.manifestDigest], release: approvedRelease(session, inbox),
      releaseDigest: session.releaseDigest, now: trustedTime(now), decision, objects: envelopes,
      replacedGrants: existing ? grantWires(inbox, existing, grant => !kept(grant)) : [],
      realignedGrants: existing ? grantWires(inbox, existing, kept) : [],
      sealedState: { state, currentRecipients: recipients.filter(item => item.organizationId !== verified.request.organizationId)
        .map(item => item.organization!.publicKey) } });
    await commit(session, prepared.body, prepared.body.checkpoint, now);
  } finally { state.key.fill(0); }
}

/** "Renew access": the same access for one organization, with a new end date
 * (`null` = until you revoke it). Contact sharing, if any, is renewed with it.
 * Access that had already ended no longer holds the case state key (a rotation
 * after it ended was not wrapped to it), so renewing it re-wraps the current
 * state key to the owner, every organization whose access is in force, and this
 * one, after confirming each of those keys in the approved roster. */
export async function renewAccess(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  grantee: CurrentGrantee, expiresAt: number | null, now: number): Promise<void> {
  await assertCurrent(session, inbox);
  if (!grantee.organization || !grantee.grants.length || !inbox.current.manifestDigest) throw new ConfidentialUnavailableError();
  const ended = !activeGrantees([grantee], now).length;
  const others = ended ? activeGrantees(await currentGrantees(session, inbox, roster), now)
    .filter(item => item.organizationId !== grantee.organizationId) : [];
  // Never silently drop another grantee's state key.
  if (others.some(item => !item.organization)) throw new ConfidentialUnavailableError();
  // Content keys are re-wrapped to this organization key: confirm it against the approved roster first.
  await confirmOrganizationKeys(session, [grantee.organization, ...others.map(item => item.organization!)],
    { operation: 'renew', target: grantee.organization.displayName });
  const envelopes = await ownerEnvelopes(session, now);
  const prepared = await prepareGrantRenewal({ trust: session.trust, owner: session.owner, checkpoint: inbox.checkpoint,
    checkpointDigest: inbox.checkpointDigest, manifest: inbox.statements[inbox.current.manifestDigest],
    release: approvedRelease(session, inbox), releaseDigest: session.releaseDigest, objects: envelopes,
    organization: { organizationId: grantee.organizationId, publicKey: grantee.organization.publicKey },
    grants: grantWires(inbox, grantee, () => true), expiresAt, now: trustedTime(now) });
  if (!ended) {
    await commit(session, prepared.body, prepared.body.checkpoint, now);
    return;
  }
  const state = await readStateKey(session, now);
  try {
    const stateEnvelopes = await Promise.all([session.trust.ownerPublicKey, ...others.map(item => item.organization!.publicKey),
      grantee.organization.publicKey].map(key => wrapCaseStateKey(session.trust.caseId, state, key, session.owner)));
    await commit(session, { ...prepared.body, stateEnvelopes, stateKeyRotation: null }, prepared.body.checkpoint, now);
  } finally { state.key.fill(0); }
}

/** Read-only profile check: never signs a grant or sends case contents to the firm. */
export async function verifyOrganizationProfile(session: OwnerSession, organizationId: string, now: number): Promise<VerifiedOrganization> {
  const organization = (await verifiedRoster(session, now)).find(item => item.organizationId === organizationId);
  if (!organization) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [organization]);
  return organization;
}

/** Proactive sharing is an explicit owner decision, not an invented firm request.
 * Refresh the enclave-authenticated roster and confirm its key on the firm's
 * domain. Existing grants must be changed through the separate renewal flow. */
export async function shareWithOrganization(session: OwnerSession, inbox: OwnerInbox, organizationId: string,
  decision: OwnerGrantDecision, now: number): Promise<void> {
  if (!inbox.current.listingDigest) throw new ConfidentialUnavailableError();
  await assertCurrent(session, inbox);
  if (!inbox.current.manifestDigest || !decision.scopes.length ||
      decision.scopes.some(scope => !['narrative', 'evidence', 'messages'].includes(scope))) throw new ConfidentialUnavailableError();
  const roster = await verifiedRoster(session, now);
  const organization = roster.find(item => item.organizationId === organizationId);
  const current = await currentGrantees(session, inbox, roster);
  if (!organization || current.some(item => item.organizationId === organizationId)) throw new ConfidentialUnavailableError();
  const active = activeGrantees(current, now);
  if (active.some(item => !item.organization)) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [organization, ...active.map(item => item.organization!)],
    { operation: 'share', target: organization.displayName });
  const objects = await ownerEnvelopes(session, now);
  const state = await readStateKey(session, now);
  try {
    await assertCurrent(session, inbox);
    const prepared = await prepareDirectGrant({ organization, decision, trust: session.trust, owner: session.owner,
      checkpoint: inbox.checkpoint, checkpointDigest: inbox.checkpointDigest,
      manifest: inbox.statements[inbox.current.manifestDigest], release: approvedRelease(session, inbox),
      releaseDigest: session.releaseDigest, now: trustedTime(now), objects,
      sealedState: { state, currentRecipients: active.map(item => item.organization!.publicKey) } });
    await commit(session, prepared.body, prepared.body.checkpoint, now);
  } finally { state.key.fill(0); }
}

/** "Change what they can read": the reporter replaces an organization's current
 * report/evidence access with a new explicit choice (for example to share files
 * added after the first Allow), without waiting for a new request. The
 * organization must already hold access under the key the verified roster names,
 * and that key is confirmed against the approved roster first. The end date comes from the
 * decision (the UI keeps the current one). Contact sharing to the same key is
 * kept and re-signed to end with it. The organization is already a state-key
 * recipient under the same key, so the state key is neither re-wrapped nor rotated. */
export async function changeAccess(session: OwnerSession, inbox: OwnerInbox, grantee: CurrentGrantee,
  decision: OwnerGrantDecision, now: number): Promise<void> {
  await assertCurrent(session, inbox);
  const time = trustedTime(now);
  const main = grantee.grants.filter(grant => !isContactGrant(grant));
  if (!grantee.organization || !main.length || !main.some(grant => grantActiveAt(grant, trustedNow(now))) ||
      !inbox.current.manifestDigest || decision.scopes.some(scope => scope === 'contact' || scope === 'identity')) {
    throw new ConfidentialUnavailableError();
  }
  const recipientKeyId = await caseRecipientKeyId(grantee.organization.publicKey);
  // Messages come only with a request; a change never adds them.
  if (decision.scopes.includes('messages') && !main.some(grant => grant.scopes.includes('messages'))) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [grantee.organization], { operation: 'change', target: grantee.organization.displayName });
  const envelopes = await ownerEnvelopes(session, now);
  const kept = (grant: AccessGrant) => isContactGrant(grant) && grant.recipientKeyId === recipientKeyId &&
    grant.keyEpoch === inbox.current.keyEpoch;
  const prepared = await prepareDirectGrant({ organization: { organizationId: grantee.organizationId,
    publicKey: grantee.organization.publicKey }, trust: session.trust, owner: session.owner, checkpoint: inbox.checkpoint,
  checkpointDigest: inbox.checkpointDigest, manifest: inbox.statements[inbox.current.manifestDigest],
  release: approvedRelease(session, inbox), releaseDigest: session.releaseDigest, now: time, objects: envelopes, decision,
  replacedGrants: grantWires(inbox, grantee, grant => !kept(grant)), realignedGrants: grantWires(inbox, grantee, kept) });
  await commit(session, prepared.body, prepared.body.checkpoint, now);
}

/** Case objects that contact sharing would disclose, from the signed manifest. */
export function contactScopes(inbox: OwnerInbox): ('contact' | 'identity')[] {
  const manifestWire = inbox.current.manifestDigest ? inbox.statements[inbox.current.manifestDigest] : undefined;
  if (!manifestWire) return [];
  try {
    const objects = (JSON.parse(manifestWire).statement as CaseManifest).objects;
    return (['contact', 'identity'] as const).filter(scope => objects.some(item => item.scope === scope));
  } catch { return []; }
}

/** Explicit "Share my contact details with X": a separate grant covering only
 * the contact (and identity, if given) objects, for an organization that already
 * has access. It ends when report access ends, or earlier if stopped. */
export async function shareContactDetails(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  grantee: CurrentGrantee, now: number): Promise<void> {
  await assertCurrent(session, inbox);
  const time = trustedTime(now);
  const scopes = contactScopes(inbox);
  const main = grantee.grants.filter(grant => !isContactGrant(grant) && grantActiveAt(grant, trustedNow(now)));
  if (!grantee.organization || !scopes.length || !main.length || !inbox.current.manifestDigest ||
      grantee.grants.some(grant => isContactGrant(grant) && grantActiveAt(grant, trustedNow(now)))) throw new ConfidentialUnavailableError();
  const expiresAt = main.some(grant => grant.expiresAt === null) ? null : Math.max(...main.map(grant => grant.expiresAt as number));
  // Contact objects and the case state key are wrapped to these organization
  // keys: confirm each against the approved roster first.
  const grantees = activeGrantees(await currentGrantees(session, inbox, roster), now);
  if (grantees.some(item => !item.organization)) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [grantee.organization, ...grantees.map(item => item.organization!)],
    { operation: 'contact', target: grantee.organization.displayName });
  const envelopes = await ownerEnvelopes(session, now);
  const state = await readStateKey(session, now);
  try {
    const current = activeGrantees(await currentGrantees(session, inbox, roster), now);
    if (current.some(item => !item.organization)) throw new ConfidentialUnavailableError();
    const grantId = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    const prepared = await prepareDirectGrant({ organization: { organizationId: grantee.organizationId,
      publicKey: grantee.organization.publicKey }, trust: session.trust, owner: session.owner, checkpoint: inbox.checkpoint,
    checkpointDigest: inbox.checkpointDigest, manifest: inbox.statements[inbox.current.manifestDigest],
    release: approvedRelease(session, inbox), releaseDigest: session.releaseDigest, now: time, objects: envelopes,
    decision: { grantId, scopes, objectRevisionLimit: null, expiresAt },
    // Drop an expired earlier contact grant rather than keep a dead entry.
    replacedGrants: grantWires(inbox, grantee, grant => isContactGrant(grant)),
    sealedState: { state, currentRecipients: current.filter(item => item.organizationId !== grantee.organizationId)
      .map(item => item.organization!.publicKey) } });
    await commit(session, prepared.body, prepared.body.checkpoint, now);
  } finally { state.key.fill(0); }
}

/** "Stop sharing contact details": removes only the contact grant. The
 * organization keeps report access; the state key is not rotated because it
 * remains a recipient. Details it already read cannot be taken back. */
export async function stopSharingContactDetails(session: OwnerSession, inbox: OwnerInbox, grantee: CurrentGrantee,
  now: number): Promise<void> {
  await assertCurrent(session, inbox);
  const dropped = new Set(grantee.grantDigests.filter((_, index) => isContactGrant(grantee.grants[index])));
  if (!dropped.size || dropped.size === grantee.grantDigests.length) throw new ConfidentialUnavailableError();
  const checkpoint = await successor(session, inbox, {
    grantDigests: inbox.current.grantDigests.filter(digest => !dropped.has(digest)) }, now);
  await commit(session, {}, checkpoint.wire, now);
}

/** Current access this organization holds under a key it has since replaced. */
export async function replacedKeyGrant(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  organizationId: string): Promise<CurrentGrantee | null> {
  if (!roster.some(item => item.organizationId === organizationId)) return null;
  return (await currentGrantees(session, inbox, roster))
    .find(item => item.organizationId === organizationId && !item.organization) ?? null;
}

export async function declineAccess(session: OwnerSession, verified: VerifiedRequest, now: number): Promise<void> {
  const reply = await operateUnlocked(session, 'decline-request', { caseId: session.trust.caseId,
    organizationId: verified.delivery.organizationId, requestId: verified.delivery.requestId }, now) as { state?: string };
  if (reply?.state !== 'declined') throw new ConfidentialUnavailableError();
}

/** Explicit "Revoke access" for one organization: every current grant it holds
 * is dropped from a new checkpoint, and the case state key is rotated and
 * re-wrapped to the owner and the remaining grantees only, so the revoked firm's
 * copy opens no later history.
 *
 * The object key epoch (`CaseCheckpoint.keyEpoch`) is deliberately kept: remaining
 * grants stay valid without re-signing, and objects are never re-encrypted.
 * Revocation stops future access and future key distribution; it cannot retract
 * content keys or plaintext the firm already downloaded. */
export async function revokeAccess(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  grantDigest: string, now: number): Promise<void> {
  const grantees = await currentGrantees(session, inbox, roster);
  const revoked = grantees.find(item => item.grantDigests.includes(grantDigest));
  if (!revoked) throw new ConfidentialUnavailableError();
  await revokeOrganizations(session, inbox, roster, [revoked.organizationId], now);
}

/** Revoke one or more organizations in one checkpoint and one state-key
 * rotation. The rotated key is wrapped only to the owner and to organizations
 * whose access is still in force, with keys confirmed in the approved roster (never to an unconfirmed or replaced key, and a
 * remaining organization is never silently dropped). When a remaining
 * organization blocks that, nothing is changed and `RevokeBlockedError` names
 * every such organization, so the reporter can fix it or revoke it too. */
export async function revokeOrganizations(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  organizationIds: readonly string[], now: number): Promise<void> {
  await assertCurrent(session, inbox);
  const grantees = await currentGrantees(session, inbox, roster);
  const ids = new Set(organizationIds);
  const revoked = grantees.filter(item => ids.has(item.organizationId));
  if (!ids.size || revoked.length !== ids.size) throw new ConfidentialUnavailableError();
  // Only organizations whose access is still in force keep the case: they get
  // the rotated state key and their keys are checked. An organization whose
  // access has ended receives nothing, is never contacted and never blocks this
  // revoke; its ended grants stay listed until the reporter renews or revokes them.
  const remaining = activeGrantees(grantees, now).filter(item => !ids.has(item.organizationId));
  const nameOf = (item: CurrentGrantee) => item.organization?.displayName ??
    roster.find(entry => entry.organizationId === item.organizationId)?.displayName ?? 'An organization that can no longer be verified';
  const blockers: RevokeBlocker[] = remaining.filter(item => !item.organization)
    .map(item => ({ organizationId: item.organizationId, name: nameOf(item), domain: null, reason: 'replaced' as const }));
  const checkable = remaining.filter(item => item.organization);
  if (!blockers.length) {
    for (const item of checkable) {
      try { await confirmOrganizationKeys(session, [item.organization!]); }
      catch { blockers.push({ organizationId: item.organizationId, name: nameOf(item), domain: item.organization!.domain, reason: 'failed' }); }
    }
  }
  if (blockers.length) {
    throw new RevokeBlockedError(revoked.map(item => ({ organizationId: item.organizationId, name: nameOf(item) })), blockers);
  }
  const dropped = new Set(revoked.flatMap(item => item.grantDigests));
  const previous = await readStateKey(session, now);
  const next = generateCaseStateKey(previous.stateEpoch + 1);
  previous.key.fill(0);
  try {
    const checkpoint = await successor(session, inbox, {
      grantDigests: inbox.current.grantDigests.filter(digest => !dropped.has(digest)) }, now);
    const stateEnvelopes = await Promise.all([session.trust.ownerPublicKey, ...remaining.map(item => item.organization!.publicKey)]
      .map(key => wrapCaseStateKey(session.trust.caseId, next, key, session.owner)));
    await commit(session, { stateEnvelopes, stateKeyRotation: { stateKey: encodeBase64(next.key), stateEpoch: next.stateEpoch } },
      checkpoint.wire, now);
  } finally { next.key.fill(0); }
}

/** Evidence encrypted on this device for one "add files" commit. Keep it for
 * the whole upload: a resume re-encrypts only the chunks the relay has not
 * confirmed (`uploadState`) from the original files. */
export type PreparedEvidence = {
  caseId: string; baseCheckpointDigest: string; revision: number; keyEpoch: number;
  objects: SealedChunkedObject[]; uploadState: ChunkUploadState;
};
/** The report changed (for example access was changed on this device) while
 * files were uploading; the prepared files no longer fit the new state. */
export class EvidenceStaleError extends Error {
  constructor() { super('Your report changed while the files were uploading. Choose Encrypt and add to try again.'); }
}

/** Step 1 of adding evidence: validate limits and encrypt each file as a chunked
 * object (new object IDs, `objectRevision` = the next checkpoint revision). */
export async function prepareEvidence(session: OwnerSession, inbox: OwnerInbox,
  files: readonly (EvidenceSource | EvidenceFile)[], onProgress?: (progress: EncryptionProgress) => void): Promise<PreparedEvidence> {
  await assertCurrent(session, inbox);
  const sources = files.map(file => 'bytes' in file ? bytesEvidenceSource(file) : file);
  if (!sources.length) throw new ConfidentialUnavailableError();
  checkEvidenceSources(sources);
  const caseId = session.trust.caseId, revision = inbox.current.revision + 1, keyEpoch = inbox.current.keyEpoch;
  const randomId = () => Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const objects = await sealEvidenceFiles(sources, () => ({ caseId, objectId: randomId(), scope: 'evidence',
    keyEpoch, objectRevision: revision }), session.owner, onProgress);
  return { caseId, baseCheckpointDigest: inbox.checkpointDigest, revision, keyEpoch, objects, uploadState: createChunkUploadState() };
}

/** Step 2: resumable upload of the encrypted chunks (see uploadChunkedObjects). */
export async function uploadEvidence(session: OwnerSession, prepared: PreparedEvidence,
  options: { onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal; wait?: (ms: number) => Promise<void> } = {}): Promise<void> {
  await uploadChunkedObjects(session.relay, prepared.objects, prepared.uploadState, options);
}

/** Step 3: a new owner-signed manifest and checkpoint reference the files.
 * Content keys are wrapped for current grantees whose grant is future-inclusive
 * (`objectRevisionLimit: null`) and covers evidence; other grantees receive
 * nothing new. Every such grantee's key is confirmed in the approved roster first;
 * if one cannot be (or the approved roster is unavailable), this
 * throws `OrganizationKeyUnconfirmedError` (operation 'add') and nothing is
 * signed or added, so the uploaded files can be committed later. Returns the
 * organizations that received keys. */
export async function commitEvidence(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  prepared: PreparedEvidence, now: number): Promise<{ sharedWith: VerifiedOrganization[];
    added: { objectId: string; name: string }[] }> {
  const currentTime = callerClock(now);
  // An upload may finish with the view captured before another action advanced
  // this device's checkpoint. Discard that prepared work rather than offering
  // to finish a commit that can no longer apply, even before the view refreshes.
  if (prepared.baseCheckpointDigest !== session.pin.digest) throw new EvidenceStaleError();
  await assertCurrent(session, inbox);
  const caseId = session.trust.caseId, current = inbox.current;
  if (prepared.caseId !== caseId || prepared.baseCheckpointDigest !== inbox.checkpointDigest ||
      prepared.revision !== current.revision + 1 || prepared.keyEpoch !== current.keyEpoch) throw new EvidenceStaleError();
  // Organizations whose access covers files added later. Each must receive the
  // key for every new file: the service lets such an organization read the new
  // files, so a missing key would stop it opening the report at all. Their keys
  // are confirmed in the approved roster before anything is signed; if one cannot
  // be confirmed (or the approved roster is unavailable), nothing is added.
  const time = trustedTime(now);
  const recipients: { organization: VerifiedOrganization; grantee: CurrentGrantee; index: number }[] = [];
  for (const grantee of await currentGrantees(session, inbox, roster)) {
    if (!grantee.organization) continue;
    const index = grantee.grants.findIndex(grant => grant.objectRevisionLimit === null && grant.scopes.includes('evidence') &&
      grant.keyEpoch === current.keyEpoch && grantActiveAt(grant, trustedNow(now)));
    if (index >= 0) recipients.push({ organization: grantee.organization, grantee, index });
  }
  for (const { organization } of recipients) {
    await confirmOrganizationKeys(session, [organization], { operation: 'add', target: organization.displayName });
  }
  let objects: ManifestEntry[] = [];
  if (current.manifestDigest) {
    const manifest = await verifyOwnerStatement(inbox.statements[current.manifestDigest] ?? '', session.trust);
    if (manifest.statement.kind !== 'manifest' || manifest.digest !== current.manifestDigest) throw new ConfidentialUnavailableError();
    objects = (manifest.statement as CaseManifest).objects;
  }
  const revision = prepared.revision;
  const manifest = await signed(session, { kind: 'manifest', caseId, revision, objects: [...objects,
    ...prepared.objects.map(item => ({ objectId: item.context.objectId, scope: 'evidence' as const, objectRevision: revision,
      keyEpoch: current.keyEpoch, ciphertextDigest: item.digest }))] });
  const checkpoint = await successor(session, inbox, { manifestDigest: manifest.digest }, now);
  const release = approvedRelease(session, inbox);
  const envelopes: { objectId: string; recipientKeyId: string; envelope: string }[] = [];
  const sharedWith: VerifiedOrganization[] = [];
  for (const { organization, grantee, index } of recipients) {
    const grant = grantee.grants[index];
    for (const item of prepared.objects) {
      // Only the small key envelope is re-wrapped; chunks are never re-encrypted.
      const envelope = await grantCaseObjectEnvelope(item.ownerEnvelope, item.context, session.owner, organization.publicKey, {
        trust: session.trust, grant: inbox.statements[grantee.grantDigests[index]], release, manifest: manifest.wire,
        checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest,
        request: { organizationId: grant.organizationId, recipientKeyId: grant.recipientKeyId, objectId: item.context.objectId,
          ciphertextDigest: item.digest, scope: 'evidence', releaseDigest: session.releaseDigest,
          keyEpoch: current.keyEpoch, objectRevision: revision, now: trustedNow(now) } });
      envelopes.push({ objectId: item.context.objectId, recipientKeyId: grant.recipientKeyId, envelope });
    }
    sharedWith.push(organization);
  }
  // Every chunk must have been confirmed by the relay before the commit names it.
  if (prepared.objects.some(item => item.chunkDigests.some(digest => !prepared.uploadState.staged.has(digest)))) {
    throw new ConfidentialUnavailableError('verification');
  }
  await commit(session, { statements: [manifest.wire], envelopes,
    objects: prepared.objects.map(item => ({ objectId: item.context.objectId, chunkedIndex: item.index, ownerEnvelope: item.ownerEnvelope })) },
  checkpoint.wire, currentTime());
  // Names stay on this device (in memory) so the reporter can pick files by name later.
  const added = prepared.objects.map(item => ({ objectId: item.context.objectId, name: item.header.name }));
  for (const item of prepared.objects) item.dispose();
  return { sharedWith, added };
}

/** Add evidence after submission in one call: prepare, upload, commit. */
export async function addEvidence(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  files: readonly (EvidenceSource | EvidenceFile)[], now: number): ReturnType<typeof commitEvidence> {
  // The commit is signed at the current time, however long the upload took.
  const clock = callerClock(now);
  const prepared = await prepareEvidence(session, inbox, files);
  try {
    await uploadEvidence(session, prepared);
    return await commitEvidence(session, inbox, roster, prepared, clock());
  } finally { for (const item of prepared.objects) item.dispose(); }
}

/** One of the reporter's own evidence files. Chunked files show their name, type
 * and size; an older whole file over 128 KB shows only that it exists. */
export type OwnerEvidence = {
  objectId: string; name?: string; type?: string; size?: number; chunked: boolean;
  /** True for files sent with the original report, false for files added later. */
  original: boolean;
};
type ObjectEntry = CaseManifest['objects'][number];
const OBJECT_RANGE = 128 * 1024;

async function currentEvidence(session: OwnerSession, inbox: OwnerInbox): Promise<ObjectEntry[]> {
  if (!inbox.current.manifestDigest) return [];
  const manifest = await verifyOwnerStatement(inbox.statements[inbox.current.manifestDigest] ?? '', session.trust);
  if (manifest.statement.kind !== 'manifest' || manifest.digest !== inbox.current.manifestDigest) throw new ConfidentialUnavailableError();
  return (manifest.statement as CaseManifest).objects.filter(entry => entry.scope === 'evidence');
}
/** Reads stored object text by ranges (all of it, or only the first range). */
async function readOwnerObjectText(session: OwnerSession, entry: ObjectEntry, now: number, firstRangeOnly: boolean):
  Promise<{ text: string | null; ownerEnvelope: string; totalBytes: number }> {
  const parts: Uint8Array[] = [];
  let totalBytes = 0, envelope = '', offset = 0;
  try {
    do {
      const reply = await operateUnlocked(session, 'read-object', { caseId: session.trust.caseId, objectId: entry.objectId,
        checkpointDigest: session.pin.digest, offset, length: OBJECT_RANGE }, now) as Record<string, unknown>;
      if (!reply || Object.keys(reply).sort().join(',') !== 'chunk,ciphertextDigest,objectId,offset,ownerEnvelope,totalBytes' ||
          reply.objectId !== entry.objectId || reply.ciphertextDigest !== entry.ciphertextDigest || reply.offset !== offset ||
          !Number.isSafeInteger(reply.totalBytes) || (reply.totalBytes as number) < 1 || (reply.totalBytes as number) > 16 * 1024 * 1024 ||
          (offset > 0 && reply.totalBytes !== totalBytes) || typeof reply.ownerEnvelope !== 'string' ||
          (envelope && envelope !== reply.ownerEnvelope) || typeof reply.chunk !== 'string') throw new ConfidentialUnavailableError();
      totalBytes = reply.totalBytes as number; envelope = reply.ownerEnvelope;
      const bytes = decodeBase64Strict(reply.chunk);
      if (bytes.length !== Math.min(OBJECT_RANGE, totalBytes - offset)) throw new ConfidentialUnavailableError();
      parts.push(bytes); offset += bytes.length;
    } while (offset < totalBytes && !firstRangeOnly);
    if (offset < totalBytes) return { text: null, ownerEnvelope: envelope, totalBytes };
    const all = new Uint8Array(totalBytes);
    parts.reduce((at, part) => { all.set(part, at); return at + part.length; }, 0);
    const digest = Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', all)), b => b.toString(16).padStart(2, '0')).join('');
    if (digest !== entry.ciphertextDigest) throw new ConfidentialUnavailableError();
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(all), ownerEnvelope: envelope, totalBytes };
  } finally { for (const part of parts) part.fill(0); }
}
function context(session: OwnerSession, entry: ObjectEntry) {
  return { caseId: session.trust.caseId, objectId: entry.objectId, scope: entry.scope, keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision };
}

export type OwnerReport = { narrative: Record<string, string | boolean | null> | null;
  records: { scope: import('../../enclave/src/confidential/authorization').CaseScope;
    fields: Record<string, string | boolean | null> }[] };

/** Read the reporter's own signed manifest and decrypt text records locally.
 * Evidence stays lazy, and no plaintext or key is persisted or sent to the host. */
export async function readOwnerReport(session: OwnerSession, inbox: OwnerInbox): Promise<OwnerReport> {
  await assertCurrent(session, inbox);
  const checkpoint = session.pin.digest;
  const manifest = await currentManifest(session, inbox);
  const report: OwnerReport = { narrative: null, records: [] };
  if (!manifest) throw new ConfidentialUnavailableError();
  for (const entry of manifest.objects.filter(item => item.scope !== 'evidence' && item.scope !== 'messages')) {
    const object = await readOwnerObjectText(session, entry, Date.now(), false);
    if (object.text === null) throw new ConfidentialUnavailableError();
    const bytes = await openOwnerCaseObject({ ciphertext: object.text, ownerEnvelope: object.ownerEnvelope },
      context(session, entry), session.owner);
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ConfidentialUnavailableError();
      const fields: Record<string, string | boolean | null> = {};
      for (const [key, item] of Object.entries(value)) {
        if (item === null || typeof item === 'string' || typeof item === 'boolean') fields[key] = item;
      }
      if (entry.scope === 'narrative' && report.narrative === null) report.narrative = fields;
      else report.records.push({ scope: entry.scope, fields });
    } finally { bytes.fill(0); }
  }
  if (session.pin.digest !== checkpoint) throw new ConfidentialUnavailableError();
  return report;
}

export type VerifiedReportOpen = { organization: VerifiedOrganization;
  receipt: import('../../enclave/src/confidential/reportOpenReceipt').ReportOpenReceipt };
/** Verify fixed-purpose firm acknowledgements against the approved key and the
 * owner's signed grant history. Legacy messages never become open receipts. */
export async function readReportOpens(session: OwnerSession, inbox: OwnerInbox,
  roster: readonly VerifiedOrganization[], now: number): Promise<VerifiedReportOpen[]> {
  const { openReportOpenReceipt } = await import('../../enclave/src/confidential/reportOpenReceipt');
  const first = new Map<string, VerifiedReportOpen>();
  for (const stored of inbox.messages.filter(item => item.kind === 'report-open' && item.sender === 'organization')) {
    const organization = roster.find(item => item.organizationId === stored.organizationId);
    if (!organization) continue;
    try {
      const history = session.history ?? [];
      const historicalKeys = new Set<string>();
      for (const digest of new Set(history.flatMap(item => item.checkpoint.grantDigests))) {
        const grant = await verifyOwnerStatement(inbox.statements[digest], session.trust);
        if (grant.digest === digest && grant.statement.kind === 'grant' &&
            grant.statement.organizationId === organization.organizationId) historicalKeys.add(grant.statement.recipientKeyId);
      }
      const receipt = await openReportOpenReceipt(stored.ciphertext, { owner: session.trust, organization },
        session.owner, [...historicalKeys]);
      const position = history.findIndex(item => item.digest === receipt.checkpointDigest);
      if (position < 0 || !issuedNotAfter(receipt.openedAt, now)) continue;
      const checkpoint = history[position].checkpoint;
      if (!issuedNotAfter(checkpoint.issuedAt, receipt.openedAt) ||
          (history[position + 1] && receipt.openedAt > history[position + 1].checkpoint.issuedAt)) continue;
      let authorized = false;
      for (const digest of checkpoint.grantDigests) {
        const verified = await verifyOwnerStatement(inbox.statements[digest], session.trust);
        const grant = verified.statement;
        if (verified.digest === digest && grant.kind === 'grant' && grant.organizationId === organization.organizationId &&
            grant.recipientKeyId === receipt.recipientKeyId && grant.keyEpoch === checkpoint.keyEpoch &&
            grant.revision <= checkpoint.revision && grant.scopes.includes('narrative') && grantActiveAt(grant, receipt.openedAt)) authorized = true;
      }
      if (!authorized) continue;
      const previous = first.get(organization.organizationId);
      if (!previous || receipt.openedAt < previous.receipt.openedAt) first.set(organization.organizationId, { organization, receipt });
    } catch { /* Unverified receipts are never displayed as facts. */ }
  }
  return [...first.values()];
}

/** The reporter's own evidence files, newest last, decrypted on this device. */
export async function listOwnerEvidence(session: OwnerSession, inbox: OwnerInbox, now: number): Promise<OwnerEvidence[]> {
  await assertCurrent(session, inbox);
  const result: OwnerEvidence[] = [];
  for (const entry of await currentEvidence(session, inbox)) {
    const { text, ownerEnvelope } = await readOwnerObjectText(session, entry, now, true);
    const base = { objectId: entry.objectId, original: entry.objectRevision === 1 };
    if (text !== null && isChunkedIndexText(text)) {
      const reader = await openOwnerChunkedObject(text, ownerEnvelope, context(session, entry), entry.ciphertextDigest, session.owner);
      result.push({ ...base, name: reader.name, type: reader.type, size: reader.size, chunked: true });
      reader.dispose();
    } else if (text !== null) {
      const plain = await openOwnerCaseObject({ ciphertext: text, ownerEnvelope }, context(session, entry), session.owner);
      try {
        const file = unpackCaseFile(plain);
        result.push({ ...base, name: file.name, type: file.type, size: file.bytes.length, chunked: false });
        file.bytes.fill(0);
      } finally { plain.fill(0); }
    } else result.push({ ...base, chunked: false });
  }
  return result;
}

/** Owner download of a chunked file (for EvidenceDownload): re-reads the current
 * signed state, then each chunk is an owner-authenticated read at that checkpoint. */
export async function openOwnerChunkedEvidence(session: OwnerSession, objectId: string, now: number): Promise<OpenedChunkedEvidence> {
  const inbox = await readOwnerInbox(session, now);
  const entry = (await currentEvidence(session, inbox)).find(item => item.objectId === objectId);
  if (!entry) throw new ConfidentialUnavailableError();
  const { text, ownerEnvelope } = await readOwnerObjectText(session, entry, now, false);
  if (text === null || !isChunkedIndexText(text) || await chunkedIndexDigest(text) !== entry.ciphertextDigest) throw new ConfidentialUnavailableError();
  const reader = await openOwnerChunkedObject(text, ownerEnvelope, context(session, entry), entry.ciphertextDigest, session.owner);
  const checkpointDigest = session.pin.digest;
  return { reader, async fetchChunk(position) {
    const reply = await operateUnlocked(session, 'read-object', { caseId: session.trust.caseId, objectId,
      checkpointDigest, chunkIndex: position }, Date.now()) as Record<string, unknown>;
    if (!reply || Object.keys(reply).sort().join(',') !== 'chunk,chunkIndex,ciphertextDigest,objectId' ||
        reply.objectId !== objectId || reply.ciphertextDigest !== entry.ciphertextDigest || reply.chunkIndex !== position ||
        typeof reply.chunk !== 'string') throw new ConfidentialUnavailableError();
    return decodeChunk(reply.chunk);
  } };
}

/** Owner download of an older whole-buffer file (at most 8 MB). */
export async function openOwnerWholeEvidence(session: OwnerSession, objectId: string, now: number): Promise<EvidenceFile> {
  const inbox = await readOwnerInbox(session, now);
  const entry = (await currentEvidence(session, inbox)).find(item => item.objectId === objectId);
  if (!entry) throw new ConfidentialUnavailableError();
  const { text, ownerEnvelope } = await readOwnerObjectText(session, entry, now, false);
  if (text === null || isChunkedIndexText(text)) throw new ConfidentialUnavailableError();
  const plain = await openOwnerCaseObject({ ciphertext: text, ownerEnvelope }, context(session, entry), session.owner);
  try { return unpackCaseFile(plain); } finally { plain.fill(0); }
}

/** Preserve only metadata authenticated by a checkpoint in this device's verified history.
 * Missing legacy fields stay absent; editing a summary never invents a submission date. */
async function submissionListingMetadata(session: OwnerSession, inbox: OwnerInbox): Promise<Pick<CaseListing, 'publishedAt' | 'hasAttachments'>> {
  const digests = [inbox.current.listingDigest, ...(session.history ?? []).slice().reverse().map(item => item.checkpoint.listingDigest)];
  for (const digest of digests) {
    if (!digest) continue;
    if (!inbox.statements[digest]) throw new ConfidentialUnavailableError();
    const verified = await verifyOwnerStatement(inbox.statements[digest], session.trust);
    if (verified.digest !== digest || verified.statement.kind !== 'listing') throw new ConfidentialUnavailableError();
    const { publishedAt, hasAttachments } = verified.statement;
    return { ...(publishedAt !== undefined ? { publishedAt } : {}), ...(hasAttachments !== undefined ? { hasAttachments } : {}) };
  }
  return {};
}

/** Close activity in one signed transition: no listing, no grants, and only the
 * owner receives the rotated state key. Never revoke firms one at a time. */
export async function closeReport(session: OwnerSession, inbox: OwnerInbox, now: number): Promise<void> {
  await assertCurrent(session, inbox);
  if (inbox.current.listingDigest === null && !inbox.current.grantDigests.length) return;
  const previous = await readStateKey(session, now);
  const next = generateCaseStateKey(previous.stateEpoch + 1);
  previous.key.fill(0);
  try {
    const checkpoint = await successor(session, inbox, { listingDigest: null, grantDigests: [] }, now);
    const envelope = await wrapCaseStateKey(session.trust.caseId, next, session.trust.ownerPublicKey, session.owner);
    await commit(session, { stateEnvelopes: [envelope],
      stateKeyRotation: { stateKey: encodeBase64(next.key), stateEpoch: next.stateEpoch } }, checkpoint.wire, now);
  } finally { next.key.fill(0); }
}

/** Restore only a summary authenticated by the owner's checkpoint history. */
export async function previousSummary(session: OwnerSession, inbox: OwnerInbox): Promise<string | null> {
  if (inbox.summary !== null) return inbox.summary;
  for (const entry of [...session.history ?? []].reverse()) {
    const digest = entry.checkpoint.listingDigest;
    if (!digest || !inbox.statements[digest]) continue;
    const verified = await verifyOwnerStatement(inbox.statements[digest], session.trust);
    if (verified.digest !== digest || verified.statement.kind !== 'listing') throw new ConfidentialUnavailableError();
    return verified.statement.summary;
  }
  return null;
}

/** Public summary edits preserve the original signed submission facts. */
export async function updateSummary(session: OwnerSession, inbox: OwnerInbox, summary: string | null, now: number): Promise<void> {
  // Validate before any network call so an unexpected value never reaches a signature.
  await assertCurrent(session, inbox);
  const revision = inbox.current.revision + 1;
  if (summary === null) {
    if (inbox.current.listingDigest === null) return;
    const checkpoint = await successor(session, inbox, { listingDigest: null }, now);
    await commit(session, {}, checkpoint.wire, now);
    return;
  }
  const listing = await signed(session, { kind: 'listing', caseId: session.trust.caseId, revision, summary, ...await submissionListingMetadata(session, inbox) });
  const checkpoint = await successor(session, inbox, { listingDigest: listing.digest }, now);
  await commit(session, { statements: [listing.wire] }, checkpoint.wire, now);
}

/** Decrypt and verify owner <-> firm threads. Only organizations on the
 * authenticated roster are shown (replying first confirms the key on the
 * approved organization registration). Each message is checked against that roster key,
 * this case and organization, and per-sender sequence floors (in stored order),
 * so replays and reordering are dropped. */
export async function readOwnerThreads(session: OwnerSession, inbox: OwnerInbox, roster: VerifiedOrganization[],
  requests: VerifiedRequest[], grantees: CurrentGrantee[]): Promise<OwnerThread[]> {
  // Replying seals the message to the organization key the roster names now.
  // Allow that only for a key the reporter has answered: a pending request
  // signed by that key, or current access granted to that exact key. When the
  // roster key changed since access was granted (a replaced or substituted
  // key), the thread is read-only until the reporter allows the new key.
  const canSend = new Set([...requests.map(item => item.request.organizationId),
    ...grantees.filter(item => item.organization).map(item => item.organizationId)]);
  const ids = [...new Set([...grantees.filter(item => item.organization).map(item => item.organizationId),
    ...requests.map(item => item.request.organizationId), ...inbox.messages.map(item => item.organizationId)])];
  const threads: OwnerThread[] = [];
  for (const organizationId of ids) {
    const organization = roster.find(item => item.organizationId === organizationId);
    if (!organization) continue;
    const participants = { owner: session.trust, organization: { organizationId, publicKey: organization.publicKey } };
    const floors = { owner: 0, organization: 0 };
    const messages: CaseMessage[] = [];
    for (const stored of inbox.messages.filter(item => item.organizationId === organizationId)) {
      try {
        const message = await openCaseMessage(stored.ciphertext, participants, session.owner, floors);
        if (message.sender !== stored.sender) continue;
        floors[message.sender] = message.sequence;
        messages.push(message);
      } catch { /* Unverifiable, replayed or reordered messages are never shown. */ }
    }
    threads.push({ organization, messages, canSend: canSend.has(organizationId),
      requestId: requests.find(item => item.request.organizationId === organizationId)?.request.requestId });
  }
  return threads;
}

export async function sendOwnerMessage(session: OwnerSession, thread: OwnerThread, body: string, now: number): Promise<void> {
  if (!thread.canSend) throw new ConfidentialUnavailableError();
  await confirmOrganizationKeys(session, [thread.organization], { operation: 'message', target: thread.organization.displayName });
  const sequence = thread.messages.filter(item => item.sender === 'owner').reduce((max, item) => Math.max(max, item.sequence), 0) + 1;
  const ciphertext = await sealCaseMessage({ sender: 'owner', sequence, sentAt: trustedTime(now), body },
    { owner: session.trust, organization: { organizationId: thread.organization.organizationId, publicKey: thread.organization.publicKey } },
    session.owner);
  const reply = await operateUnlocked(session, 'send-message', { caseId: session.trust.caseId,
    organizationId: thread.organization.organizationId, ciphertext, ...(thread.requestId ? { requestId: thread.requestId } : {}) }, now) as { sent?: boolean };
  if (reply?.sent !== true) throw new ConfidentialUnavailableError();
}

/** Backend releases a checkpoint keeps approved: the one being approved plus the
 * most recent others (rolling deploys, rollback). Well under the 32-digest
 * checkpoint cap, so approvals never run out; retired releases age out. */
export const RETAINED_RELEASE_APPROVALS = 8;

/** Explicit "Approve update": the owner consents to this exact backend release.
 * Only after that consent may the release receive the case state key. */
export async function approveCurrentRelease(session: OwnerSession, now: number): Promise<void> {
  const { reply, current, checkpoint } = await currentState(session, 'read-state', now);
  const tip = await verifyOwnerStatement(checkpoint, session.trust);
  const revision = current.revision + 1;
  const issuedAt = trustedTime(now);
  const release = await signed(session, { kind: 'release', caseId: session.trust.caseId, revision,
    releaseDigest: session.releaseDigest, issuedAt });
  // Drop earlier approvals of this same release (superseded by the new one), then
  // keep only the most recent others. Unverifiable entries count as distinct.
  const approves = async (digest: string) => {
    try {
      const verified = await verifyOwnerStatement(reply.statements![digest] ?? '', session.trust);
      return verified.digest === digest && verified.statement.kind === 'release' &&
        verified.statement.releaseDigest === session.releaseDigest;
    } catch { return false; }
  };
  const others: string[] = [];
  for (const digest of current.releaseDigests) if (!await approves(digest)) others.push(digest);
  // Signed time never runs backwards along the chain, even if this device's clock is behind.
  const next = await signOwnerStatement({ ...current, revision, previousDigest: tip.digest,
    issuedAt: Math.max(issuedAt, current.issuedAt),
    releaseDigests: [...others.slice(-(RETAINED_RELEASE_APPROVALS - 1)), release.digest] }, session.owner);
  await commit(session, { statements: [release.wire] }, next, now);
}
