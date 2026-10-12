import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { createHash, randomBytes, webcrypto } from 'node:crypto';

// Only the AWS quote check is mocked. Channel encryption, firm/owner proofs, the
// real CaseService (sealed store, grants, release gating) and local decryption
// are real. The legal dispatcher below is a TEST stand-in for the channel
// composition being built separately; it resolves the firm from a synthetic
// token map instead of verifying an Auth0 JWT.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import type { ChannelDispatch } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { CaseServiceError, createCaseService } from '../../../enclave/src/cases/service';
import type {
  CaseRecord, CaseStore, LegalOrganization, OrganizationContext, StoredAccessRequest, StoredEnvelope, StoredMessage, StoredObject,
} from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import { findCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { verifyFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { verifyEnrollmentProof } from '../../../enclave/src/confidential/enrollmentProof';
import type { EnrollmentChallenge } from '../../../enclave/src/confidential/enrollmentProof';
import { ChannelSessions, channelSessionsFor, ConfidentialUnavailableError, ConfidentialUploadInterruptedError, ownerOperation, publishPreparedCase } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import {
  EvidenceStaleError, RETAINED_RELEASE_APPROVALS, addEvidence, allowAccess, approveCurrentRelease, commitEvidence, confirmOrganizationKeys,
  currentGrantees, currentManifest, declineAccess, listOwnerEvidence, openOwnerChunkedEvidence, openOwnerWholeEvidence, prepareEvidence,
  readOwnerInbox, readOwnerReport, readReportOpens, releaseApprovalStatus, renewAccess, restoreOwnerSession, revokeAccess, shareContactDetails, shareWithOrganization, verifyOrganizationProfile,
  stopSharingContactDetails, updateSummary, closeReport, previousSummary, uploadEvidence, verifiedRequests, verifiedRoster,
} from '../../../lib/confidential/ownerCase';
import type { OwnerSession } from '../../../lib/confidential/ownerCase';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint } from '../../../enclave/src/confidential/authorization';
import {
  FirmCaseError, acknowledgeReportOpen, createFirmSession, checkReportAccess, checkReportAccessBatch, openFirmCase, openFirmChunkedEvidence, openFirmEvidence, readCaseStatus, readFirmMessages,
  readLegalDirectory, readRequestStatus, redeemInvitation, requestCaseAccess, sendFirmMessage, unlockFirmCase, withdrawCaseRequest, readCaseRequestStatus,
} from '../../../lib/confidential/firmCase';
import type { AccessRequestDetails } from '../../../enclave/src/confidential/accessRequest';
import { decisionFromChoice, defaultChoice, evidenceEntries } from '../../../lib/confidential/accessChoices';
import { canAskToRenew, canRequestAgain, canWithdraw, caseStatus, statusBadge } from '../../../lib/confidential/firmCaseView';
import { EvidenceDownload, EvidenceDownloadError } from '../../../lib/confidential/evidenceTransfer';
import type { EvidenceSink } from '../../../lib/confidential/evidenceTransfer';
import type { FirmSession } from '../../../lib/confidential/firmCase';
import {
  exportFirmIdentity, firmBindingDocument, generateFirmIdentity, generateFirmRecoveryCode, importFirmIdentity,
} from '../../../lib/confidential/firmKey';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import { LegalSignInRequired, authorizeUrl, legalAuthConfig, pkceChallenge } from '../../../lib/confidential/legalAuth';
import { reportCheckCode } from '../../../lib/confidential/reportCheckCode';

// Three chunks: two full 512 KiB chunks and a padded final one.
const LARGE_EVIDENCE = new Uint8Array(randomBytes(2 * 512 * 1024 + 70_000));
/** Collects a download like a save-file writable; nothing is kept on abort. */
function testSink() {
  const parts: Uint8Array[] = [];
  const state = { closed: false, aborted: false };
  const sink: EvidenceSink = {
    async write(bytes) { parts.push(new Uint8Array(bytes)); },
    async close() { state.closed = true; },
    async abort() { state.aborted = true; parts.length = 0; },
  };
  return { sink, state, digest: () => createHash('sha256').update(Buffer.concat(parts)).digest('hex') };
}
const digestOf = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases';
const TOKEN = 'synthetic-legal-access-token-SENTINEL';
const release = (commit: string, pcr: string) => canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: commit.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: pcr.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const MANIFEST = release('1', '11'), UPGRADE = release('2', '44');
const DETAILS: AccessRequestDetails = { kind: 'new', conflictsChecked: true, feeBasis: 'no-fee', responseTime: 'one-week',
  practiceAreas: ['Employment'], jurisdiction: 'England and Wales', website: 'https://counsel.example/team' };

/** TEST-ONLY store with the fields the sealing decorator and owner flows need. */
function memoryStore() {
  const cases = new Map<string, CaseRecord>(), staged = new Map<string, string>();
  const chunks = new Map<string, Uint8Array>(), promoted = new Set<string>();
  const objects = new Map<string, StoredObject>(), envelopes = new Map<string, StoredEnvelope>();
  const requests: StoredAccessRequest[] = [], messages: StoredMessage[] = [], organizations: LegalOrganization[] = [];
  const host = { reverseStatements: false };
  const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
  const store: CaseStore = {
    async getStagedObject(digest) { return staged.get(digest) ?? null; },
    async promoteChunks(_caseId, _objectDigest, digests, finalBytes) {
      if (!digests.every((digest, position) => chunks.get(digest)?.length ===
        (position === digests.length - 1 ? finalBytes : 512 * 1024) + 16)) return false;
      for (const digest of digests) promoted.add(digest);
      return true;
    },
    async readObjectChunk(caseId, recipientKeyId, checkpointDigest, ref, chunkIndex) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      if (recipientKeyId !== null && !envelopes.get(`${caseId}:${ref.objectId}:${recipientKeyId}`)) return null;
      const item = objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`);
      const digest = item ? JSON.parse(item.ciphertext).chunks[chunkIndex] : undefined;
      if (!digest || !promoted.has(digest)) return null;
      return { chunk: Buffer.from(chunks.get(digest)!).toString('base64') };
    },
    async putObjects(caseId, items) { for (const item of items) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item)); },
    async getObjects(caseId, refs) {
      return refs.map(ref => objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`)).filter(Boolean).map(clone) as StoredObject[];
    },
    async getOwnerEnvelopes(caseId, refs) {
      return refs.map(ref => objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`)).filter(Boolean)
        .map(item => ({ objectId: item!.objectId, ciphertextDigest: item!.ciphertextDigest, ownerEnvelope: item!.ownerEnvelope }));
    },
    async listLegalOrganizations() { return clone(organizations); },
    async getEnvelopes(caseId, recipientKeyId) {
      return [...envelopes.entries()].filter(([key]) => key.startsWith(`${caseId}:`) && key.endsWith(`:${recipientKeyId}`)).map(([, value]) => clone(value));
    },
    async readGrantedObjects(caseId, recipientKeyId, checkpointDigest, refs) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      const result = [];
      for (const ref of refs) {
        const item = objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`);
        const envelope = recipientKeyId === null ? item && { envelope: item.ownerEnvelope }
          : envelopes.get(`${caseId}:${ref.objectId}:${recipientKeyId}`);
        if (!item || !envelope) return null;
        result.push({ objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest, ciphertext: item.ciphertext, recipientEnvelope: envelope.envelope });
      }
      return clone(result);
    },
    async createCase(record) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, clone(record)); return true; },
    async getCase(caseId) {
      const value = cases.get(caseId);
      if (!value) return null;
      const copy = clone(value);
      // Host-controlled storage order for public statements.
      if (host.reverseStatements) copy.statements = Object.fromEntries(Object.entries(copy.statements).reverse());
      return copy;
    },
    async commitTransition(caseId, expected, update) {
      const record = cases.get(caseId);
      if (!record || record.currentCheckpointDigest !== expected) return false;
      for (const item of update.objects) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item));
      for (const item of update.envelopes) envelopes.set(`${caseId}:${item.objectId}:${item.recipientKeyId}`, clone(item));
      cases.set(caseId, { ...record, statements: { ...record.statements, ...update.statements },
        checkpoints: [...record.checkpoints, update.checkpoint], currentCheckpointDigest: update.checkpointDigest,
        listingDigest: update.listingDigest, recoveryPackage: update.recoveryPackage ?? record.recoveryPackage,
        stateEnvelopes: update.stateEnvelopes ?? record.stateEnvelopes, stateEpoch: update.stateEpoch ?? record.stateEpoch });
      return true;
    },
    async listListedCases(limit, after) {
      return [...cases.values()].filter(item => item.listingDigest !== null).sort((a, b) => a.caseId.localeCompare(b.caseId))
        .filter(item => after === null || item.caseId > after).slice(0, limit).map(clone);
    },
    async putAccessRequest() { return false; },
    async getAccessRequest(caseId: string, organizationId: string, requestId: string) {
      return requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId) ?? null;
    },
    async listAccessRequests(caseId) { return requests.filter(item => item.caseId === caseId).map(clone); },
    async insertAccessRequestAtCheckpoint(request, guard) {
      const record = cases.get(request.caseId);
      if (!record || record.currentCheckpointDigest !== guard.checkpointDigest || record.listingDigest === null) return 'conflict';
      const existing = requests.find(item => item.caseId === request.caseId && item.organizationId === request.organizationId &&
        item.requestId === request.requestId);
      if (existing) return existing.state === 'pending' && existing.ciphertext === request.ciphertext ? 'stored' : 'conflict';
      if (requests.some(item => item.caseId === request.caseId && item.organizationId === request.organizationId && item.state === 'pending')) return 'conflict';
      requests.push(clone(request));
      return 'stored';
    },
    async expireAccessRequests(caseId, now) {
      for (const item of requests) if (item.caseId === caseId && item.state === 'pending' && item.expiresAt <= now) item.state = 'expired';
    },
    async countAccessRequests() { return 0; },
    async withdrawAccessRequest(caseId, organizationId, requestId) {
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId && item.state === 'pending');
      if (!found) return false;
      found.state = 'withdrawn'; return true;
    },
    async declineAccessRequest(caseId, organizationId, requestId, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return 'conflict';
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId &&
        item.requestId === requestId && (item.state === 'pending' || item.state === 'declined'));
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
    async appendMessage(message, guard) {
      if (cases.get(message.caseId)?.currentCheckpointDigest !== guard.checkpointDigest) return 'conflict';
      if (message.dedupeTag !== undefined && messages.some(item => item.caseId === message.caseId &&
        item.dedupeTag === message.dedupeTag)) return 'stored';
      messages.push(clone(message)); return 'stored';
    },
    async listMessages(caseId, organizationId, limit) {
      return messages.filter(item => item.caseId === caseId && (organizationId === null || item.organizationId === organizationId)).slice(-limit).map(clone);
    },
    async readMessagesAtCheckpoint(caseId, organizationId, limit, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return messages.filter(item => item.caseId === caseId && item.organizationId === organizationId).slice(-limit).map(clone);
    },
    async readInboxAtCheckpoint(caseId, checkpointDigest) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return { requests: requests.filter(item => item.caseId === caseId && item.state === 'pending').map(clone),
        messages: messages.filter(item => item.caseId === caseId).map(clone) };
    },
    async countMessages() { return 0; },
  };
  return { store, staged, chunks, organizations, host, dump: () => JSON.stringify({ cases: [...cases.values()], objects: [...objects.values()],
    envelopes: [...envelopes.values()], requests, messages }) };
}

/** TEST stand-in for the legal channel dispatcher: wraps the real CaseService. */
function legalStandIn(options: { store: CaseStore; keyring: ReturnType<typeof createCaseKeyring>; releaseDigest: string;
  identities: Map<string, OrganizationContext>; log: string[]; tamperDirectory: () => boolean | 'metadata' | 'fact-time' | 'fact-attachments';
  refuseBatch: () => boolean;
  enrollment: { challenge: EnrollmentChallenge; firmKey: () => FirmIdentity } }): ChannelDispatch {
  return async (raw, context) => {
    const request = JSON.parse(new TextDecoder().decode(raw));
    const service = createCaseService({ store: options.store, keyring: options.keyring, clock: Date.now, audience: AUDIENCE,
      releaseDigest: options.releaseDigest, channel: { nonce: context.nonce, serverKeyId: context.serverKeyId, challenges: context.challenges } });
    options.log.push(request.operation);
    const reply = (value: unknown) => {
      const bytes = new TextEncoder().encode(JSON.stringify(value));
      // One 512 KiB evidence chunk per reply at most, as in the production dispatcher.
      if (bytes.length > 720 * 1024) throw new Error('oversized channel reply');
      return bytes;
    };
    if (request.operation === 'legal.challenge') {
      return reply(request.count === undefined ? await service.issueChallenge() : await service.issueChallenges(request.count));
    }
    const organization = options.identities.get(request.accessToken);
    if (!organization) throw new Error('unauthorized');
    if (request.operation === 'legal.directory') {
      const page = await service.listListings({ kind: 'organization', ...organization }, request.after);
      const listings = await Promise.all(page.listings.map(async item => {
        const record = (await options.store.getCase(item.caseId))!;
        const other = options.tamperDirectory() === true ? (await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
          userIDs: [{ name: 'x' }], format: 'object' })).publicKey.armor() : null;
        const listing = record.statements[record.listingDigest!];
        const wire = JSON.parse(listing);
        return { ...item,
          ...(options.tamperDirectory() === 'fact-time' ? { publishedAt: 0 } : {}),
          ...(options.tamperDirectory() === 'fact-attachments' ? { hasAttachments: !item.hasAttachments } : {}),
          ownerPublicKey: other ?? record.ownerPublicKey,
          listing: options.tamperDirectory() === 'metadata'
            ? JSON.stringify({ ...wire, statement: { ...wire.statement, category: 'financial-fraud', region: 'europe' } }) : listing };

      }));
      return reply({ listings, next: page.next });
    }
    if (request.operation === 'legal.enrollment-challenge') return reply(options.enrollment.challenge);
    if (request.operation === 'legal.enroll') {
      const input = JSON.parse(Buffer.from(request.body, 'base64').toString('utf8'));
      await verifyEnrollmentProof(options.enrollment.challenge, input.proof, options.enrollment.firmKey().privateKey.toPublic());
      return reply({ organizationId: organization.organizationId, subject: 'auth0|member', recipientKeyId: organization.recipientKeyId });
    }
    // An enclave release older than the batched status read has no handler for it.
    if (request.operation === 'legal.request-status-batch' && options.refuseBatch()) throw new Error('Legal case operation unavailable');
    const body = new Uint8Array(Buffer.from(request.body, 'base64'));
    const handlers: Record<string, () => Promise<unknown>> = {
      'legal.request-access': () => service.submitAccessRequest(body, request.proof, organization),
      'legal.withdraw-request': () => service.withdrawAccessRequest(body, request.proof, organization),
      'legal.request-status': () => service.requestStatus(body, request.proof, organization),
      'legal.request-status-batch': () => service.requestStatusBatch(body, request.proof, organization),
      'legal.read-state-keys': () => service.getStateEnvelopes(body, request.proof, organization),
      'legal.unlock-case': () => service.unlockCase(body, request.proof, organization),
      'legal.open-case': () => service.openCase(body, request.proof, organization),
      'legal.acknowledge-report-open': () => service.acknowledgeReportOpen(body, request.proof, organization),
      'legal.read-messages': () => service.readMessages(body, request.proof, organization),
      'legal.send-message': () => service.sendMessage(body, request.proof, organization),
    };
    try { return reply(await handlers[request.operation]()); } catch (error) {
      if (error instanceof CaseServiceError && (error.code === 'locked' || error.code === 'release-not-approved')) return reply({ error: error.code });
      // Mirrors the mounted dispatcher: no current grant for this firm.
      if (error instanceof CaseServiceError && error.code === 'not-found' &&
        (request.operation === 'legal.open-case' || request.operation === 'legal.read-state-keys' ||
         request.operation === 'legal.unlock-case')) return reply({ error: 'not-granted' });
      throw error;
    }
  };
}

let opens = 0;
describe('legal portal firm client over encrypted sessions', () => {
  const backing = memoryStore(), relayed: string[] = [], log: string[] = [];
  let dispatch: ChannelDispatch, relay: ChannelRelay, firm: FirmIdentity, bindingDocument: string;
  let refuseBatch = false;
  let tamper: boolean | 'metadata' | 'fact-time' | 'fact-attachments' = false, identities: Map<string, OrganizationContext>, keyring: ReturnType<typeof createCaseKeyring>;
  let prepared: Awaited<ReturnType<typeof prepareConfidentialSubmission>>;
  const enrollmentChallenge = { format: 'vera-legal-enrollment/v1' as const, invitationId: hex(0x51), organizationId: hex(0xf1),
    providerOrganizationId: 'org_synthetic', subject: 'auth0|member', recipientKeyId: '', nonce: hex(0x52), expiresAt: Date.now() + 3_600_000 };

  /** (Re)boot the enclave: fresh in-memory keyring, same storage. */
  async function boot(manifest = MANIFEST, clock = Date.now) {
    keyring = createCaseKeyring({ clock });
    const store = createSealedCaseStore(backing.store, keyring);
    const releaseDigest = (await readReleaseManifest(manifest)).digest;
    const owner = createOwnerCaseControlDispatcher({ store, keyring, clock, audience: AUDIENCE, releaseDigest });
    const legal = legalStandIn({ store, keyring, releaseDigest, identities, log, tamperDirectory: () => tamper,
      refuseBatch: () => refuseBatch, enrollment: { challenge: enrollmentChallenge, firmKey: () => firm } });
    dispatch = async (body, context) => {
      const operation = JSON.parse(new TextDecoder().decode(body)).operation as string;
      return operation.startsWith('legal.') ? legal(body, context) : owner(body, context);
    };
  }
  async function firmSession(manifest = MANIFEST): Promise<FirmSession> {
    return createFirmSession({ relay, releaseManifest: manifest, firm, accessToken: async () => TOKEN });
  }

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    const keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
    firm = await generateFirmIdentity({ organizationId: hex(0xf1), domain: 'counsel.example' });
    enrollmentChallenge.recipientKeyId = firm.recipientKeyId;
    bindingDocument = await firmBindingDocument(firm, Date.now());
    const organization = { organizationId: firm.organizationId, recipientKeyId: firm.recipientKeyId, publicKey: firm.privateKey.toPublic().armor() };
    identities = new Map([[TOKEN, organization]]);
    backing.organizations.push({ ...organization, displayName: 'Synthetic Counsel LLP', domain: 'counsel.example', approved: true } as LegalOrganization);
    await boot();
    opens = 0;
    const sessions = createSessionCore((body, context) => dispatch(body, context), async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => 1,
      // The frozen test clock never idle-expires kept sessions; the chunked-evidence and release-rotation
      // tests open many of them, so a slow run must not exhaust the production backstop of 64.
      { capacity: 4096 });
    relay = {
      async stage(ciphertext) {
        relayed.push(ciphertext);
        const digest = createHash('sha256').update(ciphertext, 'utf8').digest('hex');
        backing.staged.set(digest, ciphertext);
        return digest;
      },
      async stageChunk(chunk) {
        relayed.push(Buffer.from(chunk).toString('latin1'));
        const digest = createHash('sha256').update(chunk).digest('hex');
        backing.chunks.set(digest, new Uint8Array(chunk));
        return digest;
      },
      async open(nonce) {
        opens++;
        const identity = await sessions.open(nonce);
        return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) };
      },
      async call(nonce, ciphertext, last) {
        relayed.push(ciphertext);
        const reply = await sessions.execute(nonce, ciphertext, { last });
        relayed.push(reply);
        return reply;
      },
    };
    const now = Date.now();
    prepared = await prepareConfidentialSubmission({ summary: 'Public summary for legal review',
      narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' }, contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' }, identity: null,
      files: [{ name: 'PRIVATE-SENTINEL.txt', type: 'text/plain', bytes: LARGE_EVIDENCE },
        ...Array.from({ length: 3 }, (_, i) => ({ name: `PRIVATE-SENTINEL-${i}.txt`, type: 'text/plain', bytes: new Uint8Array([i]) }))] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });
  }, 600_000);

  test('cancelling a queued status batch prevents its challenge and encrypted request', async () => {
    const session = await firmSession();
    const sessions = channelSessionsFor(session, session.relay, session.releaseManifest);
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const started = new Promise<void>(resolve => { entered = resolve; });
    const blocker = sessions.run(async () => { entered(); await gate; });
    await started;
    log.length = 0;
    const controller = new AbortController();
    const result = checkReportAccessBatch(session, [{ caseId: prepared.caseId, requestId: null }], Date.now(), controller.signal)
      .then(() => null, error => error);
    await new Promise(resolve => setImmediate(resolve));
    controller.abort();
    release();
    await blocker;
    expect(await result).toMatchObject({ name: 'AbortError' });
    expect(log).toEqual([]);
  });

  test('89 status targets share one encrypted operation and reuse the channel on refresh', async () => {
    const session = await firmSession();
    const targets = [prepared.caseId, ...Array.from({ length: 88 }, (_, i) => hex(0xc000 + i))]
      .map(caseId => ({ caseId, requestId: null }));
    const before = opens;
    log.length = 0;
    const results = await checkReportAccessBatch(session, targets, Date.now());
    expect(results.size).toBe(89);
    expect(results.get(prepared.caseId)).toMatchObject({ access: 'none', request: 'unknown' });
    expect(results.get(targets[1].caseId)).toBeNull();
    expect(log).toEqual(['legal.challenge', 'legal.request-status-batch']);
    expect(opens - before).toBe(1);
    log.length = 0;
    await checkReportAccessBatch(session, targets, Date.now());
    expect(log).toEqual(['legal.request-status-batch']);
    expect(opens - before).toBe(1);
  }, 60_000);

  test('an enclave without the batched status read is answered with per-report reads', async () => {
    const session = await firmSession();
    const targets = [prepared.caseId, hex(0xc100), hex(0xc101)].map(caseId => ({ caseId, requestId: null }));
    refuseBatch = true;
    try {
      log.length = 0;
      const results = await checkReportAccessBatch(session, targets, Date.now());
      expect(results.get(prepared.caseId)).toMatchObject({ access: 'none', request: 'unknown' });
      expect(results.get(targets[1].caseId)).toBeNull();
      expect(results.get(targets[2].caseId)).toBeNull();
      expect(log.filter(operation => operation === 'legal.request-status-batch').length).toBeGreaterThanOrEqual(1);
      expect(log.filter(operation => operation === 'legal.request-status')).toHaveLength(3);
      // Per-report reads never unlock a case in the background.
      expect(log).not.toContain('legal.unlock-case');
      expect(log).not.toContain('legal.read-state-keys');
      // Each refusal is a relay 5xx; the session does not ask again.
      log.length = 0;
      await checkReportAccessBatch(session, targets, Date.now());
      expect(log).not.toContain('legal.request-status-batch');
      expect(log.filter(operation => operation === 'legal.request-status')).toHaveLength(3);
    } finally { refuseBatch = false; }
  }, 60_000);

  test('a refused batch whose per-report reads also fail keeps the batch failure and stops after three reads', async () => {
    const session = await firmSession();
    const targets = Array.from({ length: 6 }, (_, i) => ({ caseId: hex(0xc200 + i), requestId: null }));
    refuseBatch = true;
    try {
      log.length = 0;
      await expect(checkReportAccessBatch(session, targets, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      expect(log.filter(operation => operation === 'legal.request-status')).toHaveLength(3);
      // Nothing succeeded, so the session still tries the batch next time.
      log.length = 0;
      await expect(checkReportAccessBatch(session, targets, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      expect(log).toContain('legal.request-status-batch');
    } finally { refuseBatch = false; }
  }, 60_000);

  test('proactive owner sharing needs an approved verified firm, never fabricates a request, and survives enclave restart', async () => {
    const now = Date.now();
    const direct = await prepareConfidentialSubmission({ summary: 'Direct sharing example', narrative: { description: 'Private direct report' },
      contact: { contactValue: 'PRIVATE CONTACT' }, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: direct });
    const owner = await restoreOwnerSession({ code: direct.recoveryCode, relay, releaseManifest: MANIFEST, now });
    const unopened = await firmSession();
    await expect(readRequestStatus(unopened, direct.caseId, null, now))
      .resolves.toMatchObject({ access: 'none', request: 'unknown' });
    let inbox = await readOwnerInbox(owner, now);
    const profileDocument = await firmBindingDocument(firm, now, { practiceAreas: ['whistleblower'], jurisdiction: 'Example jurisdiction',
      website: `https://${firm.domain}/`, contacts: { email: `counsel@${firm.domain}`, signal: 'Synthetic firm contact' } });
    (backing.organizations[0] as LegalOrganization & { bindingDocument: string }).bindingDocument = profileDocument;
    await verifiedRoster(owner, now);
    const decision = { grantId: hex(0xd7), scopes: ['narrative', 'messages'] as ('narrative' | 'messages')[],
      objectRevisionLimit: inbox.current.revision, expiresAt: now + 86_400_000 };
    const beforeCheck = (await backing.store.getCase(direct.caseId))!.currentCheckpointDigest;
    const profile = await verifyOrganizationProfile(owner, firm.organizationId, now);
    expect(profile.organizationId).toBe(firm.organizationId);
    expect(profile.profile?.contacts).toEqual({ email: `counsel@${firm.domain}`, signal: 'Synthetic firm contact' });
    expect((await backing.store.getCase(direct.caseId))!.currentCheckpointDigest).toBe(beforeCheck);
    expect((await readOwnerInbox(owner, now)).current.grantDigests).toEqual([]);
    await updateSummary(owner, inbox, null, now);
    const hidden = await readOwnerInbox(owner, now);
    const hiddenCheckpoint = hidden.checkpointDigest;
    await expect(shareWithOrganization(owner, hidden, firm.organizationId, decision, now)).rejects.toThrow();
    expect((await backing.store.getCase(direct.caseId))!.currentCheckpointDigest).toBe(hiddenCheckpoint);
    await updateSummary(owner, hidden, 'Direct sharing example', now);
    inbox = await readOwnerInbox(owner, now);
    await expect(shareWithOrganization(owner, inbox, hex(0x99), decision, now)).rejects.toThrow();
    await expect(shareWithOrganization(owner, inbox, firm.organizationId, { ...decision, scopes: ['contact'] }, now)).rejects.toThrow();
    const row = backing.organizations.find(item => item.organizationId === firm.organizationId)!;
    row.approved = false;
    try { await expect(shareWithOrganization(owner, inbox, firm.organizationId, decision, now)).rejects.toThrow(); }
    finally { row.approved = true; }
    await shareWithOrganization(owner, inbox, firm.organizationId, decision, now);
    expect((await readOwnerInbox(owner, now)).deliveries).toEqual([]);
    // Access is visible before opening, without a saved request or pinned owner.
    log.length = 0;
    await expect(readRequestStatus(unopened, direct.caseId, null, now)).resolves.toEqual({
      access: 'granted', request: 'unknown', releaseApproved: true, expiresAt: decision.expiresAt, contactShared: false });
    expect(unopened.owners.size).toBe(0);
    expect(log).toEqual(['legal.challenge', 'legal.request-status']);
    await boot();
    try {
      const session = await firmSession();
      await expect(readRequestStatus(session, direct.caseId, null, now))
        .resolves.toMatchObject({ access: 'unknown', request: 'unknown' });
      const listing = (await readLegalDirectory(session, null, now)).listings.find(item => item.caseId === direct.caseId)!;
      const checkStart = log.length;
      await expect(checkReportAccess(session, direct.caseId, null, now, listing.owner)).resolves.toMatchObject({ access: 'granted' });
      // Checking access must never fetch the narrative, evidence, or messages.
      expect(log.slice(checkStart)).not.toEqual(expect.arrayContaining(['legal.open-case']));
      expect(log.slice(checkStart).some(operation => /evidence|messages/.test(operation))).toBe(false);
      expect(log.slice(-1)).toEqual(['legal.request-status']);
      session.owners.set(direct.caseId, listing.owner!);
      const opened = await openFirmCase(session, direct.caseId, now);
      expect(opened.narrative).toEqual({ description: 'Private direct report' });
      expect(opened.records).toEqual([]);
      expect(opened.scopes).not.toContain('contact');
      expect(log.slice(checkStart)).not.toContain('legal.acknowledge-report-open');
      await acknowledgeReportOpen(session, opened);
      const firstInbox = await readOwnerInbox(owner, Date.now());
      const roster = await verifiedRoster(owner, Date.now());
      const firstOpens = await readReportOpens(owner, firstInbox, roster, Date.now());
      expect(firstOpens).toHaveLength(1);
      expect(firstOpens[0].receipt.organizationId).toBe(firm.organizationId);
      await acknowledgeReportOpen(session, opened);
      const nextInbox = await readOwnerInbox(owner, Date.now());
      expect(await readReportOpens(owner, nextInbox, roster, Date.now())).toEqual(firstOpens);
      expect(await readOwnerReport(owner, nextInbox)).toMatchObject({
        narrative: { description: 'Private direct report' },
        records: [{ scope: 'contact', fields: { contactValue: 'PRIVATE CONTACT' } }],
      });
      await expect(readCaseStatus(session, direct.caseId, [], now))
        .resolves.toMatchObject({ access: { state: 'active' }, requests: [] });
    } finally {
      // Restart locks every case, including the independent fixture below.
      // Restore its original unlocked state so this test cannot turn its known
      // pre-grant status into the correct but unrelated locked/unknown result.
      const primary = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
      await readOwnerInbox(primary, Date.now());
    }
  });

  test('closing atomically hides the listing and revokes every firm; reopening never restores grants', async () => {
    const now = Date.now();
    const other = await generateFirmIdentity({ organizationId: hex(0xe2), domain: 'second.example' });
    const otherContext = { organizationId: other.organizationId, recipientKeyId: other.recipientKeyId, publicKey: other.privateKey.toPublic().armor() };
    identities.set('second-test-token', otherContext);
    backing.organizations.push({ ...otherContext, displayName: 'Second Example Counsel', domain: other.domain, approved: true } as LegalOrganization);
    try {
      const report = await prepareConfidentialSubmission({ summary: 'Synthetic closure example',
        narrative: { description: 'Private closure example' }, contact: null, identity: null, files: [] }, MANIFEST, now);
      await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: report });
      const owner = await restoreOwnerSession({ code: report.recoveryCode, relay, releaseManifest: MANIFEST, now });
      const firms = [await firmSession(), await createFirmSession({ relay, releaseManifest: MANIFEST, firm: other,
        accessToken: async () => 'second-test-token' })];
      for (const [i, participant] of firms.entries()) {
        const inbox = await readOwnerInbox(owner, now);
        await shareWithOrganization(owner, inbox, participant.firm.organizationId, { grantId: hex(0xe5 + i),
          scopes: ['narrative', 'messages'], objectRevisionLimit: null, expiresAt: null }, now);
        const listing = (await readLegalDirectory(participant, null, now)).listings.find(row => row.caseId === report.caseId)!;
        participant.owners.set(report.caseId, listing.owner!);
        expect((await openFirmCase(participant, report.caseId, now)).narrative).toEqual({ description: 'Private closure example' });
      }
      const before = await readOwnerInbox(owner, now);
      const epoch = (await backing.store.getCase(report.caseId))!.stateEpoch!;
      const failed = jest.spyOn(backing.store, 'commitTransition').mockResolvedValue(false);
      try { await expect(closeReport(owner, before, now)).rejects.toThrow(); }
      finally { failed.mockRestore(); }
      const unchanged = await readOwnerInbox(owner, now);
      expect(unchanged.checkpointDigest).toBe(before.checkpointDigest);
      expect(unchanged.current.grantDigests).toHaveLength(2);
      expect(unchanged.summary).toBe('Synthetic closure example');

      await closeReport(owner, unchanged, now);
      const closed = await readOwnerInbox(owner, now);
      expect(closed.current).toMatchObject({ revision: before.current.revision + 1, listingDigest: null, grantDigests: [] });
      const record = (await backing.store.getCase(report.caseId))!;
      expect(record.stateEpoch).toBe(epoch + 1);
      // Envelopes are padded to hide recipient count. Only the owner can open one.
      const state = await findCaseStateKey(record.stateEnvelopes!, report.caseId, owner.owner, owner.trust.ownerPublicKey);
      expect(state.stateEpoch).toBe(epoch + 1);
      state.key.fill(0);
      for (const participant of firms) {
        await expect(findCaseStateKey(record.stateEnvelopes!, report.caseId, participant.firm.privateKey, owner.trust.ownerPublicKey)).rejects.toThrow();
        expect((await readLegalDirectory(participant, null, now)).listings.some(row => row.caseId === report.caseId)).toBe(false);
        await expect(openFirmCase(participant, report.caseId, now)).rejects.toMatchObject({ code: 'not-granted' });
        await expect(sendFirmMessage(participant, report.caseId, 'must not send', now)).rejects.toThrow();
        await expect(readFirmMessages(participant, report.caseId, now)).rejects.toThrow();
      }
      // Closing is durable across owner recovery; saving the summary alone does not reshare.
      const returned = await restoreOwnerSession({ code: report.recoveryCode, relay, releaseManifest: MANIFEST, now });
      const returnedInbox = await readOwnerInbox(returned, now);
      expect(returnedInbox.current.grantDigests).toEqual([]);
      const summary = await previousSummary(returned, returnedInbox);
      expect(summary).toBe('Synthetic closure example');
      await updateSummary(returned, returnedInbox, summary, now);
      expect((await readOwnerInbox(returned, now)).current.grantDigests).toEqual([]);
      for (const participant of firms) await expect(openFirmCase(participant, report.caseId, now)).rejects.toMatchObject({ code: 'not-granted' });
      // A stale tab cannot close over a newer state.
      await expect(closeReport(owner, before, now)).rejects.toThrow();
    } finally {
      backing.organizations.splice(backing.organizations.findIndex(row => row.organizationId === other.organizationId), 1);
      identities.delete('second-test-token');
    }
  });

  test('directory -> request -> owner allows -> restart -> firm unlocks, opens, messages', async () => {
    const session = await firmSession();
    const { listings } = await readLegalDirectory(session, null, Date.now());
    const listing = listings.find(item => item.caseId === prepared.caseId)!;
    expect(listing.summary).toBe('Public summary for legal review');
    expect(listing.owner?.ownerFingerprint).toBe(prepared.owner.trust.ownerFingerprint);
    const requested = await requestCaseAccess(session, listing, { purpose: 'PRIVATE-SENTINEL-PURPOSE: conflict check first',
      scopes: ['narrative', 'evidence', 'messages'], details: DETAILS }, Date.now());
    await expect(readCaseStatus(session, prepared.caseId, [requested.requestId], Date.now())).resolves.toEqual({
      access: { state: 'none', expiresAt: null, scopes: [], contactShared: false, releaseApproved: true },
      requests: [{ requestId: requested.requestId, state: 'requested', expiresAt: expect.any(Number) }] });
    // A report cannot be opened before the owner decides; the firm is told why.
    await expect(openFirmCase(session, prepared.caseId, Date.now())).rejects.toMatchObject({ code: 'not-granted' });

    // Owner device: verify the firm against its own domain and allow.
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const requests = await verifiedRequests(owner, inbox, roster, Date.now());
    expect(requests.map(item => item.request.requestId)).toEqual([requested.requestId]);
    // Structured, firm-signed details reach the owner device intact.
    expect(requests[0].request.details).toEqual(DETAILS);
    await allowAccess(owner, inbox, roster, requests[0], { grantId: requested.requestId, scopes: ['narrative', 'evidence', 'messages'],
      objectRevisionLimit: null, expiresAt: null }, Date.now());
    const approved = await readCaseStatus(session, prepared.caseId, [requested.requestId], Date.now());
    expect(approved).toEqual({ access: { state: 'active', expiresAt: null, scopes: ['evidence', 'messages', 'narrative'],
      contactShared: false, releaseApproved: true }, requests: [{ requestId: requested.requestId, state: 'approved' }] });

    // Enclave restart: the case is locked until a participant unlocks it.
    await boot();
    log.length = 0;
    const opensBefore = opens;
    const stages: string[] = [];
    const opened = await openFirmCase(session, prepared.caseId, Date.now(), { onProgress: stage => stages.push(stage) });
    expect(stages).toEqual(['verifying', 'loading', 'unlocking', 'loading']); // Unlocking shown only when it happens.
    // Every range of every attachment reuses the firm's one verified session (the
    // session from the earlier not-granted check may still be open and reused).
    expect(opens - opensBefore).toBeLessThanOrEqual(1);
    expect(log).toEqual(expect.arrayContaining(['legal.open-case', 'legal.read-state-keys', 'legal.unlock-case']));
    expect(log.indexOf('legal.read-state-keys')).toBeGreaterThan(log.indexOf('legal.open-case'));
    expect(opened.narrative).toEqual({ description: 'PRIVATE-SENTINEL-NARRATIVE' });
    // Chunked evidence is never loaded whole: the list carries verified names and sizes.
    expect(opened.evidence).toHaveLength(0);
    expect(opened.deferredEvidence).toHaveLength(4);
    expect(opened.deferredEvidence[0]).toMatchObject({ name: 'PRIVATE-SENTINEL.txt', type: 'text/plain', size: LARGE_EVIDENCE.length, chunked: true });
    expect(opened.records).toEqual([]); // Contact was not granted.
    expect(opened.grantExpiresAt).toBeNull(); // Until revoked.
    expect(opened.scopes.sort()).toEqual(['evidence', 'messages', 'narrative']);
    expect(session.pins.get(prepared.caseId)?.digest).toBe(opened.checkpointDigest);

    log.length = 0;
    const deferred = await openFirmCase(session, prepared.caseId, Date.now(), { deferEvidence: true });
    expect(deferred.evidence).toHaveLength(0);
    expect(deferred.deferredEvidence.map(item => item.name)).toEqual(opened.deferredEvidence.map(item => item.name));
    expect(deferred.narrative).toEqual(opened.narrative);
    // Index, narrative range and one small index read per file; no chunk is fetched.
    expect(log.filter(operation => operation === 'legal.open-case')).toHaveLength(6);
    const objectId = deferred.deferredEvidence[0].objectId;
    // Streaming download: one authenticated chunk read per 512 KiB, decrypted into the sink.
    log.length = 0;
    const saved = testSink();
    const progress: number[] = [];
    await new EvidenceDownload(saved.sink, () => openFirmChunkedEvidence(session, prepared.caseId, objectId))
      .run({ onProgress: value => progress.push(value.bytesDone) });
    expect(saved.state).toEqual({ closed: true, aborted: false });
    expect(saved.digest()).toBe(digestOf(LARGE_EVIDENCE));
    expect(progress.at(-1)).toBe(LARGE_EVIDENCE.length);
    // Index + narrative + this file's index, then three chunks; no other file is touched.
    expect(log.filter(operation => operation === 'legal.open-case')).toHaveLength(6);
    // The whole-file reader refuses a chunked object; an unknown object is refused.
    await expect(openFirmEvidence(session, prepared.caseId, objectId)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    await expect(openFirmChunkedEvidence(session, prepared.caseId, hex(0xdead))).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    let tokenReads = 0;
    const expiring = { ...session, accessToken: async () => {
      if (++tokenReads > 1) throw new LegalSignInRequired();
      return TOKEN;
    } };
    await expect(openFirmChunkedEvidence(expiring, prepared.caseId, objectId)).rejects.toBeInstanceOf(LegalSignInRequired);
    // A descriptor already rendered is no authority after membership removal.
    // This test dispatcher uses a token map, not production roster storage.
    // Remove its actual identity authority; changing a directory-only fixture
    // cannot simulate membership revocation in this stand-in.
    const enrolled = identities.get(TOKEN)!;
    identities.delete(TOKEN);
    try { await expect(openFirmChunkedEvidence(session, prepared.caseId, objectId)).rejects.toBeInstanceOf(ConfidentialUnavailableError); }
    finally { identities.set(TOKEN, enrolled); }

    // Tampered storage: the chunk fails its signed digest; the partial file is discarded.
    const [, secondChunk] = JSON.parse((await backing.store.getObjects(prepared.caseId, [{ objectId,
      ciphertextDigest: (await openFirmChunkedEvidence(session, prepared.caseId, objectId)).reader.digest }]))[0].ciphertext).chunks;
    const original = backing.chunks.get(secondChunk)!;
    const tampered = new Uint8Array(original); tampered[10] ^= 1;
    backing.chunks.set(secondChunk, tampered);
    const broken = testSink();
    try {
      await expect(new EvidenceDownload(broken.sink, () => openFirmChunkedEvidence(session, prepared.caseId, objectId)).run())
        .rejects.toMatchObject({ reason: 'integrity' });
      expect(broken.state).toEqual({ closed: false, aborted: true });
    } finally { backing.chunks.set(secondChunk, original); }

    // The owner adds a file mid-download: the checkpoint changes, the read session
    // re-verifies once and the same signed object continues where it stopped.
    const midway = testSink();
    let written = 0;
    const download = new EvidenceDownload({ ...midway.sink, async write(bytes) {
      await midway.sink.write(bytes);
      if (++written === 1) {
        const inboxNow = await readOwnerInbox(owner, Date.now());
        await addEvidence(owner, inboxNow, roster, [{ name: 'later.txt', type: 'text/plain', bytes: new TextEncoder().encode('later') }], Date.now());
      }
    } }, () => openFirmChunkedEvidence(session, prepared.caseId, objectId));
    await download.run();
    expect(midway.digest()).toBe(digestOf(LARGE_EVIDENCE));
    const refreshed = await openFirmCase(session, prepared.caseId, Date.now(), { deferEvidence: true });
    expect(refreshed.deferredEvidence.map(item => item.name)).toContain('later.txt');

    // A second open uses the pin; an unchanged chain is accepted.
    await expect(openFirmCase(session, prepared.caseId, Date.now(), { deferEvidence: true })).resolves.toMatchObject({ checkpointDigest: refreshed.checkpointDigest });

    // Legacy ciphertext can still be read by the protocol helper. The mounted owner send route is retired.
    await sendFirmMessage(session, prepared.caseId, 'PRIVATE-SENTINEL-FIRM-MESSAGE', Date.now());
    const participants = { owner: prepared.owner.trust, organization: { organizationId: firm.organizationId, publicKey: firm.privateKey.toPublic() } };
    const ownerMessage = await sealCaseMessage({ sender: 'owner', sequence: 1, sentAt: Date.now(), body: 'PRIVATE-SENTINEL-OWNER-REPLY' },
      participants, prepared.owner.privateKey);
    await expect(ownerOperation({ relay, releaseManifest: MANIFEST, now: Date.now(), caseId: prepared.caseId, owner: prepared.owner.privateKey,
      operation: 'send-message', body: new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, organizationId: firm.organizationId,
        ciphertext: ownerMessage })) })).rejects.toThrow();
    const thread = await readFirmMessages(session, prepared.caseId, Date.now());
    expect(thread.rejected).toBe(0);
    expect(thread.messages.map(item => [item.sender, item.body])).toEqual([
      ['organization', 'PRIVATE-SENTINEL-FIRM-MESSAGE']]);
    await sendFirmMessage(session, prepared.caseId, 'Second firm message', Date.now());
    expect(session.sequences.get(prepared.caseId)).toEqual({ owner: 0, organization: 2 });

    // The host relay and store saw ciphertext only; the login token stayed inside the channel.
    for (const wire of [...relayed, backing.dump()]) {
      expect(wire).not.toContain('PRIVATE-SENTINEL');
      expect(wire).not.toContain(TOKEN);
    }
  }, 900_000);

  test('a fresh device with a stale or forked pin is refused', async () => {
    const session = await firmSession();
    session.owners.set(prepared.caseId, prepared.owner.trust);
    session.pins.set(prepared.caseId, { caseId: prepared.caseId, ownerFingerprint: prepared.owner.trust.ownerFingerprint,
      revision: 99, keyEpoch: 1, digest: hex(0xdead) });
    await expect(openFirmCase(session, prepared.caseId, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    // Without any owner-key pin the case cannot be opened at all.
    const unpinned = await firmSession();
    await expect(openFirmCase(unpinned, prepared.caseId, Date.now())).rejects.toBeInstanceOf(FirmCaseError);
  }, 300_000);

  test('an unapproved backend release never receives the state key', async () => {
    await boot(UPGRADE);
    try {
      const session = await firmSession(UPGRADE);
      session.owners.set(prepared.caseId, prepared.owner.trust);
      log.length = 0;
      await expect(openFirmCase(session, prepared.caseId, Date.now())).rejects.toMatchObject({ code: 'release-not-approved' });
      // The firm may read its reporter-signed envelope to learn it still holds
      // access, but the key itself is never handed to the unapproved release.
      expect(log).toContain('legal.open-case');
      expect(log).not.toContain('legal.unlock-case');
    } finally { await boot(); }
  }, 300_000);

  test('directory rows whose owner key does not match the signed listing are dropped', async () => {
    const session = await firmSession();
    tamper = true;
    try {
      const { listings } = await readLegalDirectory(session, null, Date.now());
      expect(listings.find(item => item.caseId === prepared.caseId)).toBeUndefined();
    } finally { tamper = false; }
    await expect(requestCaseAccess(session, { caseId: prepared.caseId, summary: 'x', owner: null },
      { purpose: 'p', scopes: ['narrative'], details: DETAILS }, Date.now())).rejects.toMatchObject({ code: 'owner-key-unavailable' });
  }, 300_000);

  test('directory refuses a category or region the host added to a signed listing', async () => {
    const session = await firmSession();
    tamper = 'metadata';
    try { expect((await readLegalDirectory(session, null, Date.now())).listings).toEqual([]); }
    finally { tamper = false; }
  }, 60_000);

  test.each(['fact-time', 'fact-attachments'] as const)('directory rejects unsigned changes to submission facts: %s', async mode => {
    const session = await firmSession();
    tamper = mode;
    try { expect((await readLegalDirectory(session, null, Date.now())).listings).toEqual([]); }
    finally { tamper = false; }
  }, 60_000);

  test('an existing owner pin cannot be replaced by a new directory identity or request', async () => {
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === prepared.caseId)!;
    const stranger = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Substituted owner' }], format: 'object' })).publicKey;
    const pin = { caseId: prepared.caseId, ownerFingerprint: stranger.getFingerprint(), ownerPublicKey: stranger };
    session.owners.set(prepared.caseId, pin);
    // The row stays visible without an owner key, so no request can be prepared from it.
    expect((await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === prepared.caseId))
      .toMatchObject({ owner: null, ownerKeyChanged: true, checkCode: null });
    log.length = 0;
    await expect(requestCaseAccess(session, listing, { purpose: 'Private request', scopes: ['narrative'] }, Date.now()))
      .rejects.toMatchObject({ code: 'owner-key-changed' });
    expect(log).toEqual([]);
    expect(session.owners.get(prepared.caseId)).toBe(pin);
  }, 60_000);

  test('a directory owner key that differs from the workspace pin pauses requests; the check code matches the owner', async () => {
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === prepared.caseId)!;
    expect(listing.ownerKeyChanged).toBe(false);
    expect(listing.checkCode).toBe(await reportCheckCode(prepared.caseId, prepared.owner.trust.ownerFingerprint));
    expect(listing.checkCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
    // This workspace saw another owner key for the report earlier (substitution).
    const other = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Substituted owner' }], format: 'object' });
    session.owners.set(prepared.caseId, { caseId: prepared.caseId, ownerFingerprint: other.publicKey.getFingerprint(), ownerPublicKey: other.publicKey });
    const changed = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === prepared.caseId)!;
    expect(changed).toMatchObject({ ownerKeyChanged: true, owner: null, checkCode: null });
    await expect(requestCaseAccess(session, changed, { purpose: 'p', scopes: ['narrative'] }, Date.now()))
      .rejects.toMatchObject({ code: 'owner-key-changed' });
    // Even a caller holding the served key cannot bypass the pin.
    await expect(requestCaseAccess(session, listing, { purpose: 'p', scopes: ['narrative'] }, Date.now()))
      .rejects.toMatchObject({ code: 'owner-key-changed' });
  }, 60_000);

  test('owner roster: a witnessed firm with a different key is not trusted; unwitnessed firms are labelled', async () => {
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const unrecorded = await verifiedRoster(owner, Date.now(), []);
    expect(unrecorded.map(item => item.witness)).toEqual(['unrecorded']);
    const entry = { domain: unrecorded[0].domain, organizationId: unrecorded[0].organizationId, recordedAt: '2026-09-01T00:00:00.000Z' };
    const recorded = await verifiedRoster(owner, Date.now(),
      [{ ...entry, recipientKeyId: firm.recipientKeyId }]);
    expect(recorded.map(item => item.witness)).toEqual(['recorded']);
    expect(await verifiedRoster(owner, Date.now(), [{ ...entry, recipientKeyId: hex(0xbad) }])).toEqual([]);
  }, 60_000);

  test('withdrawing a request, and a second case request flow', async () => {
    const now = Date.now();
    const other = await prepareConfidentialSubmission({ summary: 'Another summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: other });
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === other.caseId)!;
    const { requestId } = await requestCaseAccess(session, listing, { purpose: 'Review', scopes: ['narrative'], details: DETAILS }, Date.now());
    await expect(readCaseRequestStatus(session, other.caseId, requestId, Date.now())).resolves.toMatchObject({ state: 'pending' });
    await expect(readCaseRequestStatus(session, other.caseId, hex(0x9999), Date.now())).resolves.toEqual({ state: 'not-found', expiresAt: null });
    await expect(withdrawCaseRequest(session, other.caseId, requestId, Date.now())).resolves.toBeUndefined();
    await expect(readCaseRequestStatus(session, other.caseId, requestId, Date.now())).resolves.toMatchObject({ state: 'withdrawn' });
    await expect(withdrawCaseRequest(session, other.caseId, requestId, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    const withdrawn = await readCaseStatus(session, other.caseId, [requestId], Date.now());
    expect(withdrawn.requests).toEqual([{ requestId, state: 'withdrawn' }]);
    // The portal's status for this request (the same path /legal uses).
    const withdrawnStatus = caseStatus(await readRequestStatus(session, other.caseId, requestId, Date.now()), false);
    expect(statusBadge(withdrawnStatus, Date.now()).label).toBe('Withdrawn');
    expect(canRequestAgain(withdrawnStatus)).toBe(true);

    // A new request, declined by the reporter: the firm sees a generic "declined" and may ask again.
    const second = await requestCaseAccess(session, listing, { purpose: 'Second review', scopes: ['narrative'], details: DETAILS }, Date.now());
    const owner = await restoreOwnerSession({ code: other.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const [pending] = await verifiedRequests(owner, inbox, roster, Date.now());
    await declineAccess(owner, pending, Date.now());
    const declined = await readCaseStatus(session, other.caseId, [second.requestId, requestId], Date.now());
    expect(declined.requests).toEqual([{ requestId: second.requestId, state: 'declined' }, { requestId, state: 'withdrawn' }]);
    const declinedStatus = caseStatus(await readRequestStatus(session, other.caseId, second.requestId, Date.now()), false);
    expect(declinedStatus).toEqual({ kind: 'declined' });
    expect(statusBadge(declinedStatus, Date.now()).label).toBe('Declined');
    expect(canRequestAgain(declinedStatus)).toBe(true);
    expect(JSON.stringify(declined)).not.toMatch(/declinedAt|updatedAt|createdAt|reason/);
    await expect(requestCaseAccess(session, listing, { purpose: 'Third review', scopes: ['narrative'], details: DETAILS }, Date.now()))
      .resolves.toMatchObject({ requestId: expect.any(String) });
    // Unknown request IDs reveal nothing; malformed lists are refused locally.
    await expect(readCaseStatus(session, other.caseId, [hex(0xabc)], Date.now())).resolves.toMatchObject({
      requests: [{ requestId: hex(0xabc), state: 'unknown' }] });
    await expect(readCaseStatus(session, other.caseId, ['invalid'], Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
  }, 300_000);

  test('retains routing authority before sending and can withdraw after a committed request loses its reply', async () => {
    const now = Date.now();
    const other = await prepareConfidentialSubmission({ summary: 'Lost receipt fixture', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: other });
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === other.caseId)!;
    log.length = 0;
    await expect(requestCaseAccess(session, listing, { purpose: 'Review', scopes: ['narrative'], details: DETAILS }, Date.now(),
      async () => { throw new Error('device save failed'); })).rejects.toThrow('device save failed');
    expect(log).toEqual([]);
    const original = dispatch;
    let savedId = '';
    dispatch = async (body, context) => {
      const reply = await original(body, context);
      if (JSON.parse(new TextDecoder().decode(body)).operation === 'legal.request-access') throw new Error('lost reply after commit');
      return reply;
    };
    try {
      await expect(requestCaseAccess(session, listing, { purpose: 'Review', scopes: ['narrative'], details: DETAILS }, Date.now(),
        async ({ requestId }) => { savedId = requestId; expect(session.owners.get(other.caseId)).toEqual(listing.owner); }))
        .rejects.toThrow();
    } finally { dispatch = original; }
    expect(savedId).toMatch(/^[a-f0-9]{64}$/);
    await expect(readCaseRequestStatus(session, other.caseId, savedId, Date.now())).resolves.toMatchObject({ state: 'pending' });
    await expect(withdrawCaseRequest(session, other.caseId, savedId, Date.now())).resolves.toBeUndefined();
  }, 60_000);

  test('summary-only listing, request status badges and the case view data', async () => {
    const TERM = 20 * 86_400_000;
    const described = await prepareConfidentialSubmission({ summary: 'Described summary',
      narrative: { description: 'PRIVATE-SENTINEL-ACCOUNT', dateOfIncident: '2026-03-04', location: 'PRIVATE-SENTINEL-PLACE' },
      contact: null, identity: null, files: [{ name: 'PRIVATE-SENTINEL-FILE.pdf', type: 'application/pdf', bytes: new Uint8Array(2048) }] },
      MANIFEST, Date.now());
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: Date.now(), prepared: described });
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === described.caseId)!;
    expect(listing).toMatchObject({ summary: 'Described summary', publishedAt: expect.any(Number), hasAttachments: true });
    expect(Object.keys(listing).sort()).toEqual(['caseId', 'checkCode', 'hasAttachments', 'owner', 'ownerKeyChanged', 'publishedAt', 'summary']);
    // Listings published without details carry none.
    const plain = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === prepared.caseId)!;
    expect(Object.keys(plain).sort()).toEqual(['caseId', 'checkCode', 'hasAttachments', 'owner', 'ownerKeyChanged', 'publishedAt', 'summary']);

    const { requestId } = await requestCaseAccess(session, listing, { purpose: 'Status check', scopes: ['narrative', 'evidence', 'messages'], details: DETAILS }, Date.now());
    await expect(readRequestStatus(session, described.caseId, requestId, Date.now()))
      .resolves.toMatchObject({ access: 'none', request: 'pending', requestExpiresAt: expect.any(Number) });
    // Another request ID of this firm is not a record the firm can see.
    await expect(readRequestStatus(session, described.caseId, hex(0x777), Date.now()))
      .resolves.toMatchObject({ access: 'none', request: 'unknown' });
    await expect(openFirmCase(session, described.caseId, Date.now(), { deferEvidence: true })).rejects.toMatchObject({ code: 'not-granted' });
    // A pending request is not access: the state-key envelopes (whose count follows access) stay hidden.
    await expect(unlockFirmCase(session, described.caseId, Date.now())).rejects.toMatchObject({ code: 'not-granted' });

    const owner = await restoreOwnerSession({ code: described.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    let inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const [pending] = await verifiedRequests(owner, inbox, roster, Date.now());
    const grantedAt = Date.now();
    await allowAccess(owner, inbox, roster, pending, { grantId: requestId, scopes: ['narrative', 'evidence', 'messages'],
      objectRevisionLimit: null, expiresAt: grantedAt + TERM }, grantedAt);
    const granted = await readRequestStatus(session, described.caseId, requestId, Date.now());
    // The owner's grant answers the request.
    expect(granted).toEqual({ access: 'granted', request: 'approved', releaseApproved: true, expiresAt: grantedAt + TERM,
      contactShared: false });

    // After a restart the sealed grant cannot prove current access. Merely holding
    // an envelope must not be represented as an unexpired grant.
    await boot();
    log.length = 0;
    await expect(readRequestStatus(session, described.caseId, requestId, Date.now()))
      .resolves.toMatchObject({ access: 'unknown', request: 'approved' });
    expect(log).not.toContain('legal.read-state-keys');
    expect(log).not.toContain('legal.unlock-case');

    const opened = await openFirmCase(session, described.caseId, Date.now(), { deferEvidence: true });
    expect(opened.narrative).toMatchObject({ description: 'PRIVATE-SENTINEL-ACCOUNT', dateOfIncident: '2026-03-04' });
    expect(opened.grants).toEqual([{ issuedAt: expect.any(Number), expiresAt: grantedAt + TERM, scopes: ['narrative', 'evidence', 'messages'] }]);
    expect(opened.grants[0].issuedAt).toBeLessThanOrEqual(Date.now());
    expect(opened.releaseApprovedAt).toBeLessThanOrEqual(opened.grants[0].issuedAt);
    // A chunked file: name, type and exact size come from the reporter-signed index.
    expect(opened.deferredEvidence).toEqual([{ objectId: expect.stringMatching(/^[a-f0-9]{64}$/), encryptedBytes: expect.any(Number),
      name: 'PRIVATE-SENTINEL-FILE.pdf', type: 'application/pdf', size: 2048, chunked: true }]);

    // A new backend release: access is unchanged but waits for the reporter.
    await boot(UPGRADE);
    try {
      const upgraded = await firmSession(UPGRADE);
      upgraded.owners.set(described.caseId, described.owner.trust);
      log.length = 0;
      await expect(readRequestStatus(upgraded, described.caseId, requestId, Date.now()))
        .resolves.toMatchObject({ access: 'unknown' });
      const pending = await checkReportAccess(upgraded, described.caseId, requestId, Date.now());
      expect(pending).toMatchObject({ access: 'unknown', releaseApproved: false });
      expect(caseStatus(pending, false)).toEqual({ kind: 'update-pending' });
      expect(log).not.toContain('legal.unlock-case');
      expect(log).not.toContain('legal.open-case');
      await expect(openFirmCase(upgraded, described.caseId, Date.now())).rejects.toMatchObject({ code: 'release-not-approved' });
      expect(log).not.toContain('legal.unlock-case');
    } finally { await boot(); }

    const current = await restoreOwnerSession({ code: described.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    inbox = await readOwnerInbox(current, Date.now());
    await updateSummary(current, inbox, 'Updated summary', Date.now());
    const row = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === described.caseId)!;
    expect(row.summary).toBe('Updated summary');
    expect(row.publishedAt).toBe(listing.publishedAt);
    expect(row.hasAttachments).toBe(listing.hasAttachments);
    expect(Object.keys(row).sort()).toEqual(['caseId', 'checkCode', 'hasAttachments', 'owner', 'ownerKeyChanged', 'publishedAt', 'summary']);
    await updateSummary(current, await readOwnerInbox(current, Date.now()), null, Date.now());
    expect((await readLegalDirectory(session, null, Date.now())).listings.some(item => item.caseId === described.caseId)).toBe(false);
    await updateSummary(current, await readOwnerInbox(current, Date.now()), 'Relisted summary', Date.now());
    const relisted = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === described.caseId)!;
    expect(relisted).toMatchObject({ summary: 'Relisted summary', publishedAt: listing.publishedAt, hasAttachments: listing.hasAttachments });
  }, 300_000);

  test('a declined request is reported as declined and can be asked again', async () => {
    const other = await prepareConfidentialSubmission({ summary: 'Decline me', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, Date.now());
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: Date.now(), prepared: other });
    const session = await firmSession();
    const listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === other.caseId)!;
    const { requestId } = await requestCaseAccess(session, listing, { purpose: 'Please', scopes: ['narrative'], details: DETAILS }, Date.now());
    const owner = await restoreOwnerSession({ code: other.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const [pending] = await verifiedRequests(owner, inbox, roster, Date.now());
    await declineAccess(owner, pending, Date.now());
    await expect(readRequestStatus(session, other.caseId, requestId, Date.now())).resolves.toMatchObject({ access: 'none', request: 'declined' });
    const again = await requestCaseAccess(session, listing, { purpose: 'Second try', scopes: ['narrative'], details: DETAILS }, Date.now());
    await expect(readRequestStatus(session, other.caseId, again.requestId, Date.now())).resolves.toMatchObject({ request: 'pending' });
  }, 120_000);

  test('failed owner recovery clears the session opened for its recovery lookup', async () => {
    const clear = jest.spyOn(ChannelSessions.prototype, 'clear');
    try {
      await expect(restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now(),
        rememberedPin: { caseId: prepared.caseId, revision: 1, keyEpoch: 1, digest: '00'.repeat(32), ownerFingerprint: 'ff'.repeat(20) } } as never)).rejects.toThrow();
      expect(clear).toHaveBeenCalled();
    } finally { clear.mockRestore(); }
  }, 60_000);

  // One sharing journey in ordered steps (shared state), so a slow machine
  // reports the step that stalled instead of one opaque timeout.
  describe('sharing: chosen files only, no future files, contact share and stop, renew, renewal request, revoke', () => {
    let shared: Awaited<ReturnType<typeof prepareConfidentialSubmission>>;
    let session: Awaited<ReturnType<typeof firmSession>>;
    let listing: Awaited<ReturnType<typeof readLegalDirectory>>['listings'][number];
    let first: { requestId: string };
    let renewal: { requestId: string };
    let owner: OwnerSession;
    const STEP = 300_000;
    const view = async () => {
      const inbox = await readOwnerInbox(owner, Date.now());
      const roster = await verifiedRoster(owner, Date.now());
      const requests = await verifiedRequests(owner, inbox, roster, Date.now());
      const evidence = evidenceEntries(await currentManifest(owner, inbox));
      return { inbox, roster, requests, evidence, grantees: await currentGrantees(owner, inbox, roster) };
    };
    // Chunked files are listed (name from the signed index) and downloaded one at a time.
    const names = async () => {
      const opened = await openFirmCase(session, shared.caseId, Date.now());
      return [...opened.evidence.map(item => item.name), ...opened.deferredEvidence.map(item => item.name)].sort();
    };

    test('the firm sends a structured request', async () => {
      const now = Date.now();
      shared = await prepareConfidentialSubmission({ summary: 'Sharing summary', narrative: { description: 'PRIVATE-SENTINEL-SHARED' },
        contact: { contactMethod: 'email', contactValue: 'PRIVATE-SENTINEL-EMAIL' }, identity: null,
        files: ['one', 'two', 'three'].map(name => ({ name: `${name}.txt`, type: 'text/plain', bytes: new TextEncoder().encode(name) })) },
      MANIFEST, now);
      await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: shared });
      session = await firmSession();
      listing = (await readLegalDirectory(session, null, Date.now())).listings.find(item => item.caseId === shared.caseId)!;
      first = await requestCaseAccess(session, listing, { purpose: 'Employment counsel', scopes: ['narrative', 'evidence', 'messages'],
        details: DETAILS }, Date.now());
      owner = await restoreOwnerSession({ code: shared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    }, STEP);

    test('chooser: report + files one and three, not future files, for 30 days', async () => {
      const state = await view();
      expect(state.evidence).toHaveLength(3);
      const choice = { ...defaultChoice(state.requests[0].request, state.evidence), evidence: 'some' as const,
        selected: [state.evidence[0].objectId, state.evidence[2].objectId], future: false, duration: '30-days' as const };
      const decision = decisionFromChoice(choice, state.requests[0].request, state.evidence, state.inbox.current.revision, Date.now());
      expect(decision.excludedObjectIds).toEqual([state.evidence[1].objectId]);
      await allowAccess(owner, state.inbox, state.roster, state.requests[0], decision, Date.now());
      const status = await readCaseStatus(session, shared.caseId, [first.requestId], Date.now());
      expect(status.access).toMatchObject({ state: 'active', contactShared: false });
      expect(status.access.expiresAt! - Date.now()).toBeGreaterThan(29 * 86_400_000);
      expect(await names()).toEqual(['one.txt', 'three.txt']);
    }, STEP);

    test('a file added later stays private: this access excludes future files', async () => {
      const state = await view();
      const added = await addEvidence(owner, state.inbox, state.roster, [{ name: 'four.txt', type: 'text/plain',
        bytes: new TextEncoder().encode('four') }], Date.now());
      expect(added.sharedWith).toEqual([]);
      expect(added.added.map(item => item.name)).toEqual(['four.txt']);
      expect(await names()).toEqual(['one.txt', 'three.txt']);
    }, STEP);

    test('contact details: a separate, explicit grant that can be stopped', async () => {
      let state = await view();
      await shareContactDetails(owner, state.inbox, state.roster, state.grantees[0], Date.now());
      const withContact = await openFirmCase(session, shared.caseId, Date.now(), { deferEvidence: true });
      expect(withContact.records).toEqual([{ scope: 'contact', fields: { contactMethod: 'email', contactValue: 'PRIVATE-SENTINEL-EMAIL' } }]);
      expect((await readCaseStatus(session, shared.caseId, [first.requestId], Date.now())).access.contactShared).toBe(true);
      state = await view();
      await stopSharingContactDetails(owner, state.inbox, state.grantees[0], Date.now());
      expect((await openFirmCase(session, shared.caseId, Date.now(), { deferEvidence: true })).records).toEqual([]);
    }, STEP);

    test('renew: same choices, now until revoked; no key material moves', async () => {
      const state = await view();
      await renewAccess(owner, state.inbox, state.roster, state.grantees[0], null, Date.now());
      const status = await readCaseStatus(session, shared.caseId, [first.requestId], Date.now());
      expect(status.access).toMatchObject({ state: 'active', expiresAt: null });
      expect(await names()).toEqual(['one.txt', 'three.txt']);
    }, STEP);

    test('the answered request is closed, so the firm may ask again (renewal) while access continues', async () => {
      renewal = await requestCaseAccess(session, listing, { purpose: 'Please add the other files', scopes: ['narrative', 'evidence', 'messages'],
        details: { ...DETAILS, kind: 'renewal' } }, Date.now());
      const status = await readCaseStatus(session, shared.caseId, [renewal.requestId, first.requestId], Date.now());
      expect(status.requests).toEqual([{ requestId: renewal.requestId, state: 'requested', expiresAt: expect.any(Number) },
        { requestId: first.requestId, state: 'approved' }]);
      // Access continues while the renewal waits: the portal can withdraw it and does not offer to ask again.
      const renewalStatus = caseStatus(await readRequestStatus(session, shared.caseId, renewal.requestId, Date.now()), true);
      expect(renewalStatus).toMatchObject({ kind: 'granted', renewalPending: true });
      expect(statusBadge(renewalStatus, Date.now()).label).toBe('Access allowed');
      expect(canWithdraw(renewalStatus)).toBe(true);
      expect(canAskToRenew(renewalStatus, Date.now())).toBe(false);
      let state = await view();
      const renewalCard = state.requests[0];
      expect(renewalCard.request.details?.kind).toBe('renewal');
      // The chooser starts from the current access; the reporter widens it to every file.
      const start = defaultChoice(renewalCard.request, state.evidence, state.grantees[0].grants);
      expect(start).toMatchObject({ report: true, evidence: 'some', future: false });
      await allowAccess(owner, state.inbox, state.roster, renewalCard, decisionFromChoice({ ...start, evidence: 'all', future: true },
        renewalCard.request, state.evidence, state.inbox.current.revision, Date.now()), Date.now());
      state = await view();
      expect(state.grantees[0].grants).toHaveLength(1); // Replaced, not stacked.
      expect(await names()).toEqual(['four.txt', 'one.txt', 'three.txt', 'two.txt']);
    }, STEP);

    test('later files use the approved roster without contacting the organization website', async () => {
      const state = await view();
      const organization = state.grantees[0].organization!;
      const file = () => [{ name: 'five.txt', type: 'text/plain', bytes: new TextEncoder().encode('five') }];
      // Once the key is confirmed, the file is added and the organization receives it.
      const added = await addEvidence(owner, (await view()).inbox, state.roster, file(), Date.now());
      expect(added.sharedWith.map(item => item.organizationId)).toEqual([organization.organizationId]);
      expect(await names()).toEqual(['five.txt', 'four.txt', 'one.txt', 'three.txt', 'two.txt']);
    }, STEP);

    test('revoke: the firm sees "revoked" and cannot open; contact details never crossed the host', async () => {
      const state = await view();
      await revokeAccess(owner, state.inbox, state.roster, state.grantees[0].grantDigests[0], Date.now());
      const status = await readCaseStatus(session, shared.caseId, [renewal.requestId], Date.now());
      expect(status.access.state).toBe('revoked');
      const revokedStatus = caseStatus(await readRequestStatus(session, shared.caseId, renewal.requestId, Date.now()), true);
      expect(revokedStatus).toEqual({ kind: 'ended' });
      expect(statusBadge(revokedStatus, Date.now()).label).toBe('Access ended');
      expect(canRequestAgain(revokedStatus)).toBe(true);
      await expect(openFirmCase(session, shared.caseId, Date.now())).rejects.toMatchObject({ code: 'not-granted' });
      for (const wire of [...relayed, backing.dump()]) expect(wire).not.toContain('PRIVATE-SENTINEL-EMAIL');
    }, STEP);
  });
  test('invitation redemption signs the enclave challenge with the registered firm key only', async () => {
    const token = 'A'.repeat(43);
    await expect(redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation: token, accessToken: TOKEN, firm }))
      .resolves.toEqual({ organizationId: firm.organizationId });
    const stranger = await generateFirmIdentity({ organizationId: hex(0xf1), domain: 'counsel.example' });
    const clear = jest.spyOn(ChannelSessions.prototype, 'clear');
    try {
      await expect(redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation: token, accessToken: TOKEN, firm: stranger }))
        .rejects.toMatchObject({ code: 'wrong-firm-key' });
      expect(clear).toHaveBeenCalled();
    } finally { clear.mockRestore(); }
    await expect(redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation: 'short', accessToken: TOKEN, firm }))
      .rejects.toThrow('not valid');
    for (const wire of relayed) expect(wire).not.toContain(token);
  }, 60_000);

  test('evidence added after a slow upload signs its commit at the current time', async () => {
    const started = Date.now();
    let elapsed = 0;
    await boot(MANIFEST, () => started + elapsed);
    const fresh = await prepareConfidentialSubmission({ summary: 'Slow added evidence',
      narrative: { description: 'Synthetic report' }, contact: null, identity: null, files: [] }, MANIFEST, started);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: started, prepared: fresh });
    const owner = await restoreOwnerSession({ code: fresh.recoveryCode, relay, releaseManifest: MANIFEST, now: started });
    const inbox = await readOwnerInbox(owner, started);
    const clock = jest.spyOn(globalThis.performance, 'now').mockImplementation(() => elapsed);
    owner.relay = { ...relay, async stageChunk(chunk) {
      elapsed = 20 * 60_000; // Exceeds the participant proof age + skew window.
      return relay.stageChunk(chunk);
    } };
    try {
      await expect(addEvidence(owner, inbox, [], [{ name: 'late.txt', type: 'text/plain',
        bytes: new TextEncoder().encode('Synthetic slow upload') }], started)).resolves.toEqual({ sharedWith: [],
        added: [{ objectId: expect.stringMatching(/^[a-f0-9]{64}$/), name: 'late.txt' }] });
      expect((await readOwnerInbox(owner, started + elapsed)).current.revision).toBe(inbox.current.revision + 1);
    } finally { clock.mockRestore(); await boot(); }
  });



  // Rotates the case through many backend releases and
  // re-approves MANIFEST at the end.
  test('forty sequential release approvals keep working; approvals ignore host statement order', async () => {
    const releases = Array.from({ length: 40 }, (_, i) => release('a', (0x60 + i).toString(16)));
    // One owner device follows the backend through every upgrade (its pin advances).
    let owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const approve = async (manifest: string, check = true) => {
      await boot(manifest);
      owner = { ...owner, releaseManifest: manifest, releaseDigest: (await readReleaseManifest(manifest)).digest };
      if (check) expect(await releaseApprovalStatus(owner, Date.now())).toBe('needs-approval');
      await approveCurrentRelease(owner, Date.now());
      if (check) expect(await releaseApprovalStatus(owner, Date.now())).toBe('approved');
    };
    // Status round trips are checked around the old 32-digest cliff to keep this affordable.
    for (const [index, manifest] of releases.entries()) await approve(manifest, index === 0 || index >= 31);
    await expect(readOwnerInbox(owner, Date.now())).resolves.toMatchObject({ summary: 'Public summary for legal review' });
    // A fresh device restoring from the recovery code sees the same newest state.
    const restored = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: releases[39], now: Date.now() });
    expect(restored.pin).toEqual(owner.pin);
    // The checkpoint keeps a bounded recent set, far below the 32-digest cap.
    const record = (await createSealedCaseStore(backing.store, keyring).getCase(prepared.caseId))!;
    const tip = (await verifyOwnerStatement(record.checkpoints[record.checkpoints.length - 1], prepared.owner.trust)).statement as CaseCheckpoint;
    expect(tip.releaseDigests).toHaveLength(RETAINED_RELEASE_APPROVALS);
    const approved = await Promise.all(tip.releaseDigests.map(async digest =>
      ((await verifyOwnerStatement(record.statements[digest], prepared.owner.trust)).statement as { releaseDigest: string }).releaseDigest));
    const expected = await Promise.all(releases.slice(-RETAINED_RELEASE_APPROVALS).map(async item => (await readReleaseManifest(item)).digest));
    expect(approved).toEqual(expected);

    // The host reordering stored statements never changes which approvals are served.
    const approvals = async (unlocked: boolean) => {
      const ring = unlocked ? keyring : createCaseKeyring({ clock: Date.now });
      return createCaseService({ store: createSealedCaseStore(backing.store, ring), keyring: ring, clock: Date.now, audience: AUDIENCE,
        releaseDigest: expected[expected.length - 1], channel: { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() } }).releaseApprovals(prepared.caseId);
    };
    const digests = async (wires: string[]) => Promise.all(wires.map(async wire => (await verifyOwnerStatement(wire, prepared.owner.trust)).digest));
    try {
      for (const unlocked of [true, false]) {
        backing.host.reverseStatements = false;
        const inOrder = await approvals(unlocked);
        backing.host.reverseStatements = true;
        expect(await approvals(unlocked)).toEqual(inOrder);
        if (unlocked) expect(await digests(inOrder.releases)).toEqual(tip.releaseDigests);
        else {
          expect(inOrder.releases.length).toBeLessThanOrEqual(32);
          expect(await digests(inOrder.releases)).toEqual(expect.arrayContaining(tip.releaseDigests));
        }
      }
    } finally { backing.host.reverseStatements = false; }

    // Restore the original backend for anything that runs after this block.
    await approve(MANIFEST);
  }, 600_000);

  test('the reporter lists and streams their own files, and adds files with a resumable upload', async () => {
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    let inbox = await readOwnerInbox(owner, Date.now());
    // The verified roster, as the report page passes it: the granted firm receives keys for new files.
    const roster = await verifiedRoster(owner, Date.now());
    const files = await listOwnerEvidence(owner, inbox, Date.now());
    const large = files.find(item => item.name === 'PRIVATE-SENTINEL.txt')!;
    expect(large).toMatchObject({ chunked: true, size: LARGE_EVIDENCE.length, type: 'text/plain', original: true });
    expect(files.filter(item => item.original)).toHaveLength(4);

    // Owner download: every chunk is an owner-authenticated read at the checkpoint.
    const saved = testSink();
    await new EvidenceDownload(saved.sink, () => openOwnerChunkedEvidence(owner, large.objectId, Date.now())).run();
    expect(saved.digest()).toBe(digestOf(LARGE_EVIDENCE));
    await expect(openOwnerWholeEvidence(owner, large.objectId, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);

    // Reordered storage: chunk 0 served where chunk 1 belongs fails integrity and nothing is kept.
    const opened = await openOwnerChunkedEvidence(owner, large.objectId, Date.now());
    const [first, second] = opened.reader.index.chunks;
    opened.reader.dispose();
    const original = backing.chunks.get(second)!;
    backing.chunks.set(second, backing.chunks.get(first)!);
    const reordered = testSink();
    try {
      await expect(new EvidenceDownload(reordered.sink, () => openOwnerChunkedEvidence(owner, large.objectId, Date.now())).run())
        .rejects.toMatchObject({ reason: 'integrity' });
      expect(reordered.state).toEqual({ closed: false, aborted: true });
    } finally { backing.chunks.set(second, original); }

    // Pausing a download keeps its place; resuming continues without re-reading earlier chunks.
    const paused = testSink();
    const pause = new AbortController();
    let pieces = 0;
    const resumable = new EvidenceDownload({ ...paused.sink, async write(bytes) {
      await paused.sink.write(bytes);
      if (++pieces === 1) pause.abort();
    } }, () => openOwnerChunkedEvidence(owner, large.objectId, Date.now()));
    await expect(resumable.run({ signal: pause.signal })).rejects.toMatchObject({ reason: 'interrupted' });
    expect(resumable.progress.bytesDone).toBe(512 * 1024);
    await resumable.run();
    expect(paused.digest()).toBe(digestOf(LARGE_EVIDENCE));

    // Adding files: encrypt, upload with an interruption, resume, then commit.
    inbox = await readOwnerInbox(owner, Date.now());
    const addition = new Uint8Array(randomBytes(512 * 1024 + 900));
    const pending = await prepareEvidence(owner, inbox, [{ name: 'PRIVATE-SENTINEL-added.bin', type: 'application/octet-stream', bytes: addition }]);
    let failing = true, calls = 0;
    const flaky: ChannelRelay = { ...relay, async stageChunk(chunk) {
      if (failing && ++calls > 1) throw new TypeError('Failed to fetch');
      return relay.stageChunk(chunk);
    } };
    const flakyOwner = { ...owner, relay: flaky };
    await expect(uploadEvidence(flakyOwner, pending, { wait: async () => undefined })).rejects.toBeInstanceOf(ConfidentialUploadInterruptedError);
    expect(pending.uploadState.staged.size).toBe(1);
    // Nothing is committed while chunks are missing.
    await expect(commitEvidence(owner, inbox, roster, pending, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    failing = false;
    await uploadEvidence(flakyOwner, pending, { wait: async () => undefined });
    await commitEvidence(owner, inbox, roster, pending, Date.now());
    inbox = await readOwnerInbox(owner, Date.now());
    const added = (await listOwnerEvidence(owner, inbox, Date.now())).find(item => item.name === 'PRIVATE-SENTINEL-added.bin')!;
    expect(added).toMatchObject({ chunked: true, original: false, size: addition.length });
    const addedSink = testSink();
    await new EvidenceDownload(addedSink.sink, () => openOwnerChunkedEvidence(owner, added.objectId, Date.now())).run();
    expect(addedSink.digest()).toBe(digestOf(addition));

    // Prepared against an older state: refused as stale, never committed.
    const stale = await prepareEvidence(owner, inbox, [{ name: 'late.txt', type: 'text/plain', bytes: new Uint8Array([1]) }]);
    await uploadEvidence(owner, stale);
    await addEvidence(owner, inbox, roster, [{ name: 'other.txt', type: 'text/plain', bytes: new Uint8Array([2]) }], Date.now());
    // The upload callback can still hold the inbox from before that change.
    await expect(commitEvidence(owner, inbox, roster, stale, Date.now())).rejects.toBeInstanceOf(EvidenceStaleError);
    const newer = await readOwnerInbox(owner, Date.now());
    await expect(commitEvidence(owner, newer, roster, stale, Date.now())).rejects.toBeInstanceOf(EvidenceStaleError);
    for (const wire of relayed) expect(wire).not.toContain('PRIVATE-SENTINEL-added');
  }, 900_000);


  // Last in this suite: it revokes the firm's access to the shared case.
  test('revoking access during a download stops it and discards the partial file', async () => {
    const session = await firmSession();
    session.owners.set(prepared.caseId, prepared.owner.trust);
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const roster = await verifiedRoster(owner, Date.now());
    const { deferredEvidence } = await openFirmCase(session, prepared.caseId, Date.now(), { deferEvidence: true });
    const objectId = deferredEvidence.find(item => item.name === 'PRIVATE-SENTINEL.txt')!.objectId;
    // The next re-verification finds no current grant.
    const revoked = testSink();
    let chunksWritten = 0;
    const stopped = new EvidenceDownload({ ...revoked.sink, async write(bytes) {
      await revoked.sink.write(bytes);
      if (++chunksWritten === 1) {
        const inboxNow = await readOwnerInbox(owner, Date.now());
        const grantees = await currentGrantees(owner, inboxNow, roster);
        await revokeAccess(owner, inboxNow, roster, grantees[0].grantDigests[0], Date.now());
      }
    } }, () => openFirmChunkedEvidence(session, prepared.caseId, objectId));
    await expect(stopped.run()).rejects.toMatchObject({ code: 'not-granted' });
    expect(revoked.state.closed).toBe(false);
    await stopped.cancel();
    expect(revoked.state.aborted).toBe(true);
    await expect(stopped.run()).rejects.toBeInstanceOf(EvidenceDownloadError);

  }, 600_000);
});

describe('firm key setup, binding and encrypted export', () => {
  beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

  test('binding document verifies for the firm domain and organization', async () => {
    const firm = await generateFirmIdentity({ organizationId: hex(0xf2), domain: 'Counsel.Example ' });
    expect(firm.domain).toBe('counsel.example');
    const verified = await verifyFirmKeyBinding(await firmBindingDocument(firm, Date.now()), { domain: 'counsel.example', organizationId: hex(0xf2) });
    expect(verified.binding.recipientKeyId).toBe(firm.recipientKeyId);
    await expect(generateFirmIdentity({ organizationId: 'nope', domain: 'counsel.example' })).rejects.toThrow('organization ID');
  });

  test('export/import round trip with a recovery code; wrong secret or edited metadata fails', async () => {
    const firm = await generateFirmIdentity({ organizationId: hex(0xf3), domain: 'counsel.example' });
    const code = generateFirmRecoveryCode();
    expect(code).toMatch(/^VERA-FIRM-1\.[A-Za-z0-9_-]{43}$/);
    const file = await exportFirmIdentity(firm, code);
    expect(file).toContain('PRIVATE');
    expect(file).not.toContain('PRIVATE KEY BLOCK');
    const restored = await importFirmIdentity(file, `  ${code}\n`);
    expect(restored.recipientKeyId).toBe(firm.recipientKeyId);
    expect(restored.privateKey.getFingerprint()).toBe(firm.privateKey.getFingerprint());
    expect([restored.organizationId, restored.domain]).toEqual([hex(0xf3), 'counsel.example']);
    await expect(importFirmIdentity(file, generateFirmRecoveryCode())).rejects.toThrow();
    await expect(importFirmIdentity(file.replace('"domain":"counsel.example"', '"domain":"attacker.example"'), code)).rejects.toThrow();
    await expect(importFirmIdentity(file.replace('"iterations":600000', '"iterations":1000'), code)).rejects.toThrow();
  });

  test('passphrase export requires a long passphrase', async () => {
    const firm = await generateFirmIdentity({ organizationId: hex(0xf4), domain: 'counsel.example' });
    await expect(exportFirmIdentity(firm, 'short')).rejects.toThrow('at least 16');
    const file = await exportFirmIdentity(firm, 'correct horse battery staple');
    await expect(importFirmIdentity(file, 'correct horse battery staple')).resolves.toMatchObject({ recipientKeyId: firm.recipientKeyId });
  });
});

describe('legal Auth0 PKCE helpers', () => {
  test('S256 challenge matches RFC 7636 appendix B', async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    await expect(pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).resolves.toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
  test('portal is unconfigured without the separate legal application env', () => {
    expect(legalAuthConfig()).toBeNull();
  });
  test('authorize URL targets the legal application with PKCE and the legal scopes', () => {
    const url = new URL(authorizeUrl({ domain: 'legal.example.auth0.com', clientId: 'legalClient123', audience: 'https://legal.vera',
      organization: null }, { challenge: 'c', state: 's', redirectUri: 'https://vera.report/legal' }));
    expect(url.origin).toBe('https://legal.example.auth0.com');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('scope')).toContain('legal:case');
    expect(url.searchParams.get('scope')).not.toMatch(/admin|employee/);
  });
});


test('reporter devices fail closed when approved roster cannot be read, without contacting firm websites', async () => {
  const fetch = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('must not contact a third party'));
  try {
    const organization = { organizationId: 'a'.repeat(64), domain: 'counsel.example', displayName: 'Counsel', approved: true,
      publicKey: {} } as any;
    const failure = await confirmOrganizationKeys({} as any, [organization], { operation: 'contact', target: 'Target Law' })
      .catch((error: Error) => error);
    expect(failure).toMatchObject({ name: 'OrganizationKeyUnconfirmedError', reason: 'failed', operation: 'contact' });
    expect((failure as Error).message).toContain('could not confirm the approved key of Counsel');
    expect(fetch).not.toHaveBeenCalled();
  } finally { fetch.mockRestore(); }
});
