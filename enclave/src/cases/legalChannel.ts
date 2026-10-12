import { verifyApprovedOrganization, verifyApprovedMembership } from '../confidential/initialRegistration.js';
import { createCombinedEnrollment } from '../legal/combinedEnrollment.js';
import { verifyEnrollmentProof } from '../confidential/enrollmentProof.js';
import { readKey } from '../confidential/pgp.js';
import { caseRecipientKeyId } from '../confidential/caseObject.js';
import { createLegalIdentityVerifier } from '../legal/identity.js';
import type { LegalIdentityPolicy } from '../legal/identity.js';
import { createLegalEnrollmentRedeemer, createLegalEnrollmentService, verifyDeviceMembership } from '../legal/enrollment.js';
import type { EnrollmentStore, FirmEnrollmentBinding, MemberEnrollment } from '../legal/enrollment.js';
import { createApplicationChannelSessions } from '../application-channel-sessions.js';
import type { ChannelDispatch } from '../application-channel-sessions.js';
import { CaseServiceError, createCaseService } from './service.js';
import { CHUNK_REPLY_LIMIT } from './ownerChannel.js';
import type { CaseService, CaseServiceOptions, OrganizationContext } from './service.js';
import { FIRM_DEVICE_LIMIT, createLegalFirmOperations, isLegalFirmOperation } from './legalFirm.js';
import type { LegalFirmStore } from './legalFirm.js';
import { createFirmSetup, isFirmSetupStatementKind } from './legalSetup.js';
import type { LegalIdentity } from '../legal/identity.js';

/** Current enrolled member row. `recipientKeyId` is the firm key the member
 * enrolled against; a firm-key rotation invalidates it until re-enrollment. */
export type LegalMember = {
  subject: string; providerOrganizationId: string; organizationId: string;
  recipientKeyId: string; revision: number; active: boolean;
  enrollment?: MemberEnrollment;
};
/** Untrusted host rows (storage RPC). Every field is re-checked here against the
 * verified token and the firm key itself; nothing is taken from the request. */
export interface LegalMembershipStore {
  getMember(subject: string, providerOrganizationId: string): Promise<LegalMember | null>;
  getOrganization(organizationId: string): Promise<FirmEnrollmentBinding | null>;
  /** Active, unexpired members enrolled against this firm key. Host-counted and
   * therefore informational only (the onboarding checklist); it never authorizes. */
  countMembers?(organizationId: string, recipientKeyId: string, now: number): Promise<number>;
  /** Up to 16 active, unexpired member rows enrolled against this firm key. Only
   * candidates for the setup key-holder count: each is verified in full here. */
  listMembers?(organizationId: string, recipientKeyId: string, now: number): Promise<LegalMember[]>;
}
type Options = Omit<CaseServiceOptions, 'channel'> & {
  identity: LegalIdentityPolicy; members: LegalMembershipStore;
  /** Enables `legal.enrollment-challenge` / `legal.enroll` (invitation redemption). */
  enrollment?: EnrollmentStore;
  /** Loaded only from manifest-verified measured image bytes. */
  administration?: { identity: LegalIdentityPolicy; organizationId: string; onboardingPublicKey: string; initialApprovalPublicKey?: string };
  /** Enables member device keys, the organization's shared request list and the
   * enforced organization setup (`legalSetup.ts`): with a firm store, requests and
   * case reads are refused with `{error:'setup-incomplete', missing}` until the
   * organization's signed onboarding terms are recorded. The mounted
   * server (`confidential-server.ts`) always configures it. */
  firm?: LegalFirmStore;
};
type Handler = [(service: CaseService, body: Uint8Array, proof: string, org: OrganizationContext) => Promise<unknown>, number];

const MAX_REQUEST = 192 * 1024, MAX_BODY = 64 * 1024, ID = /^[a-f0-9]{64}$/;
/** Case operations refused until organization setup is complete. Withdrawing a
 * request and reading request status stay available. */
const SETUP_GATED = new Set(['legal.request-access', 'legal.read-state-keys', 'legal.unlock-case', 'legal.open-case', 'legal.acknowledge-report-open']);
const KEY_HOLDER_CANDIDATES = 16;
// Private conversation is retired, including for legacy grants with a messages scope.
// Do not re-expose read-messages or send-message when accepting older case formats.
const HANDLERS: Record<string, Handler> = {
  'legal.acknowledge-report-open': [(s, b, p, o) => s.acknowledgeReportOpen(b, p, o), 4096],
  'legal.request-access': [(s, b, p, o) => s.submitAccessRequest(b, p, o), 4096],
  'legal.withdraw-request': [(s, b, p, o) => s.withdrawAccessRequest(b, p, o), 4096],
  'legal.request-status': [(s, b, p, o) => s.requestStatus(b, p, o), 4096],
  'legal.request-status-batch': [(s, b, p, o) => s.requestStatusBatch(b, p, o), 240 * 1024],
  'legal.read-state-keys': [(s, b, p, o) => s.getStateEnvelopes(b, p, o), 240 * 1024],
  'legal.unlock-case': [(s, b, p, o) => s.unlockCase(b, p, o), 4096],
  // Index, history and range replies stay far smaller; one evidence chunk is the largest.
  'legal.open-case': [(s, b, p, o) => s.openCase(b, p, o), CHUNK_REPLY_LIMIT],
};
function denied(): never { throw new Error('Legal case operation unavailable'); }

/** Firm-side case operations behind the attested channel. The organization
 * context is derived here from a verified legal access token plus the current
 * enrolled member and approved firm-key binding; request fields never name it.
 * Platform onboarding signatures bind the roster and initial steward lease.
 * Colleague leases require the approved firm and device signatures, a current
 * approved device, and the same seven-day maximum lifetime.
 * A host may replay a still-valid lease; IdP removal and key rotation are needed
 * for removal, and participant pins are the available freshness authority.
 * Membership is re-read after the operation and the reply suppressed if it
 * changed. That suppresses results only: a committed write (request, unlock) is not rolled back.
 * Case authorization (grant, release, checkpoint) stays in the case service.
 * Evidence uses bounded open-case range and chunk replies.
 */
export function createLegalCaseDispatcher(options: Options): ChannelDispatch {
  const { identity, members, enrollment, administration, firm, ...rest } = options;
  const settings = { ...rest, limits: { ...rest.limits } };
  const verifier = createLegalIdentityVerifier(identity);
  const combinedEnrollment = enrollment && administration ? createCombinedEnrollment({ legalIdentity: identity,
    onboardingPublicKey: administration.onboardingPublicKey, initialApprovalPublicKey: administration.initialApprovalPublicKey, store: enrollment, clock: rest.clock }) : null;
  const enroller = enrollment && administration ? createLegalEnrollmentRedeemer({ legalIdentity: identity, onboardingPublicKey: administration.onboardingPublicKey, initialApprovalPublicKey: administration.initialApprovalPublicKey, store: enrollment, clock: rest.clock }) : null;
  const issuer = enrollment && administration ? createLegalEnrollmentService({ legalIdentity: identity,
    adminIdentity: administration.identity, adminOrganizationId: administration.organizationId, onboardingPublicKey: administration.onboardingPublicKey, initialApprovalPublicKey: administration.initialApprovalPublicKey,
    store: enrollment, clock: rest.clock }) : null;
  function now(): number {
    const value = settings.clock();
    if (!Number.isSafeInteger(value) || value <= 0 || value > 8640000000000000) denied();
    return value;
  }
  /** Approved organization, bound by an onboarding signature to this identity-provider organization. */
  async function verifiedOrganization(organizationId: string, providerOrganizationId: string, recipientKeyId?: string) {
    const found = await members.getOrganization(organizationId);
    if (!found) denied();
    if (!administration) denied();
    const signed = await verifyApprovedOrganization(found!.registration!, await readKey({ armoredKey: administration!.onboardingPublicKey }), now(),
      administration!.initialApprovalPublicKey ? await readKey({ armoredKey: administration!.initialApprovalPublicKey }) : undefined);
    if (!found!.approved || found!.recipientKeyId !== signed.recipientKeyId || found!.publicKey !== signed.publicKey ||
        found!.providerOrganizationId !== signed.providerOrganizationId) denied();
    const organization = { ...signed };
    if (organization.organizationId !== organizationId || organization.approved !== true ||
        organization.providerOrganizationId !== providerOrganizationId ||
        (recipientKeyId !== undefined && organization.recipientKeyId !== recipientKeyId) ||
        typeof organization.publicKey !== 'string' || organization.publicKey.length > 65_536) denied();
    const key = await readKey({ armoredKey: organization.publicKey });
    if (key.isPrivate() || await caseRecipientKeyId(key) !== organization.recipientKeyId) denied();
    return { organization, key, registration: found!.registration! };
  }
  async function membership(subject: string, providerOrganizationId: string) {
    const stored = await members.getMember(subject, providerOrganizationId);
    if (!stored) denied();
    const member = { ...stored! };
    if (member.subject !== subject || member.providerOrganizationId !== providerOrganizationId || member.active !== true ||
        !Number.isSafeInteger(member.revision) || member.revision < 1 ||
        [member.organizationId, member.recipientKeyId].some(value => typeof value !== 'string' || !ID.test(value))) denied();
    const { organization, key, registration } = await verifiedOrganization(member.organizationId, providerOrganizationId, member.recipientKeyId);
    const certificate = member.enrollment;
    if (!administration || !certificate || certificate.challenge.subject !== subject ||
        certificate.challenge.providerOrganizationId !== providerOrganizationId ||
        certificate.challenge.organizationId !== member.organizationId ||
        certificate.challenge.recipientKeyId !== member.recipientKeyId || certificate.challenge.expiresAt <= now()) denied();
    const authority = await readKey({ armoredKey: administration!.onboardingPublicKey });
    if (authority.getFingerprint() === key.getFingerprint()) denied();
    let authorized;
    if (certificate.delegation) {
      if (!firm) denied();
      const device = await firm!.getFirmDevice(member.organizationId, certificate.delegation.memberId);
      if (!device || device.subject !== subject || device.providerOrganizationId !== providerOrganizationId) denied();
      authorized = await verifyDeviceMembership(certificate, key, device!, now());
    } else authorized = await verifyApprovedMembership(certificate!.authorization, registration, authority, now(),
      administration!.initialApprovalPublicKey ? await readKey({ armoredKey: administration!.initialApprovalPublicKey }) : undefined);
    if (authorized.subject !== subject || authorized.providerOrganizationId !== providerOrganizationId ||
        authorized.organizationId !== member.organizationId || authorized.recipientKeyId !== member.recipientKeyId ||
        authorized.expiresAt !== certificate!.challenge.expiresAt) denied();
    await verifyEnrollmentProof(certificate!.challenge, certificate!.proof, key);
    return { revision: member.revision, context: { organizationId: organization.organizationId,
      recipientKeyId: organization.recipientKeyId, publicKey: organization.publicKey } };
  }
  /** Self-service onboarding status for the signed-in member only. "Not enrolled"
   * is a normal answer, not an error; a row that exists but fails verification
   * is still denied so a tampered host row never reads as a valid membership. */
  async function membershipStatus(accessToken: unknown) {
    if (typeof accessToken !== 'string') denied();
    const actor = await verifier.verify(accessToken as string, 'legal:directory', now());
    const stored = await members.getMember(actor.subject, actor.providerOrganizationId);
    if (!stored || stored.subject !== actor.subject || stored.providerOrganizationId !== actor.providerOrganizationId) {
      return { enrolled: false, lapsed: false };
    }
    const leaseExpiresAt = stored.enrollment?.challenge?.expiresAt;
    if (stored.active !== true || (typeof leaseExpiresAt === 'number' && leaseExpiresAt <= now())) return { enrolled: false, lapsed: true };
    const verified = await membership(actor.subject, actor.providerOrganizationId);
    let count: number | null = null;
    if (members.countMembers) {
      // Informational only: a storage failure hides the count, it never fails the status.
      try {
        const counted = await members.countMembers(verified.context.organizationId, verified.context.recipientKeyId, now());
        count = Number.isSafeInteger(counted) && counted >= 1 ? Math.min(counted, 1000) : null;
      } catch { count = null; }
    }
    if (actor.expiresAt <= now()) denied();
    return { enrolled: true, lapsed: false, organizationId: verified.context.organizationId,
      recipientKeyId: verified.context.recipientKeyId, leaseExpiresAt: stored.enrollment!.challenge.expiresAt, members: count };
  }
  async function principal(accessToken: unknown, scope: 'legal:directory' | 'legal:case') {
    if (typeof accessToken !== 'string') denied();
    const actor = await verifier.verify(accessToken as string, scope, now());
    const initial = await membership(actor.subject, actor.providerOrganizationId);
    if (actor.expiresAt <= now()) denied();
    return { context: initial.context, identity: actor, async recheck() {
      const current = await membership(actor.subject, actor.providerOrganizationId);
      if (current.revision !== initial.revision || current.context.organizationId !== initial.context.organizationId ||
          current.context.recipientKeyId !== initial.context.recipientKeyId ||
          current.context.publicKey !== initial.context.publicKey || actor.expiresAt <= now()) denied();
    } };
  }
  const setup = firm && administration ? createFirmSetup({ store: firm, now }) : null;
  /** Distinct people currently enrolled against this organization key, the
   * verified caller included. Host rows (enrolled members, approved member
   * devices) only nominate candidates; each counts only after the full
   * membership check, including its enrollment proof signed by this key. */
  function keyHolders(context: OrganizationContext, actor: LegalIdentity) {
    return async (enough: number): Promise<number> => {
      const counted = new Set<string>([actor.subject]), candidates = new Set<string>();
      const nominate = (row: unknown) => {
        const value = row as { subject?: unknown; providerOrganizationId?: unknown } | null;
        if (value && typeof value.subject === 'string' && value.subject.length <= 256 &&
            value.providerOrganizationId === actor.providerOrganizationId &&
            value.subject !== actor.subject && candidates.size < KEY_HOLDER_CANDIDATES) candidates.add(value.subject);
      };
      if (counted.size >= enough) return counted.size;
      if (members.listMembers) {
        const rows = await members.listMembers(context.organizationId, context.recipientKeyId, now());
        if (!Array.isArray(rows)) denied();
        rows.slice(0, KEY_HOLDER_CANDIDATES).forEach(nominate);
      }
      if (firm && candidates.size < KEY_HOLDER_CANDIDATES) {
        const rows = await firm.listFirmDevices(context.organizationId);
        // Same bound as legalFirm's device reader: an oversized host list is refused.
        if (!Array.isArray(rows) || rows.length > FIRM_DEVICE_LIMIT * 2) denied();
        rows.filter(row => (row as { state?: unknown } | null)?.state === 'approved').forEach(nominate);
      }
      for (const subject of candidates) {
        if (counted.size >= enough) break;
        try {
          const verified = await membership(subject, actor.providerOrganizationId);
          if (verified.context.organizationId === context.organizationId && verified.context.recipientKeyId === context.recipientKeyId &&
              verified.context.publicKey === context.publicKey) counted.add(subject);
        } catch { /* Not a current member for this key: not counted. */ }
      }
      return counted.size;
    };
  }
  const firmOperations = firm && administration ? createLegalFirmOperations({ store: firm, now, audience: settings.audience,
    verify: (token, scope) => verifier.verify(token, scope, now()),
    organization: async (organizationId, providerOrganizationId) => {
      const { organization } = await verifiedOrganization(organizationId, providerOrganizationId);
      return { organizationId: organization.organizationId, recipientKeyId: organization.recipientKeyId, publicKey: organization.publicKey };
    },
    approvedDomain: async (organizationId, providerOrganizationId) => (await verifiedOrganization(organizationId, providerOrganizationId)).organization.domain,
    principal: (accessToken, scope) => principal(accessToken, scope),
    enrolled: async (subject, providerOrganizationId, recipientKeyId) => {
      const row = await members.getMember(subject, providerOrganizationId).catch(() => null);
      return !!row && row.active === true && row.recipientKeyId === recipientKeyId;
    } }) : null;
  return async (body, context) => {
    let operationBody: Uint8Array | undefined;
    try {
      if (!(body instanceof Uint8Array) || body.length > MAX_REQUEST || context.signal.aborted) denied();
      const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
      if (!request || typeof request !== 'object' || Array.isArray(request)) denied();
      const fields = Object.keys(request).sort().join(',');
      const channel = { nonce: context.nonce, serverKeyId: context.serverKeyId, authenticated: context.authenticated,
        challenges: context.challenges, signal: context.signal };
      let result: unknown, replyLimit = 4096;
      if (firmOperations && isLegalFirmOperation(request.operation)) {
        ({ result, replyLimit } = await firmOperations(request, channel));
      } else if (request.operation === 'legal.challenge') {
        const service = createCaseService({ ...settings, channel });
        if (fields === 'operation') result = await service.issueChallenge();
        else if (fields === 'count,operation' && Number.isSafeInteger(request.count)) result = await service.issueChallenges(request.count);
        else denied();
      } else if (request.operation === 'legal.release-approvals') {
        if (fields !== 'caseId,operation' || typeof request.caseId !== 'string') denied();
        result = await createCaseService({ ...settings, channel }).releaseApprovals(request.caseId);
        replyLimit = 128 * 1024;
      } else if (request.operation === 'legal.directory') {
        const { after, limit } = request;
        if (fields !== 'accessToken,after,limit,operation' || !Number.isSafeInteger(limit) || limit < 1 || limit > 20 ||
            (after !== null && (typeof after !== 'string' || !ID.test(after)))) denied();
        const actor = await principal(request.accessToken, 'legal:directory');
        const service = createCaseService({ ...settings, channel, limits: { ...settings.limits, listingPage: limit } });
        const page = await service.signedListings({ kind: 'organization', ...actor.context }, after);
        await actor.recheck();
        result = { listings: page.listings.map(({ caseId, summary, publishedAt, hasAttachments, ownerPublicKey, listing }) =>
          ({ caseId, summary, ...(publishedAt !== undefined ? { publishedAt } : {}),
            ...(hasAttachments !== undefined ? { hasAttachments } : {}), ownerPublicKey, listing })), next: page.next };
        replyLimit = 240 * 1024;
      } else if (setup && (request.operation === 'legal.setup-status' || request.operation === 'legal.setup-record')) {
        // Organization setup (legalSetup.ts): any enrolled member reads it; a
        // statement is recorded only if the registered organization key signed it.
        const writing = request.operation === 'legal.setup-record';
        if (fields !== 'accessToken,body,operation' || typeof request.body !== 'string' || request.body.length > 16 * 1024) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (Buffer.from(operationBody).toString('base64') !== request.body) denied();
        const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(operationBody));
        if (!input || typeof input !== 'object' || Array.isArray(input) ||
            Object.keys(input).sort().join(',') !== (writing ? 'kind,organizationId,statement' : 'organizationId')) denied();
        const actor = await principal(request.accessToken, 'legal:case');
        if (input.organizationId !== actor.context.organizationId) denied();
        if (writing) {
          if (!isFirmSetupStatementKind(input.kind)) denied();
          if (!await setup.record(actor.context, input.kind, input.statement)) denied();
        }
        result = await setup.status(actor.context, keyHolders(actor.context, actor.identity));
        await actor.recheck();
        replyLimit = 1024;
      } else if (request.operation === 'legal.membership') {
        if (fields !== 'accessToken,operation') denied();
        result = await membershipStatus(request.accessToken);
        replyLimit = 1024;
      } else if (request.operation === 'legal.organization-key') {
        if (!enroller || fields !== 'accessToken,domain,operation,organizationId' || typeof request.accessToken !== 'string' ||
            typeof request.organizationId !== 'string' || typeof request.domain !== 'string') denied();
        result = await enroller!.getOrganizationKey(request.accessToken, request.organizationId, request.domain);
        replyLimit = 96 * 1024;
      } else if (request.operation === 'legal.activate-application') {
        if (!combinedEnrollment || fields !== 'accessToken,operation,organizationId' || typeof request.accessToken !== 'string' ||
            typeof request.organizationId !== 'string') denied();
        result = await combinedEnrollment!(request.accessToken, request.organizationId);
        replyLimit = 1024;
      } else if (request.operation === 'legal.submit-organization-key') {
        if (!enroller || fields !== 'accessToken,body,operation' || typeof request.accessToken !== 'string' ||
            typeof request.body !== 'string' || request.body.length > 128 * 1024) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (Buffer.from(operationBody).toString('base64') !== request.body) denied();
        const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(operationBody));
        if (!input || typeof input !== 'object' || Array.isArray(input) ||
            Object.keys(input).sort().join(',') !== 'bindingDocument,organizationId' ||
            typeof input.organizationId !== 'string' || typeof input.bindingDocument !== 'string') denied();
        result = await enroller!.submitOrganizationKey(request.accessToken, input.organizationId, input.bindingDocument);
      } else if (request.operation === 'legal.issue-invitation') {
        if (!issuer || fields !== 'accessToken,body,operation' || typeof request.accessToken !== 'string' ||
            typeof request.body !== 'string' || request.body.length > 128 * 1024) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (Buffer.from(operationBody).toString('base64') !== request.body) denied();
        const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(operationBody));
        if (!input || !['authorization,lifetimeMs,organizationId,subject', 'authorization,lifetimeMs,organizationId,registration,subject'].includes(Object.keys(input).sort().join(','))) denied();
        result = await issuer!.issueInvitation(request.accessToken, input.organizationId, input.subject, input.lifetimeMs, input.authorization, input.registration);
      } else if (request.operation === 'legal.enrollment-challenge' || request.operation === 'legal.enroll') {
        // The invitation token and proof travel only inside this encrypted body.
        const enroll = request.operation === 'legal.enroll';
        if (!enroller || fields !== 'accessToken,body,operation' || typeof request.accessToken !== 'string' ||
            typeof request.body !== 'string' || request.body.length > 32 * 1024) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (Buffer.from(operationBody).toString('base64') !== request.body) denied();
        const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(operationBody));
        if (!input || typeof input !== 'object' || Array.isArray(input) ||
            Object.keys(input).sort().join(',') !== (enroll ? 'proof,token' : 'token') ||
            typeof input.token !== 'string' || (enroll && typeof input.proof !== 'string')) denied();
        result = enroll ? await enroller!.redeemInvitation(input.token, request.accessToken, input.proof)
          : await enroller!.getChallenge(input.token, request.accessToken);
      } else {
        const handler = Object.prototype.hasOwnProperty.call(HANDLERS, request.operation) ? HANDLERS[request.operation] : null;
        if (fields !== 'accessToken,body,operation,proof' || !handler ||
            typeof request.proof !== 'string' || request.proof.length > 20000 ||
            typeof request.body !== 'string' || request.body.length > Math.ceil(MAX_BODY / 3) * 4) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (operationBody.length > MAX_BODY || Buffer.from(operationBody).toString('base64') !== request.body) denied();
        const actor = await principal(request.accessToken, 'legal:case');
        if (context.signal.aborted) denied();
        const missing = setup && SETUP_GATED.has(request.operation)
          ? await setup.missing(actor.context, keyHolders(actor.context, actor.identity)) : null;
        if (missing) result = { error: 'setup-incomplete', missing };
        else try {
          result = await handler![0](createCaseService({ ...settings, channel }), operationBody, request.proof, actor.context);
        } catch (error) {
          // Encrypted to the firm: prompt unlock or wait for owner release approval.
          if (error instanceof CaseServiceError && (error.code === 'locked' || error.code === 'release-not-approved')) {
            result = { error: error.code };
          } else if (error instanceof CaseServiceError && error.code === 'not-found' &&
              (request.operation === 'legal.open-case' || request.operation === 'legal.read-state-keys' ||
               request.operation === 'legal.unlock-case')) {
            // No current grant for this verified firm (or no such case/manifest).
            // For unlock-case this is a firm that still holds the current state
            // key after its grant ended while the case was locked: the key was
            // refused and dropped; the answer only lets the portal say so.
            result = { error: 'not-granted' };
          } else throw error;
        }
        await actor.recheck();
        replyLimit = handler![1];
      }
      if (context.signal.aborted) denied();
      const reply = new TextEncoder().encode(JSON.stringify(result));
      if (reply.length > replyLimit) { reply.fill(0); denied(); }
      return reply;
    } catch { return denied(); } finally { operationBody?.fill(0); }
  };
}

/** Fixed production attestor; no caller-selected key, helper or plaintext route. */
export function createLegalCaseChannel(options: Options) {
  return createApplicationChannelSessions(createLegalCaseDispatcher(options));
}
