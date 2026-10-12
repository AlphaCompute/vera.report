import { verifyOrganizationRegistration } from '../confidential/organizationRegistration.js';
import { verifyApprovedOrganization, verifyApprovedMembership } from '../confidential/initialRegistration.js';
import { firmMemberId } from '../confidential/firmMembers.js';
import { verifyFirmKeyBinding } from '../confidential/firmKeyBinding.js';
import { verifyMembershipAuthorization } from '../confidential/membershipAuthorization.js';
import { createHash, randomBytes } from 'node:crypto';
import { readKey } from '../confidential/pgp.js';
import { caseRecipientKeyId } from '../confidential/caseObject.js';
import { verifyEnrollmentProof } from '../confidential/enrollmentProof.js';
import { verifyOrganizationKeyContinuity } from '../confidential/firmMembers.js';
import type { PublicKey } from '../confidential/pgp.js';
import type { EnrollmentChallenge } from '../confidential/enrollmentProof.js';
import { createLegalIdentityVerifier, createOnboardingAdminIdentityVerifier } from './identity.js';
import type { LegalIdentity, LegalIdentityPolicy } from './identity.js';

export type FirmEnrollmentBinding = {
  organizationId: string; providerOrganizationId: string;
  recipientKeyId: string; publicKey: string; approved: boolean; registration?: string; bindingDocument?: string;
};
export type LegalInvitation = EnrollmentChallenge & {
  authorization: string; tokenDigest: string; createdAt: number; createdBy: string;
  version: number; state: 'pending' | 'redeemed' | 'revoked';
};
export type DeviceDelegation = { memberId: string; deviceFingerprint: string; deviceProof: string };
export type MemberEnrollment = { challenge: EnrollmentChallenge; proof: string; authorization: string; delegation?: DeviceDelegation };
/** Device-scoped firm delegation: the firm and approved device both sign the
 * subject-bound challenge; the firm authorization caps the lease at seven days. */
export async function verifyDeviceMembership(enrollment: MemberEnrollment, key: PublicKey, device: {
  memberId: string; deviceFingerprint: string; devicePublicKey: string; subject: string; providerOrganizationId: string;
  organizationId: string; state: string;
}, now: number) {
  const delegated = enrollment.delegation, challenge = enrollment.challenge;
  if (device.memberId !== await firmMemberId(device.providerOrganizationId, device.subject)) denied();
  if (!delegated || device.state !== 'approved' || delegated.memberId !== device.memberId ||
      delegated.deviceFingerprint !== device.deviceFingerprint || challenge.subject !== device.subject ||
      challenge.providerOrganizationId !== device.providerOrganizationId || challenge.organizationId !== device.organizationId) denied();
  const authorization = await verifyMembershipAuthorization(enrollment.authorization, key, now);
  if (authorization.subject !== challenge.subject || authorization.organizationId !== challenge.organizationId ||
      authorization.providerOrganizationId !== challenge.providerOrganizationId || authorization.recipientKeyId !== challenge.recipientKeyId ||
      authorization.expiresAt !== challenge.expiresAt || await caseRecipientKeyId(key) !== challenge.recipientKeyId) denied();
  const deviceKey = await readKey({ armoredKey: device.devicePublicKey });
  if (deviceKey.isPrivate() || deviceKey.getFingerprint() !== device.deviceFingerprint) denied();
  await verifyEnrollmentProof(challenge, enrollment.proof, key);
  await verifyEnrollmentProof({ ...challenge, recipientKeyId: await caseRecipientKeyId(deviceKey) }, delegated.deviceProof, deviceKey);
  return authorization;
}
export type EnrolledMember = { organizationId: string; subject: string; recipientKeyId: string;
  enrollment: MemberEnrollment };
export interface EnrollmentStore {
  getApplicationApproval?(organizationId: string): Promise<string | null>;
  queueFirstApplicationKeyReview?(organizationId: string, providerOrganizationId: string, enrollment: {
    organizationId: string; recipientKeyId: string; bindingDocument: string }, now: number): Promise<void>;
  registerFirstApplicationKey?(organization: FirmEnrollmentBinding & { displayName: string; domain: string }, now: number): Promise<void>;
  /** Must return an independently authenticated firm-key binding and current whitelist state. */
  getOrganization(organizationId: string): Promise<FirmEnrollmentBinding | null>;
  getLegalOrganizationRecord?(organizationId: string): Promise<unknown>;
  /** `previousRecipientKeyId`/`continuity` are present only for a registered
   * organization's key change, which the enclave accepted only with a continuity
   * statement signed by the currently registered key. Without them the store must
   * accept a candidate only for an organization that has never been registered. */
  submitLegalOrganizationKeyCandidate?(value: { organizationId: string; providerOrganizationId: string; domain: string;
    bindingDocument: string; subject: string; recipientKeyId: string; previousRecipientKeyId?: string; continuity?: string }, now: number): Promise<void>;
  upsertLegalOrganization?(organization: FirmEnrollmentBinding & { displayName: string; domain: string }, now: number): Promise<void>;
  insertInvitation(invitation: LegalInvitation): Promise<void>;
  getInvitation(tokenDigest: string): Promise<LegalInvitation | null>;
  /** One transaction: compare invitation id/version/digest/state, recheck expiry
   * and current approved org/key binding, insert the member, and consume invite.
   * False means no state was changed. A read followed by an unconditional write
   * is not sufficient. The host transaction is not an authenticity authority;
   * firm and onboarding signatures are checked independently on every read.
   */
  commitEnrollment(expected: LegalInvitation, member: EnrolledMember, now: number): Promise<boolean>;
}

function denied(): never { throw new Error('Legal enrollment unavailable'); }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) denied();
  return value as string;
}
function subject(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/.test(value)) denied();
  return value as string;
}
function tokenDigest(token: string): string {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) denied();
  return createHash('sha256').update(token, 'utf8').digest('hex');
}
function challenge(invitation: LegalInvitation): EnrollmentChallenge {
  return { format: 'vera-legal-enrollment/v1', invitationId: invitation.invitationId,
    organizationId: invitation.organizationId, providerOrganizationId: invitation.providerOrganizationId,
    subject: invitation.subject, recipientKeyId: invitation.recipientKeyId,
    nonce: invitation.nonce, expiresAt: invitation.expiresAt };
}

async function approvedOrganization(store: EnrollmentStore, id: string, authority: string, now: number, initialAuthority?: string): Promise<FirmEnrollmentBinding> {
  const stored = await store.getOrganization(id);
  if (!stored) denied();
  const signed = await verifyApprovedOrganization(stored!.registration!, await readKey({ armoredKey: authority }), now,
    initialAuthority ? await readKey({ armoredKey: initialAuthority }) : undefined);
  const value = { ...signed, registration: stored!.registration };
  if (!stored!.approved || stored!.recipientKeyId !== value.recipientKeyId || stored!.publicKey !== value.publicKey ||
      stored!.providerOrganizationId !== value.providerOrganizationId) denied();
  if (value.organizationId !== id || value.approved !== true ||
      !/^org_[a-zA-Z0-9]{1,64}$/.test(value.providerOrganizationId) ||
      typeof value.publicKey !== 'string' || value.publicKey.length > 65_536) denied();
  const key = await readKey({ armoredKey: value.publicKey });
  if (await caseRecipientKeyId(key) !== identifier(value.recipientKeyId)) denied();
  // Check that the registered bundle actually has usable encryption/signing keys.
  await key.getEncryptionKey(); await key.getSigningKey();
  if (stored!.bindingDocument !== undefined) {
    const binding = await verifyFirmKeyBinding(stored!.bindingDocument, { domain: value.domain, organizationId: id });
    if (binding.binding.recipientKeyId !== value.recipientKeyId || binding.publicKey.armor() !== value.publicKey) denied();
  }
  return { ...value, ...(stored!.bindingDocument ? { bindingDocument: stored!.bindingDocument } : {}) };
}

/** Member side of enrollment only (challenge + redeem) under the legal
 * application's policy. Needs no admin identity; mountable on the firm channel. */
export function createLegalEnrollmentRedeemer(options: {
  legalIdentity: LegalIdentityPolicy; onboardingPublicKey: string; initialApprovalPublicKey?: string; store: EnrollmentStore; clock: () => number;
}) {
  const legal = createLegalIdentityVerifier(options.legalIdentity);
  const store = options.store, clock = options.clock;
  function now(): number {
    const value = clock();
    if (!Number.isSafeInteger(value) || value <= 0) denied();
    return value;
  }
  async function pending(token: string, accessToken: string): Promise<{
    invitation: LegalInvitation; binding: FirmEnrollmentBinding; identity: LegalIdentity;
  }> {
    const digest = tokenDigest(token), identity = await legal.verify(accessToken, 'legal:enroll', now());
    const stored = await store.getInvitation(digest);
    if (!stored) denied();
    const invitation = { ...stored! };
    if (invitation.tokenDigest !== digest || invitation.state !== 'pending' || invitation.expiresAt <= now() ||
        invitation.subject !== identity.subject || invitation.providerOrganizationId !== identity.providerOrganizationId ||
        !Number.isSafeInteger(invitation.version) || invitation.version < 1) denied();
    const binding = await approvedOrganization(store, identifier(invitation.organizationId), options.onboardingPublicKey, now(), options.initialApprovalPublicKey);
    const authorized = await verifyApprovedMembership(invitation.authorization, binding.registration!, await readKey({ armoredKey: options.onboardingPublicKey }), now(),
      options.initialApprovalPublicKey ? await readKey({ armoredKey: options.initialApprovalPublicKey }) : undefined);
    if (authorized.organizationId !== invitation.organizationId || authorized.subject !== invitation.subject ||
        authorized.providerOrganizationId !== invitation.providerOrganizationId || authorized.recipientKeyId !== invitation.recipientKeyId ||
        authorized.expiresAt !== invitation.expiresAt) denied();
    if (binding.providerOrganizationId !== invitation.providerOrganizationId || binding.recipientKeyId !== invitation.recipientKeyId ||
        identity.expiresAt <= now()) denied();
    return { invitation, binding, identity };
  }
  return {
    /** Approved public key over the attested channel. A host row alone cannot
     * change the recipient: the onboarding authority signature is verified. */
    async getOrganizationKey(accessToken: string, organizationId: string, domain: string) {
      try {
        const identity = await legal.verify(accessToken, 'legal:enroll', now());
        const id = identifier(organizationId);
        if (store.getLegalOrganizationRecord) {
          const existing = await store.getOrganization(id);
          const pending = await store.getLegalOrganizationRecord(id) as Record<string, unknown> | null;
          if (!existing?.registration && !existing?.publicKey && pending && pending._id === id && pending.providerOrganizationId === identity.providerOrganizationId &&
              pending.domain === domain && pending.revokedAt === undefined && pending.approved === false &&
              !pending.registration && !pending.publicKey && identity.expiresAt > now()) {
            return { state: 'awaiting-key' as const, organizationId: id, domain };
          }
        }
        const binding = await approvedOrganization(store, identifier(organizationId), options.onboardingPublicKey, now(), options.initialApprovalPublicKey);
        const signed = await verifyApprovedOrganization(binding.registration!, await readKey({ armoredKey: options.onboardingPublicKey }), now(),
          options.initialApprovalPublicKey ? await readKey({ armoredKey: options.initialApprovalPublicKey }) : undefined);
        if (identity.providerOrganizationId !== binding.providerOrganizationId || signed.domain !== domain || identity.expiresAt <= now()) denied();
        return { organizationId: signed.organizationId, domain: signed.domain, publicKey: signed.publicKey, recipientKeyId: signed.recipientKeyId, ...(binding.bindingDocument ? { bindingDocument: binding.bindingDocument } : {}) };
      } catch { return denied(); }
    },
    /** The public self-signed key is a candidate only. Platform review must
     * still sign the registration; submitting never enrolls or grants access.
     *
     * A first key may be proposed by any signed-in member of an organization that
     * has never been registered; a registered organization may only refresh the
     * profile of its current key here. Replacements use `legal.replace-organization-key`,
     * which needs current enrollment, a fresh steward proof and a continuity
     * statement signed by the registered key and the new one. A new key never
     * inherits reporters' grants (they name the old key). */
    async submitOrganizationKey(accessToken: string, organizationId: string, bindingDocument: string) {
      try {
        const id = identifier(organizationId), identity = await legal.verify(accessToken, 'legal:enroll', now());
        if (!store.getLegalOrganizationRecord || !store.submitLegalOrganizationKeyCandidate) denied();
        const stored = await store.getLegalOrganizationRecord!(id) as Record<string, unknown> | null;
        if (!stored || stored._id !== id || stored.revokedAt !== undefined ||
            stored.providerOrganizationId !== identity.providerOrganizationId || typeof stored.domain !== 'string') denied();
        const verified = await verifyFirmKeyBinding(bindingDocument, { domain: stored!.domain as string, organizationId: id });
        const authority = await readKey({ armoredKey: options.onboardingPublicKey });
        if (verified.publicKey.isPrivate() || verified.publicKey.getFingerprint() === authority.getFingerprint() || identity.expiresAt <= now()) denied();
        // An invitation-scoped login can introduce a first key, or refresh a
        // profile signed by the registered key. Replacements use the separate
        // enrolled-member operation with a fresh proof from the current key.
        if (stored!.approved === true) {
          const active = await approvedOrganization(store, id, options.onboardingPublicKey, now(), options.initialApprovalPublicKey);
          if (active.providerOrganizationId !== identity.providerOrganizationId ||
              active.recipientKeyId !== verified.binding.recipientKeyId) denied();
        } else if (stored!.approved !== false || await store.getOrganization(id)) denied();
        await store.submitLegalOrganizationKeyCandidate!({ organizationId: id, providerOrganizationId: identity.providerOrganizationId,
          domain: stored!.domain as string, bindingDocument, subject: identity.subject, recipientKeyId: verified.binding.recipientKeyId }, now());
        if (stored!.approved === false && verified.profile && store.queueFirstApplicationKeyReview) {
          await store.queueFirstApplicationKeyReview(id, identity.providerOrganizationId, { organizationId: id,
            recipientKeyId: verified.binding.recipientKeyId, bindingDocument }, now());
        }
        return { submitted: true as const, recipientKeyId: verified.binding.recipientKeyId };
      } catch { return denied(); }
    },
    async getChallenge(token: string, accessToken: string): Promise<EnrollmentChallenge> {
      try { return challenge((await pending(token, accessToken)).invitation); }
      catch { return denied(); }
    },
    async redeemInvitation(token: string, accessToken: string, proof: string): Promise<Omit<EnrolledMember, 'enrollment'>> {
      try {
        const { invitation, binding, identity } = await pending(token, accessToken);
        await verifyEnrollmentProof(challenge(invitation), proof, await readKey({ armoredKey: binding.publicKey }));
        const committedAt = now();
        if (identity.expiresAt <= committedAt || invitation.expiresAt <= committedAt) denied();
        const member = { organizationId: invitation.organizationId, subject: identity.subject, recipientKeyId: invitation.recipientKeyId,
          enrollment: { challenge: challenge(invitation), proof, authorization: invitation.authorization } };
        if (!await store.commitEnrollment(invitation, member, committedAt)) denied();
        return { organizationId: member.organizationId, subject: member.subject, recipientKeyId: member.recipientKeyId };
      } catch { return denied(); }
    },
  };
}

/** Enclave service logic only; not a host API, HTTP listener, or persistence adapter.
 * Admin and legal applications MUST use different audiences and client IDs.
 * Onboarding authority creates membership only, never case grants or key recovery.
 */
export function createLegalEnrollmentService(options: {
  adminIdentity: LegalIdentityPolicy; legalIdentity: LegalIdentityPolicy;
  adminOrganizationId: string; onboardingPublicKey: string; initialApprovalPublicKey?: string; store: EnrollmentStore; clock: () => number;
}) {
  if (options.adminIdentity.audience === options.legalIdentity.audience ||
      options.adminIdentity.clientId === options.legalIdentity.clientId ||
      !/^org_[a-zA-Z0-9]{1,64}$/.test(options.adminOrganizationId)) throw new Error('Separate legal identity boundary required');
  const admin = createOnboardingAdminIdentityVerifier(options.adminIdentity);
  const member = createLegalEnrollmentRedeemer(options);
  const adminOrganizationId = options.adminOrganizationId, store = options.store, clock = options.clock;
  function now(): number {
    const value = clock();
    if (!Number.isSafeInteger(value) || value <= 0) denied();
    return value;
  }
  return {
    async issueInvitation(accessToken: string, organizationId: string, recipientSubject: string, lifetimeMs: number, authorization: string, registration?: { displayName: string; domain: string; bindingDocument: string; authorization: string; continuity?: string }) {
      try {
        const id = identifier(organizationId), recipient = subject(recipientSubject);
        if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > 7 * 24 * 60 * 60 * 1000) denied();
        const actor = await admin.verify(accessToken, 'legal:invite', now());
        if (actor.providerOrganizationId !== adminOrganizationId) denied();
        const authority = await readKey({ armoredKey: options.onboardingPublicKey });
        const registrationApproval = await verifyMembershipAuthorization(authorization, authority, now());
        if (registrationApproval.organizationId !== id || registrationApproval.subject !== recipient ||
            registrationApproval.expiresAt > now() + lifetimeMs || actor.expiresAt <= now()) denied();
        if (registration !== undefined) {
          if (!registration || !['authorization,bindingDocument,displayName,domain', 'authorization,bindingDocument,continuity,displayName,domain']
                .includes(Object.keys(registration).sort().join(',')) ||
              typeof registration.displayName !== 'string' || !registration.displayName.trim() || registration.displayName.length > 160 ||
              !store.upsertLegalOrganization) denied();
          const verified = await verifyFirmKeyBinding(registration.bindingDocument, { domain: registration.domain, organizationId: id });
          if (verified.binding.recipientKeyId !== registrationApproval.recipientKeyId ||
              authority.getFingerprint() === verified.publicKey.getFingerprint()) denied();
          const signed = await verifyOrganizationRegistration(registration.authorization, authority, now());
          if (signed.organizationId !== id || signed.providerOrganizationId !== registrationApproval.providerOrganizationId ||
              signed.recipientKeyId !== registrationApproval.recipientKeyId || signed.publicKey !== verified.publicKey.armor() ||
              signed.domain !== registration.domain || signed.displayName !== registration.displayName.trim() || !signed.approved) denied();
          // Replacing a registered organization's key needs the organization's own
          // continuity statement, signed by the registered key and the new one. The
          // onboarding authority alone cannot swap a registered firm's key. (A new key
          // never inherits reporters' grants either way: they name the old key.)
          const existing = await store.getOrganization(id);
          if (typeof existing?.registration === 'string') {
            const current = await approvedOrganization(store, id, options.onboardingPublicKey, now(), options.initialApprovalPublicKey);
            if (current.recipientKeyId !== verified.binding.recipientKeyId) {
              if (typeof registration.continuity !== 'string') denied();
              const proof = await verifyOrganizationKeyContinuity(registration.continuity!, { organizationId: id,
                previousPublicKey: await readKey({ armoredKey: current.publicKey }) });
              if (proof.statement.nextRecipientKeyId !== verified.binding.recipientKeyId ||
                  proof.nextPublicKey.getFingerprint() !== verified.publicKey.getFingerprint()) denied();
            } else if (registration.continuity !== undefined) denied();
          } else if (registration.continuity !== undefined) denied();
          if (actor.expiresAt <= now() || registrationApproval.expiresAt <= now()) denied();
          await store.upsertLegalOrganization!({ organizationId: id, displayName: registration.displayName.trim(), domain: registration.domain,
            providerOrganizationId: registrationApproval.providerOrganizationId, recipientKeyId: registrationApproval.recipientKeyId,
            publicKey: verified.publicKey.armor(), approved: true, registration: registration.authorization, bindingDocument: registration.bindingDocument }, now());
        }
        const binding = await approvedOrganization(store, id, options.onboardingPublicKey, now(), options.initialApprovalPublicKey), createdAt = now();
        if (actor.expiresAt <= createdAt) denied();
        if (authority.getFingerprint() === (await readKey({ armoredKey: binding.publicKey })).getFingerprint()) denied();
        const approved = await verifyMembershipAuthorization(authorization, authority, createdAt);
        if (approved.organizationId !== id || approved.providerOrganizationId !== binding.providerOrganizationId ||
            approved.subject !== recipient || approved.recipientKeyId !== binding.recipientKeyId ||
            approved.expiresAt > createdAt + lifetimeMs) denied();
        const token = randomBytes(32).toString('base64url');
        const invitation: LegalInvitation = {
          format: 'vera-legal-enrollment/v1', invitationId: randomBytes(32).toString('hex'), organizationId: id,
          providerOrganizationId: binding.providerOrganizationId, subject: recipient, recipientKeyId: binding.recipientKeyId,
          nonce: randomBytes(32).toString('hex'), expiresAt: approved.expiresAt, authorization,
          tokenDigest: tokenDigest(token), createdAt, createdBy: actor.subject, version: 1, state: 'pending',
        };
        await store.insertInvitation(invitation);
        return { token, invitationId: invitation.invitationId, expiresAt: invitation.expiresAt };
      } catch { return denied(); }
    },
    getChallenge: member.getChallenge,
    redeemInvitation: member.redeemInvitation,
  };
}
