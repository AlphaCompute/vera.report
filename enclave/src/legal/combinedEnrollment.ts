import { randomBytes, createHash } from 'node:crypto';
import { readKey } from '../confidential/pgp.js';
import { verifyCombinedApplicationApproval } from '../confidential/combinedApplicationApproval.js';
import { verifyApprovedOrganization } from '../confidential/initialRegistration.js';
import type { EnrollmentStore, LegalInvitation } from './enrollment.js';
import { createLegalIdentityVerifier } from './identity.js';
import type { LegalIdentityPolicy } from './identity.js';

/** Explicit combined-approval policy: a signed Slack decision replaces the
 * interactive admin step for FIRST enrollment only. Existing admin issuance,
 * replacement-key continuity and member key-possession proof remain enforced. */
export function createCombinedEnrollment(options: { legalIdentity: LegalIdentityPolicy; onboardingPublicKey: string; initialApprovalPublicKey?: string;
  store: EnrollmentStore; clock: () => number }) {
  const verifier = createLegalIdentityVerifier(options.legalIdentity);
  return async (accessToken: string, organizationId: string) => {
    try {
      const now = options.clock();
      if (!/^[a-f0-9]{64}$/.test(organizationId) || !options.store.getApplicationApproval || !options.store.registerFirstApplicationKey) throw new Error();
      const identity = await verifier.verify(accessToken, 'legal:enroll', now);
      const wire = await options.store.getApplicationApproval(organizationId);
      if (!wire) return { state: 'pending' as const };
      const authority = await readKey({ armoredKey: options.onboardingPublicKey });
      if (!options.initialApprovalPublicKey) throw new Error();
      const worker = await readKey({ armoredKey: options.initialApprovalPublicKey });
      if (worker.isPrivate() || worker.getFingerprint() === authority.getFingerprint()) throw new Error();
      const approved = await verifyCombinedApplicationApproval(wire, worker, now);
      const { registration: registration, authorization: member, statement } = approved;
      if (registration.organizationId !== organizationId || registration.providerOrganizationId !== identity.providerOrganizationId ||
          member.subject !== identity.subject) throw new Error();
      const existing = await options.store.getOrganization(organizationId);
      if (existing?.registration) {
        const current = await verifyApprovedOrganization(existing.registration, authority, now, worker);
        if (!existing.approved || !current.approved || current.recipientKeyId !== registration.recipientKeyId ||
            current.providerOrganizationId !== registration.providerOrganizationId || current.organizationId !== organizationId ||
            current.publicKey !== registration.publicKey) throw new Error();
      }
      // Store additionally fences revocation, domain/provider conflicts, and
      // concurrent replacement. Host rows alone never authorize a key.
      await options.store.registerFirstApplicationKey({ ...registration, registration: statement.registration, bindingDocument: statement.bindingDocument }, now);
      const createdAt = options.clock();
      if (identity.expiresAt <= createdAt || member.expiresAt <= createdAt) throw new Error();
      const token = randomBytes(32).toString('base64url');
      const invitation: LegalInvitation = { format: 'vera-legal-enrollment/v1', invitationId: randomBytes(32).toString('hex'),
        organizationId, providerOrganizationId: member.providerOrganizationId, subject: member.subject, recipientKeyId: member.recipientKeyId,
        nonce: randomBytes(32).toString('hex'), expiresAt: member.expiresAt, authorization: statement.authorization,
        tokenDigest: createHash('sha256').update(token).digest('hex'), createdAt: member.issuedAt,
        createdBy: statement.actor, version: 1, state: 'pending' };
      await options.store.insertInvitation(invitation);
      return { state: 'approved' as const, token, expiresAt: member.expiresAt };
    } catch { throw new Error('Combined enrollment unavailable'); }
  };
}
