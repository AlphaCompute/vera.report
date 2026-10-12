import { createMessage, readSignature, sign, verify } from '../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { verifyFirmKeyBinding } from '../../enclave/src/confidential/firmKeyBinding';
import { applicationOrganizationId } from '../../enclave/src/confidential/applicationOrganization';
import { combinedApprovalExpiresAt, signCombinedApplicationApproval, verifyCombinedApplicationApproval } from '../../enclave/src/confidential/combinedApplicationApproval';
import { applicationReviewDigest } from '../../src/utils/legalApplicationEnrollment';
import type { LegalApplicationView } from '../../src/utils/legalApplications';
import type { SlackApplicationDecision } from '../../src/services/legalApplicationSlack';
import type { ApplicationIdentityProvider } from '../../src/services/legalApplicationAuth0';
import { failureReason } from '../../src/utils/failureReason';

export { failureReason };

export type ReviewRecord = { decision: SlackApplicationDecision; application: LegalApplicationView; decidedAt: number };
export type ApprovalJournal = {
  /** Exclusive create; return the already existing bytes on a race/retry. */
  record(id: string, wire: string): Promise<string>;
  entries(): Promise<string[]>;
  saveApproval(id: string, wire: string): Promise<string>;
  /** Drop the entry from `entries()`; 'expired' entries were never published. */
  complete(id: string, outcome?: 'published' | 'expired'): Promise<void>;
};
export type ApprovalBackend = {
  get(id: string): Promise<LegalApplicationView | null>;
  decide(decision: SlackApplicationDecision): Promise<boolean>;
  publish(id: string, digest: string, approval: string): Promise<void>;
};

/** This worker receives authenticated Socket Mode events directly. Its isolated
 * journal and authority are never available to the public backend. It signs only
 * snapshots whose digest and displayed Key ID were approved by an allowlisted
 * reviewer through Slack. The key must match the verified binding document. */
export function combinedApprovalWorker(options: { authority: PrivateKey; journal: ApprovalJournal;
  backend: ApprovalBackend; provider: ApplicationIdentityProvider; now?: () => number }) {
  const now = options.now ?? Date.now;
  const requireCurrentReview = (decidedAt: number) => {
    const expiresAt = combinedApprovalExpiresAt(decidedAt), time = now();
    // Journal timestamps and this worker share a clock. Unlike an enclave
    // reading a remote certificate, a local clock rollback must not add leeway.
    if (!Number.isSafeInteger(time) || time < decidedAt || time >= expiresAt) throw new Error('Invalid review');
  };
  const decode = async (wire: string, requireCurrent = true): Promise<ReviewRecord> => {
    if (wire.length > 160000) throw new Error('Invalid review');
    const envelope = JSON.parse(wire);
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(envelope.record)) }),
      signature: await readSignature({ armoredSignature: envelope.signature }), verificationKeys: options.authority.toPublic(), expectSigned: true, format: 'binary' });
    if (result.signatures.length !== 1) throw new Error('Invalid review');
    await result.signatures[0].verified;
    const record = envelope.record as ReviewRecord;
    combinedApprovalExpiresAt(record.decidedAt);
    if (record.decision.id !== record.application.id || !record.decision.reviewDigest ||
        record.decision.reviewDigest !== await applicationReviewDigest(record.application) ||
        (record.decision.status === 'approved' && (!record.decision.confirmedKeyId ||
          record.decision.confirmedKeyId !== record.application.enrollment?.recipientKeyId))) throw new Error('Invalid review');
    if (requireCurrent && record.decision.status === 'approved') requireCurrentReview(record.decidedAt);
    return record;
  };
  return {
    async decide(decision: SlackApplicationDecision): Promise<boolean> {
      if (!decision.reviewDigest) return options.backend.decide(decision);
      const application = await options.backend.get(decision.id);
      if (!application?.enrollment || await applicationReviewDigest(application) !== decision.reviewDigest) return false;
      if (decision.status === 'approved' && application.id !== await applicationOrganizationId(application.enrollment.recipientKeyId)) return false;
      if (decision.status === 'approved' && decision.confirmedKeyId !== application.enrollment.recipientKeyId) return false;
      const key = await verifyFirmKeyBinding(application.enrollment.bindingDocument, { organizationId: application.id, domain: application.domain });
      if (!key.profile || key.binding.recipientKeyId !== application.enrollment.recipientKeyId) return false;
      const record: ReviewRecord = { decision, application, decidedAt: now() };
      requireCurrentReview(record.decidedAt);
      const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(record)) }), signingKeys: options.authority, detached: true, format: 'armored' });
      const stored = await decode(await options.journal.record(decision.id, JSON.stringify({ record, signature })));
      if (stored.decision.status !== decision.status || stored.decision.reviewDigest !== decision.reviewDigest) return false;
      return options.backend.decide(stored.decision);
    },
    async provision(): Promise<void> {
      const failures: string[] = [];
      for (const wire of await options.journal.entries()) {
        let step = 'decode';
        try {
        const saved = await decode(wire, false);
        if (saved.decision.status !== 'approved') continue;
        // Past its window an approval can never be signed or published, so stop
        // retrying it. A clock behind decidedAt still fails below and is kept.
        if (now() >= combinedApprovalExpiresAt(saved.decidedAt)) {
          step = 'expire';
          await options.journal.complete(saved.application.id, 'expired');
          console.warn('Approval journal entry expired; dropped unsigned', saved.application.id.slice(0, 8));
          continue;
        }
        requireCurrentReview(saved.decidedAt);
        // A crashed process may have journaled before committing the queue intent.
        step = 'decide';
        if (!await options.backend.decide(saved.decision)) continue;
        step = 'get';
        const current = await options.backend.get(saved.application.id);
        if (!current?.enrollment || current.status !== 'approved' || current.keyReviewStatus !== 'approved' || current.provisioningStatus !== 'ready' ||
            !current.providerOrganizationId || await applicationReviewDigest(current) !== saved.decision.reviewDigest ||
            !options.provider.resolveApprovedMember) continue;
        step = 'review-age';
        requireCurrentReview(saved.decidedAt);
        // Independently resolve the reviewed email through the pinned IdP, never
        // take a subject supplied by the web backend or Slack display text.
        const application = { ...saved.application, status: 'approved' as const };
        step = 'resolve-member';
        const subject = await options.provider.resolveApprovedMember(application, current.providerOrganizationId, AbortSignal.timeout(45_000));
        step = 'review-age';
        requireCurrentReview(saved.decidedAt);
        step = 'sign';
        const approval = await options.journal.saveApproval(application.id, await signCombinedApplicationApproval({
          organizationId: application.id, providerOrganizationId: current.providerOrganizationId, domain: application.domain,
          displayName: application.displayName, subject, bindingDocument: application.enrollment!.bindingDocument,
          recipientKeyId: application.enrollment!.recipientKeyId, applicationDigest: saved.decision.reviewDigest!,
          actor: saved.decision.actor, decidedAt: saved.decidedAt, now: now(),
        }, options.authority));
        // Label an expiry during storage as such, not as a certificate failure.
        step = 'review-age';
        requireCurrentReview(saved.decidedAt);
        step = 'sign';
        const checked = await verifyCombinedApplicationApproval(approval, options.authority.toPublic(), now());
        if (checked.statement.applicationDigest !== saved.decision.reviewDigest || checked.authorization.subject !== subject ||
            checked.statement.decidedAt !== saved.decidedAt || checked.statement.actor !== saved.decision.actor ||
            checked.registration.organizationId !== application.id || checked.registration.providerOrganizationId !== current.providerOrganizationId) throw new Error('Invalid cached approval');
        step = 'review-age';
        requireCurrentReview(saved.decidedAt);
        step = 'publish';
        await options.backend.publish(application.id, saved.decision.reviewDigest!, approval);
        step = 'complete';
        await options.journal.complete(application.id);
        // One unavailable account must not block other approved firms.
        } catch (error) { failures.push(`${step}: ${failureReason(error)}`); }
      }
      if (failures.length) throw Object.assign(new Error('Some approvals remain pending'), { failures });
    },
  };
}
