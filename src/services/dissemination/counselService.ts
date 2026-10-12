import { logger } from '../../utils/logger';
/**
 * Counsel bench and matter-code flow (Phase 3a/3b, VERA-PDR-001 Tier C).
 *
 * Counsel is a routing target, not a code path: Psst Legal, panel firms,
 * and "reporter's own attorney" are rows in the counsel_partners
 * collection. Deactivate a row and it leaves assignment — the
 * partner-not-roadblock principle expressed as a schema.
 *
 * The identity leg happens entirely off-platform, by design: on
 * assignment Vera generates a matter code and posts a relay message
 * telling the reporter to contact counsel directly (Signal/Proton),
 * quoting the code. Counsel learns "the person quoting M-XXXX is my
 * client"; Vera never learns who that is. There is no message type in
 * relay_threads that can carry identity.
 *
 * Filing confirmation comes back as a counsel attestation receipt.
 */

import crypto from 'node:crypto';
import { disseminationPersistence } from './disseminationPersistence';
import { receiptTracker } from './receiptTracker';
import { getEntity } from './taxonomy';
import { channelConsented } from './consentScope';
import { reportPersistenceService } from '../reportPersistence';
import type { CounselAssignment, CounselPartnerDoc } from './types';

const ENGAGEMENT_MODELS: CounselPartnerDoc['engagementModel'][] = ['psst-legal', 'panel', 'reporter-own'];

export function generateMatterCode(): string {
  // Short enough to read over Signal, random enough to never collide in
  // practice (16^6 per active matter space).
  return `M-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

class CounselService {
  async upsertPartner(
    input: Partial<CounselPartnerDoc> & { name: string; contactHandle: string },
  ): Promise<{ partner?: CounselPartnerDoc; error?: string }> {
    if (!input.name?.trim() || !input.contactHandle?.trim()) {
      return { error: 'name and contactHandle are required' };
    }
    const engagementModel = input.engagementModel ?? 'panel';
    if (!ENGAGEMENT_MODELS.includes(engagementModel)) {
      return { error: `engagementModel must be one of: ${ENGAGEMENT_MODELS.join(', ')}` };
    }
    const channels = Array.isArray(input.channels) ? input.channels.filter((c) => getEntity(c)) : [];

    const now = new Date();
    const existing = input.counselId
      ? await disseminationPersistence.getCounselPartner(input.counselId)
      : null;

    const partner: CounselPartnerDoc = {
      counselId: input.counselId ?? crypto.randomUUID(),
      name: input.name.trim(),
      channels,
      contactHandle: input.contactHandle.trim(),
      engagementModel,
      active: input.active ?? true,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await disseminationPersistence.upsertCounselPartner(partner);
    return { partner };
  }

  listPartners(activeOnly = false): Promise<CounselPartnerDoc[]> {
    return disseminationPersistence.listCounselPartners(activeOnly);
  }

  /**
   * Assign counsel to a channel's submission (admin-pick via counselId, or
   * the first active partner covering the channel). Generates the matter
   * code, stamps the submission, audits, and posts the reporter-facing
   * relay message with the contact handle + code.
   */
  async assign(
    trackingId: string,
    entityId: string,
    actor: string,
    counselId?: string,
  ): Promise<{ assignment?: CounselAssignment; error?: string }> {
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return { error: 'submission_not_found' };
    if (['withdrawn', 'failed', 'closed', 'suppressed'].includes(sub.state)) return { error: `cannot_assign_in_state_${sub.state}` };
    // Counsel files with this entity for the reporter; that needs the channel's consent (#926).
    const report = await reportPersistenceService.get(trackingId);
    if (!report) return { error: 'report_not_found' };
    if (['dismissed', 'rejected'].includes(report.status)) return { error: 'report_not_eligible' };
    if (!channelConsented(report.consent, entityId)) return { error: 'reporter_consent_missing' };
    if (sub.counsel && counselId && sub.counsel.counselId !== counselId) return { error: 'counsel_already_assigned' };
    counselId = sub.counsel?.counselId ?? counselId;

    let partner: CounselPartnerDoc | null = null;
    if (counselId) {
      partner = await disseminationPersistence.getCounselPartner(counselId);
      if (!partner || !partner.active) return { error: 'counsel_not_found_or_inactive' };
      if (!partner.channels.includes(entityId)) return { error: 'counsel_does_not_cover_channel' };
    } else {
      const candidates = await disseminationPersistence.findCounselForChannel(entityId);
      partner = candidates[0] ?? null;
      if (!partner) return { error: 'no_active_counsel_for_channel' };
    }

    const candidate: CounselAssignment = {
      counselId: partner.counselId,
      counselName: partner.name,
      contactHandle: partner.contactHandle,
      matterCode: generateMatterCode(),
    };

    const assignment = await disseminationPersistence.ensureCounselAssignment(sub.submissionId, candidate);
    if (assignment.counselId !== partner.counselId) return { error: 'counsel_already_assigned' };
    const operationId = `counsel-assignment:${sub.submissionId}:${assignment.matterCode}`;
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'counsel_assigned',
      actor,
      // The matter code is auditable; reporter identity has nowhere to appear.
      detail: { counselId: assignment.counselId, matterCode: assignment.matterCode },
    }, operationId);

    // Reporter-facing notification through the relay thread (surfaced on
    // the status page). The reporter-to-counsel leg is off-platform.
    const entityName = getEntity(entityId)?.name ?? entityId;
    await disseminationPersistence.insertRelayMessage({
      messageId: operationId,
      trackingId,
      entityId,
      direction: 'to-reporter',
      body:
        `Your report will be filed with ${entityName} anonymously through an attorney. ` +
        `Contact ${assignment.counselName} directly at ${assignment.contactHandle} and quote ` +
        `matter code ${assignment.matterCode}. Do not share this code anywhere else. ` +
        `Vera.Report is not part of that conversation and never learns your identity.`,
      createdAt: new Date(),
    });

    logger.info(`✅ [DISSEMINATION:${entityId}] Counsel assigned for ${trackingId} (${assignment.matterCode})`);
    return { assignment };
  }

  /**
   * Record counsel's filing attestation (the TCR/confirmation number the
   * counsel returns after filing). Stops the ack clock.
   */
  async attest(
    trackingId: string,
    entityId: string,
    value: string,
    actor: string,
  ): Promise<{ ok: boolean; error?: string }> {
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return { ok: false, error: 'submission_not_found' };
    if (!sub.counsel) return { ok: false, error: 'no_counsel_assigned' };
    if (!value.trim()) return { ok: false, error: 'receipt_required' };
    if (['withdrawn', 'failed', 'closed', 'suppressed'].includes(sub.state)) return { ok: false, error: `cannot_attest_in_state_${sub.state}` };

    await receiptTracker.recordReceipt(
      sub,
      {
        type: 'manual',
        value: value.trim(),
        note: `counsel attestation (${sub.counsel.counselName}, ${sub.counsel.matterCode})`,
        receivedAt: new Date(),
      },
      actor,
      'ack',
      `counsel-attestation:${sub.submissionId}:${crypto.createHash('sha256').update(JSON.stringify([sub.counsel.matterCode, value.trim()])).digest('hex')}`,
    );
    return { ok: true };
  }
}

export const counselService = new CounselService();
