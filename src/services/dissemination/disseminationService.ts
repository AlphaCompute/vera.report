import { logger } from '../../utils/logger';
/**
 * Dissemination Service orchestrator (VERA-PDR-001 §7.1).
 *
 * Ties the pipeline together for the API layer: build the identity-free
 * view, run the routing engine, enforce the consent gate on approval
 * (FR-8), create disposition + submission records, and report channel
 * status. Nothing dispatches without an admin approval event — dispatch
 * itself happens in dispatchWorker.
 */

import crypto from 'node:crypto';
import { decryptReportNarrative } from '../reportNarrative';
import { reportPersistenceService, type ReportRecord } from '../reportPersistence';
import { decryptContactValue } from '../reportFieldCrypto';
import { buildDisseminationView, type EvidenceFileInfo } from './disseminationView';
import { disseminationPersistence } from './disseminationPersistence';
import { routingEngine } from './routingEngine';
import { packetGenerator } from './packetGenerator';
import { receiptTracker } from './receiptTracker';
import { hasAdapter, getAdapter } from './adapters/registry';
import { getEntity } from './taxonomy';
import { channelConsented } from './consentScope';
import { agencyDispatchConsented, legalReviewConsented } from '../../utils/intakeConsent';
import type {
  ChannelState,
  ConsentSnapshot,
  DisseminationPlan,
  DisseminationView,
  DispositionDoc,
  SubmissionDoc,
} from './types';

export interface ChannelStatus {
  entityId: string;
  entityName: string;
  tier: string;
  state: ChannelState;
  attempts: number;
  lastError?: string;
  dispatchedAt?: Date;
  sla?: SubmissionDoc['sla'];
  handoff?: SubmissionDoc['handoff'];
  counsel?: SubmissionDoc['counsel'];
  receipts: { type: string; value: string; receivedAt: Date; note?: string }[];
}

export function idempotencyKeyFor(trackingId: string, entityId: string, packetVersion: number): string {
  return crypto
    .createHash('sha256')
    .update(`${trackingId}:${entityId}:${packetVersion}`)
    .digest('hex');
}

class DisseminationService {
  /** Load a report and build its identity-free dissemination view. */
  async buildView(trackingId: string): Promise<{ report: ReportRecord; view: DisseminationView; narrativeReadable: boolean } | null> {
    const report = await reportPersistenceService.get(trackingId);
    if (!report) return null;

    // Narrative + evidence manifest come from MongoDB (the source of record).
    // The narrative is stored encrypted-at-rest and decrypted here for the
    // identity-free view; decryption failure is non-fatal — the view falls
    // back to an empty narrative marked unreadable, which the admin can fill via the
    // redaction override) before approving. The evidence manifest surfaces
    // names + CIDs only; the per-file encryption params are deliberately NOT
    // included, per the dissemination identity firewall.
    let narrative = '';
    let narrativeReadable = true;
    if (report.encryptedDescription || report.encryptedNarrative) {
      try {
        narrative = (await decryptReportNarrative(report)) ?? '';
      } catch (err: unknown) {
        narrativeReadable = false;
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn(`[DISSEMINATION] Narrative decrypt failed for ${trackingId}: ${msg}`);
      }
    }

    const evidenceDocs = await reportPersistenceService.listEvidenceByTrackingIds([trackingId]);
    const files: EvidenceFileInfo[] = [...evidenceDocs].sort((a, b) => a.fileKey.localeCompare(b.fileKey)).map((d) => {
      const slash = d.fileKey.indexOf('/');
      return {
        name: slash >= 0 ? d.fileKey.slice(slash + 1) : d.fileKey,
        cid: d.originalCID,
        mimetype: d.mimetype,
      };
    });

    const view = buildDisseminationView(report, narrative, files);

    // Admin-accepted redaction (AI redaction pass): once frozen on the
    // disposition, the override replaces the raw narrative in everything
    // rendered from the view — packets, companions, STIX, cover letters.
    const disposition = await disseminationPersistence.getDisposition(trackingId);
    if (disposition?.narrativeOverride?.narrative) {
      view.narrative = disposition.narrativeOverride.narrative;
      narrativeReadable = true;
    }

    return { report, view, narrativeReadable };
  }

  /** Effective consent: `agency` and `legalReview` are read against the version shown (#926). */
  consentFromReport(report: ReportRecord): ConsentSnapshot | null {
    if (!report.consent) return null;
    return {
      psst: {
        granted: report.consent.psst?.granted === true,
        treatment: report.consent.psst?.treatment as ConsentSnapshot['psst']['treatment'],
      },
      agency: agencyDispatchConsented(report.consent),
      legalReview: legalReviewConsented(report.consent),
      press: report.consent.press === true,
      capturedAt: report.consent.capturedAt,
      textVersion: report.consent.textVersion,
    };
  }

  /** FR-2: run the routing engine and return the recommended plan. */
  async plan(trackingId: string): Promise<DisseminationPlan | null> {
    const loaded = await this.buildView(trackingId);
    if (!loaded) return null;

    const consent = this.consentFromReport(loaded.report);
    return routingEngine.recommend(loaded.view, consent);
  }

  /**
   * Approve a set of channels for dispatch (FR-8, FR-10).
   *
   * The consent gate is enforced here, server-side: channels the reporter
   * did not consent to are refused regardless of what the admin selected.
   * Returns the created/updated disposition, or an error string.
   */
  async approve(
    trackingId: string,
    entityIds: string[],
    approvedBy: string,
  ): Promise<{ disposition: DispositionDoc; refused: { entityId: string; reason: string }[] } | { error: string }> {
    const loaded = await this.buildView(trackingId);
    if (!loaded) return { error: 'report_not_found' };

    const consent = this.consentFromReport(loaded.report);
    if (!consent) return { error: 'no_consent_on_record' };

    const now = new Date();
    const refused: { entityId: string; reason: string }[] = [];
    const approved: { entityId: string; tier: DispositionDoc['channels'][number]['tier'] }[] = [];

    // One-channel-per-entity rule (SEC guidance: a single method of
    // transmission per agency — duplicates cause confusion and delay).
    // Withdrawn/failed channels may be re-approved; anything live may not.
    const existingSubs = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const liveEntityIds = new Set(
      existingSubs.filter((s) => !['withdrawn', 'failed'].includes(s.state)).map((s) => s.entityId),
    );

    for (const entityId of entityIds) {
      const entity = getEntity(entityId);
      if (!entity) {
        refused.push({ entityId, reason: 'unknown_entity' });
        continue;
      }
      if (!hasAdapter(entityId)) {
        refused.push({ entityId, reason: 'adapter_not_available_this_phase' });
        continue;
      }
      if (liveEntityIds.has(entityId)) {
        refused.push({ entityId, reason: 'already_filed_one_channel_rule' });
        continue;
      }
      if (!channelConsented(consent, entityId)) {
        refused.push({ entityId, reason: 'reporter_consent_missing' });
        continue;
      }
      approved.push({ entityId, tier: entity.tier });
    }

    if (approved.length === 0 && refused.length > 0) {
      return { error: `no_channels_approved: ${refused.map((r) => `${r.entityId}(${r.reason})`).join(', ')}` };
    }

    // Upsert the disposition (consent snapshot is immutable — what the
    // reporter agreed to, in the language version shown to them).
    const existing = await disseminationPersistence.getDisposition(trackingId);
    const channels = existing?.channels ?? [];
    for (const ch of approved) {
      const present = channels.find((c) => c.entityId === ch.entityId);
      if (!present) {
        channels.push({ entityId: ch.entityId, tier: ch.tier, state: 'approved' });
      } else if (['withdrawn', 'failed'].includes(present.state)) {
        present.state = 'approved';
      }
    }

    const disposition: DispositionDoc = {
      trackingId,
      channels,
      consentSnapshot: consent,
      approvedBy,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await disseminationPersistence.upsertDisposition(disposition);

    // Create submission rows — the dispatch queue entries. The unique
    // idempotency key makes re-approval a no-op rather than a double-file.
    for (const ch of approved) {
      const idempotencyKey = idempotencyKeyFor(trackingId, ch.entityId, packetGenerator.packetVersion);
      let inserted = await disseminationPersistence.insertSubmission({
        submissionId: crypto.randomUUID(),
        trackingId,
        entityId: ch.entityId,
        tier: ch.tier,
        idempotencyKey,
        state: 'approved',
        packetVersion: packetGenerator.packetVersion,
        attempts: 0,
        createdAt: now,
        updatedAt: now,
      });

      // A withdrawn/failed submission holds the idempotency key; re-approval
      // resurrects it instead of double-filing (the one-channel guard above
      // already refused anything still live).
      if (!inserted) {
        const prior = existingSubs.find((s) => s.entityId === ch.entityId);
        if (prior && ['withdrawn', 'failed'].includes(prior.state)) {
          await disseminationPersistence.patchSubmission(prior.submissionId, {
            state: 'approved',
            attempts: 0,
            nextAttemptAt: undefined,
            lastError: undefined,
          });
          inserted = true;
        }
      }

      await disseminationPersistence.appendAudit({
        trackingId,
        entityId: ch.entityId,
        event: inserted ? 'channel_approved' : 'channel_approval_duplicate_ignored',
        actor: approvedBy,
        detail: { idempotencyKey },
      });
    }

    logger.info(
      `✅ [DISSEMINATION] ${trackingId}: approved ${approved.map((c) => c.entityId).join(', ') || '(none)'}` +
        (refused.length ? `; refused ${refused.map((r) => r.entityId).join(', ')}` : ''),
    );

    return { disposition, refused };
  }

  /**
   * Withdraw a channel before dispatch (FR-8: consent is revocable prior
   * to submission). Dispatched channels cannot be withdrawn.
   */
  async withdraw(trackingId: string, entityId: string, actor: string): Promise<{ ok: boolean; error?: string }> {
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return { ok: false, error: 'submission_not_found' };

    const withdrawable: ChannelState[] = ['approved', 'deferred', 'packet_ready', 'failed'];
    if (!withdrawable.includes(sub.state)) {
      return { ok: false, error: `cannot_withdraw_in_state_${sub.state}` };
    }

    if (!await disseminationPersistence.updateUnsentSubmission(sub.submissionId, { state: 'withdrawn' }, true)) {
      return { ok: false, error: 'dispatch_started_or_channel_changed' };
    }
    await disseminationPersistence.setDispositionChannelState(trackingId, entityId, 'withdrawn');
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'channel_withdrawn',
      actor,
    });
    await this.releasePacket(sub, actor);
    return { ok: true };
  }

  /**
   * Revoke a withdrawn submission's packet reference and attempt provider
   * cleanup. Unpinning does not prove deletion of cached copies or archive
   * versions; the protected audit retains provenance and the cleanup result.
   */
  async releasePacket(sub: SubmissionDoc, actor: string): Promise<void> {
    const { trackingId, entityId } = sub;
    if (sub.packetCid) {
      let unpinned = false;
      try {
        const { evidenceStorageService } = await import('../evidenceStorage');
        await evidenceStorageService.unpin(sub.packetCid);
        unpinned = true;
      } catch {
        // Provider errors can contain credentials, URLs or report identifiers.
        logger.warn('[DISSEMINATION] Packet unpin failed; cleanup remains unverified');
      }
      await disseminationPersistence.patchSubmission(sub.submissionId, {
        packetCid: undefined,
      });
      await disseminationPersistence.appendAudit({
        trackingId,
        entityId,
        event: unpinned ? 'packet_unpinned' : 'packet_unpin_failed',
        actor,
        detail: { packetCid: sub.packetCid, packetHash: sub.packetHash, unpinned },
      });
    }
  }

  /**
   * Retry a dead-lettered channel (alerts rail, NFR-3: a failed submission
   * is retried, never silently dropped). Resets the submission to
   * `approved` so the dispatch worker picks it up on its next tick.
   */
  async retry(trackingId: string, entityId: string, actor: string): Promise<{ ok: boolean; error?: string }> {
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return { ok: false, error: 'submission_not_found' };
    if (sub.dispatchInFlightAt) return { ok: false, error: 'dispatch_outcome_requires_reconciliation' };
    if (sub.state !== 'failed') {
      return { ok: false, error: `cannot_retry_in_state_${sub.state}` };
    }

    await disseminationPersistence.patchSubmission(sub.submissionId, {
      state: 'approved',
      attempts: 0,
      nextAttemptAt: undefined,
      lastError: undefined,
    });
    await disseminationPersistence.setDispositionChannelState(trackingId, entityId, 'approved');
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'retry_requested',
      actor,
      detail: { previousError: sub.lastError, previousAttempts: sub.attempts },
    });
    return { ok: true };
  }

  /** Channel states, receipts, and SLA clocks for a report (FR-6, FR-11). */
  async status(trackingId: string): Promise<ChannelStatus[]> {
    const [submissions, receipts] = await Promise.all([
      disseminationPersistence.getSubmissionsForReport(trackingId),
      disseminationPersistence.getReceiptsForReport(trackingId),
    ]);

    return submissions.map((sub) => ({
      entityId: sub.entityId,
      entityName: getEntity(sub.entityId)?.name ?? sub.entityId,
      tier: sub.tier,
      state: sub.state,
      attempts: sub.attempts,
      lastError: sub.lastError,
      dispatchedAt: sub.dispatchedAt,
      sla: sub.sla,
      handoff: sub.handoff,
      counsel: sub.counsel,
      receipts: receipts
        .filter((r) => r.submissionId === sub.submissionId)
        .map((r) => ({ type: r.type, value: r.value, receivedAt: r.receivedAt, note: r.note })),
    }));
  }

  /** Record a manually entered receipt against a channel. */
  async recordManualReceipt(
    trackingId: string,
    entityId: string,
    value: string,
    actor: string,
    kind: 'receipt' | 'ack' | 'feedback' = 'receipt',
    note?: string,
  ): Promise<{ ok: boolean; error?: string }> {
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return { ok: false, error: 'submission_not_found' };

    const adapter = getAdapter(entityId);
    const parsed = adapter?.parseReceipt(value) ?? null;
    const receipt = parsed ?? receiptTracker.buildManualReceipt(value, note);
    if (note && !receipt.note) receipt.note = note;

    await receiptTracker.recordReceipt(sub, receipt, actor, kind);
    return { ok: true };
  }
}

export const disseminationService = new DisseminationService();
