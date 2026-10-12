import { recipientCaseReference } from './recipientCapability';
import { logger } from '../../utils/logger';
import { reviewedNarrativeMatches } from './narrativeReview';
import { packetSubmitterFor, submitterDisclosureUnchanged } from '../submitterDisclosure';
/**
 * Dispatch worker (VERA-PDR-001 §7.1 dispatchQueue, adapted).
 *
 * Mongo-backed dispatch queue with an in-process interval worker (the
 * timer-driven worker pattern — the repo has no SQS infrastructure). Each
 * tick:
 *   1. claims due submissions (state approved/deferred, nextAttemptAt due),
 *   2. generates the packet, runs the entity adapter's prepare + dispatch,
 *   3. applies exponential backoff on failure, dead-letters after max
 *      attempts (NFR-3: retried, never silently dropped),
 *   4. sweeps SLA clocks.
 *
 * Per-adapter circuit breakers isolate failures; a breaker denial defers
 * the channel without consuming an attempt. No channel's state appears in
 * the guard condition of any other channel's transition (FR-9/§13).
 */

import { disseminationPersistence } from './disseminationPersistence';
import { disseminationService } from './disseminationService';
import { packetGenerator } from './packetGenerator';
import { receiptTracker } from './receiptTracker';
import { getAdapter } from './adapters/registry';
import { channelConsented } from './consentScope';
import { reportPersistenceService } from '../reportPersistence';
import { disseminationMode } from './adapters/emailAdapter';
import { DispatchNotSentError, type SubmissionDoc } from './types';

const MAX_ATTEMPTS = 5;
const BASE_BACKOFF_MS = 60 * 1000; // 1 min, doubles per attempt
const MAX_BACKOFF_MS = 6 * 60 * 60 * 1000; // 6 hours
const BREAKER_DEFER_MS = 5 * 60 * 1000; // recheck a tripped breaker after 5 min
const MAX_CLAIMS_PER_TICK = 10;

export function backoffDelayMs(attempts: number): number {
  return Math.min(BASE_BACKOFF_MS * Math.pow(2, attempts), MAX_BACKOFF_MS);
}

class DispatchClaimLostError extends Error {}

export class DispatchWorker {
  private timer: NodeJS.Timeout | null = null;
  private running?: Promise<void>;
  private stopping = false;

  start(intervalMs = 30 * 1000): void {
    if (this.timer) return;
    this.stopping = false;
    logger.info(`[DISSEMINATION] Dispatch worker started (interval ${intervalMs / 1000}s)`);
    this.timer = setInterval(() => {
      this.tick().catch((err) => {
        logger.error('[DISSEMINATION] Worker tick failed:', err instanceof Error ? err.message : err);
      });
    }, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async close(): Promise<void> {
    this.stopping = true;
    this.stop();
    await this.running;
  }

  /** One queue pass, also used by the approve route's fast path. */
  tick(): Promise<void> {
    if (this.running) return Promise.resolve();
    if (this.stopping) return Promise.resolve();
    this.running = this.run().finally(() => { this.running = undefined; });
    return this.running;
  }

  private async run(): Promise<void> {
    const now = new Date();
    for (let i = 0; i < MAX_CLAIMS_PER_TICK && !this.stopping; i++) {
      const claimed = await disseminationPersistence.claimNextDueSubmission(now);
      if (!claimed) break;
      await this.processSubmission(claimed);
    }
    if (!this.stopping) await receiptTracker.checkSlas();
  }

  private async authorizedNow(sub: SubmissionDoc, packetSource?: NonNullable<Awaited<ReturnType<typeof disseminationService.buildView>>>): Promise<boolean> {
    const loaded = await disseminationService.buildView(sub.trackingId);
    const disposition = await disseminationPersistence.getDisposition(sub.trackingId);
    const consent = loaded && disseminationService.consentFromReport(loaded.report);
    const permitted = (c: typeof consent) => channelConsented(c, sub.entityId);
    const channel = disposition?.channels.find(c => c.entityId === sub.entityId);
    const active = channel && !['withdrawn', 'failed', 'closed', 'suppressed'].includes(channel.state);
    const reviewed = loaded && reviewedNarrativeMatches(loaded.view, disposition);
    if (loaded && loaded.narrativeReadable && !['dismissed', 'rejected'].includes(loaded.report.status) &&
        active && permitted(consent) && permitted(disposition?.consentSnapshot ?? null) &&
        (disseminationMode() !== 'live' || reviewed) &&
        (!packetSource || (submitterDisclosureUnchanged(packetSource.report, loaded.report) &&
          packetSource.view.narrative === loaded.view.narrative))) return true;
    if (loaded && !permitted(consent)) {
      await this.withdrawUnconsented(sub);
      return false;
    }
    await this.updateUnsentClaim(sub, {
      state: 'deferred', lastError: 'sharing_authorization_changed', nextAttemptAt: new Date(Date.now() + BREAKER_DEFER_MS),
    });
    await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'deferred', ['approved', 'deferred', 'packet_ready']);
    return false;
  }

  /**
   * Consent that is absent now cannot return by waiting (#926): withdraw the
   * channel instead of deferring it forever. The withdrawn write is the fence
   * that stops dispatch; the bookkeeping after it is idempotent and never turns
   * into a retry. Re-approval is refused unless consent covers the channel.
   */
  private async withdrawUnconsented(sub: SubmissionDoc): Promise<void> {
    await this.updateUnsentClaim(sub, { state: 'withdrawn', lastError: 'reporter_consent_missing', nextAttemptAt: undefined });
    // A consent-reading regression would withdraw queued channels en masse; make it loud.
    logger.warn(`[DISSEMINATION:${sub.entityId}] Withdrew ${sub.trackingId}: reporter consent does not cover this channel`);
    // Each step runs even if an earlier one fails: the packet must be released
    // whether or not the disposition or audit write succeeded.
    const step = async (label: string, run: () => Promise<unknown>) => {
      try { await run(); } catch (err: unknown) {
        logger.error(`[DISSEMINATION:${sub.entityId}] Withdrawal ${label} incomplete for ${sub.trackingId}: ${err instanceof Error ? err.message : String(err)}`);
      }
    };
    await step('disposition', () => disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'withdrawn'));
    await step('audit', () => disseminationPersistence.appendAudit({
      trackingId: sub.trackingId, entityId: sub.entityId, event: 'channel_withdrawn', actor: 'system',
      detail: { reason: 'reporter_consent_missing' },
    }, `consent-withdrawal:${sub.submissionId}`));
    // Release the packet recorded now, not a CID from before this claim's update.
    await step('packet release', async () =>
      disseminationService.releasePacket(await disseminationPersistence.getSubmission(sub.submissionId) ?? sub, 'system'));
    // Admins see every automatic withdrawal: it is rare by design, and a burst
    // is the signal that consent is being misread. No report details are sent.
    import('../emailNotification')
      .then(({ emailNotificationService }) =>
        emailNotificationService.sendAlert(
          'error_threshold',
          'Dissemination channel withdrawn automatically',
          '<p>An approved dissemination channel was withdrawn because the reporter\'s consent does not cover it.</p>' +
            '<p>Sign in to the admin dashboard and review the report\'s audit trail.</p>',
        ),
      )
      .catch(() => {});
  }

  /**
   * Withdraw before any gate that would otherwise defer an unconsented row
   * forever. Best effort: if the report cannot be read (storage outage), fall
   * through to the normal breaker/backoff path, where authorizedNow rechecks
   * consent inside the worker's error handling.
   */
  private async withdrawnForMissingConsent(sub: SubmissionDoc): Promise<boolean> {
    let report;
    try { report = await reportPersistenceService.get(sub.trackingId); } catch { return false; }
    if (!report || channelConsented(report.consent, sub.entityId)) return false;
    await this.withdrawUnconsented(sub);
    return true;
  }

  private async processSubmission(sub: SubmissionDoc): Promise<void> {
    const tag = `[DISSEMINATION:${sub.entityId}]`;

    const adapter = getAdapter(sub.entityId);
    if (!adapter) {
      // Registry drift — a submission exists for an entity with no adapter.
      await this.deadLetter(sub, 'no adapter registered for entity');
      return;
    }

    // Crash-safety guard against duplicate agency filing: a reclaimed row that
    // still carries dispatchInFlightAt means a prior attempt already reached the
    // external send but crashed before recording the outcome (the send may have
    // succeeded). Re-sending would double-file with the agency, so stop and
    // surface it for a human to reconcile against the agency's receipt rather
    // than blindly retrying.
    if (sub.dispatchInFlightAt) {
      logger.warn(`⚠️ ${tag} Dispatch outcome unknown for ${sub.trackingId} (send interrupted mid-flight) — flagging for review, NOT re-sending`);
      await this.patchClaim(sub, {
        state: 'failed',
        lastError: 'dispatch_uncertain_after_interruption',
        nextAttemptAt: undefined,
      });
      await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'failed');
      await disseminationPersistence.appendAudit({
        trackingId: sub.trackingId,
        entityId: sub.entityId,
        event: 'dispatch_uncertain',
        actor: 'system',
        detail: { detail: 'send was in-flight when the worker was interrupted; not auto-retried to avoid a duplicate agency filing' },
      });
      return;
    }

    if (await this.withdrawnForMissingConsent(sub)) return;

    // Circuit breaker admission check before doing any expensive work
    // (the fast-fail pattern from requireProofServerAdmission).
    if (!adapter.allowsDispatch()) {
      logger.warn(`${tag} Circuit denies admission — deferring ${sub.trackingId}`);
      await this.updateUnsentClaim(sub, {
        state: 'deferred',
        nextAttemptAt: new Date(Date.now() + BREAKER_DEFER_MS),
      });
      await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'deferred', ['approved', 'packet_ready', 'deferred']);
      return;
    }

    // H1: never dispatch an un-reviewed narrative to a real agency. In live
    // mode a channel waits until an admin froze a redacted narrative or
    // explicitly marked it reviewed (no redaction needed). Dryrun (internal
    // inbox) is intentionally not gated so QA can exercise dispatch; the email
    // adapter compensates by never sending dryrun report content in cleartext.
    if (disseminationMode() === 'live') {
      const disposition = await disseminationPersistence.getDisposition(sub.trackingId);
      const reviewed = !!(disposition?.narrativeOverride?.narrative || disposition?.narrativeReviewedAt);
      if (!reviewed) {
        await this.updateUnsentClaim(sub, {
          state: 'deferred',
          nextAttemptAt: new Date(Date.now() + BREAKER_DEFER_MS),
          lastError: 'awaiting_narrative_review',
        });
        await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'deferred', ['approved', 'packet_ready', 'deferred']);
        return;
      }
    }

    let dispatchStarted = false;
    let outcomePersisted = false;
    try {
      const loaded = await disseminationService.buildView(sub.trackingId);
      if (!loaded) {
        await this.deadLetter(sub, 'report not found');
        return;
      }

      if (!await this.authorizedNow(sub, loaded)) return;
      const packet = await packetGenerator.generate(loaded.view, sub.entityId, await packetSubmitterFor(loaded.report));
      if (packet.completeness && !packet.completeness.ok) {
        // Non-blocking internal heuristic, not validated recipient requirements.
        logger.warn(
          `[dispatch] packet for ${sub.entityId} internal checklist gaps (advisory only): ` +
            packet.completeness.missing.filter((m) => m.severity === 'required').map((m) => m.key).join(', '),
        );
      }
      if (!await this.updateUnsentClaim(sub, {
        caseReference: recipientCaseReference(sub.trackingId, sub.entityId),
        packetHash: packet.packetHash,
        packetCid: packet.packetCid,
        packetKey: packet.packetKey,
      })) return;

      const prepared = await adapter.prepare({ ...loaded.view, trackingId: recipientCaseReference(sub.trackingId, sub.entityId) }, packet);
      // Persist send-intent BEFORE the external call so a crash between here and
      // the outcome patch is caught on reclaim (guard above), rather than silently
      // re-sending. Cleared on success and on clean failure below.
      if (!await this.authorizedNow(sub, loaded)) return;
      if (!await disseminationPersistence.claimDispatch(sub.submissionId, sub.claimToken)) return;
      dispatchStarted = true;
      const result = await adapter.dispatch({ ...prepared, auditTrackingId: sub.trackingId });
      const now = new Date();

      if (result.outcome === 'handoff') {
        // Deep-link channels (Psst Stage-1): store the handoff payload for
        // the admin panel; state 'dispatched' with a manual-receipt SLA.
        await this.patchClaim(sub, {
          state: 'dispatched',
          dispatchedAt: now,
          dispatchInFlightAt: undefined,
          handoff: prepared.deepLink,
          attempts: sub.attempts + 1,
          nextAttemptAt: undefined,
          lastError: undefined,
          sla: receiptTracker.initialSla(sub.entityId, now),
        });
        outcomePersisted = true;
        await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'dispatched');
        await disseminationPersistence.appendAudit({
          trackingId: sub.trackingId,
          entityId: sub.entityId,
          event: 'handoff_prepared',
          actor: 'system',
          detail: { detail: result.detail },
        });
        logger.info(`✅ ${tag} Handoff prepared for ${sub.trackingId}`);
        return;
      }

      // outcome === 'sent'
      await this.patchClaim(sub, {
        state: 'dispatched',
        dispatchedAt: now,
        dispatchInFlightAt: undefined,
        attempts: sub.attempts + 1,
        nextAttemptAt: undefined,
        lastError: undefined,
        sla: receiptTracker.initialSla(sub.entityId, now),
      });
      outcomePersisted = true;
      await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'dispatched');
      await disseminationPersistence.appendAudit({
        trackingId: sub.trackingId,
        entityId: sub.entityId,
        event: 'dispatched',
        actor: 'system',
        detail: { detail: result.detail },
      });

      if (result.provisionalReceipt) {
        const fresh = await disseminationPersistence.getSubmission(sub.submissionId);
        if (fresh) {
          await receiptTracker.recordReceipt(
            fresh,
            { ...result.provisionalReceipt, receivedAt: now },
            'system',
          );
        }
      }

      logger.info(`✅ ${tag} Dispatched ${sub.trackingId}`);
    } catch (err: unknown) {
      if (err instanceof DispatchClaimLostError) return;
      const msg = err instanceof Error ? err.message : String(err);
      const attempts = sub.attempts + 1;
      // Post-send bookkeeping failures must never turn a delivered filing into a retry.
      if (outcomePersisted) throw err;
      if (dispatchStarted && !(err instanceof DispatchNotSentError)) {
        await this.deadLetter(sub, 'dispatch_uncertain_after_interruption', attempts);
        return;
      }

      if (attempts >= MAX_ATTEMPTS) {
        await this.patchClaim(sub, { dispatchInFlightAt: undefined });
        await this.deadLetter(sub, msg, attempts);
        return;
      }

      const delay = backoffDelayMs(attempts);
      logger.warn(`⚠️ ${tag} Dispatch failed for ${sub.trackingId} (attempt ${attempts}), retry in ${Math.round(delay / 1000)}s: ${msg}`);
      await this.patchClaim(sub, {
        state: 'deferred',
        attempts,
        nextAttemptAt: new Date(Date.now() + delay),
        lastError: msg,
        dispatchInFlightAt: undefined,
      });
      await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'deferred', ['approved', 'packet_ready', 'deferred']);
      await disseminationPersistence.appendAudit({
        trackingId: sub.trackingId,
        entityId: sub.entityId,
        event: 'dispatch_retry_scheduled',
        actor: 'system',
        detail: { attempts, error: msg },
      });
    }
  }

  private async updateUnsentClaim(sub: SubmissionDoc, updates: Partial<SubmissionDoc>): Promise<boolean> {
    if (!sub.claimToken) throw new DispatchClaimLostError('Missing dispatch claim');
    if (!await disseminationPersistence.updateUnsentSubmission(sub.submissionId, updates, false, sub.claimToken)) {
      throw new DispatchClaimLostError('Dispatch claim is no longer writable');
    }
    return true;
  }

  private async patchClaim(sub: SubmissionDoc, updates: Parameters<typeof disseminationPersistence.patchSubmission>[1]): Promise<void> {
    if (!sub.claimToken || !await disseminationPersistence.patchSubmission(sub.submissionId, updates, sub.claimToken)) {
      throw new DispatchClaimLostError('Dispatch claim was reclaimed');
    }
  }

  /** Dead-letter state: kept for admin action, alerted, never silently dropped. */
  private async deadLetter(sub: SubmissionDoc, reason: string, attempts = sub.attempts): Promise<void> {
    logger.error(`❌ [DISSEMINATION:${sub.entityId}] Dead-lettering ${sub.trackingId}: ${reason}`);
    await this.patchClaim(sub, {
      state: 'failed',
      attempts,
      lastError: reason,
      nextAttemptAt: undefined,
      // The outcome write may have committed before its acknowledgement was lost.
      // Restore the barrier atomically with failed state, even if that write cleared it.
      ...(reason === 'dispatch_uncertain_after_interruption' ? { dispatchInFlightAt: new Date() } : {}),
    });
    await disseminationPersistence.setDispositionChannelState(sub.trackingId, sub.entityId, 'failed');
    await disseminationPersistence.appendAudit({
      trackingId: sub.trackingId,
      entityId: sub.entityId,
      event: 'dead_lettered',
      actor: 'system',
      detail: { reason, attempts },
    });

    import('../emailNotification')
      .then(({ emailNotificationService }) =>
        emailNotificationService.sendAlert(
          'error_threshold',
          'Dissemination dispatch failed',
          '<p>A dissemination dispatch requires review.</p>' +
            '<p>Sign in to the admin dashboard to review dissemination alerts and retry or withdraw the channel.</p>',
        ),
      )
      .catch(() => {});
  }
}

export const dispatchWorker = new DispatchWorker();
