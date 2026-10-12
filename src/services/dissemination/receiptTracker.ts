import { logger } from '../../utils/logger';
/**
 * Receipt tracking and SLA timers (VERA-PDR-001 FR-6, §7.1, §8).
 *
 * Records a receipt for every outbound submission and tracks
 * acknowledgment SLAs modeled on the EU Whistleblowing Directive:
 * 7-day acknowledgment, 3-month feedback. Entities with no ack
 * expectation (per-entity SLA profile, PDR §14) get a follow-up task
 * instead of a breach alert.
 */

import crypto from 'node:crypto';
import { disseminationPersistence } from './disseminationPersistence';
import { getEntity } from './taxonomy';
import type { Receipt, SlaState, SubmissionDoc } from './types';

export const ACK_SLA_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const FEEDBACK_SLA_MS = 90 * 24 * 60 * 60 * 1000; // 3 months

class ReceiptTracker {
  /** Build the initial SLA state at dispatch time. */
  initialSla(entityId: string, dispatchedAt: Date): SlaState {
    const entity = getEntity(entityId);
    // Feedback expectation defaults to the ack expectation: an entity that
    // never acknowledges won't send substantive feedback either, so it gets
    // no feedback clock and raises no breach alert (PDR §14 alert fatigue).
    const feedbackExpected = entity?.feedbackExpected ?? entity?.ackExpected ?? false;
    return {
      ackDueAt: entity?.ackExpected ? new Date(dispatchedAt.getTime() + ACK_SLA_MS) : null,
      feedbackDueAt: feedbackExpected ? new Date(dispatchedAt.getTime() + FEEDBACK_SLA_MS) : null,
      ackBreached: false,
      feedbackBreached: false,
    };
  }

  /**
   * Record a receipt against a submission and advance its channel state.
   * kind 'ack' also stops the acknowledgment SLA clock; 'feedback' stops
   * the feedback clock.
   */
  async recordReceipt(
    submission: SubmissionDoc,
    receipt: Receipt,
    actor: string,
    kind: 'receipt' | 'ack' | 'feedback' = 'receipt',
    idempotencyKey?: string,
  ): Promise<void> {
    await disseminationPersistence.insertReceipt({
      submissionId: submission.submissionId,
      trackingId: submission.trackingId,
      entityId: submission.entityId,
      type: receipt.type,
      value: receipt.value,
      note: receipt.note,
      receivedAt: receipt.receivedAt,
      createdAt: new Date(),
    }, idempotencyKey);

    const nextState = kind === 'feedback' ? 'feedback_received' : kind === 'ack' ? 'acknowledged' : 'receipted';
    await disseminationPersistence.advanceReceiptSubmission(submission.submissionId, nextState, new Date());
    await disseminationPersistence.advanceReceiptChannel(submission.trackingId, submission.entityId, nextState);
    await disseminationPersistence.appendAudit({
      trackingId: submission.trackingId,
      entityId: submission.entityId,
      event: `receipt_${kind}`,
      actor,
      detail: { receiptType: receipt.type, receiptValue: receipt.value },
    }, idempotencyKey);

    logger.info(
      `✅ [DISSEMINATION:${submission.entityId}] Receipt (${receipt.type}) recorded for ${submission.trackingId}`,
    );
  }

  /**
   * SLA sweep, run from the dispatch worker tick. Flags newly breached
   * clocks, appends audit events, and alerts admins once per breach.
   *
   * Every API task runs this sweep (#1043). Each clock flips through a
   * compare-and-set, so only the task that wins a transition records it; the
   * audit event also carries a deterministic idempotency key per won clock.
   */
  async checkSlas(): Promise<void> {
    const now = new Date();
    const open = await disseminationPersistence.getSubmissionsWithOpenSla();

    for (const sub of open) {
      const sla = sub.sla;
      if (!sla) continue;

      const clocks: Array<'ack' | 'feedback'> = [];
      if (sla.ackDueAt && !sla.ackReceivedAt && !sla.ackBreached && now > new Date(sla.ackDueAt)) {
        clocks.push('ack');
      }
      if (
        sla.feedbackDueAt &&
        !sla.feedbackReceivedAt &&
        !sla.feedbackBreached &&
        now > new Date(sla.feedbackDueAt)
      ) {
        clocks.push('feedback');
      }

      const won: Array<'ack' | 'feedback'> = [];
      for (const clock of clocks) {
        if (await disseminationPersistence.markSlaBreached(sub.submissionId, clock, now)) won.push(clock);
      }
      if (won.length === 0) continue;
      const breaches = won.map((clock) => (clock === 'ack' ? '7-day acknowledgment' : '3-month feedback'));

      await disseminationPersistence.appendAudit({
        trackingId: sub.trackingId,
        entityId: sub.entityId,
        event: 'sla_breached',
        actor: 'system',
        detail: { breaches },
      }, `sla_breached:${sub.submissionId}:${won.join('+')}`);

      logger.warn(
        `⚠️ [DISSEMINATION:${sub.entityId}] SLA breach for ${sub.trackingId}: ${breaches.join(', ')}`,
      );

      // Fire-and-forget admin alert; never throws.
      import('../emailNotification')
        .then(({ emailNotificationService }) =>
          emailNotificationService.sendAlert(
            'error_threshold',
            'Dissemination SLA breach',
            `<p>A dissemination deadline was breached: ${breaches.join(', ')}.</p>` +
              '<p>Sign in to the admin dashboard to review dissemination alerts.</p>',
          ),
        )
        .catch(() => {});
    }
  }

  buildManualReceipt(value: string, note?: string): Receipt {
    return {
      type: 'manual',
      value: value || crypto.randomUUID(),
      note,
      receivedAt: new Date(),
    };
  }
}

export const receiptTracker = new ReceiptTracker();
