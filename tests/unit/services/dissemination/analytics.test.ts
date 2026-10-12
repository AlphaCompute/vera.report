/**
 * Outcome analytics (§13): funnel math, per-entity rows, median
 * time-to-ack, and the aggregate-only guarantee (no narratives or
 * identity fields in the output).
 */

import crypto from 'node:crypto';
import { computeAnalytics } from '../../../../src/services/dissemination/analytics';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import type { SubmissionDoc } from '../../../../src/services/dissemination/types';

function makeSubmission(overrides: Partial<SubmissionDoc>): SubmissionDoc {
  const now = new Date();
  return {
    submissionId: crypto.randomUUID(),
    trackingId: `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`,
    entityId: 'cisa',
    tier: 'A',
    idempotencyKey: crypto.randomUUID(),
    state: 'approved',
    packetVersion: 1,
    attempts: 0,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe('outcome analytics', () => {
  it('computes the funnel, per-entity rows, and median ack time', async () => {
    const dispatchedAt = new Date('2026-07-01T00:00:00Z');
    const seeds: SubmissionDoc[] = [
      makeSubmission({ state: 'approved' }),
      makeSubmission({
        state: 'dispatched',
        dispatchedAt,
        sla: { ackDueAt: null, feedbackDueAt: null, ackBreached: false, feedbackBreached: false },
      }),
      makeSubmission({
        state: 'acknowledged',
        dispatchedAt,
        sla: {
          ackDueAt: null,
          feedbackDueAt: null,
          ackReceivedAt: new Date(dispatchedAt.getTime() + 12 * 3_600_000),
          ackBreached: false,
          feedbackBreached: false,
        },
      }),
      makeSubmission({
        state: 'feedback_received',
        entityId: 'gao-fraudnet',
        dispatchedAt,
        sla: {
          ackDueAt: null,
          feedbackDueAt: null,
          ackReceivedAt: new Date(dispatchedAt.getTime() + 36 * 3_600_000),
          feedbackReceivedAt: new Date(dispatchedAt.getTime() + 200 * 3_600_000),
          ackBreached: false,
          feedbackBreached: false,
        },
      }),
      makeSubmission({ state: 'failed', entityId: 'gao-fraudnet', attempts: 5, lastError: 'boom' }),
      makeSubmission({
        state: 'dispatched',
        entityId: 'gao-fraudnet',
        dispatchedAt,
        sla: { ackDueAt: null, feedbackDueAt: null, ackBreached: true, feedbackBreached: false },
      }),
    ];
    for (const seed of seeds) {
      await disseminationPersistence.insertSubmission(seed);
    }

    const analytics = await computeAnalytics();

    expect(analytics.totalSubmissions).toBeGreaterThanOrEqual(6);
    expect(analytics.funnel.approved).toBe(analytics.totalSubmissions);
    expect(analytics.funnel.dispatched).toBeGreaterThanOrEqual(4);
    expect(analytics.funnel.acknowledged).toBeGreaterThanOrEqual(2);
    expect(analytics.funnel.feedback).toBeGreaterThanOrEqual(1);

    const cisa = analytics.entities.find((e) => e.entityId === 'cisa')!;
    expect(cisa.entityName).toBe('CISA Incident Reporting');
    expect(cisa.medianAckHours).toBe(12);

    const gao = analytics.entities.find((e) => e.entityId === 'gao-fraudnet')!;
    expect(gao.failed).toBeGreaterThanOrEqual(1);
    expect(gao.feedback).toBeGreaterThanOrEqual(1);
    expect(gao.ackSlaBreaches).toBeGreaterThanOrEqual(1);
    expect(gao.medianAckHours).toBe(36);

    // Aggregate-only: no narratives, tracking IDs, or identity fields leak.
    const json = JSON.stringify(analytics);
    expect(json).not.toContain('VRA-');
    expect(json).not.toContain('narrative');
    expect(json).not.toContain('nullifier');
  });
});
