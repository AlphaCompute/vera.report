/**
 * Outcome analytics (VERA-PDR-001 §13): what actually happens after
 * dispatch. Aggregates the submissions collection into a funnel
 * (approved → dispatched → acknowledged → feedback) and per-entity
 * outcome rows (volumes, SLA breaches, median time-to-ack), for the
 * admin Insights tab. Aggregate-only: no narratives, no identities.
 */

import { disseminationPersistence } from './disseminationPersistence';
import { getEntity } from './taxonomy';
import type { SubmissionDoc } from './types';

export interface EntityOutcomeRow {
  entityId: string;
  entityName: string;
  tier: string;
  total: number;
  dispatched: number;
  acknowledged: number;
  feedback: number;
  failed: number;
  withdrawn: number;
  ackSlaBreaches: number;
  feedbackSlaBreaches: number;
  /** Median hours from dispatch to acknowledgment, when both known. */
  medianAckHours: number | null;
}

export interface DisseminationAnalytics {
  generatedAt: string;
  totalSubmissions: number;
  byState: Record<string, number>;
  funnel: {
    approved: number;
    dispatched: number;
    acknowledged: number;
    feedback: number;
  };
  entities: EntityOutcomeRow[];
}

const DISPATCHED_STATES = new Set(['dispatched', 'receipted', 'acknowledged', 'feedback_received', 'closed']);
const ACKED_STATES = new Set(['acknowledged', 'feedback_received', 'closed']);

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function reached(sub: SubmissionDoc, stateSet: Set<string>): boolean {
  return stateSet.has(sub.state);
}

export async function computeAnalytics(): Promise<DisseminationAnalytics> {
  const submissions = await disseminationPersistence.listSubmissions();

  const byState: Record<string, number> = {};
  const perEntity = new Map<string, SubmissionDoc[]>();
  for (const sub of submissions) {
    byState[sub.state] = (byState[sub.state] ?? 0) + 1;
    const list = perEntity.get(sub.entityId) ?? [];
    list.push(sub);
    perEntity.set(sub.entityId, list);
  }

  const entities: EntityOutcomeRow[] = [...perEntity.entries()]
    .map(([entityId, subs]) => {
      const ackHours = subs
        .filter((s) => s.dispatchedAt && s.sla?.ackReceivedAt)
        .map((s) => (s.sla!.ackReceivedAt!.getTime() - s.dispatchedAt!.getTime()) / 3_600_000)
        .filter((h) => h >= 0);
      const entity = getEntity(entityId);
      return {
        entityId,
        entityName: entity?.name ?? entityId,
        tier: entity?.tier ?? '?',
        total: subs.length,
        dispatched: subs.filter((s) => reached(s, DISPATCHED_STATES)).length,
        acknowledged: subs.filter((s) => reached(s, ACKED_STATES)).length,
        feedback: subs.filter((s) => ['feedback_received', 'closed'].includes(s.state)).length,
        failed: subs.filter((s) => s.state === 'failed').length,
        withdrawn: subs.filter((s) => s.state === 'withdrawn').length,
        ackSlaBreaches: subs.filter((s) => s.sla?.ackBreached).length,
        feedbackSlaBreaches: subs.filter((s) => s.sla?.feedbackBreached).length,
        medianAckHours: median(ackHours),
      };
    })
    .sort((a, b) => b.total - a.total);

  return {
    generatedAt: new Date().toISOString(),
    totalSubmissions: submissions.length,
    byState,
    funnel: {
      approved: submissions.length,
      dispatched: submissions.filter((s) => reached(s, DISPATCHED_STATES)).length,
      acknowledged: submissions.filter((s) => reached(s, ACKED_STATES)).length,
      feedback: submissions.filter((s) => ['feedback_received', 'closed'].includes(s.state)).length,
    },
    entities,
  };
}
