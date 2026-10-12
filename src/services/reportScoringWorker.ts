import { reportPersistenceService } from './reportPersistence';
import { decryptReportNarrative } from './reportNarrative';
import { verifyReport } from './reportScoring';
import { isShroudConfigured } from './shroudClient';
import { logger } from '../utils/logger';

/** Scoring is repeatable; external filings and chain transactions never run here. */
export class ReportScoringWorker {
  private running?: Promise<void>;
  private timer?: NodeJS.Timeout;
  private stopping = false;
  private active?: AbortController;
  constructor(private readonly verify = verifyReport, private readonly now = () => new Date(),
    private readonly configured = isShroudConfigured) {}
  start() {
    if (this.timer) return;
    this.stopping = false;
    this.timer = setInterval(() => { void this.tick().catch(() => logger.error('[SCORING_QUEUE] Unavailable; durable work retained')); }, 15_000);
    this.timer.unref();
  }
  async close() {
    this.stopping = true;
    this.active?.abort(new Error('Scoring worker stopped'));
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => {});
  }
  tick(trackingId?: string): Promise<void> {
    if (this.running) return this.running;
    if (this.stopping) return Promise.resolve();
    // Disabled inference must not claim work, decrypt narratives, or spend the
    // provider retry budget. Existing failed records remain untouched.
    if (!this.configured()) return Promise.resolve();
    const controller = new AbortController();
    this.active = controller;
    this.running = this.run(trackingId, controller.signal).finally(() => {
      this.running = undefined;
      this.active = undefined;
    });
    return this.running;
  }
  private async run(trackingId: string | undefined, signal: AbortSignal) {
    for (let n = 0; n < (trackingId ? 1 : 5) && !this.stopping && !signal.aborted; n++) {
      if (!this.configured()) return;
      const record = await reportPersistenceService.claimScoring(this.now(), trackingId);
      if (!record) return;
      const job = record.scoringJob!;
      try {
        signal.throwIfAborted();
        if (job.attempts > 5) {
          await reportPersistenceService.finishScoring(record, { processingStatus: 'failed', scoringJob: { state: 'failed', attempts: job.attempts, nextAttemptAt: this.now(), lastError: 'retry_limit' } });
          continue;
        }
        // A decryption error must never become an empty narrative or fabricated score.
        const description = await decryptReportNarrative(record, signal);
        signal.throwIfAborted();
        const files = await reportPersistenceService.listEvidenceByTrackingIds([record.trackingId]);
        signal.throwIfAborted();
        const result = await this.verify({ description: description || '', evidenceType: record.category || record.categories?.[0] || 'other', hasEvidence: files.length > 0 }, signal);
        signal.throwIfAborted();
        await reportPersistenceService.finishScoring(record, {
          processingStatus: 'completed',
          scoringJob: { state: 'completed', attempts: job.attempts, nextAttemptAt: this.now() },
          verification: {
            isLegitimate: result.isLegitimate, credibilityScore: result.credibilityScore,
            category: result.category, organizationType: result.organizationType,
            namedOrganization: result.namedOrganization ?? undefined, spamIndicators: result.spamIndicators,
            contentAnalysis: result.contentAnalysis, riskLevel: result.riskLevel,
          },
        });
      } catch {
        const interrupted = signal.aborted;
        const failed = !interrupted && job.attempts >= 5;
        await reportPersistenceService.finishScoring(record, {
          processingStatus: failed ? 'failed' : 'processing',
          scoringJob: { state: failed ? 'failed' : 'pending', attempts: interrupted ? Math.max(0, job.attempts - 1) : job.attempts,
            nextAttemptAt: interrupted ? this.now() : new Date(this.now().getTime() + 30_000 * 2 ** job.attempts),
            lastError: interrupted ? 'worker_stopped' : 'scoring_unavailable' },
        });
      }
    }
  }
}
export const reportScoringWorker = new ReportScoringWorker();
