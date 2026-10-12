const DAY = 86_400_000;
const WEEK = 7 * DAY;
export type SummaryPeriod = { start: number; end: number };
export type Delivery = 'delivered' | 'failed' | { retryAfterMs: number };
export type SummaryRecord = SummaryPeriod & {
  _id: string; state: 'pending' | 'sending' | 'sent' | 'failed'; attempts: number;
  nextAttemptAt: number; leaseId?: string; total?: number; sentAt?: number;
};
export type ClaimedSummary = SummaryRecord & { leaseId: string };

/** Monday 09:00 UTC; a late start catches up only the current week's dispatch.
 * The counted period is the previous Monday 00:00 through this Monday 00:00. */
export function weeklySubmissionPeriod(now: number): SummaryPeriod | null {
  if (!Number.isSafeInteger(now) || now < 0 || now > 8_640_000_000_000_000) return null;
  const date = new Date(now);
  const monday = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) -
    ((date.getUTCDay() + 6) % 7) * DAY;
  if (now < monday + 9 * 3_600_000) return null;
  return { start: monday - WEEK, end: monday };
}

function validWebhook(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname === 'hooks.slack.com' && !url.port &&
      !url.username && !url.password && !url.search && !url.hash &&
      /^\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(url.pathname);
  } catch { return false; }
}

export function weeklySubmissionSummaryConfigurationError(env: NodeJS.ProcessEnv): string | undefined {
  if (env.WEEKLY_SUBMISSION_SUMMARY_ENABLED !== 'true') return;
  // This rollout is staging-only, even when production receives the same image.
  if (env.DEPLOY_ENV !== 'staging') return 'Weekly submission summaries are staging-only';
  if (!validWebhook(env.SLACK_WEEKLY_SUMMARY_WEBHOOK_URL?.trim() || '')) {
    return 'SLACK_WEEKLY_SUMMARY_WEBHOOK_URL must be a Slack HTTPS incoming webhook';
  }
}

/** The Incoming Webhook is bound to tech-vera-incoming-reports by its installer.
 * Never pass records, IDs, individual timestamps or decrypted content to Slack. */
export async function sendWeeklySubmissionSummary(webhook: string, period: SummaryPeriod, total: number): Promise<Delivery> {
  if (!validWebhook(webhook) || !Number.isSafeInteger(total) || total < 0 ||
      !Number.isSafeInteger(period.start) || !Number.isSafeInteger(period.end) || period.start < 0 ||
      period.end - period.start !== WEEK || period.end > 8_640_000_000_000_000) return 'failed';
  const range = `${new Date(period.start).toISOString().slice(0, 10)} – ${new Date(period.end - DAY).toISOString().slice(0, 10)} (UTC)`;
  const text = `[VERA staging] Weekly submission summary\n${range}\nTotal submissions: ${total}`;
  try {
    const response = await fetch(webhook, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, blocks: [{ type: 'section', text: { type: 'plain_text', text } }],
        unfurl_links: false, unfurl_media: false }),
    });
    if (response.status === 429) {
      const header = response.headers.get('retry-after') || '';
      const seconds = /^\d+$/.test(header) ? Number(header) : NaN;
      await response.body?.cancel();
      return { retryAfterMs: Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 86_400 ? seconds * 1000 : 60_000 };
    }
    if (response.status !== 200) { await response.body?.cancel(); return 'failed'; }
    return (await response.text()).trim() === 'ok' ? 'delivered' : 'failed';
  } catch { return 'failed'; }
}

/** Aggregate-only boundary supplied by the confidential store. */
export interface WeeklySubmissionSummaryStorage {
  initialize(): Promise<unknown>;
  claim(period: SummaryPeriod, now: number): Promise<ClaimedSummary | null>;
  count(period: SummaryPeriod): Promise<number>;
  saveTotal(claim: ClaimedSummary, total: number, now: number): Promise<boolean>;
  finish(claim: ClaimedSummary, result: Delivery, now: number): Promise<void>;
}

/** One durable job per week across replicas/restarts. Incoming Webhooks are
 * at-least-once: a crash after Slack accepts can still duplicate a message. */
export class WeeklySubmissionSummaryWorker {
  private timer?: NodeJS.Timeout;
  private running?: Promise<void>;
  private stopping = false;
  private deliveredWeek?: number;
  constructor(private readonly store: WeeklySubmissionSummaryStorage, private readonly env: NodeJS.ProcessEnv,
    private readonly send = sendWeeklySubmissionSummary, private readonly now = Date.now) {}
  start(): void {
    if (this.timer || this.env.WEEKLY_SUBMISSION_SUMMARY_ENABLED !== 'true') return;
    const error = weeklySubmissionSummaryConfigurationError(this.env);
    if (error) { console.warn(`[WEEKLY_SUBMISSION_SUMMARY] ${error}`); return; }
    this.stopping = false;
    this.timer = setInterval(() => { void this.tick(); }, 60_000);
    this.timer.unref();
    void this.tick();
  }
  async close(): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }
  tick(): Promise<void> {
    if (this.running) return this.running;
    if (this.stopping || this.env.WEEKLY_SUBMISSION_SUMMARY_ENABLED !== 'true' ||
        weeklySubmissionSummaryConfigurationError(this.env)) return Promise.resolve();
    const period = weeklySubmissionPeriod(this.now());
    if (!period || period.start === this.deliveredWeek) return Promise.resolve();
    this.running = this.run(period).catch(() => {
      // Never log a webhook URL, database error, count, or report data.
      console.warn('[WEEKLY_SUBMISSION_SUMMARY] Unavailable; will retry');
    }).finally(() => { this.running = undefined; });
    return this.running;
  }
  private async run(period: SummaryPeriod): Promise<void> {
    await this.store.initialize();
    if (this.stopping) return;
    const claim = await this.store.claim(period, this.now());
    if (!claim) return;
    let result: Delivery = 'failed';
    try {
      const total = claim.total ?? await this.store.count(period);
      if (this.stopping || !Number.isSafeInteger(total) || total < 0 ||
          !await this.store.saveTotal(claim, total, this.now())) return;
      result = await this.send(this.env.SLACK_WEEKLY_SUMMARY_WEBHOOK_URL!.trim(), period, total);
    } finally {
      await this.store.finish(claim, result, this.now());
    }
    if (result === 'delivered') {
      this.deliveredWeek = period.start;
      console.info('[WEEKLY_SUBMISSION_SUMMARY] Delivered');
    } else console.warn('[WEEKLY_SUBMISSION_SUMMARY] Delivery deferred or retry limit reached');
  }
}
