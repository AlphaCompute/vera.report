import { logger } from '../utils/logger';
import { randomUUID } from 'node:crypto';
import { MongoClient, type Collection } from 'mongodb';
import { notifySubmission as sendWebhook, submissionNotificationsEnabled, submissionNotificationConfigurationError, type SubmissionSource, type WebhookResult } from './submissionWebhook';
import type { ReportRecord } from './reportPersistence';

/** At-least-once: a crash after receiver acceptance can duplicate a notification.
 * Intent is stored in the report acceptance write. No historical backfill.
 */
export class SubmissionNotificationWorker {
  private client?: MongoClient;
  private reports?: Collection<ReportRecord>;
  private running?: Promise<void>;
  private timer?: NodeJS.Timeout;
  private stopping = false;
  private pausedUntil = 0;
  constructor(private readonly send = sendWebhook, private readonly now = () => new Date()) {}
  start() {
    if (this.timer) return;
    this.stopping = false;
    this.timer = setInterval(() => { void this.tick().catch(() => logger.error('[SUBMISSION_QUEUE] Unavailable; intents retained')); }, 30_000);
    this.timer.unref();
  }
  async close() {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => {});
    await this.client?.close(); this.client = undefined; this.reports = undefined;
  }
  tick(trackingId?: string): Promise<void> {
    if (trackingId !== undefined && (typeof trackingId !== 'string' || !trackingId.trim())) {
      return Promise.reject(new Error('invalid_tracking_id'));
    }
    if (this.running) return this.running;
    if (this.stopping) return Promise.resolve();
    if (!submissionNotificationsEnabled() || submissionNotificationConfigurationError() || this.now().getTime() < this.pausedUntil) return Promise.resolve();
    this.running = this.run(trackingId).finally(() => { this.running = undefined; });
    return this.running;
  }
  private async collection() {
    if (this.reports) return this.reports;
    if (!process.env.MONGODB_URI) throw new Error('notification_database_unconfigured');
    const client = new MongoClient(process.env.MONGODB_URI, { readPreference: 'primary', serverSelectionTimeoutMS: 5000,
      writeConcern: { w: 'majority', j: true },
      ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}) });
    try {
      await client.connect();
      const reports = client.db(process.env.MONGODB_DB_NAME || 'vera').collection<ReportRecord>('whistleblower_reports');
      await reports.createIndex({ 'submissionNotification.state': 1, 'submissionNotification.nextAttemptAt': 1 });
      this.client = client; this.reports = reports; return reports;
    } catch (error) { await client.close(); throw error; }
  }
  private async run(trackingId?: string) {
    const reports = await this.collection();
    const due = { ...(trackingId ? { trackingId: { $eq: trackingId } } : {}), 'submissionNotification.state': { $in: ['pending', 'sending'] }, 'submissionNotification.nextAttemptAt': { $lte: this.now() } };
    const expired = await reports.updateMany({ ...due, 'submissionNotification.attempts': { $gte: 5 } }, {
      $set: { 'submissionNotification.state': 'failed' }, $unset: { 'submissionNotification.leaseId': '' } });
    if (expired.modifiedCount) logger.error('[SUBMISSION_QUEUE] Retry limit reached; inspect failed notification state');
    for (let i = 0; i < (trackingId ? 1 : 10) && !this.stopping; i++) {
      const lease = randomUUID();
      const record = await reports.findOneAndUpdate({ ...due, 'submissionNotification.attempts': { $lt: 5 } }, {
        $set: { 'submissionNotification.state': 'sending', 'submissionNotification.leaseId': lease, 'submissionNotification.nextAttemptAt': new Date(this.now().getTime() + 60_000) },
        $inc: { 'submissionNotification.attempts': 1 },
      }, { returnDocument: 'after', projection: { trackingId: 1, createdAt: 1, submissionNotification: 1 } });
      if (!record) return;
      const state = record.submissionNotification!;
      let result: WebhookResult = 'failed';
      try { result = await this.send(record.trackingId, record.createdAt, state.source); } catch {}
      const rateLimited = typeof result === 'object' && result.status === 'rate_limited' ? result : undefined;
      const delay = Math.max(60_000 * 2 ** (state.attempts - 1), rateLimited?.retryAfterMs || 0);
      if (rateLimited) this.pausedUntil = this.now().getTime() + delay;
      await reports.updateOne({ trackingId: { $eq: record.trackingId }, 'submissionNotification.leaseId': lease }, {
        $set: result === 'delivered' ? { 'submissionNotification.state': 'sent', 'submissionNotification.sentAt': this.now() } : {
          'submissionNotification.state': !rateLimited && state.attempts >= 5 ? 'failed' : 'pending',
          'submissionNotification.nextAttemptAt': new Date(this.now().getTime() + delay),
        },
        // A 429 rejects delivery without accepting a message. Preserve retries.
        ...(rateLimited ? { $inc: { 'submissionNotification.attempts': -1 } } : {}),
        $unset: { 'submissionNotification.leaseId': '' },
      });
      if (rateLimited) return;
      if (result !== 'delivered') logger.error('[SUBMISSION_QUEUE] Delivery failed; inspect notification state');
    }
  }
}
export const submissionNotificationWorker = new SubmissionNotificationWorker();
/** Immediate delivery hint uses the same atomic claim as the periodic worker. */
export async function notifySubmission(trackingId: string, _createdAt: Date, _source: SubmissionSource): Promise<void> {
  await submissionNotificationWorker.tick(trackingId).catch(() => logger.error('[SUBMISSION_QUEUE] Unavailable; intent retained'));
}
