import { logger } from '../utils/logger';
import { randomUUID } from 'crypto';
import { MongoClient, type Collection } from 'mongodb';
import type { ReportRecord } from './reportPersistence';
import { emailNotificationService, type ReportAlertMetadata } from './emailNotification';

const MAX_ATTEMPTS = 5;
const LEASE_MS = 5 * 60_000;
type Sender = (metadata: ReportAlertMetadata) => Promise<{ sent: boolean; error?: string }>;

/** At-least-once delivery: a crash after SES accepts can produce a duplicate.
 * Intent lives in the report's acceptance write, so no second-write gap exists.
 * Old reports without intent are deliberately not backfilled or mass-emailed.
 */
export class ReportAlertWorker {
  private client?: MongoClient;
  private reports?: Collection<ReportRecord>;
  private timer?: NodeJS.Timeout;
  private running?: Promise<void>;
  private stopping = false;

  constructor(
    private readonly send: Sender = metadata => emailNotificationService.notifyNewReport('', '', metadata),
    private readonly now: () => Date = () => new Date(),
    private readonly configured: () => boolean = () =>
      ['SES_SENDER_EMAIL', 'AUTH0_DOMAIN', 'AUTH0_MGMT_CLIENT_ID', 'AUTH0_MGMT_CLIENT_SECRET']
        .every(name => !!process.env[name]?.trim()),
  ) {}

  private async collection(): Promise<Collection<ReportRecord>> {
    if (this.reports) return this.reports;
    const uri = process.env.MONGODB_URI?.trim();
    if (!uri) throw new Error('report_alert_database_unconfigured');
    const client = new MongoClient(uri, {
      readPreference: 'primary',
      ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}),
      serverSelectionTimeoutMS: 5000,
    });
    try {
      await client.connect();
      const reports = client.db(process.env.MONGODB_DB_NAME || 'vera').collection<ReportRecord>('whistleblower_reports');
      await reports.createIndex({ 'adminNotification.state': 1, 'adminNotification.nextAttemptAt': 1 });
      this.client = client;
      this.reports = reports;
      return reports;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  start(intervalMs = 30_000): void {
    if (this.timer) return;
    this.stopping = false;
    const run = () => { void this.tick().catch(() => logger.error('[REPORT_ALERT] Worker unavailable; durable intents retained')); };
    this.timer = setInterval(run, intervalMs);
    this.timer.unref();
    run();
  }

  async close(): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => {});
    await this.client?.close();
    this.client = undefined;
    this.reports = undefined;
  }

  tick(): Promise<void> {
    if (this.running) return this.running;
    if (this.stopping) return Promise.resolve();
    // Missing deployment configuration cannot consume retries or reclaim leases.
    // Enabling it later resumes existing intents, without historical backfill.
    if (!this.configured()) return Promise.resolve();
    this.running = this.run().finally(() => { this.running = undefined; });
    return this.running;
  }

  private async run(): Promise<void> {
    const reports = await this.collection();
    const exhausted = await reports.updateMany({
      'adminNotification.state': { $in: ['pending', 'sending'] },
      'adminNotification.nextAttemptAt': { $lte: this.now() },
      'adminNotification.attempts': { $gte: MAX_ATTEMPTS },
    }, { $set: { 'adminNotification.state': 'failed', 'adminNotification.lastError': 'attempts_exhausted' }, $unset: { 'adminNotification.leaseId': '' } });
    if (exhausted.modifiedCount) logger.error('[REPORT_ALERT] Delivery exhausted; inspect failed adminNotification records');

    for (let i = 0; i < 10 && !this.stopping; i++) {
      const leaseId = randomUUID();
      const record = await reports.findOneAndUpdate({
        'adminNotification.state': { $in: ['pending', 'sending'] },
        'adminNotification.nextAttemptAt': { $lte: this.now() },
        'adminNotification.attempts': { $lt: MAX_ATTEMPTS },
      }, {
        $set: { 'adminNotification.state': 'sending', 'adminNotification.leaseId': leaseId, 'adminNotification.nextAttemptAt': new Date(this.now().getTime() + LEASE_MS) },
        $inc: { 'adminNotification.attempts': 1 },
      }, { returnDocument: 'after', sort: { 'adminNotification.nextAttemptAt': 1 } });
      if (!record) return;
      let result: Awaited<ReturnType<Sender>>;
      try { result = await this.send({ acceptedAt: record.createdAt, reportType: record.category }); }
      catch { result = { sent: false, error: 'provider_failed' }; }
      const attempts = record.adminNotification!.attempts;
      const paused = !result.sent && ['ses_unconfigured', 'no_admin_recipients'].includes(result.error || '');
      const terminal = !paused && attempts >= MAX_ATTEMPTS;
      const safeError = ['ses_unconfigured', 'no_admin_recipients'].includes(result.error || '') ? result.error : 'provider_failed';
      await reports.updateOne({ trackingId: { $eq: record.trackingId }, 'adminNotification.leaseId': leaseId }, {
        $set: result.sent ? {
          'adminNotification.state': 'sent', 'adminNotification.sentAt': this.now(),
        } : {
          'adminNotification.state': terminal ? 'failed' : 'pending',
          'adminNotification.lastError': safeError,
          'adminNotification.nextAttemptAt': new Date(this.now().getTime() + (paused ? 60_000 : Math.min(60_000 * 2 ** (attempts - 1), 3_600_000))),
        },
        // These outcomes certify that SES was never called. Refund only our
        // still-owned claim; provider failures keep the bounded attempt count.
        ...(paused ? { $inc: { 'adminNotification.attempts': -1 } } : {}),
        $unset: { 'adminNotification.leaseId': '', ...(result.sent ? { 'adminNotification.lastError': '' } : {}) },
      });
      if (!result.sent) logger.error(terminal
        ? '[REPORT_ALERT] Delivery exhausted; inspect failed adminNotification records'
        : '[REPORT_ALERT] Delivery deferred; retry retained');
    }
  }
}

export const reportAlertWorker = new ReportAlertWorker();
