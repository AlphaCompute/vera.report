import { logger } from '../utils/logger';
import { randomUUID } from 'crypto';
import { MongoClient, type Collection } from 'mongodb';
import type { AdminAuditEntry } from './adminAuditLog';
import { emailNotificationService } from './emailNotification';

const MAX_ATTEMPTS = 5;
const LEASE_MS = 5 * 60_000;
type Sender = (metadata: AdminAuditEntry) => Promise<{ sent: boolean; error?: string }>;

/** Intent is inserted atomically with the audit event; historical entries are not backfilled.
 * Abandoned or ambiguous sends are quarantined, never automatically sent twice.
 */
export class CriticalAdminAlertWorker {
  private client?: MongoClient;
  private entries?: Collection<AdminAuditEntry>;
  private timer?: NodeJS.Timeout;
  private running?: Promise<void>;
  private stopping = false;

  constructor(
    private readonly send: Sender = () => emailNotificationService.notifyCriticalAdminAction(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  private async collection(): Promise<Collection<AdminAuditEntry>> {
    if (this.entries) return this.entries;
    const uri = process.env.MONGODB_URI?.trim();
    if (!uri) throw new Error('critical_alert_database_unconfigured');
    const client = new MongoClient(uri, {
      readPreference: 'primary',
      writeConcern: { w: 'majority', j: true },
      ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}),
      serverSelectionTimeoutMS: 5000,
    });
    try {
      await client.connect();
      const entries = client.db(process.env.MONGODB_DB_NAME || 'vera').collection<AdminAuditEntry>('admin_audit_logs');
      await entries.createIndex({ 'criticalNotification.state': 1, 'criticalNotification.nextAttemptAt': 1 });
      this.client = client;
      this.entries = entries;
      return entries;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  start(intervalMs = 30_000): void {
    if (this.timer) return;
    this.stopping = false;
    const run = () => { void this.tick().catch(() => logger.error('[CRITICAL_ADMIN_ALERT] Worker unavailable; durable intents retained')); };
    this.timer = setInterval(run, intervalMs);
    this.timer.unref();
    run();
  }

  async close(): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    try { await this.running; } finally {
      await this.client?.close();
      this.client = undefined;
      this.entries = undefined;
    }
  }

  tick(): Promise<void> {
    if (this.running) return this.running;
    if (this.stopping) return Promise.resolve();
    this.running = this.run().finally(() => { this.running = undefined; });
    return this.running;
  }

  private async run(): Promise<void> {
    const entries = await this.collection();
    const abandoned = await entries.updateMany({
      'criticalNotification.state': 'sending',
      'criticalNotification.nextAttemptAt': { $lte: this.now() },
    }, { $set: { 'criticalNotification.state': 'uncertain', 'criticalNotification.lastError': 'send_interrupted' } });
    if (!abandoned.acknowledged) throw new Error('Critical alert recovery was not acknowledged');

    for (let i = 0; i < 10 && !this.stopping; i++) {
      const leaseId = randomUUID();
      const record = await entries.findOneAndUpdate({
        'criticalNotification.state': 'pending',
        'criticalNotification.nextAttemptAt': { $lte: this.now() },
        'criticalNotification.attempts': { $lt: MAX_ATTEMPTS },
      }, {
        $set: { 'criticalNotification.state': 'sending', 'criticalNotification.leaseId': leaseId, 'criticalNotification.nextAttemptAt': new Date(this.now().getTime() + LEASE_MS) },
        $inc: { 'criticalNotification.attempts': 1 },
      }, { returnDocument: 'after', sort: { 'criticalNotification.nextAttemptAt': 1 } });
      if (!record) return;
      let result: Awaited<ReturnType<Sender>>;
      try { result = await this.send(record); }
      catch { result = { sent: false, error: 'provider_failed' }; }
      const attempts = record.criticalNotification!.attempts;
      const terminal = attempts >= MAX_ATTEMPTS;
      const safeToRetry = !result.sent && ['ses_unconfigured', 'no_admin_recipients'].includes(result.error || '');
      const completed = await entries.updateOne({ auditId: { $eq: record.auditId }, 'criticalNotification.leaseId': leaseId }, {
        $set: result.sent ? {
          'criticalNotification.state': 'sent', 'criticalNotification.sentAt': this.now(),
        } : {
          'criticalNotification.state': safeToRetry ? (terminal ? 'failed' : 'pending') : 'uncertain',
          'criticalNotification.lastError': safeToRetry ? result.error : 'provider_outcome_unknown',
          'criticalNotification.nextAttemptAt': new Date(this.now().getTime() + Math.min(60_000 * 2 ** (attempts - 1), 3_600_000)),
        },
        $unset: { 'criticalNotification.leaseId': '', ...(result.sent ? { 'criticalNotification.lastError': '' } : {}) },
      });
      if (!completed.acknowledged || completed.matchedCount !== 1) throw new Error('Critical alert result was not persisted');
      if (!result.sent) logger.error('[CRITICAL_ADMIN_ALERT] Delivery incomplete; inspect durable notification state');
    }
  }
}

export const criticalAdminAlertWorker = new CriticalAdminAlertWorker();
