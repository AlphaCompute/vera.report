import { logger } from '../utils/logger';
import { SEVERITY_MAP } from './adminAuditActions';
import type { AdminAction, AuditSeverity } from './adminAuditActions';
/**
 * MongoDB-backed audit logging for admin actions.
 *
 * Persists every admin action (evidence access, status change, etc.)
 * with the acting admin's identity, timestamp, and context.
 * Follows the singleton pattern from reportPersistence.ts.
 */

import { MongoClient, Db, Collection } from 'mongodb';
import { randomUUID } from 'crypto';



export { SEVERITY_MAP, ADMIN_ACTIONS } from './adminAuditActions';
export type { AdminAction, AuditSeverity } from './adminAuditActions';

export type AdminAuditEntry = {
  auditId: string;
  criticalNotification?: {
    state: 'pending' | 'sending' | 'sent' | 'uncertain' | 'failed';
    attempts: number;
    nextAttemptAt: Date;
    leaseId?: string;
    sentAt?: Date;
    lastError?: string;
  };
  adminUserId: string;
  adminEmail: string;
  action: AdminAction;
  severity: AuditSeverity;
  endpoint: string;
  method: string;
  timestamp: Date;
  responseStatus: number;
  details: {
    phase?: 'attempted' | 'response';
    resourceId?: string;
    filename?: string;
    newStatus?: string;
    agentId?: string;
    ipAddress?: string;
    userAgent?: string;
  };
};

export type AuditLogFilters = {
  adminEmail?: string;
  action?: AdminAction;
  severity?: AuditSeverity;
  resourceId?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
};


/** 90 days in seconds */
const TTL_SECONDS = 90 * 24 * 60 * 60;

export class AdminAuditLogService {
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private auditLogs: Collection<AdminAuditEntry> | null = null;
  private isConnected = false;
  private connecting: Promise<void> | null = null;

  private memoryStore: AdminAuditEntry[] = [];
  private static readonly MAX_MEMORY = 1000;

  private async connect(): Promise<void> {
    if (this.isConnected) return;
    if (!this.connecting) {
      this.connecting = this.initialize().finally(() => { this.connecting = null; });
    }
    await this.connecting;
  }

  private async initialize(): Promise<void> {

    const mongoUri = process.env.MONGODB_URI?.trim();
    if (!mongoUri) {
      if (process.env.NODE_ENV === 'production') {
        logger.error(
          '[AUDIT_LOG][CRITICAL] MONGODB_URI not set in production. ' +
            'Audited actions are refused until durable storage is available.',
        );
      }
      return;
    }

    const dbName = process.env.MONGODB_DB_NAME || 'vera';

    try {
      const tlsCAFile = process.env.MONGODB_TLS_CA_FILE;
      this.client = new MongoClient(mongoUri, { ...(tlsCAFile ? { tlsCAFile } : {}), readPreference: 'primary' });
      await this.client.connect();
      this.db = this.client.db(dbName);
      this.auditLogs = this.db.collection<AdminAuditEntry>('admin_audit_logs');

      await this.auditLogs.createIndex({ adminEmail: 1, timestamp: -1 });
      await this.auditLogs.createIndex({ action: 1, timestamp: -1 });
      await this.auditLogs.createIndex({ 'details.resourceId': 1 });
      await this.auditLogs.createIndex({ timestamp: -1 });
      await this.auditLogs.createIndex({ timestamp: 1 }, { expireAfterSeconds: TTL_SECONDS });

      this.isConnected = true;
      logger.info('[AUDIT_LOG] Connected to MongoDB');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`[AUDIT_LOG] MongoDB connection failed: ${msg}`);
      await this.close().catch(() => {});
    }
  }

  /**
   * Persist an admin action. Runtime writes fail closed; only tests may use memory.
   * The `severity` field is auto-set from the action if not provided.
   */
  async log(
    entry: Omit<AdminAuditEntry, 'auditId' | 'timestamp' | 'severity' | 'criticalNotification'> & {
      severity?: AuditSeverity;
    },
    requirePersistence = process.env.NODE_ENV !== 'test',
  ): Promise<void> {
    const fullEntry: AdminAuditEntry = {
      ...entry,
      auditId: randomUUID(),
      timestamp: new Date(),
      severity: entry.severity ?? SEVERITY_MAP[entry.action],
    };

    if (fullEntry.severity === 'critical') {
      fullEntry.criticalNotification = { state: 'pending', attempts: 0, nextAttemptAt: fullEntry.timestamp };
    }

    logger.info(`[AUDIT_LOG] ${fullEntry.severity.toUpperCase()}: ${fullEntry.action}`, {
      admin: fullEntry.adminEmail,
      endpoint: fullEntry.endpoint,
      resourceId: fullEntry.details.resourceId,
      responseStatus: fullEntry.responseStatus,
    });

    await this.connect();

    if (requirePersistence && (!this.isConnected || !this.auditLogs)) throw new Error('Durable audit storage unavailable');

    if (this.auditLogs) {
      try {
        const result = await this.auditLogs.insertOne(fullEntry, { writeConcern: { w: 'majority', j: true } });
        if (!result.acknowledged) throw new Error('Audit write was not acknowledged');
        return;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`[AUDIT_LOG] Failed to persist audit entry: ${msg}`);
        if (requirePersistence) throw new Error('Failed to persist audit entry');
      }
    }

    this.memoryStore.push(fullEntry);
    if (this.memoryStore.length > AdminAuditLogService.MAX_MEMORY) {
      this.memoryStore.splice(0, this.memoryStore.length - AdminAuditLogService.MAX_MEMORY);
    }
  }

  /**
   * Query audit logs with filters and pagination.
   */
  async query(
    filters: AuditLogFilters = {},
    requirePersistence = process.env.NODE_ENV !== 'test',
  ): Promise<{ entries: AdminAuditEntry[]; total: number }> {
    const { page = 1, limit = 50 } = filters;
    const cappedLimit = Math.min(limit, 200);
    const skip = (page - 1) * cappedLimit;

    await this.connect();

    if (requirePersistence && (!this.isConnected || !this.auditLogs)) throw new Error('Durable audit storage unavailable');

    if (this.auditLogs) {
      try {
        const filter = this.buildFilter(filters);
        const [entries, total] = await Promise.all([
          this.auditLogs
            .find(filter)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(cappedLimit)
            .toArray(),
          this.auditLogs.countDocuments(filter),
        ]);
        return { entries, total };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`[AUDIT_LOG] Query failed: ${msg}`);
        if (requirePersistence) throw new Error('Failed to query durable audit storage');
      }
    }

    // Fallback: filter in-memory store
    let filtered = [...this.memoryStore];
    if (filters.adminEmail) {
      filtered = filtered.filter((e) => e.adminEmail === filters.adminEmail);
    }
    if (filters.action) {
      filtered = filtered.filter((e) => e.action === filters.action);
    }
    if (filters.severity) {
      filtered = filtered.filter((e) => e.severity === filters.severity);
    }
    if (filters.resourceId) {
      filtered = filtered.filter((e) => e.details.resourceId === filters.resourceId);
    }
    if (filters.startDate) {
      filtered = filtered.filter((e) => e.timestamp >= filters.startDate!);
    }
    if (filters.endDate) {
      filtered = filtered.filter((e) => e.timestamp <= filters.endDate!);
    }
    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    const total = filtered.length;
    const entries = filtered.slice(skip, skip + cappedLimit);
    return { entries, total };
  }

  async close(): Promise<void> {
    const client = this.client;
    this.client = null;
    this.db = null;
    this.auditLogs = null;
    this.isConnected = false;
    await client?.close();
  }

  private buildFilter(filters: AuditLogFilters): Record<string, unknown> {
    const filter: Record<string, unknown> = {};

    if (filters.adminEmail) {
      filter.adminEmail = filters.adminEmail;
    }
    if (filters.action) {
      filter.action = filters.action;
    }
    if (filters.severity) {
      filter.severity = filters.severity;
    }
    if (filters.resourceId) {
      filter['details.resourceId'] = filters.resourceId;
    }
    if (filters.startDate || filters.endDate) {
      const range: Record<string, Date> = {};
      if (filters.startDate) range.$gte = filters.startDate;
      if (filters.endDate) range.$lte = filters.endDate;
      filter.timestamp = range;
    }

    return filter;
  }
}

export const adminAuditLog = new AdminAuditLogService();
