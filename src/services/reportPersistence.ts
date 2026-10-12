import { validateRecipientNarrative, type NarrativeEnvelope } from './recipientNarrativeEnvelope';
import { reporterCodeHash, REPORTER_CODE_PATTERN, LEGACY_REPORTER_CODE_PATTERN } from './reporterAccess';
import { sealPrivateValue, openPrivateValue, protectFields } from './privateRecord';
import { logger } from '../utils/logger';
/**
 * MongoDB persistence for whistleblower report records.
 *
 * Replaces the in-memory Map used in whistleblower.ts, which loses
 * all reports on process restart.
 */

import { MongoClient, Collection } from 'mongodb';
import { randomUUID } from 'node:crypto';
import { keyEnvelope } from './keyEnvelope';
import { decryptReportNarrative } from './reportNarrative';
import type { StoredSubmitterDisclosure } from './submitterDisclosure';

/**
 * Decryption parameters for a single uploaded evidence file.
 * Persisted to MongoDB so evidence remains retrievable after a process restart.
 */
export type EvidenceDecryptionParams = {
  encryptionKey: string;
  originalCID: string;
  // Storage-layer AES-GCM parameters (evidenceStorageCipher.ts). The names are
  // historical and persisted; renaming them would orphan existing records.
  pinataIv: string;
  pinataAuthTag: string;
  pinataSalt?: string;
  evidenceSalt: string;
  evidenceIv: string;
  evidenceAuthTag: string;
  /** SHA-256 of sanitized plaintext; absent only on legacy records. */
  contentHash?: string;
  contentSize?: number;
  mimetype: string;
};

type EvidenceDecryptionRecord = EvidenceDecryptionParams & { fileKey: string };
/** Prepared by this store: every data key is wrapped before durable staging. */
export type PreparedIntake = { report: ReportRecord; evidence: EvidenceDecryptionRecord[] };

export interface AdminReportNote {
  id: string;
  text: string;
  timestamp: string;
  authorId: string;
}

export interface ReportRecord {
  statusHistory?: { id: string; status: ReportRecord['status']; timestamp: string }[];
  internalNotes?: { id: string; encrypted: string }[];
  trackingId: string;
  reporterAccess?: { hash: string; encryptedCode: string };
  /** Explicit recipient disclosure election; identity is encrypted separately from reward contact. */
  submitter?: StoredSubmitterDisclosure;
  encryptedNarrative?: NarrativeEnvelope;
  evidenceHash?: string;
  /** Missing on historical records: sha256-concat-v1. Never rewrite old commitments. */
  evidenceHashVersion?: import('../utils/evidenceCommitment').EvidenceHashVersion;
  /**
   * Human-owned triage status. Legacy pipeline values remain readable but are
   * displayed as pending; only explicit human resolved/dismissed decisions close
   * a case. Background processing must never write this field.
   */
  status:
    | 'pending' | 'processing' | 'verified' | 'rejected'
    | 'reviewing' | 'investigating' | 'resolved' | 'dismissed';
  processingStatus?: 'processing' | 'completed' | 'failed';
  scoringJob?: { state: 'pending' | 'running' | 'completed' | 'failed'; attempts: number; nextAttemptAt: Date; leaseId?: string; lastError?: string };
  /** Stored atomically with acceptance; worker sends without report content. */
  adminNotification?: {
    state: 'pending' | 'sending' | 'sent' | 'failed';
    attempts: number;
    nextAttemptAt: Date;
    leaseId?: string;
    sentAt?: Date;
    lastError?: string;
  };
  submissionNotification?: {
    state: 'pending' | 'sending' | 'sent' | 'failed';
    source: 'web' | 'telegram'; // Historical reports retain their original source.
    attempts: number;
    nextAttemptAt: Date;
    leaseId?: string;
    sentAt?: Date;
  };
  /**
   * Blockchain proof state. New reports are written with 'not_applicable':
   * Midnight proofs are no longer issued. The other states appear only on
   * historical reports from when a background worker proved them (#277).
   *
   * Absent on reports proved inline (the synchronous path, and every report
   * accepted before this field existed) — absence means "nothing owes a proof",
   * not "proof pending", so historical records need no backfill.
   */
  proofGeneration?: {
    state: 'pending' | 'proving' | 'attached' | 'failed' | 'not_applicable';
    attempts: number;
    nextAttemptAt: Date;
    leaseId?: string;
    attachedAt?: Date;
    lastError?: string;
    /**
     * Anonymous per-submission id the historical proof nullifier was derived
     * from. It is not identity-bearing: it is random per submission (see the
     * submit route).
     */
    userId: string;
    /** Idempotency reservation to release once the proof resolves. */
    keyHash?: string;
  };
  ipfsHash?: string;
  category?: string;
  /** Concern categories from the ten-category dissemination taxonomy (PDR §6). */
  categories?: string[];
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
  /** Governing jurisdiction ('us' | 'eu' | 'other') for routing (Phase 4c). */
  jurisdiction?: string;
  /**
   * Reporter's dissemination consent, captured at intake (FR-8).
   * Immutable snapshot of exactly what the reporter agreed to.
   */
  consent?: {
    psst: {
      granted: boolean;
      /** Psst deposit-treatment election: contact-now | contact-on-match | hold-encrypted */
      treatment?: string;
    };
    /** Consent to government-agency submission; only meaningful under versions that asked it (#926). */
    agency: boolean;
    /** Consent to admin-reviewed sharing with trusted legal reviewers (v4+). */
    legalReview?: boolean;
    /** Consent to prepare a SecureDrop press/media handoff (reporter-elected, opt-in). */
    press?: boolean;
    capturedAt: Date;
    /** Version of the consent language shown to the reporter. */
    textVersion: string;
  };
  reward?: {
    wantsReward: boolean;
    contactMethod?: string;
    /** AES-256-GCM encrypted contact value (iv:authTag:ciphertext in hex) */
    encryptedContactValue?: string;
    contactKeyWrapped?: string;
  };
  /**
   * Reward-flow recipients the reporter chose to receive a one-time secure link
   * to their identity-free packet (validated ids from lib/rewardRecipients).
   * Drives the automatic send after processing; empty/absent = no auto-send.
   */
  disseminationRecipients?: string[];
  /**
   * Redaction-scrubbed narrative frozen for automatic dissemination, encrypted
   * at rest (same AES-256-GCM scheme). Set when an auto secure-packet link is
   * sent; the reveal route serves this copy for `origin:'auto'` links so no raw
   * self-identifying narrative reaches an external recipient.
   */
  encryptedDisseminationNarrative?: string;
  /** Historical Midnight existence proof; no new proofs are attached. */
  zkProof?: {
    proofHash: string;
    nullifier: string;
    publicSignals: string[];
    verified: boolean;
    proofType?: string;
    contractAddress?: string;
    txId?: string;
    txHash?: string;
    /** Midnight network of txHash. Absent on receipts attached before #353 (preprod). */
    network?: string;
  };
  verification?: {
    isLegitimate: boolean;
    credibilityScore: number;
    category: string;
    /** Org-type in the Psst taxonomy (FR-2 routing dimension). */
    organizationType?: string;
    /** The organization the report concerns, extracted by AI triage. */
    namedOrganization?: string;
    /** Spam/abuse indicators from the AI scorer. */
    spamIndicators?: string[];
    /** Brief AI content analysis. */
    contentAnalysis?: string;
    /** AI risk assessment. */
    riskLevel?: 'low' | 'medium' | 'high';
  };
  /** AES-256-GCM encrypted report narrative (iv:authTag:ciphertext hex), same scheme as reward contact. Revealed on-demand, admin-gated. */
  encryptedDescription?: string;
  createdAt: Date;
  updatedAt: Date;
}

/** Durable storage is required in every environment; local development can use MongoDB. */
export class ReportPersistenceService {
  private client: MongoClient | null = null;
  private reports: Collection<ReportRecord> | null = null;
  private evidenceParams: Collection<EvidenceDecryptionRecord> | null = null;
  private connecting: Promise<void> | null = null;

  private async connect(): Promise<void> {
    if (this.reports && this.evidenceParams) return;
    if (this.connecting) return this.connecting;
    this.connecting = this.open();
    try { await this.connecting; } finally { this.connecting = null; }
  }

  private async open(): Promise<void> {
    const uri = process.env.MONGODB_URI?.trim();
    if (!uri) throw new Error('Report storage unavailable: MONGODB_URI is required');
    const tlsCAFile = process.env.MONGODB_TLS_CA_FILE;
    const client = new MongoClient(uri, {
      readPreference: 'primary',
      ...(tlsCAFile ? { tlsCAFile } : {}),
      serverSelectionTimeoutMS: 10000,
      // A receipt must not depend on a write that only reached process memory.
      writeConcern: { w: 'majority', j: true },
    });
    try {
      await client.connect();
      const db = client.db(process.env.MONGODB_DB_NAME || 'vera');
      const reports = db.collection<ReportRecord>('whistleblower_reports');
      const evidence = db.collection<EvidenceDecryptionRecord>('evidence_decryption_params');
      await reports.createIndex({ trackingId: 1 }, { unique: true });
      await reports.createIndex({ 'reporterAccess.hash': 1 }, { unique: true, sparse: true });
      await reports.createIndex({ createdAt: -1 });
      await reports.createIndex({ status: 1 });
      await reports.createIndex({ processingStatus: 1, 'scoringJob.nextAttemptAt': 1 });
      await evidence.createIndex({ fileKey: 1 }, { unique: true });
      // Publish handles only after initialization succeeds. Failed initialization
      // must never leave partially connected handles or leak clients on retry.
      this.client = client;
      this.reports = reports;
      this.evidenceParams = evidence;
      logger.info('[REPORT_STORE] Connected to MongoDB');
    } catch (error) {
      await client.close().catch(() => {});
      throw error;
    }
  }

  async close(): Promise<void> {
    if (this.connecting) await this.connecting.catch(() => {});
    const client = this.client;
    this.client = null;
    this.reports = null;
    this.evidenceParams = null;
    await client?.close();
  }

  async upsert(record: ReportRecord): Promise<void> {
    await this.connect();
    const result = await this.reports!.replaceOne({ trackingId: record.trackingId }, await this.wrapNarrative(record, record.trackingId), { upsert: true });
    if (!result.acknowledged) throw new Error('Report write was not acknowledged');
  }

  async prepareIntake(record: ReportRecord, evidence: EvidenceDecryptionRecord[]): Promise<PreparedIntake> {
    return {
      report: await this.wrapNarrative(record, record.trackingId),
      evidence: await Promise.all(evidence.map(async row => ({
        ...row, encryptionKey: await keyEnvelope.wrap(row.encryptionKey, { fileKey: row.fileKey, purpose: 'evidence' }),
      }))),
    };
  }

  /** Replay a single, durably selected intake; never replace an accepted report. */
  async materializeIntake(prepared: PreparedIntake): Promise<ReportRecord> {
    await this.connect();
    const { report, evidence } = prepared;
    const existing = await this.get(report.trackingId);
    if (existing) return existing;
    // Only the winner of the reservation's atomic acceptance can reach this
    // method. Concurrent recovery writes are copies of that same durable plan.
    for (const row of evidence) {
      if (!row.fileKey.startsWith(report.trackingId + '/') || !row.encryptionKey.startsWith('enc:'))
        throw new Error('Invalid prepared evidence');
      const result = await this.evidenceParams!.replaceOne({ fileKey: row.fileKey }, row, { upsert: true });
      if (!result.acknowledged) throw new Error('Evidence manifest write was not acknowledged');
    }
    const result = await this.reports!.updateOne(
      { trackingId: report.trackingId }, { $setOnInsert: report }, { upsert: true },
    );
    if (!result.acknowledged) throw new Error('Report write was not acknowledged');
    const saved = await this.get(report.trackingId);
    if (!saved) throw new Error('Accepted report unavailable');
    return saved;
  }

  async get(trackingId: string): Promise<ReportRecord | null> {
    await this.connect();
    return protectFields(await this.reports!.findOne({ trackingId }), `report:${trackingId}`, ['verification'], 'open');
  }

  async addInternalNote(trackingId: string, text: string, authorId: string): Promise<AdminReportNote | null> {
    await this.connect();
    const note: AdminReportNote = { id: randomUUID(), text, authorId, timestamp: new Date().toISOString() };
    const encrypted = await sealPrivateValue(note, `report:${trackingId}`, `note:${note.id}`);
    const result = await this.reports!.updateOne({ trackingId }, { $push: { internalNotes: { id: note.id, encrypted } } });
    if (!result.acknowledged) throw new Error('Note write was not acknowledged');
    return result.matchedCount ? note : null;
  }

  async listInternalNotes(trackingId: string): Promise<AdminReportNote[] | null> {
    await this.connect();
    const report = await this.reports!.findOne({ trackingId }, { projection: { internalNotes: 1 } });
    if (!report) return null;
    return Promise.all((report.internalNotes || []).map(async note => {
      const opened: unknown = await openPrivateValue(note.encrypted, `report:${trackingId}`, `note:${note.id}`);
      if (!opened || typeof opened !== 'object' || !('text' in opened) || typeof opened.text !== 'string'
        || !('timestamp' in opened) || typeof opened.timestamp !== 'string'
        || !('authorId' in opened) || typeof opened.authorId !== 'string') throw new Error('Invalid stored note');
      return { id: note.id, text: opened.text, timestamp: opened.timestamp, authorId: opened.authorId };
    }));
  }

  /** Resolve only the internal binding; never return it to the reporter or open private fields. */
  async resolveAttestedReporterTrackingId(code: string, signal: AbortSignal): Promise<string | null> {
    if (typeof code !== 'string' || !REPORTER_CODE_PATTERN.test(code)) throw new Error('Reporter credential required');
    const hash = reporterCodeHash(code);
    signal.throwIfAborted();
    await this.connect();
    signal.throwIfAborted();
    const records = await this.reports!.find<{ trackingId: string }>(
      { 'reporterAccess.hash': hash }, { projection: { _id: 0, trackingId: 1 }, signal, maxTimeMS: 10000 },
    ).limit(2).toArray();
    signal.throwIfAborted();
    if (!records.length) return null;
    if (records.length !== 1 || typeof records[0].trackingId !== 'string' || !/^VRA-[A-F0-9]{16}$/.test(records[0].trackingId)) throw new Error('Reporter binding unavailable');
    return records[0].trackingId;
  }

  /** Loader for the disabled attested reader; never opens a private field on the host. */
  createReporterVerificationLoader(code: string): (trackingId: string, signal: AbortSignal) => Promise<{ trackingId: string; verification: unknown } | null> {
    if (typeof code !== 'string' || !REPORTER_CODE_PATTERN.test(code)) throw new Error('Reporter credential required');
    const hash = reporterCodeHash(code);
    return async (trackingId, signal) => {
      signal.throwIfAborted();
      if (typeof trackingId !== 'string' || !/^VRA-[A-F0-9]{16}$/.test(trackingId)) throw new Error('Invalid tracking ID');
      await this.connect();
      signal.throwIfAborted();
      // Authorization and exact record selection share one query. Rotation is
      // checked on each read; the closure retains only the credential hash.
      return this.reports!.findOne<{ trackingId: string; verification: unknown }>(
        { trackingId, 'reporterAccess.hash': hash },
        { projection: { _id: 0, trackingId: 1, verification: 1 }, signal, maxTimeMS: 10000 },
      );
    };
  }

  async getForReporter(code: string): Promise<ReportRecord | null> {
    await this.connect();
    if (REPORTER_CODE_PATTERN.test(code)) {
      const record = await this.reports!.findOne({ 'reporterAccess.hash': reporterCodeHash(code) });
      return record ? protectFields(record, `report:${record.trackingId}`, ['verification'], 'open') : null;
    }
    if (!LEGACY_REPORTER_CODE_PATTERN.test(code)) return null;
    const record = await this.get(code.toUpperCase());
    // Internal IDs never authorize access to a report with a separate credential.
    return record && !record.reporterAccess ? record : null;
  }

  async rotateReporterAccess(trackingId: string, previousHash: string | undefined, access: NonNullable<ReportRecord['reporterAccess']>): Promise<boolean> {
    await this.connect();
    const result = await this.reports!.updateOne({ trackingId, 'reporterAccess.hash': previousHash ?? { $exists: false } }, { $set: { reporterAccess: access } });
    return result.acknowledged && result.modifiedCount === 1;
  }

  async saveEvidenceParams(fileKey: string, params: EvidenceDecryptionParams): Promise<void> {
    await this.connect();
    const result = await this.evidenceParams!.replaceOne({ fileKey }, { fileKey, ...params, encryptionKey: await keyEnvelope.wrap(params.encryptionKey, { fileKey, purpose: 'evidence' }) }, { upsert: true });
    if (!result.acknowledged) throw new Error('Evidence manifest write was not acknowledged');
  }

  async getEvidenceParams(fileKey: string): Promise<EvidenceDecryptionParams | null> {
    await this.connect();
    const record = await this.evidenceParams!.findOne({ fileKey });
    if (!record) return null;
    const { fileKey: _key, ...params } = record;
    return { ...params, encryptionKey: await keyEnvelope.unwrap(params.encryptionKey, { fileKey, purpose: 'evidence' }) };
  }

  /** List reports newest-first; limit <= 0 means no limit. */
  async list(limit: number, trackingId?: string): Promise<ReportRecord[]> {
    await this.connect();
    return Promise.all((await this.reports!.find(trackingId ? { trackingId } : {})
      .sort({ createdAt: -1 }).limit(limit > 0 ? limit : 0).toArray()).map(doc => protectFields(doc, `report:${doc.trackingId}`, ['verification'], 'open')));
  }

  /** Admin-only search; reporter credentials are resolved by hash, never returned. */
  async searchAdmin(query: string, limit = 100): Promise<ReportRecord[]> {
    await this.connect();
    const normalized = query.trim();
    const escaped = normalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const filter = REPORTER_CODE_PATTERN.test(normalized)
      ? { 'reporterAccess.hash': reporterCodeHash(normalized) }
      : LEGACY_REPORTER_CODE_PATTERN.test(normalized)
        ? { trackingId: normalized.toUpperCase() }
        : { $or: [{ trackingId: { $regex: escaped, $options: 'i' } }, { category: { $regex: escaped, $options: 'i' } }] };
    const records = await this.reports!.find(filter).sort({ createdAt: -1 }).limit(limit).maxTimeMS(10000).toArray();
    return Promise.all(records.map(doc => protectFields(doc, `report:${doc.trackingId}`, ['verification'], 'open')));
  }

  async listEvidenceByTrackingIds(trackingIds: string[]): Promise<EvidenceDecryptionRecord[]> {
    if (!trackingIds.length) return [];
    await this.connect();
    const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return this.evidenceParams!.find({
      $or: trackingIds.map(t => ({ fileKey: { $regex: `^${escapeRegex(t)}/` } })),
    }).toArray();
  }

  private async wrapNarrative<T extends Partial<ReportRecord>>(record: T, trackingId: string): Promise<T> {
    const recipient = record.encryptedNarrative?.format !== undefined
      ? validateRecipientNarrative(record.encryptedNarrative, trackingId) : undefined;
    record = await protectFields(record, `report:${trackingId}`, ['verification'], 'seal');
    if (recipient) return { ...record, encryptedNarrative: recipient };
    if (!record.encryptedNarrative) return record;
    if (record.encryptedNarrative.format !== undefined) throw new Error('Narrative unavailable');
    return { ...record, encryptedNarrative: { ...record.encryptedNarrative,
      encryptionKey: await keyEnvelope.wrap(record.encryptedNarrative.encryptionKey, { trackingId, purpose: 'narrative' }),
    } };
  }

  async getReportContext(trackingId: string, preloaded?: ReportRecord) {
    const record = preloaded ?? await this.get(trackingId);
    if (!record) return null;
    const rows = await this.listEvidenceByTrackingIds([trackingId]);
    let description: string | undefined;
    let narrativeUnavailable = false;
    try { description = await decryptReportNarrative(record); }
    catch { narrativeUnavailable = true; }
    return { description, narrativeUnavailable,
      evidence: rows.filter(row => !!row.originalCID).map(row => ({
        name: row.fileKey.slice(trackingId.length + 1), ipfsHash: row.originalCID,
      })),
    };
  }

  /** Accepted reports carry the scoring intent in the same durable write as their receipt. */
  async claimScoring(now: Date, trackingId?: string): Promise<ReportRecord | null> {
    await this.connect();
    return this.reports!.findOneAndUpdate({
      ...(trackingId ? { trackingId } : {}), processingStatus: 'processing',
      $or: [
        { 'scoringJob.state': { $in: ['pending', 'running'] }, 'scoringJob.nextAttemptAt': { $lte: now } },
        { scoringJob: { $exists: false } }, // Recover pre-queue reports stranded by a restart.
      ],
    }, { $set: {
      'scoringJob.state': 'running', 'scoringJob.leaseId': randomUUID(),
      'scoringJob.nextAttemptAt': new Date(now.getTime() + 300_000),
    }, $inc: { 'scoringJob.attempts': 1 } }, { returnDocument: 'after' });
  }

  async finishScoring(record: ReportRecord, updates: Partial<ReportRecord>): Promise<boolean> {
    await this.connect();
    if (!record.scoringJob?.leaseId) throw new Error('Missing scoring lease');
    const result = await this.reports!.updateOne({
      trackingId: record.trackingId, processingStatus: 'processing',
      'scoringJob.leaseId': record.scoringJob.leaseId,
    }, { $set: { ...await this.wrapNarrative(updates, record.trackingId), updatedAt: new Date() } });
    if (!result.acknowledged) throw new Error('Scoring result was not acknowledged');
    return result.matchedCount === 1;
  }

  async setAdminStatus(trackingId: string, status: ReportRecord['status']): Promise<void> {
    await this.connect();
    const now = new Date();
    const result = await this.reports!.updateOne(
      { trackingId, status: { $ne: status } },
      {
        $set: { status, updatedAt: now },
        $push: { statusHistory: { id: randomUUID(), status, timestamp: now.toISOString() } },
      },
    );
    if (!result.acknowledged) throw new Error('Status update was not acknowledged');
    if (!result.matchedCount && !await this.reports!.findOne({ trackingId })) {
      throw new Error('Report update was not persisted');
    }
  }

  async patch(trackingId: string, updates: Partial<Omit<ReportRecord, 'trackingId' | 'createdAt'>>): Promise<void> {
    await this.connect();
    const result = await this.reports!.updateOne({ trackingId }, { $set: { ...await this.wrapNarrative(updates, trackingId), updatedAt: new Date() } });
    if (!result.acknowledged || result.matchedCount !== 1) throw new Error('Report update was not persisted');
  }
}

export const reportPersistenceService = new ReportPersistenceService();
