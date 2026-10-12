import type { EvidenceHashVersion } from '../utils/evidenceCommitment';
import crypto from 'node:crypto';
import { MongoClient, Collection } from 'mongodb';
import type { PreparedIntake } from './reportPersistence';
import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '../utils/evidenceLimits';

// 'proof_ready' and 'unknown' (and a stored `proof`) appear only on attempts
// recorded while submissions were still proved on Midnight; nothing writes them now.
type Attempt = { keyHash: string; payloadHash: string; trackingId: string; createdAt: Date; evidenceHash?: string; evidenceHashVersion?: EvidenceHashVersion;
  state?: 'active' | 'retryable' | 'proof_ready' | 'unknown' | 'accepted' | 'complete'; userId?: string;
  protocol?: 'leased-intake-v1'; leaseId?: string; leaseUntil?: Date; preparedIntake?: PreparedIntake };
export const INTAKE_LEASE_MS = EVIDENCE_TRANSFER_TIMEOUT_MS;
export class IntakeLeaseLostError extends Error {
  constructor() { super('Submission ownership changed; retry to recover its receipt'); }
}
function intakeLease() {
  return { protocol: 'leased-intake-v1' as const, leaseId: crypto.randomUUID(), leaseUntil: new Date(Date.now() + INTAKE_LEASE_MS) };
}

/** Length framing prevents field/file concatenation ambiguities. */
export function submissionPayloadHash(body: Record<string, unknown>, files: Express.Multer.File[]): string {
  const hash = crypto.createHash('sha256');
  const add = (value: string | Buffer) => {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
    hash.update(String(bytes.length)).update(':').update(bytes);
  };
  add(JSON.stringify(Object.keys(body).sort().map(key => [key, body[key]])));
  add(String(files.length));
  for (const file of files) {
    add(file.originalname); add(file.mimetype); add(file.buffer);
  }
  return hash.digest('hex');
}

export const submissionKeyHash = (key: string) => crypto.createHash('sha256').update(key).digest('hex');

/**
 * Current intake performs no proving before acceptance. A lease may therefore
 * recover its abandoned preparation, with an atomic publication fence. Legacy
 * active reservations and unknown proof outcomes are never reclaimed by age.
 */
export class SubmissionAttemptStore {
  private client?: MongoClient;
  private collection?: Collection<Attempt>;
  private connecting?: Promise<void>;

  private async connect(): Promise<void> {
    if (this.collection) return;
    if (!this.connecting) this.connecting = this.open();
    try { await this.connecting; } finally { this.connecting = undefined; }
  }
  private async open(): Promise<void> {
    const uri = process.env.MONGODB_URI?.trim();
    if (!uri) throw new Error('Submission storage unavailable');
    const client = new MongoClient(uri, {
      readPreference: 'primary',
      ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}),
      serverSelectionTimeoutMS: 10000, writeConcern: { w: 'majority', j: true },
    });
    try {
      await client.connect();
      const collection = client.db(process.env.MONGODB_DB_NAME || 'vera').collection<Attempt>('submission_attempts');
      await collection.createIndex({ keyHash: 1 }, { unique: true });
      this.client = client;
      this.collection = collection;
    } catch (error) { await client.close().catch(() => {}); throw error; }
  }
  async get(keyHash: string): Promise<Attempt | null> {
    await this.connect();
    return this.collection!.findOne({ keyHash });
  }
  async reserve(keyHash: string, payloadHash: string, trackingId: string, evidenceHash?: string, evidenceHashVersion?: EvidenceHashVersion): Promise<{ attempt: Attempt; owner: boolean }> {
    await this.connect();
    const attempt: Attempt = { keyHash, payloadHash, trackingId, evidenceHash, evidenceHashVersion, createdAt: new Date(), state: 'active', userId: crypto.randomBytes(32).toString('hex'), ...intakeLease() };
    try {
      const result = await this.collection!.insertOne(attempt);
      if (!result.acknowledged) throw new Error('Submission reservation was not acknowledged');
      return { attempt, owner: true };
    } catch (error: any) {
      if (error.code !== 11000) throw error;
      const existing = await this.get(keyHash);
      if (!existing) throw new Error('Submission reservation unavailable');
      return { attempt: existing, owner: false };
    }
  }
  async claimRetry(keyHash: string, payloadHash: string): Promise<Attempt | null> {
    await this.connect();
    return this.collection!.findOneAndUpdate(
      { keyHash, payloadHash, $or: [
        { state: { $in: ['retryable', 'proof_ready'] } },
        { state: 'active', protocol: 'leased-intake-v1', leaseUntil: { $lte: new Date() } },
      ] },
      { $set: { state: 'active', ...intakeLease() } }, { returnDocument: 'after' },
    );
  }
  async release(keyHash: string, state: 'retryable', leaseId?: string): Promise<void> {
    await this.connect();
    const result = await this.collection!.updateOne({ keyHash, state: 'active', leaseId: leaseId ?? { $exists: false } }, { $set: { state } });
    if (!result.acknowledged || result.matchedCount !== 1) throw new Error('Retry state was not acknowledged');
  }
  async acceptIntake(keyHash: string, leaseId: string, preparedIntake: PreparedIntake): Promise<void> {
    await this.connect();
    const result = await this.collection!.updateOne(
      { keyHash, leaseId, trackingId: preparedIntake.report.trackingId, state: 'active', protocol: 'leased-intake-v1' },
      { $set: { state: 'accepted', preparedIntake } },
    );
    if (!result.acknowledged) throw new Error('Intake acceptance was not acknowledged');
    if (result.matchedCount !== 1) throw new IntakeLeaseLostError();
  }
  async completeIntake(keyHash: string): Promise<void> {
    await this.connect();
    const result = await this.collection!.updateOne({ keyHash, state: 'accepted' }, {
      $set: { state: 'complete' }, $unset: { preparedIntake: '', leaseUntil: '' },
    });
    if (!result.acknowledged) throw new Error('Intake completion was not acknowledged');
  }
  async close(): Promise<void> {
    await this.connecting?.catch(() => {});
    await this.client?.close();
    this.collection = undefined; this.client = undefined;
  }
}
export const submissionAttemptStore = new SubmissionAttemptStore();
