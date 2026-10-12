import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { submissionAttemptStore, submissionPayloadHash, submissionKeyHash } from '../../../src/services/submissionAttempt';
import { evidenceCommitment } from '../../../src/utils/evidenceCommitment';
import express from 'express';
import request from 'supertest';

// Heavy service deps mocked the same way as the auth tests so the
// whistleblower router can be loaded without real network/db.
jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn().mockResolvedValue({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { algorithm: 'aes-256-gcm', salt: 'cw==', iv: 'aXY=', authTag: 'dGFn', keyVersion: 'v1.0' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } }) },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: { upload: jest.fn() },
}));
jest.mock('../../../src/services/veniceAI', () => ({
  veniceAIService: { analyzeReport: jest.fn() },
}));
jest.mock('../../../src/services/reportScoring', () => ({
  verifyReport: jest.fn(),
}));
jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => false),
}));
jest.mock('../../../src/services/metadataExtractor', () => ({
  metadataExtractorService: { extract: jest.fn() },
}));
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    get: jest.fn(async () => null),
    getEvidenceParams: jest.fn(async () => null),
    saveEvidenceParams: jest.fn(),
    upsert: jest.fn(),
    prepareIntake: jest.fn(async (report, evidence) => ({ report, evidence })),
    materializeIntake: jest.fn(async function (this: any, prepared) {
      await this.upsert(prepared.report);
      return prepared.report;
    }),
    patch: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: {
    middleware: () => (_req: any, _res: any, next: () => void) => next(),
    logError: jest.fn(),
  },
}));


jest.mock('../../../src/services/submissionEvidence', () => ({ persistSubmissionEvidence: jest.fn() }));
jest.mock('../../../src/services/reportFieldCrypto', () => ({ encryptContactValue: () => 'encrypted' }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { notifyNewReport: jest.fn(async () => {}) } }));
jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
  return { __esModule: true, ...actual, default: () => (_req: any, _res: any, next: any) => next() };
});
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp(): express.Application {
  const app = express();
  app.use(express.json());
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}


const mockAccepted = new Map<string, any>();
let mockExpireResponse: (() => void) | undefined;
jest.mock('../../../src/middleware/security', () => ({ requestTimeout: () => (_req: any, res: any, next: any) => {
  mockExpireResponse = () => res.status(408).json({ success: false, error: 'Request timeout' });
  next();
} }));

describe('Bearer-key receipt recovery', () => {
  let mongo: MongoMemoryServer;
  let keyIndex = 0;
  const key = () => (++keyIndex).toString(16).padStart(64, '0');
  const submit = (retryKey: string, consent = 'false') => request(makeApp()).post('/api/whistleblower/submit')
    .set('X-Idempotency-Key', retryKey)
    .field('description', 'Report with important evidence').field('wantsReward', 'false').field('consentAgency', consent);
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongo.getUri();
    process.env.MONGODB_DB_NAME = 'receipt_recovery';
  });
  afterAll(async () => {
    await submissionAttemptStore.close();
    await mongo.stop();
    process.env.MONGODB_URI = ''; process.env.MONGODB_DB_NAME = '';
  });
  beforeEach(() => {
    jest.clearAllMocks();
    jest.mocked(persistSubmissionEvidence).mockResolvedValue([]);
    jest.mocked(reportPersistenceService.get).mockImplementation(async id => mockAccepted.get(id) || null);
    jest.mocked(reportPersistenceService.upsert).mockImplementation(async report => { mockAccepted.set(report.trackingId, report); });
  });

  it('atomically grants one owner when reservations arrive simultaneously', async () => {
    const secret = key();
    const results = await Promise.all([
      submissionAttemptStore.reserve(secret, 'payload', 'first'),
      submissionAttemptStore.reserve(secret, 'payload', 'second'),
    ]);
    expect(results.filter(result => result.owner)).toHaveLength(1);
    expect(results[0].attempt.trackingId).toBe(results[1].attempt.trackingId);
  });

  it('keeps a pre-upgrade commitment when recovering an unaccepted legacy attempt', async () => {
    const retryKey = key();
    const body = { description: 'Report with important evidence', wantsReward: 'false', consentAgency: 'false' };
    const legacyHash = evidenceCommitment(body.description, [], 'sha256-concat-v1');
    const keyHash = submissionKeyHash(retryKey);
    // Insert the historical schema itself. New reservations may acquire fields
    // (such as ownership leases) that did not exist before this upgrade.
    const legacyClient = new MongoClient(process.env.MONGODB_URI!);
    try {
      await legacyClient.connect();
      await legacyClient.db(process.env.MONGODB_DB_NAME).collection('submission_attempts').insertOne({
        keyHash, payloadHash: submissionPayloadHash(body, []), trackingId: 'VRA-000000000000EA01',
        evidenceHash: legacyHash, state: 'retryable', createdAt: new Date(), userId: 'legacy-synthetic-user',
      });
    } finally { await legacyClient.close(); }
    await submissionAttemptStore.close();
    const response = await submit(retryKey);
    expect(response.status).toBe(200);
    expect(response.body.evidenceHash).toBe(legacyHash);
    expect(response.body.evidenceHashVersion).toBe('sha256-concat-v1');
    expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0].evidenceHashVersion).toBe('sha256-concat-v1');
    expect((await submit(retryKey)).body).toEqual(response.body);
  });

  it('distinguishes a two-file report from one concatenated attachment through real multipart intake', async () => {
    const a = Buffer.from('a,b\n1,2\n'), b = Buffer.from('c,d\n3,4\n');
    const first = await request(makeApp()).post('/api/whistleblower/submit')
      .field('description', 'Synthetic report')
      .attach('files', a, { filename: 'first.csv', contentType: 'text/csv' })
      .attach('files', b, { filename: 'second.csv', contentType: 'text/csv' });
    const second = await request(makeApp()).post('/api/whistleblower/submit')
      .field('description', 'Synthetic report')
      .attach('files', Buffer.concat([a, b]), { filename: 'merged.csv', contentType: 'text/csv' });
    expect(first.status).toBe(200); expect(second.status).toBe(200);
    expect(first.body.evidenceHash).not.toBe(second.body.evidenceHash);
    expect(first.body.evidenceHashVersion).toBe('sha256-framed-v2');
    expect(second.body.evidenceHashVersion).toBe('sha256-framed-v2');
  });

  it('binds attachment names, MIME types, bytes and every form field', () => {
    const body = { description: 'text', consentAgency: 'false', contactValue: 'person@example.test' };
    const file = { originalname: 'a.csv', mimetype: 'text/csv', buffer: Buffer.from('a,b') } as Express.Multer.File;
    const original = submissionPayloadHash(body, [file]);
    expect(submissionPayloadHash({ ...body, contactValue: 'other@example.test' }, [file])).not.toBe(original);
    expect(submissionPayloadHash(body, [{ ...file, originalname: 'b.csv' }])).not.toBe(original);
    expect(submissionPayloadHash(body, [{ ...file, mimetype: 'application/pdf' }])).not.toBe(original);
    expect(submissionPayloadHash(body, [{ ...file, buffer: Buffer.from('b,a') }])).not.toBe(original);
    expect(submissionPayloadHash({ contactValue: body.contactValue, consentAgency: 'false', description: 'text' }, [file])).toBe(original);
  });

  it('allows one concurrent owner and later returns the same accepted receipt', async () => {
    const retryKey = key();
    let release!: () => void;
    let started!: () => void;
    const reached = new Promise<void>(resolve => { started = resolve; });
    jest.mocked(persistSubmissionEvidence).mockImplementation(async () => {
      started(); await new Promise<void>(resolve => { release = resolve; }); return [];
    });
    const original = submit(retryKey).then(response => response);
    await reached;
    const concurrent = await submit(retryKey);
    expect(concurrent.status).toBe(503);
    expect(concurrent.body.error).toBe('upload_capacity_busy');
    expect(concurrent.body.trackingId).toBeUndefined();
    release();
    const accepted = await original;
    const recovered = await submit(retryKey);
    expect(recovered.body).toEqual(accepted.body);
  });

  it('recovers after the response times out after report commit', async () => {
    const retryKey = key();
    let completed!: () => void;
    const drained = new Promise<void>(resolve => { completed = resolve; });
    const complete = submissionAttemptStore.completeIntake.bind(submissionAttemptStore);
    const completion = jest.spyOn(submissionAttemptStore, 'completeIntake').mockImplementationOnce(async keyHash => {
      await complete(keyHash);
      completed();
    });
    jest.mocked(reportPersistenceService.upsert).mockImplementationOnce(async report => {
      mockAccepted.set(report.trackingId, report);
      mockExpireResponse!();
    });
    const lost = await submit(retryKey);
    expect(lost.status).toBe(408);
    // A timed-out response intentionally retains transfer capacity until the
    // handler finishes its durable work; drain it before simulating a restart.
    await drained;
    await new Promise(resolve => setImmediate(resolve));
    completion.mockRestore();
    await submissionAttemptStore.close(); // new DB connection, no in-process reservation state
    const recovered = await submit(retryKey);
    expect(recovered.status).toBe(200);
    expect(recovered.body.success).toBe(true);
  });

  it('rejects changed consent with the same key and never reveals the receipt', async () => {
    const retryKey = key();
    expect((await submit(retryKey)).status).toBe(200);
    const changed = await submit(retryKey, 'true');
    expect(changed.status).toBe(409);
    expect(changed.body.error).toBe('idempotency_payload_mismatch');
    expect(changed.body.trackingId).toBeUndefined();
  });

  it('does not expose another receipt to someone with matching content but a different secret', async () => {
    const first = await submit(key());
    const second = await submit(key());
    expect(first.status).toBe(200); expect(second.status).toBe(200);
    expect(second.body.trackingId).not.toBe(first.body.trackingId);
  });

  it('resumes the same reservation after storage failure and connection restart', async () => {
    const retryKey = key();
    jest.mocked(persistSubmissionEvidence).mockRejectedValueOnce(new Error('connection lost'));
    expect((await submit(retryKey)).status).toBe(500);
    await submissionAttemptStore.close();
    const retry = await submit(retryKey);
    expect(retry.status).toBe(200);
  });

  it('recovers a crashed active HTTP intake with its original tracking ID', async () => {
    const retryKey = key();
    const payload = submissionPayloadHash({ description: 'Report with important evidence', wantsReward: 'false', consentAgency: 'false' }, []);
    const originalId = 'VRA-0123456789ABCDEF';
    await submissionAttemptStore.reserve(submissionKeyHash(retryKey), payload, originalId);
    const client = await MongoClient.connect(mongo.getUri());
    try {
      await client.db('receipt_recovery').collection('submission_attempts').updateOne(
        { keyHash: submissionKeyHash(retryKey) }, { $set: { leaseUntil: new Date(0) } });
    } finally { await client.close(); }
    await submissionAttemptStore.close();
    const recovered = await submit(retryKey);
    expect(recovered.status).toBe(200);
    expect(mockAccepted.has(originalId)).toBe(true);
    expect((await submit(retryKey)).body).toEqual(recovered.body);
  });

  it('retries publication after selection without encrypting or uploading the content again', async () => {
    const retryKey = key();
    jest.mocked(reportPersistenceService.upsert).mockRejectedValueOnce(new Error('synthetic publication outage'));
    expect((await submit(retryKey)).status).toBe(500);
    const selected = await submissionAttemptStore.get(submissionKeyHash(retryKey));
    expect(selected?.state).toBe('accepted');
    expect(selected?.evidenceHashVersion).toBe('sha256-framed-v2');
    expect(selected?.preparedIntake?.report.evidenceHashVersion).toBe('sha256-framed-v2');
    expect(persistSubmissionEvidence).toHaveBeenCalledTimes(1);
    await submissionAttemptStore.close();
    const recovered = await submit(retryKey);
    expect(recovered.status).toBe(200);
    expect(recovered.body).toMatchObject({ evidenceHash: selected?.evidenceHash, evidenceHashVersion: 'sha256-framed-v2' });
    expect(persistSubmissionEvidence).toHaveBeenCalledTimes(1);
  });

  it.each(['sha256-concat-v1', 'sha256-framed-v2'] as const)(
    'preserves %s when reclaiming a pre-existing expired intake lease', async version => {
      const retryKey = key();
      const keyHash = submissionKeyHash(retryKey);
      const body = { description: 'Report with important evidence', wantsReward: 'false', consentAgency: 'false' };
      const evidenceHash = evidenceCommitment(body.description, [], version);
      const originalId = `VRA-${retryKey.slice(-16).toUpperCase()}`;
      const reservation = await submissionAttemptStore.reserve(
        keyHash, submissionPayloadHash(body, []), originalId, evidenceHash,
        version === 'sha256-concat-v1' ? undefined : version,
      );
      const client = await MongoClient.connect(mongo.getUri());
      try {
        await client.db('receipt_recovery').collection('submission_attempts').updateOne(
          { keyHash }, { $set: { leaseUntil: new Date(0) } });
      } finally { await client.close(); }
      await submissionAttemptStore.close();
      const recovered = await submit(retryKey);
      expect(recovered.status).toBe(200);
      expect(recovered.body).toMatchObject({ evidenceHash, evidenceHashVersion: version });
      expect(mockAccepted.get(originalId)).toMatchObject({ evidenceHash, evidenceHashVersion: version });
      const completed = await submissionAttemptStore.get(keyHash);
      expect(completed?.state).toBe('complete');
      expect(completed?.leaseId).not.toBe(reservation.attempt.leaseId);
      expect(completed?.userId).toBe(reservation.attempt.userId);
      expect((await submit(retryKey)).body).toEqual(recovered.body);
    },
  );

  it.each([
    ['unknown', 503], ['proof_ready', 200],
  ] as const)('handles an attempt left %s by the former proof path without proving', async (state, status) => {
    const retryKey = key();
    const body = { description: 'Report with important evidence', wantsReward: 'false', consentAgency: 'false' };
    const keyHash = submissionKeyHash(retryKey);
    const legacyClient = new MongoClient(process.env.MONGODB_URI!);
    try {
      await legacyClient.connect();
      await legacyClient.db(process.env.MONGODB_DB_NAME).collection('submission_attempts').insertOne({
        keyHash, payloadHash: submissionPayloadHash(body, []), trackingId: `VRA-00000000000${state === 'unknown' ? '0EA02' : '0EA03'}`,
        evidenceHash: evidenceCommitment(body.description, [], 'sha256-concat-v1'), state, createdAt: new Date(), userId: 'legacy-synthetic-user',
        ...(state === 'proof_ready' ? { proof: { proofHash: 'f'.repeat(64), nullifier: 'a'.repeat(64), publicSignals: [], proofType: 'compact_circuit' } } : {}),
      });
    } finally { await legacyClient.close(); }
    await submissionAttemptStore.close();

    const response = await submit(retryKey);

    expect(response.status).toBe(status);
    if (state === 'unknown') {
      // Its on-chain outcome can no longer be resolved, so it is never resumed.
      expect(response.body.error).toBe('submission_in_progress');
      expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    } else {
      expect(response.body).toMatchObject({ success: true, proofStatus: 'not_applicable', zkProof: null });
      expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0].zkProof).toBeUndefined();
    }
  });
});
