jest.mock('../../../src/config/env', () => ({ env: { SHROUD_API_KEY: 'synthetic-local-key', SHROUD_BASE_URL: 'http://127.0.0.1', SHROUD_MODEL: 'local-test-model' } }));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
import crypto from 'node:crypto';
import { MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { reportPersistenceService as reports, type ReportRecord } from '../../../src/services/reportPersistence';
import { ReportScoringWorker } from '../../../src/services/reportScoringWorker';
import { encryptReportNarrative } from '../../../src/services/reportNarrative';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
useDisseminationMongo();
const result: any = { isLegitimate: true, credibilityScore: 80, category: 'other', organizationType: 'unknown', namedOrganization: null, spamIndicators: [], contentAnalysis: 'PRIVATE ANALYSIS', riskLevel: 'medium' };
async function seed(overrides: Partial<ReportRecord> = {}) {
  const trackingId = 'VRA-' + crypto.randomBytes(8).toString('hex').toUpperCase();
  const record: ReportRecord = { trackingId, status: 'reviewing', processingStatus: 'processing', encryptedDescription: encryptContactValue('PRIVATE NARRATIVE'), scoringJob: { state: 'pending', attempts: 0, nextAttemptAt: new Date(0) }, createdAt: new Date(), updatedAt: new Date(), ...overrides };
  if (record.scoringJob === undefined) delete record.scoringJob;
  await reports.upsert(record);
  return trackingId;
}
test('accepted scoring survives connection restart and keeps analysis encrypted and human status intact', async () => {
  const id = await seed();
  await reports.patch(id, { encryptedNarrative: await encryptReportNarrative(id, 'PRIVATE NARRATIVE'), encryptedDescription: 'corrupt legacy value' });
  await reports.close();
  const verify = jest.fn().mockResolvedValue(result);
  const worker = new ReportScoringWorker(verify);
  await worker.tick(id);
  expect(verify).toHaveBeenCalledWith({ description: 'PRIVATE NARRATIVE', evidenceType: 'other', hasEvidence: false }, expect.any(AbortSignal));
  const row = await reports.get(id);
  expect(row?.status).toBe('reviewing');
  expect(row?.processingStatus).toBe('completed');
  expect(row?.verification?.contentAnalysis).toBe('PRIVATE ANALYSIS');
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  try {
    const raw = await client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports').findOne({ trackingId:id });
    expect(JSON.stringify(raw)).not.toMatch(/PRIVATE ANALYSIS|PRIVATE NARRATIVE/);
  } finally { await client.close(); }
  await worker.tick(id);
  expect(verify).toHaveBeenCalledTimes(1);
  await worker.close();
});
test('a replacement worker reclaims expired work and fences the old result', async () => {
  const id = await seed();
  const now = new Date();
  const old = (await reports.claimScoring(now, id))!;
  const verify = jest.fn().mockResolvedValue(result);
  const worker = new ReportScoringWorker(verify, () => new Date(now.getTime()+301_000));
  await worker.tick(id);
  expect(await reports.finishScoring(old, { processingStatus:'failed' })).toBe(false);
  expect((await reports.get(id))?.processingStatus).toBe('completed');
  await worker.close();
});
test('transient scoring failure retries after backoff but stops after five attempts', async () => {
  const id = await seed(); let now = new Date();
  const verify = jest.fn().mockRejectedValue(new Error('PRIVATE PROVIDER RESPONSE'));
  const worker = new ReportScoringWorker(verify, () => now);
  for (let i=0;i<5;i++) {
    await worker.tick(id);
    await worker.tick(id); // Not due: never burn a second attempt immediately.
    now = new Date(now.getTime()+3_000_000);
  }
  await worker.tick(id);
  expect(verify).toHaveBeenCalledTimes(5);
  const row=await reports.get(id);
  expect(row?.processingStatus).toBe('failed');
  expect(row?.verification).toBeUndefined();
  expect(row?.scoringJob?.lastError).toBe('scoring_unavailable');
  await worker.close();
});
test('corrupt encrypted narrative never reaches the inference provider', async () => {
  const id=await seed({ encryptedDescription:'enc:corrupt' });
  const verify=jest.fn(); const worker=new ReportScoringWorker(verify);
  await worker.tick(id);
  expect(verify).not.toHaveBeenCalled();
  expect((await reports.get(id))?.verification).toBeUndefined();
  await worker.close();
});
test('recovers legacy processing records without copying a second narrative payload', async () => {
  const id=await seed({scoringJob:undefined});
  const verify=jest.fn().mockResolvedValue(result); const worker=new ReportScoringWorker(verify);
  await worker.tick(id); expect(verify).toHaveBeenCalledTimes(1);
  expect((await reports.get(id))?.scoringJob?.state).toBe('completed');
  await worker.close();
});

const humanStatuses = ['pending', 'reviewing', 'investigating', 'resolved', 'dismissed'] as const;
test.each(humanStatuses.flatMap(status => ([true, false, 'failure'] as const).map(outcome => ({ status, outcome }))))(
  'late scoring $outcome preserves the concurrent human decision $status', async ({ status, outcome }) => {
    const id = await seed({ status: 'pending' });
    let announce!: () => void;
    let finish: (() => void) | undefined;
    const entered = new Promise<void>(resolve => { announce = resolve; });
    const verify = jest.fn(() => new Promise<typeof result>((resolve, reject) => {
      finish = () => outcome === 'failure'
        ? reject(new Error('Synthetic scoring outage'))
        : resolve({ ...result, isLegitimate: outcome });
      announce();
    }));
    const worker = new ReportScoringWorker(verify);
    const processing = worker.tick(id);
    try {
      await Promise.race([entered, processing]);
      expect(verify).toHaveBeenCalledTimes(1);
      await reports.patch(id, { status });
      finish!();
      await processing;
      const stored = await reports.get(id);
      expect(stored?.status).toBe(status);
      expect(stored?.processingStatus).toBe(outcome === 'failure' ? 'processing' : 'completed');
      expect(stored?.scoringJob?.state).toBe(outcome === 'failure' ? 'pending' : 'completed');
      if (outcome === 'failure') expect(stored?.verification).toBeUndefined();
      else expect(stored?.verification?.isLegitimate).toBe(outcome);
    } finally {
      finish?.();
      await worker.close();
    }
  },
);

test.each([0, 4])('shutdown cancels inference and preserves recovery after %i prior failures', async attempts => {
  const id = await seed({ scoringJob: { state: 'pending', attempts, nextAttemptAt: new Date(0) } });
  let entered!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  let receivedSignal: AbortSignal | undefined;
  let rejectInference: ((error: Error) => void) | undefined;
  const verify = jest.fn((_report: unknown, signal?: AbortSignal) => new Promise<typeof result>((_resolve, reject) => {
    rejectInference = reject;
    receivedSignal = signal;
    signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
    entered();
  }));
  const worker = new ReportScoringWorker(verify);
  const pending = worker.tick(id);
  try {
    await Promise.race([started, pending]);
    expect(receivedSignal).toBeDefined();
    await worker.close();
    await pending;
    expect(receivedSignal?.aborted).toBe(true);
    const stopped = await reports.get(id);
    expect(stopped?.scoringJob).toMatchObject({ state: 'pending', attempts, lastError: 'worker_stopped' });
    expect(stopped?.processingStatus).toBe('processing');
    expect(stopped?.verification).toBeUndefined();
    await reports.close();
    const replacement = new ReportScoringWorker(jest.fn().mockResolvedValue(result));
    try {
      await replacement.tick(id);
      expect((await reports.get(id))?.scoringJob?.state).toBe('completed');
    } finally { await replacement.close(); }
  } finally { rejectInference?.(new Error('Test cleanup')); await worker.close(); }
});

test('an interrupted stale worker cannot reset its replacement result', async () => {
  const id = await seed();
  const now = new Date();
  let entered!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  let rejectInference: ((error: Error) => void) | undefined;
  const old = new ReportScoringWorker((_report, signal) => new Promise((_resolve, reject) => {
    rejectInference = reject;
    signal!.addEventListener('abort', () => reject(signal!.reason), { once: true });
    entered();
  }), () => now);
  const pending = old.tick(id);
  const replacement = new ReportScoringWorker(jest.fn().mockResolvedValue(result), () => new Date(now.getTime() + 301_000));
  try {
    await Promise.race([started, pending]);
    await replacement.tick(id);
    await old.close();
    await pending;
    const stored = await reports.get(id);
    expect(stored?.scoringJob?.state).toBe('completed');
    expect(stored?.verification?.contentAnalysis).toBe(result.contentAnalysis);
  } finally { rejectInference?.(new Error('Test cleanup')); await old.close(); await replacement.close(); }
});

test('worker shutdown cancels the actual scoring HTTP request and persists its interrupted job', async () => {
  const { createServer } = await import('node:http');
  const { env } = await import('../../../src/config/env');
  const { verifyReport } = jest.requireActual<typeof import('../../../src/services/reportScoring')>('../../../src/services/reportScoring');
  const saved = { base: env.SHROUD_BASE_URL, key: env.SHROUD_API_KEY };
  let entered!: () => void;
  let disconnected!: () => void;
  const received = new Promise<void>(resolve => { entered = resolve; });
  const closed = new Promise<void>(resolve => { disconnected = resolve; });
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    req.resume();
    res.once('close', disconnected);
    entered();
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing local server address');
  Object.assign(env, { SHROUD_BASE_URL: `http://127.0.0.1:${address.port}`, SHROUD_API_KEY: 'synthetic-local-key' });
  const worker = new ReportScoringWorker(verifyReport);
  try {
    const id = await seed();
    const pending = worker.tick(id);
    await Promise.race([received, pending]);
    expect(requests).toBe(1);
    await worker.close();
    await pending;
    await closed;
    const stored = await reports.get(id);
    expect(stored?.scoringJob).toMatchObject({ state: 'pending', attempts: 0, lastError: 'worker_stopped' });
    expect(stored?.verification).toBeUndefined();
    expect(requests).toBe(1);
  } finally {
    await worker.close();
    Object.assign(env, { SHROUD_BASE_URL: saved.base, SHROUD_API_KEY: saved.key });
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});


describe('scoring provider configuration pause', () => {
  beforeEach(async () => {
    const client = await new MongoClient(process.env.MONGODB_URI!).connect();
    try { await client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports').deleteMany({}); }
    finally { await client.close(); }
  });

  test('missing Shroud configuration leaves pending, expired, legacy and failed records untouched, then resumes eligible work', async () => {
    const { env } = await import('../../../src/config/env');
    const key = env.SHROUD_API_KEY;
    const now = new Date();
    const pending = await seed({ scoringJob: { state: 'pending', attempts: 4, nextAttemptAt: new Date(0) } });
    const expired = await seed({ scoringJob: { state: 'running', attempts: 2, nextAttemptAt: new Date(0), leaseId: 'existing-lease' } });
    const legacy = await seed({ scoringJob: undefined });
    const failed = await seed({ processingStatus: 'failed', scoringJob: { state: 'failed', attempts: 5, nextAttemptAt: new Date(0), lastError: 'scoring_unavailable' } });
    const ids = [pending, expired, legacy, failed];
    const before = await Promise.all(ids.map(id => reports.get(id)));
    const verify = jest.fn().mockResolvedValue(result);
    const worker = new ReportScoringWorker(verify, () => now);
    const claim = jest.spyOn(reports, 'claimScoring');
    try {
      env.SHROUD_API_KEY = undefined;
      for (let n = 0; n < 8; n++) { await worker.tick(); await worker.tick(pending); }
      expect(claim).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
      expect(await Promise.all(ids.map(id => reports.get(id)))).toEqual(before);
      await worker.close();
      await reports.close();
      env.SHROUD_API_KEY = key;
      const restarted = new ReportScoringWorker(verify, () => now);
      try {
        await restarted.tick();
        expect(verify).toHaveBeenCalledTimes(3);
        expect((await reports.get(pending))?.scoringJob).toMatchObject({ state: 'completed', attempts: 5 });
        expect((await reports.get(expired))?.scoringJob).toMatchObject({ state: 'completed', attempts: 3 });
        expect((await reports.get(legacy))?.scoringJob).toMatchObject({ state: 'completed', attempts: 1 });
        expect(await reports.get(failed)).toEqual(before[3]);
      } finally { await restarted.close(); }
    } finally { env.SHROUD_API_KEY = key; claim.mockRestore(); await worker.close(); }
  });

  test('configuration pause between jobs neither claims the next job nor refunds completed provider work', async () => {
    const first = await seed();
    const second = await seed();
    const before = await Promise.all([first, second].map(id => reports.get(id)));
    let configured = true;
    const verify = jest.fn(async () => { configured = false; return result; });
    const worker = new ReportScoringWorker(verify, () => new Date(), () => configured);
    try {
      await worker.tick();
      expect(verify).toHaveBeenCalledTimes(1);
      const after = await Promise.all([first, second].map(id => reports.get(id)));
      expect(after.filter(record => record?.scoringJob?.state === 'completed')).toHaveLength(1);
      const pendingIndex = after.findIndex(record => record?.scoringJob?.state === 'pending');
      expect(after[pendingIndex]).toEqual(before[pendingIndex]);
      expect(after.find(record => record?.scoringJob?.state === 'completed')?.scoringJob?.attempts).toBe(1);
    } finally { await worker.close(); }
  });

  test('configured invalid credentials consume exactly five provider attempts and preserve terminal failure', async () => {
    const { createServer } = await import('node:http');
    const { env } = await import('../../../src/config/env');
    const { verifyReport } = jest.requireActual<typeof import('../../../src/services/reportScoring')>('../../../src/services/reportScoring');
    const previous = { base: env.SHROUD_BASE_URL, key: env.SHROUD_API_KEY };
    let requests = 0;
    const server = createServer((req, res) => {
      requests++;
      req.resume();
      res.writeHead(401, { 'content-type': 'text/plain' });
      res.end('PRIVATE AUTHENTICATION FAILURE');
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing local server address');
    Object.assign(env, { SHROUD_BASE_URL: `http://127.0.0.1:${address.port}`, SHROUD_API_KEY: 'synthetic-invalid-key' });
    let now = new Date();
    const worker = new ReportScoringWorker(verifyReport, () => now);
    try {
      const id = await seed();
      for (let n = 0; n < 8; n++) { await worker.tick(id); now = new Date(now.getTime() + 3_000_000); }
      expect(requests).toBe(5);
      const failed = await reports.get(id);
      expect(failed?.processingStatus).toBe('failed');
      expect(failed?.scoringJob).toMatchObject({ state: 'failed', attempts: 5, lastError: 'scoring_unavailable' });
      expect(failed?.verification).toBeUndefined();
      expect(JSON.stringify(failed)).not.toContain('PRIVATE AUTHENTICATION FAILURE');
      env.SHROUD_API_KEY = undefined;
      await worker.tick(id);
      expect(await reports.get(id)).toEqual(failed);
    } finally {
      await worker.close();
      Object.assign(env, { SHROUD_BASE_URL: previous.base, SHROUD_API_KEY: previous.key });
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

});
