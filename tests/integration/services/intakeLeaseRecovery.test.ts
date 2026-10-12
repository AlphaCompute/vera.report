import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { SubmissionAttemptStore, IntakeLeaseLostError } from '../../../src/services/submissionAttempt';
import { ReportPersistenceService, type ReportRecord } from '../../../src/services/reportPersistence';
import { createReporterAccess, receiptCode } from '../../../src/services/reporterAccess';

let mongo: MongoMemoryServer;
let db: MongoClient;
let attempts: SubmissionAttemptStore;
let reports: ReportPersistenceService;
let sequence = 0;
const env = { ...process.env };
beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongo.getUri();
  process.env.MONGODB_DB_NAME = 'intake_lease';
  db = await MongoClient.connect(mongo.getUri());
});
beforeEach(() => { attempts = new SubmissionAttemptStore(); reports = new ReportPersistenceService(); });
afterEach(async () => { await attempts.close(); await reports.close(); });
afterAll(async () => { await db?.close(); await mongo?.stop(); process.env = env; });
const collection = () => db.db('intake_lease').collection('submission_attempts');
async function reserve() {
  const key = (++sequence).toString(16).padStart(64, '0');
  const trackingId = 'VRA-' + sequence.toString(16).padStart(16, '0').toUpperCase();
  return { key, ...(await attempts.reserve(key, 'same-payload', trackingId, 'a'.repeat(64))) };
}
async function prepared(trackingId: string, marker: string) {
  const report: ReportRecord = {
    trackingId, evidenceHash: 'a'.repeat(64), reporterAccess: await createReporterAccess(trackingId),
    status: 'pending', createdAt: new Date(), updatedAt: new Date(), location: marker,
  };
  const evidence = [{ fileKey: trackingId + '/evidence-1.txt', encryptionKey: marker,
    originalCID: 'cid-' + marker, pinataIv: 'iv', pinataAuthTag: 'tag',
    evidenceSalt: 'salt', evidenceIv: 'iv', evidenceAuthTag: 'tag', mimetype: 'text/plain' }];
  return reports.prepareIntake(report, evidence);
}

it('recovers an abandoned reservation and fences a late owner from publication and release', async () => {
  const first = await reserve();
  expect(await attempts.claimRetry(first.key, 'same-payload')).toBeNull();
  await collection().updateOne({ keyHash: first.key }, { $set: { leaseUntil: new Date(0) } });
  await attempts.close();
  attempts = new SubmissionAttemptStore();
  const contenders = await Promise.all([attempts.claimRetry(first.key, 'same-payload'), attempts.claimRetry(first.key, 'same-payload')]);
  expect(contenders.filter(Boolean)).toHaveLength(1);
  const winner = contenders.find(Boolean)!;
  expect(winner.trackingId).toBe(first.attempt.trackingId);
  expect(winner.userId).toBe(first.attempt.userId);
  expect(winner.leaseId).not.toBe(first.attempt.leaseId);
  const selected = await prepared(winner.trackingId, 'selected');
  await attempts.acceptIntake(first.key, winner.leaseId!, selected);
  await expect(attempts.acceptIntake(first.key, first.attempt.leaseId!, await prepared(winner.trackingId, 'late')))
    .rejects.toBeInstanceOf(IntakeLeaseLostError);
  await expect(attempts.release(first.key, 'retryable', first.attempt.leaseId)).rejects.toThrow();
  const accepted = await reports.materializeIntake((await attempts.get(first.key))!.preparedIntake!);
  expect(accepted.location).toBe('selected');
  expect((await reports.getEvidenceParams(winner.trackingId + '/evidence-1.txt'))?.encryptionKey).toBe('selected');
});

it('replays an accepted encrypted plan after restart without replacing the receipt or later report changes', async () => {
  const first = await reserve();
  const selected = await prepared(first.attempt.trackingId, 'restart');
  const originalReceipt = await receiptCode(selected.report);
  await attempts.acceptIntake(first.key, first.attempt.leaseId!, selected);
  const raw = await collection().findOne({ keyHash: first.key });
  expect(raw?.preparedIntake.evidence[0].encryptionKey).toMatch(/^enc:/);
  expect(raw?.preparedIntake.evidence[0].encryptionKey).not.toBe('restart');
  await attempts.close(); await reports.close();
  attempts = new SubmissionAttemptStore(); reports = new ReportPersistenceService();
  expect(await attempts.claimRetry(first.key, 'same-payload')).toBeNull();
  const recovery = (await attempts.get(first.key))!.preparedIntake!;
  const [a, b] = await Promise.all([reports.materializeIntake(recovery), reports.materializeIntake(recovery)]);
  expect(await receiptCode(a)).toBe(originalReceipt);
  expect(await receiptCode(b)).toBe(originalReceipt);
  await reports.patch(a.trackingId, { status: 'reviewing' });
  expect((await reports.materializeIntake(recovery)).status).toBe('reviewing');
  await attempts.completeIntake(first.key);
  expect((await attempts.get(first.key))?.preparedIntake).toBeUndefined();
  expect((await attempts.get(first.key))?.state).toBe('complete');
});

it('replays a partial publication after a real report write failure', async () => {
  const first = await reserve();
  const selected = await prepared(first.attempt.trackingId, 'partial');
  await attempts.acceptIntake(first.key, first.attempt.leaseId!, selected);
  await reports.get(first.attempt.trackingId); // Initialize collections/indexes.
  await db.db('intake_lease').command({ collMod: 'whistleblower_reports', validator: { trackingId: { $ne: first.attempt.trackingId } } });
  try {
    await expect(reports.materializeIntake(selected)).rejects.toThrow();
    expect(await reports.get(first.attempt.trackingId)).toBeNull();
    expect((await attempts.get(first.key))?.state).toBe('accepted');
  } finally { await db.db('intake_lease').command({ collMod: 'whistleblower_reports', validator: {} }); }
  await reports.close(); reports = new ReportPersistenceService();
  expect((await reports.materializeIntake((await attempts.get(first.key))!.preparedIntake!)).location).toBe('partial');
  expect(await reports.listEvidenceByTrackingIds([first.attempt.trackingId])).toHaveLength(1);
});

it.each(['legacy-active', 'unknown-proof'])('never reclaims an ambiguous %s by age', async kind => {
  const first = await reserve();
  await collection().updateOne({ keyHash: first.key }, kind === 'legacy-active'
    ? { $unset: { protocol: '', leaseId: '' }, $set: { leaseUntil: new Date(0) } }
    : { $set: { state: 'unknown', leaseUntil: new Date(0) } });
  expect(await attempts.claimRetry(first.key, 'same-payload')).toBeNull();
});

it('does not grant an expired reservation to changed content', async () => {
  const first = await reserve();
  await collection().updateOne({ keyHash: first.key }, { $set: { leaseUntil: new Date(0) } });
  expect(await attempts.claimRetry(first.key, 'different-payload')).toBeNull();
});
