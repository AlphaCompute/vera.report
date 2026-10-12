import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { DisseminationPersistenceService } from '../../../src/services/dissemination/disseminationPersistence';
import type { SubmissionDoc, DispositionDoc, ReceiptDoc } from '../../../src/services/dissemination/types';

const submission = (id: string): SubmissionDoc => ({
  submissionId: id, trackingId: id, entityId: 'eeoc', tier: 'C', idempotencyKey: id,
  state: 'approved', packetVersion: 1, attempts: 0, createdAt: new Date(), updatedAt: new Date(),
  counsel: { counselId: 'counsel-1', counselName: 'Legal', contactHandle: 'secure', matterCode: 'M-ABC' },
});
const disposition = (id: string): DispositionDoc => ({
  trackingId: id, channels: [{ entityId: 'eeoc', tier: 'C', state: 'approved' }],
  consentSnapshot: { psst: { granted: false }, agency: true, capturedAt: new Date(), textVersion: 'v1' },
  approvedBy: 'admin', createdAt: new Date(), updatedAt: new Date(),
});
const receipt = (id: string): ReceiptDoc => ({
  trackingId: id, submissionId: id, entityId: 'eeoc', type: 'manual', value: 'case-received',
  receivedAt: new Date(), createdAt: new Date(),
});

describe('Legal backend durable persistence', () => {
  let mongo: MongoMemoryServer;
  let service: DisseminationPersistenceService;
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create({ instance: { storageEngine: 'wiredTiger', args: ['--setParameter', 'enableTestCommands=1'] } });
    process.env.MONGODB_URI = mongo.getUri(); process.env.MONGODB_DB_NAME = 'legal_durability';
    service = new DisseminationPersistenceService();
  });
  afterAll(async () => {
    await service.disconnect(); await mongo.stop();
    process.env.MONGODB_URI = ''; process.env.MONGODB_DB_NAME = '';
  });

  it.each(['production', 'development'])('rejects missing storage in %s instead of accepting in memory', async mode => {
    const uri = process.env.MONGODB_URI; const env = process.env.NODE_ENV;
    process.env.MONGODB_URI = ''; process.env.NODE_ENV = mode;
    const unavailable = new DisseminationPersistenceService();
    try {
      await expect(unavailable.upsertDisposition(disposition('missing'))).rejects.toThrow('MONGODB_URI');
      await expect(unavailable.insertReceipt(receipt('missing'))).rejects.toThrow('MONGODB_URI');
      await expect(unavailable.appendAudit({ trackingId: 'missing', event: 'assigned', actor: 'admin' })).rejects.toThrow('MONGODB_URI');
      await expect(unavailable.getSubmission('missing')).rejects.toThrow('MONGODB_URI');
      await expect(unavailable.tryAcquireLock('worker', 10000)).rejects.toThrow('MONGODB_URI');
    } finally { process.env.MONGODB_URI = uri; process.env.NODE_ENV = env; await unavailable.disconnect(); }
  });

  it('preserves assignments, consent, receipts and audit events through database/service restart', async () => {
    await Promise.all([
      service.upsertDisposition(disposition('accepted')),
      service.insertSubmission(submission('accepted')),
      service.insertReceipt(receipt('accepted')),
      service.appendAudit({ trackingId: 'accepted', event: 'counsel-assigned', actor: 'admin' }),
    ]);
    await service.disconnect();
    await mongo.stop({ doCleanup: false }); await mongo.start();
    process.env.MONGODB_URI = mongo.getUri();
    service = new DisseminationPersistenceService();
    expect((await service.getDisposition('accepted'))?.consentSnapshot.agency).toBe(true);
    expect((await service.getSubmission('accepted'))?.counsel?.matterCode).toBe('M-ABC');
    expect((await service.getReceiptsForReport('accepted'))[0].value).toBe('case-received');
    expect((await service.getAuditForReport('accepted'))[0].event).toBe('counsel-assigned');
  });

  it('propagates actual Mongo validation failures for dispositions, submissions, receipts and audit', async () => {
    const client = await MongoClient.connect(process.env.MONGODB_URI!);
    try {
      for (const collection of ['dispositions', 'submissions', 'dissemination_receipts', 'dissemination_audit_log']) {
        await client.db('legal_durability').command({ collMod: collection, validator: { trackingId: { $ne: 'rejected' } } });
      }
      await expect(service.upsertDisposition(disposition('rejected'))).rejects.toThrow();
      await expect(service.insertSubmission(submission('rejected'))).rejects.toThrow();
      await expect(service.insertReceipt(receipt('rejected'))).rejects.toThrow();
      await expect(service.appendAudit({ trackingId: 'rejected', event: 'counsel-assigned', actor: 'admin' })).rejects.toThrow();
      expect(await service.getDisposition('rejected')).toBeNull();
      expect(await service.getSubmission('rejected')).toBeNull();
      expect(await service.getReceiptsForReport('rejected')).toEqual([]);
      expect(await service.getAuditForReport('rejected')).toEqual([]);
    } finally { await client.close(); }
  });

  it('does not turn a database read failure into an empty legal queue', async () => {
    const client = await MongoClient.connect(process.env.MONGODB_URI!);
    try {
      await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['find'], errorCode: 2 } });
      await expect(service.getSubmissionsForReport('accepted')).rejects.toThrow();
    } finally { await client.close(); }
  });

  it('clears partially initialized handles after failed setup and reconnects on retry', async () => {
    const client = await MongoClient.connect(process.env.MONGODB_URI!);
    const recovering = new DisseminationPersistenceService();
    try {
      await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['createIndexes'], errorCode: 2 } });
      await expect(recovering.getSubmission('accepted')).rejects.toThrow();
      expect((recovering as any).client).toBeNull();
      expect((recovering as any).submissions).toBeNull();
      expect((await recovering.getSubmission('accepted'))?.submissionId).toBe('accepted');
    } finally { await recovering.disconnect(); await client.close(); }
  });

  it('preserves duplicate insertion and single claimant behavior', async () => {
    expect(await service.insertSubmission(submission('claimable'))).toBe(true);
    expect(await service.insertSubmission(submission('claimable'))).toBe(false);
    // Remove the other claimable fixture from this test's dispatch queue.
    await service.patchSubmission('accepted', { state: 'closed' });
    const claims = await Promise.all([service.claimNextDueSubmission(new Date()), service.claimNextDueSubmission(new Date())]);
    expect(claims.filter(Boolean)).toHaveLength(1);
    expect(claims.find(Boolean)?.submissionId).toBe('claimable');
    expect(await service.tryAcquireLock('one-worker', 10000)).toBe(true);
    expect(await service.tryAcquireLock('one-worker', 10000)).toBe(false);
  });
});
