import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { ReportPersistenceService, reportPersistenceService, ReportRecord } from '../../../src/services/reportPersistence';

// Durable provider double: encrypted bytes live on disk, never in a Map.
let mockStoragePath: string;
const mockUpload = jest.fn(async (bytes: Buffer) => {
  const cid = crypto.createHash('sha256').update(bytes).digest('hex');
  await writeFile(path.join(mockStoragePath, cid), bytes);
  return { originalCID: cid, iv: 'provider-iv', authTag: 'provider-tag' };
});
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: {
  uploadEncryptedFile: (...args: [Buffer]) => mockUpload(...args),
} }));
jest.mock('../../../src/services/evidenceEncryption', () => ({ evidenceEncryptionService: {
  encryptEvidence: async (bytes: Buffer, _mime: string, key: string) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
    return { encryptedData: encrypted.toString('base64'), encryptionMetadata: {
      salt: 'test-salt', iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'),
    }, contentMetadata: { hash: crypto.createHash('sha256').update(bytes).digest('hex'), size: bytes.length } };
  },
} }));
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';

const report = (trackingId: string): ReportRecord => ({ trackingId, status: 'pending',
  encryptedDescription: 'encrypted-narrative', createdAt: new Date(), updatedAt: new Date() });

describe('Durable report acceptance', () => {
  let mongo: MongoMemoryServer;
  let service: ReportPersistenceService;
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), 'vera-intake-'));
    mockStoragePath = dir;
    mongo = await MongoMemoryServer.create({ instance: { storageEngine: 'wiredTiger' } });
    process.env.MONGODB_URI = mongo.getUri();
    process.env.MONGODB_DB_NAME = 'durable_intake';
    service = new ReportPersistenceService();
  });
  afterAll(async () => {
    await service?.close();
    await reportPersistenceService.close();
    await mongo?.stop();
    await rm(dir, { recursive: true, force: true });
    process.env.MONGODB_URI = '';
    process.env.MONGODB_DB_NAME = '';
  });

  it('rejects writes and reads when no database is configured', async () => {
    const uri = process.env.MONGODB_URI;
    process.env.MONGODB_URI = '';
    const unavailable = new ReportPersistenceService();
    try {
      await expect(unavailable.upsert(report('missing'))).rejects.toThrow('MONGODB_URI');
      await expect(unavailable.get('missing')).rejects.toThrow('MONGODB_URI');
    } finally { process.env.MONGODB_URI = uri; await unavailable.close(); }
  });

  it('propagates an actual MongoDB rejected write instead of accepting it in memory', async () => {
    await service.upsert(report('setup'));
    const client = await MongoClient.connect(process.env.MONGODB_URI!);
    try {
      await client.db('durable_intake').command({ collMod: 'whistleblower_reports', validator: {
        trackingId: { $ne: 'rejected' },
      } });
      await expect(service.upsert(report('rejected'))).rejects.toThrow();
      expect(await service.get('rejected')).toBeNull();
    } finally { await client.close(); }
  });

  it('retains both same-name evidence files and their decryption keys after database and service restart', async () => {
    const id = 'VRA-1234567890ABCDEF';
    const bodies = [Buffer.from('first evidence'), Buffer.from('second evidence')];
    const files = bodies.map(buffer => ({ originalname: 'same.csv', mimetype: 'text/csv', buffer }) as Express.Multer.File);
    const manifest = await persistSubmissionEvidence(id, files);
    await service.upsert(report(id));
    expect(new Set(manifest.map(entry => entry.fileKey)).size).toBe(2);
    await service.close();
    await reportPersistenceService.close();
    await mongo.stop({ doCleanup: false });
    await mongo.start();
    process.env.MONGODB_URI = mongo.getUri();
    service = new ReportPersistenceService();
    expect((await service.get(id))?.encryptedDescription).toBe('encrypted-narrative');
    const restored = await service.listEvidenceByTrackingIds([id]);
    expect(restored).toHaveLength(2);
    for (const [index, entry] of manifest.entries()) {
      const params = await service.getEvidenceParams(entry.fileKey);
      expect(params).not.toBeNull();
      expect(params!.contentHash).toBe(crypto.createHash('sha256').update(bodies[index]).digest('hex'));
      expect(params!.contentSize).toBe(bodies[index].length);
      const ciphertext = await readFile(path.join(dir, params!.originalCID));
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(params!.encryptionKey, 'hex'), Buffer.from(params!.evidenceIv, 'hex'));
      decipher.setAuthTag(Buffer.from(params!.evidenceAuthTag, 'hex'));
      expect(Buffer.concat([decipher.update(ciphertext), decipher.final()])).toEqual(bodies[index]);
    }
  });

  it('rejects an upload when MongoDB rejects its decryption manifest', async () => {
    const client = await MongoClient.connect(process.env.MONGODB_URI!);
    const id = 'VRA-BBBBBBBBBBBBBBBB';
    try {
      await client.db('durable_intake').command({ collMod: 'evidence_decryption_params', validator: {
        fileKey: { $not: { $regex: `^${id}/` } },
      } });
      await expect(persistSubmissionEvidence(id, [{ originalname: 'same.csv', mimetype: 'text/csv', buffer: Buffer.from('x') } as Express.Multer.File])).rejects.toThrow();
      expect(await service.listEvidenceByTrackingIds([id])).toEqual([]);
      expect(await service.get(id)).toBeNull();
    } finally { await client.close(); }
  });

  it('propagates provider failure; partial manifests never create an accepted report', async () => {
    mockUpload.mockRejectedValueOnce(new Error('storage offline'));
    const id = 'VRA-AAAAAAAAAAAAAAAA';
    await expect(persistSubmissionEvidence(id, [{ originalname: 'same.csv', mimetype: 'text/csv', buffer: Buffer.from('x') } as Express.Multer.File])).rejects.toThrow('storage offline');
    expect(await service.get(id)).toBeNull();
  });
});
