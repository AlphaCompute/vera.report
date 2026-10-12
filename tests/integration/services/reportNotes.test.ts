import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { ReportPersistenceService } from '../../../src/services/reportPersistence';

let mongo: MongoMemoryServer;
let client: MongoClient;
let service: ReportPersistenceService;
const savedEnv = { ...process.env };
const trackingId = 'VRA-0123456789ABCDEF';
beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongo.getUri();
  process.env.MONGODB_DB_NAME = 'report-notes-test';
  process.env.AT_REST_LOCAL_KEY = '11'.repeat(32);
  delete process.env.KMS_AT_REST_KEY_ID;
  client = await new MongoClient(mongo.getUri()).connect();
  service = new ReportPersistenceService();
  await client.db('report-notes-test').collection('whistleblower_reports').insertOne({ trackingId, status: 'pending' });
});
afterAll(async () => {
  await service?.close();
  await client?.close();
  await mongo?.stop();
  process.env = savedEnv;
});
it('retains concurrent notes across reconnects while encrypting text and author at rest', async () => {
  const notes = await Promise.all([
    service.addInternalNote(trackingId, 'Private note alpha', 'author-alpha'),
    service.addInternalNote(trackingId, 'Private note beta', 'author-beta'),
  ]);
  expect(notes.every(note => note && !Number.isNaN(Date.parse(note.timestamp)))).toBe(true);
  const raw = await client.db('report-notes-test').collection('whistleblower_reports').findOne({ trackingId });
  expect(raw?.internalNotes).toHaveLength(2);
  expect(JSON.stringify(raw)).not.toContain('Private note');
  expect(JSON.stringify(raw)).not.toContain('author-alpha');
  await service.close();
  expect(await service.listInternalNotes(trackingId)).toEqual(expect.arrayContaining(notes));
});
it('returns not found instead of creating an orphan note', async () => {
  expect(await service.addInternalNote('VRA-FFFFFFFFFFFFFFFF', 'Missing report', 'admin')).toBeNull();
  expect(await service.listInternalNotes('VRA-FFFFFFFFFFFFFFFF')).toBeNull();
});
it('rejects ciphertext copied to another report', async () => {
  const collection = client.db('report-notes-test').collection('whistleblower_reports');
  const raw = await collection.findOne({ trackingId });
  await collection.insertOne({ trackingId: 'VRA-AAAAAAAAAAAAAAAA', internalNotes: raw?.internalNotes });
  await expect(service.listInternalNotes('VRA-AAAAAAAAAAAAAAAA')).rejects.toThrow();
});

it('persists every status transition, including reopening, without duplicate no-op events', async () => {
  await service.setAdminStatus(trackingId, 'reviewing');
  await service.setAdminStatus(trackingId, 'investigating');
  await service.setAdminStatus(trackingId, 'resolved');
  await service.setAdminStatus(trackingId, 'pending');
  await service.setAdminStatus(trackingId, 'pending');
  await service.close();
  const saved = await service.get(trackingId);
  expect(saved?.status).toBe('pending');
  expect(saved?.statusHistory?.map(entry => entry.status)).toEqual(['reviewing', 'investigating', 'resolved', 'pending']);
  expect(new Set(saved?.statusHistory?.map(entry => entry.id)).size).toBe(4);
  expect(saved?.statusHistory?.every(entry => !Number.isNaN(Date.parse(entry.timestamp)))).toBe(true);
  await expect(service.setAdminStatus('VRA-FFFFFFFFFFFFFFFF', 'reviewing')).rejects.toThrow();
});
