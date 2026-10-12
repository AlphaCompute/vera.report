import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { ReportPersistenceService } from '../../../src/services/reportPersistence';
import { reporterCodeHash } from '../../../src/services/reporterAccess';

const code = `VRC-${'A'.repeat(64)}`;
const target = 'VRA-0123456789ABCDEF';
let mongo: MongoMemoryServer;
let client: MongoClient;
let service: ReportPersistenceService;
const env = { ...process.env };
beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongo.getUri();
  process.env.MONGODB_DB_NAME = 'admin_search_test';
  client = await MongoClient.connect(mongo.getUri());
  service = new ReportPersistenceService();
  await service.list(1);
  await client.db('admin_search_test').collection('whistleblower_reports').insertMany([
    ...Array.from({ length: 105 }, (_, i) => ({ trackingId: `VRA-${i.toString(16).padStart(16, '0')}`, category: 'other', status: 'pending', createdAt: new Date(2026, 8, 17), updatedAt: new Date() })),
    { trackingId: target, category: 'ai-safety', status: 'pending', createdAt: new Date(2026, 0, 1), updatedAt: new Date(), reporterAccess: { hash: reporterCodeHash(code), encryptedCode: 'not-returned' } },
  ]);
});
afterAll(async () => { await service?.close(); await client?.close(); await mongo?.stop(); process.env = env; });
it('finds an older report outside the initial 100 by VRC hash and VRA ID', async () => {
  expect((await service.list(100)).some(r => r.trackingId === target)).toBe(false);
  for (const query of [code.toLowerCase(), ` ${target.toLowerCase()} `]) {
    expect((await service.searchAdmin(query)).map(r => r.trackingId)).toEqual([target]);
  }
});
it('searches category in the database, escapes regex metacharacters and returns no match honestly', async () => {
  expect((await service.searchAdmin('AI-SAFETY')).map(r => r.trackingId)).toEqual([target]);
  expect(await service.searchAdmin('.*')).toEqual([]);
  expect(await service.searchAdmin(`VRC-${'B'.repeat(64)}`)).toEqual([]);
});
it('returns a bounded extra row so the API can signal truncation', async () => {
  expect(await service.searchAdmin('other', 101)).toHaveLength(101);
});
