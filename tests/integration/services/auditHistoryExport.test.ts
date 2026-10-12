import express from 'express';
import { performance } from 'node:perf_hooks';
import request from 'supertest';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
jest.mock('../../../src/utils/retry', () => ({ retryWithBackoff: jest.fn(async () => ({ ok: false })) }));
import router from '../../../src/api/dissemination';
import { auditCommitmentRoot, AuditAnchorService } from '../../../src/services/dissemination/auditAnchor';
import { disseminationPersistence as persistence } from '../../../src/services/dissemination/disseminationPersistence';
import type { AuditAnchorDoc } from '../../../src/services/dissemination/types';

const app = express().use('/api/dissemination', router);
const original = { uri: process.env.MONGODB_URI, db: process.env.MONGODB_DB_NAME, secret: process.env.INTERNAL_API_SECRET };
let mongo: MongoMemoryServer;
let client: MongoClient;
let sequence = 0;
beforeAll(async () => { mongo = await MongoMemoryServer.create(); client = await MongoClient.connect(mongo.getUri()); });
beforeEach(async () => {
  await persistence.disconnect();
  process.env.MONGODB_URI = mongo.getUri(); process.env.MONGODB_DB_NAME = `history_export_${sequence++}`;
  process.env.INTERNAL_API_SECRET = 'synthetic-history-secret';
});
afterEach(() => { jest.restoreAllMocks(); });
afterAll(async () => {
  await persistence.disconnect(); await client.close(); await mongo.stop();
  for (const [key, value] of [['MONGODB_URI', original.uri], ['MONGODB_DB_NAME', original.db], ['INTERNAL_API_SECRET', original.secret]]) {
    if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
  }
});
const store = async (name: string, prevRoot?: string) => {
  const batchRoot = createHash('sha256').update(name).digest('hex');
  const anchor: AuditAnchorDoc = { anchorId: randomUUID(), commitmentVersion: 2, batchRoot, eventCount: 1,
    root: auditCommitmentRoot(batchRoot, 1, prevRoot), ...(prevRoot ? { prevRoot } : {}),
    leaves: [{ eventId: name, leafHash: batchRoot }], firstEventAt: new Date(0), lastEventAt: new Date(0),
    anchoredAt: new Date(0), network: 'local' };
  await persistence.insertAuditAnchor(anchor);
  expect(anchor).not.toHaveProperty('_id');
  return anchor;
};
const page = (head: string, tail = 'genesis', limit = '2') => request(app).get('/api/dissemination/anchors/history')
  .query({ head, tail, limit }).set('x-internal-secret', process.env.INTERNAL_API_SECRET!);

it('exports a complete paginated path from real MongoDB and verifies it independently', async () => {
  const first = await store('first'); const second = await store('second', first.root); const third = await store('third', second.root);
  await client.db(process.env.MONGODB_DB_NAME).collection('audit_anchors').updateOne({ root: first.root }, { $set: { anchoredAt: new Date('2100-01-01') } });
  const one = await page(third.root);
  expect(one.status).toBe(200);
  expect(one.body).toMatchObject({ complete: false, nextRoot: first.root, stopReason: 'page_limit' });
  expect(one.body.anchors.map((anchor: { root: string }) => anchor.root)).toEqual([third.root, second.root]);
  await persistence.disconnect();
  const two = await page(one.body.nextRoot);
  expect(two.body).toMatchObject({ complete: true, nextRoot: null, stopReason: 'checkpoint' });
  const anchors = [...one.body.anchors, ...two.body.anchors];
  expect(anchors.every(anchor => !('leaves' in anchor) && anchor.network === 'local')).toBe(true);
  const verified = spawnSync('python3', ['scripts/verify-audit-history.py', '--head', third.root, '--tail', 'genesis'], {
    input: JSON.stringify({ anchors }), encoding: 'utf8', timeout: 10_000,
  });
  expect(verified.status).toBe(0);
  expect(JSON.parse(verified.stdout)).toMatchObject({ consistent: true, anchorCount: 3 });
});

it('refuses missing and legacy links without labelling a partial export complete', async () => {
  const missing = 'a'.repeat(64), anchor = await store('incomplete', missing);
  expect((await page(anchor.root)).body).toMatchObject({ complete: false, stopReason: 'missing_anchor', nextRoot: missing });
  const legacy = { ...anchor, anchorId: randomUUID(), root: missing };
  delete legacy.commitmentVersion; delete legacy.batchRoot;
  await persistence.insertAuditAnchor(legacy);
  expect((await page(anchor.root)).body).toMatchObject({ complete: false, stopReason: 'legacy_boundary', nextRoot: missing });
  expect((await page(anchor.root, missing)).body).toMatchObject({ complete: true, stopReason: 'checkpoint', nextRoot: missing });
});

it('rejects duplicate roots and changed predecessor metadata', async () => {
  const anchor = await store('corrupt');
  const records = client.db(process.env.MONGODB_DB_NAME).collection('audit_anchors');
  await records.updateOne({ root: anchor.root }, { $set: { prevRoot: 'b'.repeat(64) } });
  expect((await page(anchor.root)).status).toBe(500);
  await records.updateOne({ root: anchor.root }, { $unset: { prevRoot: '' }, $set: { txHash: 'x'.repeat(513) } });
  expect((await page(anchor.root)).status).toBe(500);
  await records.updateOne({ root: anchor.root }, { $unset: { txHash: '' } });
  await persistence.insertAuditAnchor({ ...anchor, anchorId: randomUUID() });
  expect((await page(anchor.root)).status).toBe(500);
});

it('validates access and bounds before reading history', async () => {
  const read = jest.spyOn(persistence, 'findAuditHistoryEntry');
  expect((await request(app).get('/api/dissemination/anchors/history')).status).toBe(401);
  expect((await page('invalid')).status).toBe(400);
  expect((await page('a'.repeat(64), 'genesis', '101')).status).toBe(400);
  expect(read).not.toHaveBeenCalled();
});

it('rejects a lookup that completes after the traversal deadline', async () => {
  await persistence.listAuditAnchors();
  const clock = jest.spyOn(performance, 'now').mockReturnValue(0);
  jest.spyOn(persistence, 'findAuditHistoryEntry').mockImplementationOnce(async () => { clock.mockReturnValue(10_001); return null; });
  await expect(new AuditAnchorService().exportHistory('a'.repeat(64), null)).rejects.toThrow('timed out');
});
