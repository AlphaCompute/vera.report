import express from 'express';
import request from 'supertest';
import { apiTrustProxyHops } from '../../../src/utils/trustProxy';
import { MAX_PROCESS_UPLOADS } from '../../../src/utils/evidenceLimits';
import { proxyAdminRateLimitHeaders, proxyRecipientRateLimitHeaders } from '../../../src/utils/proxyRateLimit';

test('production proxy chain partitions reporters behind one edge within the synced two-slot ceiling', async () => {
  let budget!: typeof import('../../../src/middleware/uploadBudget');
  jest.isolateModules(() => { budget = require('../../../src/middleware/uploadBudget'); });
  budget.configureUploadReadiness(async () => true);
  const app = express();
  app.set('trust proxy', apiTrustProxyHops({ API_TRUST_PROXY_HOPS: '2' }));
  let release!: () => void, admitted!: () => void;
  const work = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { admitted = resolve; });
  app.post('/submit', budget.reserveUpload, budget.withUploadBudget(async (_req, res) => {
    admitted();
    await work; res.sendStatus(204);
  }));
  app.get('/evidence', budget.reserveUpload, budget.withUploadBudget(async (_req, res) => { res.sendStatus(204); }));
  const first = request(app).post('/submit').set('X-Forwarded-For', '192.0.2.10, 198.51.100.1, 203.0.113.1').then(r => r);
  try {
    await ready;
    // Same edge, different reporter: evidence retrieval remains available.
    await request(app).get('/evidence').set('X-Forwarded-For', '198.51.100.3, 203.0.113.1').expect(204);
    // Forging the prefix and changing edge does not give reporter 1 a new slot.
    await request(app).get('/evidence').set('X-Forwarded-For', '192.0.2.99, 198.51.100.1, 203.0.113.2').expect(503);
  } finally { release(); await first; }
  await request(app).get('/evidence').set('X-Forwarded-For', '198.51.100.1, 203.0.113.1').expect(204);
});

test('retains the two-slot process cap and rejects invalid trust settings', () => {
  expect(MAX_PROCESS_UPLOADS).toBe(2);
  for (const raw of ['true', '-1', '2.0', '10']) expect(() => apiTrustProxyHops({ API_TRUST_PROXY_HOPS: raw })).toThrow();
});

test.each([
  ['admins', proxyAdminRateLimitHeaders], ['recipient capabilities', proxyRecipientRateLimitHeaders],
] as const)('two verified %s behind one proxy can transfer while each retains a one-slot cap', async (_kind, quotaHeaders) => {
  const original = process.env.INTERNAL_API_SECRET;
  process.env.INTERNAL_API_SECRET = 'synthetic-admin-admission-test';
  let budget!: typeof import('../../../src/middleware/uploadBudget');
  jest.isolateModules(() => { budget = require('../../../src/middleware/uploadBudget'); });
  budget.configureUploadReadiness(async () => true);
  const app = express();
  let release!: () => void, admitted!: () => void;
  const work = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { admitted = resolve; });
  app.get('/hold', budget.reserveUpload, budget.withUploadBudget(async (_req, res) => {
    admitted(); await work; res.sendStatus(204);
  }));
  app.get('/evidence', budget.reserveUpload, budget.withUploadBudget(async (_req, res) => { res.sendStatus(204); }));
  const first = request(app).get('/hold').set(quotaHeaders('synthetic-first-principal', 'GET', '/hold')).then(r => r);
  try {
    await ready;
    await request(app).get('/evidence').set(quotaHeaders('synthetic-first-principal', 'GET', '/evidence')).expect(503);
    await request(app).get('/evidence').set(quotaHeaders('synthetic-second-principal', 'GET', '/evidence')).expect(204);
  } finally {
    release(); await first;
    if (original === undefined) delete process.env.INTERNAL_API_SECRET;
    else process.env.INTERNAL_API_SECRET = original;
  }
});
