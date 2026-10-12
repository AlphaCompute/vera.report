import express, { type Request } from 'express';
import request from 'supertest';
import { adminPollingHeaders, adminPollingKey } from '../../../src/utils/adminPollingQuota';
import { proxyRateLimitHeaders, requestRateLimitKey } from '../../../src/utils/proxyRateLimit';
import { apiRateLimiter } from '../../../src/middleware/security';
import { requireInternalSecret } from '../../../src/middleware/internalSecret';

const secret = 'synthetic-admin-polling-secret';
const stats = '/api/whistleblower/admin/stats';
const reports = '/api/whistleblower/admin/reports?limit=100';
const alerts = '/api/dissemination/alerts';
const audit = '/api/admin/audit-log';
const source = { headers: {}, socket: { remoteAddress: '198.51.100.15' } };
const incoming = (headers: Record<string, string>, method = 'GET', path = stats) => ({
  headers, method, originalUrl: path, ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' },
}) as Request;
const signed = (user = 'auth0|admin-a', method = 'GET', path = stats) => ({
  'x-internal-secret': secret, ...adminPollingHeaders(user, method, path),
});
let saved: NodeJS.ProcessEnv;
beforeEach(() => { saved = { ...process.env }; process.env.INTERNAL_API_SECRET = secret; process.env.FRONTEND_TRUST_PROXY_HOPS = '0'; });
afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

it('isolates users behind one proxy without sending their identities', () => {
  const a = signed(), b = signed('auth0|admin-b');
  expect(adminPollingKey(incoming(a))).toMatch(/^admin:/);
  expect(requestRateLimitKey(incoming(a))).not.toBe(requestRateLimitKey(incoming(b)));
  expect(JSON.stringify(a)).not.toContain('auth0|');
  expect(adminPollingHeaders('auth0|admin-a', 'GET', stats)).not.toHaveProperty('x-internal-secret');
});

it('requires internal authentication and signatures bound to method, complete path, time and identity', () => {
  const valid = signed();
  for (const changed of [
    {}, { 'x-internal-secret': secret },
    { ...valid, 'x-internal-secret': '' }, { ...valid, 'x-internal-secret': 'forged' },
    { ...valid, 'x-vera-admin-rate-id': 'ab'.repeat(32) },
    { ...valid, 'x-vera-admin-rate-signature': 'ff'.repeat(32) },
    { ...valid, 'x-vera-admin-rate-signature': 'invalid' },
    { ...valid, 'x-vera-admin-rate-time': String(Date.now() - 120_000) },
    { ...valid, 'x-vera-admin-rate-time': String(Date.now() + 120_000) },
    { ...valid, ...proxyRateLimitHeaders(source, 'GET', stats), 'x-vera-admin-rate-signature': '' },
  ]) expect(adminPollingKey(incoming(changed))).toBeNull();
  expect(adminPollingKey(incoming(valid, 'POST'))).toBeNull();
  expect(adminPollingKey(incoming(valid, 'GET', reports))).toBeNull();
  expect(adminPollingKey(incoming(valid, 'GET', `${stats}?extra=1`))).toBeNull();
  expect(adminPollingKey(incoming(proxyRateLimitHeaders(source, 'GET', stats)))).toBeNull();
});

it.each([
  ['POST', '/api/whistleblower/submit'], ['POST', '/api/dissemination/VRA-0123456789ABCDEF/secure-packet-email'],
  ['POST', '/api/dissemination/VRA-0123456789ABCDEF/relay'], ['GET', '/api/dissemination/secure-packet/token'],
  ['PATCH', '/api/whistleblower/admin/reports/VRA-0123456789ABCDEF/status'], ['GET', '/api/admin/audit-logs'],
])('cannot select polling quotas for %s %s', (method, path) => {
  expect(adminPollingHeaders('admin', method, path)).toEqual({});
  expect(adminPollingKey(incoming(signed(), method, path))).toBeNull();
});

it('selects the polling quota for the encrypted-report directory only as a body-cursor POST', () => {
  const listings = '/api/admin/confidential/listings';
  expect(adminPollingKey(incoming(signed('auth0|admin-a', 'POST', listings), 'POST', listings))).toMatch(/^admin:/);
  // The case-ID cursor never rides in a URL, so the old GET form gets no polling budget.
  expect(adminPollingHeaders('admin', 'GET', listings)).toEqual({});
  expect(adminPollingKey(incoming(signed('auth0|admin-a', 'GET', listings), 'GET', listings))).toBeNull();
});

it('keeps one user budget across polling endpoints and rotates the pseudonym daily', () => {
  jest.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
  const first = adminPollingKey(incoming(signed()));
  for (const [method, path] of [['GET', reports], ['GET', alerts], ['POST', audit], ['GET', '/api/dissemination/VRA-0123456789ABCDEF/status'], ['GET', '/api/dissemination/VRA-0123456789ABCDEF/relay']]) {
    expect(adminPollingKey(incoming(signed('auth0|admin-a', method, path), method, path))).toBe(first);
  }
  jest.spyOn(Date, 'now').mockReturnValue(1_800_086_400_000);
  expect(adminPollingKey(incoming(signed()))).not.toBe(first);
});

it('survives 15 minutes of normal polling, bounds bursts, and leaves public and other-user quotas independent', async () => {
  // Real Express limiter/memory stores; advance only Date.now so local sockets stay real.
  let now = Date.now();
  jest.spyOn(Date, 'now').mockImplementation(() => now);
  const app = express();
  app.use(apiRateLimiter);
  app.get('/public', (_req, res) => res.json({ ok: true }));
  app.use(requireInternalSecret);
  app.use((_req, res) => res.json({ ok: true }));
  const publicHeaders = proxyRateLimitHeaders(source, 'GET', '/public');
  for (let i = 0; i < 100; i++) expect((await request(app).get('/public').set(publicHeaders)).status).toBe(200);
  expect((await request(app).get('/public').set(publicHeaders)).status).toBe(429);
  for (let tick = 0; tick < 31; tick++) {
    for (const [method, path] of [['GET', stats], ['POST', audit], ['GET', reports], ['POST', audit], ['GET', alerts]]) {
      const call = method === 'POST' ? request(app).post(path) : request(app).get(path);
      expect((await call.set(signed('normal-polling', method, path))).status).toBe(200);
    }
    now += 30_000;
  }
  for (let i = 0; i < 60; i++) expect((await request(app).get(stats).set(signed('burst-user'))).status).toBe(200);
  now += 20_000;
  const limited = await request(app).get(stats).set(signed('burst-user'));
  expect(limited.status).toBe(429);
  expect(Number(limited.headers['retry-after'])).toBe(40);
  expect(limited.body.retryAfter).toBe(40);
  expect((await request(app).get(stats).set(signed('another-user'))).status).toBe(200);
  now += 40_001;
  expect((await request(app).get(stats).set(signed('burst-user'))).status).toBe(200);
  const quotaOnly = adminPollingHeaders('unsigned-auth-user', 'GET', stats);
  expect((await request(app).get(stats).set(quotaOnly)).status).toBe(401);
});
