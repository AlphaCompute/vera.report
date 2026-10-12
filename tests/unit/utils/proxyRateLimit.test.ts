import express, { type Request } from 'express';
import request from 'supertest';
import type { Server } from 'node:http';
import type { NextApiRequest, NextApiResponse } from 'next';
import { proxyClientQuotaKey, proxyRateLimitHeaders, requestRateLimitKey } from '../../../src/utils/proxyRateLimit';
import { createRateLimiter } from '../../../src/middleware/security';
import { requireInternalSecret } from '../../../src/middleware/internalSecret';
import submit from '../../../pages/api/whistleblower/submit';
import status from '../../../pages/api/whistleblower/status/[trackingId]';

const secret = 'synthetic-proxy-secret-with-at-least-32-characters';
const path = '/api/whistleblower/submit';
const source = (ip: string, headers = {}) => ({ socket: { remoteAddress: ip }, headers });
const incoming = (headers: Record<string, string>, method = 'POST', url = path) => ({
  headers, method, originalUrl: url, ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' },
}) as Request;
let saved: NodeJS.ProcessEnv;
beforeEach(() => {
  saved = { ...process.env };
  process.env.INTERNAL_API_SECRET = secret;
  process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
});
afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

it('keeps client quotas distinct without transmitting raw IPs or the internal secret', () => {
  const a = proxyRateLimitHeaders(source('198.51.100.1'), 'POST', path);
  const b = proxyRateLimitHeaders(source('198.51.100.2'), 'POST', path);
  expect(requestRateLimitKey(incoming(a))).toMatch(/^web:/);
  expect(requestRateLimitKey(incoming(a))).not.toBe(requestRateLimitKey(incoming(b)));
  expect(JSON.stringify(a)).not.toMatch(/198\.51\.100|synthetic-proxy-secret/);
  expect(a).not.toHaveProperty('x-internal-secret');
  expect(proxyClientQuotaKey(source('198.51.100.1'))).toBe(a['x-vera-rate-id']);
  expect(proxyClientQuotaKey(source('198.51.100.2'))).toBe(b['x-vera-rate-id']);
});

it('ignores forged forwarding headers in direct mode and untrusted prefixes behind two hops', () => {
  const direct = proxyRateLimitHeaders(source('198.51.100.3'), 'POST', path);
  const spoof = proxyRateLimitHeaders(source('198.51.100.3', { 'x-forwarded-for': '1.1.1.1' }), 'POST', path);
  expect(direct['x-vera-rate-id']).toBe(spoof['x-vera-rate-id']);
  process.env.FRONTEND_TRUST_PROXY_HOPS = '2';
  const trusted = proxyRateLimitHeaders(source('127.0.0.1', { 'x-forwarded-for': '1.1.1.1, 198.51.100.3, 203.0.113.4' }), 'POST', path);
  expect(trusted['x-vera-rate-id']).toBe(direct['x-vera-rate-id']);
});

it.each(['-1', '1.5', '10', 'all'])('rejects invalid proxy depth %s', depth => {
  process.env.FRONTEND_TRUST_PROXY_HOPS = depth;
  expect(() => proxyRateLimitHeaders(source('127.0.0.1'), 'POST', path)).toThrow('FRONTEND_TRUST_PROXY_HOPS');
});

it('fails closed when configured proxy information or signing configuration is missing', () => {
  process.env.FRONTEND_TRUST_PROXY_HOPS = '2';
  expect(() => proxyRateLimitHeaders(source('127.0.0.1'), 'POST', path)).toThrow('Trusted client address');
  process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
  delete process.env.INTERNAL_API_SECRET;
  expect(() => proxyRateLimitHeaders(source('127.0.0.1'), 'POST', path)).toThrow('INTERNAL_API_SECRET');
});

it('groups IPv6 addresses in the same subnet and rotates identities daily', () => {
  jest.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
  const a = proxyRateLimitHeaders(source('2001:db8:1234:5600::1'), 'POST', path);
  const b = proxyRateLimitHeaders(source('2001:db8:1234:5600::2'), 'POST', path);
  expect(a['x-vera-rate-id']).toBe(b['x-vera-rate-id']);
  jest.spyOn(Date, 'now').mockReturnValue(1_800_086_400_000);
  expect(proxyRateLimitHeaders(source('2001:db8:1234:5600::1'), 'POST', path)['x-vera-rate-id']).not.toBe(a['x-vera-rate-id']);
  expect(requestRateLimitKey(incoming(a))).toMatch(/^ip:/);
});

it('rejects modified signatures, client IDs, timestamps, methods and paths', () => {
  const headers = proxyRateLimitHeaders(source('198.51.100.1'), 'POST', path);
  for (const changed of [
    { ...headers, 'x-vera-rate-id': 'ab'.repeat(32) },
    { ...headers, 'x-vera-rate-signature': '00'.repeat(32) },
    { ...headers, 'x-vera-rate-signature': 'invalid' },
    { ...headers, 'x-vera-rate-time': String(Date.now() + 120_000) },
    {},
  ]) expect(requestRateLimitKey(incoming(changed))).toMatch(/^ip:/);
  expect(requestRateLimitKey(incoming(headers, 'GET'))).toMatch(/^ip:/);
  expect(requestRateLimitKey(incoming(headers, 'POST', '/different'))).toMatch(/^ip:/);
});

it('preserves independent quotas through the real streaming Next proxies and denies internal access', async () => {
  const backend = express();
  backend.use(createRateLimiter(900_000, 5));
  backend.post(path, (_req, res) => res.status(400).json({ error: 'invalid report' }));
  backend.get('/api/whistleblower/status/:trackingId', (_req, res) => res.status(404).json({ error: 'not found' }));
  backend.get('/internal', requireInternalSecret, (_req, res) => res.json({ ok: true }));
  const server = await new Promise<Server>(resolve => { const s = backend.listen(0, '127.0.0.1', () => resolve(s)); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing fixture address');
  process.env.BACKEND_URL = `http://127.0.0.1:${address.port}`;
  process.env.FRONTEND_TRUST_PROXY_HOPS = '1'; // Test ingress: one controlled forwarding hop.
  const frontend = express();
  frontend.post(path, (req, res) => { void submit(req as unknown as NextApiRequest, res as unknown as NextApiResponse); });
  frontend.get('/api/whistleblower/status/:trackingId', (req, res) => {
    Object.defineProperty(req, 'query', { value: req.params });
    void status(req as unknown as NextApiRequest, res as unknown as NextApiResponse);
  });
  try {
    for (let i = 0; i < 5; i++) {
      const result = await request(frontend).post(path).set('x-forwarded-for', '198.51.100.10').send('invalid');
      expect(result.status).toBe(400);
    }
    expect((await request(frontend).post(path).set('x-forwarded-for', '198.51.100.10').send('invalid')).status).toBe(429);
    expect((await request(frontend).post(path).set('x-forwarded-for', '198.51.100.11').send('invalid')).status).toBe(400);
    expect((await request(frontend).get('/api/whistleblower/status/example').set('x-forwarded-for', '198.51.100.12')).status).toBe(404);
    process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
    const quotaOnly = proxyRateLimitHeaders(source('198.51.100.13'), 'GET', '/internal');
    expect((await request(backend).get('/internal').set(quotaOnly)).status).toBe(401);
    expect((await request(backend).get('/internal').set('x-internal-secret', secret)).status).toBe(200);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

describe('confidential relay quotas behind CloudFront -> ALB (API_TRUST_PROXY_HOPS=2)', () => {
  it('admits two viewers sharing one CloudFront edge independently and ignores forged prefixes', async () => {
    const { createConfidentialChannelRouter } = await import('../../../src/api/confidentialChannel');
    const app = express();
    app.set('trust proxy', 2);
    app.use(createConfidentialChannelRouter(async () => { throw new Error('unavailable'); }, { maxPerMinute: 2 }));
    const open = (xff: string, n: number) => request(app).post('/channel/open').set('Content-Type', 'application/json')
      .set('X-Forwarded-For', xff).send({ nonce: n.toString(16).padStart(64, '0') });
    const statuses = [];
    // The attacker rotates a forged left-most entry; the quota still follows the viewer CloudFront saw.
    for (let n = 1; n <= 3; n++) statuses.push((await open(`10.9.9.${n}, 203.0.113.66, 130.176.1.1`, n)).status);
    expect(statuses[2]).toBe(429);
    expect((await open('198.51.100.7, 130.176.1.1', 10)).status).not.toBe(429);
  });
});
