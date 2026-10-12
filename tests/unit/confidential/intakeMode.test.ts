import { securityHeaders, usesConfidentialRouteQuota } from '../../../src/middleware/security';
import express from 'express';
import request from 'supertest';
import { confidentialIntakeOnly } from '../../../src/middleware/confidentialIntakeOnly';
import { execFileSync } from 'node:child_process';
import { confidentialCasesEnabled } from '../../../lib/confidential/config';
import submitProxy from '../../../pages/api/whistleblower/submit';

const original = { backend: process.env.CONFIDENTIAL_CASES_ENABLED, frontend: process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES };
afterEach(() => {
  for (const [key, value] of [['CONFIDENTIAL_CASES_ENABLED', original.backend], ['NEXT_PUBLIC_CONFIDENTIAL_CASES', original.frontend]]) {
    if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
  }
});

test('confidential intake is the default and only explicit 0 selects legacy', () => {
  delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  expect(confidentialCasesEnabled()).toBe(true);
  for (const value of ['', '1', 'false', 'unexpected']) {
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = value;
    expect(confidentialCasesEnabled()).toBe(true);
  }
  process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';
  expect(confidentialCasesEnabled()).toBe(false);
});
test.each([undefined, '', '1'])('confidential build (%s) without manifest is rejected', flag => {
  const env = { ...process.env, NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: '' };
  if (flag === undefined) delete env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  else env.NEXT_PUBLIC_CONFIDENTIAL_CASES = flag;
  expect(() => execFileSync(process.execPath, ['-e', "require('./next.config.js')"], {
    cwd: process.cwd(), stdio: 'pipe', env,
  })).toThrow(/Confidential frontend requires a release manifest/);
});

test('legacy builds require an explicit opt-out but no confidential manifest', () => {
  expect(() => execFileSync(process.execPath, ['-e', "require('./next.config.js')"], {
    cwd: process.cwd(), stdio: 'pipe', env: { ...process.env, NEXT_PUBLIC_CONFIDENTIAL_CASES: '0', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: '' },
  })).not.toThrow();
});

test('default development rewrites cannot bypass the plaintext submission guard', () => {
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_ENV: 'development', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: 'synthetic-test-release', BACKEND_URL: 'http://localhost:3001' };
  delete env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  delete env.VERA_DEV_CONFIDENTIAL_API_ORIGIN;
  delete env.CONFIDENTIAL_BACKEND_URL;
  const output = execFileSync(process.execPath, ['-e', "require('./next.config.js').rewrites().then(value => process.stdout.write(JSON.stringify(value)))"], {
    cwd: process.cwd(), encoding: 'utf8', env,
  });
  expect(JSON.parse(output)).toEqual([{ source: '/api/confidential/:path*', destination: 'http://localhost:3001/api/confidential/:path*' }]);
});
test.each(['submit', 'analyze'])('backend cutover rejects legacy %s before any body parser', async endpoint => {
  const parsed = jest.fn();
  const app = express();
  app.use(securityHeaders);
  app.post(`/api/whistleblower/${endpoint}`, confidentialIntakeOnly);
  app.use(express.json({ verify: parsed }));
  app.post(`/api/whistleblower/${endpoint}`, (_req, res) => { res.sendStatus(204); });
  process.env.CONFIDENTIAL_CASES_ENABLED = 'true';
  const response = await request(app).post(`/api/whistleblower/${endpoint}`).send({ report: 'PRIVATE-SENTINEL' }).expect(409);
  expect(response.headers['x-content-type-options']).toBe('nosniff');
  expect(response.headers['content-security-policy']).toContain("default-src 'self'");
  expect(response.headers['cache-control']).toBe('no-store');
  expect(parsed).not.toHaveBeenCalled();
  process.env.CONFIDENTIAL_CASES_ENABLED = 'false';
  await request(app).post(`/api/whistleblower/${endpoint}`).send({ report: 'legacy' }).expect(204);
  expect(parsed).toHaveBeenCalledTimes(1);
});
test.each([undefined, '', '1'])('frontend proxy (%s) rejects old plaintext submissions before reading them', async flag => {
  if (flag === undefined) delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  else process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = flag;
  const json = jest.fn(), status = jest.fn(() => ({ json }));
  await submitProxy({ method: 'POST' } as never, { setHeader: jest.fn(), status } as never);
  expect(status).toHaveBeenCalledWith(409);
  expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'confidential_intake_required' }));
});

test('only mounted enabled confidential endpoints use their dedicated bounded quotas', () => {
  process.env.CONFIDENTIAL_CASES_ENABLED = 'true';
  for (const path of ['/api/confidential/channel/open', '/api/confidential/channel/call', '/api/confidential/objects']) {
    expect(usesConfidentialRouteQuota({ method: 'POST', path })).toBe(true);
    expect(usesConfidentialRouteQuota({ method: 'GET', path })).toBe(false);
  }
  for (const path of ['/api/confidential/other', '/api/confidential/channel/open/extra', '/api/whistleblower/submit']) {
    expect(usesConfidentialRouteQuota({ method: 'POST', path })).toBe(false);
  }
  process.env.CONFIDENTIAL_CASES_ENABLED = 'false';
  expect(usesConfidentialRouteQuota({ method: 'POST', path: '/api/confidential/channel/open' })).toBe(false);
});

test('a confidential frontend paired with a disabled backend still blocks legacy plaintext', async () => {
  process.env.CONFIDENTIAL_CASES_ENABLED = 'false';
  process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '1';
  const parsed = jest.fn();
  const app = express();
  app.use(securityHeaders);
  app.post('/api/whistleblower/submit', confidentialIntakeOnly);
  app.use(express.json({ verify: parsed }));
  app.post('/api/whistleblower/submit', (_req, res) => { res.sendStatus(204); });
  await request(app).post('/api/whistleblower/submit').send({ content: 'PRIVATE-SENTINEL' }).expect(409);
  expect(parsed).not.toHaveBeenCalled();
});
