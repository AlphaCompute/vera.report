import { EventEmitter } from 'node:events';
const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler,
} }));
jest.mock('@/lib/auditClient', () => ({ logAuditEventRequired: jest.fn(), logAuditEvent: jest.fn() }));
// Provider authorization is covered by currentAdminAuthorization.test.ts.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));

import evidence from '../../../pages/api/whistleblower/evidence/[trackingId]/[filename]';
import companion from '../../../pages/api/dissemination/[trackingId]/companion/[entityId]';
import { requestRateLimitKey } from '../../../src/utils/proxyRateLimit';
import { adminPollingKey } from '../../../src/utils/adminPollingQuota';

const trackingId = 'VRA-0123456789ABCDEF';
let saved: NodeJS.ProcessEnv;
beforeEach(() => {
  saved = { ...process.env };
  process.env.INTERNAL_API_SECRET = 'synthetic-transfer-quota-secret';
  process.env.BACKEND_URL = 'http://synthetic.invalid';
  process.env.ADMIN_ALLOWED_DOMAINS = '@example.org';
  process.env.TENANT_ORG_ID = 'org_test';
});
afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

it.each([
  [evidence, { trackingId, filename: 'file name.pdf' }],
  [companion, { trackingId, entityId: 'sec' }],
])('separates authenticated admins behind the same proxy', async (handler, query) => {
  const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ error: 'busy' }, { status: 503 }));
  const keys: string[] = [];
  for (const userId of ['auth0|admin-a', 'auth0|admin-b']) {
    mockSession.mockResolvedValue({ user: { sub: userId, email: 'qa@example.org', email_verified: true,
      org_id: 'org_test', 'https://vera.app/roles': ['admin'] } });
    const response = Object.assign(new EventEmitter(), { setHeader: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() });
    await handler({ method: 'GET', query, url: '/', socket: { remoteAddress: '127.0.0.1' },
      headers: { 'x-vera-rate-id': 'a'.repeat(64), 'x-vera-rate-signature': 'b'.repeat(64) } } as any, response as any);
    expect(fetchSpy).toHaveBeenCalledTimes(keys.length + 1);
    const [url, init] = fetchSpy.mock.calls.at(-1)!;
    const target = new URL(String(url));
    const request = { headers: init!.headers, method: 'GET', originalUrl: target.pathname + target.search,
      ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' } } as any;
    keys.push(requestRateLimitKey(request));
    expect(adminPollingKey(request)).toBeNull();
    expect(JSON.stringify(init!.headers)).not.toContain(userId);
    expect(requestRateLimitKey({ ...request, originalUrl: '/different' })).toMatch(/^ip:/);
  }
  expect(keys[0]).toMatch(/^web:/);
  expect(keys[0]).not.toBe(keys[1]);
});

it.each([evidence, companion])('does not sign or forward transfers for a denied account', async handler => {
  mockSession.mockResolvedValue({ user: { sub: 'auth0|not-an-admin', email: 'qa@example.org',
    email_verified: true, org_id: 'org_test', 'https://vera.app/roles': [] } });
  const fetchSpy = jest.spyOn(globalThis, 'fetch');
  const response = Object.assign(new EventEmitter(), { setHeader: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() });
  await handler({ method: 'GET', query: { trackingId, filename: 'file.pdf', entityId: 'sec' }, headers: {}, socket: {} } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(403);
  expect(fetchSpy).not.toHaveBeenCalled();
});
