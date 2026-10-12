const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler,
} }));

import stats from '../../../pages/api/admin/dashboard/stats';
import reports from '../../../pages/api/admin/dashboard/reports';
import alerts from '../../../pages/api/dissemination/alerts';
import dissemination from '../../../pages/api/dissemination/[trackingId]/[action]';
import { adminPollingHeaders, adminPollingKey } from '../../../src/utils/adminPollingQuota';

const secret = 'synthetic-proxy-quota-test-secret';
const userId = 'auth0|verified-user';
let saved: NodeJS.ProcessEnv;
let fetchSpy: jest.SpiedFunction<typeof fetch>;
function res() { return { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() }; }
function session(roles = ['admin']) { return { user: { sub: userId, email: 'qa@example.org', email_verified: true, org_id: 'org_test', 'https://vera.app/roles': roles } }; }
beforeEach(() => {
  saved = { ...process.env };
  process.env.INTERNAL_API_SECRET = secret;
  process.env.BACKEND_URL = 'http://synthetic.invalid';
  process.env.ADMIN_ALLOWED_DOMAINS = '@example.org';
  process.env.TENANT_ORG_ID = 'org_test';
  mockSession.mockResolvedValue(session());
  fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    String(url).endsWith('/audit-log') ? Response.json({ success: true }) :
      Response.json({ error: 'Rate limited', retryAfter: 900 }, { status: 429, headers: { 'Retry-After': '37' } }));
});
afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

it.each([
  [stats, {}, '/api/whistleblower/admin/stats'],
  [reports, { limit: '100' }, '/api/whistleblower/admin/reports?limit=100'],
  [alerts, {}, '/api/dissemination/alerts'],
  [dissemination, { trackingId: 'VRA-0123456789ABCDEF', action: 'status' }, '/api/dissemination/VRA-0123456789ABCDEF/status'],
  [dissemination, { trackingId: 'VRA-0123456789ABCDEF', action: 'relay' }, '/api/dissemination/VRA-0123456789ABCDEF/relay'],
])('keeps verified-session quotas and upstream cooldowns through %s', async (handler, query, path) => {
  const response = res();
  await handler({ method: 'GET', query, url: '/', socket: {}, headers: { ...adminPollingHeaders('forged-user', 'GET', path) } } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(429);
  expect(response.setHeader).toHaveBeenCalledWith('Retry-After', '37');
  const upstream = fetchSpy.mock.calls[0];
  expect(upstream[0]).toBe(`http://synthetic.invalid${path}`);
  const forwarded = { headers: upstream[1]!.headers, method: 'GET', originalUrl: path } as any;
  const expected = { ...forwarded, headers: { 'x-internal-secret': secret, ...adminPollingHeaders(userId, 'GET', path) } };
  expect(adminPollingKey(forwarded)).not.toBeNull();
  expect(adminPollingKey(forwarded)).toBe(adminPollingKey(expected));
  // Stats/reports audit writes use the same verified user budget.
  for (const [url, init] of fetchSpy.mock.calls.slice(1)) {
    expect(url).toBe('http://synthetic.invalid/api/admin/audit-log');
    expect(adminPollingKey({ headers: init!.headers, method: 'POST', originalUrl: '/api/admin/audit-log' } as any)).toBe(adminPollingKey(expected));
  }
});

it('preserves the cooldown on employee report projection without exposing the upstream error', async () => {
  mockSession.mockResolvedValue(session(['employee']));
  const response = res();
  await reports({ method: 'GET', query: {}, headers: {}, socket: {} } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(429);
  expect(response.setHeader).toHaveBeenCalledWith('Retry-After', '37');
  expect(response.json).toHaveBeenCalledWith({ success: false, error: 'Failed to fetch reports' });
});

it('does not forward a signed request for a denied session', async () => {
  mockSession.mockResolvedValue(session([]));
  const response = res();
  await stats({ method: 'GET', query: {}, headers: {}, socket: {} } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(403);
  expect(fetchSpy).not.toHaveBeenCalled();
});

it('keeps search credentials in the POST body and out of upstream URLs and audit data', async () => {
  fetchSpy.mockResolvedValue(Response.json({ success: true, data: { reports: [] } }));
  const code = `VRC-${'A'.repeat(64)}`;
  const response = res();
  await reports({ method: 'POST', query: {}, body: { query: code }, url: '/api/admin/dashboard/reports', headers: {}, socket: {} } as any, response as any);
  const [url, init] = fetchSpy.mock.calls[0];
  expect(url).toBe('http://synthetic.invalid/api/whistleblower/admin/reports/search');
  expect(init?.method).toBe('POST');
  expect(adminPollingKey({ headers: init!.headers, method: 'POST', originalUrl: '/api/whistleblower/admin/reports/search' } as any)).not.toBeNull();
  expect(JSON.parse(String(init?.body))).toEqual({ query: code });
  expect(JSON.stringify(fetchSpy.mock.calls.slice(1))).not.toContain(code);
  expect(response.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
});
it('denies employee code searches before calling the backend', async () => {
  mockSession.mockResolvedValue(session(['employee']));
  const response = res();
  await reports({ method: 'POST', query: {}, body: { query: `VRC-${'A'.repeat(64)}` }, headers: {}, socket: {} } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(403); expect(fetchSpy).not.toHaveBeenCalled();
});
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));
