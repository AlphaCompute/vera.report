/**
 * Admin "re-analyze" proxy — pages/api/admin/dashboard/reports/[reportId]/analyze
 *
 * This is the Next handler that #595 re-pointed off ElizaOS. Its job is narrow but
 * security-relevant, so these are its invariants:
 *   - it targets the Express Shroud/Mongo reanalyze endpoint, never an Eliza agent;
 *   - it forwards the internal secret (and refuses to call the backend without one);
 *   - the tracking id is URL-encoded (no path injection through :reportId);
 *   - the backend's status and body pass straight through, success or failure;
 *   - a non-admin is denied before the backend is ever reached.
 */

import type { NextApiRequest, NextApiResponse } from 'next';
import { ROLES_CLAIM } from '../../../lib/roles';

const mockGetSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockGetSession(...args),
  withApiAuthRequired: (handler: Function) => handler,
} }));
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: jest.fn(), logAuditEventRequired: jest.fn().mockResolvedValue(undefined) }));

import analyze from '../../../pages/api/admin/dashboard/reports/[reportId]/analyze';

const originalFetch = global.fetch;
const originalEnv = { ...process.env };

function response() {
  return { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() } as unknown as NextApiResponse;
}
function request(over: Partial<NextApiRequest> = {}) {
  return {
    method: 'POST', headers: {}, socket: {}, url: '/api/admin/dashboard/reports/VRA-1/analyze',
    query: { reportId: 'VRA-1' }, ...over,
  } as unknown as NextApiRequest;
}
function adminSession(roles: string[] = ['admin'], org = 'org-correct') {
  mockGetSession.mockResolvedValue({ user: { email_verified: true, sub: 'u1', email: 'user@example.com', org_id: org, [ROLES_CLAIM]: roles } });
}
function backend(status: number, body: unknown) {
  return { ok: status < 400, status, json: async () => body, text: async () => JSON.stringify(body) };
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.TENANT_ORG_ID = 'org-correct';
  process.env.INTERNAL_API_SECRET = 'test-only-secret';
  process.env.BACKEND_URL = 'http://backend.test';
  global.fetch = jest.fn().mockResolvedValue(backend(200, { success: true, data: { credibilityScore: 82 } }));
});
afterAll(() => { global.fetch = originalFetch; process.env = originalEnv; });

describe('re-analyze proxy → Shroud/Mongo backend (#595)', () => {
  it('POSTs to the Express reanalyze endpoint with the internal secret — never an Eliza agent', async () => {
    adminSession();
    const res = response();
    await analyze(request(), res);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, opts] = (global.fetch as jest.Mock).mock.calls[0];
    expect(url).toBe('http://backend.test/api/whistleblower/admin/reports/VRA-1/reanalyze');
    expect(url).not.toMatch(/eliza|plugin-midnight|\/agents\//i);
    expect(opts.method).toBe('POST');
    expect(opts.headers['x-internal-secret']).toBe('test-only-secret');
    expect(opts.headers['Content-Type']).toBe('application/json');

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ success: true, data: { credibilityScore: 82 } });
  });

  it('passes the backend status and body straight through (e.g. 404 not-found)', async () => {
    adminSession();
    (global.fetch as jest.Mock).mockResolvedValue(backend(404, { success: false, error: 'Report not found' }));
    const res = response();
    await analyze(request(), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ success: false, error: 'Report not found' });
  });

  it('URL-encodes the tracking id so it cannot escape the reanalyze path', async () => {
    adminSession();
    const res = response();
    await analyze(request({ query: { reportId: 'a/b' } as any }), res);

    const [url] = (global.fetch as jest.Mock).mock.calls[0];
    expect(url).toBe('http://backend.test/api/whistleblower/admin/reports/a%2Fb/reanalyze');
  });

  it('fails closed — does not call the backend when the internal secret is unconfigured', async () => {
    delete process.env.INTERNAL_API_SECRET;
    adminSession();
    const res = response();
    await analyze(request(), res);

    expect(global.fetch).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ success: false, error: 'Backend not configured' });
  });

  it('rejects a non-POST method', async () => {
    adminSession();
    const res = response();
    await analyze(request({ method: 'GET' }), res);

    expect(res.status).toHaveBeenCalledWith(405);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('denies a non-admin session before the backend is reached', async () => {
    adminSession([]); // authenticated, but no admin role
    const res = response();
    await analyze(request(), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('maps a backend/network failure to 502 rather than leaking the error', async () => {
    adminSession();
    (global.fetch as jest.Mock).mockRejectedValue(new Error('ECONNREFUSED'));
    const res = response();
    await analyze(request(), res);

    expect(res.status).toHaveBeenCalledWith(502);
    const body = (res.json as jest.Mock).mock.calls[0][0];
    expect(body.success).toBe(false);
    expect(body.error.code).toBe('ANALYZE_ERROR');
  });
});
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));
