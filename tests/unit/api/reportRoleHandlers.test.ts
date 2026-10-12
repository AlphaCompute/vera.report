import notes from '../../../pages/api/admin/dashboard/reports/[reportId]/notes';
import { logAuditEventRequired } from '@/lib/auditClient';
import { openTriageReference, sealTriageReference } from '../../../lib/triageReference';
import type { NextApiRequest, NextApiResponse } from 'next';
import { ROLES_CLAIM } from '../../../lib/roles';
const mockGetSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockGetSession(...args),
  withApiAuthRequired: (handler: Function) => handler,
} }));
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: jest.fn(), logAuditEventRequired: jest.fn().mockResolvedValue(undefined) }));
import list from '../../../pages/api/admin/dashboard/reports';
import status from '../../../pages/api/admin/dashboard/reports/[reportId]/status';
import analyze from '../../../pages/api/admin/dashboard/reports/[reportId]/analyze';
const originalFetch = global.fetch;
const originalEnv = { ...process.env };
const handlers = [{ handler: list, method: 'GET' }, { handler: status, method: 'PATCH' }, { handler: analyze, method: 'POST' }];
function response() {
  return { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() } as unknown as NextApiResponse;
}
function request(method: string) {
  return { method, headers: {}, socket: {}, query: { agentId: 'a', reportId: 'VRA-1' }, body: { status: 'reviewing' } } as unknown as NextApiRequest;
}
function session(roles: string[], org = 'org-correct') {
  mockGetSession.mockResolvedValue({ user: { email_verified: true, sub: 'u1', email: 'user@example.com', org_id: org, [ROLES_CLAIM]: roles } });
}
beforeEach(() => {
  jest.clearAllMocks();
  process.env.TENANT_ORG_ID = 'org-correct';
  process.env.INTERNAL_API_SECRET = 'test-only-secret';
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }), text: async () => '{"success":true}' });
});
afterAll(() => { global.fetch = originalFetch; process.env = originalEnv; });
for (const { handler, method } of handlers) {
  describe(method, () => {
    it.each([['no role', [], 'org-correct'], ['wrong organization', ['admin'], 'org-other']] as const)('denies %s before backend access', async (_, roles, org) => {
      session([...roles], org);
      const res = response(); await handler(request(method), res);
      expect(res.status).toHaveBeenCalledWith(403); expect(global.fetch).not.toHaveBeenCalled();
    });
    it('allows an administrator', async () => {
      session(['admin']); const res = response(); await handler(request(method), res);
      expect(res.status).toHaveBeenCalledWith(200); expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });
}
it('allows employee triage but strips all sensitive and unknown report fields', async () => {
  session(['employee']);
  (global.fetch as jest.Mock).mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true, secret: 'outer secret', data: { reports: [{
    trackingId: 'VRA-0123456789ABCDEF', status: 'pending', description: 'raw narrative', evidence: [{ name: 'Jane.pdf', ipfsHash: 'cid' }],
    location: 'home', reward: { contactMethod: 'email' }, activity: [{ description: 'private' }], futurePii: 'secret',
  }] } }) });
  const res = response(); await list(request('GET'), res);
  const body = (res.json as jest.Mock).mock.calls[0][0];
  expect(body.data.reports[0]).toMatchObject({ description: '', evidence: [], activity: [] });
  expect(body.data.reports[0].trackingId).toMatch(/^TRI-/);
  expect(openTriageReference(body.data.reports[0].trackingId)).toBe('VRA-0123456789ABCDEF');
  expect(JSON.stringify(body)).not.toContain('VRA-0123456789ABCDEF');
  // An opaque randomized reference can contain short strings such as 'cid'.
  // Assert the entire allowed response shape, so no sensitive or future field
  // can survive sanitization without making ciphertext a probabilistic failure.
  const reference = body.data.reports[0].trackingId;
  expect(body).toEqual({ success: true, data: { reports: [{
    _id: reference, reportId: reference, trackingId: reference,
    status: 'pending', description: '', evidence: [], activity: [],
  }] } });
});
it('allows employee status changes', async () => {
  session(['employee']); const res = response(); const req = request('PATCH');
  req.query.reportId = sealTriageReference('VRA-0123456789ABCDEF');
  await status(req, res);
  expect(res.status).toHaveBeenCalledWith(200);
});
it('denies employee analysis access', async () => {
  session(['employee']); const res = response(); await analyze(request('POST'), res);
  expect(res.status).toHaveBeenCalledWith(403); expect(global.fetch).not.toHaveBeenCalled();
});
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));


describe('internal report notes', () => {
  const notesRequest = (body: unknown = { text: ' Internal review note ', authorId: 'forged' }) => ({
    ...request('POST'), query: { reportId: 'VRA-0123456789ABCDEF' }, body,
  }) as NextApiRequest;
  it.each(['employee', 'counsel'])('denies %s access to notes', async role => {
    session([role]); const res = response(); await notes(notesRequest(), res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it('takes authorship from the authenticated session and trims the note', async () => {
    session(['admin']); const res = response(); await notes(notesRequest(), res);
    expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/notes'), expect.objectContaining({
      method: 'POST', body: JSON.stringify({ text: 'Internal review note', authorId: 'u1' }),
    }));
  });
  it.each(['', '   ', 'x'.repeat(5001), 123])('rejects an invalid note before backend access', async text => {
    session(['admin']); const res = response(); await notes(notesRequest({ text }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it('fails closed when auditing is unavailable', async () => {
    session(['admin']);
    jest.mocked(logAuditEventRequired).mockRejectedValueOnce(new Error('audit unavailable'));
    const res = response(); await notes(notesRequest(), res);
    expect(res.status).toHaveBeenCalledWith(502);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});


describe('note reads and backend failures', () => {
  const getRequest = () => ({ ...request('GET'), query: { reportId: 'VRA-0123456789ABCDEF' } }) as NextApiRequest;
  it.each(['employee', 'counsel'])('denies %s read access', async role => {
    session([role]); const res = response(); await notes(getRequest(), res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it('rejects administrators from another organization', async () => {
    session(['admin'], 'other-organization'); const res = response(); await notes(getRequest(), res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it('loads stored notes through the authenticated backend', async () => {
    session(['admin']); const res = response(); await notes(getRequest(), res);
    expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/notes'), expect.objectContaining({ method: 'GET' }));
    expect(logAuditEventRequired).toHaveBeenCalledWith(expect.objectContaining({ action: 'report_notes_view' }));
  });
  it('handles an unavailable backend without returning sensitive errors', async () => {
    session(['admin']); jest.mocked(global.fetch).mockRejectedValueOnce(new Error('private backend details'));
    const res = response(); await notes(getRequest(), res);
    expect(res.status).toHaveBeenCalledWith(502);
    expect(JSON.stringify(jest.mocked(res.json).mock.calls)).not.toContain('private backend details');
  });
});
