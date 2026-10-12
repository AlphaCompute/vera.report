import { Writable } from 'node:stream';
import type { NextApiRequest, NextApiResponse } from 'next';
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: async () => ({ user: { email_verified: true, sub: 'admin', email: 'admin@example.com', 'https://vera.app/roles': ['admin'] } }),
  withApiAuthRequired: (handler: Function) => handler,
} }));
import narrative from '../../../pages/api/admin/narrative/[trackingId]';
import evidence from '../../../pages/api/whistleblower/evidence/[trackingId]/[filename]';
import contact from '../../../pages/api/whistleblower/reward-contact/[trackingId]';
import status from '../../../pages/api/admin/dashboard/reports/[reportId]/status';
const env = { ...process.env }; const originalFetch = global.fetch;
const handlers = [{ name: 'narrative', handler: narrative }, { name: 'evidence', handler: evidence }, { name: 'contact', handler: contact }, { name: 'status', handler: status }];
beforeEach(() => { process.env.INTERNAL_API_SECRET = 'test-secret'; delete process.env.TENANT_ORG_ID; });
afterEach(() => { process.env = { ...env }; global.fetch = originalFetch; });
for (const { name, handler } of handlers) {
  describe(name, () => {
    const req = { method: name === 'status' ? 'PATCH' : 'GET', query: { trackingId: 'VRA-1', reportId: 'VRA-1', filename: 'file.pdf' }, body: { status: 'reviewing' }, headers: {}, socket: {} } as unknown as NextApiRequest;
    function res() { return Object.assign(new Writable({ write(_chunk, _enc, cb) { cb(); } }), { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn(), setHeader: jest.fn() }) as unknown as NextApiResponse; }
    it.each(['http-error', 'negative-receipt', 'network-error'])('blocks the action if durable audit fails: %s', async failure => {
      global.fetch = jest.fn().mockImplementation(async () => {
        if (failure === 'network-error') throw new Error('offline');
        return new Response(JSON.stringify({ success: false }), { status: failure === 'http-error' ? 503 : 200 });
      });
      const response = res(); await handler(req, response);
      expect(response.status).toHaveBeenCalledWith(502);
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect((global.fetch as jest.Mock).mock.calls[0][0]).toContain('/audit-log');
      expect(response.send).not.toHaveBeenCalled();
    });
    it('persists attempted audit before calling the backend and response audit before success', async () => {
      const events: string[] = [];
      global.fetch = jest.fn().mockImplementation(async (url, options) => {
        if (String(url).endsWith('/audit-log')) {
          events.push(JSON.parse(options.body).details.phase);
          return new Response('{"success":true}', { status: 200 });
        }
        events.push('operation');
        return new Response('{"success":true}', { status: 200, headers: { 'content-type': 'application/json' } });
      });
      const response = res(); await handler(req, response);
      expect(events).toEqual(['attempted', 'operation', 'response']);
      expect(response.status).toHaveBeenCalledWith(200);
    });
    it('does not return successful data if the response audit fails', async () => {
      global.fetch = jest.fn()
        .mockResolvedValueOnce(new Response('{"success":true}', { status: 200 }))
        .mockResolvedValueOnce(new Response('{"success":true,"private":"secret"}', { status: 200 }))
        .mockResolvedValueOnce(new Response('{"success":false}', { status: 503 }));
      const response = res(); await handler(req, response);
      expect(response.status).toHaveBeenCalledWith(502);
      expect(JSON.stringify((response.json as jest.Mock).mock.calls)).not.toContain('secret');
      expect(response.send).not.toHaveBeenCalled();
    });
  });
}
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));
