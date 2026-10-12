import type { NextApiRequest, NextApiResponse } from 'next';
import { clearTokenCache } from '../../../lib/auth0Management';

jest.mock('@/lib/authMiddleware', () => ({
  withRoleAuth: (_role: string, handler: Function) => (req: NextApiRequest, res: NextApiResponse) =>
    handler(req, res, { userId: 'admin', email: 'admin@example.org', roles: ['admin'] }),
}));
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: jest.fn() }));
jest.mock('../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendInviteEmail: jest.fn().mockResolvedValue({ sent: true }) },
}));
import invite from '../../../pages/api/admin/users';
import { emailNotificationService } from '../../../src/services/emailNotification';

const originalEnv = { ...process.env };
const originalFetch = global.fetch;
let member: boolean;
let rejectMembership: boolean;
let roleAssigned: boolean;
let tickets: number;
function response() {
  return { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() } as unknown as NextApiResponse;
}
beforeEach(() => {
  jest.clearAllMocks(); clearTokenCache();
  member = false; rejectMembership = false; roleAssigned = false; tickets = 0;
  process.env.AUTH0_DOMAIN = 'example.auth0.com';
  process.env.AUTH0_MGMT_CLIENT_ID = 'test'; process.env.AUTH0_MGMT_CLIENT_SECRET = 'test';
  process.env.TENANT_ORG_ID = 'org_test'; process.env.AUTH0_ORG_SCOPED_ADMIN = 'true';
  global.fetch = jest.fn(async (url) => {
    const path = new URL(String(url)).pathname;
    let status = 200; let data: unknown;
    if (path === '/oauth/token') data = { access_token: 'fixture', expires_in: 3600 };
    else if (path === '/api/v2/users') data = { user_id: 'auth0|new', email: 'new@example.org' };
    else if (path === '/api/v2/roles') data = [{ id: 'role_admin', name: 'admin' }];
    else if (path === '/api/v2/organizations/org_test/members') {
      if (rejectMembership) { status = 403; data = { message: 'Membership refused' }; }
      else { member = true; data = {}; }
    } else if (path === '/api/v2/organizations/org_test/members/auth0%7Cnew/roles') {
      if (!member) { status = 404; data = { message: 'User is not an organization member' }; }
      else { roleAssigned = true; data = {}; }
    } else if (path === '/api/v2/tickets/password-change') { tickets++; data = { ticket: 'https://example.auth0.com/reset-fixture' }; }
    else throw new Error(`Unexpected test request: ${path}`);
    return { ok: status < 400, status, json: async () => data, text: async () => JSON.stringify(data) } as Response;
  });
});
afterAll(() => { process.env = originalEnv; global.fetch = originalFetch; clearTokenCache(); });
function request() {
  return { method: 'POST', body: { email: 'new@example.org', role: 'admin' }, headers: {}, socket: {}, url: '/api/admin/users' } as unknown as NextApiRequest;
}
it('provisions organization membership before role assignment and sends the invite', async () => {
  const res = response(); await invite(request(), res);
  expect(res.status).toHaveBeenCalledWith(201);
  expect(member).toBe(true); expect(roleAssigned).toBe(true); expect(tickets).toBe(1);
  expect(emailNotificationService.sendInviteEmail).toHaveBeenCalledTimes(1);
});
it('does not assign roles or send an invite if organization membership fails', async () => {
  rejectMembership = true;
  const res = response(); await invite(request(), res);
  expect(res.status).toHaveBeenCalledWith(500);
  expect(roleAssigned).toBe(false); expect(tickets).toBe(0);
  expect(emailNotificationService.sendInviteEmail).not.toHaveBeenCalled();
});
