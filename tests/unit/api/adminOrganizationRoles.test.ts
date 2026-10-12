import type { NextApiRequest, NextApiResponse } from 'next';
import { clearTokenCache } from '../../../lib/auth0Management';
jest.mock('@/lib/authMiddleware', () => ({
  withRoleAuth: (_role: string, handler: Function) => (req: NextApiRequest, res: NextApiResponse) =>
    handler(req, res, { userId: 'auth0|acting-admin', email: 'admin@example.org', roles: ['admin'] }),
}));
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: jest.fn() }));
import list from '../../../pages/api/admin/users';
import change from '../../../pages/api/admin/users/[userId]/role';
const originalEnv = process.env;
const originalFetch = global.fetch;
const userId = 'google-oauth2|target';
const memberPath = '/api/v2/organizations/org_test/members';
const rolesPath = `${memberPath}/google-oauth2%7Ctarget/roles`;
let roles: string[];
let member: boolean;
let writes: string[];
const response = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() }) as unknown as NextApiResponse;
const request = (method: string) => ({ method, query: { userId }, body: { role: 'admin' }, headers: {}, socket: {} }) as unknown as NextApiRequest;
beforeEach(() => {
  jest.clearAllMocks(); clearTokenCache(); roles = ['employee']; member = true; writes = [];
  process.env = { ...originalEnv, AUTH0_DOMAIN: 'example.auth0.com', AUTH0_MGMT_CLIENT_ID: 'test', AUTH0_MGMT_CLIENT_SECRET: 'test', TENANT_ORG_ID: 'org_test' };
  delete process.env.AUTH0_ORG_SCOPED_ADMIN;
  global.fetch = jest.fn(async (input, options) => {
    const path = new URL(String(input)).pathname;
    let data: unknown;
    if (path === '/oauth/token') data = { access_token: 'fixture', expires_in: 3600 };
    else if (path === '/api/v2/users/google-oauth2%7Ctarget') data = { user_id: userId, email: 'target@example.org' };
    else if (path === memberPath) data = member ? [{ user_id: userId, email: 'target@example.org' }] : [];
    else if (path === '/api/v2/roles') data = ['admin', 'employee'].map(name => ({ name, id: name }));
    else if (path === rolesPath) {
      if (options?.method === 'POST') { writes.push('POST'); roles.push('admin'); }
      if (options?.method === 'DELETE') { writes.push('DELETE'); roles = roles.filter(role => role !== 'employee'); }
      data = roles.map(name => ({ name }));
    } else throw new Error(`Unexpected request, including global role access: ${path}`);
    return { ok: true, status: 200, json: async () => data } as Response;
  });
});
afterEach(() => { process.env = originalEnv; global.fetch = originalFetch; clearTokenCache(); });
it('lists organization roles and promotes Employee to Admin in the same organization without a rollout flag', async () => {
  let res = response(); await list(request('GET'), res);
  expect(res.json).toHaveBeenCalledWith({ success: true, users: [expect.objectContaining({ role: 'employee' })] });
  res = response(); await change(request('PATCH'), res);
  expect(res.status).toHaveBeenCalledWith(200); expect(writes).toEqual(['POST', 'DELETE']);
  res = response(); await list(request('GET'), res);
  expect(res.json).toHaveBeenCalledWith({ success: true, users: [expect.objectContaining({ role: 'admin' })] });
});
it('displays an existing organization admin and treats promotion as a no-op', async () => {
  roles = ['admin'];
  const res = response(); await change(request('PATCH'), res);
  expect(res.status).toHaveBeenCalledWith(200); expect(writes).toEqual([]);
});
it('refuses a user outside the organization before writing any role', async () => {
  member = false;
  const res = response(); await change(request('PATCH'), res);
  expect(res.status).toHaveBeenCalledWith(500); expect(writes).toEqual([]);
});
