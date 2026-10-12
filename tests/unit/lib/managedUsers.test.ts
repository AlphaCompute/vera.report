import { removeManagedUser, assertManagedUser, clearTokenCache } from '../../../lib/auth0Management';
const originalFetch = global.fetch;
const originalEnv = { ...process.env };
const target = 'auth0|employee';
let responses: Record<string, unknown>;
beforeEach(() => {
  clearTokenCache();
  process.env.AUTH0_DOMAIN = 'example.auth0.com';
  process.env.AUTH0_MGMT_CLIENT_ID = 'test'; process.env.AUTH0_MGMT_CLIENT_SECRET = 'test';
  process.env.TENANT_ORG_ID = 'org_test'; process.env.AUTH0_ORG_SCOPED_ADMIN = 'true';
  responses = {
    '/oauth/token': { access_token: 'test-token', expires_in: 3600 },
    '/api/v2/users/auth0%7Cemployee': { user_id: target, email: 'employee@example.com' },
    '/api/v2/organizations/org_test/members?per_page=100&page=0': [{ user_id: target }],
    '/api/v2/organizations/org_test/members/auth0%7Cemployee/roles?per_page=100&page=0': [{ name: 'employee' }],
  };
  global.fetch = jest.fn(async (url, options) => {
    const parsed = new URL(String(url)); const path = parsed.pathname + parsed.search;
    if (options?.method === 'DELETE') return { ok: true, status: 204 } as Response;
    if (!(path in responses)) return { ok: false, status: 503 } as Response;
    return { ok: true, json: async () => responses[path] } as Response;
  });
});
afterEach(() => { global.fetch = originalFetch; process.env = { ...originalEnv }; clearTokenCache(); });
it('removes only the verified organization membership, never the global identity', async () => {
  await removeManagedUser(target);
  const calls = (global.fetch as jest.Mock).mock.calls.filter(([, options]) => options?.method === 'DELETE');
  expect(calls).toHaveLength(1);
  expect(String(calls[0][0])).toBe('https://example.auth0.com/api/v2/organizations/org_test/members');
  expect(JSON.parse(calls[0][1].body)).toEqual({ members: [target] });
});
it.each(['foreign-domain', 'foreign-org', 'lookup-failure', 'role-failure', 'admin'])('blocks %s before DELETE', async scenario => {
  if (scenario === 'foreign-domain') responses['/api/v2/users/auth0%7Cemployee'] = { user_id: target, email: 'other@outside.invalid' };
  if (scenario === 'foreign-org') responses['/api/v2/organizations/org_test/members?per_page=100&page=0'] = [];
  if (scenario === 'lookup-failure') delete responses['/api/v2/users/auth0%7Cemployee'];
  if (scenario === 'role-failure') delete responses['/api/v2/organizations/org_test/members/auth0%7Cemployee/roles?per_page=100&page=0'];
  if (scenario === 'admin') responses['/api/v2/organizations/org_test/members/auth0%7Cemployee/roles?per_page=100&page=0'] = [{ name: 'admin' }];
  await expect(removeManagedUser(target)).rejects.toThrow();
  expect((global.fetch as jest.Mock).mock.calls.filter(([, options]) => options?.method === 'DELETE')).toHaveLength(0);
});
it('fails closed when tenant organization enforcement is not enabled', async () => {
  process.env.AUTH0_ORG_SCOPED_ADMIN = 'false';
  await expect(assertManagedUser(target)).rejects.toThrow(/Organization-scoped/);
  expect(global.fetch).not.toHaveBeenCalled();
});
it('checks later membership pages instead of treating a truncated census as complete', async () => {
  responses['/api/v2/organizations/org_test/members?per_page=100&page=0'] = Array.from({ length: 100 }, (_, i) => ({ user_id: `other-${i}` }));
  responses['/api/v2/organizations/org_test/members?per_page=100&page=1'] = [{ user_id: target }];
  await expect(assertManagedUser(target)).resolves.toBeUndefined();
});
