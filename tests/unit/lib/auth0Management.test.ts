/** Configured tenants use organization roles unless explicitly disabled. */
import { orgScopedAdmin, memberRolesPath, mgmtFetch, clearTokenCache } from '../../../lib/auth0Management';

// Swap process.env for a plain object per test (the repo idiom — avoids the
// jest live-env object) so we can set/clear these vars cleanly.
const ORIGINAL_ENV = process.env;
beforeEach(() => {
  process.env = { ...ORIGINAL_ENV };
});
afterEach(() => {
  process.env = ORIGINAL_ENV;
});

describe('org-scoped admin gating', () => {
  it('targets the Organization endpoint only when the flag is true AND an org is set', () => {
    process.env.AUTH0_ORG_SCOPED_ADMIN = 'true';
    process.env.TENANT_ORG_ID = 'org_ABC';
    expect(orgScopedAdmin()).toBe(true);
    expect(memberRolesPath('auth0|u1')).toBe('/organizations/org_ABC/members/auth0%7Cu1/roles');
  });

  it('uses Organization roles when a tenant is configured without the legacy flag', () => {
    delete process.env.AUTH0_ORG_SCOPED_ADMIN;
    process.env.TENANT_ORG_ID = 'org_ABC';
    expect(orgScopedAdmin()).toBe(true);
    expect(memberRolesPath('auth0|u1')).toBe('/organizations/org_ABC/members/auth0%7Cu1/roles');
  });

  it('stays OFF unless the flag is exactly "true"', () => {
    process.env.AUTH0_ORG_SCOPED_ADMIN = '1';
    process.env.TENANT_ORG_ID = 'org_ABC';
    expect(orgScopedAdmin()).toBe(false);
    expect(memberRolesPath('auth0|u1')).toBe('/users/auth0%7Cu1/roles');
  });

  it('requires a TENANT_ORG_ID — flag on but no org stays OFF and global', () => {
    process.env.AUTH0_ORG_SCOPED_ADMIN = 'true';
    delete process.env.TENANT_ORG_ID;
    expect(orgScopedAdmin()).toBe(false);
    expect(memberRolesPath('auth0|u1')).toBe('/users/auth0%7Cu1/roles');
  });
});

describe('mgmtFetch SSRF guard (#394)', () => {
  it('rejects a path that would escape the Management API host', async () => {
    process.env.AUTH0_DOMAIN = 'example.us.auth0.com';
    await expect(mgmtFetch('//evil.example/x')).rejects.toThrow(/unsafe path/);
    await expect(mgmtFetch('https://evil.example')).rejects.toThrow(/unsafe path/);
    await expect(mgmtFetch('users/x')).rejects.toThrow(/unsafe path/); // no leading slash
  });
});


describe('Management API request confinement', () => {
  const originalFetch = global.fetch;
  beforeEach(() => {
    clearTokenCache();
    process.env.AUTH0_DOMAIN = 'example.us.auth0.com';
    process.env.AUTH0_MGMT_CLIENT_ID = 'unit-client';
    process.env.AUTH0_MGMT_CLIENT_SECRET = 'unit-secret';
    global.fetch = jest.fn().mockResolvedValue({
      ok: true, json: async () => ({ access_token: 'unit-token', expires_in: 3600 }),
    });
  });
  afterEach(() => { global.fetch = originalFetch; clearTokenCache(); });

  it.each(['/../../oauth/token', '/%2e%2e/%2e%2e/oauth/token', '/users#fragment', '/users\n', '/users\\other'])('rejects %j before obtaining a token', async (path) => {
    await expect(mgmtFetch(path)).rejects.toThrow('unsafe path');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it.each(['example.com@evil.example', 'example.com/path', 'example.com:443'])('rejects malformed domain %j', async (domain) => {
    process.env.AUTH0_DOMAIN = domain;
    await expect(mgmtFetch('/users')).rejects.toThrow('hostname');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('canonicalizes uppercase hostnames for the token audience and confined request', async () => {
    process.env.AUTH0_DOMAIN = 'Example.US.AUTH0.COM';
    await mgmtFetch('/users');
    const [tokenUrl, tokenOptions] = (global.fetch as jest.Mock).mock.calls[0];
    expect(tokenUrl).toBe('https://example.us.auth0.com/oauth/token');
    expect(JSON.parse(tokenOptions.body).audience).toBe('https://example.us.auth0.com/api/v2/');
    const [url, options] = (global.fetch as jest.Mock).mock.calls[1];
    expect(String(url)).toBe('https://example.us.auth0.com/api/v2/users');
    expect(options.redirect).toBe('error');
    expect(options.headers.Authorization).toBe('Bearer unit-token');
  });

  it('keeps encoded user IDs and queries on Auth0 and forbids redirects even when requested', async () => {
    await mgmtFetch('/users/auth0%7Cu1/roles?per_page=100', { redirect: 'follow' });
    expect(global.fetch).toHaveBeenNthCalledWith(1, 'https://example.us.auth0.com/oauth/token', expect.objectContaining({ redirect: 'error' }));
    const [url, options] = (global.fetch as jest.Mock).mock.calls[1];
    expect(String(url)).toBe('https://example.us.auth0.com/api/v2/users/auth0%7Cu1/roles?per_page=100');
    expect(options.redirect).toBe('error');
    expect(options.headers.Authorization).toBe('Bearer unit-token');
  });
});
