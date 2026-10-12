/**
 * Unit Tests — tenant config + admin Organization scoping (multi-tenant silo).
 * See docs/pdr/VERA-PDR-001-A1-multi-tenancy.md.
 */
import {
  getAllowedAdminDomains,
  getTenantOrgId,
  getTenantName,
} from '../../../lib/tenant';
import {
  isAllowedAdminEmail,
  isAllowedAdminOrg,
  getOrgIdFromSession,
  buildAdminEmailSearchQuery,
} from '../../../lib/adminAuth';

const ENV = { ...process.env };
afterEach(() => {
  for (const k of ['ADMIN_ALLOWED_DOMAINS', 'TENANT_ORG_ID', 'TENANT_NAME']) {
    delete process.env[k];
    if (ENV[k] !== undefined) process.env[k] = ENV[k];
  }
});

describe('getAllowedAdminDomains', () => {
  it('fails closed when unset', () => {
    delete process.env.ADMIN_ALLOWED_DOMAINS;
    expect(getAllowedAdminDomains()).toEqual([]);
  });
  it('parses a comma-separated list, trims/lowercases/prefixes @', () => {
    process.env.ADMIN_ALLOWED_DOMAINS = 'Foo.com, @Bar.io ';
    expect(getAllowedAdminDomains()).toEqual(['@foo.com', '@bar.io']);
  });
  it('drops malformed entries instead of widening the search', () => {
    process.env.ADMIN_ALLOWED_DOMAINS = '*, @, foo, *.example.com, a b.com, good.example';
    expect(getAllowedAdminDomains()).toEqual(['@good.example']);
    process.env.ADMIN_ALLOWED_DOMAINS = '*';
    expect(getAllowedAdminDomains()).toEqual([]);
    expect(() => buildAdminEmailSearchQuery()).toThrow();
  });
  it('fails closed when blank', () => {
    process.env.ADMIN_ALLOWED_DOMAINS = '  ,  ';
    expect(getAllowedAdminDomains()).toEqual([]);
  });
});

describe('isAllowedAdminEmail (env-driven)', () => {
  it('honors an env override', () => {
    process.env.ADMIN_ALLOWED_DOMAINS = '@demirix.com';
    expect(isAllowedAdminEmail('a@demirix.com')).toBe(true);
    expect(isAllowedAdminEmail('a@example.com')).toBe(false);
  });
  it('admits no one when unset', () => {
    delete process.env.ADMIN_ALLOWED_DOMAINS;
    expect(isAllowedAdminEmail('a@example.com')).toBe(false);
    expect(isAllowedAdminEmail('a@example.org')).toBe(false);
  });
});

describe('buildAdminEmailSearchQuery (env-driven)', () => {
  it('reflects the env override', () => {
    process.env.ADMIN_ALLOWED_DOMAINS = '@demirix.com,@google.com';
    expect(buildAdminEmailSearchQuery()).toBe('email:(*@demirix.com OR *@google.com)');
  });
  it('refuses to build an unfiltered query when unset', () => {
    delete process.env.ADMIN_ALLOWED_DOMAINS;
    expect(() => buildAdminEmailSearchQuery()).toThrow('ADMIN_ALLOWED_DOMAINS is not configured');
  });
});

describe('getTenantOrgId / getTenantName', () => {
  it('org id is null when unset', () => {
    delete process.env.TENANT_ORG_ID;
    expect(getTenantOrgId()).toBeNull();
  });
  it('returns the configured org id', () => {
    process.env.TENANT_ORG_ID = 'org_abc';
    expect(getTenantOrgId()).toBe('org_abc');
  });
  it('tenant name defaults to Vera', () => {
    delete process.env.TENANT_NAME;
    expect(getTenantName()).toBe('Vera');
  });
  it('returns the configured tenant name', () => {
    process.env.TENANT_NAME = 'Demirix';
    expect(getTenantName()).toBe('Demirix');
  });
});

describe('getOrgIdFromSession', () => {
  it('extracts org_id', () => {
    expect(getOrgIdFromSession({ org_id: 'org_1' })).toBe('org_1');
  });
  it('returns null when absent or non-string', () => {
    expect(getOrgIdFromSession({})).toBeNull();
    expect(getOrgIdFromSession(null)).toBeNull();
    expect(getOrgIdFromSession({ org_id: 123 as unknown as string })).toBeNull();
  });
});

describe('isAllowedAdminOrg', () => {
  it('is not enforced when TENANT_ORG_ID is unset', () => {
    delete process.env.TENANT_ORG_ID;
    expect(isAllowedAdminOrg(null)).toBe(true);
    expect(isAllowedAdminOrg('anything')).toBe(true);
  });
  it('accepts the matching organization when enforced', () => {
    process.env.TENANT_ORG_ID = 'org_tenantA';
    expect(isAllowedAdminOrg('org_tenantA')).toBe(true);
  });
  it('rejects mismatch or missing org when enforced (fail-closed)', () => {
    process.env.TENANT_ORG_ID = 'org_tenantA';
    expect(isAllowedAdminOrg('org_tenantB')).toBe(false);
    expect(isAllowedAdminOrg(null)).toBe(false);
    expect(isAllowedAdminOrg(undefined)).toBe(false);
  });
});
