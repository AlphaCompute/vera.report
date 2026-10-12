/**
 * Unit Tests — Auth Middleware
 * Tests withApiAuth, withAuditedApiAuth, isAllowedAdminEmail,
 * buildAdminEmailSearchQuery, and Auth0 Organization scoping.
 */

import {
  ALLOWED_ADMIN_DOMAINS,
  buildAdminEmailSearchQuery,
  isAllowedAdminEmail,
} from '../../../lib/adminAuth';

// Mock auth0 before importing authMiddleware
jest.mock('../../../lib/auth0', () => ({
  auth0: {
    withApiAuthRequired: (fn: Function) => fn,
    getSession: jest.fn(),
  },
}));

import { auth0 } from '../../../lib/auth0';
jest.mock('../../../lib/currentAdminAuthorization', () => ({ currentAdminAuthorization: async (user: Record<string, unknown>) => ({
  userId: user.sub, email: user.email, name: user.name, roles: user['https://vera.app/roles'] ?? ['employee'],
}) }));
import { withApiAuth, withAuditedApiAuth, withRoleAuth } from '../../../lib/authMiddleware';
import type { AdminIdentity } from '../../../lib/authMiddleware';

const mockGetSession = auth0.getSession as jest.MockedFunction<typeof auth0.getSession>;

function mockReq(overrides: Record<string, unknown> = {}): any {
  return { method: 'GET', query: {}, headers: {}, ...overrides };
}

function mockRes(): any {
  const res: any = { statusCode: 200, body: null };
  res.status = jest.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn((data: unknown) => {
    res.body = data;
    return res;
  });
  return res;
}

describe('isAllowedAdminEmail', () => {
  it('should return false for null', () => {
    expect(isAllowedAdminEmail(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isAllowedAdminEmail(undefined)).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(isAllowedAdminEmail('')).toBe(false);
  });

  it('should return true for valid example.com email', () => {
    expect(isAllowedAdminEmail('admin@example.com')).toBe(true);
  });

  it('should return true for valid example.org email', () => {
    expect(isAllowedAdminEmail('admin@example.org')).toBe(true);
  });

  it('should return true case-insensitively', () => {
    expect(isAllowedAdminEmail('ADMIN@EXAMPLE.COM')).toBe(true);
    expect(isAllowedAdminEmail('Admin@Example.Com')).toBe(true);
    expect(isAllowedAdminEmail('ADMIN@EXAMPLE.ORG')).toBe(true);
    expect(isAllowedAdminEmail('Admin@Example.Org')).toBe(true);
  });

  it('should return false for substring attack on allowed domains', () => {
    expect(isAllowedAdminEmail('admin@example.com.evil.com')).toBe(false);
    expect(isAllowedAdminEmail('admin@example.org.evil.com')).toBe(false);
  });

  it('should return false for non-allowed domains', () => {
    expect(isAllowedAdminEmail('admin@gmail.com')).toBe(false);
    expect(isAllowedAdminEmail('admin@evil.com')).toBe(false);
  });
});

describe('buildAdminEmailSearchQuery', () => {
  it('should produce a Lucene email field query', () => {
    const q = buildAdminEmailSearchQuery();
    expect(q.startsWith('email:(')).toBe(true);
    expect(q.endsWith(')')).toBe(true);
  });

  it('should include a wildcard clause for every allowed domain', () => {
    const q = buildAdminEmailSearchQuery();
    for (const domain of ALLOWED_ADMIN_DOMAINS) {
      expect(q).toContain(`*${domain}`);
    }
  });

  it('should join multiple domains with OR', () => {
    if (ALLOWED_ADMIN_DOMAINS.length < 2) return;
    const q = buildAdminEmailSearchQuery();
    expect(q).toContain(' OR ');
    expect(q.split(' OR ').length).toBe(ALLOWED_ADMIN_DOMAINS.length);
  });

  it('should match the exact expected shape for the current allowlist', () => {
    expect(buildAdminEmailSearchQuery()).toBe(
      'email:(*@example.com OR *@example.org)',
    );
  });
});

describe('withApiAuth', () => {
  beforeEach(() => {
    mockGetSession.mockReset();
  });

  it('should return 403 for non-example.com email', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'hacker@evil.com', sub: 'auth0|evil' },
    } as any);

    const innerHandler = jest.fn();
    const wrapped = withApiAuth(innerHandler);

    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body.error).toContain('Forbidden');
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('should call handler for valid admin email', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|123' },
    } as any);

    const innerHandler = jest.fn((_req, res) => res.json({ ok: true }));
    const wrapped = withApiAuth(innerHandler);

    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);

    expect(innerHandler).toHaveBeenCalledWith(req, res);
  });
});

describe('withAuditedApiAuth', () => {
  beforeEach(() => {
    mockGetSession.mockReset();
  });

  it('should extract AdminIdentity (userId, email, name)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true,
        sub: 'auth0|abc',
        email: 'alice@example.com',
        name: 'Alice Admin',
      },
    } as any);

    let receivedAdmin: AdminIdentity | undefined;
    const innerHandler = jest.fn(async (_req: any, res: any, admin: AdminIdentity) => {
      receivedAdmin = admin;
      return res.json({ ok: true });
    });

    const wrapped = withAuditedApiAuth(innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);

    expect(innerHandler).toHaveBeenCalled();
    expect(receivedAdmin).toEqual({
      userId: 'auth0|abc',
      email: 'alice@example.com',
      name: 'Alice Admin',
    });
  });

  it('should default userId and email to unknown when session fields missing', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true,},
    } as any);

    let receivedAdmin: AdminIdentity | undefined;
    const innerHandler = jest.fn(async (_req: any, res: any, admin: AdminIdentity) => {
      receivedAdmin = admin;
      return res.json({ ok: true });
    });

    const wrapped = withAuditedApiAuth(innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);

    // isAllowedAdminEmail(undefined) returns false → 403
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should return 403 for unauthorized email', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'auth0|bad', email: 'bad@evil.com', name: 'Bad Actor' },
    } as any);

    const innerHandler = jest.fn();
    const wrapped = withAuditedApiAuth(innerHandler);

    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe('organization scoping (multi-tenant)', () => {
  const OLD_ORG = process.env.TENANT_ORG_ID;
  beforeEach(() => {
    mockGetSession.mockReset();
    process.env.TENANT_ORG_ID = 'org_tenantA';
  });
  afterEach(() => {
    if (OLD_ORG === undefined) delete process.env.TENANT_ORG_ID;
    else process.env.TENANT_ORG_ID = OLD_ORG;
  });

  it('rejects an allowed email from the wrong organization', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantB' },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withApiAuth(innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body.error).toContain('organization');
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('rejects when org_id is missing but scoping is enabled (fail-closed)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1' },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withApiAuth(innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('allows an allowed email from the matching organization', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantA' },
    } as any);
    const innerHandler = jest.fn((_req: any, res: any) => res.json({ ok: true }));
    const wrapped = withApiAuth(innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(innerHandler).toHaveBeenCalledWith(req, res);
  });
});

// withRoleAuth('admin') is the wrapper behind the Next.js dissemination admin
// proxies (PDR VERA-PDR-001-A1 §A1.2). It must fail closed on BOTH the tenant
// Organization and the role claim, in that order (org check runs before role).
describe('withRoleAuth — org + role fail-closed (dissemination admin proxies)', () => {
  const ROLES_CLAIM = 'https://vera.app/roles';
  const OLD_ORG = process.env.TENANT_ORG_ID;

  beforeEach(() => {
    mockGetSession.mockReset();
    process.env.TENANT_ORG_ID = 'org_tenantA';
  });
  afterEach(() => {
    if (OLD_ORG === undefined) delete process.env.TENANT_ORG_ID;
    else process.env.TENANT_ORG_ID = OLD_ORG;
  });

  it('rejects an admin-role user from the wrong organization (fail-closed org)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantB', [ROLES_CLAIM]: ['admin'] },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withRoleAuth('admin', innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body.error).toContain('organization');
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('rejects an admin-role user whose org_id is missing while scoping is on (fail-closed)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', [ROLES_CLAIM]: ['admin'] },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withRoleAuth('admin', innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body.error).toContain('organization');
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('rejects a matching-org user who lacks the admin role (fail-closed role)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantA', [ROLES_CLAIM]: ['employee'] },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withRoleAuth('admin', innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body.error).toContain('admin role');
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('rejects a matching-org user with no roles claim at all (fail-closed role)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantA' },
    } as any);
    const innerHandler = jest.fn();
    const wrapped = withRoleAuth('admin', innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it('allows an admin-role user from the matching organization', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, email: 'admin@example.com', sub: 'auth0|1', org_id: 'org_tenantA', [ROLES_CLAIM]: ['admin'] },
    } as any);
    const innerHandler = jest.fn((_req: any, res: any) => res.json({ ok: true }));
    const wrapped = withRoleAuth('admin', innerHandler);
    const req = mockReq();
    const res = mockRes();
    await wrapped(req, res);
    expect(innerHandler).toHaveBeenCalled();
    expect(res.body).toEqual({ ok: true });
  });
});
