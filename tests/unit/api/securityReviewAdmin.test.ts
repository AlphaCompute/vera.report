const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: { getSession: (...a: unknown[]) => mockSession(...a), withApiAuthRequired: (h: unknown) => h } }));
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: jest.fn(), queryAuditLogs: jest.fn(async () => ({ entries: [], total: 0 })) }));
import audit from '../../../pages/api/admin/audit-logs';
import { sealTriageReference, openTriageReference } from '../../../lib/triageReference';
function response() { return { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() }; }
beforeEach(() => { jest.clearAllMocks(); process.env.ADMIN_ALLOWED_DOMAINS = '@example.com'; process.env.TENANT_ORG_ID = 'org_local'; process.env.INTERNAL_API_SECRET = 'synthetic-test-key'; });
it.each([undefined, false])('rejects an unverified allowed-domain admin session (%s)', async verified => {
  mockSession.mockResolvedValue({ user: { sub: 'user', email: 'user@example.com', email_verified: verified, org_id: 'org_local', 'https://vera.app/roles': ['admin'] } });
  const res = response();
  await audit({ method: 'GET', query: {}, headers: {}, socket: {} } as any, res as any);
  expect(res.status).toHaveBeenCalledWith(403);
});
it.each([[], ['employee']])('rejects a verified session without admin role (%s)', async (...roles) => {
  mockSession.mockResolvedValue({ user: { sub: 'user', email: 'user@example.com', email_verified: true, org_id: 'org_local', 'https://vera.app/roles': roles } });
  const res = response();
  await audit({ method: 'GET', query: {}, headers: {}, socket: {} } as any, res as any);
  expect(res.status).toHaveBeenCalledWith(403);
});
it('separates employee references from reporter credentials and rejects tampering', () => {
  const trackingId = 'VRA-0123456789ABCDEF';
  const reference = sealTriageReference(trackingId);
  expect(reference).not.toContain(trackingId);
  expect(reference).not.toMatch(/^VRA-/);
  expect(openTriageReference(reference)).toBe(trackingId);
  expect(() => openTriageReference(trackingId)).toThrow();
  expect(() => openTriageReference(reference.slice(0, 20) + (reference[20] === 'a' ? 'b' : 'a') + reference.slice(21))).toThrow();
});
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));
