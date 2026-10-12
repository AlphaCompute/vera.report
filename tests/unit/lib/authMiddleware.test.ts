import type { NextApiRequest, NextApiResponse } from 'next';
import { ROLES_CLAIM } from '@/lib/roles';
jest.mock('@/lib/currentAdminAuthorization', () => ({ currentAdminAuthorization: async (user: Record<string, unknown>) => ({
  userId: user.sub, email: user.email, name: user.name, roles: user['https://vera.app/roles'] ?? [],
}) }));

// Mock auth0 before importing authMiddleware
const mockGetSession = jest.fn();
const mockWithApiAuthRequired = jest.fn((handler: Function) => handler);

jest.mock('@/lib/auth0', () => ({
  auth0: {
    getSession: (...args: unknown[]) => mockGetSession(...args),
    withApiAuthRequired: (handler: Function) => mockWithApiAuthRequired(handler),
  },
}));

import { withRoleAuth } from '@/lib/authMiddleware';

function createMocks() {
  const req = { headers: {}, socket: {} } as unknown as NextApiRequest;
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  } as unknown as NextApiResponse;
  return { req, res };
}

describe('withRoleAuth', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default: withApiAuthRequired just calls the inner handler
    mockWithApiAuthRequired.mockImplementation((handler: Function) => handler);
  });

  it('returns 403 for non-@example.com email', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u1', email: 'user@evil.com', [ROLES_CLAIM]: ['admin'] },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('admin', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(handler).not.toHaveBeenCalled();
  });

  it('passes admin-gated endpoint for admin role', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u1', email: 'admin@example.com', name: 'Admin', [ROLES_CLAIM]: ['admin'] },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('admin', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledWith(
      req,
      res,
      expect.objectContaining({
        userId: 'u1',
        email: 'admin@example.com',
        roles: ['admin'],
      }),
    );
  });

  it('returns 403 for employee on admin-gated endpoint', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u2', email: 'emp@example.com', [ROLES_CLAIM]: ['employee'] },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('admin', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(handler).not.toHaveBeenCalled();
  });

  it('passes employee-gated endpoint for employee role', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u2', email: 'emp@example.com', [ROLES_CLAIM]: ['employee'] },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('employee', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledWith(
      req,
      res,
      expect.objectContaining({
        userId: 'u2',
        email: 'emp@example.com',
        roles: ['employee'],
      }),
    );
  });

  it('admin passes employee-gated endpoint (hierarchy)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u1', email: 'admin@example.com', [ROLES_CLAIM]: ['admin'] },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('employee', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalled();
  });

  it('denies access when no roles claim exists (fail-closed)', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true, sub: 'u3', email: 'old@example.com' },
    });

    const handler = jest.fn();
    const wrapped = withRoleAuth('admin', handler);
    const { req, res } = createMocks();

    await wrapped(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(handler).not.toHaveBeenCalled();
  });
});
