import type { NextApiRequest, NextApiResponse } from 'next';
import { ROLES_CLAIM } from '@/lib/roles';

const mockGetSession = jest.fn();
const mockWithApiAuthRequired = jest.fn((handler: Function) => handler);

jest.mock('@/lib/auth0', () => ({
  auth0: {
    getSession: (...args: unknown[]) => mockGetSession(...args),
    withApiAuthRequired: (handler: Function) => mockWithApiAuthRequired(handler),
  },
}));

// Dynamic import after mocks are set up
let handler: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

beforeAll(async () => {
  const mod = await import('../../../pages/api/admin/me');
  handler = mod.default as unknown as (req: NextApiRequest, res: NextApiResponse) => Promise<void>;
});

function createMocks(method = 'GET') {
  const req = {
    method,
    headers: {},
    socket: {},
  } as unknown as NextApiRequest;
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  } as unknown as NextApiResponse;
  return { req, res };
}

describe('GET /api/admin/me', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockWithApiAuthRequired.mockImplementation((fn: Function) => fn);
  });

  it('returns email, name, and roles for an admin user', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true,
        sub: 'auth0|123',
        email: 'admin@example.com',
        name: 'Admin User',
        [ROLES_CLAIM]: ['admin'],
      },
    });

    const { req, res } = createMocks();
    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      email: 'admin@example.com',
      name: 'Admin User',
      roles: ['admin'],
    });
  });

  it('returns email, null name, and roles for employee user', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true,
        sub: 'auth0|456',
        email: 'emp@example.com',
        [ROLES_CLAIM]: ['employee'],
      },
    });

    const { req, res } = createMocks();
    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      email: 'emp@example.com',
      name: null,
      roles: ['employee'],
    });
  });

  it('returns 405 for non-GET methods', async () => {
    mockGetSession.mockResolvedValue({
      user: { email_verified: true,
        sub: 'auth0|123',
        email: 'admin@example.com',
        [ROLES_CLAIM]: ['admin'],
      },
    });

    const { req, res } = createMocks('POST');
    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(405);
  });
});
// These handler tests isolate provider checks; currentAdminAuthorization.test.ts
// exercises the real authorization gate against synthetic Management API responses.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name,
    roles: user['https://vera.app/roles'] ?? [],
  }),
}));
