/**
 * Integration Tests — Admin Audit Logs API Endpoint
 * Tests pages/api/admin/audit-logs.ts handler with mocked Auth0.
 */

jest.mock('../../../lib/auth0', () => ({
  auth0: {
    withApiAuthRequired: (fn: Function) => fn,
    getSession: jest.fn().mockResolvedValue({
      user: {
        sub: 'auth0|test-admin',
        email: 'admin@example.com',
        name: 'Test Admin',
      },
    }),
  },
}));

jest.mock('../../../lib/auditClient', () => {
  const mockQueryAuditLogs = jest.fn();
  return {
    queryAuditLogs: mockQueryAuditLogs,
    logAuditEvent: jest.fn(),
  };
});

import handler from '../../../pages/api/admin/audit-logs';
import { queryAuditLogs } from '../../../lib/auditClient';

const mockQuery = queryAuditLogs as jest.MockedFunction<typeof queryAuditLogs>;

function mockReq(overrides: Record<string, unknown> = {}): any {
  return {
    method: 'GET',
    query: {},
    headers: {},
    ...overrides,
  };
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

describe('GET /api/admin/audit-logs', () => {
  beforeEach(() => {
    mockQuery.mockReset();
    mockQuery.mockResolvedValue({ entries: [], total: 0, page: 1, limit: 50 });
  });

  it('should return 405 for non-GET methods', async () => {
    const req = mockReq({ method: 'POST' });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(res.status).toHaveBeenCalledWith(405);
    expect(res.body.error).toBe('Method not allowed');
  });

  it('should return 400 for invalid action value', async () => {
    const req = mockReq({ query: { action: 'hack_system' } });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Invalid action');
  });

  it('should return 400 for invalid severity value', async () => {
    const req = mockReq({ query: { severity: 'banana' } });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Invalid severity');
  });

  it('should parse startDate/endDate as Date objects', async () => {
    const req = mockReq({
      query: {
        startDate: '2025-01-01T00:00:00Z',
        endDate: '2025-12-31T23:59:59Z',
      },
    });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(mockQuery).toHaveBeenCalledWith(
      expect.objectContaining({
        startDate: expect.any(Date),
        endDate: expect.any(Date),
      }),
    );
    const callArgs = mockQuery.mock.calls[0][0];
    expect(callArgs.startDate!.toISOString()).toBe('2025-01-01T00:00:00.000Z');
    expect(callArgs.endDate!.toISOString()).toBe('2025-12-31T23:59:59.000Z');
  });

  it('should parse page/limit as integers', async () => {
    const req = mockReq({ query: { page: '3', limit: '25' } });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(mockQuery).toHaveBeenCalledWith(
      expect.objectContaining({ page: 3, limit: 25 }),
    );
  });

  it('should default page=1 and limit=50', async () => {
    const req = mockReq({ query: {} });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(mockQuery).toHaveBeenCalledWith(
      expect.objectContaining({ page: 1, limit: 50 }),
    );
  });

  it('should return { success, data: { entries, total, page, limit } }', async () => {
    mockQuery.mockResolvedValue({
      entries: [{ auditId: 'id-1', action: 'stats_view' }] as any,
      total: 1,
      page: 1,
      limit: 50,
    });

    const req = mockReq({ query: {} });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.body).toEqual({
      success: true,
      data: {
        entries: [{ auditId: 'id-1', action: 'stats_view' }],
        total: 1,
        page: 1,
        limit: 50,
      },
    });
  });

  it('should return 500 when query throws', async () => {
    mockQuery.mockRejectedValue(new Error('DB connection lost'));

    const req = mockReq({ query: {} });
    const res = mockRes();
    await (handler as any)(req, res, {
      userId: 'auth0|test',
      email: 'admin@example.com',
    });

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Failed to query audit logs');
  });
});
