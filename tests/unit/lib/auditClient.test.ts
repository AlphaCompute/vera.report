/**
 * Unit Tests — Audit Client (lib/auditClient.ts)
 * Tests the thin HTTP client that proxies audit log operations to Express.
 */

const originalEnv = { ...process.env };

beforeEach(() => {
  process.env.BACKEND_URL = 'http://localhost:3001';
  process.env.INTERNAL_API_SECRET = 'test-secret';
  jest.restoreAllMocks();
});

afterEach(() => {
  process.env = { ...originalEnv };
});

// Re-import fresh for each test to pick up env changes
function getModule() {
  jest.resetModules();
  return require('../../../lib/auditClient');
}

describe('logAuditEvent', () => {
  it('should POST to the backend audit-log endpoint', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true }), { status: 200 }),
    );

    const { logAuditEvent } = getModule();
    logAuditEvent({
      adminUserId: 'user-1',
      adminEmail: 'admin@example.com',
      action: 'stats_view',
      endpoint: '/api/test',
      method: 'GET',
      responseStatus: 200,
      details: {},
    });

    // Wait for the fire-and-forget fetch to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(fetchSpy).toHaveBeenCalledWith(
      'http://localhost:3001/api/admin/audit-log',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'x-internal-secret': 'test-secret',
        }),
      }),
    );

    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    expect(body.action).toBe('stats_view');
    expect(body.adminEmail).toBe('admin@example.com');
  });

  it('should not throw when fetch fails', async () => {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

    const { logAuditEvent } = getModule();
    // Should not throw
    logAuditEvent({
      adminUserId: 'user-1',
      adminEmail: 'admin@example.com',
      action: 'stats_view',
      endpoint: '/api/test',
      method: 'GET',
      responseStatus: 200,
      details: {},
    });

    await new Promise((r) => setTimeout(r, 50));

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[AUDIT_CLIENT] Failed to send audit log'),
    );
  });

  it('should not call fetch when INTERNAL_API_SECRET is missing', async () => {
    delete process.env.INTERNAL_API_SECRET;
    const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{}', { status: 200 }),
    );
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

    const { logAuditEvent } = getModule();
    logAuditEvent({
      adminUserId: 'user-1',
      adminEmail: 'admin@example.com',
      action: 'stats_view',
      endpoint: '/api/test',
      method: 'GET',
      responseStatus: 200,
      details: {},
    });

    await new Promise((r) => setTimeout(r, 50));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('INTERNAL_API_SECRET not set'),
    );
  });
});

describe('queryAuditLogs', () => {
  it('should GET from the backend audit-logs endpoint with query params', async () => {
    const mockData = { entries: [], total: 0, page: 1, limit: 50 };
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: mockData }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const { queryAuditLogs } = getModule();
    const result = await queryAuditLogs({
      action: 'stats_view',
      page: 2,
      limit: 25,
    });

    const fetchSpy = globalThis.fetch as jest.MockedFunction<typeof fetch>;
    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain('action=stats_view');
    expect(url).toContain('page=2');
    expect(url).toContain('limit=25');
    expect(result).toEqual(mockData);
  });

  it('should include x-internal-secret header', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { entries: [], total: 0, page: 1, limit: 50 } }), {
        status: 200,
      }),
    );

    const { queryAuditLogs } = getModule();
    await queryAuditLogs({});

    const fetchSpy = globalThis.fetch as jest.MockedFunction<typeof fetch>;
    const opts = fetchSpy.mock.calls[0][1] as RequestInit;
    expect((opts.headers as Record<string, string>)['x-internal-secret']).toBe('test-secret');
  });

  it('should throw when INTERNAL_API_SECRET is missing', async () => {
    delete process.env.INTERNAL_API_SECRET;

    const { queryAuditLogs } = getModule();
    await expect(queryAuditLogs({})).rejects.toThrow('INTERNAL_API_SECRET not configured');
  });

  it('should throw when backend returns non-OK response', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('Internal Server Error', { status: 500 }),
    );

    const { queryAuditLogs } = getModule();
    await expect(queryAuditLogs({})).rejects.toThrow('Audit logs query failed (500)');
  });
});
