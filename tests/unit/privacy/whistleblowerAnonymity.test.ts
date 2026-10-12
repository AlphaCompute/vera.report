/**
 * Unit Tests — Privacy: Whistleblower Anonymity
 * Proves the submit proxy only forwards safe headers and doesn't leak IP/UA.
 */

describe('Privacy: Whistleblower Submit Proxy', () => {
  let handler: (req: any, res: any) => Promise<any>;
  let capturedFetchArgs: { url: string; init: RequestInit } | null;
  const originalFetch = global.fetch;

  beforeEach(() => {
    capturedFetchArgs = null;
    process.env.INTERNAL_API_SECRET = 'synthetic-privacy-proxy-secret-at-least-32';
    process.env.FRONTEND_TRUST_PROXY_HOPS = '0';

    // Mock global fetch to capture what the proxy sends
    global.fetch = jest.fn(async (url: any, init?: any) => {
      capturedFetchArgs = { url: String(url), init: init || {} };
      return {
        status: 200,
        json: async () => ({ success: true, trackingId: 'TRK-TEST' }),
      } as Response;
    });

    // Fresh import each test to pick up the mock
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    handler = require('../../../pages/api/whistleblower/submit').default;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  function mockReq(overrides: Record<string, unknown> = {}): any {
    const body = Buffer.from('test body');
    const chunks = [body];
    return {
      once: jest.fn(), removeListener: jest.fn(), destroy: jest.fn(),
      method: 'POST',
      socket: { remoteAddress: '198.51.100.7' },
      headers: {
        'content-type': 'multipart/form-data; boundary=----test',
        'content-length': String(body.length),
        'x-forwarded-for': '1.2.3.4',
        'x-real-ip': '1.2.3.4',
        'user-agent': 'Whistleblower-Browser/1.0',
        cookie: 'session=abc123',
        authorization: 'Bearer token',
      },
      [Symbol.asyncIterator]: async function* () {
        for (const c of chunks) yield c;
      },
      ...overrides,
    };
  }

  function mockRes(): any {
    const res: any = { statusCode: 200, body: null, once: jest.fn(), removeListener: jest.fn(), setHeader: jest.fn() };
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

  it('should forward only the multipart type without identifying headers', async () => {
    const req = mockReq();
    const res = mockRes();

    await handler(req, res);

    expect(capturedFetchArgs).not.toBeNull();
    const headers = capturedFetchArgs!.init.headers as Record<string, string>;

    expect(headers['content-type']).toContain('multipart/form-data');
    expect(headers['content-length']).toBeUndefined();

    // Must NOT forward identifying headers
    expect(headers).not.toHaveProperty('x-forwarded-for');
    expect(headers).not.toHaveProperty('x-real-ip');
    expect(headers).not.toHaveProperty('user-agent');
    expect(headers).not.toHaveProperty('cookie');
    expect(headers).not.toHaveProperty('authorization');
  });

  it('should return 405 for non-POST methods', async () => {
    const req = mockReq({ method: 'GET' });
    const res = mockRes();

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(405);
    expect(res.body).toEqual({ error: 'Method not allowed' });
  });

  it('should return 502 when backend is unreachable', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    });

    // Re-import with new fetch
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const freshHandler = require('../../../pages/api/whistleblower/submit').default;

    const req = mockReq();
    const res = mockRes();

    await freshHandler(req, res);

    expect(res.status).toHaveBeenCalledWith(502);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Failed to submit report');
  });
});
