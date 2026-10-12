import { addRequestId } from '@utils/errorResponse';
import { ErrorMonitor } from '@utils/errorMonitor';

describe('addRequestId middleware', () => {
  function createMockReqRes(headers: Record<string, string> = {}) {
    const req: any = { headers };
    const res: any = {
      _headers: {} as Record<string, string>,
      setHeader(name: string, value: string) {
        this._headers[name] = value;
      },
    };
    const next = jest.fn();
    return { req, res, next };
  }

  it('generates a request ID when none is provided', () => {
    const { req, res, next } = createMockReqRes();

    addRequestId(req, res, next);

    expect(req.requestId).toMatch(/^req_\d+_[a-f0-9]{10}$/);
    expect(res._headers['X-Request-ID']).toBe(req.requestId);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('uses incoming X-Request-ID header when present', () => {
    const { req, res, next } = createMockReqRes({ 'x-request-id': 'client-123' });

    addRequestId(req, res, next);

    expect(req.requestId).toBe('client-123');
    expect(res._headers['X-Request-ID']).toBe('client-123');
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('ignores empty X-Request-ID header', () => {
    const { req, res, next } = createMockReqRes({ 'x-request-id': '' });

    addRequestId(req, res, next);

    expect(req.requestId).toMatch(/^req_\d+_[a-f0-9]{10}$/);
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe('ErrorMonitor middleware requestId propagation', () => {
  let monitor: ErrorMonitor;
  let logSpy: jest.SpyInstance;

  beforeEach(() => {
    monitor = new ErrorMonitor();
    // Spy on logError but prevent the real implementation from running
    // (avoids recursive triggerAlert -> logError loop in test context)
    logSpy = jest.spyOn(monitor, 'logError').mockReturnValue('err_mock');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('attaches logError to request and calls next', () => {
    const req: any = {
      requestId: 'req_test_abc123',
      method: 'GET',
      originalUrl: '/api/test',
      get: () => 'test-agent',
      ip: '127.0.0.1',
    };
    const res: any = {};
    const next = jest.fn();

    const middleware = monitor.middleware();
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(typeof req.logError).toBe('function');
  });

  it('includes requestId in error context for nonsensitive requests', () => {
    const req: any = {
      requestId: 'req_test_abc123',
      method: 'POST',
      originalUrl: '/api/test',
      get: () => 'test-agent',
      ip: '192.168.1.1',
    };
    const res: any = {};
    const next = jest.fn();

    const middleware = monitor.middleware();
    middleware(req, res, next);

    req.logError('something broke', 'error', { extra: 'data' });

    expect(logSpy).toHaveBeenCalledWith(
      'something broke',
      'error',
      expect.objectContaining({
        requestId: 'req_test_abc123',
        endpoint: 'POST /api/test',
        extra: 'data',
      })
    );
  });
  it.each(['/api/confidential/channel/call', '/legal'])('suppresses logging and returns a private marker for %s', originalUrl => {
    const req: any = {
      requestId: 'req_private_abc123', method: 'POST', originalUrl,
      userId: 'private-identity',
    };
    const next = jest.fn();
    monitor.middleware()(req, {}, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.logError('private narrative', 'critical', { extra: 'private data' })).toBe('private-request');
    expect(logSpy).not.toHaveBeenCalled();
  });

  it.each(['POST', 'POST private-value'])('retains only an allowlisted method and legacy route family (%s)', method => {
    const req: any = { method, originalUrl: '/api/whistleblower/private-token?secret=private-value',
      requestId: 'private-request', userId: 'private-user' };
    monitor.middleware()(req, {}, jest.fn());
    expect(req.logError('private narrative', 'critical', { stack: 'private stack' })).toBe('private-request');
    expect(logSpy).toHaveBeenCalledWith('Private request failed', 'critical', {
      endpoint: `${method === 'POST' ? 'POST' : 'UNKNOWN'} /whistleblower/[redacted]`
    });
  });

});
