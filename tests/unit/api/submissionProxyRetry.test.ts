import { Readable } from 'node:stream';
import type { NextApiRequest, NextApiResponse } from 'next';
import handler from '../../../pages/api/whistleblower/submit';

describe('submission proxy retry credential', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; });
  test.each([undefined, 'a'.repeat(64)])('forwards optional credential and unchanged multipart bytes: %s', async key => {
    const bytes = Buffer.from('--boundary\r\nsynthetic multipart body\r\n--boundary--');
    const req = Readable.from([bytes]) as unknown as NextApiRequest;
    req.method = 'POST';
    Object.defineProperty(req, 'socket', { value: { remoteAddress: '198.51.100.7' } });
    process.env.INTERNAL_API_SECRET = 'synthetic-retry-proxy-secret-at-least-32';
    process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
    req.headers = {
      'content-type': 'multipart/form-data; boundary=boundary',
      'content-length': String(bytes.length),
      ...(key ? { 'x-idempotency-key': key } : {}),
    };
    const json = jest.fn();
    const status = jest.fn().mockReturnValue({ json });
    const upstream = jest.fn().mockResolvedValue({ status: 503, json: async () => ({ success: false, error: 'submission_in_progress' }) });
    global.fetch = upstream;
    await handler(req, { status, once: jest.fn(), removeListener: jest.fn(), setHeader: jest.fn() } as unknown as NextApiResponse);
    const options = upstream.mock.calls[0][1];
    expect(options.headers['x-idempotency-key']).toBe(key);
    expect(Buffer.from(await new Response(options.body).arrayBuffer())).toEqual(bytes);
    expect(status).toHaveBeenCalledWith(503);
    expect(json).toHaveBeenCalledWith({ success: false, error: 'submission_in_progress' });
  });
});
