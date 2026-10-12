import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import type { NextApiRequest, NextApiResponse } from 'next';
import {
  UPLOAD_MIN_BYTES_PER_SEC,
  UPLOAD_RECEIVE_MAX_MS,
  uploadReceiveDeadlineMs,
} from '../../../src/utils/evidenceLimits';

describe('submission proxy receive-phase capacity', () => {
  const originalFetch = global.fetch;
  const secret = 'synthetic-submit-slot-proxy-secret-at-least-32';

  beforeEach(() => {
    process.env.INTERNAL_API_SECRET = secret;
    process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
    jest.resetModules();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.useRealTimers();
  });

  function mockRes(): NextApiResponse {
    return {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      once: jest.fn(),
      removeListener: jest.fn(),
      setHeader: jest.fn(),
      headersSent: false,
      destroyed: false,
    } as unknown as NextApiResponse;
  }

  function hangingRequest(
    bytesPerTick: number,
    ip = '198.51.100.7',
    contentLength = '100000000',
  ): NextApiRequest & { stopped: boolean } {
    const req = new EventEmitter() as unknown as NextApiRequest & EventEmitter & { stopped: boolean };
    req.stopped = false;
    req.method = 'POST';
    req.complete = false;
    req.headers = {
      'content-type': 'multipart/form-data; boundary=x',
      'content-length': contentLength,
    };
    Object.defineProperty(req, 'socket', { value: { remoteAddress: ip } });
    req.destroy = jest.fn(() => { req.stopped = true; }) as typeof req.destroy;
    (req as any)[Symbol.asyncIterator] = async function* () {
      while (!req.stopped) {
        yield Buffer.alloc(bytesPerTick);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    };
    return req;
  }

  function quickRequest(ip: string): NextApiRequest {
    const bytes = Buffer.from('--x\r\n\r\nheld\r\n');
    const req = Readable.from([bytes]) as unknown as NextApiRequest;
    req.method = 'POST';
    Object.defineProperty(req, 'socket', { value: { remoteAddress: ip } });
    req.headers = {
      'content-type': 'multipart/form-data; boundary=x',
      'content-length': String(bytes.length),
    };
    return req;
  }

  async function expectSlotReleasedAfterAbort(req: NextApiRequest & { stopped: boolean }, seconds: number) {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const handler = require('../../../pages/api/whistleblower/submit').default;
    global.fetch = jest.fn((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    })) as typeof fetch;

    const res = mockRes();
    const first = handler(req, res);
    for (let second = 0; second < seconds; second++) {
      await jest.advanceTimersByTimeAsync(1000);
    }
    expect(req.destroy).toHaveBeenCalled();
    await first;
    expect(res.status).toHaveBeenCalledWith(502);

    global.fetch = jest.fn().mockResolvedValue({ status: 200, json: async () => ({ ok: true }) });
    const secondRes = mockRes();
    await handler(quickRequest('198.51.100.8'), secondRes);
    expect(secondRes.status).toHaveBeenCalledWith(200);
  }

  it('rejects missing Content-Length before taking the transfer slot', async () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const handler = require('../../../pages/api/whistleblower/submit').default;
    global.fetch = jest.fn();
    const req = Readable.from([Buffer.from('x')]) as unknown as NextApiRequest;
    req.method = 'POST';
    Object.defineProperty(req, 'socket', { value: { remoteAddress: '198.51.100.7' } });
    req.headers = { 'content-type': 'multipart/form-data; boundary=x' };
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(411);
    expect(global.fetch).not.toHaveBeenCalled();

    global.fetch = jest.fn().mockResolvedValue({ status: 200, json: async () => ({ ok: true }) });
    const admittedRes = mockRes();
    await handler(quickRequest('198.51.100.7'), admittedRes);
    expect(admittedRes.status).toHaveBeenCalledWith(200);
  });

  it('releases the sole slot after a below-floor drip aborts the incomplete body', async () => {
    jest.useFakeTimers();
    await expectSlotReleasedAfterAbort(hangingRequest(1024), 31);
  });

  it('releases the sole slot at the scaled receive ceiling with steady above-floor progress', async () => {
    jest.useFakeTimers();
    const contentLength = String(UPLOAD_MIN_BYTES_PER_SEC * (UPLOAD_RECEIVE_MAX_MS / 1000));
    const deadlineSec = uploadReceiveDeadlineMs(Number(contentLength)) / 1000;
    expect(deadlineSec).toBe(UPLOAD_RECEIVE_MAX_MS / 1000);
    await expectSlotReleasedAfterAbort(
      hangingRequest(UPLOAD_MIN_BYTES_PER_SEC, '198.51.100.7', contentLength),
      deadlineSec,
    );
  });

  it('releases above-floor drips that fall behind completion pace after grace', async () => {
    jest.useFakeTimers();
    // Large CL so the floor rate alone cannot stay on pace to finish within the ceiling.
    const contentLength = String(16 * 1024 * 1024);
    const aboveFloor = Math.floor(UPLOAD_MIN_BYTES_PER_SEC * 1.25);
    await expectSlotReleasedAfterAbort(
      hangingRequest(aboveFloor, '198.51.100.11', contentLength),
      31,
    );
  });

  it('releases small declared bodies before the five-minute cap', async () => {
    jest.useFakeTimers();
    const contentLength = String(UPLOAD_MIN_BYTES_PER_SEC * 90);
    const deadlineSec = uploadReceiveDeadlineMs(Number(contentLength)) / 1000;
    expect(deadlineSec).toBeLessThan(UPLOAD_RECEIVE_MAX_MS / 1000);
    await expectSlotReleasedAfterAbort(
      hangingRequest(UPLOAD_MIN_BYTES_PER_SEC, '198.51.100.7', contentLength),
      deadlineSec,
    );
  });

  it('admits two different clients and rejects a third when process capacity is full', async () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const handler = require('../../../pages/api/whistleblower/submit').default;
    jest.useFakeTimers();
    global.fetch = jest.fn((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    })) as typeof fetch;

    const holdA = hangingRequest(1024, '198.51.100.1');
    const holdB = hangingRequest(1024, '198.51.100.2');
    const pendingA = handler(holdA, mockRes());
    const pendingB = handler(holdB, mockRes());
    expect(global.fetch).toHaveBeenCalledTimes(2);

    const busyRes = mockRes();
    await handler(quickRequest('198.51.100.3'), busyRes);
    expect(busyRes.setHeader).toHaveBeenCalledWith('Retry-After', '30');
    expect(busyRes.status).toHaveBeenCalledWith(503);
    expect(busyRes.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'upload_capacity_busy' }));
    expect(global.fetch).toHaveBeenCalledTimes(2);

    for (let second = 0; second < 31; second++) {
      await jest.advanceTimersByTimeAsync(1000);
    }
    await Promise.all([pendingA, pendingB]);
  });

  it('rejects a second concurrent transfer from the same client while a slot remains', async () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const handler = require('../../../pages/api/whistleblower/submit').default;
    jest.useFakeTimers();
    const holder = hangingRequest(1024, '198.51.100.1');
    global.fetch = jest.fn((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    })) as typeof fetch;
    const holdRes = mockRes();
    const pending = handler(holder, holdRes);

    const sameClientBusy = mockRes();
    await handler(quickRequest('198.51.100.1'), sameClientBusy);
    expect(sameClientBusy.setHeader).toHaveBeenCalledWith('Retry-After', '30');
    expect(sameClientBusy.status).toHaveBeenCalledWith(503);
    expect(sameClientBusy.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'upload_capacity_busy' }));
    expect(global.fetch).toHaveBeenCalledTimes(1);

    const otherClient = mockRes();
    // Hang the second process slot so we do not race the quota map with a completed quick request.
    const otherHold = hangingRequest(1024, '198.51.100.2');
    const pendingOther = handler(otherHold, otherClient);
    expect(global.fetch).toHaveBeenCalledTimes(2);

    for (let second = 0; second < 31; second++) {
      await jest.advanceTimersByTimeAsync(1000);
    }
    await Promise.all([pending, pendingOther]);
    expect(holdRes.status).toHaveBeenCalledWith(502);
  });

  it('rejects a sixth admit from the same quota key without taking the slot', async () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const handler = require('../../../pages/api/whistleblower/submit').default;
    global.fetch = jest.fn().mockResolvedValue({ status: 200, json: async () => ({ ok: true }) });
    const ip = '198.51.100.9';

    for (let i = 0; i < 5; i++) {
      const res = mockRes();
      await handler(quickRequest(ip), res);
      expect(res.status).toHaveBeenCalledWith(200);
    }

    const limited = mockRes();
    await handler(quickRequest(ip), limited);
    expect(limited.setHeader).toHaveBeenCalledWith('Retry-After', '60');
    expect(limited.status).toHaveBeenCalledWith(429);
    expect(global.fetch).toHaveBeenCalledTimes(5);

    const other = mockRes();
    await handler(quickRequest('198.51.100.10'), other);
    expect(other.status).toHaveBeenCalledWith(200);
    expect(global.fetch).toHaveBeenCalledTimes(6);
  });
});
