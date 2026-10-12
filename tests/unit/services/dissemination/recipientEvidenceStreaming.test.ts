import { Writable } from 'node:stream';
import type { Response as ExpressResponse } from 'express';
jest.mock('../../../../src/services/reportPersistence', () => ({ reportPersistenceService: {
  listEvidenceByTrackingIds: async () => [{ fileKey: 'report/private-name.mp4' }],
} }));
import { sendRecipientEvidence } from '../../../../src/services/dissemination/evidenceAccess';
import { requestRateLimitKey } from '../../../../src/utils/proxyRateLimit';
import type { Request } from 'express';
const originalFetch = global.fetch, secret = process.env.INTERNAL_API_SECRET;
beforeEach(() => { process.env.INTERNAL_API_SECRET = 'synthetic'; });
afterEach(() => { global.fetch = originalFetch; if (secret === undefined) delete process.env.INTERNAL_API_SECRET; else process.env.INTERNAL_API_SECRET = secret; });
function response(write: (chunk: Buffer, encoding: BufferEncoding, callback: (error?: Error | null) => void) => void) {
  return Object.assign(new Writable({ highWaterMark: 1, write }), { setHeader: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() });
}

it('keeps distinct authorized recipient capabilities out of a shared loopback quota', async () => {
  const keys: string[] = [];
  global.fetch = jest.fn().mockImplementation(async (url, options) => {
    keys.push(requestRateLimitKey({ headers: options.headers, method: 'GET', originalUrl: new URL(url).pathname,
      ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' } } as Request));
    expect(JSON.stringify(options.headers)).not.toMatch(/synthetic-capability-[ab]/);
    return new Response('synthetic evidence');
  });
  for (const capability of ['synthetic-capability-a', 'synthetic-capability-b', 'synthetic-capability-a']) {
    const output = response((_chunk, _encoding, callback) => callback());
    await sendRecipientEvidence('report', '0', output as unknown as ExpressResponse, async () => true, capability);
  }
  expect(keys).toHaveLength(3);
  expect(keys[0]).not.toBe(keys[1]);
  expect(keys[0]).toBe(keys[2]);
  expect(keys.every(key => key.startsWith('web:'))).toBe(true);
});

it('keeps a slow recipient from pulling the whole upstream evidence into memory', async () => {
  let pulls = 0, received = 0, blocked = true, unblock!: () => void;
  const body = new ReadableStream<Uint8Array>({ pull(controller) {
    if (pulls === 32) { controller.close(); return; }
    pulls++; controller.enqueue(new Uint8Array(64 * 1024));
  } });
  global.fetch = jest.fn().mockResolvedValue(new Response(body));
  const output = response((chunk, _encoding, callback) => {
    received += chunk.length;
    if (blocked) unblock = () => { blocked = false; callback(); }; else callback();
  });
  const result = sendRecipientEvidence('report', '0', output as unknown as ExpressResponse, async () => true, 'synthetic-capability-a');
  await new Promise(resolve => setTimeout(resolve, 30));
  expect(pulls).toBeLessThan(10);
  unblock(); expect(await result).toBe(true);
  expect(received).toBe(2 * 1024 * 1024);
  expect(output.setHeader).toHaveBeenCalledWith('Content-Disposition', 'attachment; filename="evidence-1.mp4"');
});

it('cancels unread plaintext on revoked access without forwarding bytes', async () => {
  const cancelled = jest.fn();
  global.fetch = jest.fn().mockResolvedValue(new Response(new ReadableStream({ cancel: cancelled })));
  const write = jest.fn((_chunk, _encoding, callback) => callback());
  const output = response(write);
  expect(await sendRecipientEvidence('report', '0', output as unknown as ExpressResponse, async () => false, 'synthetic-capability-a')).toBe(false);
  expect(write).not.toHaveBeenCalled(); expect(cancelled).toHaveBeenCalled();
  expect(output.status).toHaveBeenCalledWith(403);
});

it('aborts a pending upstream fetch when the recipient disconnects', async () => {
  let started!: () => void;
  const pending = new Promise<void>(resolve => { started = resolve; });
  global.fetch = jest.fn().mockImplementation((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('Synthetic abort')), { once: true }); started();
  }));
  const output = response((_chunk, _encoding, callback) => callback());
  const result = sendRecipientEvidence('report', '0', output as unknown as ExpressResponse, async () => true, 'synthetic-capability-a');
  const assertion = expect(result).rejects.toThrow('Synthetic abort');
  await pending; output.destroy(); await assertion;
});
