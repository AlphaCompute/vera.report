import { Writable } from 'node:stream';
import type { ServerResponse } from 'node:http';
jest.mock('../../../src/utils/evidenceLimits', () => ({ MAX_STORED_EVIDENCE_BYTES: 4 * 1024 * 1024 }));
import { streamEvidenceResponse } from '../../../src/utils/streamEvidenceResponse';

it('applies backpressure instead of buffering a whole download', async () => {
  let pulls = 0;
  let unblock!: () => void;
  let blocked = true;
  let received = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulls === 32) { controller.close(); return; }
      pulls++; controller.enqueue(new Uint8Array(64 * 1024));
    },
  });
  const response = new Writable({ highWaterMark: 1, write(chunk, _encoding, callback) {
    received += chunk.length;
    if (blocked) unblock = () => { blocked = false; callback(); }; else callback();
  } });
  const work = streamEvidenceResponse(body, response as unknown as ServerResponse);
  await new Promise(resolve => setTimeout(resolve, 30));
  expect(pulls).toBeLessThan(10);
  unblock(); await work;
  expect(received).toBe(2 * 1024 * 1024);
});
it('cancels the upstream on oversized output', async () => {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); },
    cancel() { cancelled = true; },
  });
  const response = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  await expect(streamEvidenceResponse(body, response as unknown as ServerResponse)).rejects.toThrow(/exceeds limit/);
  expect(cancelled).toBe(true);
});
