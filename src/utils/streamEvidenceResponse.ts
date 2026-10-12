import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ServerResponse } from 'node:http';
import { MAX_STORED_EVIDENCE_BYTES } from './evidenceLimits';

/** Backpressure and cancellation keep the 1 GiB frontend from buffering media. */
export async function streamEvidenceResponse(body: ReadableStream<Uint8Array> | null, res: ServerResponse): Promise<void> {
  if (!body) throw new Error('Empty evidence response');
  let size = 0;
  await pipeline(Readable.fromWeb(body as import('node:stream/web').ReadableStream<Uint8Array>), new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      size += chunk.length;
      callback(size > MAX_STORED_EVIDENCE_BYTES ? new Error('Evidence response exceeds limit') : null, chunk);
    },
  }), res);
}
