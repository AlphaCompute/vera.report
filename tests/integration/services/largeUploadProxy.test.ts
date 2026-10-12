/** Real HTTP Next proxy -> multipart reader. No fetch or upload middleware doubles.
 * Crypto/Kubo full-size acceptance runs separately in check-large-evidence.cjs. */
import express from 'express';
import crypto from 'node:crypto';
import type { Server } from 'node:http';
import { Readable } from 'node:stream';
import handler from '../../../pages/api/whistleblower/submit';
import { evidenceUpload } from '../../../src/middleware/evidenceUpload';
import { MAX_MEDIA_BYTES } from '../../../src/utils/evidenceLimits';

it('streams a 256 MiB multipart media upload through Next into the real upload reader', async () => {
  const previous = { ...process.env };
  process.env.INTERNAL_API_SECRET = 'synthetic-large-upload-proxy-secret-at-least-32';
  process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
  const servers: Server[] = [];
  const listen = async (app: express.Express) => {
    const server = await new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    servers.push(server);
    return `http://127.0.0.1:${(server.address() as any).port}`;
  };
  try {
    const backend = express();
    backend.post('/api/whistleblower/submit', evidenceUpload.single('files'), (req, res) => {
      res.json({ size: req.file!.size, hash: crypto.createHash('sha256').update(req.file!.buffer).digest('hex'), key: req.get('x-idempotency-key') });
    });
    process.env.BACKEND_URL = await listen(backend);
    const frontend = express();
    frontend.post('/submit', (req, res) => handler(req as any, res as any));
    const url = await listen(frontend);
    const block = Buffer.alloc(1024 * 1024, 73);
    const preamble = Buffer.from('--test-boundary\r\nContent-Disposition: form-data; name="files"; filename="large.mp4"\r\nContent-Type: video/mp4\r\n\r\n');
    const epilogue = Buffer.from('\r\n--test-boundary--\r\n');
    const contentLength = preamble.length + (256 * block.length) + epilogue.length;
    const expected = crypto.createHash('sha256');
    async function* multipart() {
      yield preamble;
      for (let i = 0; i < 256; i++) { expected.update(block); yield block; }
      yield epilogue;
    }
    const response = await fetch(url + '/submit', {
      method: 'POST', headers: {
        'content-type': 'multipart/form-data; boundary=test-boundary',
        'content-length': String(contentLength),
        'x-idempotency-key': 'synthetic-large-upload',
      },
      body: Readable.toWeb(Readable.from(multipart())), duplex: 'half',
    } as RequestInit & { duplex: 'half' });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ size: MAX_MEDIA_BYTES, hash: expected.digest('hex'), key: 'synthetic-large-upload' });
  } finally {
    process.env = previous;
    await Promise.all(servers.map(server => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); })));
  }
}, 120_000);
