import express from 'express';
import request from 'supertest';
import { createHash } from 'node:crypto';
import { CHUNKS_PER_HOUR, CHUNK_CONTENT_TYPE, createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';
import { paddedChunkBudget } from '../../../enclave/src/confidential/padding';
import { CHUNK_LIMITS, createUploadAdmission } from '../../../src/utils/confidentialAdmission';

const armored = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0opaque\n=abcd\n-----END PGP MESSAGE-----\n';

function app() {
  const staged = new Map<string, string>();
  const server = express();
  server.use(express.json());
  const chunks = new Map<string, Uint8Array>();
  server.use('/api/confidential', createConfidentialObjectRouter({
    async stageObject(digest, ciphertext) { staged.set(digest, ciphertext); },
    async stageChunk(digest, data) { chunks.set(digest, data); },
  }, () => 1_000));
  return { server, staged, chunks };
}

describe('confidential ciphertext staging route', () => {
  test('stores armored ciphertext by the SHA-256 of the exact text', async () => {
    const { server, staged } = app();
    const response = await request(server).post('/api/confidential/objects')
      .set('Content-Type', 'application/pgp-encrypted').send(armored);
    const digest = createHash('sha256').update(armored, 'utf8').digest('hex');
    expect(response.status).toBe(201);
    expect(response.body).toEqual({ digest });
    expect(staged.get(digest)).toBe(armored);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  test.each([
    ['plaintext', 'text/plain', 'PRIVATE-SENTINEL narrative', 415],
    ['JSON', 'application/json', JSON.stringify({ narrative: 'PRIVATE-SENTINEL' }), 415],
    ['unarmored text as ciphertext type', 'application/pgp-encrypted', 'PRIVATE-SENTINEL', 400],
  ])('rejects %s without storing it', async (_name, type, body, status) => {
    const { server, staged } = app();
    const response = await request(server).post('/api/confidential/objects').set('Content-Type', type).send(body);
    expect(response.status).toBe(status);
    expect(staged.size).toBe(0);
    expect(JSON.stringify(response.body)).not.toContain('PRIVATE-SENTINEL');
  });

  test('has no read route', async () => {
    const { server } = app();
    expect((await request(server).get('/api/confidential/objects')).status).toBe(404);
  });
  test('rejects compressed uploads before parsing or storing their body', async () => {
    const { server, staged } = app();
    await request(server).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted')
      .set('Content-Encoding', 'gzip').send(armored).expect(400);
    expect(staged.size).toBe(0);
  });
  test('limits concurrent body/storage work per client without blocking later sequential uploads', async () => {
    const server = express();
    let finish!: () => void, started!: () => void, calls = 0;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const admitted = new Promise<void>(resolve => { started = resolve; });
    server.use('/api/confidential', createConfidentialObjectRouter({ async stageChunk() { /* unused */ }, async stageObject() {
      calls++; if (calls === 2) started(); await gate;
    } }));
    const upload = () => request(server).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted').send(armored);
    const first = upload().then(response => response.status), second = upload().then(response => response.status);
    await admitted;
    await upload().expect(429);
    finish();
    expect(await Promise.all([first, second])).toEqual([201, 201]);
    await upload().expect(201);
  });

  test('an HTTP timeout does not release slots while ciphertext persistence is still running', async () => {
    const server = express();
    let finish!: () => void, started!: () => void, calls = 0, incoming = 0;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const admitted = new Promise<void>(resolve => { started = resolve; });
    server.use((_req, res, next) => {
      incoming++;
      if (incoming <= 2) void admitted.then(() => { res.status(408).json({ error: 'Timeout' }); });
      next();
    });
    server.use('/api/confidential', createConfidentialObjectRouter({ async stageChunk() { /* unused */ }, async stageObject() {
      calls++; if (calls === 2) started(); await gate;
    } }));
    const upload = () => request(server).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted').send(armored);
    const statuses = await Promise.all([upload().then(response => response.status), upload().then(response => response.status)]);
    expect(statuses).toEqual([408, 408]);
    await upload().expect(429);
    expect(calls).toBe(2);
    finish();
    await new Promise(resolve => setImmediate(resolve));
    await upload().expect(201);
    expect(calls).toBe(3);
  });
});

describe('confidential evidence chunk staging route', () => {
  const chunkOf = (size: number, fill = 0x5a) => Buffer.alloc(size, fill);
  const post = (server: express.Express, body: string, type = CHUNK_CONTENT_TYPE) =>
    request(server).post('/api/confidential/chunks').set('Content-Type', type).send(body);

  test.each([512 * 1024 + 16, 4096 + 16, 64 * 1024 + 16])('stores a %i-byte chunk by the SHA-256 of its bytes', async size => {
    const { server, chunks } = app();
    const bytes = chunkOf(size);
    const response = await post(server, bytes.toString('base64')).expect(201);
    const digest = createHash('sha256').update(bytes).digest('hex');
    expect(response.body).toEqual({ digest });
    expect(Buffer.from(chunks.get(digest)!).equals(bytes)).toBe(true);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  test.each([
    ['a size that is not a full chunk or a final bucket', chunkOf(5000 + 16).toString('base64')],
    ['a chunk larger than 512 KiB plus the tag', chunkOf(1024 * 1024 + 16).toString('base64')],
    ['a chunk smaller than the smallest bucket', chunkOf(16).toString('base64')],
    ['non-canonical base64', (value => value.slice(0, -2) + String.fromCharCode(value.charCodeAt(value.length - 2) + 1) + '=')(chunkOf(4096 + 16).toString('base64'))],
    ['plaintext', 'PRIVATE-SENTINEL evidence text'],
  ])('rejects %s without storing it', async (_name, body) => {
    const { server, chunks } = app();
    // An oversized body is refused before it is read; the server may close the
    // connection while the client is still writing, which is also a refusal.
    const response = await post(server, body).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ECONNRESET' && error.code !== 'EPIPE') throw error;
      return undefined;
    });
    if (response) {
      expect([400, 413]).toContain(response.status);
      expect(JSON.stringify(response.body)).not.toContain('PRIVATE-SENTINEL');
    }
    expect(chunks.size).toBe(0);
  });

  test('rejects other content types, compressed bodies and query strings', async () => {
    const { server, chunks } = app();
    const body = chunkOf(4096 + 16).toString('base64');
    await post(server, body, 'application/octet-stream').expect(415);
    await request(server).post('/api/confidential/chunks?case=1').set('Content-Type', CHUNK_CONTENT_TYPE).send(body).expect(400);
    await request(server).post('/api/confidential/chunks').set('Content-Type', CHUNK_CONTENT_TYPE)
      .set('Content-Encoding', 'gzip').send(body).expect(400);
    expect(chunks.size).toBe(0);
  });

  test('refuses a chunk from a foreign browser origin before reading the body', async () => {
    const { server, chunks } = app();
    await request(server).post('/api/confidential/chunks').set('Origin', 'https://attacker.example')
      .set('Content-Type', CHUNK_CONTENT_TYPE).send(chunkOf(4096 + 16).toString('base64')).expect(403);
    expect(chunks.size).toBe(0);
  });

  test('has no read route and reports storage failure without detail', async () => {
    const { server } = app();
    expect((await request(server).get('/api/confidential/chunks')).status).toBe(404);
    const failing = express();
    failing.use('/api/confidential', createConfidentialObjectRouter({ async stageObject() { /* unused */ },
      async stageChunk() { throw new Error('PRIVATE-SENTINEL storage detail'); } }));
    const response = await post(failing, chunkOf(4096 + 16).toString('base64')).expect(503);
    expect(JSON.stringify(response.body)).not.toContain('PRIVATE-SENTINEL');
  });

  test('bounds concurrent chunk uploads per client, separately from object staging', async () => {
    const server = express();
    let finish!: () => void, started!: () => void, calls = 0;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const admitted = new Promise<void>(resolve => { started = resolve; });
    server.use('/api/confidential', createConfidentialObjectRouter({ async stageObject() { /* immediate */ },
      async stageChunk() { calls++; if (calls === CHUNK_LIMITS.clientActive) started(); await gate; } }));
    const body = chunkOf(4096 + 16).toString('base64');
    const pending = Array.from({ length: CHUNK_LIMITS.clientActive }, () => post(server, body).then(response => response.status));
    await admitted;
    await post(server, body).expect(429);
    // Whole-object staging keeps its own slots.
    await request(server).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted').send(armored).expect(201);
    finish();
    expect(await Promise.all(pending)).toEqual(Array(CHUNK_LIMITS.clientActive).fill(201));
    await post(server, body).expect(201);
  });

  test('one client can move 10 GiB of evidence within an hour and the process budget admits several such clients', () => {
    const wire = 4 * Math.ceil((512 * 1024 + 16) / 3);
    // 10 GiB of 512 KiB chunks, after worst-case chunk-count padding (caseChunks.ts).
    const chunks = paddedChunkBudget(10 * 1024 * 2);
    expect(CHUNK_LIMITS.clientHourlyBytes).toBeGreaterThanOrEqual(chunks * wire);
    expect(CHUNKS_PER_HOUR).toBeGreaterThanOrEqual(chunks);
    expect(CHUNK_LIMITS.processDailyBytes).toBeGreaterThanOrEqual(4 * CHUNK_LIMITS.clientHourlyBytes);
    // Memory is bounded by chunk size and in-flight counts, not the budgets.
    expect(CHUNK_LIMITS.processActive * wire).toBeLessThan(32 * 1024 * 1024);
    let now = 0;
    const admit = createUploadAdmission(() => now, CHUNK_LIMITS);
    for (let index = 0; index < chunks; index++) { const release = admit('reporter', wire); expect(release).not.toBeNull(); release!(); }
    // An hour later the same reporter continues.
    now = 3_600_000;
    expect(admit('reporter', wire)).not.toBeNull();
  });
});

describe('confidential staging transfer time', () => {
  test('a slow upload is not cut off by the API-wide 30-second request timer', async () => {
    const { requestTimeout } = await import('../../../src/middleware/security');
    const server = express();
    // Stand-in for the global app.use(requestTimeout(30000)), scaled down.
    server.use(requestTimeout(50));
    server.use('/api/confidential', createConfidentialObjectRouter({
      async stageObject() { await new Promise(resolve => setTimeout(resolve, 200)); },
    }));
    await request(server).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted').send(armored).expect(201);
  });

});
