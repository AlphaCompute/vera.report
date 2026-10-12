import { CHANNEL_ADMISSION } from '../../../src/utils/confidentialAdmission';
/**
 * Regression tests for the confidential API hardening pass
 * (docs/security/README.md#verification):
 * origin and content-type admission, route-scoped body limits, enclave
 * load shedding, the anonymous staging byte budget and constant-time secret
 * comparison. Every rejection must happen before the enclave or store is called
 * and must not echo the request.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import express from 'express';
import bodyParser from 'body-parser';
import request from 'supertest';
import { createConfidentialChannelRouter, CHANNEL_JSON_LIMIT, MAX_CIPHERTEXT, ENCLAVE_MAX_FRAME } from '../../../src/api/confidentialChannel';
import { createConfidentialObjectRouter, stagingHourlyBytes, STAGING_HOURLY_BYTES_DEFAULT, MAX_STAGED_CIPHERTEXT } from '../../../src/api/confidentialObjects';
import { configuredFrontendOrigins, exceptConfidentialApi, isConfidentialApiPath } from '../../../src/middleware/confidentialRequestGuard';
import { internalSecretMatches } from '../../../src/middleware/internalSecret';
import { apiTrustProxyHops } from '../../../src/utils/trustProxy';
import { throwIfThrottled } from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';

const NONCE = 'ab'.repeat(32);
/** Each channel open reserves its nonce (src/utils/confidentialAdmission.ts), so
 * tests that open several sessions use a fresh one per request. */
let nonceCounter = 0;
const freshNonce = () => (++nonceCounter).toString(16).padStart(64, '0');
/** Distinct reporter addresses, so the per-address session lease cap does not
 * mask the behaviour a test is checking. */
let addressCounter = 0;
const freshAddress = () => `198.18.${Math.floor(++addressCounter / 250)}.${addressCounter % 250 + 1}`;
const ARMORED = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0opaque\n=abcd\n-----END PGP MESSAGE-----\n';
const ALLOWED = ['https://vera.report'];

/** Same parser composition as src/api/server.ts. */
function stack(transport = jest.fn(async (_request: unknown) => ({ document: 'doc', publicKey: 'key', ciphertext: 'reply' })),
  stageObject = jest.fn(async () => undefined), options: { maxInFlight?: number; hourlyByteBudget?: number; clock?: () => number } = {}) {
  const app = express();
  app.set('trust proxy', 1);
  app.use(exceptConfidentialApi(bodyParser.json({ limit: '10mb' })));
  app.use(exceptConfidentialApi(bodyParser.urlencoded({ extended: true, limit: '10mb' })));
  app.use('/api/confidential', createConfidentialObjectRouter({ stageObject }, options.clock ?? Date.now,
    { hourlyByteBudget: options.hourlyByteBudget, allowedOrigins: ALLOWED }));
  app.use('/api/confidential', createConfidentialChannelRouter(transport,
    { maxPerMinute: 10_000, maxInFlight: options.maxInFlight, allowedOrigins: ALLOWED }));
  return { app, transport, stageObject };
}

describe('origin admission', () => {
  test.each([
    ['a foreign origin', { Origin: 'https://attacker.example' }],
    ['an opaque origin', { Origin: 'null' }],
    ['a cross-site fetch without Origin', { 'Sec-Fetch-Site': 'cross-site' }],
    ['a foreign origin claiming same-origin', { Origin: 'https://vera.report.attacker.example', 'Sec-Fetch-Site': 'same-origin' }],
  ])('refuses %s before the enclave or store is reached', async (_name, headers) => {
    const { app, transport, stageObject } = stack();
    for (const [path, type, body] of [
      ['/api/confidential/channel/open', 'application/json', JSON.stringify({ nonce: NONCE })],
      ['/api/confidential/channel/call', 'application/json', JSON.stringify({ nonce: NONCE, ciphertext: 'x' })],
      ['/api/confidential/objects', 'application/pgp-encrypted', ARMORED],
    ] as const) {
      const response = await request(app).post(path).set(headers).set('Content-Type', type).send(body);
      expect(response.status).toBe(403);
      expect(response.body).toEqual({ error: 'Request not allowed' });
      expect(response.headers['cache-control']).toBe('no-store');
    }
    expect(transport).not.toHaveBeenCalled();
    expect(stageObject).not.toHaveBeenCalled();
  });

  test('admits the site origin and same-origin requests without Origin', async () => {
    const { app } = stack();
    await request(app).post('/api/confidential/channel/open').set('Origin', 'https://vera.report')
      .set('Sec-Fetch-Site', 'same-origin').send({ nonce: freshNonce() }).expect(200);
    await request(app).post('/api/confidential/channel/open').set('Sec-Fetch-Site', 'same-origin').send({ nonce: freshNonce() }).expect(200);
    await request(app).post('/api/confidential/objects').set('Origin', 'https://vera.report')
      .set('Content-Type', 'application/pgp-encrypted').send(ARMORED).expect(201);
  });

  test('the CORS allowlist and the confidential guard share one configuration', () => {
    expect(configuredFrontendOrigins({ CORS_ALLOWED_ORIGINS: ' https://a.example ,https://b.example,' } as NodeJS.ProcessEnv))
      .toEqual(['https://a.example', 'https://b.example']);
    expect(configuredFrontendOrigins({} as NodeJS.ProcessEnv)).toContain('https://vera.report');
  });

  test('the production fallback never admits a plain-HTTP localhost origin', () => {
    const production = configuredFrontendOrigins({ NODE_ENV: 'production' } as NodeJS.ProcessEnv);
    expect(production).toEqual(['https://vera.report', 'https://whistleblower.vera.report']);
    expect(production).not.toContain('http://localhost:3000');
    expect(production.every(origin => origin.startsWith('https://'))).toBe(true);
    // Local development keeps working without configuration.
    expect(configuredFrontendOrigins({ NODE_ENV: 'development' } as NodeJS.ProcessEnv)).toContain('http://localhost:3000');
    // A production allowlist keeps only https:// entries even when configured.
    expect(configuredFrontendOrigins({ NODE_ENV: 'production', CORS_ALLOWED_ORIGINS: 'http://localhost:3000,https://staging.example.com' } as NodeJS.ProcessEnv))
      .toEqual(['https://staging.example.com']);
    // A blank value is not an empty allowlist.
    expect(configuredFrontendOrigins({ NODE_ENV: 'production', CORS_ALLOWED_ORIGINS: ' , ' } as NodeJS.ProcessEnv)).toContain('https://vera.report');
  });

  test('a stack configured with its own domain admits its channel and upload POSTs', async () => {
    const env = process.env as Record<string, string | undefined>;
    const saved = { cors: env.CORS_ALLOWED_ORIGINS, mode: env.NODE_ENV };
    env.CORS_ALLOWED_ORIGINS = 'https://staging.example.com';
    env.NODE_ENV = 'production';
    try {
      const transport = jest.fn(async (_request: unknown) => ({ document: 'doc', publicKey: 'key', ciphertext: 'reply' }));
      const stageObject = jest.fn(async () => undefined);
      const app = express();
      // No allowedOrigins: the routers read the deployment's configuration.
      app.use('/api/confidential', createConfidentialObjectRouter({ stageObject }, Date.now));
      app.use('/api/confidential', createConfidentialChannelRouter(transport, { maxPerMinute: 10_000 }));
      await request(app).post('/api/confidential/channel/open').set('Origin', 'https://staging.example.com')
        .send({ nonce: freshNonce() }).expect(200);
      await request(app).post('/api/confidential/objects').set('Origin', 'https://staging.example.com')
        .set('Content-Type', 'application/pgp-encrypted').send(ARMORED).expect(201);
      for (const origin of ['https://vera.report', 'http://localhost:3000']) {
        await request(app).post('/api/confidential/channel/open').set('Origin', origin)
          .send({ nonce: freshNonce() }).expect(403);
      }
    } finally {
      if (saved.cors === undefined) delete env.CORS_ALLOWED_ORIGINS; else env.CORS_ALLOWED_ORIGINS = saved.cors;
      env.NODE_ENV = saved.mode;
    }
  });
});

describe('content type and body limits', () => {
  test('the channel only accepts JSON; a simple-request content type is refused', async () => {
    const { app, transport } = stack();
    for (const type of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x']) {
      const response = await request(app).post('/api/confidential/channel/open').set('Content-Type', type)
        .send(JSON.stringify({ nonce: NONCE }));
      expect(response.status).toBe(415);
    }
    expect(transport).not.toHaveBeenCalled();
  });

  test.each(['/api/confidential/channel/call', '/API/Confidential/channel/call'])(
    'an oversized call body is refused by the route parser, not buffered by the 10 MB parser (%s)', async path => {
      const { app, transport } = stack();
      const ciphertext = 'A'.repeat(CHANNEL_JSON_LIMIT + 1);
      const response = await request(app).post(path).set('Content-Type', 'application/json')
        .send(JSON.stringify({ nonce: NONCE, ciphertext }));
      expect(response.status).toBe(413);
      expect(response.body).toEqual({ error: 'Request too large' });
      expect(transport).not.toHaveBeenCalled();
    });

  test('malformed JSON gets a fixed reply that never quotes the body', async () => {
    const { app, transport } = stack();
    const response = await request(app).post('/api/confidential/channel/call').set('Content-Type', 'application/json')
      .send('{"nonce":"SENTINEL-BODY"');
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: 'Invalid request' });
    expect(response.text).not.toContain('SENTINEL');
    expect(transport).not.toHaveBeenCalled();
  });

  test('a maximum-size call still fits', async () => {
    const { app, transport } = stack();
    await request(app).post('/api/confidential/channel/call').set('Content-Type', 'application/json')
      .send(JSON.stringify({ nonce: NONCE, ciphertext: 'A'.repeat(MAX_CIPHERTEXT) })).expect(200);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  test('escaped ciphertext fitting the HTTP limit cannot exceed the enclave frame limit', async () => {
    const { app, transport } = stack();
    const overhead = JSON.stringify({ nonce: NONCE, ciphertext: '' }).length;
    const ciphertext = '"'.repeat(Math.floor((ENCLAVE_MAX_FRAME - overhead) / 2));
    const body = JSON.stringify({ nonce: NONCE, ciphertext });
    expect(Buffer.byteLength(body)).toBeLessThanOrEqual(CHANNEL_JSON_LIMIT);
    await request(app).post('/api/confidential/channel/call').set('Content-Type', 'application/json').send(body).expect(413);
    expect(transport).not.toHaveBeenCalled();
  });

  test('global parsers still run for every other route', async () => {
    const app = express();
    app.use(exceptConfidentialApi(bodyParser.json()));
    app.post('/api/whistleblower/x', (req, res) => { res.json(req.body); });
    await request(app).post('/api/whistleblower/x').send({ a: 1 }).expect(200, { a: 1 });
    expect(isConfidentialApiPath('/api/confidentiality')).toBe(false);
    expect(isConfidentialApiPath('/api/confidential')).toBe(true);
  });
});

describe('enclave load shedding', () => {
  test('calls beyond the in-flight cap get a retryable 503 without reaching the enclave', async () => {
    const releases: Array<() => void> = [];
    const transport = jest.fn((_request: unknown) => new Promise<unknown>(resolve => {
      releases.push(() => resolve({ document: 'doc', publicKey: 'key' }));
    }));
    const { app } = stack(transport as never, undefined, { maxInFlight: 2 });
    const server = app.listen(0);
    try {
      const pending = [0, 1].map(() => request(server).post('/api/confidential/channel/open').set('X-Forwarded-For', freshAddress()).send({ nonce: freshNonce() }).then(r => r));
      while (transport.mock.calls.length < 2) await new Promise(resolve => setTimeout(resolve, 5));
      const shed = await request(server).post('/api/confidential/channel/open').set('X-Forwarded-For', freshAddress()).send({ nonce: freshNonce() });
      expect(shed.status).toBe(503);
      expect(shed.headers['retry-after']).toBe('2');
      expect(transport).toHaveBeenCalledTimes(2);
      releases.forEach(release => release());
      expect((await Promise.all(pending)).map(r => r.status)).toEqual([200, 200]);
      releases.length = 0;
      const after = request(server).post('/api/confidential/channel/open').set('X-Forwarded-For', freshAddress()).send({ nonce: freshNonce() }).then(r => r);
      while (transport.mock.calls.length < 3) await new Promise(resolve => setTimeout(resolve, 5));
      releases.forEach(release => release());
      expect((await after).status).toBe(200);
    } finally { server.close(); }
  });

  test('a failed enclave call releases its slot', async () => {
    const transport = jest.fn(async () => { throw new Error('down'); });
    const { app } = stack(transport as never, undefined, { maxInFlight: 1 });
    for (let i = 0; i < 3; i++) await request(app).post('/api/confidential/channel/open').set('X-Forwarded-For', freshAddress()).send({ nonce: freshNonce() }).expect(503);
    expect(transport).toHaveBeenCalledTimes(3);
  });

  test('a null transport reply is ambiguous, not a pre-transport shed', async () => {
    const transport = jest.fn(async () => null);
    const { app } = stack(transport as never);
    // Ambiguous failures keep their per-client leases until expiry.
    for (let index = 0; index < CHANNEL_ADMISSION.perClient; index++) {
      await request(app).post('/api/confidential/channel/open').send({ nonce: freshNonce() }).expect(503);
    }
    await request(app).post('/api/confidential/channel/open').send({ nonce: freshNonce() }).expect(429);
    expect(transport).toHaveBeenCalledTimes(CHANNEL_ADMISSION.perClient);
    await request(app).post('/api/confidential/channel/call').send({ nonce: freshNonce(), ciphertext: 'opaque' }).expect(503);
  });

  test('the browser treats load shedding as busy, and a bare 503 as unavailable', () => {
    const response = (status: number, retryAfter: string | null) => ({ status, headers: new Headers(retryAfter ? { 'Retry-After': retryAfter } : {}) });
    expect(() => throwIfThrottled(response(503, '2'))).toThrow(ConfidentialRateLimitError);
    expect(() => throwIfThrottled(response(429, null))).toThrow(ConfidentialRateLimitError);
    expect(() => throwIfThrottled(response(503, null))).not.toThrow();
    expect(() => throwIfThrottled(response(200, null))).not.toThrow();
  });
});

describe('anonymous staging byte budget', () => {
  test('bounds total staged bytes per hour and recovers in the next window', async () => {
    let now = 1_000_000;
    const bytes = Buffer.byteLength(ARMORED);
    const { app, stageObject } = stack(undefined, undefined, { hourlyByteBudget: bytes * 2, clock: () => now });
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(201);
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(201);
    const refused = await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED);
    expect(refused.status).toBe(503);
    expect(Number(refused.headers['retry-after'])).toBe(3600);
    expect(stageObject).toHaveBeenCalledTimes(2);
    now += 60 * 60_000;
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(201);
  });

  test('an ambiguous store failure retains its byte reservation', async () => {
    const bytes = Buffer.byteLength(ARMORED);
    const stageObject = jest.fn().mockRejectedValueOnce(new Error('down')).mockResolvedValue(undefined);
    const { app } = stack(undefined, stageObject, { hourlyByteBudget: bytes });
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(503);
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(503);
    expect(stageObject).toHaveBeenCalledTimes(1);
  });

  test('an old failed write cannot refund bytes reserved in a newer hour', async () => {
    let now = 1_000_000, rejectFirst!: (error: Error) => void, started!: () => void;
    const pending = new Promise<void>((_resolve, reject) => { rejectFirst = reject; });
    const admitted = new Promise<void>(resolve => { started = resolve; });
    const stageObject = jest.fn().mockImplementationOnce(() => { started(); return pending; }).mockResolvedValue(undefined);
    const { app } = stack(undefined, stageObject, { hourlyByteBudget: Buffer.byteLength(ARMORED), clock: () => now });
    const first = request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).then(response => response.status);
    await admitted;
    now += 60 * 60_000;
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(201);
    rejectFirst(new Error('ambiguous write result'));
    expect(await first).toBe(503);
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(503);
    expect(stageObject).toHaveBeenCalledTimes(2);
  });

  test('the budget is configurable but never below one maximum object', () => {
    expect(stagingHourlyBytes({} as NodeJS.ProcessEnv)).toBe(STAGING_HOURLY_BYTES_DEFAULT);
    expect(stagingHourlyBytes({ CONFIDENTIAL_STAGING_HOURLY_BYTES: String(MAX_STAGED_CIPHERTEXT * 4) } as NodeJS.ProcessEnv))
      .toBe(MAX_STAGED_CIPHERTEXT * 4);
    for (const bad of ['1', 'lots', '-5', '12582912.5']) {
      expect(() => stagingHourlyBytes({ CONFIDENTIAL_STAGING_HOURLY_BYTES: bad } as NodeJS.ProcessEnv)).toThrow();
    }
  });
});

test('internal secret comparison does not depend on the presented length', () => {
  expect(internalSecretMatches('s3cret-value', 's3cret-value')).toBe(true);
  expect(internalSecretMatches('s3cret-valuX', 's3cret-value')).toBe(false);
  expect(internalSecretMatches('s', 's3cret-value')).toBe(false);
  expect(internalSecretMatches('s3cret-value-and-more', 's3cret-value')).toBe(false);
});

describe('per-client quotas behind CloudFront and the ALB', () => {
  function edgeApp(hops: number) {
    const app = express();
    app.set('trust proxy', hops);
    app.use('/api/confidential', createConfidentialChannelRouter(async () => ({ document: 'doc', publicKey: 'key' }),
      { maxPerMinute: 1, allowedOrigins: ALLOWED }));
    return app;
  }
  const open = (app: express.Express, forwardedFor: string) => request(app).post('/api/confidential/channel/open')
    .set('X-Forwarded-For', forwardedFor).send({ nonce: freshNonce() });

  test('with two trusted hops, reporters behind one CloudFront edge keep separate quotas', async () => {
    const app = edgeApp(apiTrustProxyHops({ API_TRUST_PROXY_HOPS: '2' } as NodeJS.ProcessEnv));
    await open(app, '198.51.100.1, 203.0.113.9').expect(200);
    await open(app, '198.51.100.2, 203.0.113.9').expect(200);
    await open(app, '198.51.100.1, 203.0.113.9').expect(429);
    // A client-supplied X-Forwarded-For entry is ignored; CloudFront appends the real address.
    await open(app, '192.0.2.77, 198.51.100.1, 203.0.113.9').expect(429);
  });

  test('with one trusted hop every reporter behind an edge shares its quota (the regression)', async () => {
    const app = edgeApp(1);
    await open(app, '198.51.100.1, 203.0.113.9').expect(200);
    await open(app, '198.51.100.2, 203.0.113.9').expect(429);
  });

  test('hop configuration is validated and defaults to one load balancer', () => {
    expect(apiTrustProxyHops({} as NodeJS.ProcessEnv)).toBe(1);
    expect(apiTrustProxyHops({ API_TRUST_PROXY_HOPS: '0' } as NodeJS.ProcessEnv)).toBe(0);
    for (const bad of ['-1', '10', 'true', '2 ']) {
      expect(() => apiTrustProxyHops({ API_TRUST_PROXY_HOPS: bad } as NodeJS.ProcessEnv)).toThrow();
    }
  });

  test('the legacy API uses the validated proxy-hop configuration', () => {
    expect(readFileSync(path.join(__dirname, '../../../src/api/server.ts'), 'utf8')).toMatch(/app\.set\('trust proxy', apiTrustProxyHops\(\)\)/);
  });
});

describe('staging upload admission', () => {
  function raw(server: import('node:http').Server, headers: Record<string, string>, body?: string, end = true) {
    const { port } = server.address() as import('node:net').AddressInfo;
    return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; request: import('node:http').ClientRequest }>(
      (resolve, reject) => {
        const request = require('node:http').request({ host: '127.0.0.1', port, method: 'POST', path: '/api/confidential/objects',
          headers: { 'Content-Type': 'application/pgp-encrypted', ...headers } }, (response: import('node:http').IncomingMessage) => {
          response.resume();
          resolve({ status: response.statusCode!, headers: response.headers, request });
        });
        request.on('error', reject);
        if (body) request.write(body);
        if (end) request.end();
      });
  }

  test('an upload without a declared size, or declaring more than the limit, is refused before buffering', async () => {
    const stageObject = jest.fn(async () => undefined);
    const app = express();
    app.use('/api/confidential', createConfidentialObjectRouter({ stageObject }, Date.now, { allowedOrigins: ALLOWED }));
    const server = app.listen(0);
    try {
      expect((await raw(server, { 'Transfer-Encoding': 'chunked' }, ARMORED)).status).toBe(411);
      const oversized = await raw(server, { 'Content-Length': String(MAX_STAGED_CIPHERTEXT + 1) }, 'x', false);
      expect(oversized.status).toBe(413);
      oversized.request.destroy();
      expect(stageObject).not.toHaveBeenCalled();
    } finally { server.close(); }
  });

  test('concurrent uploads are capped and a finished upload frees its slot', async () => {
    const stageObject = jest.fn(async () => undefined);
    const app = express();
    app.use('/api/confidential', createConfidentialObjectRouter({ stageObject }, Date.now, { allowedOrigins: ALLOWED, maxConcurrent: 1 }));
    const server = app.listen(0);
    const { port } = server.address() as import('node:net').AddressInfo;
    try {
      // Hold one upload open by declaring more bytes than are sent.
      const held = require('node:http').request({ host: '127.0.0.1', port, method: 'POST', path: '/api/confidential/objects',
        headers: { 'Content-Type': 'application/pgp-encrypted', 'Content-Length': String(ARMORED.length) } });
      held.on('error', () => undefined);
      held.write(ARMORED.slice(0, 10));
      await new Promise(resolve => setTimeout(resolve, 50));
      const busy = await request(server).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED);
      expect(busy.status).toBe(503);
      expect(busy.headers['retry-after']).toBe('5');
      held.end(ARMORED.slice(10));
      await new Promise(resolve => setTimeout(resolve, 50));
      await request(server).post('/api/confidential/objects').type('application/pgp-encrypted').send(ARMORED).expect(201);
      expect(stageObject).toHaveBeenCalledTimes(2);
    } finally { server.close(); }
  });
});
