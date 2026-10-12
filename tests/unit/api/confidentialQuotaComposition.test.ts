import express from 'express';
import request from 'supertest';
import { apiRateLimiter } from '../../../src/middleware/security';
import { createConfidentialChannelRouter } from '../../../src/api/confidentialChannel';
import { createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';

// Real rate-limit middleware and router composition. Only enclave quote bytes
// and ciphertext persistence are synthetic; this is not attestation acceptance.
test('global quota cannot truncate confidential reads; dedicated quotas remain enforced', async () => {
  const original = process.env.CONFIDENTIAL_CASES_ENABLED;
  process.env.CONFIDENTIAL_CASES_ENABLED = 'true';
  const app = express();
  app.use(apiRateLimiter);
  app.use(express.json());
  app.get('/ordinary', (_req, res) => { res.sendStatus(204); });
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => (raw as { op: string }).op === 'call'
    ? { ciphertext: 'synthetic' } : { document: 'synthetic', publicKey: 'synthetic' }));
  const stageObject = jest.fn(async () => undefined);
  app.use('/api/confidential', createConfidentialObjectRouter({ stageObject, stageChunk: jest.fn(async () => undefined) }));
  try {
    for (let i = 0; i < 100; i++) await request(app).get('/ordinary').expect(204);
    await request(app).get('/ordinary').expect(429);
    for (let i = 0; i < 101; i++) {
      const result = await request(app).post('/api/confidential/channel/open').send({ nonce: i.toString(16).padStart(64, '0') }).expect(200);
      expect(result.headers['ratelimit-limit']).toBe('600');
      await request(app).post('/api/confidential/channel/call').send({ nonce: i.toString(16).padStart(64, '0'), ciphertext: 'opaque' }).expect(200);
    }
    await request(app).post('/api/confidential/unknown').send({}).expect(429);
    await request(app).get('/api/confidential/channel/open').expect(429);
    for (let i = 0; i < 60; i++) {
      await request(app).post('/api/confidential/objects').type('application/pgp-encrypted')
        .send('-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----').expect(201);
    }
    await request(app).post('/api/confidential/objects').type('application/pgp-encrypted')
      .send('-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----').expect(429);
    expect(stageObject).toHaveBeenCalledTimes(60);
    process.env.CONFIDENTIAL_CASES_ENABLED = 'false';
    await request(app).post('/api/confidential/channel/open').send({ nonce: 'a'.repeat(64) }).expect(429);
  } finally {
    if (original === undefined) delete process.env.CONFIDENTIAL_CASES_ENABLED;
    else process.env.CONFIDENTIAL_CASES_ENABLED = original;
  }
}, 120_000);
