import express from 'express';
import request from 'supertest';
import { requireHeaderSecret } from '../../../src/middleware/internalSecret';

const SECRET = 'synthetic-internal-secret-for-edge-tests-000000';

function app(env: NodeJS.ProcessEnv = { INTERNAL_API_SECRET: SECRET }) {
  const server = express();
  server.get('/admin', requireHeaderSecret('INTERNAL_API_SECRET', env), (_req, res) => res.json({ ok: true }));
  return server;
}

it('admits the internal proxy with the matching secret', async () => {
  await request(app()).get('/admin').set('x-internal-secret', SECRET).expect(200, { ok: true });
});

it('refuses a request from the public edge even with the matching secret', async () => {
  const response = await request(app()).get('/admin')
    .set('x-internal-secret', SECRET).set('x-origin-verify', 'cloudfront-value').expect(404);
  expect(response.body).toEqual({ success: false, error: 'Not found' });
});

it('refuses a public-edge request with an empty origin header', async () => {
  await request(app()).get('/admin').set('x-internal-secret', SECRET).set('x-origin-verify', '').expect(404);
});

it('rejects a missing or wrong secret and fails closed when unset', async () => {
  await request(app()).get('/admin').expect(401);
  await request(app()).get('/admin').set('x-internal-secret', 'wrong').expect(401);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  await request(app({})).get('/admin').set('x-internal-secret', SECRET).expect(500);
});
