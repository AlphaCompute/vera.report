import express from 'express';
import request from 'supertest';
import crypto from 'node:crypto';
import { captureWebhookBody, verifyWebhookSignature, webhookEventKey } from '../../../src/middleware/webhookIntegrity';
const path = '/api/dissemination/inbound/webhook';
const secret = 'test-webhook-secret';
const payload = JSON.stringify({ from: "Agency <sender@example.invalid>", body: " Alice's résumé <case> " });
const sign = (body: string, timestamp: string, route = path) => crypto.createHmac('sha256', secret).update(`${timestamp}.${route}.${body}`).digest('hex');
function app() {
  const server = express();
  server.use(express.json({ verify: captureWebhookBody }));
  server.post(path, (req, res) => {
    if (verifyWebhookSignature(req, res)) res.json({ payload: req.body, key: webhookEventKey(req) });
  });
  return server;
}
beforeEach(() => { process.env.DISSEMINATION_WEBHOOK_SECRET = secret; });
it('accepts exact signed bytes with punctuation, whitespace and Unicode', async () => {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const result = await request(app()).post(path).set('content-type', 'application/json')
    .set('x-vera-timestamp', timestamp).set('x-vera-signature', sign(payload, timestamp)).send(payload);
  expect(result.status).toBe(200); expect(result.body.payload).toEqual(JSON.parse(payload));
});
it.each(['expired', 'future', 'tampered', 'wrong-route', 'missing-timestamp'])('rejects %s', async scenario => {
  const timestamp = Math.floor(Date.now() / 1000 + (scenario === 'expired' ? -600 : scenario === 'future' ? 600 : 0)).toString();
  let req = request(app()).post(path).set('content-type', 'application/json');
  if (scenario !== 'missing-timestamp') req = req.set('x-vera-timestamp', timestamp);
  const result = await req.set('x-vera-signature', sign(payload, timestamp, scenario === 'wrong-route' ? '/api/dissemination/receipts/webhook' : path))
    .send(scenario === 'tampered' ? payload.replace('Alice', 'Mallory') : payload);
  expect(result.status).toBe(401);
});
it('uses a stable receipt idempotency key when a retry has a new timestamp', async () => {
  const keys = [];
  for (const offset of [0, -5]) {
    const timestamp = Math.floor(Date.now() / 1000 + offset).toString();
    const result = await request(app()).post(path).set('content-type', 'application/json')
      .set('x-vera-timestamp', timestamp).set('x-vera-signature', sign(payload, timestamp)).send(payload);
    keys.push(result.body.key);
  }
  expect(keys[0]).toHaveLength(64); expect(keys[0]).toBe(keys[1]);
});

it('accepts the prior SES relay only with a fresh signed body timestamp and message ID', async () => {
  for (const age of [0, 600000]) {
    const body = JSON.stringify({ ...JSON.parse(payload), messageId: 'synthetic-ses-id', receivedAt: new Date(Date.now() - age).toISOString() });
    const signature = crypto.createHmac('sha256', secret).update(body).digest('hex');
    const result = await request(app()).post(path).set('content-type', 'application/json').set('x-vera-signature', signature).send(body);
    expect(result.status).toBe(age === 0 ? 200 : 401);
  }
});
