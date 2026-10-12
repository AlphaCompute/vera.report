import express from 'express';
import request from 'supertest';

jest.mock('express-rate-limit', () => {
    const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
    return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { sendAlert: jest.fn() } }));
jest.mock('../../../src/services/dissemination/securePacketSender', () => ({ sendSecurePacket: jest.fn() }));
import router from '../../../src/api/dissemination';
import { sendSecurePacket } from '../../../src/services/dissemination/securePacketSender';

const app = express().use(express.json()).use('/api/dissemination', router);
const secret = 'synthetic-email-validation-secret';
const previousSecret = process.env.INTERNAL_API_SECRET;
const endpoint = '/api/dissemination/VRA-0000000000000001/secure-packet-email';

beforeEach(() => {
  process.env.INTERNAL_API_SECRET = secret;
  jest.mocked(sendSecurePacket).mockReset().mockResolvedValue({ sent: true });
});
afterAll(() => {
  if (previousSecret === undefined) delete process.env.INTERNAL_API_SECRET;
  else process.env.INTERNAL_API_SECRET = previousSecret;
});

it.each([
  undefined, null, 123, [], {}, '', ' ', 'a,b@c.org', 'person@b\u00fccher.org',
  'r\u00e9cipient@example.org', `${'a'.repeat(65)}@example.org`,
  `a@${'b'.repeat(64)}.org`, 'a..b@example.org', 'person@-example.org',
  'person@example.org\r\n', 'person@example.org\u0000',
  'one@example.org,two@example.org', 'Name <person@example.org>',
])('returns 400 for recipient %j before invoking the sender', async recipientEmail => {
  const response = await request(app).post(endpoint).set('x-internal-secret', secret)
    .send({ actor: 'synthetic-admin', recipientEmail });
  expect(response.status).toBe(400);
  expect(response.body).toEqual({ success: false, error: 'recipientEmail (valid) and actor are required' });
  expect(sendSecurePacket).not.toHaveBeenCalled();
});

it('passes a normalized plus-address and Punycode domain to the sender', async () => {
  const response = await request(app).post(endpoint).set('x-internal-secret', secret)
    .send({ actor: 'synthetic-admin', recipientEmail: '  Reviewer+Case@xn--bcher-kva.org  ' });
  expect(response.status).toBe(200);
  expect(sendSecurePacket).toHaveBeenCalledWith({
    trackingId: 'VRA-0000000000000001', actor: 'synthetic-admin', recipientEmail: 'Reviewer+Case@xn--bcher-kva.org',
  });
});

it('keeps invalid dryrun configuration a server error', async () => {
  jest.mocked(sendSecurePacket).mockResolvedValue({ sent: false, error: 'dryrun_inbox_invalid' });
  const response = await request(app).post(endpoint).set('x-internal-secret', secret)
    .send({ actor: 'synthetic-admin', recipientEmail: 'reviewer@example.org' });
  expect(response.status).toBe(500);
  expect(response.body).toEqual({ success: false, error: 'dryrun_inbox_invalid' });
});

it('still requires authentication before sending', async () => {
  const response = await request(app).post(endpoint)
    .send({ actor: 'synthetic-admin', recipientEmail: 'reviewer@example.org' });
  expect(response.status).toBe(401);
  expect(sendSecurePacket).not.toHaveBeenCalled();
});
