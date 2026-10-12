import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { notifySubmission, webhookConfigurationError } from '../../../src/services/submissionWebhook';

const originalEnv = { ...process.env };
let server: Server;
let received: { headers: Record<string, unknown>; body: string }[];
let status = 200;
let redirect = '';
let hang = false;
const submittedAt = new Date('2026-09-10T00:00:00Z');

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      received.push({ headers: req.headers, body });
      if (hang) return;
      res.writeHead(status, redirect ? { Location: redirect } : {});
      res.end('receiver response');
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
});
afterAll(async () => {
  process.env = originalEnv;
  await new Promise<void>(resolve => server.close(() => resolve()));
});
beforeEach(() => {
  received = []; status = 200; redirect = ''; hang = false;
  delete process.env.SLACK_WEBHOOK_URL;
  process.env.WEBHOOK_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhook/vera`;
  process.env.WEBHOOK_SECRET = 'unit-test-shared-secret';
});
afterEach(() => jest.restoreAllMocks());

it('does nothing without a URL', async () => {
  delete process.env.WEBHOOK_URL;
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('disabled');
  expect(received).toHaveLength(0);
});
it('refuses to send without a secret', async () => {
  process.env.WEBHOOK_SECRET = ' ';
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('failed');
  expect(received).toHaveLength(0);
});
it.each(['web', 'telegram'] as const)('delivers authenticated, allowlisted metadata for %s', async source => {
  expect(await notifySubmission('private-tracking-id', submittedAt, source)).toBe('delivered');
  expect(received).toHaveLength(1);
  const event = JSON.parse(received[0].body);
  expect(event).toEqual({ schemaVersion: 1, event: 'submission.accepted', eventId: expect.stringMatching(/^[a-f0-9]{64}$/), submittedAt: submittedAt.toISOString(), source });
  expect(received[0].headers['x-vera-webhook-secret']).toBe('unit-test-shared-secret');
  expect(received[0].headers['x-vera-event-id']).toBe(event.eventId);
  expect(received[0].body).not.toContain('private-tracking-id');
  expect(received[0].body).not.toContain('unit-test-shared-secret');
});
it('keeps event IDs stable for manual redelivery', async () => {
  await notifySubmission('private-tracking-id', submittedAt, 'web');
  await notifySubmission('private-tracking-id', submittedAt, 'web');
  expect(JSON.parse(received[0].body).eventId).toBe(JSON.parse(received[1].body).eventId);
});
it.each([401, 429, 500, 502])('reports HTTP %s as failure without throwing or retrying', async code => {
  status = code;
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('failed');
  expect(received).toHaveLength(1);
});
it('does not follow redirects carrying the shared secret', async () => {
  status = 302; redirect = process.env.WEBHOOK_URL! + '/redirected';
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('failed');
  expect(received).toHaveLength(1);
});
it('bounds requests and suppresses network exception details', async () => {
  const spy = jest.spyOn(global, 'fetch').mockImplementation(async (_url, options) => {
    expect(options?.signal).toBeDefined();
    throw new Error('sensitive-url-and-secret');
  });
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('failed');
  expect(spy).toHaveBeenCalledTimes(1);
  expect(JSON.stringify((console.error as jest.Mock).mock.calls)).not.toContain('sensitive-url-and-secret');
});
it.each(['http://example.com/hook', 'file:///etc/passwd', 'https://user:password@example.com/hook', 'https://example.com/#secret', 'not-a-url'])('rejects unsafe configuration %s', url => {
  process.env.WEBHOOK_URL = url;
  expect(webhookConfigurationError()).toBeDefined();
});
it('rejects loopback HTTP in production', () => {
  process.env.NODE_ENV = 'production';
  expect(webhookConfigurationError()).toBeDefined();
  process.env.NODE_ENV = 'test';
});

it('aborts an unresponsive receiver after five seconds', async () => {
  hang = true;
  const started = Date.now();
  expect(await notifySubmission('private-tracking-id', submittedAt, 'web')).toBe('failed');
  expect(Date.now() - started).toBeGreaterThanOrEqual(4900);
  expect(Date.now() - started).toBeLessThan(7000);
  expect(received).toHaveLength(1);
});
