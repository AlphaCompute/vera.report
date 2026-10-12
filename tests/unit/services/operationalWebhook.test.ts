import { notifyOperationalEvent } from '../../../src/services/submissionWebhook';
const originalFetch = global.fetch;
const originalUrl = process.env.WEBHOOK_URL;
const originalSecret = process.env.WEBHOOK_SECRET;
afterEach(() => { global.fetch = originalFetch; jest.restoreAllMocks(); });
afterAll(() => {
  if (originalUrl === undefined) delete process.env.WEBHOOK_URL; else process.env.WEBHOOK_URL = originalUrl;
  if (originalSecret === undefined) delete process.env.WEBHOOK_SECRET; else process.env.WEBHOOK_SECRET = originalSecret;
});
test('disabled without configuration and does not consume the alert cooldown', async () => {
  delete process.env.WEBHOOK_URL;
  global.fetch = jest.fn();
  expect(await notifyOperationalEvent('operations.error_threshold')).toBe('disabled');
  expect(global.fetch).not.toHaveBeenCalled();
});
test('allowlisted operational events are bounded, private and rate limited', async () => {
  process.env.WEBHOOK_URL = 'https://example.invalid/webhook';
  process.env.WEBHOOK_SECRET = 'synthetic-secret';
  global.fetch = jest.fn().mockResolvedValue({ ok: true, body: { cancel: jest.fn() } });
  jest.spyOn(Date, 'now').mockReturnValue(1000000);
  expect(await notifyOperationalEvent('operations.error_threshold')).toBe('delivered');
  expect(await notifyOperationalEvent('operations.error_threshold')).toBe('disabled');
  expect(global.fetch).toHaveBeenCalledTimes(1);
  const options = (global.fetch as jest.Mock).mock.calls[0][1];
  expect(JSON.parse(options.body)).toEqual({ schemaVersion: 1, event: 'operations.error_threshold', occurredAt: new Date(1000000).toISOString() });
  expect(options.redirect).toBe('error');
  expect(options.signal).toBeInstanceOf(AbortSignal);
});
test('delivery failures never throw or export receiver error details', async () => {
  process.env.WEBHOOK_URL = 'https://example.invalid/webhook';
  process.env.WEBHOOK_SECRET = 'synthetic-secret';
  global.fetch = jest.fn().mockRejectedValue(new Error('sensitive receiver response'));
  expect(await notifyOperationalEvent('operations.error_threshold')).toBe('failed');
});
