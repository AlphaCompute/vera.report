import { notifySubmission, notifyOperationalEvent, submissionNotificationsEnabled, submissionNotificationConfigurationError } from '../../../src/services/submissionWebhook';
import { slackConfigurationError } from '../../../src/services/slackNotification';

const webhook = 'https://hooks.slack.com/services/T_SYNTHETIC/B_SYNTHETIC/synthetic-test-only';
const dashboard = 'https://staging.example.invalid/admin';
const acceptedAt = new Date('2026-09-18T12:34:56Z');
const original = process.env;
let send: jest.SpyInstance;

beforeEach(() => {
  process.env = { ...original, SLACK_WEBHOOK_URL: webhook, SLACK_ADMIN_URL: dashboard, DEPLOY_ENV: 'staging' };
  delete process.env.WEBHOOK_URL;
  delete process.env.WEBHOOK_SECRET;
  send = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
  jest.clearAllMocks();
});
afterEach(() => { process.env = original; jest.restoreAllMocks(); });

it.each(['web', 'telegram'] as const)('sends a private %s notification directly to Slack without n8n credentials', async source => {
  expect(submissionNotificationsEnabled()).toBe(true);
  expect(submissionNotificationConfigurationError()).toBeUndefined();
  expect(await notifySubmission('VRA-private-access-token', acceptedAt, source)).toBe('delivered');
  expect(send).toHaveBeenCalledTimes(1);
  const [url, options] = send.mock.calls[0];
  expect(url).toBe(webhook);
  expect(options).toMatchObject({ method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' } });
  expect(options.signal).toBeInstanceOf(AbortSignal);
  const payload = JSON.parse(options.body);
  expect(payload).toMatchObject({ text: '[VERA staging] A new report is awaiting review.', unfurl_links: false, unfurl_media: false });
  expect(payload.blocks[1].fields[0].text).toContain(acceptedAt.toISOString());
  expect(payload.blocks[1].fields[1].text).toBe(`Source: ${source === 'web' ? 'Web' : 'Telegram'}`);
  expect(payload.blocks).toHaveLength(2);
  expect(payload.blocks.every((block: { type: string }) => block.type === 'section')).toBe(true);
  expect(options.body).not.toContain(dashboard);
  expect(options.body).not.toMatch(/VRA-|VRC-|eventId|trackingId|narrative|reporter|evidenceHash/);
  expect(options.headers).not.toHaveProperty('X-VERA-Webhook-Secret');
});

it.each([undefined, '', '  '])('is disabled without either transport (%p)', async value => {
  if (value === undefined) delete process.env.SLACK_WEBHOOK_URL; else process.env.SLACK_WEBHOOK_URL = value;
  expect(submissionNotificationsEnabled()).toBe(false);
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('disabled');
  expect(send).not.toHaveBeenCalled();
});

it.each([
  'https://attacker.invalid/services/T/B/token', 'https://hooks.slack.com.attacker.invalid/services/T/B/token',
  'http://hooks.slack.com/services/T/B/token', 'https://hooks.slack.com:444/services/T/B/token',
  'https://user:password@hooks.slack.com/services/T/B/token', 'https://hooks.slack.com/services/T/B/token?secret=extra',
  'https://hooks.slack.com/services/T/B/token#fragment', 'https://hooks.slack.com/other',
  'http://127.0.0.1/hook', 'file:///etc/passwd', 'not-a-url',
])('rejects unsafe Slack webhook configuration (%s)', async url => {
  process.env.SLACK_WEBHOOK_URL = url;
  expect(slackConfigurationError()).toBeDefined();
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  expect(send).not.toHaveBeenCalled();
});

it.each(['', 'http://staging.example.invalid/admin', 'https://user:password@example.invalid/admin',
  'https://example.invalid/status?trackingId=private', 'https://example.invalid/admin#private'])('rejects unsafe dashboard links (%s)', async url => {
  process.env.SLACK_ADMIN_URL = url;
  expect(slackConfigurationError()).toBeDefined();
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  expect(send).not.toHaveBeenCalled();
});

it.each([200, 403, 500])('never sends to both Slack and legacy webhook, including HTTP %s', async status => {
  process.env.WEBHOOK_URL = 'https://legacy.example.invalid/webhook';
  process.env.WEBHOOK_SECRET = 'legacy-secret';
  send.mockResolvedValue(new Response(status === 200 ? 'ok' : 'sensitive-error', { status }));
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe(status === 200 ? 'delivered' : 'failed');
  expect(send).toHaveBeenCalledTimes(1);
  expect(send.mock.calls[0][0]).toBe(webhook);
  expect(JSON.stringify(send.mock.calls[0][1])).not.toContain('legacy-secret');
});

it('fails closed on invalid Slack settings instead of falling back to the old destination', async () => {
  process.env.WEBHOOK_URL = 'https://legacy.example.invalid/webhook';
  process.env.WEBHOOK_SECRET = 'legacy-secret';
  process.env.SLACK_WEBHOOK_URL = 'invalid';
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  expect(send).not.toHaveBeenCalled();
});

it.each([[429, '120', 120_000], [429, null, 60_000], [429, 'invalid', 60_000],
  [429, '-1', 60_000], [429, '999999999999999999', 60_000]])('handles rate limiting without exposing the response (%s, %s)', async (status, header, delay) => {
  send.mockResolvedValue(new Response('sensitive-error', { status: status as number,
    headers: header === null ? {} : { 'Retry-After': String(header) } }));
  expect(await notifySubmission('private', acceptedAt, 'web')).toEqual({ status: 'rate_limited', retryAfterMs: delay });
  expect(send).toHaveBeenCalledTimes(1);
});

it.each([201, 302, 400, 403, 404, 500, 503])('does not acknowledge HTTP %s as delivered', async status => {
  send.mockResolvedValue(new Response('sensitive-error', { status, headers: { Location: 'https://attacker.invalid/' } }));
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  expect(send).toHaveBeenCalledTimes(1);
});

it('requires Slack acknowledgement and sanitizes network failures', async () => {
  send.mockResolvedValueOnce(new Response('sensitive-error'));
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  send.mockRejectedValueOnce(new Error(`${webhook} sensitive-error`));
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('failed');
  const logs = JSON.stringify((console.error as jest.Mock).mock.calls);
  expect(logs).not.toContain(webhook);
  expect(logs).not.toContain('sensitive-error');
});

it('rejects malformed metadata and never reflects unknown environment labels', async () => {
  expect(await notifySubmission('private', new Date(NaN), 'web')).toBe('failed');
  expect(await notifySubmission('private', acceptedAt, '<!channel>' as 'web')).toBe('failed');
  expect(send).not.toHaveBeenCalled();
  process.env.DEPLOY_ENV = '<!channel>';
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('delivered');
  expect(send.mock.calls[0][1].body).not.toContain('<!channel>');
});

it.each(['prod', 'production'])('labels DEPLOY_ENV=%s as production', async deployEnv => {
  process.env.DEPLOY_ENV = deployEnv;
  expect(await notifySubmission('private', acceptedAt, 'web')).toBe('delivered');
  const payload = JSON.parse(send.mock.calls[0][1].body);
  expect(payload.text).toBe('[VERA production] A new report is awaiting review.');
  expect(payload.blocks[0].text.text).toBe('[VERA production] A new report is awaiting review.');
});

it('does not route monitoring events into the new-report Slack channel', async () => {
  expect(await notifyOperationalEvent('operations.error_threshold')).toBe('disabled');
  expect(send).not.toHaveBeenCalled();
});
