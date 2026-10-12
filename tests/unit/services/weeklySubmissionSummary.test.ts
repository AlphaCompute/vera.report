import { sendWeeklySubmissionSummary, weeklySubmissionPeriod, weeklySubmissionSummaryConfigurationError,
  WeeklySubmissionSummaryWorker } from '../../../src/services/weeklySubmissionSummary';

const webhook = 'https://hooks.slack.com/services/TEST/TEST/SYNTHETIC';
const env = { DEPLOY_ENV: 'staging', WEEKLY_SUBMISSION_SUMMARY_ENABLED: 'true', SLACK_WEEKLY_SUMMARY_WEBHOOK_URL: webhook };
const period = { start: Date.parse('2026-09-28T00:00:00Z'), end: Date.parse('2026-10-05T00:00:00Z') };
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; jest.restoreAllMocks(); });

test.each(['2026-10-05T00:00:00Z', '2026-10-05T08:59:59.999Z'])("doesn't send before Monday 09:00 UTC (%s)", time => {
  expect(weeklySubmissionPeriod(Date.parse(time))).toBeNull();
});
test.each(['2026-10-05T09:00:00Z', '2026-10-06T19:30:00Z', '2026-10-11T23:59:59Z'])(
  'uses the complete previous calendar week, including a late startup (%s)', time => {
    expect(weeklySubmissionPeriod(Date.parse(time))).toEqual(period);
  });
test.each([
  ['2026-01-05T09:00:00Z', '2025-12-29T00:00:00Z', '2026-01-05T00:00:00Z'],
  ['2026-03-30T09:00:00Z', '2026-03-23T00:00:00Z', '2026-03-30T00:00:00Z'],
  ['2026-10-26T09:00:00Z', '2026-10-19T00:00:00Z', '2026-10-26T00:00:00Z'],
])('UTC boundaries survive year/DST changes (%s)', (time, start, end) => {
  expect(weeklySubmissionPeriod(Date.parse(time))).toEqual({ start: Date.parse(start), end: Date.parse(end) });
});

test.each([{}, { ...env, WEEKLY_SUBMISSION_SUMMARY_ENABLED: 'false' }, { ...env, DEPLOY_ENV: 'prod' },
  { ...env, DEPLOY_ENV: 'production' }, { ...env, SLACK_WEEKLY_SUMMARY_WEBHOOK_URL: '' }])(
  'disabled, unconfigured and production processes never count or send (%j)', async config => {
    const send = jest.fn();
    const worker = new WeeklySubmissionSummaryWorker(undefined as any, config, send, () => period.end + 9 * 3_600_000);
    await worker.tick();
    expect(send).not.toHaveBeenCalled();
  });
test.each(['http://hooks.slack.com/services/T/B/X', 'https://hooks.slack.com.evil.test/services/T/B/X',
  'https://user@hooks.slack.com/services/T/B/X', 'https://hooks.slack.com/services/T/B/X?secret=x',
  'https://hooks.slack.com/services/T/B/X#fragment', 'https://hooks.slack.com/services/T/B/X/extra'])('rejects invalid webhook %s', value => {
  expect(weeklySubmissionSummaryConfigurationError({ ...env, SLACK_WEEKLY_SUMMARY_WEBHOOK_URL: value })).toBeDefined();
});

test('sends only a fixed staging label, week and count, including zero', async () => {
  globalThis.fetch = jest.fn(async () => new Response('ok'));
  expect(await sendWeeklySubmissionSummary(webhook, { ...period, privateData: 'PRIVATE_CANARY' } as any, 0)).toBe('delivered');
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  const [url, request] = (globalThis.fetch as jest.Mock).mock.calls[0];
  expect(url).toBe(webhook);
  expect(request).toMatchObject({ method: 'POST', redirect: 'error' });
  const payload = JSON.parse(request.body);
  expect(payload.text).toBe('[VERA staging] Weekly submission summary\n2026-09-28 – 2026-10-04 (UTC)\nTotal submissions: 0');
  expect(payload).toEqual({ text: payload.text, blocks: [{ type: 'section', text: { type: 'plain_text', text: payload.text } }],
    unfurl_links: false, unfurl_media: false });
  expect(request.body).not.toMatch(/PRIVATE_CANARY|\/admin|caseId|trackingId/);
});
test.each([new Response('ok', { status: 500 }), new Response('unexpected', { status: 200 }),
  new Response('', { status: 302, headers: { Location: 'https://untrusted.invalid' } })])('requires Slack acknowledgement (%j)', async response => {
  globalThis.fetch = jest.fn(async () => response);
  expect(await sendWeeklySubmissionSummary(webhook, period, 12)).toBe('failed');
});
test.each([['3600', 3_600_000], ['invalid', 60_000], ['999999999999', 60_000]])('honors bounded Retry-After (%s)', async (header, delay) => {
  globalThis.fetch = jest.fn(async () => new Response('rate limited', { status: 429, headers: { 'Retry-After': header } }));
  expect(await sendWeeklySubmissionSummary(webhook, period, 12)).toEqual({ retryAfterMs: delay });
});
test('fetch exceptions and secret-bearing responses are never logged', async () => {
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  const error = jest.spyOn(console, 'error').mockImplementation(() => {});
  globalThis.fetch = jest.fn(async () => { throw new Error(webhook); });
  expect(await sendWeeklySubmissionSummary(webhook, period, 12)).toBe('failed');
  expect(warn).not.toHaveBeenCalled(); expect(error).not.toHaveBeenCalled();
});
