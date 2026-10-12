import { throwIfRateLimited, RateLimitError } from '../../../lib/rateLimitResponse';
import { forwardRetryAfter } from '../../../lib/proxyRetryAfter';

afterEach(() => jest.restoreAllMocks());
it.each([
  ['42', { retryAfter: 900 }, 42],
  [null, { retryAfter: 900 }, 900],
  [null, {}, 60],
  ['invalid', { retryAfter: -1 }, 60],
  ['0', {}, 1],
  ['Tue, 15 Sep 2026 22:00:45 GMT', {}, 45],
])('uses Retry-After %s and safe fallback metadata', async (header, body, seconds) => {
  const now = Date.parse('2026-09-15T22:00:00Z');
  jest.spyOn(Date, 'now').mockReturnValue(now);
  const response = Response.json(body, { status: 429, headers: header ? { 'Retry-After': header } : {} });
  await expect(throwIfRateLimited(response)).rejects.toMatchObject({ retryAt: now + seconds * 1000 });
});
it('never exposes upstream details and handles non-JSON 429s', async () => {
  await expect(throwIfRateLimited(new Response('PRIVATE DATA', { status: 429 }))).rejects.toBeInstanceOf(RateLimitError);
  await expect(throwIfRateLimited(Response.json({ error: 'PRIVATE DATA' }, { status: 429 }))).rejects.toThrow('Automatic refresh');
  await expect(throwIfRateLimited(new Response('', { status: 200 }))).resolves.toBeUndefined();
});
it('preserves Retry-After only on throttled proxy responses', () => {
  const res = { setHeader: jest.fn() };
  forwardRetryAfter(new Response('', { status: 429, headers: { 'Retry-After': '32' } }), res as any);
  expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '32');
  res.setHeader.mockClear();
  forwardRetryAfter(new Response('', { status: 200, headers: { 'Retry-After': '32' } }), res as any);
  expect(res.setHeader).not.toHaveBeenCalled();
});
