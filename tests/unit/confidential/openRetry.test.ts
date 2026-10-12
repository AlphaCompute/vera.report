import { OPEN_RETRY_DELAYS_MS, openWithRetry } from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';

describe('throttled session opens', () => {
  test('retry briefly after a relay throttle, never longer than the bounded schedule', async () => {
    const waits: number[] = [];
    let calls = 0;
    const result = await openWithRetry(async () => {
      calls++;
      if (calls < 3) throw new ConfidentialRateLimitError('100');
      return 'opened';
    }, async ms => { waits.push(ms); });
    expect(result).toBe('opened');
    expect(calls).toBe(3);
    // The relay's 100 s Retry-After is an upper bound, not the wait.
    waits.forEach((ms, index) => expect(ms).toBeLessThanOrEqual(OPEN_RETRY_DELAYS_MS[index] * 1.25));
  });

  test('gives up after the bounded attempts and surfaces the throttle', async () => {
    let calls = 0;
    await expect(openWithRetry(async () => { calls++; throw new ConfidentialRateLimitError('2'); }, async () => {}))
      .rejects.toBeInstanceOf(ConfidentialRateLimitError);
    expect(calls).toBe(OPEN_RETRY_DELAYS_MS.length + 1);
  });

  test('never retries other failures', async () => {
    let calls = 0;
    await expect(openWithRetry(async () => { calls++; throw new Error('verification'); }, async () => {})).rejects.toThrow('verification');
    expect(calls).toBe(1);
  });
});
