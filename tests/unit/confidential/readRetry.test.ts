import { ConfidentialRateLimitError, retryConfidentialRead } from '../../../lib/confidential/readRetry';

describe('bounded confidential read retry', () => {
  it('restarts the whole read after throttling instead of replaying its session', async () => {
    const attempts: number[] = [], waits: number[] = [];
    const result = await retryConfidentialRead(async () => {
      attempts.push(attempts.length);
      if (attempts.length < 3) throw new ConfidentialRateLimitError('60');
      return 'fresh read';
    }, async ms => { waits.push(ms); });
    expect(result).toBe('fresh read');
    expect(attempts).toEqual([0, 1, 2]);
    expect(waits).toEqual([60250, 60250]);
  });
  it('bounds hostile retry headers and the attempt budget', async () => {
    const waits: number[] = [];
    const attempt = jest.fn(async () => { throw new ConfidentialRateLimitError('999'); });
    await expect(retryConfidentialRead(attempt, async ms => { waits.push(ms); })).rejects.toBeInstanceOf(ConfidentialRateLimitError);
    expect(attempt).toHaveBeenCalledTimes(4);
    expect(waits).toEqual([65000, 65000, 65000]);
    expect(new ConfidentialRateLimitError('bad').delayMs).toBe(60250);
  });
  it('does not retry authorization, attestation or network failures', async () => {
    const error = new Error('denied'), attempt = jest.fn(async () => { throw error; });
    const wait = jest.fn();
    await expect(retryConfidentialRead(attempt, wait)).rejects.toBe(error);
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(wait).not.toHaveBeenCalled();
  });
});

test('shares a deadline across ranges and refuses a wait beyond it', async () => {
  let now = 1000;
  const budget = { expiresAt: 70_000, clock: () => now }, wait = jest.fn(async (ms: number) => { now += ms; });
  let calls = 0;
  await retryConfidentialRead(async () => { if (++calls === 1) throw new ConfidentialRateLimitError('60'); return true; }, wait, budget);
  await expect(retryConfidentialRead(async () => { throw new ConfidentialRateLimitError('60'); }, wait, budget)).rejects.toThrow('budget');
  expect(wait).toHaveBeenCalledTimes(1);
  now = budget.expiresAt;
  const expired = jest.fn();
  await expect(retryConfidentialRead(expired, wait, budget)).rejects.toThrow('budget');
  expect(expired).not.toHaveBeenCalled();
});
