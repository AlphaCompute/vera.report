import { retryWithBackoff, getRetryDefaults } from '@utils/retry';

describe('retryWithBackoff', () => {
  beforeEach(() => {
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns on first attempt if fn succeeds', async () => {
    const fn = jest.fn().mockResolvedValue('ok');

    const result = await retryWithBackoff(fn, { maxRetries: 3, baseDelayMs: 1 });

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries and succeeds on Nth attempt', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new Error('fail 1'))
      .mockRejectedValueOnce(new Error('fail 2'))
      .mockResolvedValue('ok');

    const result = await retryWithBackoff(fn, { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 100 });

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('throws the last error after exhausting retries', async () => {
    const fn = jest.fn().mockRejectedValue(new Error('always fails'));
    const onRetry = jest.fn();

    await expect(
      retryWithBackoff(fn, { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 100, onRetry }),
    ).rejects.toThrow('always fails');

    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
    expect(onRetry).toHaveBeenCalledTimes(2);
  });

  it('respects shouldRetry predicate and stops early', async () => {
    const fn = jest.fn().mockRejectedValue(new Error('not retryable'));
    const shouldRetry = jest.fn().mockReturnValue(false);

    await expect(
      retryWithBackoff(fn, { maxRetries: 3, baseDelayMs: 1, shouldRetry }),
    ).rejects.toThrow('not retryable');

    expect(fn).toHaveBeenCalledTimes(1);
    expect(shouldRetry).toHaveBeenCalledWith(expect.any(Error), 0);
  });

  it('calls onRetry with correct arguments', async () => {
    const error = new Error('transient');
    const fn = jest.fn()
      .mockRejectedValueOnce(error)
      .mockResolvedValue('ok');
    const onRetry = jest.fn();

    // Math.random mocked to 0.5, baseDelay=1000, attempt=0 → cappedDelay=1000, jittered=500
    await retryWithBackoff(fn, {
      maxRetries: 3,
      baseDelayMs: 1000,
      maxDelayMs: 30000,
      onRetry,
    });

    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledWith(error, 0, 500);
  });

  it('caps delay at maxDelayMs', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new Error('fail'))
      .mockResolvedValue('ok');
    const onRetry = jest.fn();

    // baseDelayMs=10000, attempt=0 → rawDelay=10000, maxDelayMs=500 → capped=500, jittered=250
    await retryWithBackoff(fn, {
      maxRetries: 3,
      baseDelayMs: 10000,
      maxDelayMs: 500,
      onRetry,
    });

    expect(onRetry).toHaveBeenCalledWith(expect.any(Error), 0, 250);
  });

  it('with maxRetries 0, calls fn once and throws on failure', async () => {
    const fn = jest.fn().mockRejectedValue(new Error('fail'));

    await expect(
      retryWithBackoff(fn, { maxRetries: 0, baseDelayMs: 1 }),
    ).rejects.toThrow('fail');

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('applies exponential backoff with jitter', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new Error('fail 1'))
      .mockRejectedValueOnce(new Error('fail 2'))
      .mockRejectedValueOnce(new Error('fail 3'))
      .mockResolvedValue('ok');
    const onRetry = jest.fn();

    // Math.random = 0.5
    // attempt 0: rawDelay=100*2^0=100, capped=min(100,30000)=100, jittered=50
    // attempt 1: rawDelay=100*2^1=200, capped=min(200,30000)=200, jittered=100
    // attempt 2: rawDelay=100*2^2=400, capped=min(400,30000)=400, jittered=200
    await retryWithBackoff(fn, {
      maxRetries: 3,
      baseDelayMs: 100,
      maxDelayMs: 30000,
      onRetry,
    });

    expect(onRetry).toHaveBeenCalledTimes(3);
    expect(onRetry).toHaveBeenNthCalledWith(1, expect.any(Error), 0, 50);
    expect(onRetry).toHaveBeenNthCalledWith(2, expect.any(Error), 1, 100);
    expect(onRetry).toHaveBeenNthCalledWith(3, expect.any(Error), 2, 200);
  });
});

describe('getRetryDefaults', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('returns hardcoded defaults when env vars are not set', () => {
    delete process.env.RETRY_MAX_ATTEMPTS;
    delete process.env.RETRY_BASE_DELAY_MS;
    delete process.env.RETRY_MAX_DELAY_MS;

    const defaults = getRetryDefaults();

    expect(defaults).toEqual({
      maxRetries: 3,
      baseDelayMs: 1000,
      maxDelayMs: 30000,
    });
  });

  it('reads from env vars when set', () => {
    process.env.RETRY_MAX_ATTEMPTS = '5';
    process.env.RETRY_BASE_DELAY_MS = '2000';
    process.env.RETRY_MAX_DELAY_MS = '60000';

    const defaults = getRetryDefaults();

    expect(defaults).toEqual({
      maxRetries: 5,
      baseDelayMs: 2000,
      maxDelayMs: 60000,
    });
  });
});

describe('retry cancellation', () => {
  it('does not invoke an already cancelled operation', async () => {
    const controller = new AbortController();
    controller.abort(new Error('stopped'));
    const fn = jest.fn();
    await expect(retryWithBackoff(fn, { signal: controller.signal })).rejects.toThrow('stopped');
    expect(fn).not.toHaveBeenCalled();
  });

  it('cancels backoff and removes its timer without another attempt', async () => {
    jest.useFakeTimers();
    const controller = new AbortController();
    const fn = jest.fn().mockRejectedValue(new Error('transient'));
    let scheduled!: () => void;
    const backoff = new Promise<void>(resolve => { scheduled = resolve; });
    const pending = retryWithBackoff(fn, { signal: controller.signal, onRetry: scheduled, baseDelayMs: 60_000 });
    const rejected = expect(pending).rejects.toThrow('stopped');
    try {
      await backoff;
      expect(jest.getTimerCount()).toBe(1);
      controller.abort(new Error('stopped'));
      await rejected;
      expect(jest.getTimerCount()).toBe(0);
      expect(fn).toHaveBeenCalledTimes(1);
    } finally { controller.abort(); jest.useRealTimers(); }
  });
});
