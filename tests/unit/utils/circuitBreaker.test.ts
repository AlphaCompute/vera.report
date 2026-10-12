import { CircuitBreaker, CircuitBreakerOpenError } from '../../../src/utils/circuitBreaker';
import type { CircuitBreakerState } from '../../../src/utils/circuitBreaker';

describe('CircuitBreaker', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  function makeBreaker(overrides?: Partial<{ failureThreshold: number; cooldownMs: number; successThreshold: number; onStateChange: (from: CircuitBreakerState, to: CircuitBreakerState) => void }>): CircuitBreaker {
    return new CircuitBreaker({
      name: 'test',
      failureThreshold: 3,
      cooldownMs: 5000,
      successThreshold: 1,
      ...overrides,
    });
  }

  it('excluded contention is neutral in closed and half-open states and releases the probe', async () => {
    const busy = new Error('busy');
    const cb = new CircuitBreaker({ name: 'busy-test', failureThreshold: 1, cooldownMs: 1000,
      shouldRecordFailure: error => error !== busy });
    for (let i = 0; i < 10; i++) await expect(cb.execute(async () => { throw busy; })).rejects.toBe(busy);
    expect(cb.getStats()).toMatchObject({ state: 'CLOSED', failures: 0, lastSuccessTime: null });
    await expect(cb.execute(async () => { throw new Error('real failure'); })).rejects.toThrow('real failure');
    jest.advanceTimersByTime(1000);
    await expect(cb.execute(async () => { throw busy; })).rejects.toBe(busy);
    expect(cb.getStats()).toMatchObject({ state: 'HALF_OPEN', failures: 1, successes: 0 });
    await expect(cb.execute(async () => 'recovered')).resolves.toBe('recovered');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('starts in CLOSED state', () => {
    const cb = makeBreaker();
    expect(cb.getState()).toBe('CLOSED');
  });

  it('passes through successful calls in CLOSED', async () => {
    const cb = makeBreaker();
    const result = await cb.execute(() => Promise.resolve('ok'));
    expect(result).toBe('ok');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('stays CLOSED when failures are below threshold', async () => {
    const cb = makeBreaker({ failureThreshold: 3 });
    const fail = (): Promise<never> => Promise.reject(new Error('boom'));

    await expect(cb.execute(fail)).rejects.toThrow('boom');
    await expect(cb.execute(fail)).rejects.toThrow('boom');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('transitions to OPEN after reaching failure threshold', async () => {
    const cb = makeBreaker({ failureThreshold: 3 });
    const fail = (): Promise<never> => Promise.reject(new Error('boom'));

    for (let i = 0; i < 3; i++) {
      await expect(cb.execute(fail)).rejects.toThrow('boom');
    }
    expect(cb.getState()).toBe('OPEN');
  });

  it('rejects immediately with CircuitBreakerOpenError when OPEN', async () => {
    const cb = makeBreaker({ failureThreshold: 1 });
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
    expect(cb.getState()).toBe('OPEN');

    const fn = jest.fn();
    await expect(cb.execute(fn)).rejects.toThrow(CircuitBreakerOpenError);
    expect(fn).not.toHaveBeenCalled();
  });

  it('transitions to HALF_OPEN after cooldown', async () => {
    const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
    expect(cb.getState()).toBe('OPEN');

    jest.advanceTimersByTime(5000);

    // Next call should probe (HALF_OPEN), succeed, and close
    const result = await cb.execute(() => Promise.resolve('recovered'));
    expect(result).toBe('recovered');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('returns to OPEN if probe fails in HALF_OPEN', async () => {
    const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

    jest.advanceTimersByTime(5000);

    await expect(cb.execute(() => Promise.reject(new Error('still down')))).rejects.toThrow('still down');
    expect(cb.getState()).toBe('OPEN');
  });

  it('resets failure counter on success in CLOSED', async () => {
    const cb = makeBreaker({ failureThreshold: 3 });
    const fail = (): Promise<never> => Promise.reject(new Error('boom'));

    // 2 failures (below threshold)
    await expect(cb.execute(fail)).rejects.toThrow();
    await expect(cb.execute(fail)).rejects.toThrow();

    // Success resets counter
    await cb.execute(() => Promise.resolve('ok'));

    // 2 more failures — should still be CLOSED (counter was reset)
    await expect(cb.execute(fail)).rejects.toThrow();
    await expect(cb.execute(fail)).rejects.toThrow();
    expect(cb.getState()).toBe('CLOSED');
  });

  it('reset() returns to CLOSED and clears counters', async () => {
    const cb = makeBreaker({ failureThreshold: 1 });
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
    expect(cb.getState()).toBe('OPEN');

    cb.reset();
    expect(cb.getState()).toBe('CLOSED');
    expect(cb.getStats().failures).toBe(0);
    expect(cb.getStats().successes).toBe(0);
  });

  it('getStats() returns accurate information', async () => {
    const cb = makeBreaker({ failureThreshold: 3 });

    await cb.execute(() => Promise.resolve('ok'));
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

    const stats = cb.getStats();
    expect(stats.state).toBe('CLOSED');
    expect(stats.failures).toBe(1);
    expect(stats.lastSuccessTime).not.toBeNull();
    expect(stats.lastFailureTime).not.toBeNull();
  });

  it('calls onStateChange on transitions', async () => {
    const onChange = jest.fn();
    const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000, onStateChange: onChange });

    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
    expect(onChange).toHaveBeenCalledWith('CLOSED', 'OPEN');

    jest.advanceTimersByTime(5000);
    await cb.execute(() => Promise.resolve('ok'));

    expect(onChange).toHaveBeenCalledWith('OPEN', 'HALF_OPEN');
    expect(onChange).toHaveBeenCalledWith('HALF_OPEN', 'CLOSED');
  });

  it('supports successThreshold > 1 in HALF_OPEN', async () => {
    const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000, successThreshold: 2 });

    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
    jest.advanceTimersByTime(5000);

    // First success in HALF_OPEN — should stay HALF_OPEN
    await cb.execute(() => Promise.resolve('ok'));
    expect(cb.getState()).toBe('HALF_OPEN');

    // Second success — should close
    await cb.execute(() => Promise.resolve('ok'));
    expect(cb.getState()).toBe('CLOSED');
  });

  it('does not transition OPEN → HALF_OPEN before cooldown', async () => {
    const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
    await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

    jest.advanceTimersByTime(4999);
    await expect(cb.execute(() => Promise.resolve('ok'))).rejects.toThrow(CircuitBreakerOpenError);
    expect(cb.getState()).toBe('OPEN');
  });

  describe('allowsRequest() — cooldown-aware admission', () => {
    // Regression coverage for the bug Dax flagged on PR #273: external
    // callers that pre-filter work before calling execute() must use a
    // cooldown-aware admission check, not raw getState(). Reading
    // `getState() === 'OPEN'` keeps returning true forever after an
    // outage because the OPEN → HALF_OPEN transition only happens
    // inside execute(). A submit handler gated on raw state would wedge
    // at 503 permanently until process restart. Once HALF_OPEN, only
    // one in-flight probe is admitted at a time.

    it('returns true when CLOSED', () => {
      const cb = makeBreaker();
      expect(cb.allowsRequest()).toBe(true);
    });

    it('returns false while OPEN and inside the cooldown window', async () => {
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
      expect(cb.getState()).toBe('OPEN');
      expect(cb.allowsRequest()).toBe(false);

      jest.advanceTimersByTime(2500);
      // Still inside cooldown — admission still denied.
      expect(cb.allowsRequest()).toBe(false);
    });

    it('returns true once cooldown has elapsed, even though raw state is still OPEN', async () => {
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

      jest.advanceTimersByTime(5000);
      // Critically: the raw state has NOT transitioned yet (that happens
      // lazily inside execute()), but admission must be allowed so a
      // probe call can reach execute() and trigger the recovery.
      expect(cb.getState()).toBe('OPEN');
      expect(cb.allowsRequest()).toBe(true);
    });

    it('allows the breaker to actually recover when admission is honored', async () => {
      // End-to-end recovery loop: open it, wait out the cooldown, then
      // a "downstream healthy" probe call closes the breaker again.
      // This is what would have caught the PR #273 bug — gating
      // submit on raw OPEN state passed unit tests but never let
      // execute() run, so the breaker never recovered in production.
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();
      expect(cb.getState()).toBe('OPEN');

      jest.advanceTimersByTime(5000);
      expect(cb.allowsRequest()).toBe(true); // ← caller is admitted

      // The admitted call reaches execute(), the underlying op succeeds,
      // and the breaker transitions OPEN → HALF_OPEN → CLOSED.
      const result = await cb.execute(() => Promise.resolve('recovered'));
      expect(result).toBe('recovered');
      expect(cb.getState()).toBe('CLOSED');
      expect(cb.allowsRequest()).toBe(true);
    });

    it('rejects overlapping HALF_OPEN probes while one probe is in flight', async () => {
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

      jest.advanceTimersByTime(5000);
      const probePromise = cb.execute(() => new Promise((resolve) => setTimeout(() => resolve('ok'), 100)));
      expect(cb.getState()).toBe('HALF_OPEN');
      expect(cb.allowsRequest()).toBe(false);

      const concurrentProbe = jest.fn(() => Promise.resolve('second'));
      await expect(cb.execute(concurrentProbe)).rejects.toThrow(CircuitBreakerOpenError);
      expect(concurrentProbe).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);
      await probePromise;
      expect(cb.getState()).toBe('CLOSED');
    });

    it('returns to allowsRequest() === false if a probe fails and the breaker reopens', async () => {
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

      jest.advanceTimersByTime(5000);
      expect(cb.allowsRequest()).toBe(true);

      // The probe fails — breaker goes HALF_OPEN → OPEN, lastFailureTime
      // resets, and the cooldown window starts over.
      await expect(cb.execute(() => Promise.reject(new Error('still broken')))).rejects.toThrow();
      expect(cb.getState()).toBe('OPEN');
      expect(cb.allowsRequest()).toBe(false);
    });

    it('allows the next sequential HALF_OPEN probe after the prior probe resolves', async () => {
      const cb = makeBreaker({ failureThreshold: 1, cooldownMs: 5000, successThreshold: 2 });
      await expect(cb.execute(() => Promise.reject(new Error('boom')))).rejects.toThrow();

      jest.advanceTimersByTime(5000);
      await expect(cb.execute(() => Promise.resolve('first ok'))).resolves.toBe('first ok');
      expect(cb.getState()).toBe('HALF_OPEN');
      expect(cb.allowsRequest()).toBe(true);

      await expect(cb.execute(() => Promise.resolve('second ok'))).resolves.toBe('second ok');
      expect(cb.getState()).toBe('CLOSED');
    });
  });
});
