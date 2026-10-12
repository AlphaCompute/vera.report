import { logger } from './logger';
export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export type CircuitBreakerOptions = {
  name: string;
  failureThreshold: number;
  cooldownMs: number;
  successThreshold: number;
  shouldRecordFailure?: (error: unknown) => boolean;
  onStateChange?: (from: CircuitBreakerState, to: CircuitBreakerState) => void;
};

export type CircuitBreakerStats = {
  state: CircuitBreakerState;
  failures: number;
  successes: number;
  lastFailureTime: number | null;
  lastSuccessTime: number | null;
};

export class CircuitBreakerOpenError extends Error {
  constructor(name: string) {
    super(`[CIRCUIT:${name}] Circuit is OPEN — request rejected`);
    this.name = 'CircuitBreakerOpenError';
  }
}

export class CircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private failures = 0;
  private successes = 0;
  private lastFailureTime: number | null = null;
  private lastSuccessTime: number | null = null;
  private halfOpenProbeInFlight = false;
  private readonly options: CircuitBreakerOptions;

  constructor(options: Partial<CircuitBreakerOptions> & { name: string }) {
    this.options = {
      failureThreshold: 5,
      cooldownMs: 30000,
      successThreshold: 1,
      ...options,
    };
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    let isHalfOpenProbe = false;

    if (this.state === 'OPEN') {
      if (this.shouldProbe()) {
        this.transition('HALF_OPEN');
      } else {
        throw new CircuitBreakerOpenError(this.options.name);
      }
    }

    if (this.state === 'HALF_OPEN') {
      if (this.halfOpenProbeInFlight) {
        throw new CircuitBreakerOpenError(this.options.name);
      }
      this.halfOpenProbeInFlight = true;
      isHalfOpenProbe = true;
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      if (this.options.shouldRecordFailure?.(error) !== false) this.onFailure();
      throw error;
    } finally {
      if (isHalfOpenProbe) {
        this.halfOpenProbeInFlight = false;
      }
    }
  }

  getState(): CircuitBreakerState {
    return this.state;
  }

  /**
   * Cooldown-aware admission check. Returns `true` when a caller is
   * allowed to attempt the underlying operation, `false` when the circuit
   * is OPEN and still cooling down.
   *
   * Critically, this returns `true` once the cooldown has elapsed even
   * though the state is still raw-OPEN, so one caller can reach
   * `execute()` and move the breaker to HALF_OPEN. While that probe is in
   * flight, additional callers are denied until the probe resolves.
   */
  allowsRequest(): boolean {
    if (this.state === 'CLOSED') return true;
    if (this.state === 'HALF_OPEN') return !this.halfOpenProbeInFlight;
    return this.shouldProbe();
  }

  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
    };
  }

  reset(): void {
    this.transition('CLOSED');
    this.failures = 0;
    this.successes = 0;
    this.halfOpenProbeInFlight = false;
  }

  private shouldProbe(): boolean {
    if (this.lastFailureTime === null) return false;
    return Date.now() - this.lastFailureTime >= this.options.cooldownMs;
  }

  private onSuccess(): void {
    this.lastSuccessTime = Date.now();

    if (this.state === 'HALF_OPEN') {
      this.successes++;
      if (this.successes >= this.options.successThreshold) {
        this.failures = 0;
        this.successes = 0;
        this.transition('CLOSED');
      }
    } else if (this.state === 'CLOSED') {
      this.failures = 0;
    }
  }

  private onFailure(): void {
    this.lastFailureTime = Date.now();
    this.failures++;

    if (this.state === 'HALF_OPEN') {
      this.successes = 0;
      this.transition('OPEN');
    } else if (this.state === 'CLOSED' && this.failures >= this.options.failureThreshold) {
      this.transition('OPEN');
    }
  }

  private transition(to: CircuitBreakerState): void {
    if (this.state === to) return;
    const from = this.state;
    this.state = to;
    logger.info(`[CIRCUIT:${this.options.name}] ${from} → ${to}`);
    this.options.onStateChange?.(from, to);
  }
}
