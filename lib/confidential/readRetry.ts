/** A relay may throttle, but it may never induce an unbounded wait or reuse an
 * expired one-use session. Only an idempotent authenticated read uses this helper. */
export class ConfidentialRateLimitError extends Error {
  readonly delayMs: number;
  constructor(retryAfter: string | null) {
    super('The secure connection is busy right now. If you were making a change, it may have completed. Check the report before trying again.');
    const seconds = retryAfter && /^\d{1,3}$/.test(retryAfter) ? Number(retryAfter) : 60;
    this.delayMs = Math.min(65_000, Math.max(1_000, seconds * 1000 + 250));
  }
}

export async function retryConfidentialRead<T>(attempt: () => Promise<T>,
  wait: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
  budget?: { expiresAt: number; clock?: () => number },
): Promise<T> {
  const clock = budget?.clock ?? Date.now;
  const check = (delay = 0) => {
    if (budget && (!Number.isSafeInteger(budget.expiresAt) || clock() + delay >= budget.expiresAt)) {
      throw new Error('Confidential read time budget exhausted');
    }
  };
  for (let retries = 0; ; retries++) {
    check();
    try { const result = await attempt(); check(); return result; }
    catch (error) {
      if (!(error instanceof ConfidentialRateLimitError) || retries >= 3) throw error;
      // The entire operation callback runs again: new time, login token,
      // attestation nonce, challenge and signature. Never replay a channel call.
      check(error.delayMs);
      await wait(error.delayMs);
    }
  }
}
