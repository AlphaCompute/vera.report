/** Bounded startup retry with exponential backoff. The host may be briefly
 * unable to serve the release manifest or identity policy, and NSM may be busy;
 * after the last attempt the error propagates and the process exits. The
 * enclave entrypoint restarts it under its own bounded supervisor, which never
 * stops the legacy crypto services. */
export async function retryBounded<T>(attempt: () => Promise<T>, options: {
  attempts?: number; initialDelayMs?: number; maxDelayMs?: number; sleep?: (ms: number) => Promise<void>;
} = {}): Promise<T> {
  const attempts = options.attempts ?? 8, maxDelayMs = options.maxDelayMs ?? 60_000;
  const sleep = options.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  if (!Number.isSafeInteger(attempts) || attempts < 1) throw new Error('Invalid retry bound');
  for (let index = 1, delay = options.initialDelayMs ?? 1_000; ; index += 1, delay = Math.min(delay * 2, maxDelayMs)) {
    try { return await attempt(); } catch (error) {
      if (index >= attempts) throw error;
      await sleep(delay);
    }
  }
}
