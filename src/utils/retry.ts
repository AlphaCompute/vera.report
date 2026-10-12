export type RetryOptions = {
  signal?: AbortSignal;
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  shouldRetry?: (error: unknown, attempt: number) => boolean;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
};

export function getRetryDefaults(): Pick<RetryOptions, 'maxRetries' | 'baseDelayMs' | 'maxDelayMs'> {
  return {
    maxRetries: parseInt(process.env.RETRY_MAX_ATTEMPTS ?? '3', 10),
    baseDelayMs: parseInt(process.env.RETRY_BASE_DELAY_MS ?? '1000', 10),
    maxDelayMs: parseInt(process.env.RETRY_MAX_DELAY_MS ?? '30000', 10),
  };
}

export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options?: Partial<RetryOptions>,
): Promise<T> {
  const defaults = getRetryDefaults();
  const maxRetries = options?.maxRetries ?? defaults.maxRetries;
  const baseDelayMs = options?.baseDelayMs ?? defaults.baseDelayMs;
  const maxDelayMs = options?.maxDelayMs ?? defaults.maxDelayMs;
  const shouldRetry = options?.shouldRetry;
  const onRetry = options?.onRetry ?? defaultOnRetry;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    options?.signal?.throwIfAborted();
    try {
      return await fn();
    } catch (error: unknown) {
      options?.signal?.throwIfAborted();
      lastError = error;

      if (attempt === maxRetries) break;
      if (shouldRetry && !shouldRetry(error, attempt)) break;

      const rawDelay = baseDelayMs * Math.pow(2, attempt);
      const cappedDelay = Math.min(rawDelay, maxDelayMs);
      const jitteredDelay = Math.floor(Math.random() * cappedDelay);

      onRetry(error, attempt, jitteredDelay);

      await new Promise<void>((resolve, reject) => {
        const signal = options?.signal;
        const abort = () => {
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          reject(signal?.reason);
        };
        const timer = setTimeout(() => {
          signal?.removeEventListener('abort', abort);
          resolve();
        }, jitteredDelay);
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
      });
    }
  }

  throw lastError;
}

function defaultOnRetry(error: unknown, attempt: number, delayMs: number): void {
  const message = error instanceof Error ? error.message : String(error);
  console.warn(`[RETRY] Attempt ${attempt + 1} failed, retrying in ${delayMs}ms: ${message}`);
}
