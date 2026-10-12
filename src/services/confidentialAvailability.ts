import type { RequestHandler } from 'express';

export interface ConfidentialAvailability<T> {
  admission: RequestHandler;
  settled: Promise<void>;
  status: () => 'starting' | 'ready' | 'unavailable' | 'closed';
  get(): Promise<T>;
  close(): Promise<void>;
}

/** Attempts, including the first, before a permanent failure stops retrying. */
export const PERMANENT_FAILURE_ATTEMPTS = 3;

/** Isolate optional confidential initialization without permitting legacy intake
 * as a fallback. Retry transient failures with bounded backoff; initializers must
 * close partially created resources on error. `settled` covers the first attempt.
 * A failure `permanent()` classifies as unrecoverable (e.g. invalid configuration)
 * is retried only until PERMANENT_FAILURE_ATTEMPTS consecutive attempts failed that
 * way; then retrying stops, `onAbandoned` runs once and the service stays closed. */
export function createConfidentialAvailability<T>(initialize: () => Promise<{ value: T; close: () => Promise<void> }>,
  onFailure: () => void, options: { permanent?: () => boolean; onAbandoned?: () => void } = {}): ConfidentialAvailability<T> {
  let state: 'starting' | 'ready' | 'unavailable' | 'closed' = 'starting';
  let resource: { value: T; close: () => Promise<void> } | undefined;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let retryDelay = 5000;
  let permanentFailures = 0;
  const isClosed = () => state === 'closed';
  async function attempt(): Promise<void> {
    if (isClosed()) return;
    try {
      resource = await initialize();
      if (!isClosed()) state = 'ready';
    } catch {
      if (isClosed()) return;
      state = 'unavailable';
      let permanent = false;
      try { permanent = options.permanent?.() === true; } catch { /* Unclassified: treat as transient. */ }
      permanentFailures = permanent ? permanentFailures + 1 : 0;
      try { onFailure(); } catch { /* Logging must not create an unhandled rejection. */ }
      if (permanentFailures >= PERMANENT_FAILURE_ATTEMPTS) {
        try { options.onAbandoned?.(); } catch { /* As above. */ }
        return;
      }
      scheduleRetry();
    }
  }
  function scheduleRetry() {
    if (state === 'closed') return;
    retry = setTimeout(() => { retry = undefined; initializing = attempt(); }, retryDelay);
    retry.unref();
    retryDelay = Math.min(retryDelay * 2, 60_000);
  }
  let initializing = Promise.resolve().then(attempt);
  const settled = initializing;
  let closing: Promise<void> | undefined;
  const admission: RequestHandler = (_req, res, next) => {
    if (state === 'ready') { next(); return; }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.status(503).json({ success: false, error: 'confidential_unavailable' });
  };
  return {
    admission, settled,
    status: () => state,
    async get(): Promise<T> {
      if (state !== 'ready' || !resource) throw new Error('Confidential service unavailable');
      return resource.value;
    },
    close(): Promise<void> {
      state = 'closed';
      clearTimeout(retry);
      retry = undefined;
      return closing ??= initializing.then(async () => { await resource?.close(); });
    },
  };
}
