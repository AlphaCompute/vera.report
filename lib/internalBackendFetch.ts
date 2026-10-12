/** Socket-level failures where no HTTP response arrived. The first request on a
 * pooled keep-alive connection that the backend closed (for example after its
 * task restarted) fails with one of these, and a fresh connection succeeds. */
const CONNECTION_ERROR_CODES = new Set(['ECONNRESET', 'EPIPE', 'ECONNABORTED', 'ECONNREFUSED', 'UND_ERR_SOCKET', 'UND_ERR_CLOSED']);
/** A retry is pointless with less time than this left in the shared deadline. */
const MIN_RETRY_BUDGET_MS = 2_000;

export function isConnectionError(error: unknown): boolean {
  // fetch rejects with TypeError('fetch failed') carrying the socket error as
  // cause. Read fields, not instanceof: undici errors can come from another realm.
  if (!error || typeof error !== 'object' || (error as { name?: unknown }).name !== 'TypeError') return false;
  const cause = (error as { cause?: unknown }).cause;
  const code = cause && typeof cause === 'object' ? (cause as { code?: unknown }).code : undefined;
  return typeof code === 'string' && CONNECTION_ERROR_CODES.has(code);
}

/**
 * fetch with one retry when the request failed at the connection level before
 * any response. HTTP error statuses, timeouts and other failures are never
 * retried, and both attempts share a single deadline of `timeoutMs`. Pass
 * `retry: true` only for requests the backend treats as idempotent: the first
 * attempt may have reached it before the socket failed.
 */
export async function fetchRetryingConnectionError(url: string, init: Omit<RequestInit, 'signal'> & { body?: string },
  { timeoutMs, retry, onRetry }: { timeoutMs: number; retry: boolean; onRetry?: (error: unknown) => void }): Promise<Response> {
  const deadline = Date.now() + timeoutMs;
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    return await fetch(url, { ...init, signal });
  } catch (error) {
    if (!retry || signal.aborted || !isConnectionError(error) || deadline - Date.now() < MIN_RETRY_BUDGET_MS) throw error;
    onRetry?.(error);
    return fetch(url, { ...init, signal });
  }
}
