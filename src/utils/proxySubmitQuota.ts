import { proxyClientQuotaKey } from './proxyRateLimit';
import type { IncomingHttpHeaders } from 'node:http';

type ProxyRequest = { headers: IncomingHttpHeaders; socket: { remoteAddress?: string } };

/** Mirror Express submitLimiter: 5 submissions per 15 minutes per proxy quota key. */
const MAX_ADMITS = 5;
const WINDOW_MS = 15 * 60 * 1000;
/** Cap distinct live quota keys so attacker-controlled addresses cannot grow the heap unboundedly. */
const MAX_KEYS = 10_000;
const admits = new Map<string, number[]>();

function pruneExpired(now: number): void {
  for (const [key, timestamps] of admits) {
    const live = timestamps.filter((t) => now - t < WINDOW_MS);
    if (live.length === 0) admits.delete(key);
    else if (live.length !== timestamps.length) admits.set(key, live);
  }
}

/**
 * Consume one pre-slot admit for this client. Returns false when the window is full
 * so the handler can reject without taking the sole transfer slot.
 */
export function tryAdmitSubmitProxy(req: ProxyRequest): boolean {
  const key = proxyClientQuotaKey(req);
  const now = Date.now();
  pruneExpired(now);

  const timestamps = admits.get(key) || [];
  if (timestamps.length >= MAX_ADMITS) return false;

  if (!admits.has(key) && admits.size >= MAX_KEYS) return false;

  timestamps.push(now);
  admits.set(key, timestamps);
  return true;
}

/** Test helper: clear process-local admit history. */
export function resetProxySubmitQuotaForTests(): void {
  admits.clear();
}

/** Test helper: number of retained quota keys. */
export function proxySubmitQuotaKeyCountForTests(): number {
  return admits.size;
}
