import { readFileSync, statSync } from 'node:fs';

/** Host delivery of the signed release withdrawal list. The host never verifies
 * or interprets the list (it is signed offline and checked by the enclave and
 * participant devices); it only re-reads the file the parent instance refreshes
 * from the release bucket, so a new list takes effect without a restart. */
const MAX_BYTES = 256 * 1024;
const CACHE_MS = 30_000;

export function releaseWithdrawalsSource(path: string | undefined, now: () => number = Date.now): () => string | null {
  let cached: { at: number; value: string | null } | null = null;
  return () => {
    if (!path) return null;
    if (cached && now() - cached.at < CACHE_MS) return cached.value;
    let value: string | null = null;
    try {
      const stat = statSync(path);
      if (stat.isFile() && stat.size > 0 && stat.size <= MAX_BYTES) value = readFileSync(path, 'utf8').trim() || null;
    } catch { value = null; }
    cached = { at: now(), value };
    return value;
  };
}
