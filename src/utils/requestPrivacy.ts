/** Route families only: reporter IDs and packet tokens are bearer credentials.
 * `confidential` covers `/api/confidential/*` and `/api/admin/confidential/*`:
 * nonces, ciphertext, digests, cursors and case IDs must never enter request,
 * flow, error or telemetry logs (docs/security/README.md#trust-boundaries). */
const PRIVATE_FAMILY = /\/(whistleblower|dissemination|packets|report|status|confidential|legal-applications|legal-approval|legal)(\/|$)/i;

export function privateRequest(url: string): boolean {
  let path = url.split(/[?#]/, 1)[0];
  try { path = decodeURIComponent(path); } catch { return true; }
  return PRIVATE_FAMILY.test(path);
}

/** Only legacy private routes keep content-free failure alarms. Confidential
 * case and legal routes retain no per-request diagnostic events. */
export function legacyPrivateFailure(url: string, status: unknown): { routeFamily: string; status: number } | null {
  let path = url.split(/[?#]/, 1)[0];
  try { path = decodeURIComponent(path); } catch { return null; }
  const family = path.match(PRIVATE_FAMILY)?.[1]?.toLowerCase();
  if (!family || !['whistleblower', 'dissemination', 'packets', 'report', 'status'].includes(family)) return null;
  return { routeFamily: family, status: typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599 ? status : 500 };
}

export function telemetryPath(url: string): string {
  let path = url.split(/[?#]/, 1)[0];
  try { path = decodeURIComponent(path); } catch { return '/[redacted]'; }
  if (privateRequest(path)) {
    const family = path.match(PRIVATE_FAMILY)?.[1];
    return `/${family}/[redacted]`;
  }
  // Unknown identifiers must not enter logs through encoded/control characters.
  return path.replace(/(?:VRA|VRC)-[a-f0-9]+/gi, '[redacted]').replace(/VERA-OWNER-1\.[^/]*/gi, '[redacted]')
    .replace(/[0-9A-Z](?:[\s\-_·–—]*[0-9A-Z]){39,71}/gi, '[redacted]')
    .replace(/[a-f0-9]{64}/gi, '[redacted]').replace(/[\r\n\t]/g, '').slice(0, 200);
}
