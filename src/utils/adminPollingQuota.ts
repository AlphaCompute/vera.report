import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';

const ID = 'x-vera-admin-rate-id';
const TIME = 'x-vera-admin-rate-time';
const SIGNATURE = 'x-vera-admin-rate-signature';

// Routine dashboard reads (including POST searches) and audit writes use this budget.
// Report mutations, dispatch, public intake and recipient links retain theirs.
function pollingRoute(method: string, path: string): boolean {
  const pathname = path.split('?')[0];
  if (method === 'POST') return pathname === '/api/admin/audit-log' || pathname === '/api/whistleblower/admin/reports/search' ||
    pathname === '/api/admin/confidential/listings';
  return method === 'GET' && (
    /^\/api\/whistleblower\/admin\/(stats|reports)$/.test(pathname) ||
    pathname === '/api/dissemination/alerts' ||
    /^\/api\/dissemination\/VRA-[A-Fa-f0-9]{16}\/(status|relay)$/.test(pathname)
  );
}

function mac(secret: string, values: string[]): string {
  return createHmac('sha256', secret).update(JSON.stringify(values)).digest('hex');
}

/** Server-only: userId must come from the verified Auth0 session, never a client header. */
export function adminPollingHeaders(userId: string, method: string, path: string): Record<string, string> {
  if (!pollingRoute(method, path)) return {};
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret || !userId || userId === 'unknown') throw new Error('Admin polling identity unavailable');
  const time = String(Date.now());
  const id = mac(secret, ['vera:admin-poll-user:v1', String(Math.floor(Number(time) / 86_400_000)), userId]);
  return {
    [ID]: id, [TIME]: time,
    [SIGNATURE]: mac(secret, ['vera:admin-poll-request:v1', method, path, time, id]),
  };
}

/** Select a bounded per-user quota only with both internal auth and a scoped signature.
 * This does not replace the authorization middleware on any route.
 */
export function adminPollingKey(req: Request): string | null {
  const secret = process.env.INTERNAL_API_SECRET;
  const provided = req.headers['x-internal-secret'];
  if (!secret || typeof provided !== 'string' ||
      Buffer.byteLength(provided) !== Buffer.byteLength(secret) ||
      !timingSafeEqual(Buffer.from(provided), Buffer.from(secret)) ||
      !pollingRoute(req.method, req.originalUrl)) return null;
  const id = req.headers[ID], time = req.headers[TIME], signature = req.headers[SIGNATURE];
  if (typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id) ||
      typeof time !== 'string' || !/^[0-9]{13}$/.test(time) || Math.abs(Date.now() - Number(time)) > 60_000 ||
      typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature)) return null;
  const expected = mac(secret, ['vera:admin-poll-request:v1', req.method, req.originalUrl, time, id]);
  return timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex')) ? `admin:${id}` : null;
}
