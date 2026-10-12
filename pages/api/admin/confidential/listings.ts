import { adminPollingHeaders } from '@/src/utils/adminPollingQuota';
import { forwardRetryAfter } from '@/lib/proxyRetryAfter';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';
import { projectConfidentialListings } from '@/lib/confidentialAdminListings';
import { fetchRetryingConnectionError } from '@/lib/internalBackendFetch';

/**
 * POST /api/admin/confidential/listings with JSON body `{ limit?, after? }`
 *
 * The page cursor (`after`) is a case ID, so it travels in the request body on
 * both hops and never in a URL: request URLs reach CDN, load balancer and WAF
 * logs, bodies do not. A query string is refused.
 *
 * Admin-gated proxy to the Express confidential directory. Admins see only the
 * opaque case ID, the owner-signed summary and any category or broad region the
 * owner chose to publish with it (the
 * disclosure boundary in docs/security/README.md#trust-boundaries). The
 * backend verifies every owner signature; this proxy re-projects the reply so a
 * backend addition can never widen what reaches the browser. Views are recorded
 * in the admin audit log without case IDs or summaries.
 */
const HEX64 = /^[a-f0-9]{64}$/;

/** Dedicated layout: the confidential-only task (CONFIDENTIAL_BACKEND_URL) with
 * its own CONFIDENTIAL_ADMIN_SECRET. Shared layout: the legacy API and
 * INTERNAL_API_SECRET. Never mixes one backend with the other's secret. */
export function confidentialListingBackend(env: NodeJS.ProcessEnv = process.env): { url: string; secret: string } | null {
  const dedicated = env.CONFIDENTIAL_BACKEND_URL?.trim();
  if (dedicated) return env.CONFIDENTIAL_ADMIN_SECRET ? { url: dedicated, secret: env.CONFIDENTIAL_ADMIN_SECRET } : null;
  return env.INTERNAL_API_SECRET ? { url: env.BACKEND_URL || 'http://localhost:3001', secret: env.INTERNAL_API_SECRET } : null;
}

async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  res.setHeader('Cache-Control', 'no-store');
  const body: unknown = req.body;
  const fields = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  const { after, limit, ...rest } = fields ?? {};
  if (!fields || Object.keys(req.query).length || Object.keys(rest).length ||
      (after !== undefined && after !== null && (typeof after !== 'string' || !HEX64.test(after))) ||
      (limit !== undefined && (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > 100))) {
    return res.status(400).json({ success: false, error: 'Invalid request' });
  }
  const backend = confidentialListingBackend();
  if (!backend) {
    console.error('[Confidential Listings Proxy] backend secret not configured');
    return res.status(500).json({ success: false, error: 'Backend not configured' });
  }
  const internalSecret = backend.secret;
  const forwarded: { limit?: number; after?: string } = {};
  if (typeof limit === 'number') forwarded.limit = limit;
  if (typeof after === 'string') forwarded.after = after;
  const pathname = '/api/admin/confidential/listings';
  try {
    // Read-only page fetch, so a resend after a stale pooled connection is safe.
    const response = await fetchRetryingConnectionError(`${backend.url}${pathname}`, {
      method: 'POST',
      body: JSON.stringify(forwarded),
      redirect: 'error',
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret,
        ...adminPollingHeaders(admin.userId, 'POST', pathname) },
    }, { timeoutMs: 15000, retry: true });
    forwardRetryAfter(response, res);
    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'confidential_listing_view',
      endpoint: pathname,
      method: 'POST',
      responseStatus: response.status,
      details: {
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });
    if (response.status === 404) return res.status(404).json({ success: false, error: 'Confidential cases are not enabled' });
    if (!response.ok) return res.status(response.status >= 500 ? 503 : response.status).json({ success: false, error: 'Confidential listings unavailable' });
    return res.status(200).json({ success: true, ...projectConfidentialListings(await response.json()) });
  } catch {
    console.error('[Confidential Listings Proxy] Request failed');
    return res.status(502).json({ success: false, error: 'Confidential listings unavailable' });
  }
}

export default withRoleAuth('admin', handler);
