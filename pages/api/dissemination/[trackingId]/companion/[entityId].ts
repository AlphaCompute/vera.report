import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '@/src/utils/evidenceLimits';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { proxyAdminRateLimitHeaders } from '@/src/utils/proxyRateLimit';

/**
 * Admin proxy: download the printable pre-filled filing form for a Tier B
 * channel (SEC/CFTC Form TCR, FinCEN submission, IRS Form 211).
 *
 *   GET /api/dissemination/:trackingId/companion/:entityId
 *
 * Downloads the filing PDF and evidence ZIP from the Express backend; Auth0 admin role enforced here.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  const { trackingId, entityId } = req.query;

  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }
  if (typeof trackingId !== 'string' || typeof entityId !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing tracking ID or entity' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Dissemination Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const path = `/api/dissemination/${encodeURIComponent(trackingId)}/companion/${encodeURIComponent(entityId)}`;
    const response = await fetch(
      `${backendUrl}${path}`,
      {
        headers: { 'x-internal-secret': internalSecret, ...proxyAdminRateLimitHeaders(admin.userId, 'GET', path) },
        signal: AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS),
      },
    );

    if (!response.ok) {
      const data = await response.json().catch(() => ({ success: false, error: 'Backend error' }));
      return res.status(response.status).json(data);
    }

    const archive = Buffer.from(await response.arrayBuffer());
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Disposition',
      response.headers.get('content-disposition') || 'attachment; filename="vera-filing.zip"',
    );
    return res.send(archive);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Companion error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
