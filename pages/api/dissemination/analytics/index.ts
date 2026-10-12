import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';

/**
 * Admin proxy: dissemination outcome analytics (§13) — the dispatch
 * funnel and per-entity outcome rows for the Insights tab.
 *
 *   GET /api/dissemination/analytics
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  _admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Dissemination Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const response = await fetch(`${backendUrl}/api/dissemination/analytics`, {
      headers: { 'x-internal-secret': internalSecret },
      signal: AbortSignal.timeout(30000),
    });

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Analytics error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
