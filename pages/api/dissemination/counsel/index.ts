import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';

/**
 * Admin proxy: counsel partner bench (Tier C routing targets).
 *
 *   GET  /api/dissemination/counsel          — list partners
 *   POST /api/dissemination/counsel          — create/update a partner
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  _admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Dissemination Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const query = req.method === 'GET' && req.query.active === 'true' ? '?active=true' : '';
    const response = await fetch(`${backendUrl}/api/dissemination/counsel${query}`, {
      method: req.method,
      headers: {
        'x-internal-secret': internalSecret,
        ...(req.method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(req.method === 'POST' ? { body: JSON.stringify(req.body ?? {}) } : {}),
      signal: AbortSignal.timeout(30000),
    });

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Counsel error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
