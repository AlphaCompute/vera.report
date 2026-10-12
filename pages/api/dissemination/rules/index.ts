import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';

/**
 * Admin proxy: routing-rules editor (FR-2, PDR §6 — rules are data,
 * editable without redeploy).
 *
 *   GET  /api/dissemination/rules — list all rules (incl. deactivated)
 *   POST /api/dissemination/rules — create/update a rule
 *
 * The actor recorded in the audit trail is stamped server-side from the
 * authenticated admin session, never trusted from the client.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
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

    const body =
      req.method === 'POST'
        ? JSON.stringify({ ...(req.body ?? {}), actor: admin.email ?? 'admin' })
        : undefined;

    const response = await fetch(`${backendUrl}/api/dissemination/rules`, {
      method: req.method,
      headers: {
        'x-internal-secret': internalSecret,
        ...(req.method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body } : {}),
      signal: AbortSignal.timeout(30000),
    });

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Rules error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
