import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * Admin proxy: Tier C counsel actions on a report channel.
 *
 *   POST /api/dissemination/:trackingId/counsel/assign
 *   POST /api/dissemination/:trackingId/counsel/attest
 *
 * The acting admin is stamped server-side for the backend audit trail.
 */
const ACTIONS = new Set(['assign', 'attest']);

async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  const { trackingId, action } = req.query;

  if (typeof trackingId !== 'string' || !trackingId) {
    return res.status(400).json({ success: false, error: 'Missing tracking ID' });
  }
  if (typeof action !== 'string' || !ACTIONS.has(action)) {
    return res.status(404).json({ success: false, error: 'Unknown counsel action' });
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Dissemination Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const response = await fetch(
      `${backendUrl}/api/dissemination/${encodeURIComponent(trackingId)}/counsel/${action}`,
      {
        method: 'POST',
        headers: {
          'x-internal-secret': internalSecret,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ...(req.body ?? {}), actor: admin.email }),
        signal: AbortSignal.timeout(30000),
      },
    );

    const data = await response.json();

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'report_status_change',
      endpoint: req.url || '',
      method: req.method,
      responseStatus: response.status,
      details: {
        resourceId: trackingId,
        newStatus: `dissemination_counsel_${action}`,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Counsel action error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
