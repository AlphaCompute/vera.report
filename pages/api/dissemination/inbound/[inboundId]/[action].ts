import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * Admin proxy: act on a queued inbound receipt mail.
 *
 *   POST /api/dissemination/inbound/:inboundId/resolve
 *   POST /api/dissemination/inbound/:inboundId/dismiss
 *
 * Auth0 admin role enforced here; the acting admin is stamped server-side
 * so the backend audit trail records who resolved each message.
 */
const ACTIONS = new Set(['resolve', 'dismiss']);

async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  const { inboundId, action } = req.query;

  if (!inboundId || typeof inboundId !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing inbound ID' });
  }
  if (!action || typeof action !== 'string' || !ACTIONS.has(action)) {
    return res.status(404).json({ success: false, error: 'Unknown inbound action' });
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
      `${backendUrl}/api/dissemination/inbound/${encodeURIComponent(inboundId)}/${action}`,
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
        resourceId: inboundId,
        newStatus: `dissemination_inbound_${action}`,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Inbound action error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
