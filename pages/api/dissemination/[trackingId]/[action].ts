import { adminPollingHeaders } from '@/src/utils/adminPollingQuota';
import { forwardRetryAfter } from '@/lib/proxyRetryAfter';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * Admin proxy for the dissemination pipeline (VERA-PDR-001 §11):
 *
 *   GET  /api/dissemination/:trackingId/status
 *   POST /api/dissemination/:trackingId/plan
 *   POST /api/dissemination/:trackingId/approve
 *   POST /api/dissemination/:trackingId/withdraw
 *   POST /api/dissemination/:trackingId/receipts
 *   POST /api/dissemination/:trackingId/retry
 *   POST /api/dissemination/:trackingId/escrow-release
 *
 * Auth0 admin role is enforced here; the internal secret authenticates the
 * forwarded request to the Express backend (same defense-in-depth pattern
 * as the evidence proxy). (Counsel, relay, redaction, and audit-proof
 * actions arrive with their respective later slices.)
 */

const ACTIONS: Record<string, ('GET' | 'POST')[]> = {
  status: ['GET'],
  plan: ['POST'],
  approve: ['POST'],
  withdraw: ['POST'],
  receipts: ['POST'],
  retry: ['POST'],
  'escrow-release': ['POST'],
  'secure-packet-email': ['POST'],
  'secure-packet-generate': ['POST'],
  redact: ['POST'],
  relay: ['GET', 'POST'],
  'audit-proofs': ['GET'],
};

async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  const { trackingId, action } = req.query;

  if (!trackingId || typeof trackingId !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing tracking ID' });
  }
  if (!action || typeof action !== 'string' || !(action in ACTIONS)) {
    return res.status(404).json({ success: false, error: 'Unknown dissemination action' });
  }
  if (!ACTIONS[action].includes(req.method as 'GET' | 'POST')) {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Dissemination Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    // Stamp the acting admin server-side — the backend records it in the
    // dissemination audit trail (FR-10: every override logged).
    const body =
      req.method === 'POST'
        ? JSON.stringify({ ...(req.body ?? {}), approvedBy: admin.email, actor: admin.email })
        : undefined;

    const path = `/api/dissemination/${encodeURIComponent(trackingId)}/${action}`;
    const response = await fetch(
      `${backendUrl}${path}`,
      {
        method: req.method,
        headers: {
          'x-internal-secret': internalSecret,
          ...adminPollingHeaders(admin.userId, req.method!, path),
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(body ? { body } : {}),
        signal: AbortSignal.timeout(30000),
      },
    );

    forwardRetryAfter(response, res);
    const data = await response.json();
    res.setHeader('Cache-Control', 'no-store');

    // Every mutating action is a consequential admin event — audit them all
    // at the proxy layer (FR-10 / Pattern C), not just approve/withdraw.
    if (req.method === 'POST') {
      logAuditEvent({
        adminUserId: admin.userId,
        adminEmail: admin.email,
        action: 'report_status_change',
        endpoint: req.url || '',
        method: req.method,
        responseStatus: response.status,
        details: {
          resourceId: trackingId,
          newStatus: `dissemination_${action}`,
          ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
          userAgent: req.headers['user-agent'],
        },
      });
    }

    return res.status(response.status).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Dissemination Proxy] Error:', msg);
    return res.status(502).json({ success: false, error: 'Failed to reach dissemination backend' });
  }
}

export default withRoleAuth('admin', handler);
