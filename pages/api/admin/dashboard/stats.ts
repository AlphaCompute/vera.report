import { adminPollingHeaders } from '@/src/utils/adminPollingQuota';
import { forwardRetryAfter } from '@/lib/proxyRetryAfter';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentity } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * GET /api/admin/dashboard/stats
 *
 * Admin-gated proxy to the Express backend, which aggregates dashboard stats from
 * MongoDB (the source of record). The Next runtime holds no DB connection.
 */
async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentity) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Stats Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const path = '/api/whistleblower/admin/stats';
    const response = await fetch(`${backendUrl}${path}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret, ...adminPollingHeaders(admin.userId, 'GET', path) },
      signal: AbortSignal.timeout(15000),
    });
    forwardRetryAfter(response, res);
    const statusCode = response.status;
    const data = await response.json();

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'stats_view',
      endpoint: req.url || '',
      method: req.method || 'GET',
      responseStatus: statusCode,
      details: {
        agentId: String(req.query.agentId ?? ''),
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(statusCode).json(data);
  } catch (error: unknown) {
    console.error('[Stats Proxy] Error:', error instanceof Error ? error.message : String(error));
    return res.status(502).json({
      success: false,
      error: { message: 'Failed to fetch stats from backend', code: 'STATS_FETCH_ERROR' },
    });
  }
}

export default withRoleAuth('employee', handler);
