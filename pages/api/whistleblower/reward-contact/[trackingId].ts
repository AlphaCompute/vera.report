import { isConfidentialIdentifier } from '@/src/utils/confidentialIdentifiers';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEventRequired } from '@/lib/auditClient';

/**
 * GET /api/whistleblower/reward-contact/:trackingId
 * Proxy to Express backend to fetch decrypted reward contact info.
 * Requires admin role — contains whistleblower PII.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { trackingId } = req.query;

    if (!trackingId || typeof trackingId !== 'string') {
      return res.status(400).json({ success: false, error: 'Missing tracking ID' });
    }
    if (isConfidentialIdentifier(trackingId)) return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });

    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[RewardContact Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }
    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'contact_info_decrypt',
      endpoint: req.url || '',
      method: req.method || 'GET',
      responseStatus: 0,
      details: {
        phase: 'attempted',
        resourceId: trackingId,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    const response = await fetch(
      `${backendUrl}/api/whistleblower/reward-contact/${encodeURIComponent(trackingId)}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'x-internal-secret': internalSecret,
        },
        signal: AbortSignal.timeout(15000),
      }
    );

    const statusCode = response.status;

    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'contact_info_decrypt',
      endpoint: req.url || '',
      method: req.method || 'GET',
      responseStatus: statusCode,
      details: {
        phase: 'response',
        resourceId: trackingId,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });
    const data = await response.json();

    return res.status(statusCode).json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[RewardContact Proxy] Error:', msg);
    return res.status(502).json({
      success: false,
      error: 'Failed to retrieve reward contact from backend',
    });
  }
}

export default withRoleAuth('admin', handler);
