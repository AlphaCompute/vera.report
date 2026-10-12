import { isConfidentialIdentifier } from '@/src/utils/confidentialIdentifiers';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentity } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * POST /api/admin/dashboard/reports/:reportId/analyze
 *
 * Re-run AI verification on a report. Admin-gated proxy to the Express backend,
 * which re-scores via Shroud (the same path used at intake) and persists the
 * verification to MongoDB. `reportId` is the tracking ID. No ElizaOS.
 */
async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentity) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Reanalyze Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const trackingId = String(req.query.reportId ?? '');
    if (isConfidentialIdentifier(trackingId)) return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    const response = await fetch(
      `${backendUrl}/api/whistleblower/admin/reports/${encodeURIComponent(trackingId)}/reanalyze`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret },
        // Shroud inference can be slow; give it room but stay under a UI-reasonable ceiling.
        signal: AbortSignal.timeout(45000),
      },
    );

    const statusCode = response.status;
    const data = await response
      .json()
      .catch(() => ({ success: false, error: 'Invalid response from backend' }));

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'report_analyze',
      endpoint: req.url || '',
      method: req.method || 'POST',
      responseStatus: statusCode,
      details: {
        resourceId: trackingId,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(statusCode).json(data);
  } catch (error: any) {
    console.error('[Reanalyze] Error:', error.message);
    return res.status(502).json({
      success: false,
      error: { message: `Failed to re-analyze: ${error.message}`, code: 'ANALYZE_ERROR' },
    });
  }
}

export default withRoleAuth('admin', handler);
