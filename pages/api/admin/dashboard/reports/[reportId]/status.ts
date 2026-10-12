import { isConfidentialIdentifier } from '@/src/utils/confidentialIdentifiers';
import { openTriageReference } from '@/lib/triageReference';
import { isAdmin } from '@/lib/roles';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEventRequired } from '@/lib/auditClient';

/**
 * PATCH /api/admin/dashboard/reports/:reportId/status
 *
 * Update a report's triage status. Proxies to the Express backend, which
 * persists to MongoDB (the source of record). `reportId` is the VRA tracking
 * ID. The Next runtime holds no DB connection; the legacy ElizaOS PATCH is gone.
 */
async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  if (req.method !== 'PATCH') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const suppliedId = req.query.reportId;
    let reportId: string;
    try {
      if (typeof suppliedId !== 'string') throw new Error();
      reportId = isAdmin(admin.roles) ? suppliedId : openTriageReference(suppliedId);
    } catch { return res.status(400).json({ success: false, error: 'Invalid report reference' }); }
    if (isConfidentialIdentifier(reportId)) return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    const { status } = req.body ?? {};

    if (!status) {
      return res.status(400).json({ success: false, error: 'Missing required field: status' });
    }

    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Status Update Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'report_status_change',
      endpoint: req.url || '',
      method: req.method || 'PATCH',
      responseStatus: 0,
      details: {
        phase: 'attempted',
        resourceId: String(reportId ?? ''),
        newStatus: String(status),
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    const response = await fetch(
      `${backendUrl}/api/whistleblower/admin/reports/${encodeURIComponent(String(reportId))}/status`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret },
        body: JSON.stringify({ status }),
        signal: AbortSignal.timeout(15000),
      },
    );
    const statusCode = response.status;

    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'report_status_change',
      endpoint: req.url || '',
      method: req.method || 'PATCH',
      responseStatus: statusCode,
      details: {
        phase: 'response',
        resourceId: String(reportId ?? ''),
        newStatus: String(status),
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });
    const data = await response.json().catch(() => ({ success: false, error: 'Invalid backend response' }));

    return res.status(statusCode).json(isAdmin(admin.roles) ? data : { success: response.ok, ...(response.ok ? {} : { error: 'Failed to update report status' }) });
  } catch (error: unknown) {
    console.error('[Status Update Proxy] Error:', error instanceof Error ? error.message : String(error));
    return res.status(502).json({
      success: false,
      error: { message: 'Failed to update status via backend', code: 'STATUS_UPDATE_ERROR' },
    });
  }
}

export default withRoleAuth('employee', handler);
