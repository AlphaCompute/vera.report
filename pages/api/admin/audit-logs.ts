import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentity } from '@/lib/authMiddleware';
import { queryAuditLogs, ADMIN_ACTIONS } from '@/lib/auditClient';
import type { AdminAction, AuditSeverity } from '@/lib/auditClient';


const VALID_SEVERITIES: AuditSeverity[] = ['critical', 'important', 'info'];

/**
 * GET /api/admin/audit-logs
 * Query audit logs via Express backend.
 */
async function handler(req: NextApiRequest, res: NextApiResponse, _admin: AdminIdentity) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const {
      adminEmail,
      action,
      severity,
      resourceId,
      startDate,
      endDate,
      page,
      limit,
    } = req.query;

    if (action && !ADMIN_ACTIONS.includes(action as AdminAction)) {
      return res.status(400).json({ success: false, error: `Invalid action. Valid: ${ADMIN_ACTIONS.join(', ')}` });
    }
    if (severity && !VALID_SEVERITIES.includes(severity as AuditSeverity)) {
      return res.status(400).json({ success: false, error: `Invalid severity. Valid: ${VALID_SEVERITIES.join(', ')}` });
    }

    const result = await queryAuditLogs({
      adminEmail: adminEmail as string | undefined,
      action: action as AdminAction | undefined,
      severity: severity as AuditSeverity | undefined,
      resourceId: resourceId as string | undefined,
      startDate: startDate ? new Date(startDate as string) : undefined,
      endDate: endDate ? new Date(endDate as string) : undefined,
      page: page ? parseInt(page as string, 10) : 1,
      limit: limit ? parseInt(limit as string, 10) : 50,
    });

    return res.status(200).json({
      success: true,
      data: {
        entries: result.entries,
        total: result.total,
        page: result.page,
        limit: result.limit,
      },
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Audit Logs] Error:', msg);
    return res.status(500).json({
      success: false,
      error: 'Failed to query audit logs',
    });
  }
}

export default withRoleAuth('admin', handler);
