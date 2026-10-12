import { Router, Request, Response } from 'express';
import { adminAuditLog } from '../services/adminAuditLog';
import { ADMIN_ACTIONS } from '../services/adminAuditActions';
import type { AdminAction, AuditSeverity } from '../services/adminAuditActions';
import { rateLimiters } from '../middleware/security';
import { requireInternalSecret } from '../middleware/internalSecret';

const router = Router();


const VALID_SEVERITIES: AuditSeverity[] = ['critical', 'important', 'info'];

router.use(rateLimiters.monitoring);
router.use(requireInternalSecret);

router.post('/audit-log', async (req: Request, res: Response) => {
  try {
    const { adminUserId, adminEmail, action, endpoint, method, responseStatus, details } = req.body;

    if (!action || !ADMIN_ACTIONS.includes(action)) {
      res.status(400).json({
        success: false,
        error: `Invalid action. Valid: ${ADMIN_ACTIONS.join(', ')}`,
      });
      return;
    }

    await adminAuditLog.log({
      adminUserId: adminUserId || 'unknown',
      adminEmail: adminEmail || 'unknown',
      action,
      endpoint: endpoint || '',
      method: method || 'UNKNOWN',
      responseStatus: responseStatus ?? 0,
      details: details || {},
    }, true);

    res.json({ success: true });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[AUDIT_ROUTER] POST /audit-log error:', msg);
    res.status(500).json({ success: false, error: 'Failed to persist audit log' });
  }
});

router.get('/audit-logs', async (req: Request, res: Response) => {
  try {
    const { adminEmail, action, severity, resourceId, startDate, endDate, page, limit } = req.query;

    if (action && !ADMIN_ACTIONS.includes(action as AdminAction)) {
      res.status(400).json({
        success: false,
        error: `Invalid action. Valid: ${ADMIN_ACTIONS.join(', ')}`,
      });
      return;
    }

    if (severity && !VALID_SEVERITIES.includes(severity as AuditSeverity)) {
      res.status(400).json({
        success: false,
        error: `Invalid severity. Valid: ${VALID_SEVERITIES.join(', ')}`,
      });
      return;
    }

    const parsedPage = page ? parseInt(page as string, 10) : 1;
    const parsedLimit = limit ? parseInt(limit as string, 10) : 50;

    const result = await adminAuditLog.query({
      adminEmail: adminEmail as string | undefined,
      action: action as AdminAction | undefined,
      severity: severity as AuditSeverity | undefined,
      resourceId: resourceId as string | undefined,
      startDate: startDate ? new Date(startDate as string) : undefined,
      endDate: endDate ? new Date(endDate as string) : undefined,
      page: parsedPage,
      limit: parsedLimit,
    }, true);

    res.json({
      success: true,
      data: {
        entries: result.entries,
        total: result.total,
        page: parsedPage,
        limit: parsedLimit,
      },
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[AUDIT_ROUTER] GET /audit-logs error:', msg);
    res.status(500).json({ success: false, error: 'Failed to query audit logs' });
  }
});

export default router;
