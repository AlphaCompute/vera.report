import { adminPollingHeaders } from '@/src/utils/adminPollingQuota';
import { forwardRetryAfter } from '@/lib/proxyRetryAfter';
import { sealTriageReference, openTriageReference } from '@/lib/triageReference';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { isAdmin } from '@/lib/roles';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * GET /api/admin/dashboard/reports
 *
 * Admin-gated proxy to the Express backend, which reads reports from MongoDB (the
 * source of record, carrying the Shroud score) and maps them to the dashboard
 * shape. The Next runtime holds no DB connection — Express owns Mongo.
 */
async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const searching = req.method === 'POST';
  res.setHeader('Cache-Control', 'no-store');
  if (searching && !isAdmin(admin.roles)) return res.status(403).json({ success: false, error: 'Admin access required' });
  if (searching && (typeof req.body?.query !== 'string' || !req.body.query.trim() || req.body.query.length > 128)) {
    return res.status(400).json({ success: false, error: 'Invalid search query' });
  }
  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Reports Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }

    const params = new URLSearchParams();
    if (typeof req.query.limit === 'string') params.append('limit', req.query.limit);
    if (typeof req.query.trackingId === 'string') params.append('trackingId', isAdmin(admin.roles) ? req.query.trackingId : openTriageReference(req.query.trackingId));

    const path = searching ? '/api/whistleblower/admin/reports/search' : `/api/whistleblower/admin/reports?${params.toString()}`;
    const method = searching ? 'POST' : 'GET';
    const response = await fetch(`${backendUrl}${path}`, {
      method,
      ...(searching ? { body: JSON.stringify({ query: req.body.query.trim() }) } : {}),
      redirect: 'error',
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret, ...adminPollingHeaders(admin.userId, method, path) },
      signal: AbortSignal.timeout(15000),
    });
    forwardRetryAfter(response, res);
    const statusCode = response.status;
    const data = await response.json();

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'report_list_view',
      endpoint: '/api/admin/dashboard/reports',
      method: req.method || 'GET',
      responseStatus: statusCode,
      details: {
        agentId: String(req.query.agentId ?? ''),
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    res.setHeader('Cache-Control', 'no-store');
    if (!isAdmin(admin.roles)) {
      // Explicit triage projection: backend additions must not silently expose
      // evidence, free text, location, or reporter contact to employees.
      if (!response.ok) return res.status(statusCode).json({ success: false, error: 'Failed to fetch reports' });
      const reports = Array.isArray(data?.data?.reports) ? data.data.reports : [];
      const triageReports = reports.map((report: any) => {
        const reference = sealTriageReference(report.trackingId);
        return {
          _id: reference, reportId: reference, trackingId: reference,
          category: report.category, submittedAt: report.submittedAt,
          status: report.status, priority: report.priority, urgency: report.urgency,
          description: '', evidence: [], activity: [],
        };
      });
      return res.status(statusCode).json({ success: data.success, data: { reports: triageReports } });
    }
    return res.status(statusCode).json(data);
  } catch (error: unknown) {
    console.error('[Reports Proxy] Request failed');
    return res.status(502).json({
      success: false,
      error: { message: 'Failed to fetch reports from backend', code: 'REPORTS_FETCH_ERROR' },
    });
  }
}

export default withRoleAuth('employee', handler);
