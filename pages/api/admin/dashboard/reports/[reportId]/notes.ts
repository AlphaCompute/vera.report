import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth, type AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEventRequired } from '@/lib/auditClient';

async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  if (req.method !== 'GET' && req.method !== 'POST') return res.status(405).json({ success: false, error: 'Method not allowed' });
  const reportId = req.query.reportId;
  if (typeof reportId !== 'string' || !/^VRA-[A-F0-9]{16}$/.test(reportId)) return res.status(400).json({ success: false, error: 'Invalid report reference' });
  const text = req.body?.text;
  if (req.method === 'POST' && (typeof text !== 'string' || !text.trim() || text.trim().length > 5000)) {
    return res.status(400).json({ success: false, error: 'Enter a note of up to 5,000 characters' });
  }
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret) return res.status(503).json({ success: false, error: 'Backend not configured' });
  try {
    await logAuditEventRequired({
      adminUserId: admin.userId, adminEmail: admin.email,
      action: req.method === 'POST' ? 'report_note_add' : 'report_notes_view',
      endpoint: req.url || '', method: req.method, responseStatus: 0,
      details: { phase: 'attempted', resourceId: reportId },
    });
    const response = await fetch(`${process.env.BACKEND_URL || 'http://localhost:3001'}/api/whistleblower/admin/reports/${encodeURIComponent(reportId)}/notes`, {
      method: req.method,
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': secret },
      ...(req.method === 'POST' ? { body: JSON.stringify({ text: text.trim(), authorId: admin.userId }) } : {}),
      signal: AbortSignal.timeout(15000),
    });
    return res.status(response.status).json(await response.json());
  } catch {
    return res.status(502).json({ success: false, error: 'Notes are unavailable. Please try again.' });
  }
}

export default withRoleAuth('admin', handler);
