import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { confidentialListingBackend } from '../listings';

async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ success: false });
  const body = req.body;
  if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '') || Object.keys(req.query).length ||
      !body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join(',') !== 'caseId,hidden' ||
      typeof body.caseId !== 'string' || !/^[a-f0-9]{64}$/.test(body.caseId) || typeof body.hidden !== 'boolean') {
    return res.status(400).json({ success: false });
  }
  const backend = confidentialListingBackend();
  if (!backend) return res.status(503).json({ success: false });
  try {
    // Actor always comes from the verified admin session, never the browser.
    const response = await fetch(`${backend.url}/api/admin/confidential/listings/moderation`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': backend.secret },
      body: JSON.stringify({ caseId: body.caseId, hidden: body.hidden, actor: admin.email }),
    });
    return res.status(response.ok ? 200 : response.status >= 500 ? 503 : response.status).json({ success: response.ok });
  } catch { return res.status(503).json({ success: false }); }
}
export default withRoleAuth('admin', handler);
