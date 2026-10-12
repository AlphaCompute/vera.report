import { logAuditEvent } from '@/lib/auditClient';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { legalApplicationRequest } from '@/lib/legalApplicationProxy';
import { LEGAL_PROVIDER_ORGANIZATION_ID } from '@/src/utils/legalOnboarding';
import { LEGAL_APPLICATION_ID } from '@/src/utils/legalApplications';
export const config = { api: { bodyParser: { sizeLimit: '8kb' } } };
export default withRoleAuth('admin', async (req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).end(); }
  if (String(req.headers['content-type'] || '').split(';')[0] !== 'application/json' || Object.keys(req.query).length ||
      !req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).end();
  const { action, id, status, before, providerOrganizationId, ...extra } = req.body;
  if (Object.keys(extra).length) return res.status(400).end();
  let body;
  if (action === 'list' && providerOrganizationId === undefined && id === undefined && status === undefined && (before === undefined || (typeof before === 'string' && LEGAL_APPLICATION_ID.test(before)))) body = before ? { before } : {};
  else if (action === 'decide' && before === undefined && typeof id === 'string' && LEGAL_APPLICATION_ID.test(id) && ['approved', 'denied'].includes(status) &&
    (providerOrganizationId === undefined || (status === 'approved' && typeof providerOrganizationId === 'string' && LEGAL_PROVIDER_ORGANIZATION_ID.test(providerOrganizationId))))
    body = { id, status, actor: admin.email, ...(providerOrganizationId ? { providerOrganizationId } : {}) };
  else return res.status(400).end();
  let responseStatus = 503;
  try {
    const result = await legalApplicationRequest(action, body);
    responseStatus = result.status;
    return res.status(result.status).json(result.data);
  } finally {
    if (action === 'decide') logAuditEvent({ adminUserId: admin.userId, adminEmail: admin.email,
      action: 'legal_application_decide', endpoint: '/api/admin/confidential/legal-applications', method: 'POST',
      responseStatus, details: { resourceId: id, newStatus: status } });
  }
});
