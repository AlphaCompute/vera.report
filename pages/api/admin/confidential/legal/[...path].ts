import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEvent } from '@/lib/auditClient';
import type { AdminAction } from '@/lib/auditClient';
import { forwardRetryAfter } from '@/lib/proxyRetryAfter';
import { confidentialListingBackend } from '../listings';
import {
  LEGAL_AUDIT_PAGE_MAX, LEGAL_INVITATION_ID, LEGAL_ONBOARDING_ERRORS, LEGAL_ORGANIZATION_ID, LEGAL_SUBJECT,
  parseAuditCursor, projectLegalAuditPage, projectLegalOrganization, projectLegalOrganizationDetail,
  projectLegalOrganizationList, validateNewLegalOrganization,
} from '@/src/utils/legalOnboarding';

/**
 * /api/admin/confidential/legal/* — admin onboarding of legal organizations.
 *
 * Admin role only. A fixed route table: each entry names the method, the path
 * shape, the audit action, the exact body sent to the backend and the projection
 * applied to the reply. The browser never chooses the backend path, the actor or
 * extra fields. Replies carry roster metadata only (names, domains, public keys,
 * invitations, member leases, audit events): no case, grant, request or message
 * exists on this surface. Mutations require a JSON body so a cross-site form post
 * cannot reach them. Audit entries record the organization or invitation ID only.
 */
type Route = {
  method: 'GET' | 'POST';
  pattern: RegExp;
  action: AdminAction;
  /** Backend body built from the validated request; null rejects with 400. */
  body?: (req: NextApiRequest, admin: AdminIdentityWithRoles, match: RegExpExecArray) => Record<string, unknown> | { invalid: Record<string, string> } | null;
  query?: (req: NextApiRequest) => URLSearchParams | null;
  project: (data: unknown, now: number) => Record<string, unknown> | null;
};
const ORG = LEGAL_ORGANIZATION_ID.source.slice(1, -1), INVITE = LEGAL_INVITATION_ID.source.slice(1, -1);
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const emptyBody = (req: NextApiRequest) => req.body === undefined || (isObject(req.body) && Object.keys(req.body).length === 0);

const ROUTES: Route[] = [
  { method: 'GET', pattern: /^organizations$/, action: 'legal_onboarding_view',
    project: data => ({ organizations: projectLegalOrganizationList(data) }) },
  { method: 'POST', pattern: /^organizations$/, action: 'legal_organization_create',
    body: (req, admin) => {
      const checked = validateNewLegalOrganization(req.body);
      return checked.ok ? { ...checked.value, actor: admin.email } : { invalid: checked.errors as Record<string, string> };
    },
    project: data => {
      const organization = isObject(data) ? projectLegalOrganization(data.organization) : null;
      return organization ? { organization } : null;
    } },
  { method: 'GET', pattern: new RegExp(`^organizations/(${ORG})$`), action: 'legal_onboarding_view',
    project: (data, now) => projectLegalOrganizationDetail(data, now) },
  { method: 'POST', pattern: new RegExp(`^organizations/(${ORG})/revoke$`), action: 'legal_organization_revoke',
    body: (req, admin) => emptyBody(req) ? { actor: admin.email } : null,
    project: data => isObject(data) ? { invitationsRevoked: Number(data.invitationsRevoked) || 0, membersRemoved: Number(data.membersRemoved) || 0 } : {} },
  { method: 'POST', pattern: new RegExp(`^organizations/(${ORG})/members/remove$`), action: 'legal_member_remove',
    body: (req, admin) => isObject(req.body) && Object.keys(req.body).join(',') === 'subject' &&
      typeof req.body.subject === 'string' && LEGAL_SUBJECT.test(req.body.subject) ? { subject: req.body.subject, actor: admin.email } : null,
    project: () => ({}) },
  { method: 'POST', pattern: new RegExp(`^invitations/(${INVITE})/revoke$`), action: 'legal_invitation_revoke',
    body: (req, admin) => emptyBody(req) ? { actor: admin.email } : null,
    project: () => ({}) },
  { method: 'GET', pattern: /^audit$/, action: 'legal_onboarding_view',
    query: req => {
      const { organizationId, before, limit, path: _path, ...rest } = req.query;
      if (Object.keys(rest).length) return null;
      const params = new URLSearchParams();
      if (organizationId !== undefined) {
        if (typeof organizationId !== 'string' || !LEGAL_ORGANIZATION_ID.test(organizationId)) return null;
        params.set('organizationId', organizationId);
      }
      if (before !== undefined) {
        if (!parseAuditCursor(before)) return null;
        params.set('before', before as string);
      }
      if (limit !== undefined) {
        const value = Number(limit);
        if (typeof limit !== 'string' || !/^[1-9][0-9]{0,2}$/.test(limit) || value > LEGAL_AUDIT_PAGE_MAX) return null;
        params.set('limit', limit);
      }
      return params;
    },
    project: data => projectLegalAuditPage(data) },
];

function onlyPathQuery(req: NextApiRequest): boolean {
  return Object.keys(req.query).every(key => key === 'path');
}

async function handler(req: NextApiRequest, res: NextApiResponse, admin: AdminIdentityWithRoles) {
  res.setHeader('Cache-Control', 'no-store');
  const segments = Array.isArray(req.query.path) ? req.query.path : [];
  const path = segments.join('/');
  const candidates = ROUTES.filter(route => route.pattern.test(path));
  if (!candidates.length) return res.status(404).json({ success: false, error: 'Not found' });
  const route = candidates.find(item => item.method === req.method);
  if (!route) {
    res.setHeader('Allow', candidates.map(item => item.method).join(', '));
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }
  const match = route.pattern.exec(path)!;
  let query: URLSearchParams | null = new URLSearchParams();
  if (route.query) query = route.query(req);
  else if (!onlyPathQuery(req)) query = null;
  if (!query) return res.status(400).json({ success: false, error: 'Invalid request' });

  let body: Record<string, unknown> | undefined;
  if (route.method === 'POST') {
    const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') return res.status(415).json({ success: false, error: 'JSON body required' });
    const built = route.body?.(req, admin, match) ?? null;
    if (!built) return res.status(400).json({ success: false, error: 'Invalid request' });
    if ('invalid' in built && isObject(built.invalid)) return res.status(400).json({ success: false, error: 'Invalid request', fields: built.invalid });
    body = built;
  }

  // Same backend selection as the listings proxy: the confidential-only task with
  // its own secret in the dedicated layout, otherwise the legacy API.
  const backend = confidentialListingBackend();
  if (!backend) {
    console.error('[Legal Onboarding Proxy] backend secret not configured');
    return res.status(500).json({ success: false, error: 'Backend not configured' });
  }
  const internalSecret = backend.secret;
  const pathname = `/api/admin/confidential/legal/${path}`;
  const search = query.toString();
  let status = 502;
  try {
    const response = await fetch(`${backend.url}${pathname}${search ? `?${search}` : ''}`, {
      method: route.method,
      redirect: 'error',
      headers: { 'Content-Type': 'application/json', 'x-internal-secret': internalSecret },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(15000),
    });
    status = response.status;
    forwardRetryAfter(response, res);
    const data = await response.json().catch(() => null);
    const code = isObject(data) && typeof data.error === 'string' &&
      Object.prototype.hasOwnProperty.call(LEGAL_ONBOARDING_ERRORS, data.error) ? data.error : null;
    // A 404 without a known code means the confidential routes are not mounted.
    if (response.status === 404 && !code) return res.status(404).json({ success: false, error: 'not-enabled' });
    if (response.status === 400) {
      const fields = isObject(data) && isObject(data.fields) ? Object.fromEntries(Object.entries(data.fields)
        .filter(([key, value]) => ['displayName', 'domain', 'providerOrganizationId'].includes(key) && typeof value === 'string')) : undefined;
      return res.status(400).json({ success: false, error: 'Invalid request', ...(fields && Object.keys(fields).length ? { fields } : {}) });
    }
    if (response.status === 404 || response.status === 409) {
      return res.status(response.status).json({ success: false, error: code ?? 'not-found' });
    }
    if (!response.ok) return res.status(response.status === 429 ? 429 : 503).json({ success: false, error: 'Legal onboarding unavailable' });
    const projected = route.project(data, Date.now());
    if (!projected) { status = 502; return res.status(502).json({ success: false, error: 'Legal onboarding unavailable' }); }
    return res.status(response.status === 201 ? 201 : 200).json({ success: true, ...projected });
  } catch {
    console.error('[Legal Onboarding Proxy] Request failed');
    return res.status(502).json({ success: false, error: 'Legal onboarding unavailable' });
  } finally {
    const resourceId = match[1];
    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: route.action,
      // Fixed route family; identifiers go only into resourceId.
      endpoint: `/api/admin/confidential/legal/${path.split('/')[0]}`,
      method: route.method,
      responseStatus: status,
      details: {
        ...(resourceId ? { resourceId } : {}),
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });
  }
}

export default withRoleAuth('admin', handler);
