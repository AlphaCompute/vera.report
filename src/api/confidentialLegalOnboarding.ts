import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import type { Request, RequestHandler, Response } from 'express';
import { requireInternalSecret } from '../middleware/internalSecret';
import {
  LEGAL_AUDIT_PAGE_MAX, LEGAL_INVITATION_ID, LEGAL_ORGANIZATION_ID, LEGAL_SUBJECT, auditCursor, legalConflictCode,
  parseAuditCursor, projectLegalAuditEvent, projectLegalInvitation, projectLegalMember, projectLegalOrganization,
  validActor, validateNewLegalOrganization,
} from '../utils/legalOnboarding';
import type { LegalOnboardingErrorCode, LegalOrganizationPreparationSource } from '../utils/legalOnboarding';

/** The confidential store's admin onboarding surface (MongoConfidentialCaseStore).
 * None of these methods is on the enclave storage RPC allowlist. */
export interface LegalOnboardingSource extends LegalOrganizationPreparationSource {
  listLegalOrganizationRecords(): Promise<unknown[]>;
  countLegalOnboarding(now: number): Promise<Record<string, { pendingInvitations: number; activeMembers: number }>>;
  listLegalInvitationRecords(organizationId: string): Promise<unknown[]>;
  listLegalMemberRecords(organizationId: string): Promise<unknown[]>;
  revokeLegalInvitation(invitationId: string, actor: string, now: number): Promise<void>;
  revokeLegalOrganization(organizationId: string, actor: string, now: number): Promise<{ invitationsRevoked: number; membersRemoved: number }>;
  removeLegalMember(organizationId: string, subject: string, actor: string, now: number): Promise<void>;
  listLegalAudit(input: { organizationId?: string; before?: { at: number; id: string }; limit: number }): Promise<unknown[]>;
}

const invalid = (res: Response, fields?: Record<string, string>) =>
  res.status(400).json({ success: false, error: 'Invalid request', ...(fields ? { fields } : {}) });
const conflict = (res: Response, code: LegalOnboardingErrorCode) =>
  res.status(code === 'not-found' ? 404 : 409).json({ success: false, error: code });
const unavailable = (res: Response) => res.status(503).json({ success: false, error: 'Legal onboarding temporarily unavailable' });
const param = (req: Request, name: string, pattern: RegExp): string | null => {
  const value = req.params[name];
  return typeof value === 'string' && pattern.test(value) ? value : null;
};
const noQuery = (req: Request) => Object.keys(req.query).length === 0;
const exactBody = (req: Request, fields: string[]) => {
  const body = req.body;
  return !!body && typeof body === 'object' && !Array.isArray(body) &&
    Object.keys(body).sort().join(',') === [...fields].sort().join(',');
};

/** /api/admin/confidential/legal/*
 * Reached only through the Next admin proxy (Auth0 admin role, audit-logged); the
 * internal secret is defense in depth. Roster metadata only: no route reads or
 * returns a case, grant, access request or message, and none can approve a firm
 * key. Registration and invitations need the separate onboarding identity and the
 * onboarding authority key inside the enclave; this host surface can only create
 * an unapproved record and revoke. Errors never echo store details, and nothing
 * here logs identifiers. */
export function createConfidentialLegalOnboardingRouter(source: () => Promise<LegalOnboardingSource>, clock: () => number = Date.now,
  guard: RequestHandler = requireInternalSecret) {
  const router = Router();
  router.use(guard);
  const handle = (work: (req: Request, res: Response) => Promise<unknown>) => async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    try { await work(req, res); } catch (error) {
      const code = legalConflictCode(error);
      if (code) { conflict(res, code); return; }
      unavailable(res);
    }
  };

  router.get('/organizations', handle(async (req, res) => {
    if (!noQuery(req)) return invalid(res);
    const store = await source(), now = clock();
    const [rows, counts] = await Promise.all([store.listLegalOrganizationRecords(), store.countLegalOnboarding(now)]);
    const organizations = rows.flatMap(row => {
      const projected = projectLegalOrganization(row);
      if (!projected) return [];
      const tally = counts[projected.organizationId] ?? { pendingInvitations: 0, activeMembers: 0 };
      return [{ ...projected, pendingInvitations: projected.status === 'revoked' ? 0 : tally.pendingInvitations,
        activeMembers: projected.status === 'revoked' ? 0 : tally.activeMembers }];
    });
    res.json({ success: true, organizations });
  }));

  router.post('/organizations', handle(async (req, res) => {
    if (!noQuery(req) || !exactBody(req, ['displayName', 'domain', 'providerOrganizationId', 'actor'])) return invalid(res);
    const { actor: rawActor, ...fields } = req.body;
    const actor = validActor(rawActor), checked = validateNewLegalOrganization(fields);
    if (!actor) return invalid(res);
    if (!checked.ok) return invalid(res, checked.errors as Record<string, string>);
    const organizationId = randomBytes(32).toString('hex');
    await (await source()).createLegalOrganization({ organizationId, ...checked.value }, actor, clock());
    const created = projectLegalOrganization(await (await source()).getLegalOrganizationRecord(organizationId));
    if (!created) return unavailable(res);
    res.status(201).json({ success: true, organization: created });
  }));

  router.get('/organizations/:organizationId', handle(async (req, res) => {
    const organizationId = param(req, 'organizationId', LEGAL_ORGANIZATION_ID);
    if (!noQuery(req) || !organizationId) return invalid(res);
    const store = await source(), now = clock();
    const row = await store.getLegalOrganizationRecord(organizationId);
    if (!row) return conflict(res, 'not-found');
    const [invitationRows, memberRows, counts] = await Promise.all([store.listLegalInvitationRecords(organizationId),
      store.listLegalMemberRecords(organizationId), store.countLegalOnboarding(now)]);
    const organization = projectLegalOrganization(row);
    if (!organization) return unavailable(res);
    const tally = organization.status === 'revoked' ? undefined : counts[organizationId];
    res.json({ success: true,
      organization: { ...organization, pendingInvitations: tally?.pendingInvitations ?? 0, activeMembers: tally?.activeMembers ?? 0 },
      invitations: invitationRows.flatMap(item => { const view = projectLegalInvitation(item, now); return view ? [view] : []; }),
      members: memberRows.flatMap(item => { const view = projectLegalMember(item, now); return view ? [view] : []; }) });
  }));

  router.post('/organizations/:organizationId/revoke', handle(async (req, res) => {
    const organizationId = param(req, 'organizationId', LEGAL_ORGANIZATION_ID), actor = validActor(req.body?.actor);
    if (!noQuery(req) || !organizationId || !exactBody(req, ['actor']) || !actor) return invalid(res);
    const result = await (await source()).revokeLegalOrganization(organizationId, actor, clock());
    res.json({ success: true, invitationsRevoked: result.invitationsRevoked, membersRemoved: result.membersRemoved });
  }));

  router.post('/organizations/:organizationId/members/remove', handle(async (req, res) => {
    const organizationId = param(req, 'organizationId', LEGAL_ORGANIZATION_ID), actor = validActor(req.body?.actor), subject = req.body?.subject;
    if (!noQuery(req) || !organizationId || !exactBody(req, ['actor', 'subject']) || !actor ||
        typeof subject !== 'string' || !LEGAL_SUBJECT.test(subject)) return invalid(res);
    await (await source()).removeLegalMember(organizationId, subject, actor, clock());
    res.json({ success: true });
  }));

  router.post('/invitations/:invitationId/revoke', handle(async (req, res) => {
    const invitationId = param(req, 'invitationId', LEGAL_INVITATION_ID), actor = validActor(req.body?.actor);
    if (!noQuery(req) || !invitationId || !exactBody(req, ['actor']) || !actor) return invalid(res);
    await (await source()).revokeLegalInvitation(invitationId, actor, clock());
    res.json({ success: true });
  }));

  router.get('/audit', handle(async (req, res) => {
    const { organizationId, before, limit: rawLimit, ...rest } = req.query;
    const limit = rawLimit === undefined ? 50 : Number(rawLimit);
    const cursor = before === undefined ? undefined : parseAuditCursor(before);
    if (Object.keys(rest).length || !Number.isSafeInteger(limit) || limit < 1 || limit > LEGAL_AUDIT_PAGE_MAX || cursor === null ||
        (organizationId !== undefined && (typeof organizationId !== 'string' || !LEGAL_ORGANIZATION_ID.test(organizationId)))) {
      return invalid(res);
    }
    const rows = await (await source()).listLegalAudit({ ...(organizationId ? { organizationId: organizationId as string } : {}),
      ...(cursor ? { before: cursor } : {}), limit: limit + 1 });
    const events = rows.flatMap(row => { const view = projectLegalAuditEvent(row); return view ? [view] : []; });
    const page = events.slice(0, limit);
    res.json({ success: true, events: page, next: rows.length > limit && page.length ? auditCursor(page[page.length - 1]) : null });
  }));

  return router;
}
