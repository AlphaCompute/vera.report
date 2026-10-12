const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler,
} }));
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name, roles: user['https://vera.app/roles'] ?? [],
  }),
}));

import express from 'express';
import request from 'supertest';
import { createConfidentialLegalOnboardingRouter } from '../../../src/api/confidentialLegalOnboarding';
import type { LegalOnboardingSource } from '../../../src/api/confidentialLegalOnboarding';
import { LegalOnboardingConflict, projectLegalOrganizationDetail } from '../../../src/utils/legalOnboarding';
import legalProxy from '../../../pages/api/admin/confidential/legal/[...path]';

const SECRET = 'synthetic-legal-onboarding-secret';
const hex = (n: number) => n.toString(16).padStart(64, '0');
const ORG = hex(0xa1), INVITE = hex(0xb2), NOW = 1_800_000_000_000;
const PUBLIC_KEY = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----\n';
const SENTINELS = ['TOKEN-DIGEST-SENTINEL', 'NONCE-SENTINEL', 'AUTHORIZATION-SENTINEL', 'PROOF-SENTINEL', 'CASE-SENTINEL'];

function row(overrides: Record<string, unknown> = {}) {
  return { _id: ORG, displayName: 'Harbor Counsel LLP', domain: 'harbor.example', publicKey: PUBLIC_KEY, approved: true,
    providerOrganizationId: 'org_harbor', recipientKeyId: hex(0xc3), registration: 'AUTHORIZATION-SENTINEL',
    createdAt: new Date(NOW - 5000), createdBy: 'admin@example.org', registeredAt: new Date(NOW - 4000), updatedAt: new Date(NOW),
    caseIds: ['CASE-SENTINEL'], ...overrides };
}
function source(): jest.Mocked<LegalOnboardingSource> {
  return {
    createLegalOrganization: jest.fn(async () => {}),
    listLegalOrganizationRecords: jest.fn(async () => [row(), row({ _id: hex(0xa2), revokedAt: new Date(NOW), approved: false, domain: 'old.example' }),
      { _id: 'not-an-id', displayName: 'Broken', domain: 'broken.example' }]),
    getLegalOrganizationRecord: jest.fn(async () => row()),
    countLegalOnboarding: jest.fn(async () => ({ [ORG]: { pendingInvitations: 2, activeMembers: 1 }, [hex(0xa2)]: { pendingInvitations: 9, activeMembers: 9 } })),
    listLegalInvitationRecords: jest.fn(async () => [
      { invitationId: INVITE, organizationId: ORG, subject: 'auth0|lawyer', createdAt: NOW - 1000, createdBy: 'auth0|operator',
        expiresAt: NOW + 1000, state: 'pending', tokenDigest: 'TOKEN-DIGEST-SENTINEL', nonce: 'NONCE-SENTINEL', authorization: 'AUTHORIZATION-SENTINEL' },
      { invitationId: hex(0xb3), organizationId: ORG, subject: 'auth0|old', createdAt: NOW - 9000, createdBy: 'auth0|operator',
        expiresAt: NOW - 1, state: 'pending' }]),
    listLegalMemberRecords: jest.fn(async () => [
      { subject: 'auth0|lawyer', active: true, leaseExpiresAt: NOW + 1000, updatedAt: new Date(NOW), proof: 'PROOF-SENTINEL' },
      { subject: 'auth0|gone', active: false, leaseExpiresAt: NOW + 1000, updatedAt: new Date(NOW) },
      { subject: 'auth0|stale', active: true, leaseExpiresAt: NOW + 1000, updatedAt: new Date(NOW), keyReplaced: true }]),
    revokeLegalInvitation: jest.fn(async () => {}),
    revokeLegalOrganization: jest.fn(async () => ({ invitationsRevoked: 2, membersRemoved: 1 })),
    removeLegalMember: jest.fn(async () => {}),
    listLegalAudit: jest.fn(async () => [
      { _id: 'e'.repeat(32), at: new Date(NOW), action: 'invitation_issued', organizationId: ORG, actor: 'auth0|operator', invitationId: INVITE, subject: 'auth0|lawyer' },
      { _id: 'd'.repeat(32), at: new Date(NOW - 1), action: 'organization_created', organizationId: ORG, actor: 'admin@example.org' },
      { _id: 'c'.repeat(32), at: new Date(NOW - 2), action: 'case_opened', organizationId: ORG, actor: 'x', caseId: 'CASE-SENTINEL' }]),
  };
}

describe('Express legal onboarding router', () => {
  let store: jest.Mocked<LegalOnboardingSource>;
  const app = express();
  app.use(express.json());
  app.use('/api/admin/confidential/legal', createConfidentialLegalOnboardingRouter(async () => store, () => NOW));
  const get = (path: string) => request(app).get(`/api/admin/confidential/legal/${path}`).set('x-internal-secret', SECRET);
  const post = (path: string, body: unknown) => request(app).post(`/api/admin/confidential/legal/${path}`).set('x-internal-secret', SECRET).send(body as object);
  beforeEach(() => { process.env.INTERNAL_API_SECRET = SECRET; store = source(); });

  it('requires the internal secret on every route', async () => {
    for (const [method, path] of [['get', 'organizations'], ['post', 'organizations'], ['get', `organizations/${ORG}`],
      ['post', `organizations/${ORG}/revoke`], ['post', `invitations/${INVITE}/revoke`], ['get', 'audit']] as const) {
      await request(app)[method](`/api/admin/confidential/legal/${path}`).expect(401);
    }
    expect(store.listLegalOrganizationRecords).not.toHaveBeenCalled();
    expect(store.revokeLegalOrganization).not.toHaveBeenCalled();
  });

  it('lists organizations with statuses and counts, dropping malformed rows and every non-roster field', async () => {
    const response = await get('organizations').expect(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body.organizations).toEqual([
      expect.objectContaining({ organizationId: ORG, status: 'active', pendingInvitations: 2, activeMembers: 1, recipientKeyId: hex(0xc3), publicKey: PUBLIC_KEY }),
      expect.objectContaining({ organizationId: hex(0xa2), status: 'revoked', pendingInvitations: 0, activeMembers: 0 }),
    ]);
    expect(JSON.stringify(response.body)).not.toMatch(new RegExp(SENTINELS.join('|')));
  });

  it('creates an organization with a server-generated ID and validates every field', async () => {
    const response = await post('organizations', { displayName: '  Harbor   Counsel LLP ', domain: 'https://Harbor.Example/',
      providerOrganizationId: 'org_harbor', actor: 'admin@example.org' }).expect(201);
    const [value, actor] = store.createLegalOrganization.mock.calls[0];
    expect(value).toEqual({ organizationId: expect.stringMatching(/^[a-f0-9]{64}$/), displayName: 'Harbor Counsel LLP',
      domain: 'harbor.example', providerOrganizationId: 'org_harbor' });
    expect(actor).toBe('admin@example.org');
    expect(store.getLegalOrganizationRecord).toHaveBeenCalledWith(value.organizationId);
    expect(response.body.organization.organizationId).toBe(ORG);

    const invalid = await post('organizations', { displayName: 'x', domain: 'not a domain', providerOrganizationId: 'harbor', actor: 'a@b.c' }).expect(400);
    expect(Object.keys(invalid.body.fields).sort()).toEqual(['displayName', 'domain', 'providerOrganizationId']);
    await post('organizations', { displayName: 'Harbor', domain: 'harbor.example', providerOrganizationId: 'org_x', actor: 'a@b.c', organizationId: ORG }).expect(400);
    await post('organizations', { displayName: 'Harbor', domain: 'harbor.example', providerOrganizationId: 'org_x' }).expect(400);
    expect(store.createLegalOrganization).toHaveBeenCalledTimes(1);
  });

  it('maps store conflicts to stable codes and hides store errors', async () => {
    store.createLegalOrganization.mockRejectedValueOnce(new LegalOnboardingConflict('duplicate-domain'));
    const conflict = await post('organizations', { displayName: 'Harbor', domain: 'harbor.example', providerOrganizationId: 'org_x', actor: 'a@b.c' }).expect(409);
    expect(conflict.body).toEqual({ success: false, error: 'duplicate-domain' });
    store.revokeLegalInvitation.mockRejectedValueOnce(new LegalOnboardingConflict('not-found'));
    expect((await post(`invitations/${INVITE}/revoke`, { actor: 'a@b.c' }).expect(404)).body.error).toBe('not-found');
    store.listLegalOrganizationRecords.mockRejectedValueOnce(new Error(`mongo detail ${ORG} TOKEN-DIGEST-SENTINEL`));
    const failed = await get('organizations').expect(503);
    expect(JSON.stringify(failed.body)).not.toMatch(/mongo|TOKEN-DIGEST|a1a1/);
  });

  it('returns organization detail with derived invitation and member statuses only', async () => {
    const response = await get(`organizations/${ORG}`).expect(200);
    expect(response.body.invitations).toEqual([
      { invitationId: INVITE, subject: 'auth0|lawyer', createdAt: NOW - 1000, createdBy: 'auth0|operator', expiresAt: NOW + 1000, status: 'pending', revokedAt: null, revokedBy: null },
      expect.objectContaining({ subject: 'auth0|old', status: 'expired' }),
    ]);
    expect(response.body.members).toEqual([
      { subject: 'auth0|lawyer', status: 'active', accessUntil: NOW + 1000, updatedAt: NOW },
      { subject: 'auth0|gone', status: 'removed', accessUntil: NOW + 1000, updatedAt: NOW },
      // Enrolled with a key the organization replaced: the enclave denies them, so never shown as active.
      { subject: 'auth0|stale', status: 'key-replaced', accessUntil: NOW + 1000, updatedAt: NOW },
    ]);
    // The browser-side re-projection keeps the status.
    expect(projectLegalOrganizationDetail(response.body, NOW)?.members.map(member => member.status))
      .toEqual(['active', 'removed', 'key-replaced']);
    expect(JSON.stringify(response.body)).not.toMatch(new RegExp(SENTINELS.join('|')));
    store.getLegalOrganizationRecord.mockResolvedValueOnce(null);
    await get(`organizations/${hex(9)}`).expect(404);
    await get('organizations/VERA-OWNER-1.abc').expect(400);
    await get(`organizations/${ORG}?caseId=${hex(1)}`).expect(400);
  });

  it('revokes organizations, invitations and members with the proxy-supplied actor only', async () => {
    expect((await post(`organizations/${ORG}/revoke`, { actor: 'admin@example.org' }).expect(200)).body)
      .toEqual({ success: true, invitationsRevoked: 2, membersRemoved: 1 });
    expect(store.revokeLegalOrganization).toHaveBeenCalledWith(ORG, 'admin@example.org', NOW);
    await post(`invitations/${INVITE}/revoke`, { actor: 'admin@example.org' }).expect(200);
    expect(store.revokeLegalInvitation).toHaveBeenCalledWith(INVITE, 'admin@example.org', NOW);
    await post(`organizations/${ORG}/members/remove`, { actor: 'admin@example.org', subject: 'auth0|lawyer' }).expect(200);
    expect(store.removeLegalMember).toHaveBeenCalledWith(ORG, 'auth0|lawyer', 'admin@example.org', NOW);
    await post(`organizations/${ORG}/revoke`, {}).expect(400);
    await post(`organizations/${ORG}/revoke`, { actor: 'a@b.c', force: true }).expect(400);
    await post(`organizations/${ORG}/members/remove`, { actor: 'a@b.c', subject: 'not a subject' }).expect(400);
    await post(`invitations/nope/revoke`, { actor: 'a@b.c' }).expect(400);
    expect(store.revokeLegalOrganization).toHaveBeenCalledTimes(1);
  });

  it('pages the audit trail with a cursor and drops unknown event kinds', async () => {
    const response = await get(`audit?organizationId=${ORG}&limit=1`).expect(200);
    expect(store.listLegalAudit).toHaveBeenCalledWith({ organizationId: ORG, limit: 2 });
    expect(response.body.events).toEqual([{ eventId: 'e'.repeat(32), at: NOW, action: 'invitation_issued', organizationId: ORG,
      actor: 'auth0|operator', invitationId: INVITE, subject: 'auth0|lawyer' }]);
    expect(response.body.next).toBe(`${NOW}_${'e'.repeat(32)}`);
    await get(`audit?before=${NOW}_${'e'.repeat(32)}`).expect(200);
    expect(store.listLegalAudit).toHaveBeenLastCalledWith({ before: { at: NOW, id: 'e'.repeat(32) }, limit: 51 });
    const all = await get('audit').expect(200);
    expect(all.body.events.map((event: { action: string }) => event.action)).toEqual(['invitation_issued', 'organization_created']);
    expect(JSON.stringify(all.body)).not.toContain('CASE-SENTINEL');
    for (const query of ['limit=0', 'limit=101', 'before=abc', 'organizationId=xyz', 'caseId=1']) await get(`audit?${query}`).expect(400);
  });
});

describe('Next admin proxy', () => {
  let saved: NodeJS.ProcessEnv;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;
  let backendReply: () => Response;
  const res = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() });
  const session = (roles: string[]) => ({ user: { sub: 'auth0|admin', email: 'qa@example.org', email_verified: true,
    org_id: 'org_test', 'https://vera.app/roles': roles } });
  const call = async (method: string, path: string[], options: { body?: unknown; query?: Record<string, string>; type?: string } = {}) => {
    const response = res();
    await legalProxy({ method, query: { path, ...options.query }, body: options.body,
      headers: { 'content-type': options.type ?? 'application/json' }, socket: {} } as any, response as any);
    return response;
  };
  const backendCalls = () => fetchSpy.mock.calls.filter(([url]) => !String(url).endsWith('/audit-log'));
  const auditEntries = () => fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/audit-log'))
    .map(([, init]) => JSON.parse(String(init!.body)));
  beforeEach(() => {
    saved = { ...process.env };
    Object.assign(process.env, { INTERNAL_API_SECRET: SECRET, BACKEND_URL: 'http://synthetic.invalid',
      ADMIN_ALLOWED_DOMAINS: '@example.org', TENANT_ORG_ID: 'org_test' });
    mockSession.mockResolvedValue(session(['admin']));
    backendReply = () => Response.json({ success: true, organizations: [{ ...row(), organizationId: ORG, status: 'active', tokenDigest: 'TOKEN-DIGEST-SENTINEL' }],
      caseIds: ['CASE-SENTINEL'] });
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async url => String(url).endsWith('/audit-log')
      ? Response.json({ success: true }) : backendReply());
  });
  afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

  it('denies employees before reaching the backend', async () => {
    mockSession.mockResolvedValue(session(['employee']));
    const denied = await call('GET', ['organizations']);
    expect(denied.status).toHaveBeenCalledWith(403);
    const revoke = await call('POST', ['organizations', ORG, 'revoke'], { body: {} });
    expect(revoke.status).toHaveBeenCalledWith(403);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('re-projects the roster and audit-logs the view without roster content', async () => {
    const response = await call('GET', ['organizations']);
    expect(response.status).toHaveBeenCalledWith(200);
    const body = response.json.mock.calls[0][0];
    expect(body.organizations).toHaveLength(1);
    expect(JSON.stringify(body)).not.toMatch(new RegExp(SENTINELS.join('|')));
    expect(String(backendCalls()[0][0])).toBe('http://synthetic.invalid/api/admin/confidential/legal/organizations');
    expect(auditEntries()).toEqual([expect.objectContaining({ action: 'legal_onboarding_view', endpoint: '/api/admin/confidential/legal/organizations' })]);
  });

  it('sets the actor from the verified session and ignores a client-supplied one', async () => {
    backendReply = () => Response.json({ success: true, organization: { ...row(), organizationId: ORG } }, { status: 201 });
    const response = await call('POST', ['organizations'], { body: { displayName: 'Harbor Counsel', domain: 'harbor.example',
      providerOrganizationId: 'org_harbor' } });
    expect(response.status).toHaveBeenCalledWith(201);
    expect(JSON.parse(String(backendCalls()[0][1]!.body))).toEqual({ displayName: 'Harbor Counsel', domain: 'harbor.example',
      providerOrganizationId: 'org_harbor', actor: 'qa@example.org' });
    const spoofed = await call('POST', ['organizations'], { body: { displayName: 'Harbor Counsel', domain: 'harbor.example',
      providerOrganizationId: 'org_harbor', actor: 'someone@else.example' } });
    expect(spoofed.status).toHaveBeenCalledWith(400);
    const revoke = await call('POST', ['organizations', ORG, 'revoke'], { body: { actor: 'someone@else.example' } });
    expect(revoke.status).toHaveBeenCalledWith(400);
    expect(backendCalls()).toHaveLength(1);
    expect(auditEntries().map(entry => entry.action)).toEqual(['legal_organization_create']);
  });

  it('forwards revocations with only the identifier in the audit entry', async () => {
    backendReply = () => Response.json({ success: true, invitationsRevoked: 3, membersRemoved: 2, caseIds: ['CASE-SENTINEL'] });
    const response = await call('POST', ['organizations', ORG, 'revoke'], { body: {} });
    expect(response.json.mock.calls[0][0]).toEqual({ success: true, invitationsRevoked: 3, membersRemoved: 2 });
    await call('POST', ['invitations', INVITE, 'revoke'], { body: {} });
    await call('POST', ['organizations', ORG, 'members', 'remove'], { body: { subject: 'auth0|lawyer' } });
    expect(backendCalls().map(([url, init]) => [String(url), JSON.parse(String(init!.body))])).toEqual([
      [`http://synthetic.invalid/api/admin/confidential/legal/organizations/${ORG}/revoke`, { actor: 'qa@example.org' }],
      [`http://synthetic.invalid/api/admin/confidential/legal/invitations/${INVITE}/revoke`, { actor: 'qa@example.org' }],
      [`http://synthetic.invalid/api/admin/confidential/legal/organizations/${ORG}/members/remove`, { subject: 'auth0|lawyer', actor: 'qa@example.org' }],
    ]);
    const entries = auditEntries();
    expect(entries.map(entry => [entry.action, entry.details.resourceId, entry.endpoint])).toEqual([
      ['legal_organization_revoke', ORG, '/api/admin/confidential/legal/organizations'],
      ['legal_invitation_revoke', INVITE, '/api/admin/confidential/legal/invitations'],
      ['legal_member_remove', ORG, '/api/admin/confidential/legal/organizations'],
    ]);
    expect(JSON.stringify(entries)).not.toContain('auth0|lawyer');
  });

  it('rejects unknown routes, wrong methods, non-JSON mutations and stray query parameters', async () => {
    expect((await call('GET', ['cases'])).status).toHaveBeenCalledWith(404);
    expect((await call('GET', ['organizations', 'VERA-OWNER-1.abc'])).status).toHaveBeenCalledWith(404);
    expect((await call('DELETE', ['organizations'])).status).toHaveBeenCalledWith(405);
    expect((await call('POST', ['organizations', ORG, 'revoke'], { body: {}, type: 'application/x-www-form-urlencoded' })).status).toHaveBeenCalledWith(415);
    expect((await call('GET', ['organizations'], { query: { caseId: hex(1) } })).status).toHaveBeenCalledWith(400);
    expect((await call('GET', ['audit'], { query: { limit: '500' } })).status).toHaveBeenCalledWith(400);
    expect(backendCalls()).toHaveLength(0);
  });

  it('passes conflicts through as known codes and reports a missing deployment', async () => {
    backendReply = () => Response.json({ success: false, error: 'duplicate-domain', detail: 'TOKEN-DIGEST-SENTINEL' }, { status: 409 });
    const conflict = await call('POST', ['organizations'], { body: { displayName: 'Harbor', domain: 'harbor.example', providerOrganizationId: 'org_harbor' } });
    expect(conflict.status).toHaveBeenCalledWith(409);
    expect(conflict.json.mock.calls[0][0]).toEqual({ success: false, error: 'duplicate-domain' });
    backendReply = () => new Response('Cannot GET', { status: 404 });
    const missing = await call('GET', ['organizations']);
    expect(missing.json.mock.calls[0][0]).toEqual({ success: false, error: 'not-enabled' });
    backendReply = () => Response.json({ success: false, error: 'boom' }, { status: 500 });
    expect((await call('GET', ['organizations'])).status).toHaveBeenCalledWith(503);
  });
});
