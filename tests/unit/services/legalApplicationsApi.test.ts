const mockAudit = jest.fn();
jest.mock('@/lib/auditClient', () => ({ logAuditEvent: (...args: unknown[]) => mockAudit(...args) }));
const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: { getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler } }));
jest.mock('@/lib/currentAdminAuthorization', () => ({ currentAdminAuthorization: async (user: Record<string, any>) => ({ userId: user.sub, email: user.email, roles: user['https://vera.app/roles'] ?? [] }) }));
const mockUpstream = jest.fn();
jest.mock('@/lib/legalApplicationProxy', () => ({ legalApplicationRequest: (...args: unknown[]) => mockUpstream(...args) }));
import express from 'express';
import { privateRequest } from '../../../src/utils/requestPrivacy';
import request from 'supertest';
import { createLegalApplicationsRouter } from '../../../src/api/legalApplications';
import adminProxy from '../../../pages/api/admin/confidential/legal-applications';
import publicProxy from '../../../pages/api/legal-applications';
import type { LegalApplications } from '../../../src/services/legalApplications';
import { InvalidFirmKeyBindingError } from '../../../src/utils/legalApplicationKey';
import { LegalApplicationIntakeClosedError, LegalProvisioningError } from '../../../src/utils/legalApplications';
const input = { displayName: 'Example Counsel', domain: 'firm.example', email: 'lawyer@firm.example', lawyerName: 'Test Lawyer', jurisdiction: 'Example', registrationNumber: 'TEST' };
const id = 'a'.repeat(64);
const res = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), end: jest.fn().mockReturnThis(), setHeader: jest.fn() });
describe('legal application authority boundaries', () => {
  const submit = jest.fn(), list = jest.fn(), decide = jest.fn(), approveAndPrepare = jest.fn(), decision = jest.fn();
  const onboarding = {} as any;
  const app = express();
  app.use(createLegalApplicationsRouter(async () => ({ submit, list, decide, approveAndPrepare, decision }) as unknown as LegalApplications,
    (req, response, next) => req.headers['x-test-authorized'] === 'yes' ? next() : void response.status(401).end(), async () => onboarding));
  beforeEach(() => {
    jest.clearAllMocks(); submit.mockResolvedValue(undefined); list.mockResolvedValue({ applications: [], next: null }); decide.mockResolvedValue(true); approveAndPrepare.mockResolvedValue(true); decision.mockResolvedValue(null);
    mockUpstream.mockResolvedValue({ status: 200, data: { success: true } });
    process.env.ADMIN_ALLOWED_DOMAINS = '@example.org'; process.env.TENANT_ORG_ID = 'org_test';
    mockSession.mockResolvedValue({ user: { sub: 'auth0|staff', email: 'staff@example.org', email_verified: true, org_id: 'org_test', 'https://vera.app/roles': ['admin'] } });
  });
  it('classifies applicant data and Slack callback routes as private', () => {
    expect(privateRequest('/api/legal-applications')).toBe(true);
    expect(privateRequest('/api/legal-applications/slack')).toBe(true);
  });
  it('requires internal authorization for every backend action before storage', async () => {
    for (const action of ['submit', 'list', 'decide', 'get', 'status', 'combined-approval']) await request(app).post('/' + action).send({}).expect(401);
    expect(submit).not.toHaveBeenCalled(); expect(list).not.toHaveBeenCalled(); expect(decide).not.toHaveBeenCalled();
  });
  it('rejects nonobject bodies and URL parameters and projects a bounded list', async () => {
    await request(app).post('/list').set('x-test-authorized', 'yes').send([]).expect(400);
    await request(app).post('/list').set('x-test-authorized', 'yes').type('form').send('before=x').expect(400);
    await request(app).post('/list?before=x').set('x-test-authorized', 'yes').send({}).expect(400);
    expect(list).not.toHaveBeenCalled();
    await request(app).post('/list').set('x-test-authorized', 'yes').send({}).expect(200);
    expect(list).toHaveBeenCalledWith(undefined);
  });
  it('accepts only public firm application fields and never permits submit to approve', async () => {
    await request(app).post('/submit').set('x-test-authorized', 'yes').send({ ...input, status: 'approved' }).expect(400);
    await request(app).post('/submit').set('x-test-authorized', 'yes').send(input).expect(202);
    expect(submit).toHaveBeenCalledWith(input); expect(decide).not.toHaveBeenCalled();
    const result = res();
    await publicProxy({ method: 'POST', headers: { 'content-type': 'application/json' }, query: {}, body: { ...input, action: 'decide' } } as any, result as any);
    expect(result.status).toHaveBeenCalledWith(400); expect(mockUpstream).not.toHaveBeenCalled();
  });
  it('forwards a per-client quota key so one applicant cannot exhaust everyone else', async () => {
    process.env.INTERNAL_API_SECRET = 'synthetic-internal-secret'; process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
    const submitFrom = async (address: string) => { const result = res();
      await publicProxy({ method: 'POST', headers: { 'content-type': 'application/json' }, query: {}, body: input, socket: { remoteAddress: address } } as any, result as any);
      return mockUpstream.mock.calls.at(-1)![2]['x-vera-application-client']; };
    const first = await submitFrom('203.0.113.1');
    expect(first).toMatch(/^[a-f0-9]{64}$/); expect(await submitFrom('203.0.113.2')).not.toBe(first);
    for (let i = 0; i < 20; i++) await request(app).post('/submit').set('x-test-authorized', 'yes').set('x-vera-application-client', first).send(input).expect(202);
    await request(app).post('/submit').set('x-test-authorized', 'yes').set('x-vera-application-client', first).send(input).expect(429);
    await request(app).post('/submit').set('x-test-authorized', 'yes').set('x-vera-application-client', 'b'.repeat(64)).send(input).expect(202);
  });
  it('distinguishes invalid public keys from unavailable storage without exposing diagnostics', async () => {
    submit.mockRejectedValueOnce(new InvalidFirmKeyBindingError());
    const invalid = await request(app).post('/submit').set('x-test-authorized', 'yes').send(input).expect(400);
    expect(invalid.body).toEqual({ error: 'Invalid application key', code: 'invalid-application-key' });
    submit.mockRejectedValueOnce(new Error('private storage detail'));
    const unavailable = await request(app).post('/submit').set('x-test-authorized', 'yes').send(input).expect(503);
    expect(unavailable.body).toEqual({ error: 'Application service unavailable' });
  });
  it('reports closed intake as a retryable refusal with a fixed public message', async () => {
    submit.mockRejectedValueOnce(new LegalApplicationIntakeClosedError('applications-closed'));
    const closed = await request(app).post('/submit').set('x-test-authorized', 'yes').send(input).expect(429);
    expect(closed.body).toEqual({ error: 'Applications are temporarily closed. Try again later.', code: 'applications-closed' });
    expect(closed.headers['retry-after']).toBe('3600');
    submit.mockRejectedValueOnce(new LegalApplicationIntakeClosedError('domain-applications-pending'));
    const domain = await request(app).post('/submit').set('x-test-authorized', 'yes').send(input).expect(429);
    // The per-domain cap is not distinguishable from outside.
    expect(domain.body).toEqual(closed.body);
  });
  it('rejects roster-unsafe characters at the public proxy before forwarding applicant data', async () => {
    for (const character of ['\u2028', '\u2029', '\u0085', '\u009f']) {
      const response = res();
      await publicProxy({ method: 'POST', headers: { 'content-type': 'application/json' }, query: {},
        body: { ...input, displayName: `Bad${character}Name` } } as any, response as any);
      expect(response.status).toHaveBeenCalledWith(400);
    }
    expect(mockUpstream).not.toHaveBeenCalled();
  });
  it('derives decision actor from an authenticated admin and rejects client actor injection', async () => {
    const req = { method: 'POST', headers: { 'content-type': 'application/json' }, query: {}, body: { action: 'decide', id, status: 'approved' }, socket: {} };
    const forged = res(); await adminProxy({ ...req, body: { ...req.body, actor: 'forged' } } as any, forged as any);
    expect(forged.status).toHaveBeenCalledWith(400); expect(mockUpstream).not.toHaveBeenCalled();
    await adminProxy(req as any, res() as any);
    expect(mockUpstream).toHaveBeenCalledWith('decide', { id, status: 'approved', actor: 'staff@example.org' });
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({ action: 'legal_application_decide', adminUserId: 'auth0|staff', responseStatus: 200, details: { resourceId: id, newStatus: 'approved' } }));
    mockUpstream.mockClear(); mockSession.mockResolvedValue(null);
    const denied = res(); await adminProxy(req as any, denied as any);
    expect(denied.status).toHaveBeenCalledWith(403); expect(mockUpstream).not.toHaveBeenCalled();
  });
  it('binds combined approval to an existing Auth0 organization and refuses provider fields on other actions', async () => {
    await request(app).post('/decide').set('x-test-authorized', 'yes')
      .send({ id, status: 'approved', actor: 'staff', providerOrganizationId: 'org_counsel' }).expect(200);
    expect(approveAndPrepare).toHaveBeenCalledWith(id, 'org_counsel', 'staff', onboarding);
    expect(decide).not.toHaveBeenCalled();
    for (const body of [{ status: 'denied', providerOrganizationId: 'org_counsel' }, { status: 'approved', providerOrganizationId: 'invalid' }]) {
      await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, actor: 'staff', ...body }).expect(400);
    }
    const req = { method: 'POST', headers: { 'content-type': 'application/json' }, query: {}, socket: {},
      body: { action: 'decide', id, status: 'approved', providerOrganizationId: 'org_counsel' } };
    await adminProxy(req as any, res() as any);
    expect(mockUpstream).toHaveBeenCalledWith('decide', { id, status: 'approved', providerOrganizationId: 'org_counsel', actor: 'staff@example.org' });
    for (const body of [{ action: 'list', providerOrganizationId: 'org_counsel' }, { ...req.body, status: 'denied' }]) {
      const response = res(); await adminProxy({ ...req, body } as any, response as any);
      expect(response.status).toHaveBeenCalledWith(400);
    }
  });
  it('returns a conflict without leaking storage errors or accepting a different decision', async () => {
    decide.mockResolvedValueOnce(false);
    await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, status: 'denied', actor: 'admin' }).expect(409);
    decide.mockRejectedValueOnce(new Error('private detail'));
    const response = await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, status: 'approved', actor: 'admin' }).expect(503);
    expect(JSON.stringify(response.body)).not.toContain('private detail');
  });
  it('logs the route and a log-safe reason for service failures, never the error message', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      decide.mockRejectedValueOnce(new LegalProvisioningError('provider_unavailable'));
      await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, status: 'approved', actor: 'admin' }).expect(503);
      expect(warn).toHaveBeenLastCalledWith('Legal application service unavailable', 'decide', 'provider_unavailable');
      // The fixed source tag tells the lock wait, fetch, Auth0 status and pending membership apart.
      for (const detail of ['lock_wait', 'fetch', 'auth0_status_404', 'membership_pending'] as const) {
        decide.mockRejectedValueOnce(new LegalProvisioningError('provider_unavailable', detail));
        await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, status: 'approved', actor: 'admin' }).expect(503);
        expect(warn).toHaveBeenLastCalledWith('Legal application service unavailable', 'decide', `provider_unavailable:${detail}`);
      }
      decide.mockRejectedValueOnce(Object.assign(new Error('E11000 lawyer@firm.example'), { code: 11000, codeName: 'DuplicateKey' }));
      await request(app).post('/decide').set('x-test-authorized', 'yes').send({ id, status: 'approved', actor: 'admin' }).expect(503);
      expect(warn).toHaveBeenLastCalledWith('Legal application service unavailable', 'decide', 'DuplicateKey');
      expect(JSON.stringify(warn.mock.calls)).not.toContain('firm.example');
    } finally { warn.mockRestore(); }
  });
});
