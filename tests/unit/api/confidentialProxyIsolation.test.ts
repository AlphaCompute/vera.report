const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler,
} }));
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name, roles: user['https://vera.app/roles'] ?? [],
  }),
}));

import status from '../../../pages/api/whistleblower/status/[trackingId]';
import narrative from '../../../pages/api/admin/narrative/[trackingId]';
import rewardContact from '../../../pages/api/whistleblower/reward-contact/[trackingId]';
import evidence from '../../../pages/api/whistleblower/evidence/[trackingId]/[filename]';
import analyze from '../../../pages/api/admin/dashboard/reports/[reportId]/analyze';
import reportStatus from '../../../pages/api/admin/dashboard/reports/[reportId]/status';

const CASE_ID = 'ef'.repeat(32);
const OWNER_CODE = `VERA-OWNER-1.${CASE_ID}.${'01'.repeat(20)}.${'S'.repeat(43)}`;
const SHORT_CODE = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
let saved: NodeJS.ProcessEnv;
let fetchSpy: jest.SpiedFunction<typeof fetch>;
const res = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn(), once: jest.fn(), on: jest.fn() });

beforeEach(() => {
  saved = { ...process.env };
  Object.assign(process.env, { INTERNAL_API_SECRET: 'synthetic-secret', BACKEND_URL: 'http://synthetic.invalid',
    ADMIN_ALLOWED_DOMAINS: '@example.org', TENANT_ORG_ID: 'org_test' });
  mockSession.mockResolvedValue({ user: { sub: 'auth0|admin', email: 'qa@example.org', email_verified: true,
    org_id: 'org_test', 'https://vera.app/roles': ['admin'] } });
  fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ success: true }));
});
afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

it.each([
  ['owner code path', { trackingId: OWNER_CODE }, {}],
  ['owner code header', { trackingId: 'lookup' }, { 'x-reporter-credential': OWNER_CODE }],
  ['case ID path', { trackingId: CASE_ID }, {}],
  ['short code path', { trackingId: SHORT_CODE }, {}],
  ['short code header', { trackingId: 'lookup' }, { 'x-reporter-credential': SHORT_CODE }],
])('the public status proxy never forwards a confidential identifier (%s)', async (_label, query, headers) => {
  const response = res();
  await status({ method: 'GET', query, headers, socket: {} } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(400);
  expect(fetchSpy).not.toHaveBeenCalled();
});

it.each([
  ['narrative', narrative, 'GET', { trackingId: CASE_ID }],
  ['reward contact', rewardContact, 'GET', { trackingId: CASE_ID }],
  ['evidence', evidence, 'GET', { trackingId: CASE_ID, filename: 'a.pdf' }],
  ['reanalyze', analyze, 'POST', { reportId: CASE_ID }],
  ['status change', reportStatus, 'PATCH', { reportId: OWNER_CODE }],
] as const)('admin %s proxy rejects confidential IDs before audit or backend calls', async (_label, handler, method, query) => {
  const response = res();
  await handler({ method, query, body: { status: 'reviewing' }, headers: {}, socket: {}, url: '/' } as any, response as any);
  expect(response.status).toHaveBeenCalledWith(400);
  // No audit write (which would persist the identifier) and no backend read.
  expect(fetchSpy).not.toHaveBeenCalled();
});
