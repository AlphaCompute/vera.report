import { EmailNotificationService } from '../../../src/services/emailNotification';

const mockSend = jest.fn();
jest.mock('@aws-sdk/client-sesv2', () => ({
  SESv2Client: jest.fn().mockImplementation(() => ({ send: mockSend })),
  SendEmailCommand: jest.fn().mockImplementation(input => ({ input })),
}));

const originalEnv = process.env;
const originalFetch = global.fetch;
let routes: Record<string, unknown>;
const profile = (id: string, email = `${id}@example.org`, extra = {}) =>
  ({ user_id: id, email, email_verified: true, ...extra });
const rolePage = '/api/v2/roles?per_page=100&page=0';
const usersPage = '/api/v2/roles/admin-role/users?per_page=100&page=0';

beforeEach(() => {
  process.env = { ...originalEnv, SES_SENDER_EMAIL: 'sender@example.org', AUTH0_DOMAIN: 'identity.example.org',
    AUTH0_MGMT_CLIENT_ID: 'test-client', AUTH0_MGMT_CLIENT_SECRET: 'test-secret', ADMIN_ALLOWED_DOMAINS: 'example.org' };
  delete process.env.ADMIN_ALERT_ROLE_MODE;
  delete process.env.TENANT_ORG_ID;
  delete process.env.AUTH0_ORG_SCOPED_ADMIN;
  routes = { [rolePage]: [{ id: 'admin-role', name: 'admin' }], [usersPage]: [{ user_id: 'allowed' }],
    '/api/v2/users/allowed': profile('allowed') };
  mockSend.mockReset().mockResolvedValue({ MessageId: 'test-message' });
  global.fetch = jest.fn(async (url: any) => {
    const path = new URL(String(url)).pathname + new URL(String(url)).search;
    if (path === '/oauth/token') return { ok: true, json: async () => ({ access_token: 'test-token', expires_in: 3600 }) } as Response;
    if (!(path in routes)) throw new Error(`Unexpected private provider response ${path}`);
    return { ok: true, json: async () => routes[path] } as Response;
  });
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { process.env = originalEnv; global.fetch = originalFetch; jest.restoreAllMocks(); });

const alert = (service = new EmailNotificationService()) => service.notifyNewReport('private-report-id', 'private-urgency');

test('sends only verified, unblocked, allowed-domain administrators and deduplicates addresses', async () => {
  const users = [profile('allowed'), profile('unverified', 'unverified@example.org', { email_verified: false }),
    profile('missing', 'missing@example.org', { email_verified: undefined }), profile('blocked', 'blocked@example.org', { blocked: true }),
    profile('foreign', 'foreign@other.org'), profile('suffix', 'bad@notexample.org'),
    profile('injection', 'bad@example.org\r\nBcc: outsider@other.org'), profile('duplicate', 'ALLOWED@EXAMPLE.ORG')];
  routes[usersPage] = users.map(user => ({ user_id: user.user_id }));
  for (const user of users) routes[`/api/v2/users/${user.user_id}`] = user;
  expect(await alert()).toEqual({ sent: true });
  expect(mockSend).toHaveBeenCalledTimes(1);
  expect(mockSend.mock.calls[0][0].input.Destination).toEqual({ BccAddresses: ['allowed@example.org'] });
  expect(JSON.stringify(mockSend.mock.calls)).not.toContain('private-report-id');
});

test('intersects global admins with configured organization membership before reading profiles', async () => {
  process.env.TENANT_ORG_ID = 'org_test';
  process.env.ADMIN_ALERT_ROLE_MODE = 'global-in-org';
  routes['/api/v2/organizations/org_test/members?per_page=100&page=0'] = [{ user_id: 'allowed' }];
  routes[usersPage] = [{ user_id: 'allowed' }, { user_id: 'other-tenant' }];
  expect(await alert()).toEqual({ sent: true });
  expect(global.fetch).not.toHaveBeenCalledWith(expect.stringContaining('/users/other-tenant'), expect.anything());
  const tokenBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
  expect(tokenBody.scope).toContain('read:organization_members');
});

test.each(['true', 'false'])('keeps staging direct organization roles by default with management flag %s', async flag => {
  process.env.TENANT_ORG_ID = 'org_test';
  process.env.AUTH0_ORG_SCOPED_ADMIN = flag;
  routes['/api/v2/organizations/org_test/roles/admin-role/members?take=100'] = { members: [{ user_id: 'allowed' }] };
  const service = new EmailNotificationService();
  expect(await alert(service)).toEqual({ sent: true });
  expect(global.fetch).not.toHaveBeenCalledWith(expect.stringContaining('/roles/admin-role/users'), expect.anything());
  expect(JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body).scope).toContain('read:organization_member_roles');
  routes['/api/v2/organizations/org_test/roles/admin-role/members?take=100'] = { members: [] };
  expect(await alert(service)).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(mockSend).toHaveBeenCalledTimes(1);
});

test('reads later pages and batches hidden recipients within the SES limit', async () => {
  routes[rolePage] = Array.from({ length: 100 }, (_, i) => ({ id: `r${i}`, name: `role${i}` }));
  routes['/api/v2/roles?per_page=100&page=1'] = [{ id: 'admin-role', name: 'admin' }];
  const users = Array.from({ length: 101 }, (_, i) => profile(`user${i}`));
  routes[usersPage] = users.slice(0, 100);
  routes['/api/v2/roles/admin-role/users?per_page=100&page=1'] = users.slice(100);
  for (const user of users) routes[`/api/v2/users/${user.user_id}`] = user;
  expect(await alert()).toEqual({ sent: true });
  expect(mockSend.mock.calls.map(call => call[0].input.Destination.BccAddresses.length)).toEqual([50, 50, 1]);
});

test('fails closed when a later membership page cannot be read', async () => {
  process.env.TENANT_ORG_ID = 'org_test';
  process.env.ADMIN_ALERT_ROLE_MODE = 'global-in-org';
  routes['/api/v2/organizations/org_test/members?per_page=100&page=0'] = Array.from({ length: 100 }, (_, i) => ({ user_id: `user${i}` }));
  expect(await alert()).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(mockSend).not.toHaveBeenCalled();
});

test.each(['roles', 'profile', 'token'])('fails closed on malformed %s response without leaking provider details', async kind => {
  if (kind === 'roles') routes[rolePage] = { sensitive: 'private-data' };
  if (kind === 'profile') routes['/api/v2/users/allowed'] = profile('different');
  if (kind === 'token') (global.fetch as jest.Mock).mockResolvedValue({ ok: true, json: async () => ({ access_token: '', expires_in: 3600 }) });
  expect(await alert()).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(mockSend).not.toHaveBeenCalled();
  expect(JSON.stringify((console.error as jest.Mock).mock.calls)).not.toMatch(/private-data|private provider/);
});

test('refuses incomplete enumeration at the page bound', async () => {
  for (let page = 0; page < 10; page++) routes[`/api/v2/roles?per_page=100&page=${page}`] = Array.from({ length: 100 }, (_, i) => ({ id: `r${i}`, name: 'employee' }));
  expect(await alert()).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(mockSend).not.toHaveBeenCalled();
});

test('confines every credential-bearing request and refreshes recipient authorization', async () => {
  const service = new EmailNotificationService();
  await alert(service);
  const fetchCount = (global.fetch as jest.Mock).mock.calls.length;
  await alert(service);
  expect((global.fetch as jest.Mock).mock.calls.length).toBeGreaterThan(fetchCount);
  for (const [url, options] of (global.fetch as jest.Mock).mock.calls) {
    expect(new URL(url).origin).toBe('https://identity.example.org');
    expect(options.redirect).toBe('error');
  }
});

test('rejects unsafe identity provider host before requesting credentials', async () => {
  process.env.AUTH0_DOMAIN = 'identity.example.org@outside.example';
  expect(await alert()).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockSend).not.toHaveBeenCalled();
});

test('direct-send provider failure exposes neither recipient, subject, nor provider text in logs/result', async () => {
  mockSend.mockRejectedValue(new Error('private-provider-payload'));
  const result = await new EmailNotificationService().sendToRecipient('private-recipient@example.org', 'private-subject', 'private-content');
  expect(result).toEqual({ sent: false, error: 'provider_failed' });
  expect(JSON.stringify((console.error as jest.Mock).mock.calls)).not.toContain('private');
});

test('does not resolve recipients or contact SES when sender is absent', async () => {
  delete process.env.SES_SENDER_EMAIL;
  expect(await alert()).toEqual({ sent: false, error: 'ses_unconfigured' });
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockSend).not.toHaveBeenCalled();
});

test('critical alert keeps the durable worker result contract and generic content', async () => {
  const service = new EmailNotificationService();
  const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: false, error: 'provider_failed' });
  expect(await service.notifyCriticalAdminAction()).toEqual({ sent: false, error: 'provider_failed' });
  expect(send.mock.calls[0][2]).toContain('authenticated admin audit log');
});

test('error alerts ignore arbitrary error samples and validate the numeric count', async () => {
  const service = new EmailNotificationService();
  const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: true });
  await service.notifyErrorThreshold(7, [{ message: 'private-report-capability', timestamp: new Date() }]);
  expect(send.mock.calls[0][2]).toContain('7 errors');
  expect(JSON.stringify(send.mock.calls)).not.toContain('private');
  await service.notifyErrorThreshold('<private>' as any);
  expect(send.mock.calls[1][2]).toContain('0 errors');
  expect(JSON.stringify(send.mock.calls)).not.toContain('private');
});

test.each(['global-in-org', 'invalid'])('fails closed for unconfigured or invalid role mode %s', async mode => {
  process.env.ADMIN_ALERT_ROLE_MODE = mode;
  expect(await alert()).toEqual({ sent: false, error: 'no_admin_recipients' });
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockSend).not.toHaveBeenCalled();
});
test('reports partial provider batch failure without claiming all recipients were sent', async () => {
  const service = new EmailNotificationService();
  jest.spyOn(service as any, 'getAdminEmails').mockResolvedValue(Array.from({length: 51}, (_, i) => `${i}@example.org`));
  mockSend.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error('private-provider-data'));
  expect(await alert(service)).toEqual({ sent: false, error: 'provider_failed' });
  expect(mockSend).toHaveBeenCalledTimes(2);
});

// Use a synthetic clock so a multi-request lookup can exceed 20s without
// making the test sleep or contacting Auth0.
test.each([8000, 21000])('gives each Auth0 lookup its own deadline at %i ms per API call', async delay => {
  jest.useFakeTimers();
  jest.spyOn(AbortSignal, 'timeout').mockImplementation(ms => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  });
  const respond = global.fetch;
  global.fetch = jest.fn(async (url, options) => {
    if (String(url).includes('/api/v2/')) {
      await jest.advanceTimersByTimeAsync(delay);
      if (options?.signal?.aborted) throw new Error('synthetic timeout');
    }
    return respond(url, options);
  });
  try {
    expect(await alert()).toEqual(delay < 20000
      ? { sent: true }
      : { sent: false, error: 'no_admin_recipients' });
    expect(mockSend).toHaveBeenCalledTimes(delay < 20000 ? 1 : 0);
  } finally {
    jest.clearAllTimers();
    jest.useRealTimers();
  }
});
