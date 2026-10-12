import { logger } from '../../../src/utils/logger';
jest.mock('../../../src/utils/logger', () => ({ logger: { warn: jest.fn() } }));
import { getAdminRecipientEmails } from '../../../src/services/adminAlertRecipients';

const savedDomains = process.env.ADMIN_ALLOWED_DOMAINS;
beforeEach(() => { jest.clearAllMocks(); process.env.ADMIN_ALLOWED_DOMAINS = 'example.test'; });
afterAll(() => { if (savedDomains === undefined) delete process.env.ADMIN_ALLOWED_DOMAINS; else process.env.ADMIN_ALLOWED_DOMAINS = savedDomains; });
const profile = (id: string) => ({ user_id: id, email: `${id}@example.test`, email_verified: true });
function reader(overrides: Record<string, unknown> = {}) {
  return jest.fn(async (path: string): Promise<any> => {
    if (path in overrides) {
      if (overrides[path] instanceof Error) throw overrides[path];
      return overrides[path];
    }
    if (path === '/roles?per_page=100&page=0') return [{ id: 'admin', name: 'admin' }];
    if (path.startsWith('/users/')) return profile(decodeURIComponent(path.slice(7)));
    throw new Error(`Unexpected lookup: ${path}`);
  });
}
it('pages direct organization admins, verifies profiles and deduplicates addresses', async () => {
  const get = reader({
    '/organizations/org%2Fone/roles/admin/members?take=100': { members: [{ user_id: 'one' }], next: 'cursor/value' },
    '/organizations/org%2Fone/roles/admin/members?take=100&from=cursor%2Fvalue': { members: [{ user_id: 'two' }, { user_id: 'one' }] },
  });
  expect(await getAdminRecipientEmails(get, 'org/one')).toEqual(['one@example.test', 'two@example.test']);
  expect(get.mock.calls.some(([path]) => path.startsWith('/roles/admin/users'))).toBe(false);
  expect(get.mock.calls.filter(([path]) => path === '/users/one')).toHaveLength(1);
});
it('supports the explicit production global-admin intersection without including outsiders', async () => {
  const get = reader({
    '/roles/admin/users?per_page=100&page=0': [{ user_id: 'one' }, { user_id: 'outsider' }],
    '/organizations/org/members?per_page=100&page=0': [{ user_id: 'one' }, { user_id: 'nonadmin' }],
  });
  expect(await getAdminRecipientEmails(get, 'org', 'global-in-org')).toEqual(['one@example.test']);
  expect(get).not.toHaveBeenCalledWith('/users/outsider');
  expect(get).not.toHaveBeenCalledWith('/users/nonadmin');
});
it('paginates global admins only when no organization is configured', async () => {
  const get = reader({
    '/roles/admin/users?per_page=100&page=0': Array.from({ length: 100 }, (_, i) => ({ user_id: String(i) })),
    '/roles/admin/users?per_page=100&page=1': [{ user_id: 'last' }],
  });
  expect(await getAdminRecipientEmails(get)).toHaveLength(101);
});
it('filters unverified, blocked and foreign-domain profiles, normalizes and deduplicates email', async () => {
  const get = reader({
    '/roles/admin/users?per_page=100&page=0': ['one', 'two', 'three', 'four', 'five'].map(user_id => ({ user_id })),
    '/users/one': { ...profile('one'), email_verified: false },
    '/users/two': { ...profile('two'), blocked: true },
    '/users/three': { ...profile('three'), email: 'someone@outsider.test' },
    '/users/four': { ...profile('four'), email: ' Allowed@EXAMPLE.TEST ' },
    '/users/five': { ...profile('five'), email: 'allowed@example.test' },
  });
  expect(await getAdminRecipientEmails(get)).toEqual(['allowed@example.test']);
  expect(logger.warn).toHaveBeenCalledWith('[EMAIL] Admin recipient domain filter excluded profiles', { count: 1 });
  expect(JSON.stringify((logger.warn as jest.Mock).mock.calls)).not.toContain('someone@');
});
it.each(['repeated', 'limit', 'malformed', 'failure', 'profile-mismatch', 'profile-failure'])('refuses partial recipients after %s', async kind => {
  let page = 0;
  const get = reader();
  const fallback = get.getMockImplementation()!;
  get.mockImplementation(async path => {
    if (path.startsWith('/organizations/')) {
      if (kind === 'failure') throw new Error('unavailable');
      if (kind === 'malformed') return { members: [{ email: 'no-id@example.test' }] };
      return { members: [{ user_id: 'one' }], ...(['repeated', 'limit'].includes(kind) ? { next: kind === 'limit' ? String(page++) : 'same' } : {}) };
    }
    if (path === '/users/one' && kind === 'profile-mismatch') return profile('other');
    if (path === '/users/one' && kind === 'profile-failure') throw new Error('unavailable');
    return fallback(path);
  });
  await expect(getAdminRecipientEmails(get, 'org')).rejects.toThrow();
});
it('refuses ambiguous admin roles and explicit intersection without an organization', async () => {
  await expect(getAdminRecipientEmails(reader({ '/roles?per_page=100&page=0': [{ id: 'a', name: 'admin' }, { id: 'b', name: 'Admin' }] }))).rejects.toThrow();
  await expect(getAdminRecipientEmails(reader(), undefined, 'global-in-org')).rejects.toThrow();
});
it('returns no recipients when admin domains are not configured', async () => {
  delete process.env.ADMIN_ALLOWED_DOMAINS;
  const get = reader({ '/roles/admin/users?per_page=100&page=0': [{ user_id: 'one' }] });
  expect(await getAdminRecipientEmails(get)).toEqual([]);
  expect(get).not.toHaveBeenCalled();
  expect(logger.warn).toHaveBeenCalledWith('[EMAIL] ADMIN_ALLOWED_DOMAINS is not configured; no admin alert recipients');
});
