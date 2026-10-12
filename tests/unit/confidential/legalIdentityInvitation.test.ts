const windowDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'window');
afterEach(() => {
  jest.resetModules();
  if (windowDescriptor) Object.defineProperty(globalThis, 'window', windowDescriptor);
  else delete (globalThis as any).window;
});
const config = { domain: 'legal.example', clientId: 'legal-client', audience: 'legal-api', organization: null };
function browser(search: string) {
  const location = { origin: 'https://vera.example', pathname: '/legal', search, assign: jest.fn() };
  const storage = new Map<string, string>();
  const replaceState = jest.fn(() => { location.search = ''; });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location, history: { replaceState },
    sessionStorage: { setItem: (key: string, value: string) => storage.set(key, value),
      getItem: (key: string) => storage.get(key) ?? null, removeItem: (key: string) => storage.delete(key) } } });
  return { location, storage, replaceState };
}
test('email invitation starts one legal PKCE flow and never retains the invitation ticket', async () => {
  const api = require('../../../lib/confidential/legalAuth');
  const { location, storage, replaceState } = browser('?invitation=opaque-ticket&organization=org_firm&organization_name=ignored&redirect_uri=https://attacker.example');
  const first = api.completeLegalSignIn(config), replay = api.completeLegalSignIn(config);
  expect(replay).toBe(first);
  await expect(first).resolves.toBe(api.LEGAL_INVITATION_REDIRECTED);
  expect(replaceState).toHaveBeenCalledTimes(1);
  expect(location.search).toBe('');
  expect(location.assign).toHaveBeenCalledTimes(1);
  const url = new URL(location.assign.mock.calls[0][0]);
  expect(url.origin).toBe('https://legal.example');
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('legal-client');
  expect(url.searchParams.get('organization')).toBe('org_firm');
  expect(url.searchParams.get('invitation')).toBe('opaque-ticket');
  expect(url.searchParams.get('redirect_uri')).toBe('https://vera.example/legal');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  const raw = storage.get('vera-legal-auth-pending')!;
  expect(raw).not.toContain('opaque-ticket');
  const pending = JSON.parse(raw);
  expect(pending.returnPath).toBe('/legal/enroll');
  expect(pending.state).toBe(url.searchParams.get('state'));
  expect(await api.pkceChallenge(pending.verifier)).toBe(url.searchParams.get('code_challenge'));
});
test.each([
  '?invitation=ticket', '?organization=org_firm', '?invitation=&organization=org_firm',
  '?invitation=ticket&organization=bad', '?invitation=ticket&invitation=other&organization=org_firm',
  '?invitation=ticket&organization=org_firm&organization=org_other',
  '?invitation=ticket&organization=org_firm&code=confused', '?invitation=https://bad&organization=org_firm',
])('malformed invitation %s is scrubbed and cannot start a login', async search => {
  const api = require('../../../lib/confidential/legalAuth');
  const { location, storage } = browser(search);
  await expect(api.completeLegalSignIn(config)).rejects.toThrow();
  expect(location.search).toBe(''); expect(location.assign).not.toHaveBeenCalled(); expect(storage.size).toBe(0);
});
test('an invitation cannot override a pinned organization', async () => {
  const api = require('../../../lib/confidential/legalAuth');
  const { location } = browser('?invitation=ticket&organization=org_other');
  await expect(api.completeLegalSignIn({ ...config, organization: 'org_pinned' })).rejects.toThrow();
  expect(location.assign).not.toHaveBeenCalled();
});
