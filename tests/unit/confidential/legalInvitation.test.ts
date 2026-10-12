const saved = Object.getOwnPropertyDescriptor(globalThis, 'window');
afterEach(() => { jest.resetModules(); jest.restoreAllMocks(); if (saved) Object.defineProperty(globalThis, 'window', saved); else delete (globalThis as any).window; });
const config = { domain: 'identity.example', clientId: 'legal-client', audience: 'legal-api', organization: null };
function fixture(search: string) {
  const storage = new Map<string, string>();
  const location = { origin: 'https://vera.example', pathname: '/legal', search, hash: '', assign: jest.fn() };
  const replaceState = jest.fn(() => { location.search = ''; });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location, history: { replaceState }, sessionStorage: {
    getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value), removeItem: (key: string) => storage.delete(key),
  } } });
  return { storage, location, replaceState, api: require('../../../lib/confidential/legalAuth') };
}

test('email sign-in first checks the Auth0 session with organization, scopes and PKCE', async () => {
  const { api, location } = fixture('');
  await api.beginLegalSignIn({ ...config, connection: 'email', organization: 'org_approved' }, '/legal');
  const url = new URL(location.assign.mock.calls[0][0]);
  expect(url.searchParams.has('connection')).toBe(false);
  expect(url.searchParams.get('prompt')).toBe('none');
  expect(url.searchParams.get('organization')).toBe('org_approved');
  expect(url.searchParams.get('scope')).toBe('openid legal:directory legal:case legal:enroll');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.has('invitation')).toBe(false);
});

test.each(['login_required', 'interaction_required', 'consent_required'])('a bound session check handles %s once with fresh PKCE', async error => {
  const { api, storage, location } = fixture('');
  const settings = { ...config, connection: 'email', organization: 'org_approved' };
  await api.beginLegalSignIn(settings, '/legal/report#' + 'ab'.repeat(32));
  const first = new URL(location.assign.mock.calls[0][0]);
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?error=${error}&state=${pending.state}`;
  const fetcher = jest.spyOn(globalThis, 'fetch');
  await expect(api.completeLegalSignIn(settings)).resolves.toBe(api.LEGAL_SIGN_IN_REDIRECTED);
  expect(fetcher).not.toHaveBeenCalled();
  expect(api.legalSignedIn()).toBe(false);
  const next = new URL(location.assign.mock.calls[1][0]);
  expect(next.searchParams.get('connection')).toBe(error === 'login_required' ? 'email' : null);
  expect(next.searchParams.has('prompt')).toBe(false);
  expect(next.searchParams.get('organization')).toBe('org_approved');
  expect(next.searchParams.get('state')).not.toBe(first.searchParams.get('state'));
  expect(next.searchParams.get('code_challenge')).not.toBe(first.searchParams.get('code_challenge'));
  const retried = JSON.parse(storage.get('vera-legal-auth-pending')!);
  expect(retried.returnPath).toBe('/legal/report#' + 'ab'.repeat(32));
  location.search = `?error=${error}&state=${retried.state}`;
  await expect(api.completeLegalSignIn(settings)).rejects.toThrow();
  expect(location.assign).toHaveBeenCalledTimes(2); // No redirect loop.
});

test.each(['access_denied', 'invalid_request'])('an Auth0 denial (%s) cannot trigger a login fallback', async error => {
  const { api, storage, location } = fixture('');
  const settings = { ...config, connection: 'email' };
  await api.beginLegalSignIn(settings, '/legal');
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?error=${error}&state=${pending.state}`;
  await expect(api.completeLegalSignIn(settings)).rejects.toThrow();
  expect(location.assign).toHaveBeenCalledTimes(1);
});

test('a forged session-check error cannot redirect or authenticate', async () => {
  const { api, location } = fixture('');
  const settings = { ...config, connection: 'email' };
  await api.beginLegalSignIn(settings, '/legal');
  location.search = '?error=login_required&state=wrong';
  await expect(api.completeLegalSignIn(settings)).rejects.toThrow();
  expect(location.assign).toHaveBeenCalledTimes(1);
  expect(api.legalSignedIn()).toBe(false);
});

test('an existing Auth0 session exchanges a code without sending an email challenge', async () => {
  const { api, storage, location } = fixture('');
  const settings = { ...config, connection: 'email', organization: 'org_approved' };
  await api.beginLegalSignIn(settings, '/legal');
  const authorization = new URL(location.assign.mock.calls[0][0]);
  expect(authorization.searchParams.get('prompt')).toBe('none');
  expect(authorization.searchParams.has('connection')).toBe(false);
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?code=session-code&state=${pending.state}`;
  jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ access_token: 'synthetic-token', expires_in: 300, token_type: 'Bearer' })));
  await expect(api.completeLegalSignIn(settings)).resolves.toBe('/legal');
  expect(location.assign).toHaveBeenCalledTimes(1);
  expect(api.legalSignedIn()).toBe(true);
  expect([...storage.values()].join(' ')).not.toContain('synthetic-token');
});

test('a callback cannot switch login connections', async () => {
  const { api, storage, location } = fixture('');
  await api.beginLegalSignIn({ ...config, connection: 'email' }, '/legal');
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?code=c&state=${pending.state}`;
  const fetcher = jest.spyOn(globalThis, 'fetch');
  await expect(api.completeLegalSignIn(config)).rejects.toThrow();
  expect(fetcher).not.toHaveBeenCalled();
});
test('invitation is stripped and forwarded once with organization and fresh PKCE/state', async () => {
  const { api, location, replaceState, storage } = fixture('?invitation=in_synthetic&organization=org_approved&organization_name=Untrusted');
  expect(api.consumeLegalInvitation()).toBe(true);
  expect(location.search).toBe(''); expect(replaceState).toHaveBeenCalledTimes(1);
  expect(api.consumeLegalInvitation()).toBe(true); // React replay preserves the consumed invitation.
  await api.beginLegalSignIn(config, '/legal');
  const url = new URL(location.assign.mock.calls[0][0]);
  expect(url.origin).toBe('https://identity.example');
  expect(url.searchParams.get('invitation')).toBe('in_synthetic');
  expect(url.searchParams.get('organization')).toBe('org_approved');
  expect(url.searchParams.has('organization_name')).toBe(false);
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  expect(pending.state).toBe(url.searchParams.get('state'));
  expect(pending.organization).toBe('org_approved'); expect(pending.binding).toContain('legal-client');
  expect(storage.get('vera-legal-auth-pending')).not.toContain('in_synthetic');
  await api.beginLegalSignIn(config, '/legal');
  expect(new URL(location.assign.mock.calls[1][0]).searchParams.has('invitation')).toBe(false);
});
test('callback rejects organization or identity substitution before token fetch', async () => {
  const { api, storage, location } = fixture('?invitation=in_synthetic&organization=org_approved');
  api.consumeLegalInvitation(); await api.beginLegalSignIn(config, '/legal');
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?code=c&state=${pending.state}`;
  const fetcher = jest.spyOn(globalThis, 'fetch');
  await expect(api.completeLegalSignIn({ ...config, organization: 'org_other' })).rejects.toThrow();
  expect(fetcher).not.toHaveBeenCalled(); expect(api.legalSignedIn()).toBe(false);
});
test('sign out discards invitation and selected organization', async () => {
  const { api, storage, location } = fixture('?invitation=in_synthetic&organization=org_approved');
  api.consumeLegalInvitation(); api.signOutLegal(config); await api.beginLegalSignIn(config, '/legal');
  expect(new URL(location.assign.mock.calls[1][0]).searchParams.has('invitation')).toBe(false);
  expect(JSON.parse(storage.get('vera-legal-auth-pending')!).organization).toBeNull();
});

test('an explicit deployment organization supersedes remembered organization context', async () => {
  const { api, storage, location } = fixture('');
  storage.set('vera-legal-organization', JSON.stringify({ binding: JSON.stringify([location.origin, config.domain, config.clientId, config.audience]), organization: 'org_previous' }));
  await api.beginLegalSignIn({ ...config, organization: 'org_pinned' }, '/legal');
  expect(new URL(location.assign.mock.calls[0][0]).searchParams.get('organization')).toBe('org_pinned');
  expect(JSON.parse(storage.get('vera-legal-auth-pending')!).organization).toBe('org_pinned');
});
test('malformed invitation invalidates the existing identity session', async () => {
  const { api, storage, location } = fixture('');
  await api.beginLegalSignIn(config, '/legal');
  const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
  location.search = `?code=c&state=${pending.state}`;
  jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ access_token: 'synthetic-token', expires_in: 300, token_type: 'Bearer' })));
  await api.completeLegalSignIn(config);
  expect(api.legalSignedIn()).toBe(true);
  location.search = '?invitation=invalid';
  expect(() => api.consumeLegalInvitation()).toThrow();
  expect(api.legalSignedIn()).toBe(false);
  await expect(api.legalAccessToken(config)).rejects.toThrow();
});
