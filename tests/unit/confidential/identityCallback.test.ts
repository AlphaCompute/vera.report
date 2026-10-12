const windowDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'window');
const fetchDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'fetch');
afterEach(() => {
  jest.resetModules();
  for (const [key, descriptor] of [['window', windowDescriptor], ['fetch', fetchDescriptor]] as const) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete (globalThis as any)[key];
  }
});

for (const kind of ['legal', 'onboarding'] as const) {
  test(`${kind} callback shares one config-bound exchange across concurrent mount effects`, async () => {
    jest.resetModules();
    const api = kind === 'legal' ? require('../../../lib/confidential/legalAuth') : require('../../../lib/confidential/onboardingAuth');
    const complete = kind === 'legal' ? api.completeLegalSignIn : api.completeOnboardingSignIn;
    const signedIn = kind === 'legal' ? api.legalSignedIn : api.onboardingSignedIn;
    const pendingKey = `vera-${kind}-auth-pending`;
    const path = kind === 'legal' ? '/legal' : '/legal/administration';
    const location = { origin: 'https://vera.example', pathname: path, search: '?code=one-use-code&state=expected-state' };
    const storage = new Map([[pendingKey, JSON.stringify({ state: 'expected-state', verifier: 'one-use-verifier', returnPath: `${path}/next`, binding: JSON.stringify([location.origin, 'identity.example', `${kind}-client`, `${kind}-api`]), organization: 'org_allowed' })]]);
    const replaceState = jest.fn(() => { location.search = ''; });
    Object.defineProperty(globalThis, 'window', { configurable: true, value: { location, history: { replaceState },
      sessionStorage: { getItem: (key: string) => storage.get(key) ?? null, removeItem: (key: string) => storage.delete(key) } } });
    let resolveExchange!: (value: unknown) => void;
    const fetch = jest.fn(() => new Promise(resolve => { resolveExchange = resolve; }));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetch });
    const config = { domain: 'identity.example', clientId: `${kind}-client`, audience: `${kind}-api`, organization: 'org_allowed' };
    const first = complete(config), replay = complete({ ...config });
    expect(replay).toBe(first);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(storage.has(pendingKey)).toBe(false);
    expect(location.search).toBe('');
    await expect(complete({ ...config, clientId: 'foreign-client' })).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
    resolveExchange(new Response(JSON.stringify({ access_token: 'synthetic-token', expires_in: 300, token_type: 'Bearer' })));
    await expect(first).resolves.toBe(`${path}/next`);
    await expect(replay).resolves.toBe(`${path}/next`);
    expect(signedIn()).toBe(true);
    await expect(complete(config)).resolves.toBeNull();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test(`${kind} failed callback is cleared without replaying consumed code or verifier`, async () => {
    jest.resetModules();
    const api = kind === 'legal' ? require('../../../lib/confidential/legalAuth') : require('../../../lib/confidential/onboardingAuth');
    const complete = kind === 'legal' ? api.completeLegalSignIn : api.completeOnboardingSignIn;
    const key = `vera-${kind}-auth-pending`;
    const location = { origin: 'https://vera.example', pathname: '/legal', search: '?code=failed-code&state=s' };
    const storage = new Map([[key, JSON.stringify({ state: 's', verifier: 'v', returnPath: '/legal', binding: JSON.stringify([location.origin, 'identity.example', 'client', 'api']), organization: null })]]);
    Object.defineProperty(globalThis, 'window', { configurable: true, value: { location,
      history: { replaceState: () => { location.search = ''; } },
      sessionStorage: { getItem: (name: string) => storage.get(name) ?? null, removeItem: (name: string) => storage.delete(name) } } });
    const fetch = jest.fn(async () => ({ ok: false }));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetch });
    const config = { domain: 'identity.example', clientId: 'client', audience: 'api', organization: null };
    await expect(complete(config)).rejects.toThrow();
    await expect(complete(config)).resolves.toBeNull();
    location.search = '?code=failed-code&state=s';
    await expect(complete(config)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
}

test.each([
  [`/legal/report#${'ab'.repeat(32)}`, `/legal/report#${'ab'.repeat(32)}`],
  ['/legal/report#not-a-reference', '/legal'],
  ['https://attacker.example/legal', '/legal'],
  [`/legal/report?case=${'ab'.repeat(32)}`, '/legal'],
])('legal sign-in returns to %j as %j', async (returnPath, expected) => {
  jest.resetModules();
  const api = require('../../../lib/confidential/legalAuth');
  const location = { origin: 'https://vera.example', pathname: '/legal', search: '?code=c&state=s' };
  const storage = new Map([['vera-legal-auth-pending', JSON.stringify({ state: 's', verifier: 'v', returnPath, binding: JSON.stringify([location.origin, 'identity.example', 'c', 'a']), organization: null })]]);
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location,
    history: { replaceState: () => { location.search = ''; } },
    sessionStorage: { getItem: (name: string) => storage.get(name) ?? null, removeItem: (name: string) => storage.delete(name) } } });
  Object.defineProperty(globalThis, 'fetch', { configurable: true, value: jest.fn(async () => new Response(
    JSON.stringify({ access_token: 'synthetic-token', expires_in: 300, token_type: 'Bearer' }))) });
  await expect(api.completeLegalSignIn({ domain: 'identity.example', clientId: 'c', audience: 'a', organization: null }))
    .resolves.toBe(expected);
});
