const settings = { domain: 'identity.example', clientId: 'legal-client', audience: 'legal-api', organization: 'org_allowed' };
const saved = Object.fromEntries(['window', 'fetch'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));

afterEach(() => {
  jest.restoreAllMocks();
  jest.resetModules();
  for (const [key, descriptor] of Object.entries(saved)) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete (globalThis as Record<string, unknown>)[key];
  }
});

function fixture(kind: 'legal' | 'onboarding') {
  const location = { origin: 'https://vera.example', pathname: kind === 'legal' ? '/legal' : '/legal/administration',
    search: '?code=synthetic-code&state=synthetic-state', assign: jest.fn() };
  const storage = new Map([[`vera-${kind}-auth-pending`, JSON.stringify({ verifier: 'synthetic-verifier', state: 'synthetic-state', returnPath: '/legal', binding: JSON.stringify([location.origin, settings.domain, settings.clientId, settings.audience]), organization: settings.organization })]]);
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location,
    history: { replaceState: () => { location.search = ''; } }, sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null, removeItem: (key: string) => storage.delete(key),
    } } });
  const api = kind === 'legal' ? require('../../../lib/confidential/legalAuth') : require('../../../lib/confidential/onboardingAuth');
  return { complete: () => (kind === 'legal' ? api.completeLegalSignIn : api.completeOnboardingSignIn)(settings),
    signedIn: kind === 'legal' ? api.legalSignedIn : api.onboardingSignedIn,
    signOut: () => (kind === 'legal' ? api.signOutLegal : api.signOutOnboarding)(settings) };
}
const validToken = { access_token: 'synthetic-access-token', token_type: 'Bearer', expires_in: 300 };
const mockFetch = (callback: typeof fetch) => Object.defineProperty(globalThis, 'fetch', { configurable: true, value: callback });

describe.each(['legal', 'onboarding'] as const)('%s token-exchange boundaries', kind => {
  test('rejects an oversized response before it can install a token', async () => {
    const api = fixture(kind);
    mockFetch(jest.fn(async () => new Response(JSON.stringify({ ...validToken, padding: 'x'.repeat(65536) }))) as typeof fetch);
    await expect(api.complete()).rejects.toThrow();
    expect(api.signedIn()).toBe(false);
  });

  test('the request deadline also interrupts a body that never finishes', async () => {
    const api = fixture(kind);
    const abort = new AbortController();
    const timeout = jest.spyOn(AbortSignal, 'timeout').mockReturnValue(abort.signal);
    let stream!: ReadableStreamDefaultController<Uint8Array>;
    mockFetch(jest.fn(async (_url: unknown, init?: RequestInit) => {
      const body = new ReadableStream<Uint8Array>({ start(controller) { stream = controller; controller.enqueue(new TextEncoder().encode('{')); } });
      init?.signal?.addEventListener('abort', () => stream.error(new Error('synthetic timeout')), { once: true });
      return new Response(body);
    }) as typeof fetch);
    const pending = api.complete().then(() => 'accepted', () => 'rejected');
    await Promise.resolve();
    abort.abort();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([pending, new Promise(resolve => { timer = setTimeout(() => resolve('still pending'), 50); })]);
      expect(result).toBe('rejected');
      expect(timeout).toHaveBeenCalledWith(10000);
      expect(api.signedIn()).toBe(false);
    } finally {
      clearTimeout(timer);
      try { stream.error(new Error('test cleanup')); } catch { /* already closed */ }
      await pending;
    }
  });

  test('a late response cannot restore a session after sign-out', async () => {
    const api = fixture(kind);
    let deliver!: (response: Response) => void;
    mockFetch(jest.fn(() => new Promise<Response>(resolve => { deliver = resolve; })) as typeof fetch);
    const pending = api.complete();
    api.signOut();
    deliver(new Response(JSON.stringify(validToken)));
    await expect(pending).rejects.toThrow();
    expect(api.signedIn()).toBe(false);
  });

  test('a valid response succeeds without permitting redirect forwarding', async () => {
    const api = fixture(kind);
    const fetcher = jest.fn(async () => new Response(JSON.stringify(validToken)));
    mockFetch(fetcher as typeof fetch);
    await expect(api.complete()).resolves.toBe('/legal');
    expect(api.signedIn()).toBe(true);
    expect(fetcher).toHaveBeenCalledWith('https://identity.example/oauth/token', expect.objectContaining({ redirect: 'error', credentials: 'omit' }));
  });

  test.each(['0', '-1', '301', '1e309', '"300"'])('rejects expires_in=%s', async expiry => {
    const api = fixture(kind);
    mockFetch(jest.fn(async () => new Response(`{"access_token":"synthetic-token","token_type":"Bearer","expires_in":${expiry}}`)) as typeof fetch);
    await expect(api.complete()).rejects.toThrow();
    expect(api.signedIn()).toBe(false);
  });

  test('rejects invalid UTF-8 before interpreting the token', async () => {
    const api = fixture(kind);
    const before = new TextEncoder().encode('{"access_token":"synthetic-');
    const after = new TextEncoder().encode('","token_type":"Bearer","expires_in":300}');
    const bytes = new Uint8Array(before.length + 1 + after.length);
    bytes.set(before); bytes[before.length] = 0xff; bytes.set(after, before.length + 1);
    mockFetch(jest.fn(async () => new Response(bytes)) as typeof fetch);
    await expect(api.complete()).rejects.toThrow();
    expect(api.signedIn()).toBe(false);
  });
});
