import {
  proxySubmitQuotaKeyCountForTests,
  resetProxySubmitQuotaForTests,
  tryAdmitSubmitProxy,
} from '../../../src/utils/proxySubmitQuota';

describe('proxySubmitQuota memory bound', () => {
  const secret = 'synthetic-submit-quota-memory-secret-at-least-32';

  beforeEach(() => {
    process.env.INTERNAL_API_SECRET = secret;
    process.env.FRONTEND_TRUST_PROXY_HOPS = '0';
    resetProxySubmitQuotaForTests();
  });

  afterEach(() => {
    jest.useRealTimers();
    resetProxySubmitQuotaForTests();
  });

  function req(ip: string) {
    return { headers: {}, socket: { remoteAddress: ip } };
  }

  it('deletes expired quota keys instead of retaining empty entries', () => {
    jest.useFakeTimers();
    const now = 1_700_000_000_000;
    jest.setSystemTime(now);

    for (let i = 0; i < 50; i++) {
      expect(tryAdmitSubmitProxy(req(`198.51.${Math.floor(i / 256)}.${i % 256}`))).toBe(true);
    }
    expect(proxySubmitQuotaKeyCountForTests()).toBe(50);

    jest.setSystemTime(now + 15 * 60 * 1000 + 1);
    expect(tryAdmitSubmitProxy(req('203.0.113.50'))).toBe(true);
    // Unpatched code kept all 50 stale keys plus the new one (51). Fixed code retains only live keys.
    expect(proxySubmitQuotaKeyCountForTests()).toBe(1);
  });

  it('refuses new quota keys once the live-key capacity is reached', () => {
    jest.useFakeTimers();
    jest.setSystemTime(1_700_000_000_000);

    const maxKeys = 10_000;
    for (let i = 0; i < maxKeys; i++) {
      const a = Math.floor(i / 65_536);
      const b = Math.floor((i % 65_536) / 256);
      const c = i % 256;
      expect(tryAdmitSubmitProxy(req(`203.${a}.${b}.${c}`))).toBe(true);
    }
    expect(proxySubmitQuotaKeyCountForTests()).toBe(maxKeys);

    expect(tryAdmitSubmitProxy(req('198.51.100.1'))).toBe(false);
    expect(proxySubmitQuotaKeyCountForTests()).toBe(maxKeys);
  });
});
