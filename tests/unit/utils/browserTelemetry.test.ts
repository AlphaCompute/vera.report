import { installBrowserTelemetry } from '../../../lib/browserTelemetry';

describe('browser telemetry', () => {
  const descriptors = new Map<string, PropertyDescriptor | undefined>();
  let browser: EventTarget & { fetch: typeof fetch; setTimeout: typeof setTimeout; clearTimeout: typeof clearTimeout };
  let transport: jest.Mock;
  beforeEach(() => {
    jest.useFakeTimers();
    transport = jest.fn().mockResolvedValue({ ok: true });
    browser = Object.assign(new EventTarget(), { fetch: transport, setTimeout, clearTimeout });
    for (const [name, value] of Object.entries({ window: browser, location: { pathname: '/admin', origin: 'https://vera.report' } })) {
      descriptors.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
      Object.defineProperty(globalThis, name, { configurable: true, value });
    }
  });
  afterEach(() => {
    for (const [name, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete (globalThis as Record<string, unknown>)[name];
    }
    jest.useRealTimers();
  });
  test('emits bounded events without error content, then removes hooks', () => {
    const stop = installBrowserTelemetry();
    const event = Object.assign(new Event('error'), { message: 'private report', filename: '/status/secret' });
    for (let i = 0; i < 20; i++) browser.dispatchEvent(event);
    expect(transport).toHaveBeenCalledTimes(10);
    const [url, options] = transport.mock.calls[0];
    expect(url).toBe('/api/monitoring/client');
    expect(options.credentials).toBe('omit');
    expect(options.referrerPolicy).toBe('no-referrer');
    expect(JSON.parse(options.body)).toEqual({ kind: 'exception', page: '/admin', value: 1 });
    expect(JSON.stringify(transport.mock.calls)).not.toMatch(/private|secret/);
    stop();
    expect(browser.fetch).toBe(transport);
    browser.dispatchEvent(event);
    expect(transport).toHaveBeenCalledTimes(10);
  });
  test('preserves failed API response and rejection; collector cannot recurse', async () => {
    const failure = new Error('private body');
    transport.mockResolvedValueOnce({ ok: false, status: 503 });
    const stop = installBrowserTelemetry();
    const result = await browser.fetch('/api/vault/list?secret=hidden');
    expect(result.status).toBe(503);
    expect(JSON.parse(transport.mock.calls[1][1].body).kind).toBe('request_failure');
    transport.mockRejectedValueOnce(failure);
    await expect(browser.fetch('/api/vault/list')).rejects.toBe(failure);
    expect(transport).toHaveBeenCalledTimes(4);
    transport.mockResolvedValueOnce({ ok: false, status: 503 });
    await browser.fetch('/api/monitoring/client');
    expect(transport).toHaveBeenCalledTimes(5);
    stop();
  });
  test('does not send telemetry from reporter routes or for private API failures', async () => {
    const stop = installBrowserTelemetry();
    transport.mockResolvedValueOnce({ ok: false, status: 503 });
    await browser.fetch('/api/whistleblower/submit');
    expect(transport).toHaveBeenCalledTimes(1);
    location.pathname = '/status/private-token';
    browser.dispatchEvent(new Event('error'));
    expect(transport).toHaveBeenCalledTimes(1);
    stop();
  });

  test.each(['/legal', '/legal/keys', '/legal/administration', '/legal/enroll', '/legal/report', '/legal/members', '/legal/join', '/legal/cases/private-case'])
    ('sends no operational or exception telemetry from %s', async pathname => {
      location.pathname = pathname;
      const stop = installBrowserTelemetry();
      browser.dispatchEvent(new Event('error'));
      browser.dispatchEvent(new Event('unhandledrejection'));
      transport.mockResolvedValueOnce({ ok: false, status: 503 });
      await browser.fetch('/api/public-config');
      expect(transport).toHaveBeenCalledTimes(1);
      expect(transport.mock.calls[0][0]).toBe('/api/public-config');
      stop();
    });

});
