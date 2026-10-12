/** Regression: a legal sign-in (five-minute token) that expires during a long
 * evidence download must be renewable without leaving the page, and the
 * download must pause and resume instead of failing as "access changed". */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '../../..');
const g = globalThis as Record<string, unknown>;
const saved = ['window', 'fetch', 'BroadcastChannel'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const);
afterEach(() => {
  jest.resetModules();
  jest.useRealTimers();
  for (const [key, descriptor] of saved) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete g[key];
  }
});

async function until(check: () => boolean) {
  for (let i = 0; i < 200 && !check(); i++) await new Promise(resolve => setTimeout(resolve, 5));
  expect(check()).toBe(true);
}
type Listener = (event: { origin: string; data: unknown }) => void;
const channels: { name: string; onmessage: ((event: { data: unknown }) => void) | null; posted: unknown[]; closed: boolean }[] = [];
class FakeChannel {
  onmessage: ((event: { data: unknown }) => void) | null = null;
  posted: unknown[] = [];
  closed = false;
  constructor(readonly name: string) { channels.push(this); }
  postMessage(data: unknown) {
    this.posted.push(data);
    for (const other of channels) if (other !== this && !other.closed && other.name === this.name) other.onmessage?.({ data });
  }
  close() { this.closed = true; }
}
const config = { domain: 'identity.example', clientId: 'legal-client', audience: 'legal-api', organization: 'org_allowed' };
const b64url = (bytes: Buffer) => bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function openerWindow(popup: unknown) {
  const listeners = new Set<Listener>();
  const win = {
    location: { origin: 'https://vera.example', pathname: '/legal/report', search: '' },
    open: jest.fn(() => popup),
    addEventListener: (type: string, listener: Listener) => { if (type === 'message') listeners.add(listener); },
    removeEventListener: (type: string, listener: Listener) => { if (type === 'message') listeners.delete(listener); },
    sessionStorage: { getItem: jest.fn(), setItem: jest.fn(), removeItem: jest.fn() },
  };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: win });
  Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, value: FakeChannel });
  return { win, dispatch: (event: { origin: string; data: unknown }) => { for (const listener of [...listeners]) listener(event); } };
}

describe('legal sign-in renewal in a separate window', () => {
  beforeEach(() => { channels.length = 0; });

  test('same-account renewal keeps its workspace identity; another account or organization invalidates it', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { dispatch } = openerWindow(popup);
    let subject = 'email|first', organization = 'org_allowed';
    const fetcher = jest.fn(async () => new Response(JSON.stringify({ expires_in: 300, token_type: 'Bearer',
      access_token: `header.${Buffer.from(JSON.stringify({ sub: subject, org_id: organization })).toString('base64url')}.signature` })));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetcher });
    const changed = jest.fn();
    const unsubscribe = api.subscribeLegalIdentityChange(changed);
    const renew = async () => {
      const count = popup.location.replace.mock.calls.length;
      const pending = api.renewLegalSignIn({ ...config, organization });
      await until(() => popup.location.replace.mock.calls.length > count);
      const state = new URL(popup.location.replace.mock.calls[count][0]).searchParams.get('state');
      dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state, code: 'fresh-code' } });
      await pending;
    };
    await renew();
    const original = api.legalIdentityVersion();
    await renew();
    expect(api.legalIdentityVersion()).toBe(original);
    expect(changed).not.toHaveBeenCalled();
    // Expiring the token must not forget which account owns the open workspace.
    const clock = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 360_000);
    await expect(api.legalAccessToken(config)).rejects.toBeInstanceOf(api.LegalSignInRequired);
    subject = 'email|second';
    await renew();
    expect(api.legalIdentityVersion()).toBe(original + 1);
    expect(changed).toHaveBeenCalledTimes(1);
    organization = 'org_other';
    await renew();
    expect(api.legalIdentityVersion()).toBe(original + 2);
    expect(changed).toHaveBeenCalledTimes(2);
    unsubscribe(); clock.mockRestore();
  });

  test('first OTP attaches the approved firm then reuses its session without requesting another code', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, postMessage: jest.fn(), closed: false, focus: jest.fn() };
    const { dispatch } = openerWindow(popup);
    let entryNonce = '';
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const fetcher = jest.fn(async (_url: string, _init: { body: string }) => {
      if (fetcher.mock.calls.length === 1) {
        const now = Math.floor(Date.now() / 1000);
        return new Response(JSON.stringify({ access_token: 'unused-profile-token', expires_in: 86400,
          id_token: `${encode({ alg: 'RS256' })}.${encode({ iss: 'https://identity.example/', aud: 'legal-client', sub: 'email|approved',
            nonce: entryNonce, iat: now, exp: now + 300, 'https://vera.app/legal-entry': { organization: 'org_allowed' } })}.signature` }));
      }
      return new Response(JSON.stringify({ access_token: 'legal-authority', expires_in: 300, token_type: 'Bearer' }));
    });
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetcher });
    const promise = api.renewLegalSignIn({ ...config, connection: 'email' }, { firstSignIn: true });
    await until(() => popup.location.replace.mock.calls.length === 1);
    const first = new URL(popup.location.replace.mock.calls[0][0]);
    entryNonce = first.searchParams.get('nonce')!;
    expect(first.searchParams.get('scope')).toBe('openid email');
    expect(first.searchParams.get('connection')).toBe('email');
    expect(first.searchParams.has('organization')).toBe(false);
    expect(first.searchParams.get('audience')).toBe('https://identity.example/userinfo');
    const msg = { type: 'vera-legal-renewal', state: entryNonce, code: 'otp-code-result' };
    dispatch({ origin: 'https://vera.example', data: msg }); dispatch({ origin: 'https://vera.example', data: msg });
    await until(() => popup.postMessage.mock.calls.length === 1);
    expect(api.legalSignedIn()).toBe(false);
    const next = popup.postMessage.mock.calls[0][0];
    expect(next.organization).toBe('org_allowed'); expect(next.previousState).toBe(entryNonce);
    expect(next.state).not.toBe(entryNonce);
    expect(JSON.stringify(next)).not.toMatch(/unused-profile-token|code_verifier|id_token/);
    const finalUrl = new URL(api.authorizeUrl({ ...config, connection: 'email' }, { ...next, redirectUri: 'https://vera.example/legal', mode: 'session' }));
    expect(finalUrl.searchParams.get('organization')).toBe('org_allowed');
    expect(finalUrl.searchParams.get('audience')).toBe('legal-api');
    expect(finalUrl.searchParams.has('connection')).toBe(false);
    expect(finalUrl.searchParams.has('prompt')).toBe(false);
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state: next.state, code: 'org-code-result' } });
    await promise;
    expect(fetcher).toHaveBeenCalledTimes(2);
    await expect(api.legalAccessToken({ ...config, connection: 'email' })).resolves.toBe('legal-authority');
  });

  test('email renewal lets Auth0 reuse its session and show consent without a silent-probe round trip', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { win, dispatch } = openerWindow(popup);
    const fetcher = jest.fn(async (_url: string, _init: { body: string }) => new Response(JSON.stringify({ access_token: 'synthetic-token', expires_in: 300, token_type: 'Bearer' })));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetcher });
    const settings = { ...config, connection: 'email' };
    const renewed = api.renewLegalSignIn(settings);
    await until(() => popup.location.replace.mock.calls.length === 1);
    const authorize = new URL(popup.location.replace.mock.calls[0][0]);
    expect(authorize.searchParams.has('prompt')).toBe(false);
    expect(authorize.searchParams.has('connection')).toBe(false);
    expect(authorize.searchParams.get('state')).not.toMatch(/^renew\.probe\./);
    const message = { type: 'vera-legal-renewal', state: authorize.searchParams.get('state'), code: 'fresh-code' };
    dispatch({ origin: 'https://attacker.example', data: message });
    expect(popup.location.replace).toHaveBeenCalledTimes(1);
    expect(win.open).toHaveBeenCalledTimes(1);
    expect(fetcher).not.toHaveBeenCalled();
    dispatch({ origin: 'https://vera.example', data: message });
    dispatch({ origin: 'https://vera.example', data: message }); // Duplicate delivery.
    await expect(renewed).resolves.toBeUndefined();
    const request = new URLSearchParams(fetcher.mock.calls[0][1].body);
    expect(b64url(createHash('sha256').update(request.get('code_verifier')!).digest())).toBe(authorize.searchParams.get('code_challenge'));
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.legalSignedIn()).toBe(true);
  });

  test('a session-check popup stays open while its parent starts interactive MFA', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const location = { origin: 'https://vera.example', pathname: '/legal', search: '?error=interaction_required&state=renew.probe.synthetic' };
    const opener = { postMessage: jest.fn() }, close = jest.fn();
    Object.defineProperty(globalThis, 'window', { configurable: true, value: { location, opener, close,
      history: { replaceState: () => { location.search = ''; } } } });
    Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, value: FakeChannel });
    await expect(api.completeLegalSignIn({ ...config, connection: 'email' })).resolves.toBe(api.LEGAL_SIGN_IN_REDIRECTED);
    expect(opener.postMessage).toHaveBeenCalledWith({ type: 'vera-legal-renewal', state: 'renew.probe.synthetic', code: null, error: 'interaction_required' }, location.origin);
    expect(close).not.toHaveBeenCalled();
    expect(api.legalSignedIn()).toBe(false);
  });

  test('renews the token in this page, bound to its own PKCE verifier and state', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { win, dispatch } = openerWindow(popup);
    const fetch = jest.fn(async (_url: string, _init: { body: string }) => new Response(
      JSON.stringify({ access_token: 'synthetic-renewed-token', expires_in: 300, token_type: 'Bearer' })));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetch });
    await expect(api.legalAccessToken(config)).rejects.toBeInstanceOf(api.LegalSignInRequired);

    const renewed = api.renewLegalSignIn(config);
    // Opened synchronously (inside the click), never by navigating this page.
    expect(win.open).toHaveBeenCalledTimes(1);
    expect(win.open).toHaveBeenCalledWith('', 'vera-legal-sign-in');
    expect(win.sessionStorage.setItem).not.toHaveBeenCalled();
    expect(api.renewLegalSignIn(config)).toBe(renewed); // One renewal at a time.
    await until(() => popup.location.replace.mock.calls.length > 0);
    const authorize = new URL(popup.location.replace.mock.calls[0][0]);
    expect(authorize.origin).toBe('https://identity.example');
    expect(authorize.searchParams.get('redirect_uri')).toBe('https://vera.example/legal');
    expect(authorize.searchParams.get('scope')).toBe('openid legal:directory legal:case legal:enroll');
    expect(authorize.searchParams.get('organization')).toBe('org_allowed');
    const state = authorize.searchParams.get('state')!;
    expect(state).toMatch(/^renew\./);

    // Wrong state, wrong origin, or a message from elsewhere are ignored.
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state: 'renew.other', code: 'x' } });
    dispatch({ origin: 'https://attacker.example', data: { type: 'vera-legal-renewal', state, code: 'x' } });
    expect(fetch).not.toHaveBeenCalled();

    // The sign-in window relays the one-use code; this page exchanges it.
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state, code: 'one-use-code' } });
    new FakeChannel('vera-legal-renewal').postMessage({ type: 'vera-legal-renewal', state, code: 'one-use-code' }); // Duplicate copy.
    await expect(renewed).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(1);
    const body = new URLSearchParams(fetch.mock.calls[0][1].body);
    expect(body.get('code')).toBe('one-use-code');
    expect(b64url(createHash('sha256').update(body.get('code_verifier')!).digest())).toBe(authorize.searchParams.get('code_challenge'));
    await expect(api.legalAccessToken(config)).resolves.toBe('synthetic-renewed-token');
  });

  test('popup enrollment replaces the previous firm routing context without persisting its token', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { win, dispatch } = openerWindow(popup);
    const storage = new Map<string, string>();
    win.sessionStorage.getItem.mockImplementation(key => storage.get(key) ?? null);
    win.sessionStorage.setItem.mockImplementation((key, value) => { storage.set(key, value); });
    const env = { ...process.env };
    process.env.NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN = config.domain;
    process.env.NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID = config.clientId;
    process.env.NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE = config.audience;
    process.env.NEXT_PUBLIC_LEGAL_AUTH0_ORGANIZATION = '';
    process.env.NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION = '';
    storage.set('vera-legal-organization', JSON.stringify({
      binding: JSON.stringify([win.location.origin, config.domain, config.clientId, config.audience]), organization: 'org_previous',
    }));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: jest.fn(async () => new Response(
      JSON.stringify({ access_token: 'new-firm-private-token', expires_in: 300, token_type: 'Bearer' }))) });
    try {
      expect(api.legalAuthConfig().organization).toBe('org_previous');
      const renewed = api.renewLegalSignIn(config);
      await until(() => popup.location.replace.mock.calls.length > 0);
      const state = new URL(popup.location.replace.mock.calls[0][0]).searchParams.get('state');
      dispatch({ origin: win.location.origin, data: { type: 'vera-legal-renewal', state, code: 'one-use-code' } });
      await renewed;
      const routed = api.legalAuthConfig();
      expect(routed.organization).toBe(config.organization);
      await expect(api.legalAccessToken(routed)).resolves.toBe('new-firm-private-token');
      expect([...storage.values()].join('')).not.toMatch(/new-firm-private-token|one-use-code/);
      await expect(api.legalAccessToken({ ...routed, organization: 'org_previous' })).rejects.toBeInstanceOf(api.LegalSignInRequired);
    } finally { process.env = env; }
  });

  test('a blocked window, a cancelled sign-in or a closed window never leaves renewal stuck', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const { win, dispatch } = openerWindow(null);
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: jest.fn() });
    await expect(api.renewLegalSignIn(config)).rejects.toBeInstanceOf(api.LegalPopupBlocked);

    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    win.open.mockImplementation(() => popup);
    const first = api.renewLegalSignIn(config);
    await until(() => popup.location.replace.mock.calls.length > 0);
    popup.closed = true;
    const second = api.renewLegalSignIn(config);
    expect(second).not.toBe(first);
    await expect(first).rejects.toBeInstanceOf(api.LegalSignInRequired);
    await until(() => popup.location.replace.mock.calls.length > 1);
    const state = new URL(popup.location.replace.mock.calls[1][0]).searchParams.get('state');
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state, code: null } }); // Error at the IdP.
    await expect(second).rejects.toBeInstanceOf(api.LegalSignInRequired);
    expect(g.fetch).not.toHaveBeenCalled();
  });

  test('the user can cancel a stalled sign-in and retry with fresh PKCE state', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { dispatch } = openerWindow(popup);
    const fetcher = jest.fn(async () => new Response(JSON.stringify({ access_token: 'retry-token', expires_in: 300, token_type: 'Bearer' })));
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetcher });
    const first = api.renewLegalSignIn(config);
    await until(() => popup.location.replace.mock.calls.length === 1);
    const oldState = new URL(popup.location.replace.mock.calls[0][0]).searchParams.get('state');
    api.cancelLegalSignInRenewal();
    await expect(first).rejects.toBeInstanceOf(api.LegalSignInRequired);
    const second = api.renewLegalSignIn(config);
    await until(() => popup.location.replace.mock.calls.length === 2);
    const state = new URL(popup.location.replace.mock.calls[1][0]).searchParams.get('state');
    expect(state).not.toBe(oldState);
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state: oldState, code: 'stale' } });
    expect(fetcher).not.toHaveBeenCalled();
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state, code: 'current' } });
    await expect(second).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  test.each(['headers', 'body'])('a closed callback popup shares the renewal while token %s are pending', async phase => {
    const api = require('../../../lib/confidential/legalAuth');
    const popup = { location: { replace: jest.fn() }, closed: false, focus: jest.fn() };
    const { win, dispatch } = openerWindow(popup);
    const payload = JSON.stringify({ access_token: 'shared-token', expires_in: 300, token_type: 'Bearer' });
    let deliver!: () => void;
    const response = phase === 'headers'
      ? new Promise<Response>(resolve => { deliver = () => resolve(new Response(payload)); })
      : Promise.resolve(new Response(new ReadableStream({ start(controller) {
        deliver = () => { controller.enqueue(new TextEncoder().encode(payload)); controller.close(); };
      } })));
    const fetch = jest.fn(() => response);
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetch });
    const first = api.renewLegalSignIn(config);
    await until(() => popup.location.replace.mock.calls.length > 0);
    const state = new URL(popup.location.replace.mock.calls[0][0]).searchParams.get('state');
    dispatch({ origin: 'https://vera.example', data: { type: 'vera-legal-renewal', state, code: 'one-code' } });
    popup.closed = true;
    const second = api.renewLegalSignIn(config);
    expect(second).toBe(first);
    expect(win.open).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
    deliver();
    await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);
    await expect(api.legalAccessToken(config)).resolves.toBe('shared-token');
  });

  test('the sign-in window hands the code back and exchanges nothing itself', async () => {
    const api = require('../../../lib/confidential/legalAuth');
    const location = { origin: 'https://vera.example', pathname: '/legal', search: '?code=one-use-code&state=renew.abc' };
    const opener = { postMessage: jest.fn() };
    const close = jest.fn();
    const storage = { getItem: jest.fn(() => null), removeItem: jest.fn() };
    Object.defineProperty(globalThis, 'window', { configurable: true, value: { location, opener, close, sessionStorage: storage,
      history: { replaceState: () => { location.search = ''; } } } });
    Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, value: FakeChannel });
    const fetch = jest.fn();
    Object.defineProperty(globalThis, 'fetch', { configurable: true, value: fetch });
    await expect(api.completeLegalSignIn(config)).resolves.toBe(api.LEGAL_RENEWAL_RELAYED);
    expect(location.search).toBe('');
    expect(fetch).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled(); // A pending full sign-in in this tab is left alone.
    const message = { type: 'vera-legal-renewal', state: 'renew.abc', code: 'one-use-code' };
    expect(opener.postMessage).toHaveBeenCalledWith(message, 'https://vera.example'); // Same origin only.
    expect(channels[0].posted).toEqual([message]);
    expect(close).toHaveBeenCalled();
    expect(api.legalSignedIn()).toBe(false);
  });
});

describe('an expired sign-in pauses a chunked download', () => {
  test('stops without re-verifying or discarding, and resumes where it stopped', async () => {
    const { LegalSignInRequired } = require('../../../lib/confidential/legalAuth');
    const { EvidenceDownload } = require('../../../lib/confidential/evidenceTransfer');
    const chunks = [new Uint8Array([1, 2]), new Uint8Array([3, 4]), new Uint8Array([5, 6])];
    let signedIn = true, opens = 0;
    const written: number[] = [];
    const sink = { write: async (bytes: Uint8Array) => { written.push(...bytes); }, close: jest.fn(async () => undefined), abort: jest.fn(async () => undefined) };
    const open = async () => {
      opens += 1;
      if (!signedIn) throw new LegalSignInRequired();
      return {
        reader: { index: { chunkCount: 3 }, size: 6, digest: 'd'.repeat(64), dispose: () => undefined,
          openChunk: async (_position: number, ciphertext: Uint8Array) => new Uint8Array(ciphertext) },
        fetchChunk: async (position: number) => {
          if (position === 1 && opens === 1) signedIn = false; // The token expires mid-transfer.
          if (!signedIn) throw new LegalSignInRequired();
          return new Uint8Array(chunks[position]);
        },
      };
    };
    const download = new EvidenceDownload(sink, open);
    await expect(download.run()).rejects.toBeInstanceOf(LegalSignInRequired);
    expect(opens).toBe(1); // Not mistaken for a report change.
    expect(written).toEqual([1, 2]);
    expect(sink.abort).not.toHaveBeenCalled();
    signedIn = true; // Renewed in the separate window.
    await download.run();
    expect(written).toEqual([1, 2, 3, 4, 5, 6]);
    expect(sink.close).toHaveBeenCalledTimes(1);
  });

  test('the download UI offers an in-page sign-in instead of the generic access message', () => {
    const button = readFileSync(path.join(ROOT, 'components/vera/confidential/EvidenceDownloadButton.tsx'), 'utf8');
    expect(button).toMatch(/signIn\?\.required\(error\)[\s\S]*?kind: "sign-in"/);
    expect(button).toContain('Sign in again to continue');
    expect(button).toMatch(/signIn\.renew\(\)\.then\(\(\) => \{ if \(mounted\.current\) void run\(true\)/);
    const report = readFileSync(path.join(ROOT, 'components/vera/confidential/LegalReportView.tsx'), 'utf8');
    expect(report).toMatch(/function ChunkedFileRow[\s\S]*?signIn=\{DOWNLOAD_SIGN_IN\}/);
    expect(report).toMatch(/DOWNLOAD_SIGN_IN = \{[\s\S]*?renewLegalSignIn\(config\)/);
    expect(report).not.toContain('beginLegalSignIn');
    const portal = readFileSync(path.join(ROOT, 'components/vera/confidential/LegalPortal.tsx'), 'utf8');
    // The expiry banner renews in a window first; a full-page sign-in is only an explicit fallback.
    expect(portal).toMatch(/\{expired && [\s\S]*?renewLegalSignIn\(gate\.config\)[\s\S]*?Sign in on this page instead/);
    expect(portal).toMatch(/next === LEGAL_RENEWAL_RELAYED/);
  });
});
