/** Legal-organization sign-in: Auth0 authorization code + PKCE against the
 * SEPARATE legal Auth0 application (NEXT_PUBLIC_LEGAL_AUTH0_*). It never uses
 * the admin session, admin cookies or admin roles. Tokens are kept in memory
 * only (no cookies or web storage); the PKCE verifier and state live in
 * sessionStorage for the length of one redirect. No third-party script is
 * loaded: the browser talks to the Auth0 endpoints with fetch.
 *
 * Login alone grants nothing: every case operation also needs a firm-key
 * signature, and case contents need the owner's grant.
 */
import { exchangeIdentityToken, exchangeLegalEntry } from './identityToken';
import { setupFromIdentityToken } from './legalSetup';
export type LegalAuthConfig = { domain: string; clientId: string; audience: string; organization: string | null; connection?: string };
export class LegalSignInRequired extends Error {
  constructor() { super('Please sign in again to continue.'); }
}

const PENDING_KEY = 'vera-legal-auth-pending';
// The measured legal policy requires approved-member assurance and does not issue
// offline legal authority. An IdP browser session can still simplify return login.
const SCOPE = 'openid legal:directory legal:case legal:enroll';
export const LEGAL_CALLBACK_PATH = '/legal';
const CALLBACK_PATH = LEGAL_CALLBACK_PATH;
let tokens: { accessToken: string; expiresAt: number } | null = null;
let tokenGeneration = 0;
let identityVersion = 0;
let lastIdentity: string | null = null;
const identityListeners = new Set<() => void>();
/** Local isolation only. The enclave independently verifies the JWT and membership. */
export function legalIdentityVersion(): number { return identityVersion; }
export function subscribeLegalIdentityChange(listener: () => void): () => void {
  identityListeners.add(listener);
  return () => { identityListeners.delete(listener); };
}
function identityLabel(token: string, config: LegalAuthConfig): string | null {
  try {
    const part = token.split('.')[1];
    const claims = JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')));
    if (typeof claims.sub !== 'string' || !claims.sub || typeof claims.org_id !== 'string' || !claims.org_id) return null;
    return JSON.stringify([config.domain, config.clientId, config.audience, claims.sub, claims.org_id]);
  } catch { return null; }
}
const ORGANIZATION_KEY = 'vera-legal-organization';
let invitation: { invitation: string; organization: string } | null = null;
const organizationId = (value: unknown): value is string => typeof value === 'string' && /^org_[a-zA-Z0-9]{1,64}$/.test(value);
const identityBinding = (config: LegalAuthConfig) => JSON.stringify([window.location.origin, config.domain, config.clientId, config.audience,
  ...(config.connection ? [config.connection] : [])]);
let tokenBinding: string | null = null;
const sessionBinding = (config: LegalAuthConfig) => JSON.stringify([identityBinding(config), config.organization]);

/** Auth0 organization invitations land here. Remove the credential from the URL
 * before rendering or starting any network work; keep it only until sign-in. */
export function consumeLegalInvitation(config?: LegalAuthConfig): boolean {
  const params = new URLSearchParams(window.location.search);
  if (!params.has('invitation') && !params.has('organization')) return !!invitation;
  window.history.replaceState(null, '', window.location.pathname + (window.location.hash ?? ''));
  const id = params.get('invitation'), organization = params.get('organization');
  invitation = null;
  tokens = null; tokenBinding = null; tokenGeneration++; renewal?.abandon();
  if (window.location.pathname !== CALLBACK_PATH || params.getAll('invitation').length !== 1 ||
      params.getAll('organization').length !== 1 || params.has('code') || params.has('error') ||
      !id || !/^[A-Za-z0-9_-]{1,512}$/.test(id) || !organizationId(organization) || (config?.organization && config.organization !== organization)) throw new LegalSignInRequired();
  invitation = { invitation: id, organization };
  return true;
}
function selectedOrganization(config: LegalAuthConfig): string | null {
  if (config.organization) return config.organization;
  if (invitation) return invitation.organization;
  try {
    const saved = JSON.parse(window.sessionStorage.getItem(ORGANIZATION_KEY) ?? 'null');
    if (saved?.binding === identityBinding(config) && organizationId(saved.organization)) return saved.organization;
  } catch { /* No persisted organization context. */ }
  return config.organization;
}


export function legalAuthConfig(): LegalAuthConfig | null {
  // Literal references so Next inlines them at build time.
  const domain = process.env.NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN ?? '';
  const clientId = process.env.NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID ?? '';
  const audience = process.env.NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE ?? '';
  const organization = process.env.NEXT_PUBLIC_LEGAL_AUTH0_ORGANIZATION ?? '';
  const connection = process.env.NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION ?? '';
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) || !/^[A-Za-z0-9_-]{8,128}$/.test(clientId) ||
      !audience || audience.length > 512 || (organization && !/^org_[a-zA-Z0-9]{1,64}$/.test(organization)) ||
      (connection && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(connection))) return null;
  const config = { domain, clientId, audience, organization: organization || null, ...(connection ? { connection } : {}) };
  return { ...config, organization: typeof window === 'undefined' || new URLSearchParams(window.location.search).has('invitation') ? config.organization : selectedOrganization(config) };
}

export function base64url(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
/** RFC 7636 S256 code challenge. */
export async function pkceChallenge(verifier: string): Promise<string> {
  return base64url(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}
/** A same-origin /legal path, optionally with a case-ID fragment (legalCaseLink.ts).
 * The fragment stays in sessionStorage and the local URL only, never in the
 * identity provider redirect. */
export function safeReturnPath(value: unknown): string {
  return typeof value === 'string' && /^\/legal(?:\/[A-Za-z0-9/_-]*)?(?:#[a-f0-9]{64})?$/.test(value) && !value.includes('//')
    ? value : CALLBACK_PATH;
}
function redirectUri(): string { return `${window.location.origin}${CALLBACK_PATH}`; }

type SignInMode = 'login' | 'probe' | 'session' | 'entry';
// An explicit passwordless connection forces a fresh email code even when an
// Auth0 session exists. Let Auth0 check its own session first; no local device
// flag, saved key or email address is evidence of an authenticated session.
function initialMode(config: LegalAuthConfig): SignInMode { return config.connection === 'email' ? config.organization ? 'probe' : 'entry' : 'login'; }
function retryMode(mode: unknown, error: unknown): SignInMode | null {
  if (mode !== 'probe') return null;
  if (error === 'login_required') return 'login';
  if (error === 'interaction_required' || error === 'consent_required') return 'session';
  return null;
}
export function authorizeUrl(config: LegalAuthConfig, input: { challenge: string; state: string; redirectUri: string; invitation?: string; mode?: SignInMode }): string {
  const params = new URLSearchParams({ response_type: 'code', client_id: config.clientId, redirect_uri: input.redirectUri,
    scope: SCOPE, audience: config.audience, code_challenge: input.challenge, code_challenge_method: 'S256', state: input.state });
  if (input.mode === 'entry') { params.set('scope', 'openid email'); params.set('audience', `https://${config.domain}/userinfo`); params.set('nonce', input.state); }
  else if (config.organization) params.set('organization', config.organization);
  if (config.connection && (!input.mode || input.mode === 'login' || input.mode === 'entry')) params.set('connection', config.connection);
  if (input.mode === 'probe') params.set('prompt', 'none');
  if (input.invitation) params.set('invitation', input.invitation);
  return `https://${config.domain}/authorize?${params.toString()}`;
}

export async function beginLegalSignIn(config: LegalAuthConfig, returnPath: string): Promise<void> {
  return redirectLegalSignIn(config, returnPath, invitation ? 'login' : initialMode(config));
}
async function redirectLegalSignIn(config: LegalAuthConfig, returnPath: string, mode: SignInMode): Promise<void> {
  tokens = null; tokenBinding = null; const generation = ++tokenGeneration; renewal?.abandon();
  const settings = { ...config, organization: selectedOrganization(config) };
  const acceptedInvitation = invitation;
  const verifier = base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const state = base64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  const challenge = await pkceChallenge(verifier);
  if (generation !== tokenGeneration) throw new LegalSignInRequired();
  window.sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, returnPath: safeReturnPath(returnPath), binding: identityBinding(settings), organization: settings.organization, mode }));
  window.sessionStorage.setItem(ORGANIZATION_KEY, JSON.stringify({ binding: identityBinding(settings), organization: settings.organization }));
  invitation = null;
  window.location.assign(authorizeUrl(settings, { challenge, state, redirectUri: redirectUri(), invitation: acceptedInvitation?.invitation, mode }));
}

async function tokenRequest(config: LegalAuthConfig, body: Record<string, string>): Promise<void> {
  const generation = ++tokenGeneration;
  try {
    const next = await exchangeIdentityToken(config.domain, config.clientId, body);
    if (generation !== tokenGeneration) throw new LegalSignInRequired();
    const identity = identityLabel(next.accessToken, config);
    // Expiry alone keeps the open key. A different account/organization (or an
    // unreadable identity) cannot inherit private state from the previous login.
    if (identity === null || identity !== lastIdentity) {
      const replacing = identityVersion > 0;
      identityVersion++;
      lastIdentity = identity;
      if (replacing) for (const listener of identityListeners) listener();
    }
    tokens = next; tokenBinding = sessionBinding(config);
    // Popup enrollment can select a different approved firm than the previous
    // full-page login. Keep only its nonsecret routing context for /legal;
    // otherwise that route rejects the new token against the old organization.
    try { window.sessionStorage.setItem(ORGANIZATION_KEY, JSON.stringify({
      binding: identityBinding(config), organization: config.organization,
    })); } catch { /* Tokens remain memory-only when storage is unavailable. */ }
  } catch { throw new LegalSignInRequired(); }
}

/** Call on the /legal callback. Removes code/state from the URL before any
 * other work. Returns the page to continue on, or null when this is not a callback. */
let callbackCompletion: { binding: string; promise: Promise<string | null> } | null = null;
/** React effect replay must await the same code exchange after URL/state removal.
 * Never share an exchange with another identity configuration or origin. */
export function completeLegalSignIn(config: LegalAuthConfig): Promise<string | null> {
  const settings = { ...config };
  const binding = JSON.stringify([window.location.origin, CALLBACK_PATH, settings.domain,
    settings.clientId, settings.audience, settings.organization, settings.connection ?? null]);
  if (callbackCompletion) {
    return callbackCompletion.binding === binding ? callbackCompletion.promise : Promise.reject(new LegalSignInRequired());
  }
  const promise = consumeSignInCallback(settings).finally(() => {
    if (callbackCompletion?.promise === promise) callbackCompletion = null;
  });
  callbackCompletion = { binding, promise };
  return promise;
}
async function consumeSignInCallback(config: LegalAuthConfig): Promise<string | null> {
  const params = new URLSearchParams(window.location.search);
  if (params.has('invitation') || params.has('organization')) {
    consumeLegalInvitation(config);
    await beginLegalSignIn(config, '/legal/enroll');
    return LEGAL_INVITATION_REDIRECTED;
  }
  if (!params.has('code') && !params.has('error')) return null;
  const code = params.get('code'), state = params.get('state'), error = params.get('error');
  window.history.replaceState(null, '', window.location.pathname);
  if (params.getAll('state').length !== 1 || params.getAll('code').length > 1 || params.getAll('error').length > 1 || (code && error)) throw new LegalSignInRequired();
  // A renewal window hands the code to the page that opened it and does no
  // exchange itself: only that page holds the PKCE verifier.
  if (state && state.startsWith(RENEWAL_STATE_PREFIX)) {
    if (code && state.startsWith(RENEWAL_ENTRY_PREFIX)) {
      waitForOrganizationRedirect(config, state);
      relayRenewal({ type: RENEWAL_MESSAGE, state, code }, false);
      return LEGAL_SIGN_IN_REDIRECTED;
    }
    const retry = !code && state.startsWith(RENEWAL_PROBE_PREFIX) && retryMode('probe', error);
    relayRenewal({ type: RENEWAL_MESSAGE, state, code: code ?? null, ...(error ? { error } : {}) }, !retry);
    if (retry) return LEGAL_SIGN_IN_REDIRECTED;
    return LEGAL_RENEWAL_RELAYED;
  }
  const raw = window.sessionStorage.getItem(PENDING_KEY);
  window.sessionStorage.removeItem(PENDING_KEY);
  let pending: { verifier?: unknown; state?: unknown; returnPath?: unknown; binding?: unknown; organization?: unknown; mode?: unknown } | null = null;
  try { pending = raw ? JSON.parse(raw) : null; } catch { pending = null; }
  if (!state || !pending || pending.state !== state || typeof pending.verifier !== 'string') throw new LegalSignInRequired();
  if (pending.binding !== identityBinding(config) || pending.organization !== config.organization) throw new LegalSignInRequired();
  const retry = config.connection === 'email' && !code && retryMode(pending.mode, error);
  if (retry) {
    await redirectLegalSignIn(config, safeReturnPath(pending.returnPath), retry);
    return LEGAL_SIGN_IN_REDIRECTED;
  }
  if (!code) throw new LegalSignInRequired();
  if (pending.mode === 'entry') {
    const generation = tokenGeneration;
    const organization = await exchangeLegalEntry(config.domain, config.clientId, state,
      { grant_type: 'authorization_code', code, code_verifier: pending.verifier, redirect_uri: redirectUri() });
    if (generation !== tokenGeneration || config.organization && organization !== config.organization) throw new LegalSignInRequired();
    await redirectLegalSignIn({ ...config, organization }, safeReturnPath(pending.returnPath), 'session');
    return LEGAL_SIGN_IN_REDIRECTED;
  }
  await tokenRequest(config, { grant_type: 'authorization_code', code, code_verifier: pending.verifier, redirect_uri: redirectUri() });
  return safeReturnPath(pending.returnPath);
}

export function legalSignedIn(): boolean { return !!tokens && (tokens.expiresAt - 30_000 > Date.now()); }

/** Read setup labels only from this in-memory, identity-bound login. No token or
 * setup details are copied to browser storage. This does not authorize access. */
export function legalSetupContext(config: LegalAuthConfig) {
  return tokens && tokenBinding === sessionBinding(config) && legalSignedIn()
    ? setupFromIdentityToken(tokens.accessToken, config) : null;
}

/** Five-minute approved-member tokens. Renewal requires authorization again
 * (beginLegalSignIn, or renewLegalSignIn to keep this page and its work). */
export async function legalAccessToken(config: LegalAuthConfig): Promise<string> {
  if (tokens && tokenBinding === sessionBinding(config) && tokens.expiresAt - 30_000 > Date.now()) return tokens.accessToken;
  tokens = null;
  throw new LegalSignInRequired();
}

export function signOutLegal(config: LegalAuthConfig): void {
  tokens = null; tokenBinding = null; invitation = null; tokenGeneration++; renewal?.abandon();
  identityVersion++; lastIdentity = null;
  try { window.sessionStorage.removeItem(ORGANIZATION_KEY); window.sessionStorage.removeItem(PENDING_KEY); } catch { /* Logout must still proceed. */ }
  const params = new URLSearchParams({ client_id: config.clientId, returnTo: `${window.location.origin}${CALLBACK_PATH}` });
  window.location.assign(`https://${config.domain}/v2/logout?${params.toString()}`);
}

/** Returned by completeLegalSignIn in a renewal window after it handed the
 * sign-in back to the page that opened it; that window has nothing else to do. */
export const LEGAL_RENEWAL_RELAYED = 'renewal-relayed';
export const LEGAL_INVITATION_REDIRECTED = 'invitation-redirected';
export const LEGAL_SIGN_IN_REDIRECTED = 'sign-in-redirected';
/** The browser blocked the sign-in window. */
export class LegalPopupBlocked extends Error {
  constructor() { super('Your browser blocked the sign-in window. Allow pop-up windows for this site, then try again.'); }
}
const RENEWAL_STATE_PREFIX = 'renew.';
const RENEWAL_PROBE_PREFIX = 'renew.probe.';
const RENEWAL_ENTRY_PREFIX = 'renew.entry.';
const RENEWAL_MESSAGE = 'vera-legal-renewal';
const RENEWAL_CHANNEL = 'vera-legal-renewal';
const RENEWAL_TIMEOUT_MS = 10 * 60_000;
type RenewalMessage = { type: typeof RENEWAL_MESSAGE; state: string; code: string | null; error?: string };
let renewal: { promise: Promise<void>; popup: Window | null; exchanging: () => boolean; abandon: () => void } | null = null;

/** End a stalled sign-in without navigating away from the in-memory key. */
export function cancelLegalSignInRenewal(): void { renewal?.abandon(); }

function relayRenewal(message: RenewalMessage, close = true): void {
  // Same-origin only. The code alone is useless without the opener's PKCE verifier.
  try { window.opener?.postMessage(message, window.location.origin); } catch { /* opener gone or severed */ }
  try {
    const channel = new BroadcastChannel(RENEWAL_CHANNEL);
    channel.postMessage(message);
    channel.close();
  } catch { /* unsupported */ }
  if (close) { try { window.close(); } catch { /* not script-closable */ } }
}

/** The IdP may sever window.opener. The callback tab listens before relaying
 * its code, then navigates itself using a fixed issuer/client/callback. No URL,
 * verifier, private key or token is accepted from another tab. */
function waitForOrganizationRedirect(config: LegalAuthConfig, previousState: string): void {
  let channel: BroadcastChannel | null = null, done = false;
  const finish = () => { done = true; clearTimeout(timer); window.removeEventListener('message', onMessage); channel?.close(); };
  const receive = (value: any) => {
    if (done || value?.type !== 'vera-legal-entry-continue' || value.previousState !== previousState ||
        !organizationId(value.organization) || !/^renew\.[A-Za-z0-9_-]{22}$/.test(value.state || '') ||
        !/^[A-Za-z0-9_-]{43}$/.test(value.challenge || '')) return;
    finish();
    window.location.replace(authorizeUrl({ ...config, organization: value.organization },
      { challenge: value.challenge, state: value.state, redirectUri: redirectUri(), mode: 'session' }));
  };
  const onMessage = (event: MessageEvent) => { if (event.origin === window.location.origin) receive(event.data); };
  const timer = setTimeout(finish, RENEWAL_TIMEOUT_MS);
  window.addEventListener('message', onMessage);
  try { channel = new BroadcastChannel(RENEWAL_CHANNEL); channel.onmessage = event => receive(event.data); } catch { /* opener fallback */ }
}

/** Renews the legal sign-in in a separate window, without leaving this page, so
 * in-memory work (an evidence download, its file, the unlocked key) survives.
 * Call straight from a click: the window must open within the user gesture.
 * The same authorize request as a full sign-in (same scopes, assurance and
 * organization), bound to a fresh PKCE verifier and state that stay in this
 * page's memory; the window only relays the one-use code back. */
export function renewLegalSignIn(config: LegalAuthConfig, options: { firstSignIn?: boolean } = {}): Promise<void> {
  if (renewal) {
    // The callback closes its popup after delivering the code. Both the portal
    // and a report may request renewal while that code is still being exchanged.
    if (renewal.exchanging()) return renewal.promise;
    let closed = true;
    try { closed = !renewal.popup || renewal.popup.closed; } catch { /* treat as closed */ }
    if (!closed) {
      try { renewal.popup!.focus(); } catch { /* ignore */ }
      return renewal.promise;
    }
    // The window was closed before sign-in finished: start over with a new state.
    renewal.abandon(); tokenGeneration++;
  }
  // Use a normal tab. Embedded browsers can place feature-requested popup
  // windows in a separate browser context, preventing the same-origin relay.
  const popup = window.open('', 'vera-legal-sign-in');
  if (!popup) return Promise.reject(new LegalPopupBlocked());
  // A renewal must be able to display consent in this tab. A prompt=none probe
  // adds a cross-window retry that can no longer navigate its WindowProxy once
  // COOP severs it at the identity-provider boundary. Omitting both prompt and
  // connection lets Auth0 reuse the session and show consent when needed.
  let verifier = '', state = '', mode: SignInMode = config.connection === 'email' ? options.firstSignIn || !config.organization ? 'entry' : 'session' : 'login';
  const settings = { ...config };
  let channel: BroadcastChannel | null = null;
  let onMessage: ((event: MessageEvent) => void) | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let listening = true;
  let exchanging = false;
  const stopListening = () => {
    listening = false;
    if (timer) clearTimeout(timer);
    if (onMessage) window.removeEventListener('message', onMessage);
    try { channel?.close(); } catch { /* ignore */ }
  };
  let abandon = () => { /* replaced below */ };
  const promise = new Promise<void>((resolve, reject) => {
    const fail = () => { stopListening(); reject(new LegalSignInRequired()); };
    abandon = () => { if (listening) fail(); };
    const launch = (nextMode: SignInMode, previousState?: string) => {
      mode = nextMode;
      verifier = base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      state = (mode === 'entry' ? RENEWAL_ENTRY_PREFIX : mode === 'probe' ? RENEWAL_PROBE_PREFIX : RENEWAL_STATE_PREFIX) + base64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
      const nextState = state;
      pkceChallenge(verifier).then(challenge => {
        if (!listening || state !== nextState) return;
        exchanging = false;
        if (previousState) {
          const message = { type: 'vera-legal-entry-continue', previousState, organization: settings.organization, state, challenge };
          channel?.postMessage(message);
          try { popup.postMessage(message, window.location.origin); } catch { /* COOP may sever the opener; channel remains same-origin. */ }
        } else popup.location.replace(authorizeUrl(settings, { challenge, state, redirectUri: redirectUri(), mode }));
      }).catch(fail);
    };
    const receive = (data: unknown) => {
      const message = data as Partial<RenewalMessage> | null;
      if (!listening || exchanging || !message || message.type !== RENEWAL_MESSAGE || message.state !== state) return;
      const retry = !message.code && retryMode(mode, message.error);
      if (retry) { launch(retry); return; } // Rotate state before a duplicate relay can arrive.
      if (message.error || typeof message.code !== 'string' || !message.code || message.code.length > 2048) { fail(); return; }
      exchanging = true;
      if (mode === 'entry') {
        const entryState = state;
        exchangeLegalEntry(settings.domain, settings.clientId, state,
          { grant_type: 'authorization_code', code: message.code, code_verifier: verifier, redirect_uri: redirectUri() })
          .then(organization => {
            if (!listening || state !== entryState) return;
            if (settings.organization && settings.organization !== organization) { fail(); return; }
            settings.organization = organization;
            launch('session', entryState);
          }, fail);
        return;
      }
      stopListening(); // One code per state; later copies of the message are ignored.
      tokenRequest(settings, { grant_type: 'authorization_code', code: message.code, code_verifier: verifier, redirect_uri: redirectUri() })
        .then(resolve, () => reject(new LegalSignInRequired()));
    };
    onMessage = event => { if (event.origin === window.location.origin) receive(event.data); };
    window.addEventListener('message', onMessage);
    try { channel = new BroadcastChannel(RENEWAL_CHANNEL); channel.onmessage = event => receive(event.data); } catch { channel = null; }
    timer = setTimeout(fail, RENEWAL_TIMEOUT_MS);
    launch(mode);
  }).finally(() => { if (renewal?.promise === promise) renewal = null; });
  renewal = { promise, popup, exchanging: () => exchanging, abandon };
  return promise;
}
