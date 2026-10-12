/** Separate onboarding-only PKCE session. No case scopes or firm keys. */
import { exchangeIdentityToken } from './identityToken';
export type LegalAuthConfig = { domain: string; clientId: string; audience: string; organization: string | null };
export class LegalSignInRequired extends Error {
  constructor() { super('Please sign in again to continue.'); }
}

const PENDING_KEY = 'vera-onboarding-auth-pending';
const SCOPE = 'openid legal:invite';
const CALLBACK_PATH = '/legal/administration';
let tokens: { accessToken: string; expiresAt: number } | null = null;
let tokenGeneration = 0;

export function onboardingAuthConfig(): LegalAuthConfig | null {
  // Literal references so Next inlines them at build time.
  const domain = process.env.NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN ?? '';
  const clientId = process.env.NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID ?? '';
  const audience = process.env.NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE ?? '';
  const organization = process.env.NEXT_PUBLIC_ONBOARDING_AUTH0_ORGANIZATION ?? '';
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) || !/^[A-Za-z0-9_-]{8,128}$/.test(clientId) ||
      !audience || audience.length > 512 || (organization && !/^org_[a-zA-Z0-9]{1,64}$/.test(organization))) return null;
  return { domain, clientId, audience, organization: organization || null };
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
function safeReturnPath(value: unknown): string {
  return typeof value === 'string' && /^\/legal(?:\/[A-Za-z0-9/_-]*)?$/.test(value) ? value : CALLBACK_PATH;
}
function redirectUri(): string { return `${window.location.origin}${CALLBACK_PATH}`; }

export function authorizeUrl(config: LegalAuthConfig, input: { challenge: string; state: string; redirectUri: string }): string {
  const params = new URLSearchParams({ response_type: 'code', client_id: config.clientId, redirect_uri: input.redirectUri,
    scope: SCOPE, audience: config.audience, code_challenge: input.challenge, code_challenge_method: 'S256', state: input.state });
  if (config.organization) params.set('organization', config.organization);
  return `https://${config.domain}/authorize?${params.toString()}`;
}

export async function beginOnboardingSignIn(config: LegalAuthConfig, returnPath: string): Promise<void> {
  tokens = null; tokenGeneration++;
  const verifier = base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const state = base64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  window.sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, returnPath: safeReturnPath(returnPath) }));
  window.location.assign(authorizeUrl(config, { challenge: await pkceChallenge(verifier), state, redirectUri: redirectUri() }));
}

async function tokenRequest(config: LegalAuthConfig, body: Record<string, string>): Promise<void> {
  const generation = ++tokenGeneration;
  try {
    const next = await exchangeIdentityToken(config.domain, config.clientId, body);
    if (generation !== tokenGeneration) throw new LegalSignInRequired();
    tokens = next;
  } catch { throw new LegalSignInRequired(); }
}

/** Call on the /legal callback. Removes code/state from the URL before any
 * other work. Returns the page to continue on, or null when this is not a callback. */
let callbackCompletion: { binding: string; promise: Promise<string | null> } | null = null;
/** React effect replay must await the same code exchange after URL/state removal.
 * Never share an exchange with another identity configuration or origin. */
export function completeOnboardingSignIn(config: LegalAuthConfig): Promise<string | null> {
  const settings = { ...config };
  const binding = JSON.stringify([window.location.origin, CALLBACK_PATH, settings.domain,
    settings.clientId, settings.audience, settings.organization]);
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
  if (!params.has('code') && !params.has('error')) return null;
  const code = params.get('code'), state = params.get('state');
  window.history.replaceState(null, '', window.location.pathname);
  const raw = window.sessionStorage.getItem(PENDING_KEY);
  window.sessionStorage.removeItem(PENDING_KEY);
  let pending: { verifier?: unknown; state?: unknown; returnPath?: unknown } | null = null;
  try { pending = raw ? JSON.parse(raw) : null; } catch { pending = null; }
  if (!code || !state || !pending || pending.state !== state || typeof pending.verifier !== 'string') throw new LegalSignInRequired();
  await tokenRequest(config, { grant_type: 'authorization_code', code, code_verifier: pending.verifier, redirect_uri: redirectUri() });
  return safeReturnPath(pending.returnPath);
}

export function onboardingSignedIn(): boolean { return !!tokens && (tokens.expiresAt - 30_000 > Date.now()); }
/** When the current onboarding sign-in stops being usable (30 s before token expiry), or null. */
export function onboardingSessionEndsAt(): number | null { return tokens ? tokens.expiresAt - 30_000 : null; }

/** Five-minute interactive MFA tokens. Renewal requires a fresh sign-in. */
export async function onboardingAccessToken(config: LegalAuthConfig): Promise<string> {
  if (tokens && tokens.expiresAt - 30_000 > Date.now()) return tokens.accessToken;
  tokens = null;
  throw new LegalSignInRequired();
}

export function signOutOnboarding(config: LegalAuthConfig): void {
  tokens = null; tokenGeneration++;
  try { window.sessionStorage.removeItem(PENDING_KEY); } catch { /* Logout must still proceed. */ }
  const params = new URLSearchParams({ client_id: config.clientId, returnTo: `${window.location.origin}${CALLBACK_PATH}` });
  window.location.assign(`https://${config.domain}/v2/logout?${params.toString()}`);
}
