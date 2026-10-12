import type { Browser, BrowserContext, BrowserContextOptions, Page } from '@playwright/test';
import * as jose from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import {
  FIRM_DOMAIN, FIRM_DOMAINS, IDENTITY_DOMAIN, ISSUER, LEGAL_AUDIENCE, LEGAL_CLIENT, ONBOARDING_AUDIENCE, ONBOARDING_CLIENT, ONBOARDING_ORG,
  SECOND_FIRM_DOMAIN,
} from '../stack/stack';
import { stackState } from './state';
import { followStackTime, stackNow } from './time';
import type { LegalSetup } from '../../../lib/confidential/legalSetup';

// The AWS Nitro root pinned in enclave/src/confidential/attestation.ts. The test
// browser receives the page's own compiled code with this one constant (and its
// SHA-256 pin) swapped for the synthetic root: the only attestation mock. Every
// other verification step (COSE signature, chain, freshness, nonce, PCR pins,
// channel-key binding, release approval) runs unchanged in the browser.
const AWS_ROOT_PREFIX = 'MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMw';
const AWS_ROOT_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';
const AWS_ROOT = /MIICETCCAZagAwIBAgIRAPkxdWgbkK\/hHUbMtOTn\+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMw[A-Za-z0-9+/=]+/g;

export type Persona = { subject: string; providerOrganizationId: string; setup?: LegalSetup; nativeEmail?: string };
const personas = new WeakMap<BrowserContext, { legal?: Persona; onboarding?: Persona }>();
const codes = new Map<string, { client: string; persona: Persona; entry: boolean; nonce: string; challenge: string; redirect: string }>();

// All accelerated personas share one loopback quota key. Keep the positive
// journey below the unchanged 600/minute production limit regardless of machine
// speed or rate-window alignment: at most eight channel starts per second,
// across contexts. This delays each original request; it never retries one.
let channelStart = Promise.resolve(), lastChannelStart = -Infinity;
function paceChannel(): Promise<void> {
  channelStart = channelStart.then(async () => {
    const delay = 125 - (performance.now() - lastChannelStart);
    if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay));
    lastChannelStart = performance.now();
  });
  return channelStart;
}

export function signInAs(context: BrowserContext, persona: Persona, kind: 'legal' | 'onboarding' = 'legal') {
  personas.set(context, { ...personas.get(context), [kind]: persona });
}

async function token(client: string, persona: Persona): Promise<string> {
  const state = stackState();
  const key = await jose.importJWK(state.issuerKey, 'RS256');
  // A few seconds in the past: the enclave compares against its attested clock.
  const iat = Math.floor(await stackNow() / 1000) - 5;
  const legal = client === LEGAL_CLIENT;
  return new jose.SignJWT({ azp: client, org_id: persona.providerOrganizationId,
    ...(legal && persona.setup ? { 'https://vera.app/legal-setup': persona.setup } : {}),
    scope: legal ? 'openid legal:directory legal:case legal:enroll' : 'openid legal:invite',
    'https://vera.app/legal-assurance': legal ? 'approved-member-verified-email' : 'mfa-verified-email' })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: state.issuerKid })
    .setIssuer(ISSUER).setAudience(legal ? LEGAL_AUDIENCE : ONBOARDING_AUDIENCE).setSubject(persona.subject)
    .setIssuedAt(iat).setExpirationTime(iat + 300).sign(key);
}

/** Synthetic identity for protocol setup of pre-existing requests. */
export const existingRequestToken = (persona: Persona) => token(LEGAL_CLIENT, persona);

/** Wire one browser context to the local stack. */
/** The declared source commit: the one field the next release manifest changes. */
const sourceCommit = (manifest: string) => (JSON.parse(manifest) as { sourceCommit: string }).sourceCommit;

export async function prepare(context: BrowserContext, options: { admin?: boolean; release?: 'current' | 'next' } = {}) {
  const state = stackState();
  await context.route(`${state.baseURL}/api/confidential/channel/*`, async route => {
    await paceChannel();
    await route.fallback();
  });
  // 'next': this browser receives a later VERA release (the compiled release
  // manifest names another source commit), as after a frontend deploy.
  const [from, to] = [sourceCommit(state.releaseManifest), sourceCommit(state.nextReleaseManifest)];
  await context.route(/\/_next\/static\/.*\.js(\?.*)?$/, async route => {
    // Retry only connection resets while loading immutable production assets; never replay API mutations.
    const response = await route.fetch({ maxRetries: 2 });
    let body = await response.text();
    if (options.release === 'next' && body.includes(from)) body = body.split(from).join(to);
    if (!body.includes(AWS_ROOT_PREFIX)) return route.fulfill({ response, body });
    return route.fulfill({ response, body: body.replace(AWS_ROOT, state.attestationRoot).split(AWS_ROOT_SHA256).join(state.attestationRootSha256) });
  });
  // Synthetic identity provider for the legal and onboarding sign-ins.
  await context.route(`https://${IDENTITY_DOMAIN}/**`, async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.pathname === '/authorize') {
      const client = url.searchParams.get('client_id') ?? '';
      const persona = personas.get(context)?.[client === ONBOARDING_CLIENT ? 'onboarding' : 'legal'];
      if (!persona) return route.fulfill({ status: 403, body: 'No synthetic user for this test context' });
      const entry = client === LEGAL_CLIENT && url.searchParams.get('audience') === `${ISSUER}userinfo` && !url.searchParams.has('organization');
      if (entry && persona.nativeEmail) {
        const response = await context.request.post(`${state.baseURL}/__e2e/native-email`, {
          headers: { 'x-e2e-review-key': state.adminCookie }, data: { email: persona.nativeEmail },
        });
        if (!response.ok()) return route.fulfill({ status: 403, body: 'Synthetic OTP approval rejected' });
        const result = await response.json();
        if (result.organization !== persona.providerOrganizationId) throw new Error('Wrong approved organization');
        persona.subject = result.subject; delete persona.nativeEmail;
      }
      const code = randomBytes(16).toString('hex');
      codes.set(code, { client, persona, entry, nonce: url.searchParams.get('nonce') || '',
        challenge: url.searchParams.get('code_challenge') || '', redirect: url.searchParams.get('redirect_uri') || '' });
      const back = new URL(url.searchParams.get('redirect_uri')!);
      back.searchParams.set('code', code); back.searchParams.set('state', url.searchParams.get('state') ?? '');
      return route.fulfill({ status: 302, headers: { location: back.toString() } });
    }
    const cors = { 'Access-Control-Allow-Origin': '*' };
    if (url.pathname === '/oauth/token' && request.method() === 'POST') {
      const body = new URLSearchParams(request.postData() ?? '');
      const grant = codes.get(body.get('code') ?? '');
      if (!grant || grant.client !== body.get('client_id') || grant.redirect !== body.get('redirect_uri') ||
          createHash('sha256').update(body.get('code_verifier') || '').digest('base64url') !== grant.challenge) return route.fulfill({ status: 403, headers: cors, body: '{}' });
      codes.delete(body.get('code')!);
      if (grant.entry) {
        const key = await jose.importJWK(state.issuerKey, 'RS256');
        // On the stack's time, like the access token: the browser checks iat and exp against its (shifted) clock.
        const iat = Math.floor(await stackNow() / 1000) - 5;
        const idToken = await new jose.SignJWT({ nonce: grant.nonce, 'https://vera.app/legal-entry': { organization: grant.persona.providerOrganizationId } })
          .setProtectedHeader({ alg: 'RS256', kid: state.issuerKid }).setIssuer(ISSUER).setAudience(grant.client)
          .setSubject(grant.persona.subject).setIssuedAt(iat).setExpirationTime(iat + 300).sign(key);
        return route.fulfill({ status: 200, headers: cors, contentType: 'application/json',
          body: JSON.stringify({ id_token: idToken, access_token: 'profile-only-never-legal-authority', token_type: 'Bearer', expires_in: 86400 }) });
      }
      return route.fulfill({ status: 200, headers: cors, contentType: 'application/json',
        body: JSON.stringify({ access_token: await token(grant.client, grant.persona), token_type: 'Bearer', expires_in: 240 }) });
    }
    if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { ...cors, 'Access-Control-Allow-Headers': '*' } });
    return route.fulfill({ status: 404, headers: cors, body: 'Not found' });
  });
  // The application must finish onboarding without fetching a firm's website.
  // Keep synthetic domains offline so a regression cannot reach an external host.
  for (const domain of FIRM_DOMAINS) await context.route(`https://${domain}/**`, route =>
    route.abort('blockedbyclient'));
  if (options.admin) {
    await context.addCookies([{ name: '__session', value: state.adminCookie, url: state.baseURL, httpOnly: true, sameSite: 'Lax' }]);
  }
}

export async function newParticipant(browser: Browser, options: BrowserContextOptions & { admin?: boolean; release?: 'current' | 'next' } = {}) {
  const { admin, release, ...contextOptions } = options;
  const context = await browser.newContext({ acceptDownloads: true,
    ...(process.env.VERA_E2E_VIDEO_DIR ? { recordVideo: { dir: process.env.VERA_E2E_VIDEO_DIR } } : {}),
    ...contextOptions });
  // Availability diagnostics only: no identities, nonces, URLs, headers or
  // ciphertext bodies. Keep 503/429 evidence when a timing-sensitive step fails.
  const channelResponses: Record<string, number> = {};
  context.on('response', response => {
    const route = new URL(response.url()).pathname.match(/^\/api\/confidential\/channel\/(open|call)$/)?.[1];
    if (!route) return;
    const key = `${route}:${response.status()}`;
    channelResponses[key] = (channelResponses[key] ?? 0) + 1;
  });
  context.on('close', () => process.stderr.write(`[e2e channel responses] ${JSON.stringify(channelResponses)}\n`));
  await prepare(context, { admin, release });
  await followStackTime(context);
  // VERA_E2E_DEBUG=1: uncaught page errors and console errors (messages only).
  if (process.env.VERA_E2E_DEBUG) context.on('page', page => {
    page.on('pageerror', error => process.stderr.write(`[e2e pageerror] ${page.url()} ${error.message}\n${error.stack}\n`));
    page.on('console', message => { if (message.type() === 'error') process.stderr.write(`[e2e console] ${message.text().slice(0, 300)}\n`); });
  });
  return context;
}

export { FIRM_DOMAIN, FIRM_DOMAINS, ONBOARDING_ORG, SECOND_FIRM_DOMAIN };
export { recordTraffic } from './leaks';
