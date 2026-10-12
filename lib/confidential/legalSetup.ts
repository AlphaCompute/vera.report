import { LEGAL_DOMAIN, LEGAL_ORGANIZATION_ID, LEGAL_PROVIDER_ORGANIZATION_ID, LEGAL_TEXT_CONTROL } from '../../src/utils/legalOnboarding';

export const LEGAL_SETUP_CLAIM = 'https://vera.app/legal-setup';
export type LegalSetup = { organizationId: string; providerOrganizationId: string; domain: string; displayName: string };

/** Presentation context only. The enclave still verifies identity, the signed
 * roster/key binding and membership independently for every legal operation. */
export function setupFromIdentityToken(token: string, config: { domain: string; clientId: string; audience: string; organization: string | null }, now = Date.now()): LegalSetup | null {
  try {
    if (token.length > 16_384) return null;
    const parts = token.split('.');
    if (parts.length !== 3 || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(payload + '='.repeat((4 - payload.length % 4) % 4)), c => c.charCodeAt(0))));
    const value = body[LEGAL_SETUP_CLAIM];
    if (body.iss !== `https://${config.domain}/` || body.azp !== config.clientId ||
        !(body.aud === config.audience || (Array.isArray(body.aud) && body.aud.includes(config.audience))) ||
        typeof body.exp !== 'number' || body.exp * 1000 <= now || !value ||
        typeof value.organizationId !== 'string' || !LEGAL_ORGANIZATION_ID.test(value.organizationId) ||
        typeof value.providerOrganizationId !== 'string' || !LEGAL_PROVIDER_ORGANIZATION_ID.test(value.providerOrganizationId) ||
        body.org_id !== value.providerOrganizationId || (config.organization && config.organization !== value.providerOrganizationId) ||
        typeof value.domain !== 'string' || !LEGAL_DOMAIN.test(value.domain) || typeof value.displayName !== 'string' ||
        value.displayName.trim().length < 2 || value.displayName.length > 160 || LEGAL_TEXT_CONTROL.test(value.displayName)) return null;
    return { organizationId: value.organizationId, providerOrganizationId: value.providerOrganizationId, domain: value.domain, displayName: value.displayName };
  } catch { return null; }
}

/** Pasting the membership link keeps the unlocked key in this tab. Never follow
 * a supplied URL or send the invitation token to a host outside the enclave. */
export function membershipInvitation(value: string, origin: string): string | null {
  try {
    const url = new URL(value.trim());
    const params = new URLSearchParams(url.hash.slice(1));
    const token = params.get('invitation');
    return url.origin === origin && url.pathname === '/legal/enroll' && !url.search && !url.username && !url.password &&
      [...params.keys()].length === 1 && token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
  } catch { return null; }
}
