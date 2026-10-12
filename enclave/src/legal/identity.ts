import type { JSONWebKeySet } from 'jose';

export const LEGAL_ASSURANCE_CLAIM = 'https://vera.app/legal-assurance';
export const LEGAL_ASSURANCE_VALUE = 'approved-member-verified-email';
export const ADMIN_ASSURANCE_VALUE = 'mfa-verified-email';
export type LegalIdentityPolicy = {
  issuer: string; audience: string; clientId: string; jwks: JSONWebKeySet;
};
export type LegalIdentity = { subject: string; providerOrganizationId: string; expiresAt: number };

/** Measured startup configuration, never parameters from an HTTP request.
 * Obtain/refresh JWKS through authenticated IdP TLS inside the enclave or an
 * independently pinned configuration. This verifier never follows token URLs.
 */
export function createLegalIdentityVerifier(policy: LegalIdentityPolicy) {
  return createIdentityVerifier(policy, false);
}

/** Separate measured entry point: legal-user assurance never authorizes staff. */
export function createOnboardingAdminIdentityVerifier(policy: LegalIdentityPolicy) {
  return createIdentityVerifier(policy, true);
}

function createIdentityVerifier(policy: LegalIdentityPolicy, admin: boolean): {
  verify: (token: string, requiredScope: 'legal:invite' | 'legal:enroll' | 'legal:directory' | 'legal:case', now: number) => Promise<LegalIdentity>;
} {
  const issuer = policy.issuer, audience = policy.audience, clientId = policy.clientId;
  const origin = new URL(issuer);
  if (origin.protocol !== 'https:' || issuer !== `${origin.origin}/` ||
      typeof audience !== 'string' || !audience || audience.length > 512 || audience === clientId ||
      typeof clientId !== 'string' || !clientId || clientId.length > 128 || !Array.isArray(policy.jwks?.keys) ||
      !policy.jwks.keys.length || policy.jwks.keys.length > 8) throw new Error('Invalid legal identity policy');
  const keys = JSON.parse(JSON.stringify(policy.jwks)) as JSONWebKeySet;
  const keyIds = new Set<string>();
  for (const key of keys.keys) {
    if (key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' ||
        typeof key.kid !== 'string' || !key.kid || keyIds.has(key.kid) ||
        ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(field => (key as unknown as Record<string, unknown>)[field] !== undefined) ||
        typeof key.n !== 'string' || typeof key.e !== 'string') throw new Error('Invalid legal identity policy');
    keyIds.add(key.kid);
  }
  // Native dynamic import retains JOSE's ESM boundary in the enclave Node build.
  const implementation = import('jose').then(jose => ({ jose, resolveKey: jose.createLocalJWKSet(keys) }));
  return {
    async verify(token, requiredScope, now) {
      try {
        if (typeof token !== 'string' || token.length > 16_384 ||
            !Number.isSafeInteger(now) || now <= 0 || now > 8_640_000_000_000_000 ||
            !(admin ? ['legal:invite'] : ['legal:enroll', 'legal:directory', 'legal:case']).includes(requiredScope)) throw new Error();
        const { jose, resolveKey } = await implementation;
        const { payload, protectedHeader } = await jose.jwtVerify(token, resolveKey, {
          issuer, audience, algorithms: ['RS256'], clockTolerance: 0, currentDate: new Date(now), maxTokenAge: 300,
          requiredClaims: ['sub', 'org_id', 'azp', 'scope', 'iat', 'exp', LEGAL_ASSURANCE_CLAIM],
        });
        if (protectedHeader.typ !== 'JWT' || typeof protectedHeader.kid !== 'string' || !keyIds.has(protectedHeader.kid) ||
            Object.keys(protectedHeader).some(key => !['alg', 'kid', 'typ'].includes(key)) ||
            payload.azp !== clientId || typeof payload.sub !== 'string' ||
            !/^[a-zA-Z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/.test(payload.sub) || payload.gty === 'client-credentials' ||
            typeof payload.org_id !== 'string' || !/^org_[a-zA-Z0-9]{1,64}$/.test(payload.org_id) ||
            typeof payload.scope !== 'string' || !payload.scope.split(' ').includes(requiredScope) ||
            payload[LEGAL_ASSURANCE_CLAIM] !== (admin ? ADMIN_ASSURANCE_VALUE : LEGAL_ASSURANCE_VALUE) ||
            !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) ||
            payload.iat! > Math.floor(now / 1000) || payload.exp! <= payload.iat! || payload.exp! - payload.iat! > 300) throw new Error();
        return { subject: payload.sub, providerOrganizationId: payload.org_id as string, expiresAt: payload.exp! * 1000 };
      } catch {
        // No JWT, provider response, invitation, or identity details in errors.
        throw new Error('Legal authentication required');
      }
    },
  };
}
