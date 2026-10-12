/**
 * Auth0 post-login Action: Vera legal assurance claim.
 *
 * Issues distinct signed assurance for legal members and onboarding admins,
 * ONLY for their configured applications, and only when
 *   - the user's email is verified and matches the approved organization's exact domain,
 *   - the login is organization-scoped (the admin app: the configured internal org),
 *   - the requested audience is that application's own API, and
 * Legal members additionally require an approved application and legal-member
 * role. They use the pinned email-code connection (including its existing IdP
 * sessions), without MFA. A verified email on a password account is insufficient.
 * Admins still require fresh security-key, passkey or authenticator-app MFA.
 * Refresh-token exchanges never receive either claim: short-lived authority must
 * be renewed through authorization with current organization/role checks.
 * The claim is never derived from user or app metadata.
 *
 * Other applications are untouched, but they may not obtain tokens for the legal
 * APIs. Configuration comes from Action secrets (set by auth0/main.tf):
 *   LEGAL_CLIENT_ID, LEGAL_AUDIENCE, LEGAL_EMAIL_CONNECTION_ID,
 *   ADMIN_CLIENT_ID, ADMIN_AUDIENCE, ADMIN_ORGANIZATION_ID
 * None of these are credentials; they are stored as secrets so the code stays static.
 */
'use strict';

const LEGAL_ASSURANCE_CLAIM = 'https://vera.app/legal-assurance';
const LEGAL_ASSURANCE_VALUE = 'approved-member-verified-email';
const ADMIN_ASSURANCE_VALUE = 'mfa-verified-email';
const DENIED = 'Access to the Vera legal portal is not available for this sign-in.';
// Grants that cannot carry an interactive MFA challenge for a browser user.
const NON_INTERACTIVE = new Set(['oauth2-refresh-token', 'oauth2-password', 'oauth2-resource-owner',
  'oauth2-resource-owner-jwt-bearer', 'oauth2-device-code', 'oauth2-token-exchange']);

function text(value) { return typeof value === 'string' && value.length > 0 ? value : null; }

/** Pure decision, exported for unit tests. Returns one of:
 *  { kind: 'ignore' }   not a legal application or audience: do nothing
 *  { kind: 'deny' }     refuse the login/token
 *  { kind: 'withhold' } allow, but never add the assurance claim
 *  { kind: 'issue', admin: boolean } add profile-specific assurance */
function evaluateLegalAssurance(event) {
  const secrets = (event && event.secrets) || {};
  const profiles = [
    { clientId: text(secrets.LEGAL_CLIENT_ID), audience: text(secrets.LEGAL_AUDIENCE), organizationId: null },
    { clientId: text(secrets.ADMIN_CLIENT_ID), audience: text(secrets.ADMIN_AUDIENCE),
      organizationId: text(secrets.ADMIN_ORGANIZATION_ID), requireOrganizationId: true },
  ];
  const clientId = text(event && event.client && event.client.client_id);
  const audience = text(event && event.resource_server && event.resource_server.identifier);
  const profile = profiles.find(candidate => candidate.clientId && candidate.clientId === clientId);
  const legalAudience = profiles.some(candidate => candidate.audience && candidate.audience === audience);

  if (!profile) return legalAudience ? { kind: 'deny', reason: 'foreign-client' } : { kind: 'ignore' };
  if (!profile.requireOrganizationId &&
      (!/^con_[A-Za-z0-9]+$/.test(secrets.LEGAL_EMAIL_CONNECTION_ID || '') ||
       event.connection?.id !== secrets.LEGAL_EMAIL_CONNECTION_ID ||
       event.connection?.strategy !== 'email' || event.connection?.name !== 'email')) {
    return { kind: 'deny', reason: 'email-connection' };
  }
  // Approved first sign-in is an OIDC-only bootstrap. The shared entry Action
  // checks exact approval and adds membership; this transaction gets NO legal
  // assurance or legal API audience. Normal organization authorization follows.
  const hostname = event?.request?.hostname;
  const profileOnly = !audience || (typeof hostname === 'string' && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname) &&
    audience === `https://${hostname}/userinfo`);
  if (!profile.requireOrganizationId && profileOnly && !event.organization &&
      event.transaction?.protocol === 'oidc-basic-profile' && event.connection?.strategy === 'email' && event.connection.name === 'email') return { kind: 'ignore' };
  if (!profile.audience || (profile.requireOrganizationId && !profile.organizationId)) {
    return { kind: 'deny', reason: 'configuration' };
  }
  if (audience !== profile.audience) return { kind: 'deny', reason: 'audience' };
  const organizationId = text(event.organization && event.organization.id);
  if (!organizationId || (profile.organizationId && organizationId !== profile.organizationId)) {
    return { kind: 'deny', reason: 'organization' };
  }
  if (!event.user || event.user.email_verified !== true || !text(event.user.email)) {
    return { kind: 'deny', reason: 'email' };
  }
  // Auth0 organization membership remains required; matching an email domain
  // never creates membership. Only platform-managed organization metadata can
  // establish the approved domain, never a user's editable profile metadata.
  if (!profile.requireOrganizationId) {
    const metadata = event.organization.metadata;
    if (!/^org_[A-Za-z0-9]{1,64}$/.test(organizationId) ||
        typeof metadata?.vera_application_id !== 'string' || !/^[a-f0-9]{64}$/.test(metadata.vera_application_id) ||
        !Array.isArray(event.authorization?.roles) || !event.authorization.roles.includes('vera-legal-member')) {
      return { kind: 'deny', reason: 'approved-membership' };
    }
    const domain = event.organization && event.organization.metadata && event.organization.metadata.vera_domain;
    const email = event.user.email;
    if (typeof domain !== 'string' || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) ||
        !/^[^@\s]+@[^@\s]+$/.test(email) || email.slice(email.lastIndexOf('@') + 1).toLowerCase() !== domain) {
      return { kind: 'deny', reason: 'approved-domain' };
    }
  }
  const protocol = text(event.transaction && event.transaction.protocol);
  if (protocol === 'oauth2-refresh-token') return { kind: 'withhold', reason: 'refresh' };
  if (!protocol || NON_INTERACTIVE.has(protocol)) return { kind: 'deny', reason: 'protocol' };
  return { kind: 'issue', admin: profile.requireOrganizationId === true };
}

/** Phishing-resistant security keys/passkeys, or an authenticator app (TOTP).
 * Email, SMS, voice and push are never offered for admin access, even when the
 * tenant enables them for other applications. */
const LEGAL_MFA_FACTORS = Object.freeze([
  Object.freeze({ type: 'webauthn-roaming' }), Object.freeze({ type: 'webauthn-platform' }), Object.freeze({ type: 'otp' })]);
const ALLOWED_FACTOR_TYPES = new Set(LEGAL_MFA_FACTORS.map(factor => factor.type));

/** 'challenge' when the user has an allowed factor, 'enroll' for a user with no
 * second factor yet, 'deny' when every enrolled factor is a disallowed one (an
 * administrator must reset MFA; a password alone must not add a new factor). */
function legalMfaStep(user) {
  const enrolled = Array.isArray(user && user.enrolledFactors) ? user.enrolledFactors
    .map(factor => text(factor && factor.type)).filter(type => type && type !== 'recovery-code') : [];
  if (enrolled.some(type => ALLOWED_FACTOR_TYPES.has(type))) return 'challenge';
  return enrolled.length ? 'deny' : 'enroll';
}

exports.onExecutePostLogin = async (event, api) => {
  const decision = evaluateLegalAssurance(event);
  if (decision.kind === 'deny') { api.access.deny(DENIED); return; }
  if (decision.kind !== 'issue') return;
  if (decision.admin) {
    // Administrator assurance still requires MFA in this transaction. A remembered
    // browser or an earlier session's MFA never substitutes for this challenge.
    const step = legalMfaStep(event.user);
    if (step === 'deny') { api.access.deny(DENIED); return; }
    const factors = LEGAL_MFA_FACTORS.map(factor => ({ ...factor }));
    if (step === 'challenge') api.authentication.challengeWithAny(factors);
    else api.authentication.enrollWithAny(factors);
  }
  api.accessToken.setCustomClaim(LEGAL_ASSURANCE_CLAIM, decision.admin ? ADMIN_ASSURANCE_VALUE : LEGAL_ASSURANCE_VALUE);
  // Labels for the approved firm's key setup, from organization metadata only.
  // Never copy user-editable metadata or use this claim as membership authority.
  const org = event.organization;
  const metadata = org && org.metadata;
  // Auth0 supplies this Post Login event (not an HTTP request). Client, audience,
  // verified email and organization checks above gate issuance; this adds labels only.
  // nosemgrep: ajinabraham.njsscan.generic.logic_bypass.node_logic_bypass
  if (event.client.client_id === event.secrets.LEGAL_CLIENT_ID && metadata &&
      typeof metadata.vera_application_id === 'string' && /^[a-f0-9]{64}$/.test(metadata.vera_application_id) &&
      typeof metadata.vera_domain === 'string' && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(metadata.vera_domain) &&
      typeof org.id === 'string' && /^org_[A-Za-z0-9]{1,64}$/.test(org.id) &&
      typeof org.display_name === 'string' && org.display_name.trim().length >= 2 && org.display_name.length <= 160 &&
      !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(org.display_name)) {
    api.accessToken.setCustomClaim('https://vera.app/legal-setup', {
      organizationId: metadata.vera_application_id, providerOrganizationId: org.id,
      domain: metadata.vera_domain, displayName: org.display_name,
    });
  }
};

exports.evaluateLegalAssurance = evaluateLegalAssurance;
exports.legalMfaStep = legalMfaStep;
exports.LEGAL_MFA_FACTORS = LEGAL_MFA_FACTORS;
exports.LEGAL_ASSURANCE_CLAIM = LEGAL_ASSURANCE_CLAIM;
exports.LEGAL_ASSURANCE_VALUE = LEGAL_ASSURANCE_VALUE;
exports.ADMIN_ASSURANCE_VALUE = ADMIN_ASSURANCE_VALUE;
