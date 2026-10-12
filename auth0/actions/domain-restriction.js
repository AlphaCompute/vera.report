/** Legal-client-only entry gate. Legal firms use their approved organization's
 * membership and domain, created by the Slack approval worker.
 * Deploy alongside legal-assurance.js, which owns assurance and admin MFA.
 * Action settings: LEGAL_CLIENT_ID, LEGAL_AUDIENCE, LEGAL_EMAIL_CONNECTION_ID,
 * LEGAL_MGMT_DOMAIN, LEGAL_MGMT_CLIENT_ID and LEGAL_MGMT_CLIENT_SECRET.
 * Current membership is read directly from Auth0.
 * Deploy as NEW legal-scoped Actions, never as a replacement for staff domain
 * restrictions or role assignment. Other applications are untouched.
 */
'use strict';
const { createHash } = require('node:crypto');

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const ORG = /^org_[A-Za-z0-9]{1,64}$/;
const READ_SCOPES = 'read:organizations read:organization_connections read:organization_members read:users read:roles read:organization_member_roles';
// Legacy manually provisioned orgs may lack a status. New application orgs must
// explicitly be approved; pending/denied orgs never participate in sign-in.
const approvedOrganization = org => org?.metadata?.vera_approval_status === 'approved' ||
  (org?.metadata?.vera_approval_status === undefined && org?.metadata?.vera_application_version === undefined);

function legalClient(event) {
  return typeof event?.secrets?.LEGAL_CLIENT_ID === 'string' && !!event.secrets.LEGAL_CLIENT_ID.trim() &&
    event?.client?.client_id === event.secrets.LEGAL_CLIENT_ID;
}
function emailConnection(event) {
  const id = event?.secrets?.LEGAL_EMAIL_CONNECTION_ID;
  return typeof id === 'string' && /^con_[A-Za-z0-9]+$/.test(id) && event?.connection?.id === id &&
    event?.connection?.strategy === 'email' && event.connection.name === 'email';
}

// This same source is deployed to the Pre User Registration and Post Login
// triggers. Approval prepares accounts and memberships before native email OTP.
// The registration gate also covers an account arriving while approval is queued.
function entryLogin(event) {
  const audience = event?.resource_server?.identifier;
  const hostname = event?.request?.hostname;
  const profileOnly = !audience || (typeof hostname === 'string' && DOMAIN.test(hostname) && audience === `https://${hostname}/userinfo`);
  return legalClient(event) &&
    !event?.organization && profileOnly &&
    event?.transaction?.protocol === 'oidc-basic-profile' &&
    emailConnection(event);
}
async function approvedEntry(event, operation) {
  const settings = event?.secrets || {};
  const fail = () => { throw new Error('Entry unavailable'); };
  if (!DOMAIN.test(settings.LEGAL_MGMT_DOMAIN || '') || !settings.LEGAL_MGMT_CLIENT_ID || !settings.LEGAL_MGMT_CLIENT_SECRET ||
      !legalClient(event) || !emailConnection(event) || typeof event?.user?.email !== 'string') fail();
  const email = event.user.email.toLowerCase();
  if (email.length > 254 || !/^[^@\s]+@[^@\s]+$/.test(email)) fail();
  const domain = email.split('@')[1], origin = `https://${settings.LEGAL_MGMT_DOMAIN}`;
  const signal = AbortSignal.timeout(18_000);
  const accessToken = async scope => {
    const tokenResponse = await fetch(`${origin}/oauth/token`, { method: 'POST', redirect: 'error', signal,
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials',
        client_id: settings.LEGAL_MGMT_CLIENT_ID, client_secret: settings.LEGAL_MGMT_CLIENT_SECRET,
        audience: `${origin}/api/v2/`, scope }) });
    if (!tokenResponse.ok) fail();
    const token = await tokenResponse.json();
    if (typeof token.access_token !== 'string' || !token.access_token || token.token_type?.toLowerCase() !== 'bearer') fail();
    return token.access_token;
  };
  const token = await accessToken(READ_SCOPES);
  const api = async path => {
    const response = await fetch(`${origin}/api/v2/${path}`, { method: 'GET', redirect: 'error', signal,
      headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) fail();
    return response.status === 204 ? null : response.json();
  };
  const list = async path => {
    const result = [];
    for (let page = 0; page < 10; page++) {
      const rows = await api(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      if (!Array.isArray(rows) || rows.length > 100 || rows.some(row => !row || typeof row !== 'object')) fail();
      result.push(...rows);
      if (rows.length < 100) return result;
    }
    fail(); // An incomplete directory is never evidence of absence or uniqueness.
  };
  const organizations = (await list('organizations')).filter(org => org.metadata?.vera_domain === domain && approvedOrganization(org));
  if (organizations.length !== 1) fail();
  const organization = organizations[0], base = `organizations/${organization.id}`;
  if (!ORG.test(organization.id || '') || !/^[a-f0-9]{64}$/.test(organization.metadata?.vera_application_id || '') ||
      organization.metadata?.vera_legal_disabled === 'true') fail();
  const connection = await api(`${base}/enabled_connections/${settings.LEGAL_EMAIL_CONNECTION_ID}`);
  if (connection?.connection_id !== settings.LEGAL_EMAIL_CONNECTION_ID || connection.assign_membership_on_login !== false ||
      connection.connection?.name !== 'email' || connection.connection?.strategy !== 'email') fail();
  // Auth0 metadata keys are limited to 50 characters: 39 hex of the SHA-256.
  // Keep in sync with legalEntryHintKey in src/services/legalApplicationAuth0.ts.
  const hint = organization.metadata[`vera_entry_${createHash('sha256').update(email).digest('hex').slice(0, 39)}`];
  const pending = typeof hint === 'string' && /^[0-9]{13}$/.test(hint) && Number(hint) > Date.now() &&
    Number(hint) <= Date.now() + 7 * 86_400_000;
  // The Slack provisioning worker publishes this exact-address hint before an
  // account exists. It allows native registration only, never API access.
  if (operation === 'lookup' && pending) return organization.id;
  // The Action event is not the provisioning authority. Independently resolve
  // the exact passwordless subject, including blocked and verified-email state.
  const users = await api(`users-by-email?${new URLSearchParams({ email })}`);
  if (!Array.isArray(users)) fail();
  const candidates = users.filter(user => user?.email?.toLowerCase() === email && user.identities?.some(identity =>
    identity.connection === 'email' && identity.provider === 'email'));
  if (candidates.length !== 1 || candidates[0].blocked === true ||
      !/^email\|[^\s\u0000-\u001f]{1,200}$/.test(candidates[0].user_id || '')) fail();
  if (operation === 'complete' && (candidates[0].user_id !== event.user.user_id || candidates[0].email_verified !== true)) fail();
  const subject = candidates[0].user_id;
  const roles = (await list('roles?name_filter=vera-legal-member')).filter(role => role.name === 'vera-legal-member');
  if (roles.length !== 1 || !/^rol_[A-Za-z0-9]+$/.test(roles[0].id || '')) fail();
  const role = roles[0];
  const permissions = await list(`roles/${role.id}/permissions`);
  if (permissions.length !== 3 || permissions.some(p => p.resource_server_identifier !== settings.LEGAL_AUDIENCE) ||
      permissions.map(p => p.permission_name).sort().join(' ') !== 'legal:case legal:directory legal:enroll') fail();
  // Sign-in is read-only: it cannot restore a removed membership or role.
  const rolePath = `${base}/members/${encodeURIComponent(subject)}/roles`;
  for (let attempt = 0; attempt < (pending ? 10 : 1); attempt++) {
    signal.throwIfAborted();
    const member = (await list(`${base}/members`)).some(row => row.user_id === subject && row.email?.toLowerCase() === email);
    if (member && (await list(rolePath)).some(row => row.id === role.id)) return organization.id;
    if (pending && attempt < 9) await new Promise(resolve => setTimeout(resolve, 1000));
  }
  fail(); // A slow/unavailable provisioner never turns an approval hint into access.
}

exports.onExecutePreUserRegistration = async (event, api) => {
  if (!legalClient(event)) return;
  try {
    if (emailConnection(event)) { await approvedEntry(event, 'lookup'); return; }
  } catch { /* Fail closed; no email addresses, credentials or provider bodies in logs. */ }
  api.access.deny('registration_denied', 'Registration requires an approved application.');
};

function accessKind(event) {
  const secrets = event?.secrets || {};
  const audience = event?.resource_server?.identifier;
  if (legalClient(event)) {
    if (typeof secrets.LEGAL_AUDIENCE !== 'string' || !secrets.LEGAL_AUDIENCE.trim() || !emailConnection(event)) return 'deny';
    if (entryLogin(event)) return 'entry';
    const email = event?.user?.email;
    if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(email)) return 'deny';
    const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
    if (!DOMAIN.test(domain)) return 'deny';
    const org = event.organization;
    const approvedDomain = org?.metadata?.vera_domain;
    return secrets.LEGAL_AUDIENCE && audience === secrets.LEGAL_AUDIENCE &&
      event.user.email_verified === true && /^org_[A-Za-z0-9]{1,64}$/.test(org?.id || '') &&
      /^[a-f0-9]{64}$/.test(org?.metadata?.vera_application_id || '') &&
      approvedOrganization(org) &&
      org?.metadata?.vera_legal_disabled !== 'true' &&
      typeof approvedDomain === 'string' && DOMAIN.test(approvedDomain) && approvedDomain === domain &&
      Array.isArray(event.authorization?.roles) && event.authorization.roles.includes('vera-legal-member')
      ? 'legal' : 'deny';
  }
  // Another client must not obtain legal API tokens through this Action.
  if (secrets.LEGAL_AUDIENCE && audience === secrets.LEGAL_AUDIENCE) return 'deny';
  return 'other';
}

exports.onExecutePostLogin = async (event, api) => {
  const kind = accessKind(event);
  if (kind === 'deny') { api.access.deny('Access restricted!'); return; }
  if (kind === 'entry') {
    try {
      if (event.user?.email_verified !== true || typeof event.user.user_id !== 'string') throw new Error('Unverified');
      const organization = await approvedEntry(event, 'complete');
      // Routing hint only: no legal API audience, scopes or assurance are issued.
      // The SPA next authorizes in this organization using the established SSO
      // session. That fresh transaction sees its real membership and RBAC role.
      api.idToken.setCustomClaim('https://vera.app/legal-entry', { organization });
    } catch { api.access.deny('Organization sign-in could not be confirmed. Try again shortly. If it continues, contact VERA.'); }
    return;
  }
  // Membership belongs to the approval worker; staff policies and role claims
  // belong to their existing Actions. This Action must not replace either.
};

exports.accessKind = accessKind;
exports.entryLogin = entryLogin;
