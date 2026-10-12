import type { LegalApplicationView } from '../utils/legalApplications';
import { LegalProvisioningError, projectLegalApplication } from '../utils/legalApplications';
import type { LegalProvisioningDetail } from '../utils/legalApplications';
import { validateNewLegalOrganization, projectLegalOrganization, validActor } from '../utils/legalOnboarding';
import type { NewLegalOrganization } from '../utils/legalOnboarding';
import { createHash } from 'node:crypto';
import type { LegalMembershipApproval } from './legalAuth0Memberships';
import { applicationOrganizations } from './legalApplicationOrganizations';
import type { ApplicationOrganizations } from './legalApplicationOrganizations';

type OrganizationRoster = {
  createLegalOrganization(value: NewLegalOrganization & { organizationId: string }, actor: string, now: number): Promise<void>;
  getLegalOrganizationRecord(id: string): Promise<unknown>;
  queueLegalAuth0Membership?(approval: LegalMembershipApproval): Promise<void>;
  legalAuth0MembershipPrepared?(approval: LegalMembershipApproval): Promise<boolean>;
  retireDeletedLegalOrganizations?(domain: string, provider: ApplicationOrganizations, signal: AbortSignal): Promise<void>;
};
export type ApplicationIdentityProvider = {
  applicationOrganizations?: ApplicationOrganizations;
  nativeEntry?: boolean;
  registrationApproval?(target: LegalSignInTarget & { expires: number }, signal: AbortSignal): Promise<void>;
  candidate?(target: LegalSignInTarget, signal: AbortSignal): Promise<string | null>;
  createApprovedAccount?(target: LegalSignInTarget, signal: AbortSignal): Promise<string>;
  approveMembership?(target: LegalSignInTarget, subject: string, signal: AbortSignal, created: boolean): Promise<string>;
  organization(application: LegalApplicationView, signal: AbortSignal): Promise<string>;
  invite(application: LegalApplicationView, organizationId: string, signal: AbortSignal): Promise<void>;
  inviteMember?(target: { providerOrganizationId: string; domain: string; email: string }, signal: AbortSignal): Promise<void>;
  resolveApprovedMember?(application: LegalApplicationView, organizationId: string, signal: AbortSignal): Promise<string>;
  existingMember?(target: LegalSignInTarget, signal: AbortSignal): Promise<string | null>;
  completeSignIn?(target: LegalSignInTarget, subject: string, signal: AbortSignal, attach: boolean): Promise<string>;
};
export type LegalSignInTarget = { providerOrganizationId: string; domain: string; email: string };
/** Organization metadata key of the exact-address registration hint. Auth0
 * rejects metadata keys longer than 50 characters, so the SHA-256 of the
 * normalized email is truncated to 39 hex characters (156 bits). Keep in sync
 * with auth0/actions/domain-restriction.js. */
export const LEGAL_ENTRY_HINT_KEY = /^vera_entry_[a-f0-9]{39}$/;
export function legalEntryHintKey(email: string): string {
  return `vera_entry_${createHash('sha256').update(email).digest('hex').slice(0, 39)}`;
}
export const LEGAL_AUTH0_PROVISIONING_SCOPES = [
  'read:organizations', 'create:organizations', 'delete:organizations', 'read:organization_connections', 'create:organization_connections',
  'read:organization_members', 'create:organization_members', 'read:users', 'create:users', 'update:users', 'read:email_templates',
  'read:roles', 'read:organization_member_roles', 'create:organization_member_roles', 'update:organizations',
].join(' ');
const ORGANIZATION_ID = /^org_[A-Za-z0-9]{1,64}$/;
const USER_ID = /^[A-Za-z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/;
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// The public PNG from vera.report works in email clients as well as Universal Login.
// Keep the same default in auth0/main.tf and auth0/templates/user-invitation.html.
const VERA_LOGO_URL = 'https://vera.report/apple-touch-icon.png';
const hasApproval = (metadata: Record<string, unknown> | undefined) => metadata?.vera_approval_status === 'approved' ||
  (metadata?.vera_approval_status === undefined && metadata?.vera_application_version === undefined);

/** The dedicated M2M prepares approved organizations and exact memberships.
 * Approval prepares membership without sending an email. Sign-in owns OTP.
 * Existing provisioning settings also enable the one-time membership worker;
 * interactive sign-in uses the separately pinned legal identity policy. */
export function legalApplicationProvisioner(env: NodeJS.ProcessEnv, identityPolicy?: unknown): ApplicationIdentityProvider | null {
  const domain = env.LEGAL_AUTH0_MGMT_DOMAIN?.trim();
  const clientId = env.LEGAL_AUTH0_MGMT_CLIENT_ID?.trim();
  const clientSecret = env.LEGAL_AUTH0_MGMT_CLIENT_SECRET;
  const connectionId = env.LEGAL_AUTH0_CONNECTION_ID?.trim();
  if (!domain && !clientId && !clientSecret && !connectionId) return null;
  const policy = identityPolicy as { clientId?: unknown; issuer?: unknown; audience?: unknown } | undefined;
  const invitationClientId = policy?.clientId;
  const legalAudience = policy?.audience;
  const issuer = typeof policy?.issuer === 'string' ? policy.issuer : '';
  const loginDomain = issuer.slice(8, -1);
  if (!domain || !HOSTNAME.test(domain) || issuer !== `https://${loginDomain}/` || !HOSTNAME.test(loginDomain) ||
      !clientId || !clientSecret?.trim() || !connectionId || !/^con_[A-Za-z0-9]+$/.test(connectionId) ||
      typeof invitationClientId !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(invitationClientId) ||
      invitationClientId === clientId ||
      typeof legalAudience !== 'string' || !legalAudience || legalAudience.length > 512) {
    throw new Error('Invalid legal organization provisioning configuration');
  }
  // Auth0 custom-domain tokens and API calls use that same domain, but the
  // Management API audience always keeps the canonical tenant hostname.
  const origin = `https://${loginDomain}`, audience = `https://${domain}/api/v2/`;
  let token: { value: string; expires: number } | undefined;
  const fail = (code: ConstructorParameters<typeof LegalProvisioningError>[0] = 'provider_unavailable', detail?: LegalProvisioningDetail): never => {
    throw new LegalProvisioningError(code, detail);
  };
  async function request(url: string, init: RequestInit, deadline: AbortSignal): Promise<Response> {
    try {
      deadline.throwIfAborted();
      // The shared 45-second attempt still ends before the work lease. Allow
      // cold Auth0 token requests enough time within that overall deadline.
      return await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.any([deadline, AbortSignal.timeout(30_000)]) });
    } catch (error) {
      const name = (error as { name?: unknown } | null)?.name;
      return fail('provider_unavailable', name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'fetch');
    }
  }
  async function checkStatus(response: Response): Promise<never> {
    if (response.status === 401) token = undefined;
    await response.body?.cancel();
    return fail([400, 403].includes(response.status) ? 'provider_configuration' : 'provider_unavailable', `auth0_status_${response.status}`);
  }
  async function accessToken(signal: AbortSignal) {
    if (token && token.expires > Date.now()) return token.value;
    const response = await request(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret,
        audience, scope: LEGAL_AUTH0_PROVISIONING_SCOPES }) }, signal);
    if (!response.ok) return checkStatus(response);
    const body = await response.json();
    if (typeof body.access_token !== 'string' || !body.access_token || body.token_type?.toLowerCase() !== 'bearer' ||
        !Number.isFinite(body.expires_in) || body.expires_in <= 0) return fail('provider_unavailable', 'token_response');
    token = { value: body.access_token, expires: Date.now() + Math.max(0, body.expires_in - 60) * 1000 };
    return token.value;
  }
  async function api(path: string, signal: AbortSignal, body?: unknown, method?: 'PATCH' | 'DELETE') {
    return request(`${origin}/api/v2/${path}`, { method: method ?? (body === undefined ? 'GET' : 'POST'),
      headers: { Authorization: `Bearer ${await accessToken(signal)}`, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, signal);
  }
  // Never infer absence from a partial listing and duplicate provider writes.
  async function find(path: string, fields: string, match: (row: any) => boolean, signal: AbortSignal): Promise<any | null> {
    for (let page = 0; page < 10; page++) {
      const response = await api(`${path}${path.includes('?') ? '&' : '?'}${new URLSearchParams({ page: String(page), per_page: '100',
        ...(fields ? { fields, include_fields: 'true' } : {}) })}`, signal);
      if (response.status !== 200) return checkStatus(response);
      const rows = await response.json();
      if (!Array.isArray(rows) || rows.length > 100 || rows.some(row => !row || typeof row !== 'object')) return fail('provider_unavailable', 'listing_shape');
      const found = rows.find(match);
      if (found) return found;
      if (rows.length < 100) return null;
    }
    return fail('lookup_limit');
  }
  function approved(application: LegalApplicationView) {
    const value = projectLegalApplication(application);
    if (!value || value.status !== 'approved') fail('invalid_application');
  }
  async function ensureMembership(email: string, organizationId: string, signal: AbortSignal,
    options: { readOnly?: boolean; subject?: string; approval?: boolean; created?: boolean } = {}) {
      const { readOnly = false, subject, approval = false, created = false } = options;
      if (!ORGANIZATION_ID.test(organizationId)) return fail('provider_binding');
      const base = `organizations/${organizationId}`;
      const readConnection = () => api(`${base}/enabled_connections/${connectionId}`, signal);
      let connection = await readConnection();
      if (connection.status === 404) {
        if (readOnly) return fail('provider_binding');
        await connection.body?.cancel();
        const added = await api(`${base}/enabled_connections`, signal, { connection_id: connectionId, assign_membership_on_login: false });
        if (![200, 201, 409].includes(added.status)) return checkStatus(added);
        await added.body?.cancel();
        connection = await readConnection();
      }
      if (connection.status !== 200) return checkStatus(connection);
      const enabled = await connection.json();
      if (enabled?.connection_id !== connectionId || enabled.assign_membership_on_login !== false) return fail('provider_configuration');
      // Use the role already managed by auth0/main.tf, without another manual ID.
      // Verify its exact permissions before assigning it; never infer authority
      // from a role name alone or give applicants onboarding-admin privileges.
      const role = await find('roles?name_filter=vera-legal-member', '', row => row.name === 'vera-legal-member', signal);
      if (!role || typeof role.id !== 'string' || !/^rol_[A-Za-z0-9]+$/.test(role.id)) return fail('provider_configuration');
      const permissionsResponse = await api(`roles/${role.id}/permissions?per_page=100`, signal);
      if (permissionsResponse.status !== 200) return checkStatus(permissionsResponse);
      const permissions = await permissionsResponse.json();
      const required = ['legal:case', 'legal:directory', 'legal:enroll'];
      if (!Array.isArray(permissions) || permissions.length !== required.length ||
          permissions.some(p => p?.resource_server_identifier !== legalAudience) ||
          permissions.map(p => p.permission_name).sort().join(' ') !== required.join(' ')) return fail('provider_configuration');
      const assignRole = async (userId: string) => {
        const path = `${base}/members/${encodeURIComponent(userId)}/roles`;
        if (!await find(path, '', row => row.id === role.id, signal)) {
          if (readOnly) return fail('provider_binding');
          const assigned = await api(path, signal, { roles: [role.id] });
          if (assigned.status !== 204) return checkStatus(assigned);
          await assigned.body?.cancel();
        }
      };
      // Resolve only the approved address in the configured login connection.
      // Do not auto-join everyone at the same domain or choose between duplicate
      // identities. Membership does not assert ownership of an email address.
      const connectionName = enabled.connection?.name;
      const strategy = enabled.connection?.strategy;
      if (typeof connectionName !== 'string' || !connectionName || !['auth0', 'email'].includes(strategy)) {
        return fail('provider_configuration');
      }
      const validUser = (user: any) => user && typeof user === 'object' &&
        typeof user.user_id === 'string' && USER_ID.test(user.user_id) &&
        typeof user.email === 'string' && user.email.toLowerCase() === email && Array.isArray(user.identities);
      const fromConnection = (user: any) => user.identities.some((identity: any) =>
        identity?.connection === connectionName && identity.provider === strategy);
      const lookupUser = async () => {
        const usersResponse = await api(`users-by-email?${new URLSearchParams({ email,
          fields: 'user_id,email,email_verified,blocked,identities', include_fields: 'true' })}`, signal);
        if (usersResponse.status !== 200) return checkStatus(usersResponse);
        const users = await usersResponse.json();
        if (!Array.isArray(users) || users.some(user => !validUser(user))) return fail('provider_binding');
        const candidates = users.filter(fromConnection);
        if (candidates.length > 1 || (candidates[0]?.blocked === true &&
            !(created && approval && candidates[0].user_id === subject))) return fail('provider_binding');
        return candidates[0] || null;
      };
      const user = await lookupUser();
      if (!user) return null;
      if ((subject && user.user_id !== subject) || (!approval && (subject || readOnly) && user.email_verified !== true) ||
          (created && (user.blocked !== true || user.email_verified !== false))) return fail('provider_binding');
      // Match the resolved identity, not just an email shared by a different
      // connection. A password account must not stand in for an email-code user.
      const member = await find(`${base}/members`, 'user_id,email', row => row.user_id === user.user_id &&
        typeof row.email === 'string' && row.email.toLowerCase() === email, signal);
      if (!member) {
        if (readOnly) return fail('provider_binding');
        const added = await api(`${base}/members`, signal, { members: [user.user_id] });
        if (added.status !== 204) return checkStatus(added);
        await added.body?.cancel();
      }
      await assignRole(user.user_id);
      return user.user_id as string;
  }
  async function approvedOrganization(target: LegalSignInTarget, signal: AbortSignal) {
    if (!ORGANIZATION_ID.test(target.providerOrganizationId) || target.email !== target.email.toLowerCase() ||
        target.email.length > 254 || !/^[^@\s]+@[^@\s]+$/.test(target.email) ||
        target.email.split('@')[1] !== target.domain) return fail('provider_binding');
    const response = await api(`organizations/${target.providerOrganizationId}`, signal);
    if (response.status !== 200) return checkStatus(response);
    const org = await response.json();
    if (org?.id !== target.providerOrganizationId || org.metadata?.vera_domain !== target.domain ||
        !/^[a-f0-9]{64}$/.test(org.metadata?.vera_application_id || '') ||
        !hasApproval(org.metadata) ||
        org.metadata.vera_legal_disabled === 'true') return fail('provider_binding');
  }
  async function updateCreatedAccount(subject: string, body: { email_verified?: false; blocked?: false }, signal: AbortSignal) {
    const response = await request(`${origin}/api/v2/users/${encodeURIComponent(subject)}`, { method: 'PATCH',
      headers: { Authorization: `Bearer ${await accessToken(signal)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body) }, signal);
    if (response.status !== 200) return checkStatus(response);
    const user = await response.json();
    if (user?.user_id !== subject || user.email_verified !== false ||
        user.blocked !== (body.blocked === false ? false : true)) return fail('provider_binding');
  }
  return {
    applicationOrganizations: applicationOrganizations(api, checkStatus, connectionId),
    nativeEntry: true,
    async registrationApproval(target, signal) {
      if (!ORGANIZATION_ID.test(target.providerOrganizationId) ||
          !Number.isSafeInteger(target.expires) || target.expires <= Date.now() ||
          target.expires > Date.now() + 7 * 86_400_000 || target.email !== target.email.toLowerCase() ||
          target.email.length > 254 || !/^[^@\s]+@[^@\s]+$/.test(target.email) ||
          target.email.split('@')[1] !== target.domain) return fail('provider_binding');
      const path = `organizations/${target.providerOrganizationId}`;
      const response = await api(path, signal);
      // A deleted organization never comes back; the membership job cancels on this.
      if (response.status === 404) { await response.body?.cancel(); return fail('provider_binding', 'organization_deleted'); }
      if (response.status !== 200) return checkStatus(response);
      const organization = await response.json();
      if (organization?.id !== target.providerOrganizationId || organization.metadata?.vera_domain !== target.domain ||
          !/^[a-f0-9]{64}$/.test(organization.metadata?.vera_application_id || '') ||
          !hasApproval(organization.metadata) ||
          organization.metadata.vera_legal_disabled === 'true') return fail('provider_binding');
      const key = legalEntryHintKey(target.email);
      const previous = organization.metadata[key];
      const expiry = typeof previous === 'string' && /^[0-9]{13}$/.test(previous) && Number(previous) >= target.expires &&
        Number(previous) <= Date.now() + 7 * 86_400_000 ? previous : String(target.expires);
      if (previous === expiry && organization.metadata.vera_approval_status === 'approved') return;
      // Auth0 replaces organization metadata in full. Only the approval worker
      // writes these hints; Actions never consume/modify them. A hint permits
      // account creation, NOT membership. The Mongo one-shot job owns that grant.
      const metadata = Object.fromEntries(Object.entries(organization.metadata).filter(([name, value]) =>
        !LEGAL_ENTRY_HINT_KEY.test(name) || Number(value) > Date.now()));
      metadata[key] = expiry;
      // Legacy organizations acquire an explicit status here. Never promote a
      // pending/denied Auth0 application from a stale work item (checked above).
      metadata.vera_approval_status = 'approved';
      if (Object.keys(metadata).length > 25) return fail('provider_configuration');
      const saved = await request(`${origin}/api/v2/${path}`, { method: 'PATCH',
        headers: { Authorization: `Bearer ${await accessToken(signal)}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ metadata }) }, signal);
      if (saved.status !== 200) return checkStatus(saved);
      const updated = await saved.json();
      if (updated?.id !== target.providerOrganizationId || updated.metadata?.[key] !== expiry ||
          updated.metadata?.vera_approval_status !== 'approved' ||
          updated.metadata?.vera_domain !== target.domain ||
          updated.metadata?.vera_application_id !== organization.metadata.vera_application_id) return fail('provider_binding');
    },
    async candidate(target, signal) {
      if (!ORGANIZATION_ID.test(target.providerOrganizationId)) return fail('provider_binding');
      const response = await api(`organizations/${target.providerOrganizationId}/enabled_connections/${connectionId}`, signal);
      if (response.status !== 200) return checkStatus(response);
      const connection = await response.json();
      if (connection?.connection_id !== connectionId || connection.assign_membership_on_login !== false ||
          connection.connection?.strategy !== 'email' || connection.connection?.name !== 'email') return fail('provider_configuration');
      const usersResponse = await api(`users-by-email?${new URLSearchParams({ email: target.email })}`, signal);
      if (usersResponse.status !== 200) return checkStatus(usersResponse);
      const users = await usersResponse.json();
      if (!Array.isArray(users)) return fail('provider_binding');
      const candidates = users.filter(user => user?.email?.toLowerCase() === target.email &&
        user.identities?.some((identity: any) => identity.connection === 'email' && identity.provider === 'email'));
      if (candidates.length > 1 || candidates[0]?.blocked === true) return fail('provider_binding');
      if (!candidates.length) return null;
      if (!/^email\|[^\s\u0000-\u001f]{1,200}$/.test(candidates[0].user_id || '')) return fail('provider_binding');
      return candidates[0].user_id;
    },
    async createApprovedAccount(target, signal) {
      await approvedOrganization(target, signal);
      // A welcome email would violate approval's no-email contract too. Require
      // an explicitly disabled template; never change tenant-wide settings here.
      const welcome = await api('email-templates/welcome_email', signal);
      if (welcome.status !== 200) return checkStatus(welcome);
      if ((await welcome.json())?.enabled !== false) return fail('provider_configuration');
      // Auth0 ignores verify_email:false for passwordless accounts. Its documented
      // workaround temporarily sets email_verified:true. Keep the new account
      // BLOCKED throughout that window, restore false before granting membership,
      // and unblock only after provisioning succeeds. Never apply this to an
      // existing account. Ambiguous writes are fenced by the one-shot job.
      const created = await api('users', signal, { connection: 'email', email: target.email,
        email_verified: true, verify_email: false, blocked: true });
      if (created.status !== 201) return checkStatus(created);
      const user = await created.json();
      if (!/^email\|[^\s\u0000-\u001f]{1,200}$/.test(user?.user_id || '') || user.email?.toLowerCase() !== target.email ||
          user.blocked !== true || !user.identities?.some((identity: any) => identity.connection === 'email' && identity.provider === 'email'))
        return fail('provider_binding');
      await updateCreatedAccount(user.user_id, { email_verified: false }, signal);
      return user.user_id;
    },
    async approveMembership(target, subject, signal, created) {
      if (!/^email\|[^\s\u0000-\u001f]{1,200}$/.test(subject)) return fail('provider_binding');
      await approvedOrganization(target, signal);
      const resolved = await ensureMembership(target.email, target.providerOrganizationId, signal, { subject, approval: true, created });
      if (!resolved) return fail('provider_binding');
      if (created) await updateCreatedAccount(subject, { blocked: false }, signal);
      return resolved;
    },
    async organization(application, signal) {
      approved(application);
      const name = `vera-legal-${application.id.slice(0, 32)}`;
      const checked = (body: any) => {
        if (!body || typeof body.id !== 'string' || !ORGANIZATION_ID.test(body.id) || body.name !== name ||
            body.metadata?.vera_application_id !== application.id || body.metadata?.vera_domain !== application.domain ||
            !hasApproval(body.metadata)) return fail('provider_binding');
        return body.id as string;
      };
      const read = () => api(`organizations/name/${name}`, signal);
      const existing = await read();
      if (existing.status === 200) return checked(await existing.json());
      if (existing.status !== 404) return checkStatus(existing);
      await existing.body?.cancel();
      if (application.providerOrganizationId) return fail('provider_binding');
      const created = await api('organizations', signal, { name, display_name: application.displayName,
        branding: { logo_url: VERA_LOGO_URL },
        metadata: { vera_application_id: application.id, vera_domain: application.domain, vera_approval_status: 'approved' },
        enabled_connections: [{ connection_id: connectionId, assign_membership_on_login: false }],
      });
      if (created.status === 201) return checked(await created.json());
      if (created.status === 409) {
        await created.body?.cancel();
        const raced = await read();
        if (raced.status === 200) return checked(await raced.json());
        return checkStatus(raced);
      }
      return checkStatus(created);
    },
    async invite(application, organizationId, signal) {
      approved(application);
      await ensureMembership(application.email, organizationId, signal);
    },
    async resolveApprovedMember(application, organizationId, signal) {
      approved(application);
      const response = await api(`organizations/${organizationId}`, signal);
      if (response.status !== 200) return checkStatus(response);
      const organization = await response.json();
      if (organization?.id !== organizationId || organization.metadata?.vera_application_id !== application.id ||
          organization.metadata?.vera_domain !== application.domain || organization.name !== `vera-legal-${application.id.slice(0, 32)}` ||
          !hasApproval(organization.metadata)) return fail('provider_binding');
      const subject = await ensureMembership(application.email, organizationId, signal, { readOnly: true });
      if (!subject) return fail('provider_binding');
      return subject;
    },
    async existingMember(target, signal) {
      return ensureMembership(target.email, target.providerOrganizationId, signal, { readOnly: true });
    },
    async completeSignIn(target, subject, signal, attach) {
      if (!USER_ID.test(subject)) return fail('provider_binding');
      const response = await api(`organizations/${target.providerOrganizationId}`, signal);
      if (response.status !== 200) return checkStatus(response);
      const org = await response.json();
      if (org?.id !== target.providerOrganizationId || org.metadata?.vera_domain !== target.domain ||
          !/^[a-f0-9]{64}$/.test(org.metadata?.vera_application_id || '') ||
          !hasApproval(org.metadata) ||
          org.metadata.vera_legal_disabled === 'true') return fail('provider_binding');
      const resolved = await ensureMembership(target.email, target.providerOrganizationId, signal, { readOnly: !attach, subject });
      if (!resolved) return fail('provider_binding');
      return resolved;
    },
    async inviteMember(target, signal) {
      const { providerOrganizationId, domain, email } = target;
      if (!ORGANIZATION_ID.test(providerOrganizationId) || !HOSTNAME.test(domain) || domain.length > 253 ||
          typeof email !== 'string' || email.length > 254 || email !== email.toLowerCase() ||
          !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(email) || email.split('@')[1] !== domain) return fail('provider_binding');
      // Manual onboarding has no application row. Validate the same exact domain
      // that the Auth0 Action enforces against platform-managed org metadata.
      const response = await api(`organizations/${providerOrganizationId}`, signal);
      if (response.status !== 200) return checkStatus(response);
      const organization = await response.json();
      if (organization?.id !== providerOrganizationId || organization.metadata?.vera_domain !== domain ||
          !hasApproval(organization.metadata)) return fail('provider_binding');
      await ensureMembership(email, providerOrganizationId, signal);

    },
  };
}

/** Persist an unenrolled roster before adding the applicant to Auth0. Auth0
 * membership enables sign-in only; firm-key enrollment and case grants remain separate. */
export async function provisionLegalApplication(application: LegalApplicationView,
  provider: ApplicationIdentityProvider, store: OrganizationRoster, signal = AbortSignal.timeout(45_000)): Promise<string> {
  // All provider requests share a deadline shorter than the 60-second work lease.
  const projected = projectLegalApplication(application);
  if (!projected || projected.status !== 'approved' || !validActor(projected.decidedBy) ||
      !Number.isSafeInteger(projected.decidedAt)) throw new LegalProvisioningError('invalid_application');
  const checked = validateNewLegalOrganization({ displayName: projected.displayName, domain: projected.domain,
    providerOrganizationId: 'org_validation' });
  if (!checked.ok) throw new LegalProvisioningError('invalid_application');
  const canonical = { ...projected, displayName: checked.value.displayName, domain: checked.value.domain };
  const matches = (raw: unknown, providerId?: string) => {
    const existing = projectLegalOrganization(raw);
    return existing && existing.organizationId === canonical.id && existing.status !== 'revoked' &&
      existing.displayName === canonical.displayName && existing.domain === canonical.domain && existing.providerOrganizationId &&
      (!providerId || existing.providerOrganizationId === providerId) &&
      (!canonical.organizationId || canonical.organizationId === existing.organizationId) &&
      (!canonical.providerOrganizationId || canonical.providerOrganizationId === existing.providerOrganizationId)
      ? existing.providerOrganizationId : null;
  };
  const existing = await store.getLegalOrganizationRecord(canonical.id);
  let providerOrganizationId: string;
  if (existing) {
    const bound = matches(existing);
    if (!bound) throw new LegalProvisioningError('roster_conflict');
    providerOrganizationId = bound;
  } else {
    if (canonical.organizationId) throw new LegalProvisioningError('roster_conflict');
    providerOrganizationId = await provider.organization(canonical, signal);
    if (canonical.providerOrganizationId && canonical.providerOrganizationId !== providerOrganizationId) throw new LegalProvisioningError('provider_binding');
    const organization = validateNewLegalOrganization({ displayName: canonical.displayName, domain: canonical.domain, providerOrganizationId });
    if (!organization.ok) throw new LegalProvisioningError('provider_binding');
    if (provider.applicationOrganizations && store.retireDeletedLegalOrganizations)
      await store.retireDeletedLegalOrganizations(canonical.domain, provider.applicationOrganizations, signal);
    try {
      await store.createLegalOrganization({ organizationId: canonical.id, ...organization.value }, canonical.decidedBy!, canonical.decidedAt!);
    } catch {
      if (!matches(await store.getLegalOrganizationRecord(canonical.id), providerOrganizationId)) throw new LegalProvisioningError('roster_conflict');
    }
  }
  if (provider.nativeEntry) {
    if (!store.queueLegalAuth0Membership || !provider.registrationApproval) throw new LegalProvisioningError('provider_configuration');
    const approval = { organizationId: canonical.id, providerOrganizationId, domain: canonical.domain, email: canonical.email,
      approvalId: canonical.id, expires: canonical.decidedAt! + 7 * 86_400_000 };
    await store.queueLegalAuth0Membership(approval);
    // New Auth0-backed applications become sign-in-ready only after the exact
    // membership job completes. Queueing alone must not announce a ready workspace.
    if (provider.applicationOrganizations && (!store.legalAuth0MembershipPrepared || !await store.legalAuth0MembershipPrepared(approval)))
      throw new LegalProvisioningError('provider_unavailable', 'membership_pending');
  } else await provider.invite(canonical, providerOrganizationId, signal);
  return providerOrganizationId;
}
