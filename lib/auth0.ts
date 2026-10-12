import { Auth0Client } from '@auth0/nextjs-auth0/server';
import { getTenantOrgId } from './tenant';

const ROLES_CLAIM = 'https://vera.app/roles';

// Silo multi-tenancy (VERA-PDR-001-A1): when this deployment serves a specific
// Auth0 Organization (TENANT_ORG_ID set), scope every login to it so Auth0
// returns the `org_id` claim and enforces membership at the IdP. When unset we
// pass no `authorizationParameters` at all, so historical single-tenant login
// is byte-for-byte unchanged. Passing only `organization` is safe: the SDK
// backfills the default scope (openid profile email …) via ensureDefaultScope,
// so the email + roles claims are preserved.
const tenantOrgId = getTenantOrgId();

export const auth0 = new Auth0Client({
  ...(tenantOrgId
    ? { authorizationParameters: { organization: tenantOrgId } }
    : {}),
  async beforeSessionSaved(session, idToken) {
    // idToken is the raw JWT string — decode the payload to extract custom claims
    let roles: string[] = [];
    let orgId: string | undefined;
    if (typeof idToken === 'string') {
      try {
        const payload = JSON.parse(
          Buffer.from(idToken.split('.')[1], 'base64url').toString(),
        );
        roles = payload[ROLES_CLAIM] ?? [];
        // `org_id` is a standard claim on org-scoped logins. Persist it into the
        // session so getOrgIdFromSession()/isAllowedAdminOrg() can enforce this
        // deployment's tenant (fail-closed once TENANT_ORG_ID is set).
        orgId = typeof payload.org_id === 'string' ? payload.org_id : undefined;
      } catch {
        // ignore decode errors
      }
    }

    return {
      ...session,
      user: {
        ...session.user,
        [ROLES_CLAIM]: roles,
        ...(orgId ? { org_id: orgId } : {}),
      },
    };
  },
});
