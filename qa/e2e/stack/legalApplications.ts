// External transports only: real application routes, HMAC verification, durable
// workers and roster transactions run unchanged. These values never leave QA.
const entryActions = require('../../../auth0/actions/domain-restriction.js');
export const applicationFixtures = {
  backend: { LEGAL_AUTH0_MGMT_DOMAIN: 'identity.example', LEGAL_AUTH0_MGMT_CLIENT_ID: 'synthetic-applications',
    LEGAL_AUTH0_MGMT_CLIENT_SECRET: 'synthetic-applications-secret', LEGAL_AUTH0_CONNECTION_ID: 'con_test',
    SLACK_APPLICATION_WEBHOOK_URL: 'https://hooks.slack.com/services/APPLICATIONS/TEST/SYNTHETIC' },
  frontend: { SLACK_APPLICATION_SIGNING_SECRET: 'synthetic-application-signing-secret', SLACK_APPLICATION_TEAM_ID: 'TTEST',
    SLACK_APPLICATION_APPROVERS: 'UTEST' },
};

export function installApplicationFixtures() {
  const original = globalThis.fetch;
  const organizations = new Map<string, { id: string; name: string; metadata: unknown }>();
  const messages: unknown[] = [];
  const invitations: Record<string, any>[] = [];
  const users: Record<string, any>[] = [];
  const memberships: Record<string, any>[] = [];
  const emails: { email: string; kind: 'verification' | 'code' }[] = [];
  const seedUser = (email: string) => {
    let user = users.find(row => row.email === email);
    if (!user) {
      user = { user_id: `email|fixture${users.length + 1}`, email, email_verified: true,
        identities: [{ connection: 'email', provider: 'email' }] };
      users.push(user);
    }
    user.email_verified = true;
    return user.user_id as string;
  };
  globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = init?.method || 'GET';
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    if (url.href === applicationFixtures.backend.SLACK_APPLICATION_WEBHOOK_URL) {
      messages.push(JSON.parse(String(init?.body))); return new Response('ok');
    }
    if (url.hostname !== applicationFixtures.backend.LEGAL_AUTH0_MGMT_DOMAIN) return original(input, init);
    if (url.pathname === '/oauth/token') {
      const body = JSON.parse(String(init?.body));
      return json({ access_token: body.client_id === 'synthetic-read-only-action' ? 'synthetic-action-token' : 'synthetic-application-token', token_type: 'Bearer', expires_in: 3600 });
    }
    const authorization = new Headers(init?.headers).get('Authorization');
    if (authorization === 'Bearer synthetic-action-token') {
      if (method !== 'GET') return json({}, 403);
    } else if (authorization !== 'Bearer synthetic-application-token') return json({}, 401);
    if (url.pathname === '/api/v2/roles') return json([{ id: 'rol_legal', name: 'vera-legal-member' }]);
    if (url.pathname === '/api/v2/email-templates/welcome_email') return json({ enabled: false });
    if (url.pathname === '/api/v2/roles/rol_legal/permissions') return json(
      ['legal:case', 'legal:directory', 'legal:enroll'].map(permission_name => ({ permission_name, resource_server_identifier: 'https://legal-api.example' })));
    if (url.pathname.startsWith('/api/v2/organizations/name/') && init?.method === 'GET') {
      const row = organizations.get(url.pathname.split('/').pop()!);
      return json(row || {}, row ? 200 : 404);
    }
    if (/^\/api\/v2\/organizations\/org_[A-Za-z0-9]+$/.test(url.pathname) && ['GET', 'PATCH'].includes(method)) {
      const organization = [...organizations.values()].find(row => row.id === url.pathname.split('/').pop());
      if (organization && method === 'PATCH') organization.metadata = JSON.parse(String(init?.body)).metadata;
      return organization ? json(organization) : json({}, 404);
    }
    if (url.pathname === '/api/v2/organizations' && method === 'GET') {
      const start = Number(url.searchParams.get('page') || 0) * Number(url.searchParams.get('per_page') || 100);
      return json([...organizations.values()].slice(start, start + Number(url.searchParams.get('per_page') || 100)));
    }
    if (url.pathname === '/api/v2/organizations' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      if (organizations.has(body.name)) return json({}, 409);
      const row = { ...body, id: `org_fixture${organizations.size + 1}` };
      organizations.set(body.name, row); return json(row, 201);
    }
    const orgId = url.pathname.split('/')[4];
    if (url.pathname.endsWith('/enabled_connections/con_test')) return json({ connection_id: 'con_test', assign_membership_on_login: false,
      connection: { name: 'email', strategy: 'email' } });
    if (url.pathname === '/api/v2/users-by-email') return json(users.filter(user => user.email === url.searchParams.get('email')));
    if (url.pathname === '/api/v2/users' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      if (users.some(user => user.email === body.email)) return json({}, 409);
      // Auth0 ignores verify_email:false on passwordless creation.
      if (body.email_verified !== true) emails.push({ email: body.email, kind: 'verification' });
      const user = { ...body, user_id: `email|fixture${users.length + 1}`,
        identities: [{ connection: 'email', provider: 'email' }] };
      users.push(user); return json(user, 201);
    }
    if (url.pathname.startsWith('/api/v2/users/') && method === 'PATCH') {
      const user = users.find(row => row.user_id === decodeURIComponent(url.pathname.split('/').pop()!));
      if (!user) return json({}, 404);
      Object.assign(user, JSON.parse(String(init?.body))); return json(user);
    }
    if (url.pathname.endsWith('/members')) {
      if (method === 'GET') return json(memberships.filter(row => row.organization_id === orgId));
      for (const id of JSON.parse(String(init?.body)).members) {
        const user = users.find(row => row.user_id === id);
        if (!user) return json({}, 400);
        if (!memberships.some(row => row.organization_id === orgId && row.user_id === id)) memberships.push({ ...user, organization_id: orgId, roles: [] });
      }
      return new Response(null, { status: 204 });
    }
    if (/\/members\/[^/]+\/roles$/.test(url.pathname)) {
      const userId = decodeURIComponent(url.pathname.split('/')[6]);
      const member = memberships.find(row => row.organization_id === orgId && row.user_id === userId);
      if (!member) return json({}, 404);
      if (method === 'GET') return json(member.roles.map((id: string) => ({ id })));
      member.roles = JSON.parse(String(init?.body)).roles; return new Response(null, { status: 204 });
    }
    if (url.pathname.endsWith('/invitations')) {
      if (init?.method === 'GET') return json(invitations.filter(row => row.organization_id === orgId));
      const body = JSON.parse(String(init?.body));
      const row = { ...body, id: `uinv_fixture${invitations.length + 1}`, organization_id: orgId,
        expires_at: new Date(Date.now() + 604800000).toISOString() };
      invitations.push(row); return json(row);
    }
    return json({}, 400);
  };
  return { seedUser,
    // Only Auth0 transport and OTP proof are synthetic. Run the deployed Action
    // source against Auth0 reads; the real background worker assigns membership.
    nativeEmail: async (email: string, clientId: string) => {
      const event = { client: { client_id: clientId }, connection: { id: 'con_test', name: 'email', strategy: 'email' },
        user: { email, user_id: '', email_verified: false }, transaction: { protocol: 'oidc-basic-profile' },
        request: { hostname: 'identity.example' }, resource_server: { identifier: 'https://identity.example/userinfo' },
        secrets: { LEGAL_CLIENT_ID: clientId, LEGAL_AUDIENCE: 'https://legal-api.example', LEGAL_EMAIL_CONNECTION_ID: 'con_test',
          LEGAL_MGMT_DOMAIN: 'identity.example', LEGAL_MGMT_CLIENT_ID: 'synthetic-read-only-action', LEGAL_MGMT_CLIENT_SECRET: 'synthetic-action-credential' } };
      let denied = false, organization: string | undefined;
      const api = { access: { deny: () => { denied = true; } },
        idToken: { setCustomClaim: (name: string, value: { organization: string }) => {
          if (name === 'https://vera.app/legal-entry') organization = value.organization;
        } } };
      await entryActions.onExecutePreUserRegistration(event, api);
      if (denied) throw new Error('Unapproved synthetic OTP');
      if (users.find(user => user.email === email)?.blocked === true) throw new Error('Blocked synthetic OTP');
      emails.push({ email, kind: 'code' });
      const subject = seedUser(email);
      event.user = { email, user_id: subject, email_verified: true };
      await entryActions.onExecutePostLogin(event, api);
      if (denied || !organization) throw new Error('Synthetic OTP membership failed');
      return { subject, organization };
    },
    snapshot: () => ({ messages, invitations, users, emails,
      memberships: memberships.map(member => ({ ...member, ...users.find(user => user.user_id === member.user_id) })),
      organizations: [...organizations.values()] }), restore: () => { globalThis.fetch = original; } };
}
