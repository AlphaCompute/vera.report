import { legalApplicationProvisioner, provisionLegalApplication, LEGAL_AUTH0_PROVISIONING_SCOPES, LEGAL_ENTRY_HINT_KEY, legalEntryHintKey } from '../../../src/services/legalApplicationAuth0';
import type { LegalApplicationView } from '../../../src/utils/legalApplications';
import { failureReason } from '../../../src/utils/failureReason';
import { createHash } from 'node:crypto';

const env = { LEGAL_AUTH0_MGMT_DOMAIN: 'legal.example', LEGAL_AUTH0_MGMT_CLIENT_ID: 'synthetic-client',
  LEGAL_AUTH0_MGMT_CLIENT_SECRET: 'synthetic-secret', LEGAL_AUTH0_CONNECTION_ID: 'con_test' };
const policy = { issuer: 'https://legal.example/', clientId: 'legal-portal-client', audience: 'https://legal-api.example' };
const organizationProvider = (config = env) => {
  const provider = legalApplicationProvisioner(config, policy)!;
  return (value: LegalApplicationView) => provider.organization(value, AbortSignal.timeout(45000));
};
const application: LegalApplicationView = { id: 'a'.repeat(64), displayName: 'Test Counsel', domain: 'firm.example',
  email: 'lawyer@firm.example', lawyerName: 'Test Lawyer', jurisdiction: 'Test', registrationNumber: 'TEST',
  status: 'approved', createdAt: 1000, decidedAt: 2000, decidedBy: 'admin' };
const organization = { id: 'org_created', name: `vera-legal-${application.id.slice(0, 32)}`,
  metadata: { vera_application_id: application.id, vera_domain: application.domain } };
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const token = () => response({ access_token: 'synthetic-token', token_type: 'Bearer', expires_in: 3600 });

describe('dedicated legal Auth0 provisioning', () => {
  afterEach(() => jest.restoreAllMocks());
  it('is optional, rejects incomplete/URL configuration and cannot provision pending or denied requests', async () => {
    expect(legalApplicationProvisioner({})).toBeNull();
    expect(() => legalApplicationProvisioner({ LEGAL_AUTH0_MGMT_DOMAIN: env.LEGAL_AUTH0_MGMT_DOMAIN }, policy)).toThrow('configuration');
    for (const invalid of [{ ...env, LEGAL_AUTH0_MGMT_DOMAIN: 'https://legal.example/path' },
      { ...env, LEGAL_AUTH0_MGMT_CLIENT_SECRET: '' }, { ...env, LEGAL_AUTH0_CONNECTION_ID: 'untrusted' }, { ...env, LEGAL_AUTH0_CONNECTION_ID: '' }]) {
      expect(() => legalApplicationProvisioner(invalid, policy)).toThrow('configuration');
    }
    const fetchMock = jest.spyOn(global, 'fetch');
    for (const status of ['pending', 'denied'] as const) {
      await expect(organizationProvider()({ ...application, status })).rejects.toThrow();
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('creates with fixed scope, deterministic binding and no automatic membership; retries reuse the organization', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token())
      .mockResolvedValueOnce(response({}, 404)).mockResolvedValueOnce(response(organization, 201))
      .mockResolvedValueOnce(response(organization));
    const provision = organizationProvider();
    expect(await provision(application)).toBe('org_created');
    expect(await provision(application)).toBe('org_created');
    const calls = fetchMock.mock.calls;
    expect(calls).toHaveLength(4);
    expect(calls.every(([, init]) => init?.redirect === 'error' && init.signal)).toBe(true);
    expect(JSON.parse(calls[0][1]!.body as string)).toMatchObject({ audience: 'https://legal.example/api/v2/', scope: LEGAL_AUTH0_PROVISIONING_SCOPES });
    expect(calls[1][0]).toBe(`https://legal.example/api/v2/organizations/name/${organization.name}`);
    const payload = JSON.parse(calls[2][1]!.body as string);
    expect(payload).toEqual({ name: organization.name, display_name: application.displayName,
      metadata: { ...organization.metadata, vera_approval_status: 'approved' },
      branding: { logo_url: 'https://vera.report/apple-touch-icon.png' },
      enabled_connections: [{ connection_id: 'con_test', assign_membership_on_login: false }] });
    expect(JSON.stringify(payload)).not.toContain(application.email);
  });
  it('recovers a lost create response by name without another POST', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token())
      .mockResolvedValueOnce(response({}, 404)).mockRejectedValueOnce(new Error('connection lost after creation'))
      .mockResolvedValueOnce(response(organization));
    const provision = organizationProvider();
    await expect(provision(application)).rejects.toThrow();
    expect(await provision(application)).toBe('org_created');
    expect(fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith('/organizations') && init?.method === 'POST')).toHaveLength(1);
  });
  it('handles a concurrent create conflict only when the stored binding matches', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({}, 404))
      .mockResolvedValueOnce(response({}, 409)).mockResolvedValueOnce(response(organization));
    expect(await organizationProvider()(application)).toBe('org_created');
  });
  it.each([{}, { ...organization, metadata: { vera_application_id: 'b'.repeat(64), vera_domain: application.domain } }])(
    'does not adopt a foreign or malformed organization', async foreign => {
      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response(foreign));
      await expect(organizationProvider()(application)).rejects.toThrow('unavailable');
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  it('does not create on lookup failure and refreshes an expired token on the next durable retry', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({ error: 'private' }, 401))
      .mockResolvedValueOnce(token()).mockResolvedValueOnce(response(organization));
    const provision = organizationProvider();
    await expect(provision(application)).rejects.toThrow('unavailable');
    expect(await provision(application)).toBe('org_created');
    expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/oauth/token'))).toHaveLength(2);
  });
  it('keeps the existing manual or active binding and finishes only its invitation', async () => {
    const row = { _id: application.id, displayName: application.displayName, domain: application.domain,
      providerOrganizationId: 'org_manual', approved: true, registration: 'signed-key-registration', publicKey: 'unchanged' };
    const store = { getLegalOrganizationRecord: jest.fn().mockResolvedValue(row), createLegalOrganization: jest.fn() };
    const provider = { organization: jest.fn(async () => 'org_unwanted'), invite: jest.fn(async () => {}) };
    expect(await provisionLegalApplication({ ...application, organizationId: application.id, providerOrganizationId: 'org_manual' }, provider, store)).toBe('org_manual');
    expect(await provisionLegalApplication(application, provider, store)).toBe('org_manual');
    await expect(provisionLegalApplication({ ...application, providerOrganizationId: 'org_other' }, provider, store)).rejects.toThrow('conflict');
    store.getLegalOrganizationRecord.mockResolvedValue({ ...row, revokedAt: new Date() });
    await expect(provisionLegalApplication(application, provider, store)).rejects.toThrow('conflict');
    expect(provider.organization).not.toHaveBeenCalled(); expect(store.createLegalOrganization).not.toHaveBeenCalled();
    expect(provider.invite).toHaveBeenCalledTimes(2);
    expect(provider.invite).toHaveBeenCalledWith(expect.objectContaining({ id: application.id }), 'org_manual', expect.any(AbortSignal));
  });
  it('validates legacy input before provider side effects and uses the same canonical name on retry', async () => {
    const provider = { organization: jest.fn(async () => 'org_created'), invite: jest.fn(async () => {}) };
    const store = { getLegalOrganizationRecord: jest.fn(), createLegalOrganization: jest.fn() };
    for (const displayName of ['A', 'Bad\u2028Firm', 'Bad\u2029Firm', 'Bad\u0085Firm']) {
      await expect(provisionLegalApplication({ ...application, displayName }, provider, store)).rejects.toThrow('invalid_application');
    }
    expect(provider.organization).not.toHaveBeenCalled(); expect(store.createLegalOrganization).not.toHaveBeenCalled();
    const spaced = { ...application, displayName: 'Test   Counsel' };
    expect(await provisionLegalApplication(spaced, provider, store)).toBe('org_created');
    expect(provider.organization).toHaveBeenCalledWith({ ...application, provisioningStatus: 'queued' }, expect.any(AbortSignal));
    expect(store.createLegalOrganization).toHaveBeenCalledWith(expect.objectContaining({ displayName: 'Test Counsel' }), 'admin', 2000);
    store.getLegalOrganizationRecord.mockResolvedValue({ _id: application.id, displayName: 'Test Counsel', domain: application.domain, providerOrganizationId: 'org_created' });
    expect(await provisionLegalApplication(spaced, provider, store)).toBe('org_created');
    expect(provider.organization).toHaveBeenCalledTimes(1);
  });
  it('creates only an unenrolled roster entry and recovers only an exact existing binding', async () => {
    const createLegalOrganization = jest.fn().mockResolvedValue(undefined);
    const getLegalOrganizationRecord = jest.fn();
    const store = { createLegalOrganization, getLegalOrganizationRecord };
    const provider = { organization: jest.fn(async () => 'org_created'), invite: jest.fn(async () => {}) };
    expect(await provisionLegalApplication(application, provider, store)).toBe('org_created');
    expect(createLegalOrganization).toHaveBeenCalledWith({ organizationId: application.id, displayName: application.displayName,
      domain: application.domain, providerOrganizationId: 'org_created' }, 'admin', 2000);
    createLegalOrganization.mockRejectedValue(new Error('duplicate'));
    getLegalOrganizationRecord.mockResolvedValue({ _id: application.id, displayName: application.displayName, domain: application.domain, providerOrganizationId: 'org_created' });
    expect(await provisionLegalApplication(application, provider, store)).toBe('org_created');
    getLegalOrganizationRecord.mockResolvedValue({ _id: application.id, displayName: 'Different firm', domain: application.domain, providerOrganizationId: 'org_foreign' });
    await expect(provisionLegalApplication(application, provider, store)).rejects.toThrow('conflict');
    getLegalOrganizationRecord.mockResolvedValue({ domain: application.domain, providerOrganizationId: 'org_created', revokedAt: new Date() });
    await expect(provisionLegalApplication(application, provider, store)).rejects.toThrow('conflict');
  });
});

describe('native Auth0 registration hints and approved candidates', () => {
  const key = `vera_entry_${createHash('sha256').update(application.email).digest('hex').slice(0, 39)}`;
  const target = () => ({ providerOrganizationId: organization.id, domain: application.domain,
    email: application.email, expires: Date.now() + 60000 });
  const nativeProvider = () => legalApplicationProvisioner(env, policy)!;
  const emailConnection = { connection_id: 'con_test', assign_membership_on_login: false,
    connection: { name: 'email', strategy: 'email' } };
  const user = { user_id: 'email|approved', email: application.email, email_verified: true,
    identities: [{ connection: 'email', provider: 'email' }] };
  afterEach(() => jest.restoreAllMocks());
  it('keeps the entry hint key within the Auth0 metadata key limit', () => {
    expect(key).toHaveLength(50);
    expect(legalEntryHintKey(application.email)).toBe(key);
    expect(LEGAL_ENTRY_HINT_KEY.test(key)).toBe(true);
  });
  it('queues approval silently and announces readiness only after membership is prepared', async () => {
    const provider = nativeProvider();
    const fetchMock = jest.spyOn(global, 'fetch');
    const store = {
      getLegalOrganizationRecord: jest.fn(async () => ({ _id: application.id, displayName: application.displayName,
        domain: application.domain, providerOrganizationId: organization.id })),
      createLegalOrganization: jest.fn(), queueLegalAuth0Membership: jest.fn(),
      legalAuth0MembershipPrepared: jest.fn().mockResolvedValue(false),
    };
    expect(provider.nativeEntry).toBe(true);
    await expect(provisionLegalApplication(application, provider, store)).rejects.toMatchObject({ code: 'provider_unavailable', detail: 'membership_pending' });
    store.legalAuth0MembershipPrepared.mockResolvedValue(true);
    expect(await provisionLegalApplication(application, provider, store)).toBe(organization.id);
    expect(store.queueLegalAuth0Membership).toHaveBeenCalledWith(expect.objectContaining({
      approvalId: application.id, email: application.email, providerOrganizationId: organization.id,
    }));
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('stores only an expiring exact-address hash hint and preserves unrelated metadata under Auth0 replacement semantics', async () => {
    let org = { ...organization, metadata: { ...organization.metadata, custom_setting: 'preserve',
      [`vera_entry_${'0'.repeat(39)}`]: '1' } as Record<string, string> };
    const calls = jest.spyOn(global, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/oauth/token')) {
        expect(JSON.parse(String(init?.body)).scope).toContain('update:organizations'); return token();
      }
      expect(String(url)).toBe(`https://legal.example/api/v2/organizations/${organization.id}`);
      if (init?.method === 'PATCH') {
        const metadata = JSON.parse(String(init.body)).metadata;
        // Auth0 rejects metadata keys longer than 50 characters (400 Bad Request).
        if (Object.keys(metadata).some(name => name.length > 50)) return new Response('{}', { status: 400 });
        org = { ...org, metadata };
      }
      return response(org);
    });
    const provider = nativeProvider(), value = target();
    await provider.registrationApproval!(value, AbortSignal.timeout(45000));
    await provider.registrationApproval!(value, AbortSignal.timeout(45000));
    expect(org.metadata).toEqual({ ...organization.metadata, custom_setting: 'preserve',
      vera_approval_status: 'approved', [key]: String(value.expires) });
    expect(calls.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1);
    expect(JSON.stringify(org)).not.toContain(application.email);
  });
  it('records approval on an existing organization without shortening its hint or changing the sign-in flow', async () => {
    const value = target(), existingExpiry = String(value.expires + 60000);
    let org = { ...organization, metadata: { ...organization.metadata, custom_setting: 'preserve',
      [key]: existingExpiry } as Record<string, string> };
    const calls = jest.spyOn(global, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/oauth/token')) return token();
      expect(String(url)).toBe(`https://legal.example/api/v2/organizations/${organization.id}`);
      if (init?.method === 'PATCH') {
        const metadata = JSON.parse(String(init.body)).metadata;
        // Auth0 rejects metadata keys longer than 50 characters (400 Bad Request).
        if (Object.keys(metadata).some(name => name.length > 50)) return new Response('{}', { status: 400 });
        org = { ...org, metadata };
      }
      return response(org);
    });
    const provider = nativeProvider();
    await provider.registrationApproval!(value, AbortSignal.timeout(45000));
    await provider.registrationApproval!(value, AbortSignal.timeout(45000));
    expect(org.metadata).toEqual({ ...organization.metadata, custom_setting: 'preserve',
      vera_approval_status: 'approved', [key]: existingExpiry });
    expect(calls.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1);
    expect(calls.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1); // OAuth token only.
  });
  it.each([
    { ...organization, metadata: { ...organization.metadata, vera_legal_disabled: 'true' } },
    { ...organization, metadata: { ...organization.metadata, vera_domain: 'other.example' } },
    { ...organization, metadata: { ...organization.metadata, ...Object.fromEntries(Array.from({ length: 23 }, (_, i) => [`other_${i}`, 'keep'])) } },
  ])('cannot publish a hint in a disabled, mismatched or full organization', async org => {
    const calls = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValue(response(org));
    await expect(nativeProvider().registrationApproval!(target(), AbortSignal.timeout(45000))).rejects.toThrow();
    expect(calls.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false);
  });
  it('reports only a 404 on the target organization as deleted, before any write', async () => {
    const calls = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({ message: 'private' }, 404));
    const error = await nativeProvider().registrationApproval!(target(), AbortSignal.timeout(45000)).catch(caught => caught);
    expect(error).toMatchObject({ code: 'provider_binding', detail: 'organization_deleted' });
    expect(failureReason(error)).toBe('provider_binding:organization_deleted');
    expect(calls.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false);
  });
  it.each([[500, 'provider_unavailable'], [429, 'provider_unavailable'], [403, 'provider_configuration']] as const)(
    'labels Auth0 status %i with its source and keeps the code', async (status, code) => {
      jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({ message: 'private' }, status));
      const error = await nativeProvider().registrationApproval!(target(), AbortSignal.timeout(45000)).catch(caught => caught);
      expect(error).toMatchObject({ code, detail: `auth0_status_${status}` });
      expect(failureReason(error)).toBe(`${code}:auth0_status_${status}`);
    });
  it('labels a failed or timed-out request without its message', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockRejectedValueOnce(new TypeError(`fetch failed ${application.email}`))
      .mockRejectedValueOnce(new DOMException('slow', 'TimeoutError'));
    const provider = nativeProvider();
    const failed = await provider.registrationApproval!(target(), AbortSignal.timeout(45000)).catch(caught => caught);
    const slow = await provider.registrationApproval!(target(), AbortSignal.timeout(45000)).catch(caught => caught);
    expect([failureReason(failed), failureReason(slow)]).toEqual(['provider_unavailable:fetch', 'provider_unavailable:timeout']);
    expect(failed.message).not.toContain(application.email);
  });
  it('only looks up a missing account without creating or verifying it', async () => {
    const calls = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token())
      .mockResolvedValueOnce(response(emailConnection)).mockResolvedValueOnce(response([]));
    expect(await nativeProvider().candidate!(target(), AbortSignal.timeout(45000))).toBeNull();
    expect(calls.mock.calls.slice(1).every(([, init]) => init?.method === 'GET')).toBe(true);
  });
  it.each([true, false])('resolves the pinned email identity independently of verification (%s)', async email_verified => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(token())
      .mockResolvedValueOnce(response(emailConnection)).mockResolvedValueOnce(response([{ ...user, email_verified }]));
    expect(await nativeProvider().candidate!(target(), AbortSignal.timeout(45000))).toBe('email|approved');
  });
  it.each([{ users: [{ ...user, blocked: true }] }, { users: [user, { ...user, user_id: 'email|ambiguous' }] }])('rejects blocked or ambiguous candidates', async ({ users }) => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(token())
      .mockResolvedValueOnce(response(emailConnection)).mockResolvedValueOnce(response(users));
    await expect(nativeProvider().candidate!(target(), AbortSignal.timeout(45000))).rejects.toThrow();
  });
  it('queues the same approval identity without attempting membership inside provisioning', async () => {
    const row = { _id: application.id, displayName: application.displayName, domain: application.domain,
      providerOrganizationId: organization.id, approved: false };
    const store = { getLegalOrganizationRecord: jest.fn(async () => row), createLegalOrganization: jest.fn(),
      queueLegalAuth0Membership: jest.fn(async () => {}) };
    const provider = { nativeEntry: true, organization: jest.fn(), invite: jest.fn(), registrationApproval: jest.fn() };
    await provisionLegalApplication(application, provider, store);
    await provisionLegalApplication(application, provider, store);
    expect(store.queueLegalAuth0Membership).toHaveBeenCalledWith({ organizationId: application.id, approvalId: application.id,
      providerOrganizationId: organization.id, email: application.email, domain: application.domain, expires: application.decidedAt! + 7 * 86_400_000 });
    expect(provider.invite).not.toHaveBeenCalled(); expect(provider.registrationApproval).not.toHaveBeenCalled();
  });
});

describe('automatic Auth0 membership on approval', () => {
  const connection = { connection_id: 'con_test', assign_membership_on_login: false,
    connection: { name: 'Legal-Accounts', strategy: 'auth0' } };
  const account = (extra = {}) => ({ user_id: 'auth0|approved', email: application.email, email_verified: false,
    identities: [{ connection: 'Legal-Accounts', provider: 'auth0' }], ...extra });
  function fixture(initialUsers: any[] = []) {
    const users = [...initialUsers], members: any[] = [], roles = new Set<string>();
    let failure: 'create' | 'verify' | 'member' | 'role' | null = null;
    let conflict = false;
    let enabled: any = connection;
    let lookupStatus = 200;
    let rolePermissions = ['legal:case', 'legal:directory', 'legal:enroll'];
    let welcomeEnabled = false;
    const calls = jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input)), body = init?.body ? JSON.parse(String(init.body)) : undefined;
      if (url.pathname === '/oauth/token') return token();
      if (url.pathname === '/api/v2/email-templates/welcome_email') return response({ enabled: welcomeEnabled });
      if (url.pathname.endsWith('/enabled_connections/con_test')) return response(enabled);
      if (url.pathname === '/api/v2/roles') return response([{ id: 'rol_legal', name: 'vera-legal-member' }]);
      if (url.pathname.endsWith('/roles/rol_legal/permissions')) return response(rolePermissions.map(permission_name =>
        ({ permission_name, resource_server_identifier: policy.audience })));
      if (url.pathname === '/api/v2/users-by-email') return response(users, lookupStatus);
      if (url.pathname === '/api/v2/users' && init?.method === 'POST') {
        const user = account({ ...body, user_id: `${enabled.connection.strategy}|approved`,
          identities: [{ connection: body.connection, provider: enabled.connection.strategy }] }); users.push(user);
        if (failure === 'create') { failure = null; throw new Error('lost create response'); }
        if (conflict) return response({}, 409);
        return response(user, 201);
      }
      if (url.pathname === '/api/v2/users/email%7Capproved' && init?.method === 'PATCH') {
        const user = users.find(row => row.user_id === 'email|approved');
        if (failure === 'verify' && body.email_verified === false) return response({}, 503);
        Object.assign(user, body);
        return response(user);
      }
      if (url.pathname.endsWith('/members')) {
        if (init?.method === 'GET') return response(members);
        const user = users.find(row => row.user_id === body.members[0]);
        if (!user) throw new Error('unbound membership');
        members.push(user);
        if (failure === 'member') { failure = null; throw new Error('lost member response'); }
        return new Response(null, { status: 204 });
      }
      if (/\/members\/(?:auth0|email)%7Capproved\/roles$/.test(url.pathname)) {
        if (init?.method === 'GET') return response([...roles].map(id => ({ id })));
        if (failure === 'role') { failure = null; return response({}, 503); }
        body.roles.forEach((id: string) => roles.add(id));
        return new Response(null, { status: 204 });
      }
      if (url.pathname === '/api/v2/organizations/org_created') return response(organization);
      throw new Error('Unexpected provider operation: ' + url.pathname);
    });
    const provider = legalApplicationProvisioner(env, policy)!;
    return { calls, users, members, roles, provider,
      run: () => provider.invite(application, 'org_created', AbortSignal.timeout(45000)),
      fail: (point: typeof failure) => { failure = point; },
      conflict: () => { conflict = true; },
      connection: (value: any) => { enabled = value; },
      lookupStatus: (value: number) => { lookupStatus = value; },
      rolePermissions: (value: string[]) => { rolePermissions = value; },
      welcomeEnabled: () => { welcomeEnabled = true; },
      posts: (path: string) => calls.mock.calls.filter(([url, init]) => new URL(String(url)).pathname === '/api/v2/' + path && init?.method === 'POST') };
  }
  afterEach(() => jest.restoreAllMocks());
  it('defers a missing account until native OTP sign-in without sending an email', async () => {
    const f = fixture(); await f.run(); await f.run();
    expect(f.members).toHaveLength(0); expect(f.users).toHaveLength(0);
    expect(f.posts('users')).toHaveLength(0);
    expect(f.calls.mock.calls.some(([url]) => String(url).includes('/invitations'))).toBe(false);
    expect(LEGAL_AUTH0_PROVISIONING_SCOPES.split(' ')).toEqual(expect.arrayContaining(['create:users', 'update:users', 'read:email_templates']));
  });  it.each([true, false])('adds an existing account immediately without changing its verified-email state (%s)', async email_verified => {
    const user = account({ email_verified }), f = fixture([user]); await f.run();
    expect(f.members).toEqual([user]); expect([...f.roles]).toEqual(['rol_legal']);
    expect(f.posts('users')).toHaveLength(0);
    expect(f.calls.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false);
  });
  it.each([true, false])('approves an existing email account before sign-in without sending mail or changing verification (%s)', async email_verified => {
    const user = account({ user_id: 'email|approved', email_verified, identities: [{ connection: 'email', provider: 'email' }] });
    const f = fixture([user]); f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    const target = { providerOrganizationId: 'org_created', domain: application.domain, email: application.email };
    await f.provider.approveMembership!(target, user.user_id, AbortSignal.timeout(45000), false);
    expect(f.members).toEqual([user]); expect([...f.roles]).toEqual(['rol_legal']);
    expect(user.email_verified).toBe(email_verified);
    expect(f.posts('users')).toHaveLength(0);
    expect(f.calls.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false);
    if (!email_verified) {
      await expect(f.provider.resolveApprovedMember!(application, 'org_created', AbortSignal.timeout(45000))).rejects.toThrow();
    }
  });
  it('creates a blocked account silently, clears verification before membership, then unblocks it', async () => {
    const f = fixture(); f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    const target = { providerOrganizationId: 'org_created', domain: application.domain, email: application.email };
    const subject = await f.provider.createApprovedAccount!(target, AbortSignal.timeout(45000));
    expect(f.users).toEqual([expect.objectContaining({ user_id: subject, email_verified: false, blocked: true })]);
    expect(f.members).toEqual([]);
    await f.provider.approveMembership!(target, subject, AbortSignal.timeout(45000), true);
    expect(f.users[0]).toMatchObject({ email_verified: false, blocked: false });
    expect(f.members).toHaveLength(1); expect([...f.roles]).toEqual(['rol_legal']);
    const writes = f.calls.mock.calls.filter(([url, init]) => !String(url).endsWith('/oauth/token') && init?.method !== 'GET')
      .map(([url, init]) => ({ path: new URL(String(url)).pathname, body: JSON.parse(String(init?.body)) }));
    expect(writes).toEqual([
      { path: '/api/v2/users', body: { connection: 'email', email: application.email, email_verified: true, verify_email: false, blocked: true } },
      { path: '/api/v2/users/email%7Capproved', body: { email_verified: false } },
      { path: '/api/v2/organizations/org_created/members', body: { members: [subject] } },
      { path: '/api/v2/organizations/org_created/members/email%7Capproved/roles', body: { roles: ['rol_legal'] } },
      { path: '/api/v2/users/email%7Capproved', body: { blocked: false } },
    ]);
    await expect(f.provider.resolveApprovedMember!(application, 'org_created', AbortSignal.timeout(45000))).rejects.toThrow();
  });
  it('refuses account creation if welcome emails are enabled', async () => {
    const f = fixture(); f.welcomeEnabled();
    await expect(f.provider.createApprovedAccount!({ providerOrganizationId: 'org_created', domain: application.domain,
      email: application.email }, AbortSignal.timeout(45000))).rejects.toMatchObject({ code: 'provider_configuration' });
    expect(f.posts('users')).toHaveLength(0);
  });
  it('keeps a new account blocked if membership provisioning fails', async () => {
    const f = fixture(); f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    const target = { providerOrganizationId: 'org_created', domain: application.domain, email: application.email };
    const subject = await f.provider.createApprovedAccount!(target, AbortSignal.timeout(45000));
    f.fail('role');
    await expect(f.provider.approveMembership!(target, subject, AbortSignal.timeout(45000), true)).rejects.toThrow();
    expect(f.users[0]).toMatchObject({ email_verified: false, blocked: true });
  });
  it('cannot grant membership or unblock a new account if clearing temporary verification fails', async () => {
    const f = fixture(); f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    const target = { providerOrganizationId: 'org_created', domain: application.domain, email: application.email };
    f.fail('verify');
    await expect(f.provider.createApprovedAccount!(target, AbortSignal.timeout(45000))).rejects.toThrow();
    expect(f.users[0]).toMatchObject({ email_verified: true, blocked: true });
    await expect(f.provider.approveMembership!(target, 'email|approved', AbortSignal.timeout(45000), true)).rejects.toThrow();
    expect(f.members).toEqual([]); expect([...f.roles]).toEqual([]);
    expect(f.users[0].blocked).toBe(true);
  });
  it('never unblocks an existing blocked applicant', async () => {
    const user = account({ user_id: 'email|approved', blocked: true, identities: [{ connection: 'email', provider: 'email' }] });
    const f = fixture([user]); f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    await expect(f.provider.approveMembership!({ providerOrganizationId: 'org_created', domain: application.domain,
      email: application.email }, user.user_id, AbortSignal.timeout(45000), false)).rejects.toThrow();
    expect(f.members).toEqual([]); expect(user.blocked).toBe(true);
    expect(f.calls.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false);
  });
  it('attaches a native OTP account only when its verified subject matches', async () => {
    const f = fixture();
    f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    await f.run(); expect(f.posts('users')).toHaveLength(0);
    const user = account({ user_id: 'email|approved', email_verified: true, identities: [{ connection: 'email', provider: 'email' }] });
    f.users.push(user);
    const target = { providerOrganizationId: 'org_created', domain: application.domain, email: application.email };
    await expect(f.provider.completeSignIn!(target, 'email|wrong', AbortSignal.timeout(45000), true)).rejects.toThrow();
    user.email_verified = false;
    await expect(f.provider.completeSignIn!(target, 'email|approved', AbortSignal.timeout(45000), true)).rejects.toThrow();
    expect(f.members).toHaveLength(0);
    user.email_verified = true;
    expect(await f.provider.completeSignIn!(target, 'email|approved', AbortSignal.timeout(45000), true)).toBe('email|approved');
    expect(f.members).toEqual([user]); expect([...f.roles]).toEqual(['rol_legal']);
    expect(f.posts('users')).toHaveLength(0);
    f.roles.clear();
    await expect(f.provider.completeSignIn!(target, 'email|approved', AbortSignal.timeout(45000), false)).rejects.toThrow();
    expect([...f.roles]).toEqual([]); // A consumed approval cannot repair a removed role.
  });
  it('does not treat a password membership as an email-code membership', async () => {
    const existing = account(), f = fixture([existing]); f.members.push(existing);
    f.connection({ ...connection, connection: { name: 'email', strategy: 'email' } });
    await f.run(); await f.run();
    expect(f.members.map(row => row.user_id)).toEqual(['auth0|approved']);
    expect(f.posts('users')).toHaveLength(0);
    expect(f.posts('organizations/org_created/members')).toHaveLength(0);
  });  it('is idempotent and repairs a missing organization role', async () => {
    const f = fixture([account()]); await f.run(); f.roles.clear(); await f.run();
    expect(f.posts('organizations/org_created/members')).toHaveLength(1);
    expect(f.posts('users')).toHaveLength(0); expect([...f.roles]).toEqual(['rol_legal']);
  });
  it.each(['member', 'role'] as const)('recovers a %s failure without creating another account', async point => {
    const f = fixture([account()]); f.fail(point); await expect(f.run()).rejects.toThrow(); await f.run();
    expect(f.users).toHaveLength(1); expect(f.members).toHaveLength(1);
    expect([...f.roles]).toEqual(['rol_legal']); expect(f.posts('users')).toHaveLength(0);
  });  it.each([
    [account({ blocked: true })], [account(), account({ user_id: 'auth0|duplicate' })],
    [account({ email: 'someone-else@firm.example' })], [account({ user_id: 'invalid' })], [account({ identities: null })],
  ])('fails closed on blocked, ambiguous or mismatched account results', async (...users) => {
    const f = fixture(users); await expect(f.run()).rejects.toMatchObject({ code: 'provider_binding' });
    expect(f.members).toHaveLength(0); expect(f.posts('users')).toHaveLength(0);
  });
  it('does not reuse a same-email account from another connection', async () => {
    const foreign = account({ user_id: 'auth0|foreign', identities: [{ connection: 'Other', provider: 'auth0' }] });
    const f = fixture([foreign]); await f.run();
    expect(f.members).toHaveLength(0);
  });
  it('does not mistake a failed lookup for a new user', async () => {
    const f = fixture(); f.lookupStatus(403);
    await expect(f.run()).rejects.toMatchObject({ code: 'provider_configuration' });
    expect(f.posts('users')).toHaveLength(0); expect(f.members).toHaveLength(0);
  });
  it.each([
    { ...connection, assign_membership_on_login: true },
    { ...connection, connection: undefined },
    { ...connection, connection: { name: 'Enterprise', strategy: 'samlp' } },
  ])('rejects unsafe or unsupported new-account connection configuration', async enabled => {
    const f = fixture(); f.connection(enabled);
    await expect(f.run()).rejects.toMatchObject({ code: 'provider_configuration' }); expect(f.posts('users')).toHaveLength(0);
  });
  it('never grants onboarding-admin permissions', async () => {
    const f = fixture(); f.rolePermissions(['legal:invite']);
    await expect(f.run()).rejects.toMatchObject({ code: 'provider_configuration' }); expect(f.members).toHaveLength(0);
  });
  it('adds a colleague only after validating the approved organization domain', async () => {
    const f = fixture([account()]);
    await f.provider.inviteMember!({ providerOrganizationId: 'org_created', domain: application.domain, email: application.email }, AbortSignal.timeout(45000));
    expect(f.members).toHaveLength(1);
    await expect(f.provider.inviteMember!({ providerOrganizationId: 'org_created', domain: 'other.example', email: application.email }, AbortSignal.timeout(45000))).rejects.toMatchObject({ code: 'provider_binding' });
  });
  it('does not perform provider operations for pending applications or after the deadline', async () => {
    const f = fixture();
    await expect(f.provider.invite({ ...application, status: 'pending' }, 'org_created', AbortSignal.timeout(45000))).rejects.toThrow();
    await expect(f.provider.invite(application, 'org_created', AbortSignal.abort())).rejects.toThrow();
    expect(f.calls).not.toHaveBeenCalled();
  });
  it('the shared attempt deadline cancels a slow provider request', async () => {
    const deadline = new AbortController();
    jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => new Promise((_resolve, reject) => {
      init!.signal!.addEventListener('abort', () => reject(new Error('deadline')), { once: true });
      deadline.abort();
    }));
    const provider = legalApplicationProvisioner(env, policy)!;
    await expect(provider.invite(application, 'org_created', deadline.signal)).rejects.toMatchObject({ code: 'provider_unavailable' });
  });
});
