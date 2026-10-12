const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { onExecutePreUserRegistration, onExecutePostLogin } = require('./domain-restriction.js');
const email = 'lawyer@approved.example';
const key = `vera_entry_${createHash('sha256').update(email).digest('hex').slice(0, 39)}`;
const event = () => ({ secrets: { LEGAL_CLIENT_ID: 'legal-client', LEGAL_AUDIENCE: 'https://api.example',
  LEGAL_EMAIL_CONNECTION_ID: 'con_email', LEGAL_MGMT_DOMAIN: 'identity.example',
  LEGAL_MGMT_CLIENT_ID: 'management-client', LEGAL_MGMT_CLIENT_SECRET: 'synthetic-management-secret' },
  client: { client_id: 'legal-client' }, connection: { id: 'con_email', name: 'email', strategy: 'email' },
  request: { hostname: 'identity.example' }, resource_server: { identifier: 'https://identity.example/userinfo' },
  transaction: { protocol: 'oidc-basic-profile' }, user: { email, user_id: 'email|123', email_verified: true } });
function fixture(t, { pending = true, member = false } = {}) {
  const state = { member, role: member, fail: '', calls: [],
    organization: { id: 'org_allowed', metadata: { vera_domain: 'approved.example', vera_application_id: 'a'.repeat(64),
      ...(pending ? { [key]: String(Date.now() + 60000) } : {}) } },
    user: { ...event().user, identities: [{ connection: 'email', provider: 'email' }] },
    connection: { connection_id: 'con_email', assign_membership_on_login: false, connection: { name: 'email', strategy: 'email' } },
    permissions: ['legal:case', 'legal:directory', 'legal:enroll'], duplicate: false, otherOrganizations: [], fullPage: false, polls: 0, joinOnPoll: 0 };
  t.mock.method(globalThis, 'setTimeout', callback => { queueMicrotask(callback); return 0; });
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    const url = new URL(String(input)), body = init.body && JSON.parse(init.body), method = init.method || 'GET';
    assert.equal(url.origin, 'https://identity.example');
    assert.equal(init.redirect, 'error'); assert.ok(init.signal);
    state.calls.push({ path: url.pathname, method, body });
    const response = (value, status = 200) => new Response(JSON.stringify(value), { status });
    if (state.fail === url.pathname) return response({}, 503);
    if (url.pathname === '/oauth/token') return response({ access_token: 'synthetic-token', token_type: 'Bearer' });
    if (url.pathname === '/api/v2/organizations') {
      const page = Number(url.searchParams.get('page')), all = [...state.otherOrganizations, state.organization];
      return response(state.fullPage ? Array(100).fill(state.organization) :
        state.duplicate ? [state.organization, { ...state.organization, id: 'org_duplicate' }] : all.slice(page * 100, page * 100 + 100));
    }
    if (url.pathname === '/api/v2/organizations/org_allowed/enabled_connections/con_email') return response(state.connection);
    if (url.pathname === '/api/v2/users-by-email') return response(state.user ? [state.user] : []);
    if (url.pathname === '/api/v2/roles') return response([{ id: 'rol_member', name: 'vera-legal-member' }]);
    if (url.pathname === '/api/v2/roles/rol_member/permissions') return response(state.permissions.map(permission_name =>
      ({ permission_name, resource_server_identifier: event().secrets.LEGAL_AUDIENCE })));
    assert.equal(method, 'GET', 'Auth0 sign-in must never mutate membership or approval metadata');
    if (url.pathname === '/api/v2/organizations/org_allowed/members') {
      state.polls++;
      if (state.polls === state.joinOnPoll) { state.member = true; state.role = true; }
      return response(state.member ? [state.user] : []);
    }
    if (url.pathname === '/api/v2/organizations/org_allowed/members/email%7C123/roles') {
      return response(state.role ? [{ id: 'rol_member' }] : []);
    }
    assert.fail(`Unexpected request: ${method} ${url.pathname}`);
  });
  return state;
}
async function run(kind, e = event()) {
  const denied = [], claims = [];
  await (kind === 'registration' ? onExecutePreUserRegistration : onExecutePostLogin)(e, {
    access: { deny: (...args) => denied.push(args) }, idToken: { setCustomClaim: (...args) => claims.push(args) } });
  return { denied, claims };
}
test('approved absent account registers natively; first login waits for the worker without calling Vera or writing Auth0', async t => {
  const f = fixture(t);
  const user = f.user; f.user = null;
  assert.deepEqual((await run('registration')).denied, []);
  assert.equal(f.member, false); assert.equal(f.calls.some(c => c.path.endsWith('/users')), false);
  f.user = user; f.joinOnPoll = 2;
  const completed = await run('login');
  assert.deepEqual(completed.denied, []);
  assert.deepEqual(completed.claims, [['https://vera.app/legal-entry', { organization: 'org_allowed' }]]);
  assert.equal(f.member && f.role, true);
  assert.equal(f.calls.some(c => /passwordless|invitations|legal-entry/.test(c.path)), false);
  const writes = f.calls.filter(c => c.method !== 'GET' && c.path !== '/oauth/token');
  assert.deepEqual(writes, []);
  assert.equal(f.polls, 2);
});
test('existing approved membership works without a pending approval or any mutation', async t => {
  const f = fixture(t, { member: true, pending: false });
  assert.deepEqual((await run('login')).denied, []);
  assert.equal(f.calls.some(c => c.method !== 'GET' && c.path !== '/oauth/token'), false);
  assert.ok(f.calls.filter(c => c.path === '/oauth/token').every(c => !c.body.scope.includes('create:')));
});
test('pending and denied applications at the same domain do not block an approved member', async t => {
  const f = fixture(t, { member: true, pending: false });
  f.organization.metadata.vera_approval_status = 'approved';
  f.organization.metadata.vera_application_version = '1';
  f.otherOrganizations = ['pending', 'denied'].map((status, index) => ({ id: `org_other${index}`,
    metadata: { ...f.organization.metadata, vera_approval_status: status } }));
  assert.deepEqual((await run('login')).denied, []);
});
test('an approved member signs in with 999 organizations listed, and the 1,000th fails closed', async t => {
  const f = fixture(t, { member: true, pending: false });
  f.organization.metadata.vera_approval_status = 'approved';
  f.organization.metadata.vera_application_version = '1';
  f.otherOrganizations = Array.from({ length: 998 }, (_, index) => ({ id: `org_other${index}`,
    metadata: { vera_domain: `other${index}.example`, vera_application_id: 'b'.repeat(64), vera_application_version: '1', vera_approval_status: 'pending' } }));
  assert.deepEqual((await run('login')).denied, []);
  assert.equal(f.calls.filter(c => c.path === '/api/v2/organizations').length, 10);
  f.otherOrganizations.push({ id: 'org_other998', metadata: { vera_domain: 'other998.example' } });
  assert.equal((await run('login')).denied.length, 1);
});
for (const status of ['pending', 'denied']) test(`${status} application cannot register or sign in even with a stale hint and membership`, async t => {
  const f = fixture(t, { member: true });
  f.organization.metadata.vera_approval_status = status;
  f.organization.metadata.vera_application_version = '1';
  assert.equal((await run('registration')).denied.length, 1);
  assert.equal((await run('login')).denied.length, 1);
});
test('an unapproved address at an approved domain cannot register or join', async t => {
  const f = fixture(t, { pending: false });
  assert.equal((await run('registration')).denied.length, 1);
  assert.equal((await run('login')).denied.length, 1);
  assert.equal(f.member, false);
});
test('an old registration hint cannot restore a removed membership', async t => {
  const f = fixture(t, { member: true });
  assert.deepEqual((await run('login')).denied, []);
  f.member = false; f.role = false; f.calls.length = 0;
  assert.equal((await run('login')).denied.length, 1);
  assert.equal(f.calls.some(c => c.method === 'PATCH' || c.body?.members), false);
  assert.equal(f.polls, 11); // First successful read, then the bounded wait.
});
test('removed roles are not repaired, even with an old pending approval', async t => {
  const f = fixture(t, { member: true }); f.role = false;
  assert.equal((await run('login')).denied.length, 1);
  assert.equal(f.role, false);
});
test('an unavailable worker cannot turn a registration hint into legal access', async t => {
  const f = fixture(t);
  assert.equal((await run('login')).denied.length, 1);
  assert.equal(f.polls, 10);
  assert.equal(f.member, false);
  assert.equal((await run('login')).denied.length, 1);
});
test('expired approvals, disabled organizations, ambiguous and truncated listings deny access', async t => {
  for (const change of [f => { f.organization.metadata[key] = '1'; },
    f => { f.organization.metadata[key] = String(Date.now() + 8 * 86_400_000); },
    f => { f.organization.metadata.vera_legal_disabled = 'true'; }, f => { f.duplicate = true; }, f => { f.fullPage = true; }]) {
    await t.test('invalid approval authority', async s => {
      const f = fixture(s); change(f);
      assert.equal((await run('registration')).denied.length, 1);
      assert.equal((await run('login')).denied.length, 1);
    });
  }
});
test('provider failure, wrong subject, blocked user, unsafe connection and elevated role all fail closed', async t => {
  for (const change of [f => { f.fail = '/api/v2/organizations'; }, f => { f.user.user_id = 'email|other'; },
    f => { f.user.blocked = true; }, f => { f.user.email_verified = false; },
    f => { f.connection.assign_membership_on_login = true; }, f => { f.permissions.push('legal:invite'); }]) {
    await t.test('invalid provider authority', async s => {
      const f = fixture(s); change(f);
      assert.equal((await run('login')).denied.length, 1);
      assert.equal(f.member, false);
    });
  }
});
test('wrong connection, unverified user and malformed management host cannot consult Auth0', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('Unexpected lookup'));
  for (const mutate of [e => { e.connection.strategy = 'auth0'; }, e => { e.connection.name = 'other'; },
    e => { e.connection.id = 'con_other'; }, e => { delete e.secrets.LEGAL_EMAIL_CONNECTION_ID; },
    e => { e.secrets.LEGAL_MGMT_DOMAIN = 'https://identity.example/path'; }, // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret -- Deliberately malformed public test URL, not a credential.
    e => { e.secrets.LEGAL_MGMT_CLIENT_SECRET = ''; },
  ]) {
    const e = event(); mutate(e);
    assert.equal((await run('registration', e)).denied.length, 1);
  }
  const e = event(); e.user.email_verified = false;
  assert.equal((await run('login', e)).denied.length, 1);
});
test('unrelated staff registration and login remain untouched, including missing legal configuration', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('Must not consult legal approval for staff'));
  const api = new Proxy({}, { get() { assert.fail('Must not deny staff or replace existing role claims'); } });
  for (const strategy of ['email', 'auth0', 'google-oauth2']) {
    for (const secrets of [event().secrets, {}, { LEGAL_CLIENT_ID: '' }]) {
      const e = { ...event(), client: { client_id: 'staff' }, resource_server: { identifier: 'https://staff.example/api' },
        connection: { id: 'con_staff', name: strategy, strategy }, secrets };
      await onExecutePreUserRegistration(e, api); await onExecutePostLogin(e, api);
    }
  }
});
