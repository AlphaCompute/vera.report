const { test } = require('node:test');
const assert = require('node:assert/strict');
const { accessKind, onExecutePostLogin, entryLogin } = require('./domain-restriction.js');

test('entry permits only the issuer userinfo audience, never a foreign or legal API audience', () => {
  const event = { secrets: { LEGAL_CLIENT_ID: 'legal', LEGAL_EMAIL_CONNECTION_ID: 'con_email' }, client: { client_id: 'legal' }, request: { hostname: 'identity.example' },
    connection: { id: 'con_email', strategy: 'email', name: 'email' }, transaction: { protocol: 'oidc-basic-profile' },
    resource_server: { identifier: 'https://identity.example/userinfo' } };
  assert.equal(entryLogin(event), true);
  for (const identifier of ['https://other.example/userinfo', 'https://legal.example/api', 'https://identity.example/userinfo/']) {
    assert.equal(entryLogin({ ...event, resource_server: { identifier } }), false);
  }
  assert.equal(entryLogin({ ...event, transaction: { protocol: 'oauth2-refresh-token' } }), false);
});

const legal = (domain = 'counsel.example') => ({
  secrets: { LEGAL_CLIENT_ID: 'legal-client', LEGAL_AUDIENCE: 'https://legal.example/api', LEGAL_EMAIL_CONNECTION_ID: 'con_email' },
  connection: { id: 'con_email', strategy: 'email', name: 'email' },
  client: { client_id: 'legal-client' }, resource_server: { identifier: 'https://legal.example/api' },
  user: { email: `lawyer@${domain}`, email_verified: true },
  organization: { id: 'org_approved', metadata: { vera_application_id: 'a'.repeat(64), vera_domain: domain } },
  authorization: { roles: ['vera-legal-member'] },
});

test('any approved firm domain is eligible without a manual domain allowlist', async () => {
  for (const domain of ['counsel.example', 'another-firm.co.uk', 'xn--bcher-kva.example']) {
    const event = legal(domain);
    assert.equal(accessKind(event), 'legal');
    await onExecutePostLogin(event, new Proxy({}, { get() { throw new Error('Legal login must not touch staff roles or deny'); } }));
  }
});

test('approval metadata, organization role, verified email, client and audience remain required', () => {
  const mutations = [
    e => { delete e.organization; }, e => { delete e.organization.metadata.vera_application_id; },
    e => { e.organization.metadata.vera_domain = 'other.example'; },
    e => { e.user.email = 'lawyer@sub.counsel.example'; }, e => { e.user.email = 'lawyer@evilcounsel.example'; },
    e => { e.user.email_verified = false; }, e => { e.authorization.roles = ['employee']; },
    e => { e.client.client_id = 'other-client'; }, e => { e.resource_server.identifier = 'https://other.example/api'; },
    e => { delete e.secrets.LEGAL_CLIENT_ID; }, e => { delete e.secrets.LEGAL_AUDIENCE; },
    e => { delete e.secrets.LEGAL_EMAIL_CONNECTION_ID; }, e => { e.connection.id = 'con_other'; },
    e => { e.connection.strategy = 'auth0'; },
  ];
  for (const mutate of mutations) { const event = legal(); mutate(event); assert.equal(accessKind(event), 'deny'); }
  assert.equal(accessKind(null), 'other');
});

test('other applications are untouched; existing staff Actions retain responsibility for roles and domains', async () => {
  const event = legal('any-company.example');
  event.client.client_id = 'staff-client';
  event.resource_server.identifier = 'https://staff.example/api';
  event.authorization.roles = ['admin'];
  const claims = [];
  await onExecutePostLogin(event, { idToken: { setCustomClaim: (...args) => claims.push(args) },
    accessToken: { setCustomClaim: (...args) => claims.push(args) } });
  assert.deepEqual(claims, []);
  assert.equal(accessKind(event), 'other');
});

test('a sign-in without assigned roles never receives employee or admin access', async () => {
  const event = legal('any-company.example');
  event.client.client_id = 'other-client';
  event.resource_server.identifier = 'https://other.example/api';
  delete event.authorization;
  const claims = [];
  await onExecutePostLogin(event, { idToken: { setCustomClaim: (...args) => claims.push(args) },
    accessToken: { setCustomClaim: (...args) => claims.push(args) } });
  assert.deepEqual(claims, []);
});

test('a denied legal login issues no role claims', async () => {
  const event = legal();
  event.authorization.roles = [];
  const denials = [];
  await onExecutePostLogin(event, { access: { deny: message => denials.push(message) } });
  assert.deepEqual(denials, ['Access restricted!']);
});
