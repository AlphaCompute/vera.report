// node --test auth0/actions/legal-assurance.test.cjs
// Pure unit tests with a fake Auth0 `api`; no tenant or network access.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const action = require('./legal-assurance.js');

const SECRETS = {
  LEGAL_CLIENT_ID: 'legalClient000000000000000000001',
  LEGAL_AUDIENCE: 'https://legal-api.vera.report',
  LEGAL_EMAIL_CONNECTION_ID: 'con_email',
  ADMIN_CLIENT_ID: 'adminClient000000000000000000001',
  ADMIN_AUDIENCE: 'https://legal-admin-api.vera.report',
  ADMIN_ORGANIZATION_ID: 'org_internal0001',
};

function event(overrides = {}) {
  const base = {
    secrets: { ...SECRETS },
    client: { client_id: SECRETS.LEGAL_CLIENT_ID, name: 'Vera legal portal' },
    connection: { id: 'con_email', name: 'email', strategy: 'email' },
    resource_server: { identifier: SECRETS.LEGAL_AUDIENCE },
    organization: { id: 'org_firm0001', name: 'synthetic-firm', metadata: { vera_domain: 'firm.example', vera_application_id: 'b'.repeat(64) } },
    authorization: { roles: ['vera-legal-member'] },
    user: { user_id: 'email|synthetic', email: 'member@firm.example', email_verified: true,
      app_metadata: {}, user_metadata: {}, enrolledFactors: [{ type: 'otp' }] },
    transaction: { protocol: 'oidc-basic-profile' },
    authentication: { methods: [{ name: 'pwd', timestamp: '2026-09-27T12:00:00.000Z' }] },
  };
  return { ...base, ...overrides };
}

function adminEvent(overrides = {}) {
  return event({ client: { client_id: SECRETS.ADMIN_CLIENT_ID }, resource_server: { identifier: SECRETS.ADMIN_AUDIENCE },
    connection: { id: 'con_admin', name: 'vera-legal-members', strategy: 'auth0' },
    organization: { id: SECRETS.ADMIN_ORGANIZATION_ID }, ...overrides });
}

test('profile-only entry has no legal assurance; admin and legal API requests still require their normal gates', () => {
  const entry = event({ resource_server: undefined, organization: undefined,
    connection: { id: 'con_email', name: 'email', strategy: 'email' } });
  assert.deepEqual(action.evaluateLegalAssurance(entry), { kind: 'ignore' });
  const userinfo = { ...entry, request: { hostname: 'identity.example' }, resource_server: { identifier: 'https://identity.example/userinfo' } };
  assert.deepEqual(action.evaluateLegalAssurance(userinfo), { kind: 'ignore' });
  assert.equal(action.evaluateLegalAssurance({ ...userinfo, resource_server: { identifier: 'https://other.example/userinfo' } }).kind, 'deny');
  assert.equal(action.evaluateLegalAssurance({ ...userinfo, transaction: { protocol: 'oauth2-refresh-token' } }).kind, 'deny');
  // Public audience and client identifiers in synthetic events, not credentials.
  // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret
  assert.equal(action.evaluateLegalAssurance({ ...entry, resource_server: { identifier: SECRETS.LEGAL_AUDIENCE } }).kind, 'deny');
  // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret
  assert.equal(action.evaluateLegalAssurance({ ...entry, client: { client_id: SECRETS.ADMIN_CLIENT_ID } }).kind, 'deny');
});

function fakeApi() {
  const calls = { deny: [], mfa: [], claims: {} };
  return {
    calls,
    access: { deny: reason => { calls.deny.push(reason); } },
    multifactor: { enable: () => { throw new Error('multifactor.enable would allow any tenant factor, including email'); } },
    authentication: {
      challengeWithAny: factors => { calls.mfa.push({ step: 'challenge', factors }); },
      enrollWithAny: factors => { calls.mfa.push({ step: 'enroll', factors }); },
    },
    accessToken: { setCustomClaim: (name, value) => { calls.claims[name] = value; } },
    idToken: { setCustomClaim: () => { throw new Error('the assurance claim belongs in the access token only'); } },
  };
}

async function run(e) {
  const api = fakeApi();
  await action.onExecutePostLogin(e, api);
  return api.calls;
}

const CLAIM = 'https://vera.app/legal-assurance';
const SETUP = 'https://vera.app/legal-setup';
const APPROVED_ORG = { id: 'org_approved', display_name: 'Approved Counsel', metadata: {
  vera_application_id: 'a'.repeat(64), vera_domain: 'counsel.example',
} };

test('setup labels come only from the approved organization for the legal portal', async () => {
  const calls = await run(event({ organization: APPROVED_ORG, user: { ...event().user, email: 'member@counsel.example' } }));
  assert.deepEqual(calls.claims[SETUP], { organizationId: 'a'.repeat(64), providerOrganizationId: 'org_approved',
    displayName: 'Approved Counsel', domain: 'counsel.example' });
  assert.equal(calls.claims[CLAIM], 'approved-member-verified-email');
  assert.equal(calls.mfa.length, 0);
  const forged = await run(event({ organization: { id: 'org_unapproved' },
    user: { ...event().user, user_metadata: APPROVED_ORG.metadata, app_metadata: APPROVED_ORG.metadata } }));
  assert.equal(forged.claims[SETUP], undefined);
  assert.equal(forged.deny.length, 1);
  const admin = await run(event({ organization: { ...APPROVED_ORG, id: SECRETS.ADMIN_ORGANIZATION_ID },
    client: { client_id: SECRETS.ADMIN_CLIENT_ID }, resource_server: { identifier: SECRETS.ADMIN_AUDIENCE } }));
  assert.equal(admin.claims[SETUP], undefined);
});

test('malformed setup labels are omitted and malformed approved domains deny access', async () => {
  for (const organization of [
    { ...APPROVED_ORG, id: 'invalid' }, { ...APPROVED_ORG, display_name: 'Injected\nname' },
    { ...APPROVED_ORG, metadata: { ...APPROVED_ORG.metadata, vera_domain: 'https://counsel.example/' } },
    { ...APPROVED_ORG, metadata: { ...APPROVED_ORG.metadata, vera_application_id: 'invalid' } },
  ]) {
    const calls = await run(event({ organization, user: { ...event().user, email: 'member@counsel.example' } }));
    assert.equal(calls.claims[SETUP], undefined);
    if (organization.metadata.vera_domain.startsWith('https:') || organization.id === 'invalid' || organization.metadata.vera_application_id === 'invalid') {
      assert.equal(calls.deny.length, 1);
      assert.deepEqual(calls.claims, {});
    } else assert.equal(calls.claims[CLAIM], 'approved-member-verified-email');
  }
  const denied = await run(event({ organization: APPROVED_ORG, user: { ...event().user, email_verified: false } }));
  assert.deepEqual(denied.claims, {});
});

test('claim name and value match the enclave verifier', () => {
  assert.equal(action.LEGAL_ASSURANCE_CLAIM, CLAIM);
  assert.equal(action.LEGAL_ASSURANCE_VALUE, 'approved-member-verified-email');
  assert.equal(action.ADMIN_ASSURANCE_VALUE, 'mfa-verified-email');
});

test('approved legal member receives distinct assurance without an MFA challenge', async () => {
  const calls = await run(event());
  assert.deepEqual(calls.deny, []);
  assert.deepEqual(calls.mfa, []);
  assert.deepEqual(calls.claims, { [CLAIM]: 'approved-member-verified-email' });
});

test('verified password/social accounts and unpinned email sessions cannot obtain legal assurance or bootstrap', async () => {
  for (const connection of [undefined, { id: 'con_email', name: 'email', strategy: 'auth0' },
    { id: 'con_db', name: 'vera-legal-members', strategy: 'auth0' },
    { id: 'con_google', name: 'google-oauth2', strategy: 'google-oauth2' },
    { id: 'con_other', name: 'email', strategy: 'email' }, { name: 'email', strategy: 'email' }]) {
    for (const bootstrap of [false, true]) {
      const calls = await run(event({ connection, transaction: { protocol: 'oidc-basic-profile', prompt: ['none'] },
        ...(bootstrap ? { resource_server: undefined, organization: undefined } : {}) }));
      assert.equal(calls.deny.length, 1);
      assert.deepEqual(calls.claims, {});
    }
  }
  for (const id of [undefined, '', 'email', 'con_wrong']) {
    const calls = await run(event({ secrets: { ...SECRETS, LEGAL_EMAIL_CONNECTION_ID: id } }));
    assert.equal(calls.deny.length, 1);
    assert.deepEqual(calls.claims, {});
  }
  const admin = await run(adminEvent());
  assert.equal(admin.claims[CLAIM], 'mfa-verified-email');
  assert.equal(admin.mfa.length, 1);
});

test('admin onboarding app requires the internal organization', async () => {
  const admin = { client: { client_id: SECRETS.ADMIN_CLIENT_ID }, resource_server: { identifier: SECRETS.ADMIN_AUDIENCE } };
  const ok = await run(event({ ...admin, organization: { id: SECRETS.ADMIN_ORGANIZATION_ID } }));
  assert.deepEqual(ok.claims, { [CLAIM]: 'mfa-verified-email' });
  assert.equal(ok.mfa.length, 1);
  const firm = await run(event({ ...admin, organization: { id: 'org_firm0001' } }));
  assert.equal(firm.deny.length, 1);
  assert.deepEqual(firm.claims, {});
});

test('unverified, missing or non-boolean email verification is denied without a claim', async () => {
  for (const user of [
    { email: 'member@firm.example', email_verified: false },
    { email: 'member@firm.example' },
    { email: 'member@firm.example', email_verified: 'true' },
    { email_verified: true },
    // Metadata can never substitute for the identity provider's verification.
    { email: 'member@firm.example', email_verified: false, app_metadata: { email_verified: true, legalAssurance: 'mfa-verified-email' } },
  ]) {
    const calls = await run(event({ user }));
    assert.equal(calls.deny.length, 1, JSON.stringify(user));
    assert.deepEqual(calls.claims, {});
    assert.deepEqual(calls.mfa, []);
  }
});

test('refresh-token exchanges never receive either profile claim', async () => {
  const calls = await run(event({
    transaction: { protocol: 'oauth2-refresh-token' },
    authentication: { methods: [{ name: 'pwd', timestamp: '2026-09-27T12:00:00.000Z' },
      { name: 'mfa', timestamp: '2026-09-27T12:00:05.000Z' }] },
  }));
  assert.deepEqual(calls.claims, {});
  assert.deepEqual(calls.mfa, []);
  assert.deepEqual(calls.deny, []);
  assert.deepEqual((await run(adminEvent({ transaction: { protocol: 'oauth2-refresh-token' } }))).claims, {});
});

test('an earlier admin session MFA does not replace this transaction\'s challenge', async () => {
  const calls = await run(adminEvent({ authentication: { methods: [{ name: 'mfa', timestamp: '2026-01-01T00:00:00.000Z' }] } }));
  assert.deepEqual(calls.mfa, [{ step: 'challenge', factors: [{ type: 'webauthn-roaming' }, { type: 'webauthn-platform' }, { type: 'otp' }] }]);
  assert.deepEqual(calls.claims, { [CLAIM]: 'mfa-verified-email' });
});

test('non-interactive or unknown grants are denied', async () => {
  for (const protocol of ['oauth2-password', 'oauth2-resource-owner', 'oauth2-device-code', 'oauth2-token-exchange', undefined]) {
    const calls = await run(event({ transaction: { protocol } }));
    assert.equal(calls.deny.length, 1, String(protocol));
    assert.deepEqual(calls.claims, {});
  }
});

test('organization is mandatory for legal applications', async () => {
  for (const organization of [undefined, {}, { id: '' }]) {
    const calls = await run(event({ organization }));
    assert.equal(calls.deny.length, 1);
    assert.deepEqual(calls.claims, {});
  }
});

test('legal app may only request its own audience', async () => {
  for (const identifier of [SECRETS.ADMIN_AUDIENCE, 'https://api.vera.report', undefined]) {
    const calls = await run(event({ resource_server: identifier ? { identifier } : undefined }));
    assert.equal(calls.deny.length, 1, String(identifier));
    assert.deepEqual(calls.claims, {});
  }
});

test('other applications are untouched, but cannot obtain legal API tokens', async () => {
  const other = await run(event({ client: { client_id: 'mainAppClient' }, resource_server: { identifier: 'https://api.vera.report' } }));
  assert.deepEqual(other, { deny: [], mfa: [], claims: {} });
  for (const identifier of [SECRETS.LEGAL_AUDIENCE, SECRETS.ADMIN_AUDIENCE]) {
    const foreign = await run(event({ client: { client_id: 'mainAppClient' }, resource_server: { identifier } }));
    assert.equal(foreign.deny.length, 1);
    assert.deepEqual(foreign.claims, {});
  }
});

test('missing configuration fails closed and never issues the claim', async () => {
  const noAudience = await run(event({ secrets: { ...SECRETS, LEGAL_AUDIENCE: '' } }));
  assert.equal(noAudience.deny.length, 1);
  assert.deepEqual(noAudience.claims, {});
  const noAdminOrg = await run(event({ secrets: { ...SECRETS, ADMIN_ORGANIZATION_ID: undefined },
    client: { client_id: SECRETS.ADMIN_CLIENT_ID }, resource_server: { identifier: SECRETS.ADMIN_AUDIENCE },
    organization: { id: 'org_anything' } }));
  assert.equal(noAdminOrg.deny.length, 1);
  assert.deepEqual(noAdminOrg.claims, {});
  // Without secrets the legal clients are not recognized, so no claim is ever set.
  const none = await run(event({ secrets: {} }));
  assert.deepEqual(none.claims, {});
});

test('evaluateLegalAssurance is total over malformed events', () => {
  for (const malformed of [undefined, null, {}, { client: null }, { secrets: null, client: { client_id: 5 } }]) {
    assert.doesNotThrow(() => action.evaluateLegalAssurance(malformed));
    assert.notEqual(action.evaluateLegalAssurance(malformed).kind, 'issue');
  }
});

test('admin MFA offers only security keys, passkeys and authenticator apps', async () => {
  assert.deepEqual(action.LEGAL_MFA_FACTORS.map(factor => factor.type), ['webauthn-roaming', 'webauthn-platform', 'otp']);
  for (const type of ['webauthn-roaming', 'webauthn-platform', 'otp']) {
    const calls = await run(adminEvent({ user: { ...event().user, enrolledFactors: [{ type: 'email' }, { type }] } }));
    assert.deepEqual(calls.mfa, [{ step: 'challenge', factors: [{ type: 'webauthn-roaming' }, { type: 'webauthn-platform' }, { type: 'otp' }] }], type);
    assert.deepEqual(calls.claims, { [CLAIM]: 'mfa-verified-email' });
  }
});

test('an admin with only email, SMS or push factors is denied rather than allowed to add one', async () => {
  for (const enrolledFactors of [[{ type: 'email' }], [{ type: 'phone' }], [{ type: 'push-notification' }, { type: 'recovery-code' }]]) {
    const calls = await run(adminEvent({ user: { ...event().user, enrolledFactors } }));
    assert.equal(calls.deny.length, 1, JSON.stringify(enrolledFactors));
    assert.deepEqual(calls.mfa, []);
    assert.deepEqual(calls.claims, {});
  }
});

test('an admin with no second factor must enroll an allowed one in this transaction', async () => {
  for (const enrolledFactors of [[], undefined, [{ type: 'recovery-code' }]]) {
    const calls = await run(adminEvent({ user: { ...event().user, enrolledFactors } }));
    assert.deepEqual(calls.mfa, [{ step: 'enroll', factors: [{ type: 'webauthn-roaming' }, { type: 'webauthn-platform' }, { type: 'otp' }] }]);
    assert.deepEqual(calls.claims, { [CLAIM]: 'mfa-verified-email' });
  }
});


test('legal sign-in requires the exact approved email domain, never metadata or suffix matching', async () => {
  for (const email of ['member@other.example', 'member@sub.firm.example', 'member@evilfirm.example',
    'member@firm.example.evil', 'member@@firm.example', 'member @firm.example']) {
    const calls = await run(event({ user: { ...event().user, email,
      user_metadata: { vera_domain: 'firm.example' }, app_metadata: { vera_domain: 'firm.example' } } }));
    assert.equal(calls.deny.length, 1, email);
    assert.deepEqual(calls.claims, {});
    assert.deepEqual(calls.mfa, []);
  }
  const accepted = await run(event({ user: { ...event().user, email: 'Member@FIRM.EXAMPLE' } }));
  assert.equal(accepted.claims[CLAIM], 'approved-member-verified-email');
  for (const metadata of [undefined, {}, { vera_domain: 'FIRM.EXAMPLE' }, { vera_domain: 'firm.example/' }]) {
    const calls = await run(event({ organization: { ...event().organization, metadata } }));
    assert.equal(calls.deny.length, 1);
    assert.deepEqual(calls.claims, {});
  }
});

test('new and returning legal users never need a second factor', async () => {
  for (const enrolledFactors of [undefined, [], [{ type: 'otp' }], [{ type: 'email' }]]) {
    const calls = await run(event({ user: { ...event().user, enrolledFactors },
      authentication: { methods: [{ name: 'pwd', timestamp: '2026-01-01T00:00:00.000Z' }] },
      transaction: { protocol: 'oidc-basic-profile', prompt: ['none'] } }));
    assert.deepEqual(calls.deny, []);
    assert.deepEqual(calls.mfa, []);
    assert.equal(calls.claims[CLAIM], 'approved-member-verified-email');
  }
});

test('verified mailbox or same-domain session without approved membership is denied', async () => {
  for (const override of [
    { authorization: undefined }, { authorization: { roles: [] } }, { authorization: { roles: ['employee', 'admin'] } },
    { authorization: { roles: 'vera-legal-member' } },
    { organization: { ...event().organization, metadata: { vera_domain: 'firm.example' } } },
    { organization: { ...event().organization, metadata: { vera_domain: 'firm.example', vera_application_id: 'invalid' } } },
  ]) {
    const calls = await run(event(override));
    assert.equal(calls.deny.length, 1);
    assert.deepEqual(calls.claims, {});
    assert.deepEqual(calls.mfa, []);
  }
});
