// Compiled enclave integration: real RSA JWTs and real firm-key signatures.
// The in-memory transaction adapter below exists ONLY in this test file.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const enclaveRequire = createRequire(require('node:path').resolve(__dirname, '../../enclave/package.json'));
const { createLegalIdentityVerifier, createOnboardingAdminIdentityVerifier, LEGAL_ASSURANCE_CLAIM } = enclaveRequire('./dist/legal/identity.js');
const { createLegalEnrollmentService, createLegalEnrollmentRedeemer, verifyDeviceMembership } = enclaveRequire('./dist/legal/enrollment.js');
const { generateKey } = enclaveRequire('./dist/confidential/pgp.js');
const { caseRecipientKeyId } = enclaveRequire('./dist/confidential/caseObject.js');
const { signEnrollmentChallenge } = enclaveRequire('./dist/confidential/enrollmentProof.js');
const { signMembershipAuthorization } = enclaveRequire('./dist/confidential/membershipAuthorization.js');
const { signOrganizationRegistration } = enclaveRequire('./dist/confidential/organizationRegistration.js');
let onboarding;
let jose, issuerKeys, otherIssuer, firm, otherFirm, jwks, binding;
const issuer = 'https://identity.example/';
const baseline = Math.floor(Date.now() / 1000) * 1000;
const organizationId = '1'.repeat(64);

before(async () => {
  jose = await import(pathToFileURL(enclaveRequire.resolve('jose')).href);
  [issuerKeys, otherIssuer] = await Promise.all([jose.generateKeyPair('RS256'), jose.generateKeyPair('RS256')]);
  jwks = { keys: [{ ...await jose.exportJWK(issuerKeys.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] };
  [firm, otherFirm] = await Promise.all(['firm', 'other'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
  onboarding = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' })).privateKey;
  binding = { organizationId, providerOrganizationId: 'org_firm', approved: true,
    recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };
  binding.registration = await signOrganizationRegistration({ format: 'vera-organization-registration/v1', ...binding, displayName: 'Synthetic firm', domain: 'counsel.example', issuedAt: baseline }, onboarding);
}, { timeout: 180_000 });

function policy(kind) { return { issuer, audience: `https://api.example/${kind}`, clientId: `${kind}-client`, jwks }; }
async function token(kind = 'legal', overrides = {}, signingKey = issuerKeys.privateKey, headers = {}) {
  return new jose.SignJWT({ iss: issuer, aud: policy(kind).audience, azp: policy(kind).clientId,
    sub: kind === 'admin' ? 'auth0|admin' : 'auth0|lawyer', org_id: kind === 'admin' ? 'org_admin' : 'org_firm',
    scope: kind === 'admin' ? 'legal:invite' : 'legal:enroll legal:directory',
    iat: baseline / 1000, exp: baseline / 1000 + 300,
    [LEGAL_ASSURANCE_CLAIM]: kind === 'admin' ? 'mfa-verified-email' : 'approved-member-verified-email', ...overrides,
  }).setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key', ...headers }).sign(signingKey);
}
function fixture() {
  let clock = baseline;
  const invitations = new Map(), members = new Map();
  let currentBinding = { ...binding };
  const store = {
    async getOrganization(id) { return id === organizationId ? { ...currentBinding } : null; },
    async insertInvitation(record) {
      assert.ok(!invitations.has(record.tokenDigest));
      invitations.set(record.tokenDigest, { ...record });
    },
    async getInvitation(digest) { return invitations.get(digest) || null; },
    async commitEnrollment(expected, member, now) {
      // No await between comparison and mutation: atomic test transaction.
      const stored = invitations.get(expected.tokenDigest);
      if (!stored || stored.state !== 'pending' || stored.version !== expected.version ||
          stored.invitationId !== expected.invitationId || stored.expiresAt <= now ||
          !currentBinding.approved || currentBinding.recipientKeyId !== expected.recipientKeyId) return false;
      invitations.set(expected.tokenDigest, { ...stored, state: 'redeemed', version: stored.version + 1 });
      members.set(`${member.organizationId}:${member.subject}`, { ...member });
      return true;
    },
  };
  const options = { adminIdentity: policy('admin'), legalIdentity: policy('legal'),
    adminOrganizationId: 'org_admin', onboardingPublicKey: onboarding.toPublic().armor(), store, clock: () => clock };
  return { service: createLegalEnrollmentService(options), store, options, invitations, members,
    setClock(value) { clock = value; }, setBinding(value) { currentBinding = { ...currentBinding, ...value }; } };
}
async function invited(f) {
  const invite = await f.service.issueInvitation(await token('admin'), organizationId, 'auth0|lawyer', 60_000, await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId, providerOrganizationId: 'org_firm', subject: 'auth0|lawyer', recipientKeyId: binding.recipientKeyId, issuedAt: baseline, expiresAt: baseline + 60_000 }, onboarding));
  const accessToken = await token();
  const challenge = await f.service.getChallenge(invite.token, accessToken);
  return { invite, accessToken, challenge, proof: await signEnrollmentChallenge(challenge, firm) };
}

test('accepts a valid short-lived legal token; roles alone carry no authority', async () => {
  const verifier = createLegalIdentityVerifier(policy('legal'));
  const identity = await verifier.verify(await token(), 'legal:directory', baseline);
  assert.deepEqual(identity, { subject: 'auth0|lawyer', providerOrganizationId: 'org_firm', expiresAt: baseline + 300_000 });
  await assert.rejects(verifier.verify(await token('legal', { scope: 'openid', roles: ['admin'] }), 'legal:directory', baseline), /Legal authentication required/);
});

test('legal and administrator assurance are separate even with a valid signature', async () => {
  const legal = createLegalIdentityVerifier(policy('legal'));
  const admin = createOnboardingAdminIdentityVerifier(policy('admin'));
  await assert.rejects(legal.verify(await token('legal', { [LEGAL_ASSURANCE_CLAIM]: 'mfa-verified-email' }), 'legal:directory', baseline));
  await assert.rejects(admin.verify(await token('admin', { [LEGAL_ASSURANCE_CLAIM]: 'approved-member-verified-email' }), 'legal:invite', baseline));
  await assert.rejects(admin.verify(await token('admin', { [LEGAL_ASSURANCE_CLAIM]: undefined }), 'legal:invite', baseline));
  await assert.rejects(legal.verify(await token('legal', { scope: 'legal:invite' }), 'legal:invite', baseline));
  await assert.rejects(admin.verify(await token('admin', { scope: 'legal:directory' }), 'legal:directory', baseline));
  assert.equal((await admin.verify(await token('admin'), 'legal:invite', baseline)).subject, 'auth0|admin');
});

test('rejects wrong issuer/audience/client/org, absent assurance, stale/future tokens and machine clients', async () => {
  const verifier = createLegalIdentityVerifier(policy('legal'));
  for (const override of [
    { iss: 'https://attacker.example/' }, { aud: policy('admin').audience }, { azp: 'admin-client' },
    { org_id: undefined }, { [LEGAL_ASSURANCE_CLAIM]: undefined }, { [LEGAL_ASSURANCE_CLAIM]: 'password' },
    { sub: 'machine@clients' }, { gty: 'client-credentials' }, { iat: baseline / 1000 + 1 },
    { exp: baseline / 1000 }, { exp: baseline / 1000 + 301 }, { iat: undefined },
    { scope: 'legal:directory-extra' },
  ]) await assert.rejects(verifier.verify(await token('legal', override), 'legal:directory', baseline), /Legal authentication required/);
  await assert.rejects(verifier.verify(await token(), 'legal:directory', Number.MAX_SAFE_INTEGER));
});

test('signature/key/header confusion and malformed JWTs fail closed without remote key lookup', async () => {
  const verifier = createLegalIdentityVerifier(policy('legal'));
  await assert.rejects(verifier.verify(await token('legal', {}, otherIssuer.privateKey), 'legal:directory', baseline));
  for (const header of [{ typ: 'at+jwt' }, { kid: 'unknown' }, { jku: 'https://attacker.example/jwks' }]) {
    await assert.rejects(verifier.verify(await token('legal', {}, issuerKeys.privateKey, header), 'legal:directory', baseline));
  }
  for (const value of ['PRIVATE-TOKEN-SENTINEL', 'x'.repeat(16_385), 'eyJhbGciOiJub25lIn0.e30.']) {
    await assert.rejects(verifier.verify(value, 'legal:directory', baseline), { message: 'Legal authentication required' });
  }
});

test('identity configuration cannot accept private signing keys or collapse admin/legal applications', () => {
  assert.throws(() => createLegalIdentityVerifier({ ...policy('legal'), jwks: { keys: [{ ...jwks.keys[0], d: 'private' }] } }));
  assert.throws(() => createLegalIdentityVerifier({ ...policy('legal'), issuer: 'http://identity.example/' }));
  const f = fixture();
  assert.throws(() => createLegalEnrollmentService({ ...f.options, adminIdentity: policy('legal') }), /Separate legal identity boundary/);
});

test('private invitation stores only a digest and redeems into membership, never a case grant', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  assert.equal(invite.token.length, 43);
  assert.ok(!JSON.stringify([...f.invitations.values()]).includes(invite.token));
  const member = await f.service.redeemInvitation(invite.token, accessToken, proof);
  assert.deepEqual(member, { organizationId, subject: 'auth0|lawyer', recipientKeyId: binding.recipientKeyId });
  assert.equal(f.members.size, 1);
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof), /Legal enrollment unavailable/);
});

test('a forwarded link, platform admin login, or another organization cannot accept the invitation', async () => {
  const f = fixture(), { invite, proof } = await invited(f);
  for (const accessToken of [await token('legal', { sub: 'auth0|other' }), await token('admin'),
    await token('legal', { org_id: 'org_other' })]) {
    await assert.rejects(f.service.getChallenge(invite.token, accessToken));
    await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof));
  }
  assert.equal(f.members.size, 0);
});

test('a legal account cannot issue invitations and an admin from another org is rejected', async () => {
  const f = fixture();
  for (const adminToken of [await token('legal', { scope: 'legal:invite' }), await token('admin', { org_id: 'org_other' })]) {
    await assert.rejects(f.service.issueInvitation(adminToken, organizationId, 'auth0|lawyer', 60_000));
  }
});

test('key possession is mandatory and proof cannot cross invitation nonces or subjects', async () => {
  const f = fixture(), first = await invited(f), second = await invited(f);
  await assert.rejects(signEnrollmentChallenge(first.challenge, otherFirm));
  await assert.rejects(f.service.redeemInvitation(first.invite.token, first.accessToken, 'PRIVATE-PROOF-SENTINEL'));
  await assert.rejects(f.service.redeemInvitation(second.invite.token, second.accessToken, first.proof));
  const changed = await signEnrollmentChallenge({ ...first.challenge, subject: 'auth0|other' }, firm);
  await assert.rejects(f.service.redeemInvitation(first.invite.token, first.accessToken, changed));
  assert.equal(f.members.size, 0);
});

test('expiry, withdrawal and firm-key changes prevent enrollment', async () => {
  const expired = fixture(), a = await invited(expired);
  expired.setClock(a.invite.expiresAt);
  await assert.rejects(expired.service.redeemInvitation(a.invite.token, a.accessToken, a.proof));
  const revoked = fixture(), b = await invited(revoked);
  revoked.setBinding({ approved: false });
  await assert.rejects(revoked.service.redeemInvitation(b.invite.token, b.accessToken, b.proof));
  const changed = fixture(), c = await invited(changed);
  changed.setBinding({ publicKey: otherFirm.toPublic().armor(), recipientKeyId: await caseRecipientKeyId(otherFirm.toPublic()) });
  await assert.rejects(changed.service.redeemInvitation(c.invite.token, c.accessToken, c.proof));
});

test('one atomic consumption wins concurrent redemptions', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  const result = await Promise.allSettled([f.service.redeemInvitation(invite.token, accessToken, proof),
    f.service.redeemInvitation(invite.token, accessToken, proof)]);
  assert.equal(result.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(result.filter(value => value.status === 'rejected').length, 1);
  assert.equal(f.members.size, 1);
});

test('failed atomic persistence cannot be reported as successful enrollment', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  f.store.commitEnrollment = async () => false;
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof));
  assert.equal(f.members.size, 0);
});

test('revocation racing with proof verification is enforced by the atomic commit', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  const commit = f.store.commitEnrollment;
  f.store.commitEnrollment = async (...args) => { f.setBinding({ approved: false }); return commit(...args); };
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof));
  assert.equal(f.members.size, 0);
});

test('invalid proof does not consume the invitation; persistence errors do not echo private diagnostics', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, 'bad-proof'));
  assert.equal([...f.invitations.values()][0].state, 'pending');
  f.store.commitEnrollment = async () => { throw new Error('PRIVATE-DATABASE-SENTINEL'); };
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof), { message: 'Legal enrollment unavailable' });
});

test('a token expiring during firm lookup cannot authorize a later mutation', async () => {
  const f = fixture(), { invite, accessToken, proof } = await invited(f);
  const original = f.store.getOrganization;
  f.store.getOrganization = async id => { const value = await original(id); f.setClock(baseline + 300_000); return value; };
  await assert.rejects(f.service.redeemInvitation(invite.token, accessToken, proof));
  assert.equal(f.members.size, 0);
});

test('approved organization public key requires the signed binding and matching identity organization', async () => {
  const f = fixture(), service = createLegalEnrollmentRedeemer(f.options), accessToken = await token();
  assert.equal((await service.getOrganizationKey(accessToken, organizationId, 'counsel.example')).publicKey, firm.toPublic().armor());
  await assert.rejects(service.getOrganizationKey(accessToken, organizationId, 'other.example'));
  await assert.rejects(service.getOrganizationKey(await token('legal', { org_id: 'org_other' }), organizationId, 'counsel.example'));
  f.setBinding({ publicKey: otherFirm.toPublic().armor() });
  await assert.rejects(service.getOrganizationKey(accessToken, organizationId, 'counsel.example'));
});

test('awaiting-key is explicit and restricted to the caller onboarding domain and organization', async () => {
  const f = fixture();
  let pending = { _id: organizationId, providerOrganizationId: 'org_firm', domain: 'counsel.example', approved: false, publicKey: '' };
  f.store.getLegalOrganizationRecord = async () => ({ ...pending });
  const service = createLegalEnrollmentRedeemer(f.options);
  const accessToken = await token();
  // A real registered binding takes precedence over an inconsistent pending projection.
  assert.equal((await service.getOrganizationKey(accessToken, organizationId, 'counsel.example')).publicKey, binding.publicKey);
  f.setBinding({ registration: undefined, publicKey: '', approved: false });
  assert.deepEqual(await service.getOrganizationKey(accessToken, organizationId, 'counsel.example'), {
    state: 'awaiting-key', organizationId, domain: 'counsel.example',
  });
  await assert.rejects(service.getOrganizationKey(accessToken, organizationId, 'other.example'));
  await assert.rejects(service.getOrganizationKey(await token('legal', { org_id: 'org_other' }), organizationId, 'counsel.example'));
  await assert.rejects(service.getOrganizationKey(await token('legal', { scope: 'legal:directory' }), organizationId, 'counsel.example'));
  pending.revokedAt = baseline;
  await assert.rejects(service.getOrganizationKey(accessToken, organizationId, 'counsel.example'));
  delete pending.revokedAt;
  pending.approved = true;
  await assert.rejects(service.getOrganizationKey(accessToken, organizationId, 'counsel.example'));
});

test('organization key submission is only a signed candidate scoped to the caller organization', async () => {
  const { createFirmKeyBinding } = enclaveRequire('./dist/confidential/firmKeyBinding.js');
  const f = fixture(), candidates = [], accessToken = await token();
  let row = { _id: organizationId, providerOrganizationId: 'org_firm', domain: 'counsel.example', approved: false };
  f.store.getOrganization = async () => null;
  f.store.getLegalOrganizationRecord = async () => row;
  f.store.submitLegalOrganizationKeyCandidate = async value => candidates.push(value);
  const service = createLegalEnrollmentRedeemer(f.options);
  const document = await createFirmKeyBinding({ organizationId, domain: 'counsel.example', issuedAt: baseline }, firm);
  const result = await service.submitOrganizationKey(accessToken, organizationId, document);
  assert.deepEqual(result, { submitted: true, recipientKeyId: binding.recipientKeyId });
  assert.equal(candidates.length, 1);
  assert.equal(f.members.size, 0);
  assert.equal(f.invitations.size, 0);
  // A signed-in invitee cannot introduce a replacement on a registered firm.
  row = { ...row, approved: true };
  f.store.getOrganization = async () => binding;
  const replacement = await createFirmKeyBinding({ organizationId, domain: 'counsel.example', issuedAt: baseline }, otherFirm);
  await assert.rejects(service.submitOrganizationKey(accessToken, organizationId, replacement));
  assert.equal(candidates.length, 1);
  await assert.rejects(service.submitOrganizationKey(await token('legal', { org_id: 'org_other' }), organizationId, document));
  await assert.rejects(service.submitOrganizationKey(accessToken, organizationId, document.replace('counsel.example', 'other.example')));
  row = { ...row, revokedAt: baseline };
  await assert.rejects(service.submitOrganizationKey(accessToken, organizationId, document));
  assert.equal(candidates.length, 1);
});


test('a never-registered organization accepts a first key without continuity', async () => {
  const { createFirmKeyBinding } = enclaveRequire('./dist/confidential/firmKeyBinding.js');
  const f = fixture(), candidates = [], accessToken = await token();
  f.store.getOrganization = async () => null;
  f.store.getLegalOrganizationRecord = async () => ({ _id: organizationId, providerOrganizationId: 'org_firm', domain: 'counsel.example', approved: false });
  f.store.submitLegalOrganizationKeyCandidate = async value => candidates.push(value);
  const service = createLegalEnrollmentRedeemer(f.options);
  const document = await createFirmKeyBinding({ organizationId, domain: 'counsel.example', issuedAt: baseline }, otherFirm);
  await service.submitOrganizationKey(accessToken, organizationId, document);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].previousRecipientKeyId, undefined);
  // An organization whose row claims approval but has no verifiable registration is refused.
  f.store.getLegalOrganizationRecord = async () => ({ _id: organizationId, providerOrganizationId: 'org_firm', domain: 'counsel.example', approved: true });
  await assert.rejects(service.submitOrganizationKey(accessToken, organizationId, document));
  assert.equal(candidates.length, 1);
});

test('the onboarding authority alone cannot replace a registered organization key', async () => {
  const { createFirmKeyBinding } = enclaveRequire('./dist/confidential/firmKeyBinding.js');
  const { rotateOrganizationKey } = enclaveRequire('./dist/confidential/firmMembers.js');
  const f = fixture(), upserts = [];
  f.store.upsertLegalOrganization = async value => { upserts.push(value); f.setBinding(value); };
  const replace = async (key, continuity) => {
    const recipientKeyId = await caseRecipientKeyId(key.toPublic());
    const registration = { format: 'vera-organization-registration/v1', organizationId, providerOrganizationId: 'org_firm',
      recipientKeyId, publicKey: key.toPublic().armor(), displayName: 'Synthetic firm', domain: 'counsel.example', approved: true, issuedAt: baseline };
    return f.service.issueInvitation(await token('admin'), organizationId, 'auth0|lawyer', 60_000,
      await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId, providerOrganizationId: 'org_firm',
        subject: 'auth0|lawyer', recipientKeyId, issuedAt: baseline, expiresAt: baseline + 60_000 }, onboarding),
      { displayName: 'Synthetic firm', domain: 'counsel.example',
        bindingDocument: await createFirmKeyBinding({ organizationId, domain: 'counsel.example', issuedAt: baseline }, key),
        authorization: await signOrganizationRegistration(registration, onboarding), ...(continuity ? { continuity } : {}) });
  };
  // A VERA-chosen key for an already registered firm: refused, nothing stored.
  await assert.rejects(replace(otherFirm));
  const forged = await rotateOrganizationKey({ organizationId, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: baseline }, otherFirm);
  await assert.rejects(replace(forged.organizationKey, forged.continuity));
  assert.equal(upserts.length, 0);
  // The organization's own rotation (signed by its registered key) is accepted.
  const rotated = await rotateOrganizationKey({ organizationId, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: baseline }, firm);
  await replace(rotated.organizationKey, rotated.continuity);
  assert.equal(upserts.length, 1);
  assert.equal(upserts[0].recipientKeyId, rotated.statement.nextRecipientKeyId);
});

test('delegated leases require the approved device, both signatures and a current bounded authorization', async () => {
  const challenge = { format: 'vera-legal-enrollment/v1', invitationId: '8'.repeat(64), nonce: '9'.repeat(64),
    organizationId, providerOrganizationId: 'org_firm', subject: 'auth0|colleague', recipientKeyId: binding.recipientKeyId,
    expiresAt: baseline + 7 * 86400000 };
  const device = { organizationId, providerOrganizationId: 'org_firm', subject: challenge.subject,
    memberId: await enclaveRequire('./dist/confidential/firmMembers.js').firmMemberId('org_firm', challenge.subject), state: 'approved', deviceFingerprint: otherFirm.getFingerprint(), devicePublicKey: otherFirm.toPublic().armor() };
  const enrollment = { challenge, proof: await signEnrollmentChallenge(challenge, firm),
    authorization: await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId,
      providerOrganizationId: 'org_firm', subject: challenge.subject, recipientKeyId: binding.recipientKeyId,
      issuedAt: baseline, expiresAt: challenge.expiresAt }, firm),
    delegation: { memberId: device.memberId, deviceFingerprint: device.deviceFingerprint,
      deviceProof: await signEnrollmentChallenge({ ...challenge, recipientKeyId: await caseRecipientKeyId(otherFirm.toPublic()) }, otherFirm) } };
  await verifyDeviceMembership(enrollment, firm.toPublic(), device, baseline);
  await assert.rejects(verifyDeviceMembership(enrollment, firm.toPublic(), { ...device, state: 'removed' }, baseline));
  await assert.rejects(verifyDeviceMembership(enrollment, firm.toPublic(), { ...device, subject: 'auth0|other' }, baseline));
  await assert.rejects(verifyDeviceMembership({ ...enrollment, delegation: { ...enrollment.delegation, deviceProof: enrollment.proof } }, firm.toPublic(), device, baseline));
  await assert.rejects(verifyDeviceMembership(enrollment, firm.toPublic(), device, challenge.expiresAt));
  await assert.rejects(verifyDeviceMembership(enrollment, onboarding.toPublic(), device, baseline));
});
