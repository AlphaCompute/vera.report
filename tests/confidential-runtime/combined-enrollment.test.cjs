const { test, before } = require('node:test');
const assert = require('node:assert/strict');
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const req = createRequire(require('node:path').resolve(__dirname, '../../enclave/package.json'));
const { generateKey, createMessage, sign } = req('./dist/confidential/pgp.js');
const { caseRecipientKeyId } = req('./dist/confidential/caseObject.js');
const { applicationOrganizationId } = req('./dist/confidential/applicationOrganization.js');
const { createFirmKeyBinding } = req('./dist/confidential/firmKeyBinding.js');
const { signCombinedApplicationApproval, verifyCombinedApplicationApproval } = req('./dist/confidential/combinedApplicationApproval.js');
const { createCombinedEnrollment } = req('./dist/legal/combinedEnrollment.js');
const { createLegalEnrollmentRedeemer } = req('./dist/legal/enrollment.js');
const { signEnrollmentChallenge } = req('./dist/confidential/enrollmentProof.js');
let jose, issuer, policy, authority, administrator, firm, other, approval, input, id;
const REVIEW_LIFETIME = 7 * 86400000;
const now = Math.floor(Date.now() / 1000) * 1000;
before(async () => {
  jose = await import(pathToFileURL(req.resolve('jose')).href);
  issuer = await jose.generateKeyPair('RS256');
  policy = { issuer: 'https://identity.example/', audience: 'https://legal.example/', clientId: 'legal-spa',
    jwks: { keys: [{ ...await jose.exportJWK(issuer.publicKey), kid: 'issuer', use: 'sig', alg: 'RS256' }] } };
  [authority, administrator, firm, other] = await Promise.all(['authority', 'administrator', 'firm', 'other'].map(async name => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  id = await applicationOrganizationId(await caseRecipientKeyId(firm.toPublic()));
  input = { organizationId: id, providerOrganizationId: 'org_firm', domain: 'firm.example', displayName: 'Synthetic Firm',
    subject: 'email|approved', recipientKeyId: await caseRecipientKeyId(firm.toPublic()), applicationDigest: 'd'.repeat(64), actor: 'slack:T123:U123', decidedAt: now, now,
    bindingDocument: await createFirmKeyBinding({ organizationId: id, domain: 'firm.example', issuedAt: now,
      profile: { practiceAreas: ['whistleblower'], jurisdiction: 'New York', website: 'https://firm.example/' } }, firm) };
  approval = await signCombinedApplicationApproval(input, authority);
});
async function token(changes = {}) {
  return new jose.SignJWT({ sub: input.subject, org_id: 'org_firm', azp: policy.clientId, scope: 'legal:enroll',
    'https://vera.app/legal-assurance': 'approved-member-verified-email', ...changes })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer' }).setIssuer(policy.issuer).setAudience(policy.audience)
    .setIssuedAt(now / 1000).setExpirationTime(now / 1000 + 300).sign(issuer.privateKey);
}
function fixture(wire = approval) {
  let binding = null, member = null;
  const invitations = new Map();
  const store = {
    getApplicationApproval: async () => wire,
    getOrganization: async () => binding,
    registerFirstApplicationKey: async value => { if (binding && binding.recipientKeyId !== value.recipientKeyId) throw new Error(); binding = value; },
    insertInvitation: async value => invitations.set(value.tokenDigest, value),
    getInvitation: async digest => invitations.get(digest) ?? null,
    commitEnrollment: async (expected, value) => {
      if (invitations.get(expected.tokenDigest)?.state !== 'pending' || binding.recipientKeyId !== expected.recipientKeyId) return false;
      invitations.set(expected.tokenDigest, { ...expected, state: 'redeemed', version: 2 }); member = value; return true;
    },
  };
  const options = { legalIdentity: policy, onboardingPublicKey: administrator.toPublic().armor(), initialApprovalPublicKey: authority.toPublic().armor(), store, clock: () => now };
  return { activate: createCombinedEnrollment(options), redeem: createLegalEnrollmentRedeemer(options), store,
    binding: () => binding, member: () => member, setBinding: value => { binding = value; }, invitations };
}
test('one signed review registers only the approved key and still requires private-key proof', async () => {
  const f = fixture(), access = await token();
  const result = await f.activate(access, id);
  assert.equal(result.state, 'approved');
  assert.equal(f.binding().recipientKeyId, input.recipientKeyId);
  assert.equal(f.member(), null);
  const challenge = await f.redeem.getChallenge(result.token, access);
  const wrongProof = await signEnrollmentChallenge({ ...challenge, recipientKeyId: await caseRecipientKeyId(other.toPublic()) }, other);
  await assert.rejects(f.redeem.redeemInvitation(result.token, access, wrongProof));
  await f.redeem.redeemInvitation(result.token, access, await signEnrollmentChallenge(challenge, firm));
  assert.equal(f.member().subject, input.subject);
  await assert.rejects(f.redeem.redeemInvitation(result.token, access, await signEnrollmentChallenge(challenge, firm)));
});
test('rejects unapproved identity, wrong organization, missing scope and admin assurance', async () => {
  for (const change of [{ sub: 'email|intruder' }, { org_id: 'org_other' }, { scope: 'openid' },
    { 'https://vera.app/legal-assurance': undefined }, { 'https://vera.app/legal-assurance': 'mfa-verified-email' }]) {
    const f = fixture(); await assert.rejects(f.activate(await token(change), id)); assert.equal(f.binding(), null);
  }
});
test('absent approval waits; host-tampered or wrong-authority approvals cannot register keys', async () => {
  const absent = fixture(null); assert.deepEqual(await absent.activate(await token(), id), { state: 'pending' });
  const changed = JSON.parse(approval); changed.statement.applicationDigest = 'e'.repeat(64);
  for (const wire of [JSON.stringify(changed), await signCombinedApplicationApproval(input, other), '{}']) {
    const f = fixture(wire); await assert.rejects(f.activate(await token(), id)); assert.equal(f.binding(), null);
  }
});
test('approval signs the exact public profile and denies substitution', async () => {
  const changed = JSON.parse(approval), document = JSON.parse(changed.statement.bindingDocument);
  document.binding.profile.website = 'https://attacker.example/'; changed.statement.bindingDocument = JSON.stringify(document);
  await assert.rejects(verifyCombinedApplicationApproval(JSON.stringify(changed), authority.toPublic(), now));
  await assert.rejects(verifyCombinedApplicationApproval(approval, authority.toPublic(), now + 8 * 86400000));
});
test('combined approval cannot replace another registered key or resurrect a revoked key', async () => {
  const f = fixture(); await f.activate(await token(), id);
  f.setBinding({ ...f.binding(), approved: false });
  await assert.rejects(f.activate(await token(), id));
  await assert.rejects(signCombinedApplicationApproval({ ...input, recipientKeyId: await caseRecipientKeyId(other.toPublic()),
    bindingDocument: await createFirmKeyBinding({ organizationId: id, domain: input.domain, issuedAt: now }, other) }, authority));
  const g = fixture(); g.setBinding({ ...f.binding(), approved: true, recipientKeyId: await caseRecipientKeyId(other.toPublic()), publicKey: other.toPublic().armor() });
  await assert.rejects(g.activate(await token(), id));
});

test('delayed signing consumes the original seven-day review window, with no expiry grace', async () => {
  const issuedAt = now + REVIEW_LIFETIME - 1;
  const wire = await signCombinedApplicationApproval({ ...input, now: issuedAt }, authority);
  const checked = await verifyCombinedApplicationApproval(wire, authority.toPublic(), issuedAt);
  assert.equal(checked.authorization.issuedAt, issuedAt);
  assert.equal(checked.authorization.expiresAt, now + REVIEW_LIFETIME);
  for (const time of [now + REVIEW_LIFETIME, now + REVIEW_LIFETIME + 1]) {
    await assert.rejects(verifyCombinedApplicationApproval(wire, authority.toPublic(), time));
    await assert.rejects(signCombinedApplicationApproval({ ...input, now: time }, authority));
  }
});

test('signer rejects future, malformed and overflowing decision times', async () => {
  for (const decidedAt of [now + 1, 0, -1, now + 0.5, null, 'now', NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(signCombinedApplicationApproval({ ...input, decidedAt }, authority));
  }
  for (const time of [0, -1, NaN, Infinity, now + 0.5]) {
    await assert.rejects(signCombinedApplicationApproval({ ...input, now: time }, authority));
  }
});

test('enclave refuses a correctly signed old review carrying a newly issued seven-day authorization', async () => {
  // Model an old worker: it signs fresh nested certificates but leaves the old
  // review timestamp. Every signature is valid; freshness must reject the bundle.
  for (const decidedAt of [now - REVIEW_LIFETIME + 1, now - REVIEW_LIFETIME, now - REVIEW_LIFETIME - 1]) {
    const statement = { ...JSON.parse(approval).statement, decidedAt };
    const wire = JSON.stringify({ statement, signature: await sign({
      message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
      signingKeys: authority, detached: true, format: 'armored' }) });
    await assert.rejects(verifyCombinedApplicationApproval(wire, authority.toPublic(), now));
    const f = fixture(wire);
    await assert.rejects(f.activate(await token(), id));
    assert.equal(f.binding(), null); assert.equal(f.invitations.size, 0);
  }
});

test('remote-clock issue-time tolerance cannot extend the review expiration', async () => {
  await verifyCombinedApplicationApproval(approval, authority.toPublic(), now - 5 * 60_000);
  await assert.rejects(verifyCombinedApplicationApproval(approval, authority.toPublic(), now - 5 * 60_000 - 1));
  await assert.rejects(verifyCombinedApplicationApproval(approval, authority.toPublic(), now + REVIEW_LIFETIME));
});
