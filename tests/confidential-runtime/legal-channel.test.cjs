// Compiled enclave: composed owner/legal dispatch with native ESM JOSE and real
// firm keys. The in-memory rows below exist ONLY in this test file.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { createSessionChallenges } = require('../../enclave/dist/session-challenges.js');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const path = require('node:path');
const req = createRequire(path.resolve(__dirname, '../../enclave/package.json'));
const { createLegalCaseDispatcher } = req('./dist/cases/legalChannel.js');
const { createCaseChannelDispatch } = req('./dist/confidential-server.js');
const { LEGAL_ASSURANCE_CLAIM } = req('./dist/legal/identity.js');
const { generateKey } = req('./dist/confidential/pgp.js');
const { signOrganizationRegistration } = req('./dist/confidential/organizationRegistration.js');
const { signMembershipAuthorization } = req('./dist/confidential/membershipAuthorization.js');
const { signEnrollmentChallenge } = req('./dist/confidential/enrollmentProof.js');
const { caseRecipientKeyId } = req('./dist/confidential/caseObject.js');
const hex = n => n.toString(16).padStart(64, '0');
let jose, signing, dispatch, member;

before(async () => {
  jose = await import(pathToFileURL(req.resolve('jose')).href);
  signing = await jose.generateKeyPair('RS256');
  const identity = { issuer: 'https://identity.example/', audience: 'https://api.example/legal', clientId: 'legal-client',
    jwks: { keys: [{ ...await jose.exportJWK(signing.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer' }] } };
  const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic firm' }], format: 'object' })).privateKey;
  const organization = { organizationId: hex(1), providerOrganizationId: 'org_firm', recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
    publicKey: firm.toPublic().armor(), approved: true };
  member = { subject: 'auth0|lawyer', providerOrganizationId: 'org_firm', organizationId: hex(1),
    recipientKeyId: organization.recipientKeyId, revision: 1, active: true };
  const challenge = { format: 'vera-legal-enrollment/v1', invitationId: hex(7), nonce: hex(8),
    organizationId: organization.organizationId, providerOrganizationId: 'org_firm', subject: member.subject,
    recipientKeyId: member.recipientKeyId, expiresAt: Date.now() + 86400000 };
  const onboarding = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' })).privateKey;
  organization.registration = await signOrganizationRegistration({ format: 'vera-organization-registration/v1', ...organization, displayName: 'Synthetic firm', domain: 'counsel.example', issuedAt: Date.now() }, onboarding);
  member.enrollment = { challenge, authorization: await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId: member.organizationId, providerOrganizationId: member.providerOrganizationId, subject: member.subject, recipientKeyId: member.recipientKeyId, issuedAt: Date.now(), expiresAt: challenge.expiresAt }, onboarding), proof: await signEnrollmentChallenge(challenge, firm) };
  const store = { async listListedCases() { return []; } };
  const members = { async getMember() { return member && { ...member }; }, async getOrganization() { return { ...organization }; } };
  const options = { store, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest: hex(2) };
  const owner = async () => new TextEncoder().encode('"owner"');
  dispatch = createCaseChannelDispatch(owner, createLegalCaseDispatcher({ ...options, identity, members, administration: { identity: { ...identity, audience: 'admin-api', clientId: 'admin-client' }, organizationId: 'org_admin', onboardingPublicKey: onboarding.toPublic().armor() } }));
});
async function token() {
  const iat = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({ iss: 'https://identity.example/', aud: 'https://api.example/legal', azp: 'legal-client',
    sub: 'auth0|lawyer', org_id: 'org_firm', scope: 'legal:directory', iat, exp: iat + 300,
    [LEGAL_ASSURANCE_CLAIM]: 'approved-member-verified-email' }).setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer' }).sign(signing.privateKey);
}
const context = () => ({ nonce: hex(3), requestId: hex(4), serverKeyId: hex(5), requestDigest: hex(6), signal: new AbortController().signal,
  challenges: createSessionChallenges() });
const call = async body => JSON.parse(new TextDecoder().decode(await dispatch(new TextEncoder().encode(JSON.stringify(body)), context())));

test('routes by prefix and serves the directory to a verified, enrolled member', async () => {
  assert.equal(await call({ operation: 'case.challenge' }), 'owner');
  assert.deepEqual(await call({ operation: 'legal.directory', accessToken: await token(), after: null, limit: 10 }), { listings: [], next: null });
  assert.ok((await call({ operation: 'legal.challenge' })).challenge);
  await assert.rejects(call({ operation: 'admin.read' }), /unavailable/);
  await assert.rejects(call({ operation: 'legal.open-case', accessToken: await token(), proof: '{}', body: 'e30=' }), /unavailable/);
  member = { ...member, active: false };
  await assert.rejects(call({ operation: 'legal.directory', accessToken: await token(), after: null, limit: 10 }), /unavailable/);
});
