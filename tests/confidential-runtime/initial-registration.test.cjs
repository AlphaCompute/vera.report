const { test, before } = require('node:test');
const assert = require('node:assert/strict');
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { generateKey } = require('../../enclave/dist/confidential/pgp.js');
const { caseRecipientKeyId } = require('../../enclave/dist/confidential/caseObject.js');
const { applicationOrganizationId } = require('../../enclave/dist/confidential/applicationOrganization.js');
const { signOrganizationRegistration } = require('../../enclave/dist/confidential/organizationRegistration.js');
const { signMembershipAuthorization } = require('../../enclave/dist/confidential/membershipAuthorization.js');
const { signInitialRegistration, verifyApprovedOrganization, verifyApprovedMembership } = require('../../enclave/dist/confidential/initialRegistration.js');
let admin, worker, firm, registration, membership, rawRegistration, authorization, certificate;
const now = Date.now(), week = 7 * 86400000;
before(async () => {
  [admin, worker, firm] = await Promise.all(['admin', 'worker', 'firm'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  const recipientKeyId = await caseRecipientKeyId(firm.toPublic());
  registration = { format: 'vera-organization-registration/v1', organizationId: await applicationOrganizationId(recipientKeyId),
    recipientKeyId, publicKey: firm.toPublic().armor(), providerOrganizationId: 'org_firm', domain: 'firm.example',
    displayName: 'Firm', approved: true, issuedAt: now };
  membership = { format: 'vera-membership-authorization/v1', organizationId: registration.organizationId, recipientKeyId,
    providerOrganizationId: 'org_firm', subject: 'email|first', issuedAt: now, expiresAt: now + week };
  rawRegistration = await signOrganizationRegistration(registration, worker);
  authorization = await signMembershipAuthorization(membership, worker);
  certificate = await signInitialRegistration(rawRegistration, authorization, worker);
});
test('worker can certify only a key-derived first registration and its exact first member', async () => {
  assert.deepEqual(await verifyApprovedOrganization(certificate, admin.toPublic(), now, worker.toPublic()), registration);
  assert.deepEqual(await verifyApprovedMembership(authorization, certificate, admin.toPublic(), now, worker.toPublic()), membership);
  for (const changes of [{ subject: 'email|another' }, { issuedAt: now + 1, expiresAt: now + week + 1 }]) {
    const forged = await signMembershipAuthorization({ ...membership, ...changes }, worker);
    await assert.rejects(verifyApprovedMembership(forged, certificate, admin.toPublic(), now + 1, worker.toPublic()));
  }
  const arbitraryId = 'a'.repeat(64);
  const forged = await signInitialRegistration(await signOrganizationRegistration({ ...registration, organizationId: arbitraryId }, worker),
    await signMembershipAuthorization({ ...membership, organizationId: arbitraryId }, worker), worker);
  await assert.rejects(verifyApprovedOrganization(forged, admin.toPublic(), now, worker.toPublic()));
});
test('worker key cannot sign ordinary administrator registrations or invitations', async () => {
  await assert.rejects(verifyApprovedOrganization(rawRegistration, admin.toPublic(), now, worker.toPublic()));
  const ordinary = await signOrganizationRegistration(registration, admin);
  await assert.rejects(verifyApprovedMembership(authorization, ordinary, admin.toPublic(), now, worker.toPublic()));
  await assert.rejects(verifyApprovedOrganization(certificate, admin.toPublic(), now));
  await assert.rejects(verifyApprovedOrganization(certificate, worker.toPublic(), now, worker.toPublic()));
});
test('registration survives the initial lease expiry, but membership requires a current authorization', async () => {
  assert.deepEqual(await verifyApprovedOrganization(certificate, admin.toPublic(), now + week, worker.toPublic()), registration);
  await assert.rejects(verifyApprovedMembership(authorization, certificate, admin.toPublic(), now + week, worker.toPublic()));
  const renewed = { ...membership, subject: 'email|next', issuedAt: now + week, expiresAt: now + 2 * week };
  const manual = await signMembershipAuthorization(renewed, admin);
  assert.deepEqual(await verifyApprovedMembership(manual, certificate, admin.toPublic(), now + week, worker.toPublic()), renewed);
});
test('ordinary administrator signatures retain legacy assigned-ID support', async () => {
  const legacy = { ...registration, organizationId: 'a'.repeat(64) };
  const wire = await signOrganizationRegistration(legacy, admin);
  assert.deepEqual(await verifyApprovedOrganization(wire, admin.toPublic(), now, worker.toPublic()), legacy);
});
