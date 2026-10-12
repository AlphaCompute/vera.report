import { generateKey } from '../../../enclave/src/confidential/pgp';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { signMembershipAuthorization, verifyMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import type { MembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';

test('independent onboarding signature binds member, firm, provider and bounded lease', async () => {
  const [authority, firm] = await Promise.all(['authority', 'firm'].map(async name => (await generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  const now = Date.now();
  const value: MembershipAuthorization = { format: 'vera-membership-authorization/v1', organizationId: '1'.repeat(64),
    providerOrganizationId: 'org_firm', subject: 'auth0|lawyer', recipientKeyId: '2'.repeat(64), issuedAt: now, expiresAt: now + 60000 };
  const wire = await signMembershipAuthorization(value, authority);
  await expect(verifyMembershipAuthorization(wire, authority.toPublic(), now)).resolves.toEqual(value);
  await expect(verifyMembershipAuthorization(await signMembershipAuthorization(value, firm), authority.toPublic(), now)).rejects.toThrow();
  for (const changes of [{ subject: 'auth0|other' }, { recipientKeyId: '3'.repeat(64) }, { organizationId: '4'.repeat(64) },
    { providerOrganizationId: 'org_other' }, { expiresAt: now + 120000 }]) {
    const changed = JSON.parse(wire); changed.statement = { ...changed.statement, ...changes };
    await expect(verifyMembershipAuthorization(JSON.stringify(changed), authority.toPublic(), now)).rejects.toThrow();
  }
  await expect(verifyMembershipAuthorization(wire, authority.toPublic(), now + 60000)).rejects.toThrow();
  await expect(verifyMembershipAuthorization(wire, authority.toPublic(), now - CLOCK_SKEW_MS - 1)).rejects.toThrow();
  // A signing device a few minutes ahead of the enclave is tolerated.
  await expect(verifyMembershipAuthorization(wire, authority.toPublic(), now - CLOCK_SKEW_MS + 1_000)).resolves.toEqual(value);
  await expect(signMembershipAuthorization({ ...value, expiresAt: now + 7 * 86400000 + 1 }, authority)).rejects.toThrow();
});
