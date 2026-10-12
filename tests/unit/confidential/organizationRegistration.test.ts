import { generateKey } from '../../../enclave/src/confidential/pgp';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { signOrganizationRegistration, verifyOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { authenticatedRoster } from '../../../enclave/src/cases/authenticatedRoster';
import type { CaseStore } from '../../../enclave/src/cases/service';

test('roster fields require the independent measured onboarding authority', async () => {
  const [authority, firm] = await Promise.all(['authority', 'firm'].map(async name => (await generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  const now = Date.now(), organizationId = '1'.repeat(64);
  const value = { format: 'vera-organization-registration/v1' as const, organizationId, providerOrganizationId: 'org_firm',
    recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor(), displayName: 'Counsel',
    domain: 'counsel.example', approved: true, issuedAt: now };
  const registration = await signOrganizationRegistration(value, authority);
  await expect(verifyOrganizationRegistration(registration, authority.toPublic(), now)).resolves.toEqual(value);
  await expect(verifyOrganizationRegistration(await signOrganizationRegistration(value, firm), authority.toPublic(), now)).rejects.toThrow();
  for (const changes of [{ domain: 'attacker.example' }, { displayName: 'Another firm' }, { approved: false }, { providerOrganizationId: 'org_other' }]) {
    const changed = JSON.parse(registration); changed.statement = { ...changed.statement, ...changes };
    await expect(verifyOrganizationRegistration(JSON.stringify(changed), authority.toPublic(), now)).rejects.toThrow();
  }
  const store = { async listLegalOrganizations() { return [{ ...value, domain: 'host-substitution.example', registration },
    { ...value, organizationId: '2'.repeat(64), registration }, { ...value, approved: false, registration }, { ...value, registration: '{}' }]; } } as unknown as CaseStore;
  const rows = await authenticatedRoster(store, authority.toPublic().armor(), () => now).listLegalOrganizations!();
  expect(rows).toEqual([{ organizationId, displayName: 'Counsel', domain: 'counsel.example', publicKey: value.publicKey, approved: true }]);
  expect(await authenticatedRoster(store, undefined, () => now).listLegalOrganizations!()).toEqual([]);
  const bindingDocument = await createFirmKeyBinding({ domain: value.domain, organizationId, issuedAt: now }, firm);
  const profileStore = { async listLegalOrganizations() { return [{ ...value, registration, bindingDocument }]; } } as unknown as CaseStore;
  expect(await authenticatedRoster(profileStore, authority.toPublic().armor(), () => now).listLegalOrganizations!())
    .toEqual([{ ...rows[0], bindingDocument }]);
  const wrongKeyDocument = await createFirmKeyBinding({ domain: value.domain, organizationId, issuedAt: now }, authority);
  const substituted = { async listLegalOrganizations() { return [{ ...value, registration, bindingDocument: wrongKeyDocument }]; } } as unknown as CaseStore;
  expect(await authenticatedRoster(substituted, authority.toPublic().armor(), () => now).listLegalOrganizations!()).toEqual([]);

});
