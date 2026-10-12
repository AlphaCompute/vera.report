import { test, expect } from '@playwright/test';
import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { applicationFixtures, installApplicationFixtures } from '../e2e/stack/legalApplications';
import { legalApplicationProvisioner } from '../../src/services/legalApplicationAuth0';
import { LegalAuth0Memberships } from '../../src/services/legalAuth0Memberships';

test('approval prepares membership silently and native OTP verifies the existing account through Auth0 Actions', async () => {
  const fixture = installApplicationFixtures();
  const mongo = await MongoMemoryServer.create();
  const client = await MongoClient.connect(mongo.getUri());
  try {
    const clientId = 'synthetic-legal-client';
    const provider = legalApplicationProvisioner(applicationFixtures.backend, {
      clientId, issuer: 'https://identity.example/', audience: 'https://legal-api.example',
    })!;
    const response = await fetch('https://identity.example/api/v2/organizations', {
      method: 'POST', headers: { Authorization: 'Bearer synthetic-application-token' },
      body: JSON.stringify({ name: 'synthetic-firm', metadata: { vera_domain: 'firm.example', vera_application_id: 'a'.repeat(64) } }),
    });
    const organization = await response.json();
    const worker = await LegalAuth0Memberships.fromDatabase(client.db('native_entry_fixture'));
    const approval = { organizationId: 'a'.repeat(64), approvalId: 'b'.repeat(64),
      providerOrganizationId: organization.id, domain: 'firm.example', email: 'approved@firm.example', expires: Date.now() + 300_000 };
    await worker.queue(approval);
    await worker.runOne(provider, async () => true);
    expect(fixture.snapshot().users).toEqual([
      expect.objectContaining({ user_id: 'email|fixture1', email: approval.email, email_verified: false, blocked: false }),
    ]);
    expect(fixture.snapshot().memberships).toEqual([
      expect.objectContaining({ user_id: 'email|fixture1', organization_id: organization.id,
        email: approval.email, roles: ['rol_legal'], email_verified: false, blocked: false }),
    ]);
    expect(fixture.snapshot().emails).toEqual([]);
    expect(await worker.consumed(approval.organizationId, approval.email)).toBe(true);
    await expect(fixture.nativeEmail('unapproved@firm.example', clientId)).rejects.toThrow('Unapproved synthetic OTP');
    expect(fixture.snapshot().users.filter(user => user.email === 'unapproved@firm.example')).toEqual([]);
    expect(fixture.snapshot().emails).toEqual([]);

    // Replaying approval cannot create another account, send an email, or grant again.
    await worker.queue(approval);
    expect(await worker.runOne(provider, async () => true, Date.now() + 3000)).toBe(false);
    expect(fixture.snapshot().users).toHaveLength(1);
    expect(fixture.snapshot().memberships).toHaveLength(1);
    expect(fixture.snapshot().emails).toEqual([]);

    const identity = await fixture.nativeEmail(approval.email, clientId);
    expect(identity).toEqual({ subject: 'email|fixture1', organization: organization.id });
    expect(fixture.snapshot().users).toEqual([
      expect.objectContaining({ user_id: identity.subject, email: approval.email, email_verified: true, blocked: false }),
    ]);
    expect(fixture.snapshot().memberships).toEqual([
      expect.objectContaining({ user_id: identity.subject, organization_id: organization.id, roles: ['rol_legal'], email_verified: true }),
    ]);
    expect(fixture.snapshot().emails).toEqual([{ email: approval.email, kind: 'code' }]);
    expect(fixture.snapshot().invitations).toEqual([]);
    expect(await worker.runOne(provider, async () => true, Date.now() + 60_000)).toBe(false);
  } finally {
    fixture.restore();
    await client.close();
    await mongo.stop();
  }
});
