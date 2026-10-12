import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { generateApplicationIdentity, firmBindingDocument } from '../../../lib/confidential/firmKey';
import { applicationReviewDigest } from '../../../src/utils/legalApplicationEnrollment';
import { provisionLegalApplication } from '../../../src/services/legalApplicationAuth0';

describe('combined first-key approval persistence', () => {
  let mongo: MongoMemoryReplSet, client: MongoClient, store: MongoConfidentialCaseStore;
  const input = { displayName: 'Test Firm', domain: 'firm.example', email: 'lawyer@firm.example', lawyerName: 'Test Lawyer', jurisdiction: 'New York', registrationNumber: 'TEST-1' };
  let enrollment: { organizationId: string; recipientKeyId: string; bindingDocument: string };
  beforeAll(async () => {
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } }); client = await MongoClient.connect(mongo.getUri());
    const firm = await generateApplicationIdentity(input.domain);
    enrollment = { organizationId: firm.organizationId, recipientKeyId: firm.recipientKeyId, bindingDocument: await firmBindingDocument(firm, Date.now(), {
      practiceAreas: ['whistleblower'], jurisdiction: 'New York', website: 'https://firm.example/' }) };
  }, 120000);
  beforeEach(async () => { await client.db('combined_test').dropDatabase(); store = await MongoConfidentialCaseStore.fromDatabase(client.db('combined_test'), client); });
  afterAll(async () => { await client?.close(); await mongo?.stop(); });
  test('pins one immutable application/key snapshot, hides all details in status and publishes once after provisioning', async () => {
    const service = store.applications, id = enrollment.organizationId;
    await service.submit({ ...input, enrollment }); await service.submit({ ...input, enrollment });
    expect((await service.list()).applications).toHaveLength(1);
    await expect(service.submit({ ...input, email: 'different@firm.example', enrollment })).rejects.toThrow();
    const digest = await applicationReviewDigest((await service.get(id))!);
    expect(await service.decide(id, 'approved', 'slack:TTEST:UTEST')).toBe(false);
    expect(await service.decide(id, 'approved', 'slack:TTEST:UTEST', Date.now(), '0'.repeat(64))).toBe(false);
    expect(await service.saveCombinedApproval(id, digest, 'certificate')).toBe(false);
    expect(await service.applicationStatus(id)).toEqual({ state: 'pending' });
    expect(await service.decide(id, 'approved', 'slack:TTEST:UTEST', Date.now(), digest)).toBe(false);
    expect(await service.decide(id, 'approved', 'slack:TTEST:UTEST', Date.now(), digest, '0'.repeat(64))).toBe(false);
    expect(await service.applicationStatus(id)).toEqual({ state: 'pending' });
    expect(await service.decide(id, 'approved', 'slack:TTEST:UTEST', Date.now(), digest, enrollment.recipientKeyId)).toBe(true);
    expect(await service.decide(id, 'denied', 'slack:TTEST:UOTHER', Date.now(), digest)).toBe(false);
    await service.provisionOne(app => provisionLegalApplication(app, { organization: async () => 'org_test', invite: async () => {} }, store));
    expect(await service.applicationStatus(id)).toEqual({ state: 'sign-in-ready', providerOrganizationId: 'org_test' });
    expect(await store.legalSignInTarget(input.email)).toMatchObject({ providerOrganizationId: 'org_test', pending: true });
    expect(await store.legalSignInTarget('other@firm.example')).toMatchObject({ pending: false });
    expect(await service.saveCombinedApproval(id, digest, 'certificate')).toBe(true);
    // Old completed approvals cannot recreate membership if it is later removed.
    expect(await store.legalSignInTarget(input.email)).toMatchObject({ pending: false });
    expect(await service.saveCombinedApproval(id, digest, 'certificate')).toBe(true);
    expect(await service.saveCombinedApproval(id, digest, 'different')).toBe(false);
    expect(await service.applicationStatus(id)).toEqual({ state: 'ready', providerOrganizationId: 'org_test' });
    expect(await service.getCombinedApproval(id)).toBe('certificate');
  });
  test('first verified sign-in consumes only that address approval; revocation cannot revive it', async () => {
    const service = store.applications, id = enrollment.organizationId;
    await service.submit({ ...input, enrollment });
    const digest = await applicationReviewDigest((await service.get(id))!);
    await service.decide(id, 'approved', 'slack:TTEST:UTEST', Date.now(), digest, enrollment.recipientKeyId);
    await service.provisionOne(app => provisionLegalApplication(app, { organization: async () => 'org_test', invite: async () => {} }, store));
    expect(await service.firstSignInApproved(id, input.email)).toBe(true);
    await store.consumeLegalSignInApproval(id, input.email, 'email|approved');
    expect(await service.firstSignInApproved(id, input.email)).toBe(false);
    expect(await store.legalSignInTarget(input.email, 'org_wrong')).toBeNull();
    await store.revokeLegalOrganization(id, 'staff', Date.now());
    expect(await store.legalSignInTarget(input.email)).toBeNull();
  });
  test('first registration is atomic, preserves refreshed profiles on retry, and cannot replace or revive a key', async () => {
    const id = enrollment.organizationId;
    await store.createLegalOrganization({ organizationId: id, displayName: input.displayName, domain: input.domain, providerOrganizationId: 'org_test' }, 'staff', Date.now());
    const value = { organizationId: id, providerOrganizationId: 'org_test', domain: input.domain, displayName: input.displayName,
      recipientKeyId: enrollment.recipientKeyId, publicKey: 'verified public key', registration: 'verified registration', bindingDocument: enrollment.bindingDocument, approved: true };
    const other = { ...value, recipientKeyId: 'b'.repeat(64), publicKey: 'different verified key', registration: 'different registration' };
    const results = await Promise.allSettled([store.registerFirstApplicationKey(value, Date.now()), store.registerFirstApplicationKey(other, Date.now())]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const winner = results[0].status === 'fulfilled' ? value : other;
    const rows = client.db('combined_test').collection<any>('confidential_legal_organizations');
    await rows.updateOne({ _id: id }, { $set: { bindingDocument: 'newer same-key profile' } });
    const before = await rows.findOne({ _id: id });
    await store.registerFirstApplicationKey(winner, Date.now());
    expect(await rows.findOne({ _id: id })).toMatchObject({ bindingDocument: 'newer same-key profile', deviceAdmissionRevision: before.deviceAdmissionRevision });
    await store.revokeLegalOrganization(id, 'staff', Date.now());
    await expect(store.registerFirstApplicationKey(winner, Date.now())).rejects.toThrow();
  });
  test('legacy assigned IDs remain on the manual administrator path without queuing worker approvals', async () => {
    const service = store.applications;
    await service.submit(input); const id = (await service.list()).applications[0].id;
    await service.approveAndPrepare(id, 'org_test', 'staff', store);
    const key = { ...enrollment, organizationId: id };
    await service.queueFirstKeyReview(id, 'org_test', key, Date.now());
    expect((await service.get(id))?.enrollment).toBeUndefined();
    expect(await service.applicationStatus(id)).toEqual({ state: 'unavailable' });
    expect(await service.saveCombinedApproval(id, 'a'.repeat(64), 'certificate')).toBe(false);
  });
});
