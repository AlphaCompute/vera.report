import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { LegalApplications, LEGAL_APPLICATION_RETENTION_MS } from '../../../src/services/legalApplications';
import { generateFirmIdentity, generateApplicationIdentity, firmBindingDocument } from '../../../lib/confidential/firmKey';

describe('public application ID ownership', () => {
  let mongo: MongoMemoryServer;
  let client: MongoClient;
  let applications: LegalApplications;
  const input = { displayName: 'Review Test Firm', domain: 'review-firm.example', email: 'lawyer@review-firm.example',
    lawyerName: 'Review Lawyer', jurisdiction: 'New York', registrationNumber: 'REVIEW-1039' };
  const profile = { practiceAreas: ['whistleblower'] as ['whistleblower'], jurisdiction: 'New York', website: 'https://review-firm.example/' };
  const now = Date.now();
  async function candidate(organizationId: string) {
    const firm = await generateFirmIdentity({ organizationId, domain: input.domain });
    return { organizationId, recipientKeyId: firm.recipientKeyId, bindingDocument: await firmBindingDocument(firm, now, profile) };
  }
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create();
    client = await MongoClient.connect(mongo.getUri());
    applications = await LegalApplications.fromDatabase(client.db('pr1039_review'));
  }, 120000);
  afterAll(async () => { await client?.close(); await mongo?.stop(); });
  test('an attacker cannot reserve a known unused ID; the owning key can submit and retry', async () => {
    const firm = await generateApplicationIdentity(input.domain), id = firm.organizationId;
    const attacker = await candidate(id);
    const legitimate = { organizationId: id, recipientKeyId: firm.recipientKeyId, bindingDocument: await firmBindingDocument(firm, now, profile) };
    await expect(applications.submit({ ...input, enrollment: attacker }, now)).rejects.toThrow('Invalid application ID');
    expect(await applications.get(id)).toBeNull();
    await applications.submit({ ...input, enrollment: legitimate }, now);
    await applications.submit({ ...input, enrollment: legitimate }, now);
    await expect(applications.submit({ ...input, enrollment: attacker }, now)).rejects.toThrow('Application conflict');
    const persisted = await client.db('pr1039_review').collection('legal_applications').findOne({ id });
    expect(persisted?.status).toBe('pending');
    expect(persisted?.expiresAt.getTime()).toBe(now + LEGAL_APPLICATION_RETENTION_MS);
    expect(persisted?.enrollment.recipientKeyId).toBe(legitimate.recipientKeyId);
    expect(id).not.toBe(firm.recipientKeyId);
    expect((await applications.list()).applications).toHaveLength(1);
  });
  test('an already-created legacy onboarding record cannot be reserved or overwritten through keyed public submission', async () => {
    await applications.submit(input, now + 1);
    const legacy = (await applications.list()).applications.find(row => !row.enrollment)!;
    await expect(applications.submit({ ...input, enrollment: await candidate(legacy.id) }, now + 2)).rejects.toThrow();
    expect((await applications.get(legacy.id))?.enrollment).toBeUndefined();
  });
  test('an exact existing keyed application can retry after migration; an assigned ID uses manual setup', async () => {
    const id = 'a'.repeat(64), enrollment = await candidate(id);
    await client.db('pr1039_review').collection<any>('legal_applications').insertOne({
      _id: id, id, ...input, enrollment, status: 'pending', createdAt: now, expiresAt: new Date(now + LEGAL_APPLICATION_RETENTION_MS), notifyAt: now });
    await applications.submit({ ...input, enrollment }, now + 1);
    expect(await applications.applicationStatus(id)).toEqual({ state: 'unavailable' });
    await expect(applications.submit({ ...input, email: 'another@review-firm.example', enrollment }, now + 2)).rejects.toThrow('Application conflict');
  });
});
