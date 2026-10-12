import express from 'express';
import request from 'supertest';
import { createLegalApplicationsRouter } from '../../../src/api/legalApplications';
import { projectLegalOrganization } from '../../../src/utils/legalOnboarding';
import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { provisionLegalApplication } from '../../../src/services/legalApplicationAuth0';
import { LEGAL_APPLICATION_RETENTION_MS, LegalApplications } from '../../../src/services/legalApplications';
import type { LegalApplicationSource } from '../../../src/services/legalApplications';
import { LegalProvisioningError } from '../../../src/utils/legalApplications';

const input = { displayName: 'Example Counsel', domain: 'firm.example', email: 'lawyer@firm.example',
  lawyerName: 'Synthetic Lawyer', jurisdiction: 'Example jurisdiction', registrationNumber: 'TEST-123' };
describe('legal applications isolated review and durable notification', () => {
  let server: MongoMemoryReplSet, client: MongoClient, service: LegalApplicationSource, store: MongoConfidentialCaseStore;
  beforeAll(async () => { server = await MongoMemoryReplSet.create({ replSet: { count: 1 } }); client = await MongoClient.connect(server.getUri()); store = await MongoConfidentialCaseStore.fromDatabase(client.db('applications'), client); service = store.applications; });
  afterAll(async () => { await client?.close(); await server?.stop(); });
  beforeEach(async () => { for (const name of ['legal_applications', 'confidential_legal_organizations', 'confidential_legal_audit']) await client.db('applications').collection(name).deleteMany({}); });
  it('never dispatches malformed legacy approval rows to a provisioning callback', async () => {
    const rows = client.db('applications').collection('legal_applications');
    const id = 'f'.repeat(64);
    await rows.insertOne({ _id: id as never, id, ...input, displayName: 'Bad\u2028Firm', status: 'approved',
      createdAt: 1000, decidedAt: 2000, decidedBy: 'admin', provisionAt: 2000 });
    const provider = jest.fn(async () => 'org_shouldnotexist');
    expect(await service.provisionOne(provider, 3000)).toBe(true);
    expect(provider).not.toHaveBeenCalled();
    expect(await rows.findOne({ id })).toMatchObject({ provisioningStatus: 'retrying', status: 'approved' });
  });
  it('automatic approval queues one canonical organization and rejects stale manual setup', async () => {
    const app = express();
    app.use(createLegalApplicationsRouter(async () => service, (_req, _res, next) => next(), async () => store, async () => true));
    await service.submit({ ...input, displayName: 'Example   Counsel' }, 1000);
    const id = (await service.list()).applications[0].id;
    expect((await request(app).post('/list').send({}).expect(200)).body.provisioningEnabled).toBe(true);
    await request(app).post('/decide').send({ id, status: 'approved', providerOrganizationId: 'org_manual', actor: 'staff' }).expect(409);
    expect((await service.list()).applications[0].status).toBe('pending');
    await request(app).post('/decide').send({ id, status: 'approved', actor: 'staff' }).expect(200);
    const provider = { organization: jest.fn(async () => 'org_automatic'), invite: jest.fn(async () => undefined) };
    await service.provisionOne(application => provisionLegalApplication(application, provider, store));
    expect((await service.list()).applications[0]).toMatchObject({ organizationId: id, providerOrganizationId: 'org_automatic', provisioningStatus: 'ready' });
    expect(projectLegalOrganization(await store.getLegalOrganizationRecord(id))).toMatchObject({ displayName: 'Example Counsel', status: 'awaiting-registration', activeMembers: 0, publicKey: null });
    await request(app).post('/decide').send({ id, status: 'approved', actor: 'retry' }).expect(200);
    expect(await service.provisionOne(application => provisionLegalApplication(application, provider, store))).toBe(false);
    expect(provider.organization).toHaveBeenCalledTimes(1);
  });
  it('manual preparation is already ready and survives enabling the automatic worker without provider effects', async () => {
    await service.submit(input, 1000);
    const id = (await service.list()).applications[0].id;
    await service.approveAndPrepare(id, 'org_existing', 'staff', store, 2000);
    const provider = { organization: jest.fn(async () => 'org_unwanted'), invite: jest.fn(async () => undefined) };
    expect(await service.provisionOne(application => provisionLegalApplication(application, provider, store))).toBe(false);
    expect(provider.organization).not.toHaveBeenCalled();
    expect(provider.invite).not.toHaveBeenCalled();
    expect((await service.list()).applications[0]).toMatchObject({ provisioningStatus: 'ready', providerOrganizationId: 'org_existing' });
  });
  it('approval remains application-only and concurrent conflicting decisions cannot overwrite the audit', async () => {
    await service.submit(input, 1000);
    const id = (await service.list()).applications[0].id;
    const result = await Promise.all([service.decide(id, 'approved', 'admin-a', 2000), service.decide(id, 'denied', 'admin-b', 2001)]);
    expect(result.filter(Boolean)).toHaveLength(1);
    const row = (await service.list()).applications[0];
    expect(row.status).not.toBe('pending');
    expect(await service.decide(id, row.status as 'approved' | 'denied', 'replay', 3000)).toBe(true);
    expect((await service.list()).applications[0].decidedBy).toBe(row.decidedBy);
    expect(await client.db('applications').collection('confidential_legal_organizations').countDocuments()).toBe(0);
  });
  it('prepares one pending roster on concurrent approval, never membership or keys, and rejects rebinding or revival', async () => {
    await service.submit(input);
    const id = (await service.list()).applications[0].id;
    expect(await Promise.all([service.approveAndPrepare(id, 'org_firm', 'staff', store),
      service.approveAndPrepare(id, 'org_firm', 'retry', store)])).toEqual([true, true]);
    const rows = await store.listLegalOrganizationRecords();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ _id: id, domain: input.domain, approved: false, publicKey: '', providerOrganizationId: 'org_firm' });
    expect(await store.listLegalMemberRecords(id)).toEqual([]);
    expect(await store.listLegalInvitationRecords(id)).toEqual([]);
    expect((await service.list()).applications[0]).toMatchObject({ status: 'approved', organizationId: id, providerOrganizationId: 'org_firm' });
    expect(await service.approveAndPrepare(id, 'org_different', 'other', store)).toBe(false);
    expect((await store.getLegalOrganizationRecord(id))?.providerOrganizationId).toBe('org_firm');
    await store.revokeLegalOrganization(id, 'staff', Date.now());
    expect(await service.approveAndPrepare(id, 'org_firm', 'retry', store)).toBe(false);
  });
  it('recovers an interrupted create and permits correcting an already-claimed provider before creation', async () => {
    await store.createLegalOrganization({ organizationId: 'f'.repeat(64), displayName: 'Other', domain: 'other.example', providerOrganizationId: 'org_taken' }, 'staff', Date.now());
    await service.submit(input);
    const id = (await service.list()).applications[0].id;
    await expect(service.approveAndPrepare(id, 'org_taken', 'staff', store)).rejects.toThrow();
    expect((await service.list()).applications[0]).not.toHaveProperty('providerOrganizationId');
    // Simulate storage committing, then a connection loss before the caller sees success.
    const interrupted = { getLegalOrganizationRecord: store.getLegalOrganizationRecord.bind(store),
      createLegalOrganization: async (...args: Parameters<typeof store.createLegalOrganization>) => {
        await store.createLegalOrganization(...args); throw new Error('response lost');
      } };
    expect(await service.approveAndPrepare(id, 'org_correct', 'staff', interrupted)).toBe(true);
    expect(await service.approveAndPrepare(id, 'org_correct', 'staff', store)).toBe(true);
    expect((await service.list()).applications[0]).toMatchObject({ organizationId: id, providerOrganizationId: 'org_correct' });
    expect(await client.db('applications').collection('confidential_legal_audit').countDocuments({ organizationId: id, action: 'organization_created' })).toBe(1);
  });
  it('different provider races cannot overwrite the winner and denied applicants cannot prepare', async () => {
    await service.submit(input);
    const id = (await service.list()).applications[0].id;
    const outcomes = await Promise.allSettled(['org_first', 'org_second'].map(provider => service.approveAndPrepare(id, provider, 'staff', store)));
    expect(outcomes.filter(result => result.status === 'fulfilled' && result.value === true)).toHaveLength(1);
    const row = (await service.list()).applications[0];
    expect((await store.getLegalOrganizationRecord(id))?.providerOrganizationId).toBe(row.providerOrganizationId);
    await service.submit({ ...input, domain: 'denied.example', email: 'a@denied.example' });
    const denied = (await service.list()).applications.find(row => row.domain === 'denied.example')!;
    await service.decide(denied.id, 'denied', 'staff');
    expect(await service.approveAndPrepare(denied.id, 'org_denied', 'staff', store)).toBe(false);
    expect(await store.getLegalOrganizationRecord(denied.id)).toBeNull();
  });
  it('rejects unsafe intake and legacy malformed names before approval or claiming roster identities', async () => {
    const app = express();
    app.use(createLegalApplicationsRouter(async () => service, (_req, _res, next) => next(), async () => store));
    const rows = client.db('applications').collection<any>('legal_applications');
    for (const [index, displayName] of ['Bad\u2028Name', 'Bad\u2029Name', 'Bad\u0085Name', 'Bad\u009fName', 'A'].entries()) {
      await request(app).post('/submit').send({ ...input, displayName }).expect(400);
      expect(await rows.countDocuments()).toBe(index);
      // A persisted row from the old validator cannot bypass validation at approval.
      const id = index.toString(16).padStart(64, '0');
      await rows.insertOne({ _id: id, id, ...input, displayName, status: 'pending', createdAt: 1000, notifyAt: 1000 });
      await request(app).post('/decide').send({ id, status: 'approved', providerOrganizationId: 'org_firm', actor: 'staff' }).expect(409);
      expect(await rows.findOne({ _id: id })).toMatchObject({ status: 'pending' });
      expect(await rows.findOne({ _id: id })).not.toHaveProperty('decidedAt');
      expect(await store.getLegalOrganizationRecord(id)).toBeNull();
    }
    expect(await store.listLegalOrganizationRecords()).toEqual([]);
    expect(await client.db('applications').collection('confidential_legal_audit').countDocuments()).toBe(0);
    // Invalid attempts reserved no claims: a valid application for the same firm works.
    await request(app).post('/submit').send({ ...input, displayName: '  Example   Counsel  ' }).expect(202);
    const valid = (await service.list()).applications[0];
    await request(app).post('/decide').send({ id: valid.id, status: 'approved', providerOrganizationId: 'org_firm', actor: 'staff' }).expect(200);
    expect(projectLegalOrganization(await store.getLegalOrganizationRecord(valid.id)))
      .toMatchObject({ displayName: 'Example Counsel', status: 'awaiting-registration' });
    expect(await service.approveAndPrepare(valid.id, 'org_firm', 'retry', store)).toBe(true);
  });
  it('returns the original decision actor through the API for duplicate and conflicting Slack clicks', async () => {
    const app = express();
    app.use(createLegalApplicationsRouter(async () => service, (_req, _res, next) => next(), async () => store));
    await service.submit(input);
    const id = (await service.list()).applications[0].id;
    const first = await request(app).post('/decide').send({ id, status: 'approved', actor: 'slack:T123:U123' }).expect(200);
    expect(first.body.decision).toMatchObject({ id, status: 'approved', decidedBy: 'slack:T123:U123' });
    for (const status of ['approved', 'denied']) {
      const repeated = await request(app).post('/decide').send({ id, status, actor: 'slack:T123:U456' }).expect(status === 'approved' ? 200 : 409);
      expect(repeated.body.decision).toEqual(first.body.decision);
    }
    expect(await store.listLegalOrganizationRecords()).toEqual([]);
  });
  it('persists application before delivery, leases concurrent workers and retries failure', async () => {
    await service.submit(input, 1000);
    const failed = jest.fn(async () => false);
    expect(await service.deliverOne(failed, 1000)).toBe(true);
    expect(await service.deliverOne(failed, 2000)).toBe(false);
    const accepted = jest.fn(async () => true);
    await Promise.all([service.deliverOne(accepted, 301_000), service.deliverOne(accepted, 301_000)]);
    expect(accepted).toHaveBeenCalledTimes(1);
    expect(await service.deliverOne(accepted, 1_000_000)).toBe(false);
  });
  it('lists bounded projections without outbox internals', async () => {
    await Promise.all(Array.from({ length: 51 }, () => service.submit(input, 1000)));
    await service.submit(input, 2000);
    const first = await service.list(); expect(first.applications).toHaveLength(50); expect(first.next).toBeTruthy();
    expect(first.applications[0].createdAt).toBe(2000);
    expect(first.applications[0]).not.toHaveProperty('notifyAt'); expect(first.applications[0]).not.toHaveProperty('_id');
    const second = await service.list(first.next!);
    expect(second.applications).toHaveLength(2); expect(second.next).toBeNull();
    expect(new Set([...first.applications, ...second.applications].map(row => row.id)).size).toBe(52);
  });
  it('queues only approved applications and provisions once across workers and decision replays', async () => {
    await service.submit(input, 1000);
    const id = (await service.list()).applications[0].id;
    const provision = jest.fn(async () => 'org_created');
    expect(await service.provisionOne(provision, 1000)).toBe(false);
    await service.decide(id, 'approved', 'admin', 2000);
    await Promise.all([service.provisionOne(provision, 2000), service.provisionOne(provision, 2000)]);
    expect(provision).toHaveBeenCalledTimes(1);
    expect((await service.list()).applications[0]).toMatchObject({ provisioningStatus: 'ready', providerOrganizationId: 'org_created', organizationId: id });
    await service.decide(id, 'approved', 'replay', 3000);
    expect(await service.provisionOne(provision, 100_000)).toBe(false);
    await service.submit({ ...input, domain: 'denied.example', email: 'lawyer@denied.example' });
    const denied = (await service.list()).applications.find(row => row.status === 'pending')!;
    await service.decide(denied.id, 'denied', 'admin', 2000);
    expect(await service.provisionOne(provision, 100_000)).toBe(false);
  });
  it('retains failures across service restarts without exposing provider error details', async () => {
    await service.submit(input, 1000);
    const id = (await service.list()).applications[0].id;
    await service.decide(id, 'approved', 'admin', 2000);
    await service.provisionOne(async () => { throw new Error('private-token'); }, 2000);
    expect((await service.list()).applications[0].provisioningStatus).toBe('retrying');
    expect(JSON.stringify(await service.list())).not.toContain('private-token');
    const restarted = await LegalApplications.fromDatabase(client.db('applications'));
    const provision = jest.fn(async () => 'org_created');
    expect(await restarted.provisionOne(provision, 301_999)).toBe(false);
    expect(await restarted.provisionOne(provision, 302_000)).toBe(true);
    expect((await service.list()).applications[0].provisioningStatus).toBe('ready');
  });
  it('fences an expired worker so its failure cannot undo a newer successful attempt', async () => {
    await service.submit(input, 1000);
    await service.decide((await service.list()).applications[0].id, 'approved', 'admin', 2000);
    let rejectOld!: (reason: Error) => void, claimed!: () => void;
    const entered = new Promise<void>(resolve => { claimed = resolve; });
    const old = service.provisionOne(() => { claimed(); return new Promise<string>((_resolve, reject) => { rejectOld = reject; }); }, 2000);
    await entered;
    expect(await service.provisionOne(async () => 'org_created', 62_000)).toBe(true);
    rejectOld(new Error('stale worker'));
    await old;
    expect((await service.list()).applications[0]).toMatchObject({ provisioningStatus: 'ready', providerOrganizationId: 'org_created' });
  });
  it('allows only one approved application per domain, even with concurrent decisions', async () => {
    await service.submit(input, 1000); await service.submit(input, 1000);
    const rows = (await service.list()).applications;
    const decisions = await Promise.all(rows.map(row => service.decide(row.id, 'approved', 'admin', 2000)));
    expect(decisions.filter(Boolean)).toHaveLength(1);
    expect((await service.list()).applications.filter(row => row.status === 'pending')).toHaveLength(1);
  });
  it('expires pending and denied applicant records after 180 days and retains approved provenance', async () => {
    const rows = client.db('applications').collection<any>('legal_applications');
    const day = 24 * 60 * 60 * 1000;
    expect(LEGAL_APPLICATION_RETENTION_MS).toBe(180 * day);
    const indexes = await rows.indexes();
    expect(indexes.find(index => index.name === 'legal_application_retention')).toMatchObject({ key: { expiresAt: 1 }, expireAfterSeconds: 0 });
    expect(indexes.find(index => index.name === 'one_approved_application_per_domain')).toMatchObject({ unique: true });
    await service.submit(input, 1000);
    await service.submit({ ...input, domain: 'denied.example', email: 'a@denied.example' }, 1000);
    await service.submit({ ...input, domain: 'pending.example', email: 'a@pending.example' }, 1000);
    const byDomain = async (domain: string) => rows.findOne({ domain });
    expect((await byDomain('pending.example')).expiresAt).toEqual(new Date(1000 + 180 * day));
    const approved = (await byDomain(input.domain)).id, denied = (await byDomain('denied.example')).id;
    expect(await service.decide(approved, 'approved', 'staff', 5000)).toBe(true);
    expect(await service.decide(denied, 'denied', 'staff', 7000)).toBe(true);
    expect(await byDomain(input.domain)).not.toHaveProperty('expiresAt');
    expect((await byDomain('denied.example')).expiresAt).toEqual(new Date(7000 + 180 * day));
    // A repeated or conflicting decision cannot restart or remove the retention clock.
    expect(await service.decide(denied, 'denied', 'replay', 9000)).toBe(true);
    expect(await service.decide(denied, 'approved', 'other', 9000)).toBe(false);
    expect((await byDomain('denied.example')).expiresAt).toEqual(new Date(7000 + 180 * day));
    // Provisioning completion keeps approved provenance indefinitely.
    await service.provisionOne(async () => 'org_created', 6000);
    expect(await byDomain(input.domain)).toMatchObject({ provisioningStatus: 'ready' });
    expect(await byDomain(input.domain)).not.toHaveProperty('expiresAt');
    expect((await service.get(approved))).not.toHaveProperty('expiresAt');
  });
  it('backfills retention for rows written before the policy and the TTL monitor purges due rows', async () => {
    const rows = client.db('applications').collection<any>('legal_applications');
    const day = 24 * 60 * 60 * 1000, now = Date.now();
    const legacy = (n: number, row: Record<string, unknown>) => ({ _id: n.toString(16).padStart(64, '0'), id: n.toString(16).padStart(64, '0'),
      ...input, domain: `legacy${n}.example`, email: `a@legacy${n}.example`, notifyAt: 0, ...row });
    await rows.insertMany([
      legacy(1, { status: 'pending', createdAt: now - 200 * day }),
      legacy(2, { status: 'denied', createdAt: now - 400 * day, decidedAt: now - 10 * day, decidedBy: 'staff' }),
      legacy(3, { status: 'approved', createdAt: now - 400 * day, decidedAt: now - 399 * day, decidedBy: 'staff', provisioningStatus: 'ready' }),
      legacy(4, { status: 'approved', createdAt: now - 400 * day, decidedAt: now - 399 * day, decidedBy: 'staff', expiresAt: new Date(0) }),
      legacy(5, { status: 'pending', createdAt: now - 1 * day, expiresAt: new Date(now + 5 * day) }),
    ]);
    await LegalApplications.fromDatabase(client.db('applications'));
    // Idempotent for concurrently starting processes.
    await LegalApplications.fromDatabase(client.db('applications'));
    const expires = async (n: number) => (await rows.findOne({ _id: legacy(n, {})._id }))?.expiresAt;
    expect(await expires(1)).toEqual(new Date(now - 20 * day));
    expect(await expires(2)).toEqual(new Date(now + 170 * day));
    expect(await expires(3)).toBeUndefined();
    expect(await expires(4)).toBeUndefined();
    expect(await expires(5)).toEqual(new Date(now + 5 * day));
    await client.db('admin').command({ setParameter: 1, ttlMonitorSleepSecs: 1 });
    try {
      for (let attempt = 0; attempt < 100 && await rows.countDocuments({ _id: legacy(1, {})._id }); attempt++) await new Promise(resolve => setTimeout(resolve, 200));
    } finally { await client.db('admin').command({ setParameter: 1, ttlMonitorSleepSecs: 60 }); }
    expect((await rows.find({}, { projection: { _id: 1 } }).toArray()).map(row => row._id).sort()).toEqual([2, 3, 4, 5].map(n => legacy(n, {})._id));
  });
  it('persists safe failure codes and emits only fenced outcomes, clearing the error after recovery', async () => {
    await service.submit(input, 1000);
    const id = (await service.list()).applications[0].id;
    await service.decide(id, 'approved', 'admin', 2000);
    const outcome = jest.fn();
    await service.provisionOne(async () => { throw new LegalProvisioningError('roster_conflict'); }, 2000, outcome);
    expect(await service.get(id)).toMatchObject({ provisioningStatus: 'retrying', provisioningError: 'roster_conflict' });
    expect(outcome).toHaveBeenLastCalledWith({ applicationId: id, status: 'retrying', error: 'roster_conflict' });
    await service.provisionOne(async () => 'org_created', 302000, outcome);
    expect(await service.get(id)).not.toHaveProperty('provisioningError');
    expect(outcome).toHaveBeenLastCalledWith({ applicationId: id, status: 'ready' });
    expect(JSON.stringify(outcome.mock.calls)).not.toContain(input.email);
  });
});
