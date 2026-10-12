import { MongoClient, Db } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { Auth0LegalApplications, applicationIntakeLimits } from '../../../src/services/auth0LegalApplications';
import { LegalProvisioningError } from '../../../src/utils/legalApplications';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { LEGAL_APPLICATION_RETENTION_MS } from '../../../src/services/legalApplications';
import type { ApplicationOrganization, ApplicationOrganizations } from '../../../src/services/legalApplicationOrganizations';
import { applicationOrganizationId, applicationReviewDigest } from '../../../src/utils/legalApplicationEnrollment';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { createHash } from 'node:crypto';

const input = { displayName: 'Murphy Law', domain: 'firm.example', email: 'lawyer@firm.example',
  lawyerName: 'Example Lawyer', jurisdiction: 'NC', registrationNumber: 'TEST123' };
const clone = <T>(value: T): T => structuredClone(value);
describe('Auth0 owns pending, approved and denied applications', () => {
  let server: MongoMemoryReplSet, client: MongoClient, db: Db, service: Auth0LegalApplications;
  let organizations: Map<string, ApplicationOrganization>, directory: ApplicationOrganizations;
  let sequence = 0, created = 0;
  beforeAll(async () => {
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } }); client = await MongoClient.connect(server.getUri());
  });
  afterAll(async () => { await client?.close(); await server?.stop(); });
  beforeEach(async () => {
    db = client.db(`auth0_applications_${++sequence}`); organizations = new Map();
    directory = {
      get: jest.fn(async name => clone([...organizations.values()].find(org => org.name === name) ?? null)),
      getById: jest.fn(async id => clone(organizations.get(id) ?? null)),
      // Mirrors the real directory: ten pages of 100, failing closed on the tenth full page.
      list: jest.fn(async () => {
        if (organizations.size >= 1000) throw new LegalProvisioningError('lookup_limit');
        return clone([...organizations.values()]);
      }),
      create: jest.fn(async value => {
        const org = { ...clone(value), id: `org_test${++created}` }; organizations.set(org.id, org); return clone(org);
      }),
      update: jest.fn(async value => {
        if (!organizations.has(value.id)) throw new Error('Not found');
        expect(Object.keys(value.metadata).length).toBeLessThanOrEqual(25);
        expect(Object.values(value.metadata).every(item => item.length <= 255)).toBe(true);
        organizations.set(value.id, clone(value));
      }),
      remove: jest.fn(async id => { organizations.delete(id); }),
    };
    service = await Auth0LegalApplications.fromDatabase(db, directory);
  });
  async function submit(extra = {}) {
    const previous = new Set([...organizations.values()].map(org => org.metadata.vera_application_id));
    await service.submit({ ...input, ...extra });
    return (await service.list()).applications.find(row => !previous.has(row.id))!;
  }
  it('stores application details and denial in Auth0, with no Mongo application row or contact/decision copy', async () => {
    const row = await submit();
    expect([...organizations.values()][0].metadata).toMatchObject({ vera_approval_status: 'pending', vera_email: input.email,
      vera_display_name: input.displayName, vera_domain: input.domain, vera_application_id: row.id });
    expect(await service.decide(row.id, 'denied', 'reviewer')).toBe(true);
    expect(await service.get(row.id)).toMatchObject({ status: 'denied', decidedBy: 'reviewer' });
    expect(await service.decide(row.id, 'approved', 'other')).toBe(false);
    expect(await db.collection('legal_applications').countDocuments()).toBe(0);
    const work = await db.collection('legal_application_work').findOne({});
    expect(work).not.toHaveProperty('email'); expect(work).not.toHaveProperty('status'); expect(work).not.toHaveProperty('domain');
  });
  it('does not allow a deleted Auth0 organization or historical Mongo approval to reserve the domain', async () => {
    const old = await submit(); await service.decide(old.id, 'approved', 'reviewer');
    const stale = clone([...organizations.values()][0]);
    await db.collection('legal_applications').insertOne({ ...input, id: old.id, status: 'approved', createdAt: Date.now() });
    organizations.clear();
    expect(await service.get(old.id)).toBeNull(); expect(await service.decide(old.id, 'approved', 'reviewer')).toBe(false);
    const replacement = await submit({ displayName: 'Murphy Law New' });
    // Even a stale directory listing is not evidence that the old org exists.
    const live = [...organizations.values()][0];
    live.id = 'org_replacement'; organizations.clear(); organizations.set(live.id, live);
    jest.mocked(directory.list).mockResolvedValue([stale, clone(live)]);
    expect(await service.decide(replacement.id, 'approved', 'reviewer')).toBe(true);
    expect(await service.get(replacement.id)).toMatchObject({ status: 'approved' });
  });
  it('still prevents a second approved organization for a domain that exists in Auth0', async () => {
    const first = await submit(); await service.decide(first.id, 'approved', 'reviewer');
    const second = await submit({ displayName: 'Second Firm' });
    expect(await service.decide(second.id, 'approved', 'reviewer')).toBe(false);
    expect(await service.get(second.id)).toMatchObject({ status: 'pending' });
  });
  it('treats an approved organization from before application records as approved', async () => {
    organizations.set('org_legacy', { id: 'org_legacy', name: 'vera-legal-legacy', display_name: 'Legacy Firm',
      metadata: { vera_application_id: 'e'.repeat(64), vera_domain: input.domain } });
    const second = await submit({ displayName: 'Second Firm' });
    expect(await service.decide(second.id, 'approved', 'reviewer')).toBe(false);
    expect(await service.get(second.id)).toMatchObject({ status: 'pending' });
  });
  it('imports an approved record into its matching organization from before application records', async () => {
    const id = 'd'.repeat(64), now = Date.now();
    organizations.set('org_legacy', { id: 'org_legacy', name: `vera-legal-${id.slice(0, 32)}`, display_name: input.displayName,
      metadata: { vera_application_id: id, vera_domain: input.domain } });
    await db.collection('legal_applications').insertOne({ ...input, id, status: 'approved', createdAt: now, decidedAt: now,
      decidedBy: 'reviewer', providerOrganizationId: 'org_legacy' });
    const restarted = await Auth0LegalApplications.fromDatabase(db, directory);
    expect(await restarted.get(id)).toMatchObject({ status: 'approved', decidedBy: 'reviewer' });
    expect(organizations.get('org_legacy')!.metadata).toMatchObject({ vera_approval_status: 'approved', vera_application_id: id });
  });
  it('serializes opposing decisions across service instances and preserves the recorded actor/time', async () => {
    const row = await submit(); const other = await Auth0LegalApplications.fromDatabase(db, directory);
    const outcomes = await Promise.allSettled([service.decide(row.id, 'approved', 'first'), other.decide(row.id, 'denied', 'second')]);
    expect(outcomes.filter(outcome => outcome.status === 'fulfilled' && outcome.value)).toHaveLength(1);
    const saved = await service.get(row.id);
    expect(await service.decide(row.id, saved!.status as 'approved' | 'denied', 'retry')).toBe(true);
    expect((await service.get(row.id))!.decidedBy).toBe(saved!.decidedBy);
  });
  it('handles simultaneous decisions for different domains without losing either click', async () => {
    const first = await submit();
    const second = await submit({ domain: 'other.example', email: 'lawyer@other.example' });
    const other = await Auth0LegalApplications.fromDatabase(db, directory);
    expect(await Promise.all([service.decide(first.id, 'approved', 'first'), other.decide(second.id, 'denied', 'second')])).toEqual([true, true]);
    expect(await service.get(second.id)).toMatchObject({ status: 'denied' });
  });
  it('allows only one winner when two applications for the same domain are approved concurrently', async () => {
    const first = await submit(), second = await submit({ displayName: 'Second Firm' });
    const other = await Auth0LegalApplications.fromDatabase(db, directory);
    const decisions = await Promise.all([service.decide(first.id, 'approved', 'first'), other.decide(second.id, 'approved', 'second')]);
    expect(decisions.sort()).toEqual([false, true]);
  });
  it('labels a decision that waited out a held organization lock as lock_wait', async () => {
    const row = await submit(); const org = [...organizations.values()][0];
    await db.collection('legal_auth0_membership_locks').insertOne({ _id: org.id as any, lease: 'held', until: Date.now() + 60_000 });
    await expect(service.decide(row.id, 'approved', 'reviewer')).rejects.toMatchObject({ code: 'provider_unavailable', detail: 'lock_wait' });
    expect(await service.get(row.id)).toMatchObject({ status: 'pending' });
  }, 20_000);
  it('fails closed on Auth0 failure, even when Mongo says the application is approved', async () => {
    const row = await submit(); await service.decide(row.id, 'approved', 'reviewer');
    jest.mocked(directory.get).mockRejectedValue(new Error('Auth0 unavailable'));
    await expect(service.get(row.id)).rejects.toThrow('Auth0 unavailable');
    await expect(service.decide(row.id, 'approved', 'reviewer')).rejects.toThrow('Auth0 unavailable');
  });
  it('keeps unrelated metadata and membership hints when updating approval and provisioning', async () => {
    const row = await submit(); const org = [...organizations.values()][0];
    org.metadata.external = 'keep'; org.metadata.vera_entry_test = 'keep';
    await service.decide(row.id, 'approved', 'reviewer');
    await service.provisionOne(async () => org.id);
    expect(await service.get(row.id)).toMatchObject({ status: 'approved', provisioningStatus: 'ready', providerOrganizationId: org.id });
    expect(organizations.get(org.id)!.metadata).toMatchObject({ external: 'keep', vera_entry_test: 'keep' });
    expect(organizations.get(org.id)!.metadata).not.toHaveProperty('vera_expires_at');
  });
  it('does not deliver or provision an application removed from Auth0', async () => {
    await submit(); organizations.clear(); const deliver = jest.fn(), provision = jest.fn();
    await service.deliverOne(deliver); await service.provisionOne(provision);
    expect(deliver).not.toHaveBeenCalled(); expect(provision).not.toHaveBeenCalled();
  });
  it('migrates pending/denied records, while an approved record needs its matching live Auth0 organization', async () => {
    const now = Date.now();
    await db.collection('legal_applications').insertMany([
      { ...input, id: 'a'.repeat(64), status: 'pending', createdAt: now },
      { ...input, id: 'b'.repeat(64), status: 'denied', createdAt: now, decidedAt: now, decidedBy: 'reviewer' },
      { ...input, id: 'c'.repeat(64), status: 'approved', createdAt: now, providerOrganizationId: 'org_deleted' },
    ]);
    const restarted = await Auth0LegalApplications.fromDatabase(db, directory);
    expect((await restarted.list()).applications.map(row => row.status).sort()).toEqual(['denied', 'pending']);
    expect(await restarted.get('c'.repeat(64))).toBeNull();
    await restarted.decide('a'.repeat(64), 'denied', 'new-reviewer');
    await Auth0LegalApplications.fromDatabase(db, directory);
    expect(await restarted.get('a'.repeat(64))).toMatchObject({ status: 'denied', decidedBy: 'new-reviewer' });
    organizations.clear();
    await Auth0LegalApplications.fromDatabase(db, directory);
    expect(organizations.size).toBe(0);
  });
  it('does not fall back to the legacy database if Auth0 is unconfigured', async () => {
    await db.collection('legal_applications').insertOne({ ...input, id: 'a'.repeat(64), status: 'approved', createdAt: Date.now() });
    const unavailable = await Auth0LegalApplications.fromDatabase(db, null);
    await expect(unavailable.get('a'.repeat(64))).rejects.toMatchObject({ code: 'provider_configuration' });
    await expect(unavailable.submit(input)).rejects.toMatchObject({ code: 'provider_configuration' });
  });
  it('retires a stale cryptographic domain claim only after an explicit Auth0 404', async () => {
    const store = await MongoConfidentialCaseStore.fromDatabase(db, client, directory);
    await store.createLegalOrganization({ ...input, organizationId: 'd'.repeat(64), providerOrganizationId: 'org_deleted' }, 'reviewer', Date.now());
    jest.mocked(directory.getById).mockRejectedValueOnce(new Error('outage'));
    await expect(store.retireDeletedLegalOrganizations(input.domain, directory, AbortSignal.timeout(5000))).rejects.toThrow('outage');
    expect(await store.getLegalOrganizationRecord('d'.repeat(64))).not.toHaveProperty('revokedAt');
    await store.retireDeletedLegalOrganizations(input.domain, directory, AbortSignal.timeout(5000));
    expect(await store.getLegalOrganizationRecord('d'.repeat(64))).toHaveProperty('revokedAt');
    await expect(store.createLegalOrganization({ ...input, organizationId: 'e'.repeat(64), providerOrganizationId: 'org_new' }, 'reviewer', Date.now())).resolves.toBeUndefined();
  });
  it('retains approved records while deleting expired pending/denied Auth0 application records', async () => {
    const now = Date.now(), old = now - LEGAL_APPLICATION_RETENTION_MS - 1;
    await service.submit(input, old);
    expect((await service.list()).applications).toEqual([]);
    await service.provisionOne(jest.fn(), now);
    expect(organizations.size).toBe(0); expect(directory.remove).toHaveBeenCalledTimes(1);
    const approved = await submit(); await service.decide(approved.id, 'approved', 'reviewer');
    await service.provisionOne(async row => row.providerOrganizationId!, now + LEGAL_APPLICATION_RETENTION_MS + 1000);
    expect(await service.get(approved.id)).toMatchObject({ status: 'approved' });
  });
  it('pins the signed key artifact in Auth0 and rejects changed details, key substitution and deleted-key replay', async () => {
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic test' }], format: 'object' });
    const recipientKeyId = createHash('sha256').update(privateKey.toPublic().write()).digest('hex');
    const id = await applicationOrganizationId(recipientKeyId);
    const bindingDocument = await createFirmKeyBinding({ organizationId: id, domain: input.domain, issuedAt: Date.now(),
      profile: { practiceAreas: ['whistleblower'], jurisdiction: input.jurisdiction, website: 'https://firm.example/', contacts: { email: input.email } } }, privateKey);
    const submission = { ...input, enrollment: { organizationId: id, recipientKeyId, bindingDocument } };
    await service.submit(submission); await service.submit(submission);
    const row = (await service.get(id))!, digest = await applicationReviewDigest(row);
    const org = [...organizations.values()][0];
    expect(await service.decide(id, 'approved', 'slack:T123:U123', Date.now(), digest, 'a'.repeat(64))).toBe(false);
    org.metadata.vera_lawyer_name = 'Changed';
    expect(await service.decide(id, 'approved', 'slack:T123:U123', Date.now(), digest, recipientKeyId)).toBe(false);
    org.metadata.vera_lawyer_name = input.lawyerName;
    expect(await service.decide(id, 'approved', 'slack:T123:U123', Date.now(), digest, recipientKeyId)).toBe(true);
    await service.provisionOne(async () => org.id);
    expect(await service.applicationStatus(id)).toMatchObject({ state: 'sign-in-ready' });
    expect(await service.saveCombinedApproval(id, digest, 'signed-certificate')).toBe(true);
    expect(await service.applicationStatus(id)).toMatchObject({ state: 'ready' });
    organizations.clear();
    expect(await service.getCombinedApproval(id)).toBeNull();
    await expect(service.submit(submission)).rejects.toThrow('Application removed');
    expect(await service.applicationStatus(id)).toEqual({ state: 'unavailable' });
  });
  const firm = (index: number) => ({ domain: `firm${index}.example`, email: `lawyer@firm${index}.example` });
  const work = () => db.collection('legal_application_work');
  it('bounds the tenant-wide cap to a safe default and maximum', () => {
    expect(applicationIntakeLimits(undefined)).toEqual({ pending: 300, domainPending: 3 });
    for (const [value, pending] of [['', 300], ['abc', 300], ['0', 300], ['1.5', 300], ['-4', 300], ['120', 120], ['600', 600], ['5000', 600]] as const)
      expect(applicationIntakeLimits(value).pending).toBe(pending);
  });
  it('refuses a fourth pending application for a domain until one is decided, without creating anything', async () => {
    const rows = [await submit(), await submit(), await submit()];
    await expect(service.submit(input)).rejects.toMatchObject({ code: 'domain-applications-pending' });
    expect(organizations.size).toBe(3); expect(await work().countDocuments()).toBe(3);
    await expect(service.submit({ ...input, ...firm(1) })).resolves.toBeUndefined();
    expect(await service.decide(rows[0].id, 'denied', 'reviewer')).toBe(true);
    await expect(service.submit(input)).resolves.toBeUndefined();
    await expect(service.submit(input)).rejects.toMatchObject({ code: 'domain-applications-pending' });
  });
  it('does not count expired pending applications toward either cap', async () => {
    const limited = await Auth0LegalApplications.fromDatabase(db, directory, { pending: 2, domainPending: 3 });
    const old = Date.now() - LEGAL_APPLICATION_RETENTION_MS - 1;
    for (let i = 0; i < 3; i++) await service.submit(input, old);
    await service.submit({ ...input, ...firm(1) }, old);
    await expect(limited.submit(input)).resolves.toBeUndefined();
    await expect(limited.submit({ ...input, ...firm(2) })).resolves.toBeUndefined();
    await expect(limited.submit({ ...input, ...firm(3) })).rejects.toMatchObject({ code: 'applications-closed' });
  });
  it('closes intake tenant-wide at the pending cap and reopens once applications are decided', async () => {
    const limited = await Auth0LegalApplications.fromDatabase(db, directory, { pending: 4, domainPending: 3 });
    for (let i = 0; i < 4; i++) await limited.submit({ ...input, ...firm(i) });
    await expect(limited.submit({ ...input, ...firm(9) })).rejects.toMatchObject({ code: 'applications-closed' });
    expect(organizations.size).toBe(4); expect(await work().countDocuments()).toBe(4);
    const [approved, denied] = (await limited.list()).applications;
    expect(await limited.decide(approved.id, 'approved', 'reviewer')).toBe(true);
    await limited.submit({ ...input, ...firm(9) });
    await expect(limited.submit({ ...input, ...firm(10) })).rejects.toMatchObject({ code: 'applications-closed' });
    expect(await limited.decide(denied.id, 'denied', 'reviewer')).toBe(true);
    await expect(limited.submit({ ...input, ...firm(10) })).resolves.toBeUndefined();
  });
  it('lets two concurrent submissions at one below the cap admit at most one', async () => {
    const limited = await Auth0LegalApplications.fromDatabase(db, directory, { pending: 2, domainPending: 3 });
    await limited.submit({ ...input, ...firm(0) });
    const outcomes = await Promise.allSettled([limited.submit({ ...input, ...firm(1) }), limited.submit({ ...input, ...firm(2) })]);
    expect(outcomes.filter(outcome => outcome.status === 'fulfilled').length).toBeLessThanOrEqual(1);
    expect(organizations.size).toBeLessThanOrEqual(2);
  });
  it('reopens intake when a counted organization was deleted directly in Auth0, and stays closed if the directory cannot be listed', async () => {
    const limited = await Auth0LegalApplications.fromDatabase(db, directory, { pending: 2, domainPending: 3 });
    const earlier = Date.now() - 300_000;
    await limited.submit({ ...input, ...firm(0) }, earlier); await limited.submit({ ...input, ...firm(1) }, earlier);
    organizations.delete([...organizations.keys()][0]);
    jest.mocked(directory.list).mockRejectedValueOnce(new LegalProvisioningError('lookup_limit'));
    await expect(limited.submit({ ...input, ...firm(2) })).rejects.toMatchObject({ code: 'applications-closed' });
    // Reconciliation runs at most once a minute; a later attempt after the window succeeds.
    await expect(limited.submit({ ...input, ...firm(2) })).rejects.toMatchObject({ code: 'applications-closed' });
    await db.collection('legal_auth0_membership_locks').updateOne({ _id: 'application-intake-reconcile' as any }, { $set: { until: 0 } });
    await expect(limited.submit({ ...input, ...firm(2) })).resolves.toBeUndefined();
    await expect(limited.submit({ ...input, ...firm(3) })).rejects.toMatchObject({ code: 'applications-closed' });
  });
  it('clears the counter when the worker finds a pending organization missing or expired', async () => {
    const limited = await Auth0LegalApplications.fromDatabase(db, directory, { pending: 1, domainPending: 3 });
    await limited.submit({ ...input, ...firm(0) });
    organizations.clear();
    await limited.provisionOne(jest.fn());
    await expect(limited.submit({ ...input, ...firm(1) })).resolves.toBeUndefined();
    expect(await work().countDocuments({ pendingUntil: { $exists: true } })).toBe(1);
  });
  it('does not let the workers consume an application before its Auth0 organization exists', async () => {
    const deliver = jest.fn(async () => true), provision = jest.fn();
    jest.mocked(directory.create).mockImplementationOnce(async value => {
      expect(await service.deliverOne(deliver)).toBe(false);
      expect(await service.provisionOne(provision)).toBe(false);
      const org = { ...clone(value), id: `org_test${++created}` }; organizations.set(org.id, org); return clone(org);
    });
    await service.submit(input);
    expect(await service.deliverOne(deliver)).toBe(true);
    expect(deliver).toHaveBeenCalledTimes(1);
    expect(await work().countDocuments({ pendingUntil: { $exists: true } })).toBe(1);
  });
  it('does not reopen intake at the total cap when a pending application is denied', async () => {
    const row = await submit();
    for (let i = 0; i < 899; i++) organizations.set(`org_retained${i}`, {
      id: `org_retained${i}`, name: `retained-${i}`,
      metadata: { vera_approval_status: 'denied', vera_domain: `retained${i}.example` },
    });
    expect(await service.decide(row.id, 'denied', 'reviewer')).toBe(true);
    expect(await work().countDocuments({ pendingUntil: { $exists: true } })).toBe(0);
    await expect(service.submit({ ...input, ...firm(9) })).rejects.toMatchObject({ code: 'applications-closed' });
    expect(organizations.size).toBe(900);
    expect(await work().countDocuments()).toBe(1);
  });
  it('serializes total-cap admission across service instances', async () => {
    for (let i = 0; i < 899; i++) organizations.set(`org_existing${i}`, {
      id: `org_existing${i}`, name: `existing-${i}`, metadata: {},
    });
    const second = await Auth0LegalApplications.fromDatabase(db, directory);
    const outcomes = await Promise.allSettled([
      service.submit({ ...input, ...firm(1) }), second.submit({ ...input, ...firm(2) }),
    ]);
    expect(outcomes.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter(result => result.status === 'rejected')).toHaveLength(1);
    expect(organizations.size).toBe(900);
  });
  it('does not create an organization when the directory is unavailable or already truncated', async () => {
    jest.mocked(directory.list).mockRejectedValueOnce(new Error('provider outage'));
    await expect(service.submit(input)).rejects.toThrow();
    expect(directory.create).not.toHaveBeenCalled();
    jest.mocked(directory.list).mockRejectedValueOnce(new LegalProvisioningError('lookup_limit'));
    await expect(service.submit({ ...input, ...firm(2) })).rejects.toMatchObject({ code: 'applications-closed' });
    expect(directory.create).not.toHaveBeenCalled();
  });
  it('approves and signs in with the directory one organization below the listing ceiling', async () => {
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic test' }], format: 'object' });
    const recipientKeyId = createHash('sha256').update(privateKey.toPublic().write()).digest('hex');
    const id = await applicationOrganizationId(recipientKeyId);
    const bindingDocument = await createFirmKeyBinding({ organizationId: id, domain: input.domain, issuedAt: Date.now(),
      profile: { practiceAreas: ['whistleblower'], jurisdiction: input.jurisdiction, website: 'https://firm.example/', contacts: { email: input.email } } }, privateKey);
    await service.submit({ ...input, enrollment: { organizationId: id, recipientKeyId, bindingDocument } });
    for (let i = 0; i < 998; i++) organizations.set(`org_seed${i}`, { id: `org_seed${i}`, name: `seed-${i}`,
      metadata: { vera_application_id: i.toString(16).padStart(64, '0'), vera_domain: `seed${i}.example` } });
    expect(organizations.size).toBe(999);
    await expect(service.submit({ ...input, ...firm(999) })).rejects.toMatchObject({ code: 'applications-closed' });
    const digest = await applicationReviewDigest((await service.get(id))!);
    expect(await service.decide(id, 'approved', 'reviewer', Date.now(), digest, recipientKeyId)).toBe(true);
    const org = [...organizations.values()].find(row => row.metadata.vera_application_id === id)!;
    await service.provisionOne(async () => org.id);
    expect(await service.firstSignInApproved(id, input.email)).toBe(true);
    expect((await service.list()).applications.map(row => row.id)).toEqual([id]);
    // The ceiling itself still fails closed rather than trusting a partial listing.
    organizations.set('org_seed_last', { id: 'org_seed_last', name: 'seed-last', metadata: {} });
    await expect(service.list()).rejects.toMatchObject({ code: 'lookup_limit' });
  });
});
