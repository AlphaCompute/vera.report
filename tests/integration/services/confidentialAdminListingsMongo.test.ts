import { webcrypto } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { listConfidentialAdminListings } from '../../../src/services/confidentialAdminListings';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';

const hex = (n: number) => n.toString(16).padStart(64, '0');

describe('admin confidential listings read from MongoDB', () => {
  let server: MongoMemoryReplSet, client: MongoClient, store: MongoConfidentialCaseStore;
  const now = Date.now();

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(server.getUri());
    store = await MongoConfidentialCaseStore.fromDatabase(client.db('test_confidential_admin'), client);
  }, 120_000);
  afterAll(async () => { await client?.close(); await server?.stop(); });

  async function publish(summary: string | null) {
    const owner = await createCaseOwner(), trust = owner.trust;
    const signed = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner.privateKey);
      return { wire, ...await verifyOwnerStatement(wire, trust) };
    };
    const listing = summary === null ? null : await signed({ kind: 'listing', caseId: trust.caseId, revision: 1, summary });
    const grant = await signed({ kind: 'grant', caseId: trust.caseId, revision: 1, grantId: hex(1), organizationId: hex(2),
      recipientKeyId: hex(3), scopes: ['narrative'], keyEpoch: 1, objectRevisionLimit: null, issuedAt: now, expiresAt: now + 60_000 });
    const manifest = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 1, objects: [] });
    const checkpoint = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
      listingDigest: listing?.digest ?? null, manifestDigest: manifest.digest, grantDigests: [grant.digest], releaseDigests: [], issuedAt: now });
    await store.createCase({ caseId: trust.caseId, ownerPublicKey: trust.ownerPublicKey.armor(), ownerFingerprint: trust.ownerFingerprint,
      statements: { ...(listing ? { [listing.digest]: listing.wire } : {}), [grant.digest]: grant.wire, [manifest.digest]: manifest.wire },
      checkpoints: [checkpoint.wire], currentCheckpointDigest: checkpoint.digest, listingDigest: listing?.digest ?? null,
      recoveryPackage: 'ENCRYPTED-RECOVERY-PACKAGE', createdAt: now });
    await store.putAccessRequest({ caseId: trust.caseId, organizationId: hex(2), requestId: hex(4), ciphertext: 'REQUEST-CIPHERTEXT',
      recipientKeyId: hex(3), expiresAt: now + 60_000, state: 'pending', createdAt: now });
    return trust.caseId;
  }

  test('projects only the listing wire per case and pages in case-ID order', async () => {
    const listed = await Promise.all(['First summary', 'Second summary', 'Third summary'].map(publish));
    const unlisted = await publish(null);
    const rows = await store.listListingWires(100, null);
    // The database projection returns one statement wire, never the case's other
    // statements, checkpoints, envelopes, recovery package or request rows.
    expect(rows.map(row => row.caseId)).toEqual([...listed].sort());
    for (const row of rows) {
      expect(Object.keys(row).sort()).toEqual(['caseId', 'listingDigest', 'listingWire', 'ownerFingerprint', 'ownerPublicKey']);
      expect(JSON.parse(row.listingWire!).statement.kind).toBe('listing');
    }
    expect(JSON.stringify(rows)).not.toMatch(/"grant"|"manifest"|"checkpoint"|RECOVERY-PACKAGE|REQUEST-CIPHERTEXT/);
    expect(rows.map(row => row.caseId)).not.toContain(unlisted);

    const sorted = [...listed].sort();
    const first = await listConfidentialAdminListings(store, { limit: 2 });
    expect(first.listings.map(item => item.caseId)).toEqual(sorted.slice(0, 2));
    expect(first.next).toBe(sorted[1]);
    const second = await listConfidentialAdminListings(store, { limit: 2, after: first.next });
    expect(second.listings.map(item => item.caseId)).toEqual(sorted.slice(2));
    expect(second.next).toBeNull();
    for (const item of [...first.listings, ...second.listings]) expect(Object.keys(item).sort()).toEqual(['caseId', 'summary']);
  }, 60_000);

  test('omits a case whose stored listing was tampered with', async () => {
    const caseId = await publish('Original summary');
    const record = await client.db('test_confidential_admin').collection<{ _id: string; listingDigest: string; statements: Record<string, string> }>('confidential_cases').findOne({ _id: caseId });
    const wire = JSON.parse(record!.statements[record!.listingDigest]);
    wire.statement.summary = 'Operator-edited summary';
    await client.db('test_confidential_admin').collection<{ _id: string }>('confidential_cases').updateOne({ _id: caseId },
      { $set: { [`statements.${record!.listingDigest}`]: JSON.stringify(wire) } });
    const all = await listConfidentialAdminListings(store, { limit: 100 });
    expect(all.listings.map(item => item.caseId)).not.toContain(caseId);
    expect(JSON.stringify(all)).not.toContain('Operator-edited summary');
  }, 60_000);

  test('moderation changes only public visibility and atomically audits hide and restore', async () => {
    const caseId = await publish('Public spam review summary');
    const before = await store.getCase(caseId);
    const audit = client.db('test_confidential_admin').collection('confidential_listing_moderation_audit');
    expect(await store.moderateListing(caseId, true, 'admin@example.test', now)).toBe(true);
    expect(await store.getCase(caseId)).toEqual(before);
    expect((await store.listListedCases(100, null)).map(row => row.caseId)).not.toContain(caseId);
    expect((await listConfidentialAdminListings(store, { limit: 100 })).listings.find(row => row.caseId === caseId))
      .toEqual({ caseId, summary: 'Public spam review summary', hidden: true });
    expect(await store.moderateListing(caseId, true, 'admin@example.test', now + 1)).toBe(true);
    expect(await audit.countDocuments({ caseId })).toBe(1);
    expect(await store.moderateListing(caseId, false, 'admin@example.test', now + 2)).toBe(true);
    expect((await store.listListedCases(100, null)).map(row => row.caseId)).toContain(caseId);
    expect(await store.getCase(caseId)).toEqual(before);
    expect(await audit.countDocuments({ caseId })).toBe(2);
    // A failed audit must not leave an unaudited visibility change committed.
    const collection = client.db('test_confidential_admin').collection;
    const spy = jest.spyOn(client, 'db').mockImplementation((...args) => {
      const db = MongoClient.prototype.db.apply(client, args);
      const original = db.collection.bind(db);
      db.collection = ((name: string, options: any) => {
        const result = original(name, options);
        if (name === 'confidential_listing_moderation_audit') result.insertOne = jest.fn().mockRejectedValue(new Error('audit unavailable'));
        return result;
      }) as typeof collection;
      return db;
    });
    await expect(store.moderateListing(caseId, true, 'admin@example.test', now + 3)).rejects.toThrow('audit unavailable');
    spy.mockRestore();
    expect((await store.listListedCases(100, null)).map(row => row.caseId)).toContain(caseId);
    expect(await audit.countDocuments({ caseId })).toBe(2);
    expect(await store.moderateListing(hex(999), true, 'admin@example.test', now)).toBe(false);
  }, 60_000);

  test('rejects out-of-range guards before querying', async () => {
    await expect(store.listListingWires(0, null)).rejects.toThrow('Invalid listing page guard');
    await expect(store.listListingWires(10, 'VERA-OWNER-1.x')).rejects.toThrow('Invalid listing page guard');
  });
});
