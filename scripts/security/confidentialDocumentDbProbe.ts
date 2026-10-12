/**
 * DocumentDB compatibility probe for the confidential storage adapter
 * (src/services/confidentialCaseStore.ts). The adapter is otherwise tested only
 * on mongodb-memory-server; DocumentDB 5.0 implements a subset of MongoDB.
 *
 * Exercises, through the real adapter, every server feature the confidential
 * path relies on, in a throwaway database it creates and drops:
 *   - multi-document transactions with readConcern "snapshot" and w:majority
 *     (segmented commits, guarded request/message writes, mailbox pages);
 *   - $substrBytes and $strLenBytes in an aggregation $project for ranged
 *     ciphertext reads (DocumentDB find projections do not accept expressions);
 *   - $objectToArray/$filter/$arrayElemAt in the admin listing projection;
 *   - segmented statements: rows written in the
 *     checkpoint's compare-and-set transaction, exact reassembly by position, the
 *     bounded public read (compound kind/revision-descending index sort with a
 *     limit) and exact (case, digest) `$in` lookups for the directory;
 *   - unique and partial unique indexes, TTL indexes;
 *   - compare-and-set conflicts and stale-writer rejection.
 * (Single-use challenges are held inside the enclave session, not the store.)
 *
 * Run from the rehearsal API host (it reaches the dedicated cluster):
 *   CONFIDENTIAL_PROBE_URI='mongodb://...' npx ts-node scripts/security/confidentialDocumentDbProbe.ts
 * The URI is read from the environment only and never printed. Exits 1 on the
 * first unsupported feature, naming the step. Synthetic data only.
 */
import { randomBytes } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { MongoConfidentialCaseStore } from '../../src/services/confidentialCaseStore';

const hex = (n: number) => n.toString(16).padStart(64, '0');
/** Synthetic statement wires with the claimed kind/revision the adapter indexes. */
const SEGMENTED_LISTING = JSON.stringify({ statement: { kind: 'listing', revision: 2, summary: 'probe listing' } });
const SEGMENTED_RELEASE = JSON.stringify({ statement: { kind: 'release', revision: 2 } });

export type ProbeResult = { step: string; ok: boolean }[];

export async function runDocumentDbProbe(client: MongoClient, databaseName = `vera_confidential_probe_${randomBytes(4).toString('hex')}`):
  Promise<ProbeResult> {
  const results: ProbeResult = [];
  const db = client.db(databaseName);
  const step = async (name: string, run: () => Promise<boolean>) => {
    let ok = false;
    try { ok = await run(); } catch { ok = false; }
    results.push({ step: name, ok });
    if (!ok) throw Object.assign(new Error(`DocumentDB probe failed at: ${name}`), { results });
  };
  try {
    const now = Date.now();
    let store!: MongoConfidentialCaseStore;
    await step('indexes (unique, partial unique, TTL)', async () => {
      store = await MongoConfidentialCaseStore.fromDatabase(db, client);
      return true;
    });
    const caseId = hex(0xd0c);
    const record = { caseId, ownerPublicKey: 'probe-owner-key', ownerFingerprint: 'f'.repeat(40),
      statements: { [hex(1)]: 'probe-listing-wire' }, checkpoints: ['probe-checkpoint-0'], currentCheckpointDigest: hex(0x100),
      listingDigest: hex(1), recoveryPackage: 'probe-package', createdAt: now };
    await step('transactional publication (head + first history segment)', async () =>
      await store.createCase(record) && !(await store.createCase(record)));
    await step('staging and object writes', async () => {
      await store.stageObject(hex(0x200), 'probe-ciphertext-'.repeat(64), now);
      await store.putObjects(caseId, [{ objectId: hex(0x300), ciphertextDigest: hex(0x301), ciphertext: 'x'.repeat(4096), ownerEnvelope: 'owner-env' }]);
      return (await store.getStagedObject(hex(0x200)))?.startsWith('probe-ciphertext-') === true;
    });
    await step('segmented compare-and-set transition in a snapshot transaction', async () =>
      await store.commitTransition(caseId, hex(0x100), { statements: { [hex(2)]: SEGMENTED_LISTING, [hex(3)]: SEGMENTED_RELEASE },
        checkpoint: 'probe-checkpoint-1', checkpointDigest: hex(0x101), listingDigest: hex(2), objects: [],
        envelopes: [{ objectId: hex(0x300), recipientKeyId: hex(0x400), envelope: 'probe-envelope' }], recoveryPackage: null }) &&
      !(await store.commitTransition(caseId, hex(0x100), { statements: {}, checkpoint: 'stale', checkpointDigest: hex(0x102),
        listingDigest: hex(1), objects: [], envelopes: [], recoveryPackage: null })));
    await step('history reassembly', async () => (await store.getCase(caseId))?.checkpoints.length === 2);
    await step('statement segments (exact reassembly, bounded kind/revision read)', async () => {
      const full = await store.getCase(caseId), bounded = await store.getCase(caseId, { releaseLimit: 1 });
      const listed = (await store.listListedCases(10, null)).find(row => row.caseId === caseId);
      return !!full && Object.keys(full.statements).sort().join() === [hex(1), hex(2), hex(3)].join() &&
        full.statements[hex(3)] === SEGMENTED_RELEASE && !!bounded &&
        Object.keys(bounded.statements).sort().join() === [hex(2), hex(3)].join() &&
        JSON.stringify(listed?.statements) === JSON.stringify({ [hex(2)]: SEGMENTED_LISTING });
    });
    await step('ranged ciphertext projection ($substrBytes, $strLenBytes)', async () => {
      const range = await store.readGrantedObjects(caseId, hex(0x400), hex(0x101), [{ objectId: hex(0x300), ciphertextDigest: hex(0x301) }],
        { offset: 1024, length: 128 });
      return range?.[0]?.ciphertext.length === 128 && range[0].totalBytes === 4096;
    });
    await step('empty range projection ($literal)', async () => {
      const range = await store.readGrantedObjects(caseId, hex(0x400), hex(0x101), [{ objectId: hex(0x300), ciphertextDigest: hex(0x301) }],
        { offset: 0, length: 0 });
      return range?.[0]?.ciphertext === '' && range[0].totalBytes === 4096;
    });
    await step('admin listing projection ($objectToArray, $filter)', async () => {
      // One head whose listing is embedded (genesis) and one whose listing is a segment row.
      const embedded = hex(0xd0d);
      await store.createCase({ ...record, caseId: embedded });
      const rows = await store.listListingWires(10, null);
      return rows.some(row => row.caseId === embedded && row.listingWire === 'probe-listing-wire') &&
        rows.some(row => row.caseId === caseId && row.listingWire === SEGMENTED_LISTING);
    });
    await step('guarded request insertion and checkpoint-bound mailbox page', async () => {
      const stored = await store.insertAccessRequestAtCheckpoint({ caseId, organizationId: hex(0x500), requestId: hex(0x501),
        recipientKeyId: hex(0x502), ciphertext: 'probe-request', state: 'pending', createdAt: now, expiresAt: now + 60_000 },
      { checkpointDigest: hex(0x101), now, since: now - 60_000, organizationLimit: 5, caseLimit: 5 });
      const page = await store.readMailboxPageAtCheckpoint(caseId, null, hex(0x101), null);
      return stored === 'stored' && page?.requests.length === 1;
    });
    await step('guarded message append with quota', async () =>
      await store.appendMessage({ caseId, organizationId: hex(0x500), sender: 'owner', ciphertext: 'probe-message', createdAt: now },
        { checkpointDigest: hex(0x101), since: now - 60_000, limit: 5 }) === 'stored');
  } finally {
    await db.dropDatabase().catch(() => {});
  }
  return results;
}

if (require.main === module) {
  (async () => {
    const uri = process.env.CONFIDENTIAL_PROBE_URI;
    if (!uri) throw new Error('Set CONFIDENTIAL_PROBE_URI (never pass it on the command line)');
    const client = await MongoClient.connect(uri, { readPreference: 'primary', writeConcern: { w: 'majority', j: true },
      serverSelectionTimeoutMS: 15_000, ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}) });
    try {
      const results = await runDocumentDbProbe(client);
      process.stdout.write(`${JSON.stringify({ compatible: true, steps: results })}\n`);
    } finally { await client.close(); }
  })().catch(error => {
    process.stderr.write(`${JSON.stringify({ compatible: false, error: error instanceof Error ? error.message : 'failed',
      steps: (error as { results?: ProbeResult }).results ?? [] })}\n`);
    process.exit(1);
  });
}
