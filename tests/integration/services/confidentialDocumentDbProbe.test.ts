/** The DocumentDB compatibility probe must stay runnable: CI runs it against
 * MongoDB; operators run the same function against DocumentDB 5.0 from the
 * rehearsal stack (runbook section 10). */
import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { runDocumentDbProbe } from '../../../scripts/security/confidentialDocumentDbProbe';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';

describe('confidential DocumentDB compatibility probe', () => {
  let server: MongoMemoryReplSet, client: MongoClient;
  beforeAll(async () => {
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(server.getUri());
  }, 120_000);
  afterAll(async () => { await client?.close(); await server?.stop(); });

  test('every feature the adapter relies on passes and the throwaway database is dropped', async () => {
    const results = await runDocumentDbProbe(client, 'vera_confidential_probe_test');
    expect(results.every(result => result.ok)).toBe(true);
    expect(results.map(result => result.step)).toEqual(expect.arrayContaining([
      'segmented compare-and-set transition in a snapshot transaction',
      'statement segments (exact reassembly, bounded kind/revision read)',
      'ranged ciphertext projection ($substrBytes, $strLenBytes)',
      'admin listing projection ($objectToArray, $filter)',
    ]));
    const databases = (await client.db().admin().listDatabases()).databases.map(item => item.name);
    expect(databases).not.toContain('vera_confidential_probe_test');
  }, 120_000);

  test('an unsupported feature stops the probe and names the step', async () => {
    const failing = { db: (name: string) => {
      const db = client.db(name);
      return new Proxy(db, { get: (target, key) => key === 'collection' ? (collection: string) => {
        const real = target.collection(collection);
        return new Proxy(real, { get: (inner, method) => method === 'aggregate'
          ? () => { throw new Error('Unsupported aggregation operator'); }
          : typeof (inner as never)[method] === 'function' ? ((inner as never)[method] as (...args: unknown[]) => unknown).bind(inner) : (inner as never)[method] });
      } : typeof (target as never)[key] === 'function' ? ((target as never)[key] as (...args: unknown[]) => unknown).bind(target) : (target as never)[key] });
    }, startSession: client.startSession.bind(client) } as unknown as MongoClient;
    await expect(runDocumentDbProbe(failing, 'vera_confidential_probe_failing'))// Ranged reads are the first aggregation the adapter runs.
      .rejects.toThrow('ranged ciphertext projection');
    await client.db('vera_confidential_probe_failing').dropDatabase();
  }, 120_000);

  test('a missing statement segment fails the adapter-level probe', async () => {
    const read = MongoConfidentialCaseStore.prototype.getCase;
    const missing = jest.spyOn(MongoConfidentialCaseStore.prototype, 'getCase')
      .mockImplementation(async function (caseId, options) {
        const record = await read.call(this, caseId, options);
        return record && options?.releaseLimit ? { ...record, statements: {} } : record;
      });
    try {
      await expect(runDocumentDbProbe(client, 'vera_confidential_probe_missing_segment'))
        .rejects.toThrow('statement segments (exact reassembly, bounded kind/revision read)');
    } finally { missing.mockRestore(); }
    const databases = (await client.db().admin().listDatabases()).databases.map(item => item.name);
    expect(databases).not.toContain('vera_confidential_probe_missing_segment');
  }, 120_000);
});
