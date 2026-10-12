import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
import { decryptReportNarrative } from '../../../src/services/reportNarrative';

describe('narrative migration CLI', () => {
  let server: MongoMemoryServer;
  let client: MongoClient;
  const previous = { ...process.env };
  beforeAll(async () => {
    server = await MongoMemoryServer.create();
    process.env.MONGODB_URI = server.getUri();
    process.env.MONGODB_DB_NAME = 'narrative_migration';
    process.env.REWARD_ENCRYPTION_KEY = 'synthetic-legacy-test-key';
    process.env.AT_REST_LOCAL_KEY = 'synthetic-envelope-test-key';
    delete process.env.KMS_AT_REST_KEY_ID;
    delete process.env.MONGODB_TLS_CA_FILE;
    client = await new MongoClient(server.getUri()).connect();
  });
  afterAll(async () => { await client?.close(); await server?.stop(); process.env = previous; });
  const run = (args: string[], env = process.env) => spawnSync(process.execPath, [
    '-r', 'ts-node/register/transpile-only', path.resolve('scripts/migrate-narrative-to-envelope.ts'), ...args,
  ], { env, encoding: 'utf8', timeout: 30000 });

  it('dry-runs, migrates once, preserves legacy ciphertext, and reads the migrated report', async () => {
    const reports = client.db('narrative_migration').collection('whistleblower_reports');
    const trackingId = 'VRA-FA00000000000001';
    const narrative = 'Synthetic evidence narrative: unicode π and\nnewlines.';
    const legacy = encryptContactValue(narrative);
    await reports.insertOne({ trackingId, encryptedDescription: legacy });
    const dry = run([]);
    expect({ status: dry.status, stderr: dry.stderr }).toMatchObject({ status: 0 });
    expect((await reports.findOne({ trackingId }))?.encryptedNarrative).toBeUndefined();
    const applied = run(['--apply']);
    expect({ status: applied.status, stderr: applied.stderr }).toMatchObject({ status: 0 });
    const stored = await reports.findOne({ trackingId });
    expect(stored?.encryptedDescription).toBe(legacy);
    expect(stored?.encryptedNarrative.encryptionKey).toMatch(/^enc:local:v1:/);
    expect(await decryptReportNarrative(stored as any)).toBe(narrative);
    expect(run(['--apply']).status).toBe(0);
    expect((await reports.findOne({ trackingId }))?.encryptedNarrative).toEqual(stored?.encryptedNarrative);
  });

  it('refuses to migrate without an explicitly configured wrapping key', () => {
    const env = { ...process.env };
    delete env.AT_REST_LOCAL_KEY;
    const result = run(['--apply'], env);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('migration must not use a development constant');
  });

  it.each(['legacy', 'envelope'])('preserves a concurrent %s write and reports migration failure', async (kind) => {
    const reports = client.db('narrative_migration').collection('whistleblower_reports');
    await reports.deleteMany({});
    const trackingId = 'VRA-FA00000000000002';
    const legacy = encryptContactValue('Original synthetic narrative');
    const concurrent = kind === 'legacy'
      ? { encryptedDescription: encryptContactValue('Updated synthetic narrative') }
      : { encryptedNarrative: { encryptedData: 'concurrent-writer-ciphertext' } };
    await reports.insertOne({ trackingId, encryptedDescription: legacy });
    const result = run(['--apply'], {
      ...process.env,
      NODE_OPTIONS: `--require=${path.resolve('tests/fixtures/narrativeMigrationRace.cjs')}`,
      NARRATIVE_MIGRATION_COMPETING_WRITE: JSON.stringify(concurrent),
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('update matched 0, modified 0, not migrated');
    const stored = await reports.findOne({ trackingId });
    expect(stored).toMatchObject(concurrent);
    if (kind === 'legacy') expect(stored?.encryptedNarrative).toBeUndefined();
    else expect(stored?.encryptedDescription).toBe(legacy);
  });
});
