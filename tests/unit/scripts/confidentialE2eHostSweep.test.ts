import { readFileSync, readdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { Binary, MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { encodeRecoveryCodeV2, formatRecoveryCode } from '../../../enclave/src/confidential/recoveryCode';
import { recoveryFileText } from '../../../lib/confidential/recoveryFile';
import {
  appendSecretRegister, describeHostLeaks, parseSecretRegister, recoveryFileSecrets, storedRecordText, sweepHostRecords,
} from '../../../qa/e2e/support/leaks';
import type { HostRecord } from '../../../qa/e2e/support/leaks';
import { captureProcessOutput, storedRecords } from '../../../qa/e2e/stack/hostRecords';

// Architecture acceptance test 7: no plaintext, recovery code or key material in
// logs, queues or stored object metadata. The click-through suite's browser
// checks cover what participants send; its global teardown sweeps what the host
// kept (the Next log, the API and enclave output, every stored record) for the
// sentinels and device secrets the specs register. These guard that sweep.

jest.setTimeout(120_000);

async function sampleReport() {
  const secret = new Uint8Array(randomBytes(32));
  const recoveryCode = formatRecoveryCode(await encodeRecoveryCodeV2(secret));
  const recoveryFile = recoveryFileText({ recoveryCode, recoveryPackage: '{"format":"vera-owner-recovery/v2","ciphertext":"AAAA"}' });
  return { recoveryCode, recoveryFile, secret: Buffer.from(secret) };
}

describe('secret register', () => {
  it('round-trips appended lines and drops empty values', () => {
    let text = '';
    const append = (_file: string, data: string) => { text += data; };
    appendSecretRegister('register', ['SENTINEL-A', ''], append);
    appendSecretRegister('register', [], append);
    appendSecretRegister('register', ['SENTINEL-A', 'device-code-123'], append);
    expect(text.trim().split('\n')).toHaveLength(2);
    expect(parseSecretRegister(text)).toEqual([{ secret: 'SENTINEL-A', allowedIn: [] }, { secret: 'device-code-123', allowedIn: [] }]);
  });

  it('keeps a value allowed only where every registration allowed it', () => {
    let text = '';
    const append = (_file: string, data: string) => { text += data; };
    appendSecretRegister('register', ['address-sentinel'], append, ['db.notifications', 'db.other']);
    appendSecretRegister('register', ['address-sentinel'], append, ['db.notifications']);
    appendSecretRegister('register', ['strict-sentinel'], append, ['db.notifications']);
    appendSecretRegister('register', ['strict-sentinel'], append);
    expect(parseSecretRegister(text)).toEqual([
      { secret: 'address-sentinel', allowedIn: ['db.notifications'] },
      { secret: 'strict-sentinel', allowedIn: [] },
    ]);
  });

  it('fails loudly on a malformed register instead of sweeping for nothing', () => {
    expect(() => parseSecretRegister('{"not":"a list"}\n')).toThrow();
    expect(() => parseSecretRegister('not json\n')).toThrow();
    expect(() => parseSecretRegister('{"secrets":["x"]}\n')).toThrow();
  });
});

describe('stored record text', () => {
  it('finds a sentinel in keys, nested values, binary bytes and base64 strings', () => {
    const sentinel = 'SENTINEL-STORED-9Z';
    const records: HostRecord[] = [
      { source: 'key', text: storedRecordText({ meta: { [sentinel]: 1 } }) },
      { source: 'nested', text: storedRecordText({ a: [{ b: `x ${sentinel} y` }] }) },
      { source: 'binary', text: storedRecordText({ data: new Binary(Buffer.from(`\u0001${sentinel}\u0002`)) }) },
      { source: 'buffer', text: storedRecordText({ data: Buffer.from(sentinel) }) },
      { source: 'base64', text: storedRecordText({ ciphertext: Buffer.from(`${sentinel} in the clear`).toString('base64') }) },
      { source: 'base64url', text: storedRecordText({ ciphertext: Buffer.from(`${sentinel}??>>`).toString('base64url') }) },
    ];
    expect(sweepHostRecords(records, [sentinel]).map(leak => leak.source)).toEqual(['key', 'nested', 'binary', 'buffer', 'base64', 'base64url']);
  });

  it('finds the raw recovery secret in a binary field and the code in a log line', async () => {
    const { recoveryCode, recoveryFile, secret } = await sampleReport();
    const secrets = recoveryFileSecrets(recoveryFile, recoveryCode);
    const records: HostRecord[] = [
      { source: 'stored', text: storedRecordText({ blob: new Binary(Buffer.concat([Buffer.from([9]), secret])) }) },
      { source: 'log', text: `[api] restore attempt code=${recoveryCode.toLowerCase()}` },
      { source: 'clean', text: storedRecordText({ ciphertext: new Binary(randomBytes(64)) }) },
    ];
    expect([...new Set(sweepHostRecords(records, secrets).map(leak => leak.source))]).toEqual(['stored', 'log']);
  });

  it('reports sentinels by name and device secrets without echoing them', async () => {
    const { recoveryCode } = await sampleReport();
    const message = describeHostLeaks([{ source: 'next.log', secret: 'SENTINEL-X' }, { source: 'mongo a.b', secret: recoveryCode }]);
    expect(message).toContain('next.log: "SENTINEL-X"');
    expect(message).toContain('mongo a.b: device secret');
    expect(message).not.toContain(recoveryCode);
  });
});

describe('reporter contact has no host collection exception', () => {
  it('is detected in every collection and log', () => {
    const address = { secret: 'sentinel-notify', allowedIn: [] };
    const records: HostRecord[] = [
      { source: 'own collection', text: 'sentinel-notify@x.example', namespace: 'vera.confidential_owner_notifications' },
      { source: 'case record', text: 'sentinel-notify@x.example', namespace: 'vera.confidential_cases' },
      { source: 'next.log', text: 'GET /status?email=sentinel-notify@x.example' },
    ];
    expect(sweepHostRecords(records, [address]).map(leak => leak.source)).toEqual(['own collection', 'case record', 'next.log']);
    expect(sweepHostRecords(records, ['sentinel-notify']).map(leak => leak.source)).toEqual(['own collection', 'case record', 'next.log']);
  });
});

describe('captured process output', () => {
  it('records what this process prints to stdout and stderr, and restores the streams', () => {
    const { stdout, stderr } = process;
    const originals = [stdout.write, stderr.write];
    const quiet = jest.fn(() => true);
    stdout.write = quiet as never; stderr.write = quiet as never;
    try {
      const capture = captureProcessOutput();
      process.stdout.write('api: SENTINEL-STDOUT\n');
      process.stderr.write('enclave: SENTINEL-STDERR\n'); // jest replaces console; in the stack it writes here
      process.stderr.write(Buffer.from('SENTINEL-BYTES'));
      capture.restore();
      process.stdout.write('after restore: SENTINEL-LATE\n');
      expect(sweepHostRecords([{ source: 'host', text: capture.text() }], ['SENTINEL-STDOUT', 'SENTINEL-STDERR', 'SENTINEL-BYTES', 'SENTINEL-LATE'])
        .map(leak => leak.secret)).toEqual(['SENTINEL-STDOUT', 'SENTINEL-STDERR', 'SENTINEL-BYTES']);
      expect(stdout.write).toBe(quiet);
    } finally { stdout.write = originals[0]; stderr.write = originals[1]; }
  });
});

describe('stored records', () => {
  let mongo: MongoMemoryReplSet;
  beforeAll(async () => { mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } }); });
  afterAll(async () => { await mongo?.stop(); });

  it('walks every database and collection, and the oplog keeps records later deleted', async () => {
    const client = await MongoClient.connect(mongo.getUri(), { directConnection: true });
    try {
      await client.db('vera_confidential_e2e').collection('objects').insertOne({ ciphertext: new Binary(randomBytes(32)), metadata: { note: 'SENTINEL-METADATA' } });
      await client.db('other_db').collection('queue').insertOne({ job: 'notify', body: 'SENTINEL-QUEUE' });
      const transient = client.db('vera_confidential_e2e').collection('staging');
      await transient.insertOne({ plaintext: 'SENTINEL-DELETED' });
      await transient.deleteMany({});
      await transient.createIndex({ 'SENTINEL-INDEX-FIELD': 1 });
      // Historical plaintext contact is a leak even after deleting its live row.
      // The oplog attributes each write, including transaction writes.
      const notifications = client.db('vera_confidential_e2e').collection('confidential_owner_notifications');
      await notifications.insertOne({ address: 'sentinel-address@x.example' });
      const session = client.startSession();
      try {
        await session.withTransaction(async () => {
          await notifications.deleteMany({}, { session });
          await client.db('vera_confidential_e2e').collection('confidential_cases').insertOne({ misplaced: 'sentinel-address@x.example' }, { session });
        });
      } finally { await session.endSession(); }
    } finally { await client.close(); }

    const records: HostRecord[] = [];
    for await (const record of storedRecords(mongo.getUri())) records.push(record);
    const leaks = sweepHostRecords(records, ['SENTINEL-METADATA', 'SENTINEL-QUEUE', 'SENTINEL-DELETED', 'SENTINEL-INDEX-FIELD', 'SENTINEL-NEVER-WRITTEN']);
    const where = (secret: string) => leaks.filter(leak => leak.secret === secret).map(leak => leak.source);
    expect(where('SENTINEL-METADATA')).toContain('mongo vera_confidential_e2e.objects');
    expect(where('SENTINEL-QUEUE')).toContain('mongo other_db.queue');
    expect(where('SENTINEL-DELETED')).toEqual(['mongo local.oplog.rs (vera_confidential_e2e.staging)']);
    expect(where('SENTINEL-INDEX-FIELD')).toContain('mongo vera_confidential_e2e.staging (index)');
    expect(where('SENTINEL-NEVER-WRITTEN')).toEqual([]);
    const address = sweepHostRecords(records, ['sentinel-address'])
      .map(leak => leak.source);
    expect(address).toEqual(expect.arrayContaining(['mongo vera_confidential_e2e.confidential_cases', 'mongo local.oplog.rs (vera_confidential_e2e.confidential_cases)']));
    expect(address).toContain('mongo local.oplog.rs (vera_confidential_e2e.confidential_owner_notifications)');
  });
});

describe('the click-through suite sweeps the host at teardown', () => {
  it('every spec that checks browser traffic also registers those secrets for the host sweep', () => {
    const names = readdirSync('qa/e2e/specs').filter(name => name.endsWith('.spec.ts')).map(name => name.replace(/\.spec\.ts$/, ''));
    // These must check browser traffic; any other spec that does is held to the same rule.
    const required = ['confidential-journey', 'confidential-two-firms', 'smoke', 'owner-mobile', 'release-update', 'owner-notifications'];
    expect(names).toEqual(expect.arrayContaining(required));
    for (const name of names) {
      const spec = readFileSync(`qa/e2e/specs/${name}.spec.ts`, 'utf8');
      const checks = spec.split('\n').filter(line => /leakedSecrets\(/.test(line));
      if (required.includes(name)) expect(checks.length).toBeGreaterThan(0);
      expect(checks.filter(line => !/leakedSecrets\(\w+, (\[\.\.\.\w+, \.\.\.)?sweptFromHost\(\[/.test(line))).toEqual([]);
    }
    // The shared firm helper checks the operator's page the same way.
    const firm = readFileSync('qa/e2e/support/firm.ts', 'utf8').split('\n').filter(line => /leakedSecrets\(/.test(line));
    expect(firm.length).toBeGreaterThan(0);
    expect(firm.filter(line => !/leakedSecrets\(\w+, sweptFromHost\(\[/.test(line))).toEqual([]);
  });

  it('the legacy probe never sends the reporter\'s own recovery code (request lines reach host logs)', () => {
    const spec = readFileSync('qa/e2e/specs/confidential-journey.spec.ts', 'utf8');
    const legacy = spec.slice(spec.indexOf("test('legacy routes reject"), spec.indexOf("test('the reporter edits and then withdraws"));
    expect(legacy).toMatch(/const code = formatRecoveryCode\(await encodeRecoveryCodeV2\(new Uint8Array\(randomBytes\(32\)\)\)\)/);
    expect(legacy).not.toMatch(/const code = journey\.report!\.recoveryCode/);
  });

  it('the reporter journey grants no host storage exception', () => {
    const spec = readFileSync('qa/e2e/specs/owner-notifications.spec.ts', 'utf8');
    expect(spec).not.toMatch(/allowedIn|confidentialCollection/);
    expect(spec).toContain("getByLabel('Separate email address')).toHaveCount(0)");
  });

  it('global teardown sweeps before stopping the stack, and the sweep covers logs, host output and Mongo', () => {
    const setup = readFileSync('qa/e2e/global-setup.ts', 'utf8');
    expect(setup).toMatch(/try \{[\s\S]*await sweep\(\)[\s\S]*\} finally \{ await stop\(\); \}/);
    const stack = readFileSync('qa/e2e/stack/stack.ts', 'utf8');
    expect(stack).toMatch(/captureProcessOutput\(\)/);
    expect(stack).toMatch(/nextOutput\.join\(''\)/);
    expect(stack).toMatch(/yield\* storedRecords\(mongoUri\)/);
    expect(stack).toMatch(/if \(leaks\.length\) throw new Error\(describeHostLeaks\(leaks\)\)/);
    expect(stack).toMatch(/parseSecretRegister\(readFileSync\(secretRegister, 'utf8'\)\)/);
  });
});
