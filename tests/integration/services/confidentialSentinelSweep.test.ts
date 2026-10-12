/**
 * Automated sentinel sweep (architecture acceptance test 7) against the mounted
 * local stack: browser client -> host relay (with the real private-route
 * middleware) -> enclave frame server -> owner dispatcher -> sealed store ->
 * storage RPC -> MongoDB, with only the AWS quote mocked. Sentinels go into every
 * private field; the sweep then searches both databases (every collection, raw
 * BSON), all captured process output and staged data, and must find nothing.
 * The same scripts run against the deployed rehearsal stack (runbook section 9).
 */
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import { mkdtempSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { webcrypto } from 'node:crypto';
import type { AddressInfo, Server } from 'node:net';
import express from 'express';
import { Binary, MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { parseRecoveryCode } from '../../../enclave/src/confidential/recoveryCode';
import { createConfidentialChannelRouter, tcpEnclaveTransport } from '../../../src/api/confidentialChannel';
import { createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';
import { createRemoteCaseStore } from '../../../enclave/src/cases/storageRpc';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch, createConfidentialFrameServer } from '../../../enclave/src/confidential-server';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { fetchRelay } from '../../../lib/confidential/client';
import { submitSentinelReport } from '../../../scripts/security/confidentialSentinelSubmit';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const sweep = require('../../../scripts/security/confidential-sentinel-sweep.cjs');

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(21), imageSha256: hex(22), configurationSha256: hex(23), provenanceSha256: hex(24),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '44'.repeat(48), pcr1: '55'.repeat(48), pcr2: '66'.repeat(48) } });
const listen = (server: Server) => new Promise<number>(resolve =>
  server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));

describe('automated sentinel sweep over the mounted stack', () => {
  let mongo: MongoMemoryReplSet, client: MongoClient, dir: string, logFile: string;
  const servers: Server[] = [];
  const restore: (() => void)[] = [];

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    dir = mkdtempSync(path.join(tmpdir(), 'vera-sentinel-sweep-'));
    logFile = path.join(dir, 'process-output.log');
    writeFileSync(logFile, '');
    // Capture everything this process writes, as a deployed log group would.
    for (const stream of [process.stdout, process.stderr]) {
      const original = stream.write.bind(stream);
      stream.write = ((chunk: unknown, ...rest: unknown[]) => {
        appendFileSync(logFile, typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array));
        return (original as (...args: unknown[]) => boolean)(chunk, ...rest);
      }) as typeof stream.write;
      restore.push(() => { stream.write = original as typeof stream.write; });
    }
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      const original = console[level];
      console[level] = (...args: unknown[]) => { appendFileSync(logFile, `${args.map(String).join(' ')}\n`); };
      restore.push(() => { console[level] = original; });
    }

    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(mongo.getUri());
    const store = await MongoConfidentialCaseStore.fromDatabase(client.db('vera_confidential'), client);
    // A legacy database with ordinary content must also be searched.
    await client.db('vera').collection('reports').insertOne({ trackingId: 'LEGACY-1', status: 'pending' });
    const storage = createConfidentialStorageServer(store as unknown as Record<string, unknown>, { releaseManifest: MANIFEST });
    const storagePort = await listen(storage);
    servers.push(storage);
    const channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic enclave' }], format: 'object' });
    const onboarding = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' });
    const keyring = createCaseKeyring({ clock: Date.now });
    const { authenticatedRoster } = await import('../../../enclave/src/cases/authenticatedRoster');
    const dispatch = createCaseChannelDispatch(createOwnerCaseControlDispatcher({
      store: authenticatedRoster(createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring), onboarding.publicKey.armor(), Date.now),
      keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest: (await readReleaseManifest(MANIFEST)).digest,
    }), null);
    const sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(channelKey.privateKey,
      { nonce, publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'), document: Buffer.from('synthetic').toString('base64') }), () => Date.now());
    const enclave = createConfidentialFrameServer(sessions);
    const enclavePort = await listen(enclave);
    servers.push(enclave);
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    app.use('/api/confidential', createConfidentialObjectRouter(store));
    app.use('/api/confidential', createConfidentialChannelRouter(tcpEnclaveTransport(enclavePort), { maxPerMinute: 10_000 }));
    const host = app.listen(0, '127.0.0.1');
    await new Promise(resolve => host.once('listening', resolve));
    servers.push(host as unknown as Server);
    process.env.SWEEP_RELAY_BASE = `http://127.0.0.1:${(host.address() as AddressInfo).port}/api/confidential`;
  }, 180_000);

  afterAll(async () => {
    for (const undo of restore.reverse()) undo();
    for (const server of servers) server.close();
    await client?.close();
    await mongo?.stop();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.SWEEP_RELAY_BASE;
  });

  test('no sentinel reaches either database, any collection or any process output', async () => {
    const sentinels = sweep.generateSentinels();
    const base = process.env.SWEEP_RELAY_BASE!;
    const result = await submitSentinelReport({ relay: fetchRelay(`${base}/channel`, `${base}/objects`),
      releaseManifest: MANIFEST, values: sentinels.values });
    expect(result.caseId).toMatch(/^[a-f0-9]{64}$/);
    // The owner device holds plaintext; the stack must not.
    const list = sweep.needles(sentinels);
    const mongoHits = await sweep.searchMongo(client, ['vera_confidential', 'vera'], list);
    const collections = (await client.db('vera_confidential').listCollections().toArray()).map(item => item.name);
    expect(collections.length).toBeGreaterThan(3);
    expect(mongoHits).toEqual([]);
    expect(sweep.searchPaths([dir], list)).toEqual([]);
    // The operator flow: the sweep loads <sentinels>.recovery and searches every
    // form and encoding of the owner recovery code across both stores and logs.
    const operatorDir = mkdtempSync(path.join(tmpdir(), 'vera-sentinel-operator-'));
    try {
      const file = path.join(operatorDir, 'sentinels.json');
      writeFileSync(file, JSON.stringify(sentinels));
      writeFileSync(`${file}.recovery`, `${result.recoveryCode}\n`, { mode: 0o600 });
      const loaded = sweep.readSentinels(file);
      expect(loaded.recoveryCode).toBe(result.recoveryCode);
      const withRecovery = sweep.needles(loaded);
      expect(withRecovery.filter((item: { label: string }) => item.label.startsWith('recoveryCode'))).toHaveLength(4 * 6);
      expect(await sweep.searchMongo(client, ['vera_confidential', 'vera'], withRecovery)).toEqual([]);
      expect(sweep.searchPaths([dir], withRecovery)).toEqual([]);
    } finally { rmSync(operatorDir, { recursive: true, force: true }); }
    // Nor is the recovery code's secret part stored or logged.
    const parsed = await parseRecoveryCode(result.recoveryCode);
    const secret = [
      { label: 'recoveryCode', encoding: 'raw', bytes: Buffer.from(result.recoveryCode) },
      { label: 'recoveryCodeCompact', encoding: 'raw', bytes: Buffer.from(result.recoveryCode.replace(/-/g, '')) },
      { label: 'recoverySecret', encoding: 'binary', bytes: Buffer.from(parsed.secret) },
      { label: 'recoverySecret', encoding: 'base64', bytes: Buffer.from(Buffer.from(parsed.secret).toString('base64').replace(/=+$/, '')) },
      { label: 'recoverySecret', encoding: 'hex', bytes: Buffer.from(Buffer.from(parsed.secret).toString('hex')) },
    ];
    expect(secret.every(item => item.bytes.length > 16)).toBe(true);
    expect(await sweep.searchMongo(client, ['vera_confidential', 'vera'], secret)).toEqual([]);
    expect(sweep.searchPaths([dir], secret)).toEqual([]);
  }, 240_000);

  test('the sweep itself detects a planted sentinel in any encoding and location', async () => {
    const sentinels = sweep.generateSentinels();
    const list = sweep.needles(sentinels);
    const marker = sentinels.values.contact;
    await client.db('vera').collection('planted').insertMany([
      { note: `prefix ${marker} suffix` },
      { blob: new Binary(Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(marker)])) },
      { encoded: Buffer.from(sentinels.values.narrative).toString('base64') },
    ]);
    const hits = await sweep.searchMongo(client, ['vera_confidential', 'vera'], list);
    expect(hits).toEqual(expect.arrayContaining([
      { location: 'mongo:vera.planted', label: 'contact', encoding: 'raw' },
      { location: 'mongo:vera.planted', label: 'narrative', encoding: 'base64' },
    ]));
    const log = path.join(dir, 'planted.log');
    writeFileSync(log, `GET /api/confidential/x?c=${Buffer.from(sentinels.values.requestPurpose).toString('hex')}\n`);
    expect(sweep.searchPaths([log], list)).toEqual([{ location: `file:${log}`, label: 'requestPurpose', encoding: 'hex' }]);
    rmSync(log);
    await client.db('vera').collection('planted').drop();
  }, 60_000);

  test('CloudWatch search queries every group for raw and base64 forms and reports only locations', async () => {
    const sentinels = sweep.generateSentinels();
    const calls: string[][] = [];
    const hits = await sweep.searchLogGroups(['/ecs/vera-rehearsal-api', 'aws-waf-logs-vera-rehearsal'], sentinels, { region: 'us-east-2' },
      async (args: string[]) => {
        calls.push(args);
        const pattern = args[args.indexOf('--filter-pattern') + 1];
        return JSON.stringify({ events: args.includes('/ecs/vera-rehearsal-api') && pattern.includes('-ownerMessage-') ? [{ message: 'x' }] : [] });
      });
    expect(calls).toHaveLength(2 * sweep.LABELS.length * 2);
    expect(hits).toEqual([{ location: 'cloudwatch:/ecs/vera-rehearsal-api', label: 'ownerMessage', encoding: 'raw' }]);
  });

  test('CLI refuses to run with no source and never takes a database URI on the command line', async () => {
    const file = path.join(dir, 'sentinels.json');
    writeFileSync(file, JSON.stringify(sweep.generateSentinels()));
    await expect(sweep.main(['search', '--sentinels', file])).rejects.toThrow(/nothing to search/);
    expect(() => sweep.parseArgs(['search', '--mongo-uri', 'mongodb://x'])).toThrow(/invalid argument/);
    process.env.SWEEP_TEST_URI = mongo.getUri();
    await expect(sweep.main(['search', '--sentinels', file, '--mongo-uri-env', 'SWEEP_TEST_URI', '--mongo-db', 'vera_confidential']))
      .resolves.toEqual(expect.objectContaining({ hits: [], sources: 1 }));
    delete process.env.SWEEP_TEST_URI;
  }, 60_000);
});
