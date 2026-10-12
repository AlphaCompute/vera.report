import express from 'express';
import request from 'supertest';
import { createAttestedReporterVerificationRouter } from '../../../src/api/attestedReporterVerification';
import processes = require('node:child_process');
import path from 'node:path';
import os from 'node:os';
import { AttestedReporterVerification } from '../../../src/services/attestedReporterVerification';
import { MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { reporterCodeHash } from '../../../src/services/reporterAccess';
import { AttestedReportVerificationReader } from '../../../src/services/attestedReportVerificationReader';
import { keyEnvelope } from '../../../src/services/keyEnvelope';

useDisseminationMongo();
const trackingId = 'VRA-0123456789ABCDEF';
const code = 'VRC-' + 'A'.repeat(64);
const rotated = 'VRC-' + 'B'.repeat(64);
const envelope = 'private:v1:' + JSON.stringify({ key: 'enc:kms:v2:AQ==',
  iv: Buffer.alloc(12).toString('base64'), tag: Buffer.alloc(16).toString('base64'), data: 'AQ==' });
let client: MongoClient;
beforeEach(async () => {
  client = await new MongoClient(process.env.MONGODB_URI!).connect();
  const reports = client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports');
  await reports.deleteMany({});
  await reports.insertOne({ trackingId, reporterAccess: { hash: reporterCodeHash(code), encryptedCode: 'hidden' },
    verification: envelope, status: 'pending', rewardContact: 'must not be projected', encryptedNarrative: { secret: true } });
});
afterEach(async () => { jest.restoreAllMocks(); await client.close(); });

it('returns only the exact encrypted field without host key unwrapping', async () => {
  const unwrap = jest.spyOn(keyEnvelope, 'unwrap').mockRejectedValue(new Error('Host unwrap forbidden'));
  const loader = reportPersistenceService.createReporterVerificationLoader(code.toLowerCase());
  expect(await loader(trackingId, new AbortController().signal)).toEqual({ trackingId, verification: envelope });
  expect(unwrap).not.toHaveBeenCalled();
});

it('does not authorize a different report or credential', async () => {
  const signal = new AbortController().signal;
  expect(await reportPersistenceService.createReporterVerificationLoader(code)('VRA-FFFFFFFFFFFFFFFF', signal)).toBeNull();
  expect(await reportPersistenceService.createReporterVerificationLoader(rotated)(trackingId, signal)).toBeNull();
  expect(() => reportPersistenceService.createReporterVerificationLoader(trackingId)).toThrow('Reporter credential required');
  expect(() => reportPersistenceService.createReporterVerificationLoader('')).toThrow('Reporter credential required');
});

it('rechecks rotation and credential removal on every read', async () => {
  const reports = client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports');
  const loader = reportPersistenceService.createReporterVerificationLoader(code);
  const signal = new AbortController().signal;
  expect(await loader(trackingId, signal)).not.toBeNull();
  await reports.updateOne({ trackingId }, { $set: { 'reporterAccess.hash': reporterCodeHash(rotated) } });
  expect(await loader(trackingId, signal)).toBeNull();
  const newLoader = reportPersistenceService.createReporterVerificationLoader(rotated);
  expect(await newLoader(trackingId, signal)).toEqual({ trackingId, verification: envelope });
  await reports.updateOne({ trackingId }, { $unset: { reporterAccess: '' } });
  expect(await newLoader(trackingId, signal)).toBeNull();
});

it('rejects cancellation and malformed record selection', async () => {
  const loader = reportPersistenceService.createReporterVerificationLoader(code);
  const controller = new AbortController();
  controller.abort(new Error('Synthetic cancellation'));
  await expect(loader(trackingId, controller.signal)).rejects.toThrow('Synthetic cancellation');
  await expect(loader('not-a-record', new AbortController().signal)).rejects.toThrow('Invalid tracking ID');
  await expect(loader({ $ne: null, toString: () => trackingId } as unknown as string, new AbortController().signal)).rejects.toThrow('Invalid tracking ID');
});

it('denied database authorization stops the reader before credential retrieval', async () => {
  const credentials = jest.fn();
  const reader = new AttestedReportVerificationReader({
    pythonExecutable: '/opt/vera-attestation/venv/bin/python', moduleRoot: '/opt/vera-attestation', port: 9,
    keyArn: 'arn:aws:kms:us-east-2:000000000000:key/00000000-0000-0000-0000-000000000001',
    pcrs: { '0': '11'.repeat(48), '1': '22'.repeat(48), '2': '33'.repeat(48) },
    loadAuthorized: reportPersistenceService.createReporterVerificationLoader(rotated), credentials,
  });
  try {
    await expect(reader.read(trackingId)).rejects.toThrow('Report verification reader unavailable');
    expect(credentials).not.toHaveBeenCalled();
  } finally { await reader.close(); }
});

it('resolves modern reporter code internally without opening or returning protected fields', async () => {
  const unwrap = jest.spyOn(keyEnvelope, 'unwrap').mockRejectedValue(new Error('Host unwrap forbidden'));
  expect(await reportPersistenceService.resolveAttestedReporterTrackingId(code.toLowerCase(), new AbortController().signal)).toBe(trackingId);
  expect(await reportPersistenceService.resolveAttestedReporterTrackingId(rotated, new AbortController().signal)).toBeNull();
  expect(unwrap).not.toHaveBeenCalled();
  await expect(reportPersistenceService.resolveAttestedReporterTrackingId(trackingId, new AbortController().signal)).rejects.toThrow();
});

it('code-only resolution retains unique credential binding and observes rotation/cancellation', async () => {
  const reports = client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports');
  await expect(reports.insertOne({ trackingId: 'VRA-FFFFFFFFFFFFFFFF', reporterAccess: { hash: reporterCodeHash(code) } })).rejects.toMatchObject({ code: 11000 });
  expect(await reportPersistenceService.resolveAttestedReporterTrackingId(code, new AbortController().signal)).toBe(trackingId);
  await reports.updateOne({ trackingId }, { $set: { 'reporterAccess.hash': reporterCodeHash(rotated) } });
  expect(await reportPersistenceService.resolveAttestedReporterTrackingId(code, new AbortController().signal)).toBeNull();
  const abort = new AbortController(); abort.abort();
  await expect(reportPersistenceService.resolveAttestedReporterTrackingId(rotated, abort.signal)).rejects.toThrow();
});


it('composes HTTP, real Mongo authorization and child lifecycle across credential rotation', async () => {
  const fixtureId = 'VRA-1234567890ABCDEF';
  const reports = client.db(process.env.MONGODB_DB_NAME).collection('whistleblower_reports');
  await reports.updateOne({ trackingId }, { $set: { trackingId: fixtureId } });
  const unwrap = jest.spyOn(keyEnvelope, 'unwrap').mockRejectedValue(new Error('Host unwrap forbidden'));
  const actualSpawn = processes.spawn;
  // Explicit process fixture replaces only the unavailable live Nitro boundary.
  const spawn = jest.spyOn(processes, 'spawn').mockImplementation((_executable, _args, options) =>
    actualSpawn(process.execPath, [path.resolve('tests/helpers/attestedReaderChild.cjs'), 'valid', String(options?.cwd)], options));
  const credentials = jest.fn(async () => ({ accessKeyId: 'synthetic-access', secretAccessKey: 'synthetic-secret',
    sessionToken: 'synthetic-token', expiration: new Date(Date.now() + 120000).toISOString() }));
  const service = new AttestedReporterVerification(reportPersistenceService, {
    pythonExecutable: '/explicit/pinned/python', moduleRoot: os.tmpdir(), port: 15003,
    keyArn: 'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012',
    pcrs: { '0': '11'.repeat(48), '1': '22'.repeat(48), '2': '33'.repeat(48) }, credentials,
  });
  try {
    const app = express(); app.use(express.json());
    app.use('/api/whistleblower', createAttestedReporterVerificationRouter(service));
    const read = () => request(app).post('/api/whistleblower/status/access/verification').set('X-Reporter-Credential', code).send({});
    const result = await read();
    expect(result.status).toBe(200);
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.body).toEqual({ success: true, verification: { credibilityScore: 80, category: 'synthetic' } });
    expect(spawn).toHaveBeenCalledTimes(1); expect(credentials).toHaveBeenCalledTimes(1); expect(unwrap).not.toHaveBeenCalled();
    await reports.updateOne({ trackingId: fixtureId }, { $set: { 'reporterAccess.hash': reporterCodeHash(rotated) } });
    const denied = await read();
    expect(denied.status).toBe(404);
    expect(denied.body).toEqual({ success: false, error: 'Not found' });
    expect(spawn).toHaveBeenCalledTimes(1); expect(credentials).toHaveBeenCalledTimes(1);
  } finally { await service.close(); }
});
