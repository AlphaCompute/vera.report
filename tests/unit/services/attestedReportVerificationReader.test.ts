import processes = require('node:child_process');
import path from 'node:path';
import os from 'node:os';
import { AttestedReportVerificationReader, type AttestedVerificationReaderOptions } from '../../../src/services/attestedReportVerificationReader';

const trackingId = 'VRA-1234567890ABCDEF';
const stored = { key: 'enc:kms:v2:' + Buffer.from('synthetic-wrapper').toString('base64'),
  iv: Buffer.alloc(12).toString('base64'), tag: Buffer.alloc(16).toString('base64'), data: Buffer.from('synthetic-ciphertext').toString('base64') };
const value = 'private:v1:' + JSON.stringify(stored);
const originalSpawn = processes.spawn;
let reader: AttestedReportVerificationReader | undefined;
let spawn: jest.SpyInstance;
let mode = 'valid';
let children: processes.ChildProcess[];
const options = (): AttestedVerificationReaderOptions => ({
  pythonExecutable: '/explicit/pinned/python', moduleRoot: os.tmpdir(), port: 15003,
  keyArn: 'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012',
  pcrs: { '0': '1'.repeat(96), '1': '2'.repeat(96), '2': '3'.repeat(96) },
  loadAuthorized: jest.fn(async () => ({ trackingId, verification: value })),
  credentials: jest.fn(async () => ({ accessKeyId: 'synthetic-access', secretAccessKey: 'synthetic-secret',
    sessionToken: 'synthetic-token', expiration: new Date(Date.now() + 60000).toISOString() })),
});
beforeEach(() => {
  mode = 'valid'; children = [];
  spawn = jest.spyOn(processes, 'spawn').mockImplementation((_executable, _args, spawnOptions) => {
    const child = originalSpawn(process.execPath, [path.resolve('tests/helpers/attestedReaderChild.cjs'), mode, String(spawnOptions?.cwd)], spawnOptions);
    children.push(child);
    return child;
  });
});
afterEach(async () => { await reader?.close(); reader = undefined; spawn?.mockRestore(); });

test('authorizes exact report before credentials and uses a private bounded process without inherited secrets', async () => {
  const config = options(); reader = new AttestedReportVerificationReader(config);
  expect(await reader.read(trackingId)).toEqual({ credibilityScore: 80, category: 'synthetic' });
  expect(config.loadAuthorized).toHaveBeenCalledWith(trackingId, expect.any(AbortSignal));
  expect((config.loadAuthorized as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan((config.credentials as jest.Mock).mock.invocationCallOrder[0]);
  const [executable, args, spawnOptions] = spawn.mock.calls[0];
  expect(executable).toBe('/explicit/pinned/python');
  expect(args).toEqual(['-E', '-s', '-m', 'enclave.verification.read_report_verification']);
  expect(spawnOptions.env).toEqual({ PATH: '/usr/bin:/bin' });
  expect(spawnOptions.cwd).toBe(config.moduleRoot);
  expect(JSON.stringify(spawn.mock.calls)).not.toContain('synthetic-secret');
});

test.each([null, { trackingId: 'VRA-AAAAAAAAAAAAAAAA', verification: value }])('denies absent or mismatched authorized record before credentials/transport', async report => {
  const config = options(); config.loadAuthorized = jest.fn(async () => report);
  reader = new AttestedReportVerificationReader(config);
  await expect(reader.read(trackingId)).rejects.toThrow('Report verification reader unavailable');
  expect(config.credentials).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
});

test.each(['plaintext', 'private:v2:{}', 'private:v1:' + JSON.stringify({ ...stored, key: 'enc:kms:v1:YWJj' }),
  'private:v1:' + JSON.stringify({ ...stored, key: 'enc:local:v1:YWJj' }),
  'private:v1:' + JSON.stringify({ ...stored, key: 'enc:kms:recipient:v1:YWJj' }),
  'private:v1:' + JSON.stringify({ ...stored, field: 'different' }),
  'private:v1:' + JSON.stringify({ ...stored, tag: Buffer.alloc(4).toString('base64') }),
  'private:v1:' + JSON.stringify({ ...stored, data: 'YR==' })])('refuses unsupported/malformed fields before credentials', async verification => {
  const config = options(); config.loadAuthorized = jest.fn(async () => ({ trackingId, verification }));
  reader = new AttestedReportVerificationReader(config);
  await expect(reader.read(trackingId)).rejects.toThrow('Report verification reader unavailable');
  expect(config.credentials).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
});

test.each(['stderr', 'oversized', 'malformed', 'invalid-utf8'])('rejects %s subprocess output without fallback or diagnostics', async failure => {
  mode = failure; reader = new AttestedReportVerificationReader(options());
  await expect(reader.read(trackingId)).rejects.toThrow(/^Report verification reader unavailable$/);
  expect(spawn).toHaveBeenCalledTimes(1);
  expect(children[0].exitCode !== null || children[0].signalCode !== null).toBe(true);
});

test('close kills and drains a real pending child, refuses concurrent/new reads and emits no late result', async () => {
  mode = 'hanging'; reader = new AttestedReportVerificationReader(options());
  const pending = reader.read(trackingId).catch(error => error);
  await expect(reader.read(trackingId)).rejects.toThrow('Report verification reader unavailable');
  while (!children.length) await new Promise<void>(resolve => setImmediate(resolve));
  const child = children[0];
  await reader.close();
  expect((await pending).message).toBe('Report verification reader unavailable');
  expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
  await expect(reader.read(trackingId)).rejects.toThrow('Report verification reader unavailable');
  expect(spawn).toHaveBeenCalledTimes(1);
});

test('closure during authorization never discovers credentials or starts a process', async () => {
  const config = options(); let release!: (value: null) => void;
  config.loadAuthorized = jest.fn(() => new Promise(resolve => { release = resolve; }));
  reader = new AttestedReportVerificationReader(config);
  const pending = reader.read(trackingId).catch(error => error);
  await reader.close();
  expect((await pending).message).toBe('Report verification reader unavailable');
  expect((config.loadAuthorized as jest.Mock).mock.calls[0][1].aborted).toBe(true);
  release(null);
  await new Promise<void>(resolve => setImmediate(resolve));
  expect(config.credentials).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
});

test('close does not wait on stalled credentials and their late resolution cannot spawn a child', async () => {
  const config = options(); let release!: (value: Awaited<ReturnType<typeof config.credentials>>) => void;
  const supplied = await config.credentials(new AbortController().signal);
  config.credentials = jest.fn(() => new Promise(resolve => { release = resolve; }));
  reader = new AttestedReportVerificationReader(config);
  const pending = reader.read(trackingId).catch(error => error);
  while (!release) await new Promise<void>(resolve => setImmediate(resolve));
  await reader.close();
  expect((await pending).message).toBe('Report verification reader unavailable');
  expect((config.credentials as jest.Mock).mock.calls[0][0].aborted).toBe(true);
  release(supplied);
  await new Promise<void>(resolve => setImmediate(resolve));
  expect(spawn).not.toHaveBeenCalled();
});

test('whole-read deadline rejects an unresolved authorization callback without opening transport', async () => {
  jest.useFakeTimers();
  try {
    const config = options(); config.loadAuthorized = jest.fn(() => new Promise(() => {}));
    reader = new AttestedReportVerificationReader(config);
    const pending = reader.read(trackingId).catch(error => error);
    await jest.advanceTimersByTimeAsync(60_000);
    expect((await pending).message).toBe('Report verification reader unavailable');
    expect((config.loadAuthorized as jest.Mock).mock.calls[0][1].aborted).toBe(true);
    expect(config.credentials).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
    await reader.close();
  } finally { jest.useRealTimers(); }
});

test('the process deadline kills and drains a real stalled child before rejecting', async () => {
  mode = 'hanging';
  const originalTimeout = global.setTimeout;
  const timeout = jest.spyOn(global, 'setTimeout').mockImplementation(((callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) =>
    originalTimeout(callback, delay === 60_000 ? 25 : delay, ...args)) as typeof setTimeout);
  try {
    reader = new AttestedReportVerificationReader(options());
    await expect(reader.read(trackingId)).rejects.toThrow(/^Report verification reader unavailable$/);
    expect(timeout.mock.calls.some(([, delay]) => delay === 60_000)).toBe(true);
    expect(children[0].exitCode !== null || children[0].signalCode !== null).toBe(true);
    expect(spawn).toHaveBeenCalledTimes(1);
  } finally { timeout.mockRestore(); }
});
