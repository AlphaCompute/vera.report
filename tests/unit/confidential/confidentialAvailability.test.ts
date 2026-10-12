import express from 'express';
import request from 'supertest';
import { PERMANENT_FAILURE_ATTEMPTS, createConfidentialAvailability } from '../../../src/services/confidentialAvailability';
import { confidentialIntakeOnly } from '../../../src/middleware/confidentialIntakeOnly';
import { securityHeaders } from '../../../src/middleware/security';

const original = process.env.CONFIDENTIAL_CASES_ENABLED;
afterEach(() => {
  if (original === undefined) delete process.env.CONFIDENTIAL_CASES_ENABLED;
  else process.env.CONFIDENTIAL_CASES_ENABLED = original;
});

test.each(['missing manifest', 'Mongo unavailable', 'RPC binding failure'])('%s closes confidential operations without taking down health or allowing plaintext', async failure => {
  process.env.CONFIDENTIAL_CASES_ENABLED = 'true';
  const parsed = jest.fn(), reportFailure = jest.fn();
  const runtime = createConfidentialAvailability(async () => { throw new Error(failure); }, reportFailure);
  const app = express();
  app.use(securityHeaders);
  app.post('/api/whistleblower/submit', confidentialIntakeOnly);
  app.get('/health', (_req, res) => { res.json({ confidential: runtime.status() }); });
  app.use('/api/confidential', runtime.admission);
  app.use(express.json({ verify: parsed }));
  app.post('/api/confidential/channel/call', (_req, res) => { res.sendStatus(204); });
  await runtime.settled;
  await request(app).get('/health').expect(200, { confidential: 'unavailable' });
  const result = await request(app).post('/api/confidential/channel/call').send({ ciphertext: 'synthetic' }).expect(503);
  expect(result.headers['x-content-type-options']).toBe('nosniff');
  expect(result.text).not.toContain(failure);
  await request(app).post('/api/whistleblower/submit').send({ report: 'PRIVATE-SENTINEL' }).expect(409);
  expect(parsed).not.toHaveBeenCalled();
  await expect(runtime.get()).rejects.toThrow('Confidential service unavailable');
  expect(reportFailure).toHaveBeenCalledTimes(1);
  await runtime.close();
});

test('starting and closed resources cannot admit requests, including shutdown during initialization', async () => {
  let finish!: (value: { value: string; close: () => Promise<void> }) => void;
  const close = jest.fn(async () => {});
  const runtime = createConfidentialAvailability(() => new Promise(resolve => { finish = resolve; }), jest.fn());
  const app = express(); app.use(runtime.admission); app.get('/', (_req, res) => { res.sendStatus(204); });
  await request(app).get('/').expect(503);
  const closing = runtime.close();
  finish({ value: 'resource', close });
  await closing;
  expect(runtime.status()).toBe('closed');
  expect(close).toHaveBeenCalledTimes(1);
  await runtime.close();
  expect(close).toHaveBeenCalledTimes(1);
  await request(app).get('/').expect(503);
});

test('a successfully initialized resource admits requests until closed', async () => {
  const close = jest.fn(async () => {});
  const runtime = createConfidentialAvailability(async () => ({ value: 'ready-store', close }), jest.fn());
  await runtime.settled;
  expect(await runtime.get()).toBe('ready-store');
  const app = express(); app.use(runtime.admission); app.get('/', (_req, res) => { res.sendStatus(204); });
  await request(app).get('/').expect(204);
  await runtime.close();
  await request(app).get('/').expect(503);
  expect(close).toHaveBeenCalledTimes(1);
});

test('retries transient initialization failures while denying intake, then becomes ready', async () => {
  jest.useFakeTimers();
  const close = jest.fn(async () => {});
  const initialize = jest.fn().mockRejectedValueOnce(new Error('database temporarily unavailable'))
    .mockRejectedValueOnce(new Error('database still unavailable')).mockResolvedValue({ value: 'recovered', close });
  const runtime = createConfidentialAvailability(initialize, jest.fn());
  try {
    await runtime.settled;
    expect(runtime.status()).toBe('unavailable');
    await expect(runtime.get()).rejects.toThrow('Confidential service unavailable');
    await jest.advanceTimersByTimeAsync(4999);
    expect(initialize).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    expect(initialize).toHaveBeenCalledTimes(2);
    expect(runtime.status()).toBe('unavailable');
    await jest.advanceTimersByTimeAsync(10000);
    expect(await runtime.get()).toBe('recovered');
    expect(runtime.status()).toBe('ready');
    await jest.advanceTimersByTimeAsync(120000);
    expect(initialize).toHaveBeenCalledTimes(3);
  } finally { await runtime.close(); jest.useRealTimers(); }
  expect(close).toHaveBeenCalledTimes(1);
});

test('shutdown cancels scheduled retries', async () => {
  jest.useFakeTimers();
  const initialize = jest.fn().mockRejectedValue(new Error('unavailable'));
  const runtime = createConfidentialAvailability(initialize, jest.fn());
  try {
    await runtime.settled;
    await runtime.close();
    await jest.advanceTimersByTimeAsync(120000);
    expect(initialize).toHaveBeenCalledTimes(1);
    expect(runtime.status()).toBe('closed');
  } finally { await runtime.close(); jest.useRealTimers(); }
});

test('shutdown waits for a retry in flight and closes its late resource exactly once', async () => {
  jest.useFakeTimers();
  let finish!: (value: { value: string; close: () => Promise<void> }) => void;
  const close = jest.fn(async () => {});
  const initialize = jest.fn().mockRejectedValueOnce(new Error('unavailable'))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const runtime = createConfidentialAvailability(initialize, jest.fn());
  try {
    await runtime.settled;
    await jest.advanceTimersByTimeAsync(5000);
    expect(initialize).toHaveBeenCalledTimes(2);
    let stopped = false;
    const stopping = runtime.close().then(() => { stopped = true; });
    await Promise.resolve();
    expect(stopped).toBe(false);
    finish({ value: 'late resource', close });
    await stopping;
    expect(runtime.status()).toBe('closed');
    expect(close).toHaveBeenCalledTimes(1);
    await runtime.close();
    expect(close).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(120000);
    expect(initialize).toHaveBeenCalledTimes(2);
  } finally { jest.useRealTimers(); }
});

test('permanent failures stop after three attempts, report once and keep the service closed', async () => {
  jest.useFakeTimers();
  const initialize = jest.fn().mockRejectedValue(new Error('configuration invalid'));
  const failed = jest.fn(), abandoned = jest.fn();
  const runtime = createConfidentialAvailability(initialize, failed, { permanent: () => true, onAbandoned: abandoned });
  try {
    await runtime.settled;
    await jest.advanceTimersByTimeAsync(5000);
    expect(initialize).toHaveBeenCalledTimes(2);
    expect(abandoned).not.toHaveBeenCalled();
    await jest.advanceTimersByTimeAsync(10000);
    expect(initialize).toHaveBeenCalledTimes(PERMANENT_FAILURE_ATTEMPTS);
    expect(abandoned).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(24 * 60 * 60_000);
    expect(initialize).toHaveBeenCalledTimes(3);
    expect(failed).toHaveBeenCalledTimes(3);
    expect(abandoned).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
    expect(runtime.status()).toBe('unavailable');
    await expect(runtime.get()).rejects.toThrow('Confidential service unavailable');
    const app = express(); app.use(runtime.admission); app.get('/', (_req, res) => { res.sendStatus(204); });
    await request(app).get('/').expect(503);
  } finally { await runtime.close(); jest.useRealTimers(); }
});

test('transient failures keep retrying and reset the permanent-failure count', async () => {
  jest.useFakeTimers();
  const kinds = ['permanent', 'permanent', 'transient', 'permanent', 'permanent', ...Array(20).fill('transient')];
  let current = '';
  const initialize = jest.fn(async () => { current = kinds.shift() ?? 'transient'; throw new Error(current); });
  const abandoned = jest.fn();
  const runtime = createConfidentialAvailability(initialize, jest.fn(), { permanent: () => current === 'permanent', onAbandoned: abandoned });
  try {
    await runtime.settled;
    await jest.advanceTimersByTimeAsync(30 * 60_000);
    expect(initialize.mock.calls.length).toBeGreaterThan(20);
    expect(abandoned).not.toHaveBeenCalled();
    expect(runtime.status()).toBe('unavailable');
  } finally { await runtime.close(); jest.useRealTimers(); }
});

test('a throwing classifier or abandonment reporter cannot break availability', async () => {
  jest.useFakeTimers();
  const initialize = jest.fn().mockRejectedValue(new Error('unavailable'));
  const runtime = createConfidentialAvailability(initialize, jest.fn(), { permanent: () => { throw new Error('classifier'); } });
  try {
    await runtime.settled;
    await jest.advanceTimersByTimeAsync(5 * 60_000);
    expect(initialize.mock.calls.length).toBeGreaterThan(PERMANENT_FAILURE_ATTEMPTS);
  } finally { await runtime.close(); jest.useRealTimers(); }
  jest.useFakeTimers();
  const second = createConfidentialAvailability(jest.fn().mockRejectedValue(new Error('x')), jest.fn(),
    { permanent: () => true, onAbandoned: () => { throw new Error('logger'); } });
  try {
    await second.settled;
    await jest.advanceTimersByTimeAsync(60_000);
    expect(second.status()).toBe('unavailable');
  } finally { await second.close(); jest.useRealTimers(); }
});
