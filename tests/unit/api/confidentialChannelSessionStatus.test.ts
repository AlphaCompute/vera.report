/**
 * Channel calls the enclave refuses before any work (no ready session for the
 * nonce) are the client's to resolve, not outages: a missing session answers
 * 410, a busy one 409. Every other enclave or transport failure stays 503, and
 * the relay counts outcomes without recording anything about the request.
 */
import express from 'express';
import request from 'supertest';
import { createConfidentialChannelRouter } from '../../../src/api/confidentialChannel';
import { createChannelOutcomeCounter } from '../../../src/utils/confidentialChannelOutcomes';
import type { ChannelOutcome } from '../../../src/utils/confidentialChannelOutcomes';
import { RelayHttpError, channelFailure, throwIfThrottled } from '../../../lib/confidential/client';

let nonceCounter = 0;
const freshNonce = () => (++nonceCounter).toString(16).padStart(64, '0');

function stack(transport: (request: unknown) => Promise<unknown>, maxPerMinute = 10_000) {
  const outcomes: ChannelOutcome[] = [];
  const app = express();
  app.use('/api/confidential', createConfidentialChannelRouter(transport,
    { maxPerMinute, onOutcome: outcome => outcomes.push(outcome) }));
  return { app, outcomes };
}
const call = (app: express.Express) => request(app).post('/api/confidential/channel/call')
  .set('Content-Type', 'application/json').send({ nonce: freshNonce(), ciphertext: 'opaque' });

describe('channel call status for enclave refusals', () => {
  test.each([
    [{ error: 'unavailable', sessionClosed: true, session: 'missing' }, 410, 'call_session_missing'],
    [{ error: 'unavailable', sessionClosed: false, session: 'busy' }, 409, 'call_session_busy'],
    // A failure while the request ran also closes the session, but is not labelled.
    [{ error: 'unavailable', sessionClosed: true }, 503, 'call_enclave_error'],
    [{ error: 'unavailable', sessionClosed: false }, 503, 'call_enclave_error'],
    // Only the two known labels change the status.
    [{ error: 'unavailable', sessionClosed: true, session: 'other' }, 503, 'call_enclave_error'],
  ])('%j answers %i', async (reply, status, outcome) => {
    const { app, outcomes } = stack(async () => reply);
    const response = await call(app).expect(status);
    expect(response.headers['retry-after']).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toMatch(/[a-f0-9]{64}|opaque/);
    expect(outcomes).toEqual([outcome]);
  });

  test('a transport failure stays 503', async () => {
    const { app, outcomes } = stack(async () => { throw new Error('ECONNREFUSED'); });
    await call(app).expect(503);
    expect(outcomes).toEqual(['call_transport_error']);
  });

  test('successful opens and calls are counted', async () => {
    const { app, outcomes } = stack(async () => ({ document: 'doc', publicKey: 'key', ciphertext: 'reply', sessionOpen: false }));
    await request(app).post('/api/confidential/channel/open').set('Content-Type', 'application/json')
      .send({ nonce: freshNonce() }).expect(200);
    await call(app).expect(200);
    expect(outcomes).toEqual(['open_ok', 'call_ok']);
  });

  test('requests refused by the per-minute limiter are counted with the same response', async () => {
    const { app, outcomes } = stack(async () => ({ document: 'doc', publicKey: 'key', ciphertext: 'reply', sessionOpen: false }), 1);
    await call(app).expect(200);
    const limited = await call(app).expect(429);
    expect(limited.body).toEqual({ error: 'Too many requests, please try again later.' });
    await request(app).post('/api/confidential/channel/open').set('Content-Type', 'application/json')
      .send({ nonce: freshNonce() }).expect(429);
    expect(outcomes).toEqual(['call_ok', 'call_rate_limited', 'open_rate_limited']);
  });

  test('the browser treats 410 and 409 like any other relay failure', () => {
    const response = (status: number) => ({ status, headers: new Headers() });
    for (const status of [409, 410]) {
      expect(() => throwIfThrottled(response(status))).not.toThrow();
      expect(channelFailure(new RelayHttpError(status)).reason).toBe('unavailable');
    }
  });
});

describe('channel outcome counter', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test('emits one count-only line per busy minute and nothing when idle', () => {
    const emit = jest.fn();
    const counter = createChannelOutcomeCounter(emit, 60_000);
    jest.advanceTimersByTime(180_000);
    expect(emit).not.toHaveBeenCalled();
    counter.record('call_ok'); counter.record('call_ok'); counter.record('call_session_missing');
    jest.advanceTimersByTime(60_000);
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenLastCalledWith({ source: 'confidential-relay', windowSeconds: 60, call_ok: 2, call_session_missing: 1 });
    jest.advanceTimersByTime(120_000);
    expect(emit).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
  });

  test('close flushes pending counts', () => {
    const emit = jest.fn();
    const counter = createChannelOutcomeCounter(emit, 60_000);
    counter.record('open_ok');
    counter.close();
    expect(emit).toHaveBeenCalledWith({ source: 'confidential-relay', windowSeconds: 60, open_ok: 1 });
    expect(jest.getTimerCount()).toBe(0);
  });
});
