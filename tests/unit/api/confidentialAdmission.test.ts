import express from 'express';
import request from 'supertest';
import { CHANNEL_ADMISSION, createChannelAdmission, createUploadAdmission, STAGING_CLIENT_HOURLY_BYTES, STAGING_PROCESS_DAILY_BYTES } from '../../../src/utils/confidentialAdmission';
import { createConfidentialChannelRouter } from '../../../src/api/confidentialChannel';

test('the default 600-per-minute budget is shared by opens and calls and refuses excess before transport', async () => {
  const transport = jest.fn(async (raw: unknown) => (raw as { op: string }).op === 'open'
    ? { document: 'synthetic', publicKey: 'synthetic' }
    : { ciphertext: 'synthetic', sessionClosed: true });
  const app = express();
  app.use('/api/confidential', createConfidentialChannelRouter(transport));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  for (let index = 0; index < 300; index++) {
    await request(app).post('/api/confidential/channel/open').send({ nonce: nonce(index) }).expect(200);
    await request(app).post('/api/confidential/channel/call')
      .send({ nonce: nonce(index), ciphertext: 'opaque', last: true }).expect(200);
  }
  const open = await request(app).post('/api/confidential/channel/open').send({ nonce: nonce(301) }).expect(429);
  expect(open.headers['ratelimit-limit']).toBe('600');
  expect(open.headers['ratelimit-remaining']).toBe('0');
  expect(Number(open.headers['retry-after'])).toBeGreaterThan(0);
  await request(app).post('/api/confidential/channel/call')
    .send({ nonce: nonce(299), ciphertext: 'opaque', last: true }).expect(429);
  expect(transport).toHaveBeenCalledTimes(600);
}, 30_000);

test('one client cannot park the global channel capacity; failures retain bounded leases until expiry', () => {
  let now = 0;
  const admission = createChannelAdmission(() => now);
  const { perClient, openLease } = CHANNEL_ADMISSION;
  for (let index = 0; index < perClient; index++) expect(admission.reserve(`a${index}`, 'attacker')).toBe(true);
  expect(admission.reserve('extra', 'attacker')).toBe(false);
  expect(admission.reserve('legitimate', 'new-client')).toBe(true);
  // Aborted/ambiguous work does not call complete and remains charged, but an
  // unused open covers possible generation followed by anonymous idle.
  now = openLease - 1;
  expect(admission.reserve('extra', 'attacker')).toBe(false);
  now = openLease;
  expect(admission.reserve('extra', 'attacker')).toBe(true);
  admission.complete('extra', 'wrong-client');
  expect(admission.reserve('b0', 'attacker')).toBe(true);
  admission.complete('extra', 'attacker');
  expect(admission.reserve('b1', 'attacker')).toBe(true);
});
test('global leases bound distributed admission and reject a backwards clock', () => {
  let now = 100;
  const admission = createChannelAdmission(() => now);
  for (let index = 0; index < CHANNEL_ADMISSION.capacity; index++) expect(admission.reserve(String(index), String(index))).toBe(true);
  expect(admission.reserve('overflow', 'another')).toBe(false);
  now = 0;
  expect(admission.reserve('rollback', 'another')).toBe(false);
});
test('a session the enclave keeps open renews its lease, up to the absolute lifetime', () => {
  let now = 0;
  const admission = createChannelAdmission(() => now);
  const { perClient, openLease, renewLease, maxLease } = CHANNEL_ADMISSION;
  for (let index = 0; index < perClient; index++) expect(admission.reserve(`s${index}`, 'firm')).toBe(true);
  // A multi-range download keeps s0 busy well past the anonymous window.
  for (now = 1_000; now < maxLease; now += 30_000) admission.renew('s0', 'firm');
  // s1..s3 were never used and expired; s0 is still charged until maxLease.
  now = maxLease - 1;
  for (let index = 1; index < perClient; index++) expect(admission.reserve(`n${index}`, 'firm')).toBe(true);
  expect(admission.reserve('over', 'firm')).toBe(false);
  now = maxLease;
  expect(admission.reserve('over', 'firm')).toBe(true);
  // Renewal by another client or for an unknown nonce changes nothing.
  admission.renew('over', 'someone-else'); admission.renew('unknown', 'firm');
  now = maxLease + openLease;
  expect(admission.reserve('after', 'firm')).toBe(true);
  expect(renewLease).toBeGreaterThan(60_000);
});

test('slow generation remains charged beyond the old forty-second lease', () => {
  let now = 0;
  const admission = createChannelAdmission(() => now);
  for (let i = 0; i < CHANNEL_ADMISSION.perClient; i++) admission.reserve(String(i), 'viewer');
  now = 59_999;
  expect(admission.reserve('while-generating', 'viewer')).toBe(false);
  now += 15_000;
  expect(admission.reserve('while-anonymous-idle', 'viewer')).toBe(false);
});

test('an ambiguous near-expiry call retains its lease without exceeding the lifetime cap', async () => {
  let now = 0;
  const app = express();
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => {
    if ((raw as { op: string }).op === 'call') throw new Error('reply lost after dispatch');
    return { document: 'synthetic', publicKey: 'synthetic' };
  }, { admissionClock: () => now }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  const call = () => request(app).post('/api/confidential/channel/call').send({ nonce: nonce(1), ciphertext: 'opaque' });
  await open(1).expect(200);
  now = CHANNEL_ADMISSION.openedLease - 1;
  await call().expect(503);
  now++;
  for (let i = 2; i <= CHANNEL_ADMISSION.perClient; i++) await open(i).expect(200);
  await open(50).expect(429);
  for (now += 30_000; now < CHANNEL_ADMISSION.maxLease; now += 30_000) await call().expect(503);
  now = CHANNEL_ADMISSION.maxLease - 1;
  for (let i = 2; i <= CHANNEL_ADMISSION.perClient; i++) await open(i + 100).expect(200);
  await open(60).expect(429);
  now++;
  await open(60).expect(200);
});
test('one upload client may submit sixteen maximum-size files, then is byte-limited', () => {
  const admit = createUploadAdmission(() => 0);
  for (let index = 0; index < 16; index++) {
    const release = admit('owner', 12 * 1024 * 1024);
    expect(release).not.toBeNull(); release!();
  }
  expect(STAGING_CLIENT_HOURLY_BYTES).toBe(16 * 12 * 1024 * 1024);
  expect(admit('owner', 1)).toBeNull();
  expect(admit('different-owner', 1)).not.toBeNull();
});
test('upload concurrency, global retained-byte window and client-map memory are bounded', () => {
  const admit = createUploadAdmission(() => 0);
  const first = admit('a', 1)!, second = admit('a', 1)!;
  expect(admit('a', 1)).toBeNull();
  const third = admit('b', 1)!, fourth = admit('c', 1)!;
  expect(admit('d', 1)).toBeNull();
  for (const release of [first, second, third, fourth]) { release(); release(); }
  const fill = createUploadAdmission(() => 0);
  let total = 0;
  for (let index = 0; index < 42; index++) {
    const release = fill(`owner-${index}`, 12 * 1024 * 1024)!; expect(release).not.toBeNull(); release(); total += 12 * 1024 * 1024;
  }
  expect(total).toBeLessThan(STAGING_PROCESS_DAILY_BYTES);
  expect(fill('more', 12 * 1024 * 1024)).toBeNull();
  const clients = createUploadAdmission(() => 0);
  for (let index = 0; index < 4096; index++) clients(String(index), 1)!();
  expect(clients('overflow', 1)).toBeNull();
});
test('relay retains ambiguous failure leases while forwarding cross-replica calls', async () => {
  const app = express(); app.use(express.json());
  let failed = true;
  const transport = jest.fn(async (value: unknown) => {
    if ((value as { op: string }).op === 'call') return { ciphertext: 'opaque-reply' };
    if (failed) throw new Error('ambiguous timeout');
    return { document: 'synthetic', publicKey: 'synthetic' };
  });
  app.use('/api/confidential', createConfidentialChannelRouter(transport));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) await request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) }).expect(503);
  failed = false;
  await request(app).post('/api/confidential/channel/open').send({ nonce: nonce(50) }).expect(429);
  expect(transport).toHaveBeenCalledTimes(CHANNEL_ADMISSION.perClient);
  // This call could have opened on a different API replica; never reject it locally.
  await request(app).post('/api/confidential/channel/call').send({ nonce: nonce(99), ciphertext: 'opaque' }).expect(200);
});

test('HTTP timeout does not free abandoned opens or cause late response writes', async () => {
  const app = express(); app.use(express.json());
  let started!: () => void, finish!: () => void, opens = 0, incoming = 0;
  const admitted = new Promise<void>(resolve => { started = resolve; });
  const gate = new Promise<void>(resolve => { finish = resolve; });
  app.use((_req, res, next) => {
    if (++incoming <= CHANNEL_ADMISSION.perClient) void admitted.then(() => { res.status(408).json({ error: 'Timeout' }); });
    next();
  });
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => {
    if ((raw as { op: string }).op === 'call') return { ciphertext: 'opaque' };
    if (++opens === CHANNEL_ADMISSION.perClient) started();
    await gate;
    return { document: 'synthetic', publicKey: 'synthetic' };
  }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  const statuses = await Promise.all(Array.from({ length: CHANNEL_ADMISSION.perClient }, (_, i) => open(i + 1).then(response => response.status)));
  expect(statuses.every(status => status === 408)).toBe(true);
  finish();
  await new Promise(resolve => setImmediate(resolve));
  await open(50).expect(429);
  // A completed call the enclave reports closed releases its lease.
  await request(app).post('/api/confidential/channel/call').send({ nonce: nonce(1), ciphertext: 'opaque' }).expect(200);
  await open(51).expect(200);
});


test('only enclave-confirmed terminal denial releases a lease; ambiguous/ongoing denials retain it', async () => {
  const app = express(); app.use(express.json());
  let closed = false;
  app.use('/api/confidential', createConfidentialChannelRouter(async raw =>
    (raw as { op: string }).op === 'call' ? { error: 'unavailable', sessionClosed: closed }
      : { document: 'synthetic', publicKey: 'synthetic' }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  const call = () => request(app).post('/api/confidential/channel/call').send({ nonce: nonce(1), ciphertext: 'opaque' });
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) await open(n).expect(200);
  await call().expect(503); await open(50).expect(429);
  closed = true;
  await call().expect(503); await open(50).expect(200);
});

test('a call the enclave reports still open keeps the lease; a closed one releases it', async () => {
  const app = express(); app.use(express.json());
  let open = true;
  app.use('/api/confidential', createConfidentialChannelRouter(async raw =>
    (raw as { op: string }).op === 'call' ? { ciphertext: 'opaque', sessionOpen: open }
      : { document: 'synthetic', publicKey: 'synthetic' }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const post = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) await post(n).expect(200);
  const reply = await request(app).post('/api/confidential/channel/call').send({ nonce: nonce(1), ciphertext: 'opaque' }).expect(200);
  expect(reply.body).toEqual({ ciphertext: 'opaque' });
  await post(50).expect(429);
  open = false;
  await request(app).post('/api/confidential/channel/call').send({ nonce: nonce(1), ciphertext: 'opaque' }).expect(200);
  await post(50).expect(200);
});

test('the relay forwards only a literal last=true hint', async () => {
  const app = express(); app.use(express.json());
  const seen: unknown[] = [];
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => { seen.push(raw); return { ciphertext: 'opaque', sessionOpen: false }; }));
  const nonce = '1'.repeat(64);
  await request(app).post('/api/confidential/channel/call').send({ nonce, ciphertext: 'opaque', last: true }).expect(200);
  await request(app).post('/api/confidential/channel/call').send({ nonce, ciphertext: 'opaque', last: false }).expect(400);
  await request(app).post('/api/confidential/channel/call').send({ nonce, ciphertext: 'opaque', last: 'yes' }).expect(400);
  expect(seen).toEqual([{ op: 'call', nonce, ciphertext: 'opaque', last: true }]);
});

test('a client at its cap reuses the slot of its least recently used idle session, never a busy one', () => {
  let now = 0;
  const admission = createChannelAdmission(() => now);
  const { perClient } = CHANNEL_ADMISSION;
  for (let index = 0; index < perClient; index++) expect(admission.reserve(`s${index}`, 'office')).toBe(true);
  // No session has answered a call yet: nothing is idle, so nothing is evicted.
  expect(admission.idleVictim('office')).toBeNull();
  now = 1_000; admission.renew('s2', 'office');
  now = 2_000; admission.renew('s1', 'office');
  now = 3_000; admission.begin('s2', 'office'); // A call is running on s2 again.
  expect(admission.idleVictim('office')).toBe('s1');
  // The victim is no longer idle, so a concurrent open cannot pick it too.
  expect(admission.idleVictim('office')).toBeNull();
  // Another client's idle sessions are never offered.
  expect(admission.idleVictim('someone-else')).toBeNull();
  admission.complete('s1', 'office');
  expect(admission.reserve('new', 'office')).toBe(true);
  expect(admission.reserve('over', 'office')).toBe(false);
});

test('the relay closes an idle session in the enclave before admitting the same client again', async () => {
  const app = express(); app.use(express.json());
  const seen: { op: string; nonce: string }[] = [];
  let closable = true;
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => {
    const value = raw as { op: string; nonce: string };
    seen.push({ op: value.op, nonce: value.nonce });
    if (value.op === 'close') return { closed: closable };
    if (value.op === 'call') return { ciphertext: 'opaque', sessionOpen: true };
    return { document: 'synthetic', publicKey: 'synthetic' };
  }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) {
    await open(n).expect(200);
    await request(app).post('/api/confidential/channel/call').send({ nonce: nonce(n), ciphertext: 'opaque' }).expect(200);
  }
  await open(50).expect(200);
  expect(seen.filter(item => item.op === 'close')).toEqual([{ op: 'close', nonce: nonce(1) }]);
  // An enclave that refuses to close (busy session) leaves the client at its cap.
  closable = false;
  await open(51).expect(429);
  // A protected challenge can finish before the next open. A refused eviction
  // must not strand the still-charged lease as permanently busy.
  closable = true;
  await open(51).expect(200);
});

test('restoring a refused eviction never marks a concurrent call idle or releases its lease', () => {
  let now = 0;
  const admission = createChannelAdmission(() => now);
  for (let n = 0; n < CHANNEL_ADMISSION.perClient; n++) admission.reserve(`s${n}`, 'office');
  admission.renew('s0', 'office');
  expect(admission.idleVictim('office')).toBe('s0');
  admission.restoreVictim('s0', 'other-client');
  expect(admission.idleVictim('office')).toBeNull();
  admission.restoreVictim('s0', 'office');
  expect(admission.reserve('extra', 'office')).toBe(false);
  expect(admission.idleVictim('office')).toBe('s0');
  admission.begin('s0', 'office');
  admission.restoreVictim('s0', 'office');
  expect(admission.idleVictim('office')).toBeNull();
  expect(admission.reserve('extra', 'office')).toBe(false);
});

test('a confirmed refusal remains retryable when it is the only reclaimable lease', async () => {
  const app = express();
  let ambiguousOpen = false, closable = false;
  const closedNonces: string[] = [];
  app.use('/api/confidential', createConfidentialChannelRouter(async raw => {
    const value = raw as { op: string; nonce: string };
    if (value.op === 'close') { closedNonces.push(value.nonce); return { closed: closable }; }
    if (ambiguousOpen) throw new Error('open reply lost');
    return { document: 'synthetic', publicKey: 'synthetic' };
  }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  await open(1).expect(200);
  // Unknown outcomes remain charged and cannot serve as alternative victims.
  ambiguousOpen = true;
  for (let n = 2; n <= CHANNEL_ADMISSION.perClient; n++) await open(n).expect(503);
  await open(50).expect(429);
  ambiguousOpen = false; closable = true;
  await open(50).expect(200);
  expect(closedNonces).toEqual([nonce(1), nonce(1)]);
});

test('a confirmed but unused open holds the pool only for the enclave anonymous idle window', async () => {
  let now = 0;
  const app = express();
  app.use('/api/confidential', createConfidentialChannelRouter(async raw =>
    (raw as { op: string }).op === 'close' ? { closed: true } : { document: 'synthetic', publicKey: 'synthetic' },
  { admissionClock: () => now }));
  const nonce = (n: number) => n.toString(16).padStart(64, '0');
  const open = (n: number) => request(app).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) await open(n).expect(200);
  // The client's own next open evicts its least recently opened idle session
  // (the enclave confirms the close) instead of being refused.
  await open(10).expect(200);
  // Without enclave confirmation of the close, the cap holds until leases lapse.
  const refusing = express();
  refusing.use('/api/confidential', createConfidentialChannelRouter(async raw =>
    (raw as { op: string }).op === 'close' ? { closed: false } : { document: 'synthetic', publicKey: 'synthetic' },
  { admissionClock: () => now }));
  const openRefusing = (n: number) => request(refusing).post('/api/confidential/channel/open').send({ nonce: nonce(n) });
  for (let n = 1; n <= CHANNEL_ADMISSION.perClient; n++) await openRefusing(n).expect(200);
  await openRefusing(20).expect(429);
  now = CHANNEL_ADMISSION.openedLease - 1;
  await openRefusing(21).expect(429);
  now = CHANNEL_ADMISSION.openedLease;
  await openRefusing(22).expect(200);
  expect(CHANNEL_ADMISSION.openedLease).toBeLessThan(CHANNEL_ADMISSION.openLease);
});
