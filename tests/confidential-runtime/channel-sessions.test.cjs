const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const net = require('node:net');
const { createConfidentialFrameServer } = require('../../enclave/dist/confidential-server.js');
const { generateKey, readKey } = require('../../enclave/dist/confidential/pgp.js');
const { ApplicationChannelIdentity } = require('../../enclave/dist/application-channel-identity.js');
const { createSessionCore, SESSION_LIMITS } = require('../../enclave/dist/application-channel-sessions.js');
const { sealChannelRequest } = require('../../enclave/dist/confidential/channelMessage.js');
const nonce = n => n.toString(16).padStart(64, '0');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const keys = generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic session only' }], format: 'object' });
async function identity(challenge) {
  const k = await keys;
  return new ApplicationChannelIdentity(k.privateKey, { nonce: challenge,
    publicKey: Buffer.from(k.publicKey.write()).toString('base64'), document: 'synthetic-not-AWS' });
}
async function request(service, n = nonce(1)) {
  const evidence = await service.open(n);
  const key = await readKey({ binaryKey: Buffer.from(evidence.publicKey, 'base64') });
  return sealChannelRequest(key, n, new TextEncoder().encode('SYNTHETIC PRIVATE REQUEST'));
}
test('returns evidence/ciphertext only, dispatches once and clears owned body buffers', async t => {
  let calls = 0, received, returned;
  const service = createSessionCore(async body => {
    calls++; received = body;
    assert.equal(new TextDecoder().decode(body), 'SYNTHETIC PRIVATE REQUEST');
    returned = new TextEncoder().encode('SYNTHETIC PRIVATE RESPONSE'); return returned;
  }, identity, () => 0);
  t.after(() => service.close());
  const pending = await request(service);
  const outcomes = await Promise.allSettled([service.execute(nonce(1), pending.ciphertext), service.execute(nonce(1), pending.ciphertext)]);
  assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1);
  const reply = outcomes.find(x => x.status === 'fulfilled').value;
  assert.equal(new TextDecoder().decode(await pending.openResponse(reply)), 'SYNTHETIC PRIVATE RESPONSE');
  assert.equal(calls, 1); assert.ok(received.every(x => x === 0)); assert.ok(returned.every(x => x === 0));
  await assert.rejects(service.execute(nonce(1), pending.ciphertext));
});
test('malformed ciphertext consumes session without dispatch or plaintext diagnostics', async t => {
  let calls = 0;
  const service = createSessionCore(async () => { calls++; return new Uint8Array(); }, identity, () => 0);
  t.after(() => service.close());
  const pending = await request(service);
  await assert.rejects(service.execute(nonce(1), 'sensitive malformed text'), /^Error: Confidential channel unavailable$/);
  await assert.rejects(service.execute(nonce(1), pending.ciphertext));
  assert.equal(calls, 0);
});
test('expired or closed sessions do not dispatch', async t => {
  let time = 0, calls = 0;
  const service = createSessionCore(async () => { calls++; return new Uint8Array(); }, identity, () => time);
  t.after(() => service.close());
  const pending = await request(service);
  time = 60000;
  await assert.rejects(service.execute(nonce(1), pending.ciphertext));
  service.close(); await assert.rejects(service.open(nonce(2)));
  assert.equal(calls, 0);
});
test('reserves slots before asynchronous identity generation and bounds in-flight work', async t => {
  let time = 0, calls = 0;
  const gate = deferred();
  const service = createSessionCore(async () => new Uint8Array(), async n => { calls++; await gate.promise; return identity(n); }, () => time);
  t.after(() => service.close());
  const capacity = SESSION_LIMITS.capacity;
  const openings = Array.from({ length: capacity }, (_, i) => service.open(nonce(i + 1)));
  const settled = Promise.allSettled(openings);
  await assert.rejects(service.open(nonce(capacity + 1)));
  await assert.rejects(service.open(nonce(1)));
  time = 60001;
  await assert.rejects(service.open(nonce(capacity + 2))); // Expired work still occupies its slot until it settles.
  assert.equal(calls, capacity);
  gate.resolve();
  assert.ok((await settled).every(result => result.status === 'rejected'));
  assert.equal((await service.open(nonce(capacity + 2))).nonce, nonce(capacity + 2));
});
test('expiry or closure during dispatch aborts context and suppresses its reply', async t => {
  for (const close of [false, true]) {
    let time = 0, context;
    const started = deferred(), finish = deferred();
    const service = createSessionCore(async (_, ctx) => { context = ctx; started.resolve(); await finish.promise; return new Uint8Array([1]); }, identity, () => time);
    t.after(() => service.close());
    const pending = await request(service);
    const execution = service.execute(nonce(1), pending.ciphertext);
    const rejected = assert.rejects(execution, /^Error: Confidential channel unavailable$/);
    await started.promise;
    if (close) service.close(); else { time = 60001; await service.open(nonce(2)); }
    assert.equal(context.signal.aborted, true);
    finish.resolve(); await rejected;
  }
});
test('failed identity generation frees its reservation and clock rollback fails closed', async t => {
  let fail = true, time = 100;
  const service = createSessionCore(async () => new Uint8Array(), async n => {
    if (fail) throw new Error('private native diagnostic'); return identity(n);
  }, () => time);
  t.after(() => service.close());
  await assert.rejects(service.open(nonce(1)), /^Error: Confidential channel unavailable$/);
  fail = false; await service.open(nonce(1));
  time = 99; await assert.rejects(service.open(nonce(2)));
});
test('handler failures consume the session and release capacity without exposing diagnostics', async t => {
  const service = createSessionCore(async () => { throw new Error('SYNTHETIC PRIVATE HANDLER ERROR'); }, identity, () => 0);
  t.after(() => service.close());
  const pending = await request(service);
  await assert.rejects(service.execute(nonce(1), pending.ciphertext), /^Error: Confidential channel unavailable$/);
  await assert.rejects(service.execute(nonce(1), pending.ciphertext));
  assert.equal((await service.open(nonce(1))).nonce, nonce(1));
});
test('closing during key generation disposes the late credential', async () => {
  const gate = deferred(), credential = await identity(nonce(1));
  const service = createSessionCore(async () => new Uint8Array(), async () => { await gate.promise; return credential; }, () => 0);
  const pending = service.open(nonce(1)), rejected = assert.rejects(pending);
  service.close(); gate.resolve(); await rejected;
  assert.throws(() => credential.getPrivateKey());
});

test('framed denial releases only a completed session, never its concurrent duplicate', async t => {
  const started = deferred(), finish = deferred();
  const service = createSessionCore(async () => {
    started.resolve(); await finish.promise;
    throw new Error('SYNTHETIC PRIVATE DENIAL');
  }, identity, () => 0);
  const server = createConfidentialFrameServer(service);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { finish.resolve(); service.close(); await new Promise(resolve => server.close(resolve)); });
  const pending = await request(service);
  const call = () => new Promise((resolve, reject) => {
    const socket = net.connect(server.address().port, '127.0.0.1');
    const chunks = [];
    socket.on('error', reject);
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => {
      try {
        const reply = Buffer.concat(chunks);
        assert.equal(reply.readUInt32BE(0), reply.length - 4);
        resolve(JSON.parse(reply.subarray(4).toString('utf8')));
      } catch (error) { reject(error); }
    });
    socket.on('connect', () => {
      const body = Buffer.from(JSON.stringify({ op: 'call', nonce: nonce(1), ciphertext: pending.ciphertext }));
      const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
      socket.write(Buffer.concat([header, body]));
    });
  });
  const first = call();
  await started.promise;
  assert.equal(service.hasPendingSession(nonce(1)), true);
  assert.deepEqual(await call(), { error: 'unavailable', sessionClosed: false, session: 'busy' });
  assert.equal(service.hasPendingSession(nonce(1)), true);
  finish.resolve();
  assert.deepEqual(await first, { error: 'unavailable', sessionClosed: true });
  assert.equal(service.hasPendingSession(nonce(1)), false);
});

test('framed calls on a nonce with no session are labelled missing; a handler failure is not', async t => {
  const service = createSessionCore(async () => { throw new Error('SYNTHETIC PRIVATE DENIAL'); }, identity, () => 0);
  const server = createConfidentialFrameServer(service);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { service.close(); await new Promise(resolve => server.close(resolve)); });
  const frame = value => new Promise((resolve, reject) => {
    const socket = net.connect(server.address().port, '127.0.0.1'), chunks = [];
    socket.on('error', reject); socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => { const reply = Buffer.concat(chunks); resolve(JSON.parse(reply.subarray(4).toString('utf8'))); });
    socket.on('connect', () => {
      const body = Buffer.from(JSON.stringify(value)), header = Buffer.alloc(4); header.writeUInt32BE(body.length);
      socket.write(Buffer.concat([header, body]));
    });
  });
  const pending = await request(service);
  assert.deepEqual(await frame({ op: 'call', nonce: nonce(2), ciphertext: pending.ciphertext }),
    { error: 'unavailable', sessionClosed: true, session: 'missing' });
  // The handler ran and failed: the session is gone, but this is not a refusal.
  assert.deepEqual(await frame({ op: 'call', nonce: nonce(1), ciphertext: pending.ciphertext }),
    { error: 'unavailable', sessionClosed: true });
  // The same nonce afterwards has no session.
  assert.deepEqual(await frame({ op: 'call', nonce: nonce(1), ciphertext: pending.ciphertext }),
    { error: 'unavailable', sessionClosed: true, session: 'missing' });
});

async function sealed(service, n) {
  const key = await readKey({ binaryKey: Buffer.from((await service.open(n)).publicKey, 'base64') });
  return async body => sealChannelRequest(key, n, new TextEncoder().encode(body));
}
test('one session serves sequential requests; each needs a fresh request ID', async t => {
  let time = 0, calls = 0;
  const service = createSessionCore(async (body, ctx) => { calls++; ctx.authenticated(); return new TextEncoder().encode('ok'); }, identity, () => time);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  for (let index = 0; index < 5; index++) {
    const pending = await next(`request ${index}`);
    time += 1_000;
    assert.equal(new TextDecoder().decode(await pending.openResponse(await service.execute(nonce(1), pending.ciphertext))), 'ok');
    assert.equal(service.hasPendingSession(nonce(1)), true);
  }
  assert.equal(calls, 5);
  // A replayed ciphertext is refused and closes the session.
  const pending = await next('replayed');
  await service.execute(nonce(1), pending.ciphertext);
  await assert.rejects(service.execute(nonce(1), pending.ciphertext));
  assert.equal(service.hasPendingSession(nonce(1)), false);
  assert.equal(calls, 6);
});
test('concurrent requests on one session are refused without closing the in-flight one', async t => {
  const started = deferred(), finish = deferred();
  const service = createSessionCore(async () => { started.resolve(); await finish.promise; return new Uint8Array([1]); }, identity, () => 0);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  const first = await next('first'), second = await next('second');
  const running = service.execute(nonce(1), first.ciphertext);
  await started.promise;
  await assert.rejects(service.execute(nonce(1), second.ciphertext));
  finish.resolve();
  await first.openResponse(await running);
  assert.equal(service.hasPendingSession(nonce(1)), true);
});
test('unauthenticated sessions expire after the short idle window, authenticated ones later', async t => {
  let time = 0;
  let authenticate = false;
  const service = createSessionCore(async (_, ctx) => { if (authenticate) ctx.authenticated(); return new Uint8Array([1]); }, identity, () => time);
  t.after(() => service.close());
  // Opened and never used: gone after the anonymous idle window.
  await service.open(nonce(1));
  time = SESSION_LIMITS.anonymousIdle;
  assert.equal((await service.open(nonce(1))).nonce, nonce(1)); // The idle session was reclaimed.
  // An anonymous request does not extend past the anonymous window.
  const anonymous = await sealed(service, nonce(2));
  const a = await anonymous('anonymous');
  await service.execute(nonce(2), a.ciphertext);
  time += SESSION_LIMITS.anonymousIdle;
  await assert.rejects(service.execute(nonce(2), (await anonymous('late')).ciphertext));
  // An authenticated request extends the idle window.
  authenticate = true;
  const authed = await sealed(service, nonce(3));
  await service.execute(nonce(3), (await authed('proof')).ciphertext);
  time += SESSION_LIMITS.anonymousIdle + 1;
  authenticate = false;
  await service.execute(nonce(3), (await authed('range')).ciphertext);
  time += SESSION_LIMITS.authenticatedIdle;
  await assert.rejects(service.execute(nonce(3), (await authed('late')).ciphertext));
});
test('absolute lifetime and request count bound a kept-alive session', async t => {
  let time = 0;
  const service = createSessionCore(async (_, ctx) => { ctx.authenticated(); return new Uint8Array([1]); }, identity, () => time);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  while (time + SESSION_LIMITS.authenticatedIdle / 2 < SESSION_LIMITS.maxLifetime) {
    await service.execute(nonce(1), (await next('keepalive')).ciphertext);
    time += SESSION_LIMITS.authenticatedIdle / 2;
  }
  time = SESSION_LIMITS.maxLifetime; // Active well within the idle window, but past the lifetime.
  await assert.rejects(service.execute(nonce(1), (await next('too late')).ciphertext));
  assert.equal(service.hasPendingSession(nonce(1)), false);
});
test('the request count closes a session after its last allowed request', async t => {
  let time = 0;
  const service = createSessionCore(async (_, ctx) => { ctx.authenticated(); return new Uint8Array([1]); }, identity, () => time,
    { maxRequests: 3 });
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  for (let index = 0; index < 3; index++) {
    assert.equal(service.hasPendingSession(nonce(1)), true);
    await service.execute(nonce(1), (await next(`r${index}`)).ciphertext);
  }
  assert.equal(service.hasPendingSession(nonce(1)), false);
});
test('anonymous callers cannot hold the pool: idle sessions are reclaimed for new opens', async t => {
  let time = 0;
  const service = createSessionCore(async () => new Uint8Array([1]), identity, () => time);
  t.after(() => service.close());
  for (let index = 1; index <= SESSION_LIMITS.capacity; index++) await service.open(nonce(index));
  await assert.rejects(service.open(nonce(1000)));
  time = SESSION_LIMITS.anonymousIdle;
  assert.equal((await service.open(nonce(1000))).nonce, nonce(1000));
});
test('a request marked last closes the session after its reply', async t => {
  const service = createSessionCore(async () => new Uint8Array([1]), identity, () => 0);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  await service.execute(nonce(1), (await next('keep')).ciphertext);
  assert.equal(service.hasPendingSession(nonce(1)), true);
  const final = await next('final');
  await final.openResponse(await service.execute(nonce(1), final.ciphertext, { last: true }));
  assert.equal(service.hasPendingSession(nonce(1)), false);
});
test('framed calls carry the last hint and report whether the session stays open', async t => {
  const service = createSessionCore(async () => new Uint8Array([1]), identity, () => 0);
  const server = createConfidentialFrameServer(service);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { service.close(); await new Promise(resolve => server.close(resolve)); });
  const frame = value => new Promise((resolve, reject) => {
    const socket = net.connect(server.address().port, '127.0.0.1'), chunks = [];
    socket.on('error', reject); socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => { const reply = Buffer.concat(chunks); resolve(JSON.parse(reply.subarray(4).toString('utf8'))); });
    socket.on('connect', () => {
      const body = Buffer.from(JSON.stringify(value)), header = Buffer.alloc(4); header.writeUInt32BE(body.length);
      socket.write(Buffer.concat([header, body]));
    });
  });
  const next = await sealed(service, nonce(1));
  const kept = await frame({ op: 'call', nonce: nonce(1), ciphertext: (await next('a')).ciphertext });
  assert.equal(kept.sessionOpen, true);
  assert.deepEqual(await frame({ op: 'call', nonce: nonce(1), ciphertext: (await next('b')).ciphertext, last: false }),
    { error: 'unavailable', sessionClosed: false });
  const closed = await frame({ op: 'call', nonce: nonce(1), ciphertext: (await next('c')).ciphertext, last: true });
  assert.equal(closed.sessionOpen, false);
  assert.equal(service.hasPendingSession(nonce(1)), false);
});
test('the relay may close an idle session but never a busy or generating one', async t => {
  const started = deferred(), finish = deferred(), gate = deferred();
  let hold = false;
  const service = createSessionCore(async () => { if (hold) { started.resolve(); await finish.promise; } return new Uint8Array([1]); },
    async n => { if (n === nonce(3)) await gate.promise; return identity(n); }, () => 0);
  t.after(() => service.close());
  const idle = await sealed(service, nonce(1));
  await service.execute(nonce(1), (await idle('a')).ciphertext);
  assert.equal(service.release(nonce(1)), true);
  assert.equal(service.hasPendingSession(nonce(1)), false);
  hold = true;
  const busy = await sealed(service, nonce(2));
  const running = service.execute(nonce(2), (await busy('b')).ciphertext);
  await started.promise;
  assert.equal(service.release(nonce(2)), false);
  finish.resolve(); await running;
  const generating = service.open(nonce(3));
  assert.equal(service.release(nonce(3)), false);
  gate.resolve(); await generating;
  assert.equal(service.release(nonce(99)), true); // Already gone.
});
test('each session gives its dispatcher one enclave-memory challenge ledger, cleared when the session ends', async t => {
  const ledgers = [];
  const service = createSessionCore(async (_, ctx) => { ledgers.push(ctx.challenges); return new Uint8Array([1]); }, identity, () => 0);
  t.after(() => service.close());
  const first = await sealed(service, nonce(1)), second = await sealed(service, nonce(2));
  await service.execute(nonce(1), (await first('a')).ciphertext);
  ledgers[0].add('ab'.repeat(32), 10, 0);
  await service.execute(nonce(1), (await first('b')).ciphertext);
  await service.execute(nonce(2), (await second('c')).ciphertext);
  assert.equal(ledgers[0], ledgers[1]); // Same session, same ledger.
  assert.notEqual(ledgers[0], ledgers[2]); // A challenge never moves to another session.
  assert.equal(ledgers[2].consume('ab'.repeat(32), 0), false);
  await service.execute(nonce(1), (await first('d')).ciphertext, { last: true });
  assert.equal(ledgers[0].outstanding(0), 0); // Challenges die with the session.
});

test('admission cannot evict a session between its challenge and the signed follow-up', async t => {
  const proofChallenge = nonce(91), stockedChallenge = nonce(92);
  const trustedTime = 1_000; // Deliberately different from the host wall clock.
  let calls = 0;
  const service = createSessionCore(async (body, ctx) => {
    const message = new TextDecoder().decode(body);
    if (message === 'challenge') {
      ctx.challenges.add(proofChallenge, trustedTime + 120_000, trustedTime, true);
      ctx.challenges.add(stockedChallenge, trustedTime + 120_000, trustedTime);
    } else {
      assert.equal(ctx.challenges.consume(proofChallenge, trustedTime), true);
      ctx.authenticated(); calls++;
    }
    return new Uint8Array([1]);
  }, identity, () => 0);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  await service.execute(nonce(1), (await next('challenge')).ciphertext);
  assert.equal(service.release(nonce(1)), false); // Another tab opens while the browser signs.
  await service.execute(nonce(1), (await next('proof')).ciphertext);
  assert.equal(calls, 1);
  assert.equal(service.release(nonce(1)), true); // Unused read stock does not pin an idle workspace.
});

test('initial attestation verification is protected only until the existing idle deadline', async t => {
  let time = 0;
  const service = createSessionCore(async () => new Uint8Array([1]), identity, () => time);
  t.after(() => service.close());
  await service.open(nonce(1));
  assert.equal(service.release(nonce(1)), false);
  time = SESSION_LIMITS.anonymousIdle;
  assert.equal(service.release(nonce(1)), true);
});

test('an abandoned protected follow-up still expires at the unchanged anonymous deadline', async t => {
  let time = 0;
  const service = createSessionCore(async (_, ctx) => {
    ctx.challenges.add(nonce(99), Date.now() + 120_000, Date.now(), true);
    return new Uint8Array([1]);
  }, identity, () => time);
  t.after(() => service.close());
  const next = await sealed(service, nonce(1));
  await service.execute(nonce(1), (await next('challenge')).ciphertext);
  time = SESSION_LIMITS.anonymousIdle;
  assert.equal(service.release(nonce(1)), true);
  assert.equal(service.hasPendingSession(nonce(1)), false);
});
