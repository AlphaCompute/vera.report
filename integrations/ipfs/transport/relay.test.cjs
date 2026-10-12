const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { randomBytes, createHash } = require('node:crypto');
const { mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { once } = require('node:events');
const { createRelay } = require('../../../scripts/ipfs-loopback-relay.cjs');

async function setup(t, handler, opts = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'vera-relay-'));
  const path = join(dir, 'peer.sock');
  const sockets = new Set();
  const peer = net.createServer({ allowHalfOpen: true }, s => {
    sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); handler(s);
  });
  peer.listen(path); await once(peer, 'listening');
  const relay = await createRelay({ socketPath: path, port: 0, ...opts });
  t.after(async () => {
    await relay.close(); for (const s of sockets) s.destroy();
    await new Promise(r => peer.close(r)); await rm(dir, { recursive: true, force: true });
  });
  function connect() {
    const s = net.connect(relay.server.address().port, '127.0.0.1');
    s.on('error', () => {}); return s;
  }
  return { connect, relay, path };
}

test('streams a large half-closed request and delayed response through real sockets', { timeout: 15000 }, async t => {
  const bytes = randomBytes(8 * 1024 * 1024);
  const expected = createHash('sha256').update(bytes).digest('hex');
  const { connect, relay } = await setup(t, s => {
    s.pause(); setTimeout(() => s.resume(), 100);
    const hash = createHash('sha256');
    s.on('data', b => hash.update(b));
    s.on('end', () => { assert.equal(hash.digest('hex'), expected); s.end(bytes); });
  });
  assert.equal(relay.server.address().address, '127.0.0.1');
  const client = connect(); await once(client, 'connect');
  assert.equal(client.write(bytes), false, 'large producer must encounter stream backpressure');
  client.end(); client.pause();
  const hash = createHash('sha256'); let total = 0;
  client.on('data', b => { total += b.length; hash.update(b); });
  const ended = once(client, 'end'); setTimeout(() => client.resume(), 150);
  await ended;
  assert.equal(total, bytes.length); assert.equal(hash.digest('hex'), expected);
});

test('immediate reconnects after upstream EOF never lose the next response', { timeout: 10000 }, async t => {
  let attempt = 0;
  const { connect } = await setup(t, s => { if (++attempt % 2 === 1) s.destroy(); else s.end('ready'); });
  for (let i = 0; i < 50; i++) {
    const first = connect(); await once(first, 'close');
    const second = connect(); const chunks = []; second.on('data', b => chunks.push(b));
    await once(second, 'end'); assert.equal(Buffer.concat(chunks).toString(), 'ready');
    // Deliberately reconnect on EOF, without waiting for local close callbacks.
  }
});

test('one paused admission waits for upstream teardown; a third connection is rejected', { timeout: 5000 }, async t => {
  let accepted;
  let count = 0;
  const ready = new Promise(r => { accepted = r; });
  const { connect, relay } = await setup(t, s => {
    if (++count === 1) accepted(s);
    else { assert.equal(count, 2); s.end('after-reset'); }
  });
  const first = connect(); const peer = await ready;
  const peerEnded = once(peer, 'end'); peer.resume();
  const secondAccepted = once(relay.server, 'connection');
  const second = connect(); const chunks = []; second.on('data', b => chunks.push(b));
  const secondEnded = once(second, 'end');
  await secondAccepted;
  const third = connect(); await once(third, 'close');
  assert.equal(count, 1, 'queued client must not open a concurrent upstream');
  first.resetAndDestroy(); await peerEnded; peer.destroy();
  await secondEnded;
  assert.equal(Buffer.concat(chunks).toString(), 'after-reset');
});

test('reset queued client releases admission without opening an upstream', { timeout: 5000 }, async t => {
  let count = 0;
  let accepted;
  const ready = new Promise(r => { accepted = r; });
  const { connect, relay } = await setup(t, s => {
    count++;
    if (count === 1) accepted(s);
    else s.end('replacement');
  });
  const first = connect(); const peer = await ready;
  peer.resume();
  const queuedEvent = once(relay.server, 'connection');
  const queued = connect(); const [queuedServer] = await queuedEvent;
  const queuedClosed = new Promise(resolve => queuedServer.once('close', resolve));
  queued.resetAndDestroy(); await queuedClosed;
  assert.equal(count, 1);
  const replacementEvent = once(relay.server, 'connection');
  const replacement = connect(); const chunks = [];
  replacement.on('data', b => chunks.push(b));
  const ended = once(replacement, 'end');
  await replacementEvent;
  const peerEnded = once(peer, 'end'); first.resetAndDestroy(); await peerEnded; peer.destroy();
  await ended;
  assert.equal(Buffer.concat(chunks).toString(), 'replacement'); assert.equal(count, 2);
});

test('global shutdown closes active and queued clients without promoting the queue', { timeout: 5000 }, async t => {
  let count = 0;
  let accepted;
  const ready = new Promise(r => { accepted = r; });
  const { connect, relay } = await setup(t, s => { count++; accepted(s); });
  const first = connect(); const peer = await ready;
  peer.resume(); const peerEnded = once(peer, 'end');
  const queuedEvent = once(relay.server, 'connection');
  const second = connect(); await queuedEvent;
  const firstClosed = once(first, 'close'); const secondClosed = once(second, 'close');
  await relay.close(); await Promise.all([firstClosed, secondClosed, peerEnded]);
  peer.destroy(); assert.equal(count, 1);
});

test('absolute deadline closes a stalled transfer', { timeout: 5000 }, async t => {
  const { connect } = await setup(t, () => {}, { deadlineMs: 100 });
  await once(connect(), 'close');
});

test('missing upstream fails closed', { timeout: 5000 }, async t => {
  const relay = await createRelay({ socketPath: '/no-such-vera-relay/socket', port: 0 });
  t.after(() => relay.close());
  const client = net.connect(relay.server.address().port, '127.0.0.1');
  client.on('error', () => {}); await once(client, 'close');
});

test('startup rejects invalid activation and non-API use before creating a listener', async () => {
  const { main } = require('../../../scripts/start-ipfs-transport.cjs');
  await assert.rejects(main('node', [], { VERA_IPFS_TRANSPORT_ENABLED: 'yes', RUN_MODE: 'api' }), /Invalid/);
  await assert.rejects(main('node', [], { VERA_IPFS_TRANSPORT_ENABLED: '1', RUN_MODE: 'bot' }), /API runtime/);
});
