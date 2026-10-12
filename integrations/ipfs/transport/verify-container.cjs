const assert = require('node:assert/strict');
const { randomBytes, createCipheriv, createDecipheriv } = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const { main } = require('../../../scripts/start-ipfs-transport.cjs');

const origin = 'http://127.0.0.1:15002';
async function request(path, method = 'GET', body) {
  const response = await fetch(origin + path, {
    method, body, headers: { Connection: 'close' }, redirect: 'error', signal: AbortSignal.timeout(30_000),
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  // The peer's socket must complete teardown before its single slot is reused.
  await new Promise(r => setTimeout(r, 50));
  return { status: response.status, bytes };
}
async function deniedAddress(address, port) {
  await new Promise((resolve, reject) => {
    const socket = net.connect({ host: address, port });
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Unexpected non-loopback listener')); });
    socket.once('error', resolve); socket.once('timeout', () => { socket.destroy(); resolve(); });
  });
}
async function verify() {
  assert.equal((await request('/health')).status, 204);
  for (const path of ['/api/v0/config', '/api/v0/shutdown', '/api/v0/pin/rm', '/cat?arg=anything']) {
    assert.equal((await request(path, 'POST', Buffer.from('rejected'))).status, 404);
  }
  assert.equal((await request('/cat', 'POST', Buffer.from('../invalid'))).status, 400);
  const plaintext = randomBytes(1024 * 1024);
  const key = randomBytes(32); const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const added = await request('/add', 'POST', ciphertext);
  assert.equal(added.status, 200);
  const cid = JSON.parse(added.bytes.toString()).cid;
  const read = await request('/cat', 'POST', Buffer.from(cid));
  assert.equal(read.status, 200); assert.deepEqual(read.bytes, ciphertext);
  const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAuthTag(cipher.getAuthTag());
  assert.deepEqual(Buffer.concat([decipher.update(read.bytes), decipher.final()]), plaintext);
  for (const iface of Object.values(os.networkInterfaces()).flat()) {
    if (!iface.internal && iface.family === 'IPv4') await deniedAddress(iface.address, 15002);
  }
  await deniedAddress('127.0.0.1', 5001); await deniedAddress('127.0.0.1', 8080);
  key.fill(0); plaintext.fill(0);
  console.log(JSON.stringify({ transport: 'bridge-container-unix-vsock', bytes: ciphertext.length, cid, accepted: true }));
}
if (process.argv[2] === '--client' && process.env.VERA_TRANSPORT_CHECK === 'child-failure') process.exit(42);
else if (process.argv[2] === '--client') verify().then(() => {
  // The wrapper treats an unexpectedly exiting workload as a failure. Signal
  // its normal coordinated shutdown after successful verification instead.
  process.kill(process.ppid, 'SIGTERM');
}).catch(() => { console.error('Container transport verification failed'); process.exit(1); });
else main(process.execPath, [__filename, '--client']).catch(() => {
  console.error('Container transport startup failed'); process.exit(1);
});
