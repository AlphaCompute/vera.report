'use strict';
// Synthetic negative acceptance through the compiled reader and installed Python.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const tls = require('node:tls');
const { once } = require('node:events');
const { AttestedNarrative } = require('../dist/services/attestedNarrative');
const { AttestedReportVerificationReader } = require('../dist/services/attestedReportVerificationReader');

test('compiled backend rejects unauthenticated reports and untrusted attestation before sending credentials', { timeout: 15000 }, async () => {
  assert.equal(process.getuid(), 1001);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-attested-backend-'));
  const key = path.join(directory, 'key.pem'), cert = path.join(directory, 'cert.pem');
  const requests = [], failures = [], sockets = new Set();
  let server, reader, narrative;
  let credentialLoads = 0;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=synthetic.invalid'], { stdio: 'ignore', timeout: 5000 });
    server = tls.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert), minVersion: 'TLSv1.3' }, socket => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', error => failures.push(error));
      let pending = Buffer.alloc(0);
      socket.on('data', chunk => {
        pending = Buffer.concat([pending, chunk]);
        if (pending.length < 4) return;
        const size = pending.readUInt32BE(0);
        assert.ok(size <= 1024);
        if (pending.length < 4 + size) return;
        assert.equal(pending.length, 4 + size);
        const request = JSON.parse(pending.subarray(4).toString());
        requests.push(request);
        pending = Buffer.alloc(0);
        const body = Buffer.from(JSON.stringify({ id: request.id, result: { document: 'AQ==' } }));
        const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
        socket.write(Buffer.concat([header, body]));
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const options = {
      pythonExecutable: '/opt/vera-attestation/venv/bin/python', moduleRoot: '/opt/vera-attestation',
      port: server.address().port,
      keyArn: 'arn:aws:kms:us-east-2:000000000000:key/00000000-0000-0000-0000-000000000001',
      pcrs: { '0': '11'.repeat(48), '1': '22'.repeat(48), '2': '33'.repeat(48) },
      credentials: async () => {
        credentialLoads++;
        return { accessKeyId: 'synthetic-access', secretAccessKey: 'synthetic-secret',
          sessionToken: 'synthetic-session', expiration: new Date(Date.now() + 60000).toISOString() };
      },
    };
    const trackingId = 'VRA-0123456789ABCDEF';
    reader = new AttestedReportVerificationReader({ ...options, loadAuthorized: async () => null });
    await assert.rejects(reader.read(trackingId), { message: 'Report verification reader unavailable' });
    await reader.close();
    assert.equal(credentialLoads, 0);
    assert.equal(requests.length, 0);
    const envelope = 'private:v1:' + JSON.stringify({ key: 'enc:kms:v2:AQ==',
      iv: Buffer.alloc(12).toString('base64'), tag: Buffer.alloc(16).toString('base64'), data: 'AQ==' });
    reader = new AttestedReportVerificationReader({ ...options,
      loadAuthorized: async () => ({ trackingId, verification: envelope }) });
    await assert.rejects(reader.read(trackingId), { message: 'Report verification reader unavailable' });
    await reader.close();
    assert.equal(credentialLoads, 1);
    assert.equal(requests.length, 1, 'Python must reach the TLS peer, but send no privileged follow-up');
    assert.deepEqual(Object.keys(requests[0]).sort(), ['id', 'method', 'params']);
    assert.equal(requests[0].method, 'attestChannel');
    assert.deepEqual(Object.keys(requests[0].params), ['nonce']);
    assert.match(requests[0].params.nonce, /^[a-f0-9]{64}$/);
    narrative = new AttestedNarrative(options);
    await assert.rejects(narrative.encrypt(trackingId, 'synthetic private narrative'), { message: 'Narrative unavailable' });
    await assert.rejects(narrative.decrypt(trackingId, {
      format: 'recipient-narrative:v1', trackingId, purpose: 'narrative',
      key: 'enc:kms:recipient:v1:AQ==', iv: Buffer.alloc(12).toString('base64'),
      tag: Buffer.alloc(16).toString('base64'), data: 'AQ==',
    }), { message: 'Narrative unavailable' });
    await narrative.close();
    assert.equal(credentialLoads, 3);
    assert.equal(requests.length, 3, 'Both narrative operations must reach installed Python and send only a challenge');
    for (const request of requests) {
      assert.deepEqual(Object.keys(request).sort(), ['id', 'method', 'params']);
      assert.equal(request.method, 'attestChannel');
      assert.deepEqual(Object.keys(request.params), ['nonce']);
      assert.match(request.params.nonce, /^[a-f0-9]{64}$/);
    }
    assert.equal(new Set(requests.map(request => request.params.nonce)).size, 3);
    assert.deepEqual(failures, []);
  } finally {
    if (reader) await reader.close();
    if (narrative) await narrative.close();
    for (const socket of sockets) socket.destroy();
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
