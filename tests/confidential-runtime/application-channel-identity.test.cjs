const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const childProcess = require('node:child_process');
const { createHash } = require('node:crypto');
const { createApplicationChannelIdentity } = require('../../enclave/dist/application-channel-identity.js');
const pgp = require('../../enclave/dist/confidential/pgp.js');

const nonce = 'ab'.repeat(32);
const failure = /^Error: Application channel attestation unavailable$/;

function helper(t, output = '{"document":"AQID"}', error = null) {
  const calls = [];
  t.mock.method(childProcess, 'execFile', (path, args, options, callback) => {
    const call = { path, args, options };
    calls.push(call);
    return { stdin: { on() {}, end(input) {
      call.input = JSON.parse(input);
      queueMicrotask(() => callback(error, output));
    } } };
  });
  return calls;
}

test('attests only freshly generated public-key bytes and keeps private credentials out of JSON', async t => {
  const calls = helper(t);
  const first = await createApplicationChannelIdentity(nonce);
  const second = await createApplicationChannelIdentity(nonce);
  assert.notEqual(first.evidence.publicKey, second.evidence.publicKey);
  assert.equal(calls.length, 2);
  const bytes = Buffer.from(first.evidence.publicKey, 'base64');
  assert.deepEqual(calls[0].input, {
    nonce: Buffer.from(nonce, 'hex').toString('base64'),
    channel_key_sha256: createHash('sha256').update(bytes).digest('base64'),
  });
  assert.equal(calls[0].path, '/app/bin/vera-nsm-application-channel');
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].options.timeout, 10000);
  assert.equal(calls[0].options.maxBuffer, 24576);
  const publicKey = await pgp.readKey({ binaryKey: bytes });
  assert.equal(publicKey.isPrivate(), false);
  assert.equal(publicKey.getFingerprint(), first.getPrivateKey().getFingerprint());
  assert.deepEqual(JSON.parse(JSON.stringify(first)), first.evidence);
  assert.deepEqual(Object.keys(first), ['evidence']);
  assert.equal(Object.isFrozen(first.evidence), true);
  // Real recipient encryption proves that the attested public bytes match the
  // retained private key, independently of the mock NSM response.
  const encrypted = await pgp.encrypt({ message: await pgp.createMessage({ text: 'synthetic channel input' }),
    encryptionKeys: publicKey });
  const clear = await pgp.decrypt({ message: await pgp.readMessage({ armoredMessage: encrypted }),
    decryptionKeys: first.getPrivateKey() });
  assert.equal(clear.data, 'synthetic channel input');
});

test('rejects malformed challenges before starting any helper', async t => {
  const calls = helper(t);
  for (const value of [null, undefined, {}, { nonce, publicKey: 'caller' }, '', 'AB'.repeat(32),
    'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64)]) {
    await assert.rejects(createApplicationChannelIdentity(value), failure);
  }
  assert.equal(calls.length, 0);
});

test('helper failure does not return a usable unattested identity or leak diagnostic details', async t => {
  helper(t, 'sensitive helper output', new Error('sensitive helper error'));
  await assert.rejects(createApplicationChannelIdentity(nonce), failure);
});

test('requires a bounded canonical attestation response without extra fields', async t => {
  for (const response of ['bad json', 'null', '[]', '{}', '{"document":""}',
    '{"document":123}', '{"document":"AQID","privateKey":"untrusted"}',
    '{"document":"AQID\\n"}', JSON.stringify({ document: Buffer.alloc(16385).toString('base64') })]) {
    await t.test(response.slice(0, 60), async sub => {
      helper(sub, response);
      await assert.rejects(createApplicationChannelIdentity(nonce), failure);
    });
  }
});

test('missing real native helper fails closed', { skip: process.platform !== 'darwin' }, async () => {
  await assert.rejects(createApplicationChannelIdentity(nonce), failure);
});
