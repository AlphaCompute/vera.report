const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const {
  createRoughtimeRequest, decodeRoughtimeMessage, encodeRoughtimeMessage, roughtimeTag: tag, verifyRoughtimeResponse,
} = require('../../enclave/dist/cases/roughtime.js');
const { parseRoughtimePolicy } = require('../../enclave/dist/cases/measuredConfiguration.js');

// Compiled enclave Roughtime client against a synthetic server keypair.
const u32 = value => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value, 0); return bytes; };
const u64 = value => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(value), 0); return bytes; };
const raw = key => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
const root = generateKeyPairSync('ed25519'), online = generateKeyPairSync('ed25519');
const SECONDS = 1_790_000_000;

function respond(request, seconds) {
  const nonce = decodeRoughtimeMessage(request.subarray(12)).get(tag('NONC'));
  const dele = encodeRoughtimeMessage(new Map([[tag('PUBK'), raw(online.publicKey)], [tag('MINT'), u64(seconds - 60)], [tag('MAXT'), u64(seconds + 60)]]));
  const cert = encodeRoughtimeMessage(new Map([[tag('DELE'), dele],
    [tag('SIG'), sign(null, Buffer.concat([Buffer.from('RoughTime v1 delegation signature\0'), dele]), root.privateKey)]]));
  const leaf = createHash('sha512').update(Buffer.concat([Buffer.from([0]), request])).digest().subarray(0, 32);
  const srep = encodeRoughtimeMessage(new Map([[tag('VER'), u32(1)], [tag('RADI'), u32(1)], [tag('MIDP'), u64(seconds)],
    [tag('VERS'), u32(1)], [tag('ROOT'), leaf]]));
  const message = encodeRoughtimeMessage(new Map([[tag('SIG'), sign(null, Buffer.concat([Buffer.from('RoughTime v1 response signature\0'), srep]), online.privateKey)],
    [tag('NONC'), nonce], [tag('TYPE'), u32(1)], [tag('PATH'), Buffer.alloc(0)], [tag('SREP'), srep], [tag('CERT'), cert], [tag('INDX'), u32(0)]]));
  const length = Buffer.alloc(4); length.writeUInt32LE(message.length, 0);
  return Buffer.concat([Buffer.from('ROUGHTIM'), length, message]);
}

test('compiled Roughtime client verifies a pinned server and refuses another nonce or key', () => {
  const publicKey = raw(root.publicKey);
  const { packet, nonce } = createRoughtimeRequest(publicKey);
  assert.deepEqual(verifyRoughtimeResponse({ response: respond(packet, SECONDS), request: packet, nonce, publicKey }),
    { midpoint: SECONDS * 1000, radius: 1000 });
  const other = createRoughtimeRequest(publicKey);
  assert.throws(() => verifyRoughtimeResponse({ response: respond(packet, SECONDS), request: other.packet, nonce: other.nonce, publicKey }));
  assert.throws(() => verifyRoughtimeResponse({ response: respond(packet, SECONDS), request: packet, nonce,
    publicKey: raw(generateKeyPairSync('ed25519').publicKey) }));
});

test('compiled measured policy parser accepts only public 32-byte keys', () => {
  const publicKey = raw(root.publicKey).toString('base64');
  assert.equal(parseRoughtimePolicy(null), null);
  assert.equal(parseRoughtimePolicy({ servers: [{ name: 'a', address: 'a.example:2002', publicKey }], quorum: 1, toleranceMs: 5000 }).quorum, 1);
  assert.throws(() => parseRoughtimePolicy({ servers: [{ name: 'a', address: 'a.example:2002', publicKey: 'x' }], quorum: 1, toleranceMs: 5000 }));
});
