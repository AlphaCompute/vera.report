// Independent OpenSSL certificate issuer and Node signer. Synthetic keys only.
const { execFileSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { generateKeyPairSync, X509Certificate, createHash, sign } = require('node:crypto');

function encode(value) {
  function head(major, n) {
    if (n < 24) return Buffer.from([major * 32 + n]);
    if (n < 256) return Buffer.from([major * 32 + 24, n]);
    if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
    const data = Buffer.alloc(9); data[0] = major * 32 + 27; data.writeBigUInt64BE(BigInt(n), 1); return data;
  }
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  throw new Error('Invalid fixture value');
}

function createPkiFixture(extensions = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature', intermediateCa) {
  const directory = mkdtempSync(join(tmpdir(), 'vera-synthetic-pki-'));
  const rootKey = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey;
  const leafKey = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey;
  let root, leaf, intermediate;
  try {
    for (const [name, key] of [['root', rootKey], ['leaf', leafKey]]) {
      writeFileSync(join(directory, `${name}.key`), key.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    }
    writeFileSync(join(directory, 'root.cnf'), '[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
    writeFileSync(join(directory, 'leaf.cnf'), extensions + '\n');
    const openssl = args => execFileSync(process.env.OPENSSL_BIN || 'openssl', args, { cwd: directory, stdio: 'pipe', timeout: 10000 });
    openssl(['req', '-new', '-x509', '-key', 'root.key', '-subj', '/CN=Synthetic-Nitro-root', '-days', '2', '-sha384', '-config', 'root.cnf', '-out', 'root.pem']);
    if (intermediateCa !== undefined) {
      const key = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey;
      writeFileSync(join(directory, 'intermediate.key'), key.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      writeFileSync(join(directory, 'intermediate.cnf'), `basicConstraints=critical,CA:${intermediateCa ? 'TRUE' : 'FALSE'}\nkeyUsage=critical,keyCertSign\n`);
      openssl(['req', '-new', '-key', 'intermediate.key', '-subj', '/CN=Synthetic-intermediate', '-out', 'intermediate.csr']);
      openssl(['x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-set_serial', '3', '-days', '1', '-sha384', '-extfile', 'intermediate.cnf', '-out', 'intermediate.pem']);
      intermediate = new X509Certificate(readFileSync(join(directory, 'intermediate.pem'))).raw;
    }
    openssl(['req', '-new', '-key', 'leaf.key', '-subj', '/CN=Synthetic-Nitro-leaf', '-out', 'leaf.csr']);
    const issuer = intermediate ? 'intermediate' : 'root';
    openssl(['x509', '-req', '-in', 'leaf.csr', '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-set_serial', '2', '-days', '1', '-sha384', '-extfile', 'leaf.cnf', '-out', 'leaf.pem']);
    root = new X509Certificate(readFileSync(join(directory, 'root.pem'))).raw;
    leaf = new X509Certificate(readFileSync(join(directory, 'leaf.pem'))).raw;
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const now = Date.now(), nonce = Buffer.alloc(32, 3), publicKey = Buffer.from('synthetic application key');
  const expectedPcrs = new Map([0, 1, 2].map(i => [i, Buffer.alloc(48, i + 1)]));
  const cabundle = intermediate ? [root, intermediate] : [root];
  const header = encode(new Map([[1, -35]]));
  const payload = encode(new Map([
    ['module_id', 'synthetic'], ['timestamp', now], ['digest', 'SHA384'], ['pcrs', expectedPcrs],
    ['certificate', leaf], ['cabundle', cabundle], ['nonce', nonce], ['public_key', null],
    ['user_data', Buffer.concat([Buffer.from('VERA-CONFIDENTIAL-CHANNEL-v1'), createHash('sha256').update(publicKey).digest()])],
  ]));
  const signedBytes = encode(['Signature1', header, Buffer.alloc(0), payload]);
  const signature = sign('sha384', signedBytes, { key: leafKey, dsaEncoding: 'ieee-p1363' });
  return { now, nonce, publicKey, expectedPcrs, root,
    document: encode([header, new Map(), payload, signature]),
    evidence: { status: 'unverified', channelPublicKey: publicKey, signedBytes, signature, certificate: leaf, cabundle, timestamp: now } };
}
module.exports = { createPkiFixture };
