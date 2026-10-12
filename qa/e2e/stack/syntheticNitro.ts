// Synthetic Nitro attestation for the local browser stack. This is the ONLY
// mocked part of the confidential path: an OpenSSL-issued root and leaf stand in
// for the AWS Nitro PKI, and this module stands in for the NSM helper binary.
// Documents use the real COSE_Sign1 / CBOR layout, bind the fresh browser nonce
// and the channel key digest, and carry PCRs that match the synthetic release
// manifest. Synthetic keys only; nothing here is a production credential.
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';

type Cbor = null | number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>;

function encode(value: Cbor): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([major * 32 + n]);
    if (n < 256) return Buffer.from([major * 32 + 24, n]);
    if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
    if (n < 2 ** 32) { const data = Buffer.alloc(5); data[0] = major * 32 + 26; data.writeUInt32BE(n, 1); return data; }
    const data = Buffer.alloc(9); data[0] = major * 32 + 27; data.writeBigUInt64BE(BigInt(n), 1); return data;
  };
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
}

export type SyntheticNitro = {
  /** DER root certificate the test browser trusts in place of the AWS root. */
  rootDer: Buffer;
  pcrs: { pcr0: string; pcr1: string; pcr2: string };
  identityFactory: (nonce: string) => Promise<ApplicationChannelIdentity>;
};

/** `now`: the NSM clock (default the wall clock; the stack passes its shifted
 * clock, ./timeShift.ts, so documents carry the time the enclave anchors on). */
export function createSyntheticNitro(options: { now?: () => number } = {}): SyntheticNitro {
  const now = options.now ?? Date.now;
  const directory = mkdtempSync(join(tmpdir(), 'vera-e2e-nitro-'));
  const rootKey = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey;
  const leafKey: KeyObject = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey;
  let rootDer: Buffer, leafDer: Buffer;
  try {
    writeFileSync(join(directory, 'root.key'), rootKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(join(directory, 'leaf.key'), leafKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(join(directory, 'root.cnf'), '[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
    writeFileSync(join(directory, 'leaf.cnf'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
    // Valid long enough for a spec that moves the stack's time past a 30-day grant (./timeShift.ts).
    const openssl = (args: string[]) => execFileSync('openssl', args, { cwd: directory, stdio: 'pipe', timeout: 10_000 });
    openssl(['req', '-new', '-x509', '-key', 'root.key', '-subj', '/CN=Synthetic-E2E-Nitro-root', '-days', '60', '-sha384', '-config', 'root.cnf', '-out', 'root.pem']);
    openssl(['req', '-new', '-key', 'leaf.key', '-subj', '/CN=Synthetic-E2E-Nitro-leaf', '-out', 'leaf.csr']);
    openssl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-set_serial', '2', '-days', '59', '-sha384', '-extfile', 'leaf.cnf', '-out', 'leaf.pem']);
    rootDer = Buffer.from(new X509Certificate(readFileSync(join(directory, 'root.pem'))).raw);
    leafDer = Buffer.from(new X509Certificate(readFileSync(join(directory, 'leaf.pem'))).raw);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const pcrBytes = [0, 1, 2].map(() => randomBytes(48));
  const pcrs = { pcr0: pcrBytes[0].toString('hex'), pcr1: pcrBytes[1].toString('hex'), pcr2: pcrBytes[2].toString('hex') };
  const header = encode(new Map([[1, -35]]));

  function document(nonce: Buffer, channelKey: Uint8Array): string {
    const payload = encode(new Map<Cbor, Cbor>([
      ['module_id', 'synthetic-e2e'], ['timestamp', now()], ['digest', 'SHA384'],
      ['pcrs', new Map<Cbor, Cbor>(pcrBytes.map((value, index) => [index, value]))],
      ['certificate', leafDer], ['cabundle', [rootDer]], ['nonce', nonce], ['public_key', null],
      ['user_data', Buffer.concat([Buffer.from('VERA-CONFIDENTIAL-CHANNEL-v1'), createHash('sha256').update(channelKey).digest()])],
    ]));
    const signed = encode(['Signature1', header, Buffer.alloc(0), payload]);
    const signature = sign('sha384', signed, { key: leafKey, dsaEncoding: 'ieee-p1363' });
    return encode([header, new Map(), payload, signature]).toString('base64');
  }

  return {
    rootDer, pcrs,
    // Same contract as createApplicationChannelIdentity: fresh ephemeral channel
    // key per session, evidence binding the caller's nonce and that key.
    async identityFactory(nonce) {
      if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) throw new Error('Application channel attestation unavailable');
      const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
        userIDs: [{ name: 'Vera ephemeral application channel' }], format: 'object' });
      const publicBytes = publicKey.write();
      return new ApplicationChannelIdentity(privateKey, { nonce, publicKey: Buffer.from(publicBytes).toString('base64'),
        document: document(Buffer.from(nonce, 'hex'), publicBytes) });
    },
  };
}
