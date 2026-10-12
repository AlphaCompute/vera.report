import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { generateKey } from './confidential/pgp.js';
import type { PrivateKey } from './confidential/pgp.js';

const FAILURE = 'Application channel attestation unavailable';

/** Internal credentials, never a route response. JSON serialization exposes only
 * public evidence; the private key lives in a non-enumerable private field.
 * This is not yet a session/authorization service or a browser quote verifier. */
export class ApplicationChannelIdentity {
  #privateKey: PrivateKey | undefined;
  constructor(privateKey: PrivateKey, readonly evidence: Readonly<{
    nonce: string; publicKey: string; document: string;
  }>) {
    this.#privateKey = privateKey;
    Object.freeze(this.evidence);
  }
  /** Enclave-local channel code only. Never serialize or persist this key. */
  getPrivateKey(): PrivateKey {
    if (!this.#privateKey) throw new Error(FAILURE);
    return this.#privateKey;
  }
  close(): void { this.#privateKey = undefined; }
  toJSON(): Readonly<{ nonce: string; publicKey: string; document: string }> { return this.evidence; }
}

/** The only caller input is a fresh browser challenge. In particular, neither a
 * public key, its digest, a helper path nor an attestation context is accepted. */
export async function createApplicationChannelIdentity(nonce: string): Promise<ApplicationChannelIdentity> {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) throw new Error(FAILURE);
  try {
    const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Vera ephemeral application channel' }], format: 'object' });
    const publicBytes = publicKey.write();
    const digest = createHash('sha256').update(publicBytes).digest('base64');
    const output = await new Promise<string>((resolve, reject) => {
      const child = execFile('/app/bin/vera-nsm-application-channel', [],
        { timeout: 10000, maxBuffer: 24576 }, (error, stdout) => {
          if (error) reject(new Error(FAILURE)); else resolve(stdout);
        });
      child.stdin!.on('error', () => {});
      child.stdin!.end(JSON.stringify({ nonce: Buffer.from(nonce, 'hex').toString('base64'),
        channel_key_sha256: digest }));
    });
    const value: unknown = JSON.parse(output);
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).join(',') !== 'document') throw new Error(FAILURE);
    const document = (value as { document: unknown }).document;
    if (typeof document !== 'string' || !document.length || document.length > 21848 ||
        Buffer.from(document, 'base64').toString('base64') !== document ||
        Buffer.from(document, 'base64').length > 16384) throw new Error(FAILURE);
    return new ApplicationChannelIdentity(privateKey, {
      nonce, publicKey: Buffer.from(publicBytes).toString('base64'), document,
    });
  } catch { throw new Error(FAILURE); }
}
