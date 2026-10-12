import { KMSClient, DecryptCommand, GenerateDataKeyCommand } from '@aws-sdk/client-kms';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { Agent } from 'node:https';
import * as tls from 'node:tls';
import { Readable, Transform } from 'node:stream';
import { createHash } from 'node:crypto';

const HOST = 'kms.us-east-2.amazonaws.com';
const REGION = 'us-east-2';
const MAX_RESPONSE = 65536;
const KEY_ARN = /^arn:aws:kms:us-east-2:000000000000:key\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

/** The parent relays opaque TLS bytes; certificate and hostname verification stay here. */
export class EnclaveKmsAgent extends Agent {
  override createConnection(options: tls.ConnectionOptions & { host?: string }): tls.TLSSocket {
    if (options.host !== HOST || (options.servername && options.servername !== HOST)) throw new Error('KMS endpoint rejected');
    return tls.connect({ host: '127.0.0.1', port: 8000, servername: HOST,
      rejectUnauthorized: true, minVersion: 'TLSv1.2', ca: [...tls.rootCertificates],
      checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity(HOST, certificate) });
  }
}
class BoundedHandler extends NodeHttpHandler {
  override async handle(...args: Parameters<NodeHttpHandler['handle']>) {
    const request = args[0];
    if (request.protocol !== 'https:' || request.hostname !== HOST || request.port && request.port !== 443) throw new Error('KMS endpoint rejected');
    const result = await super.handle(...args);
    const source = result.response.body;
    if (!(source instanceof Readable)) throw new Error('Invalid KMS response stream');
    let size = 0;
    const bounded = new Transform({ transform(chunk: Buffer, _encoding, callback) {
      size += chunk.length;
      if (size > MAX_RESPONSE) { source.destroy(); callback(new Error('KMS response too large')); }
      else callback(null, chunk);
    } });
    source.on('error', error => bounded.destroy(error));
    bounded.once('close', () => source.destroy());
    result.response.body = source.pipe(bounded);
    return result;
  }
}
export interface TemporaryKmsCredentials {
  accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: Date;
}
export interface RecipientDecryptRequest {
  keyArn: string; ciphertext: Uint8Array; attestation: Uint8Array;
  context: Record<string, string>;
}

function encryptionContext(input: Record<string, string>): Record<string, string> {
    const entries = Object.entries(input);
    if (!['evidence','narrative'].includes(input.purpose) || !['record','trackingId','fileKey'].some(k => input[k]) || entries.length > 5 ||
        entries.some(([k,v]) => !['purpose','record','trackingId','fileKey','field'].includes(k) || typeof v !== 'string' || !v.length || v.length > 256)) throw new Error('Invalid KMS encryption context');
    return Object.fromEntries(entries.map(([k,v]) => [k, k === 'purpose' ? v : createHash('sha256').update(JSON.stringify(['vera-context-v2',k,v])).digest('hex')]));
}

/** Internal bootstrap client, not an RPC. Returns only recipient-encrypted bytes. */
export class KmsRecipientClient {
  private readonly client: KMSClient;
  private readonly agent = new EnclaveKmsAgent({ keepAlive: false, maxSockets: 1 });
  private closed = false;
  private readonly shutdown = new AbortController();
  private busy = false;
  private readonly expires: number;
  constructor(credentials: TemporaryKmsCredentials) {
    this.expires = credentials.expiration.getTime();
    if (!Number.isFinite(this.expires) || this.expires <= Date.now() ||
        [credentials.accessKeyId, credentials.secretAccessKey, credentials.sessionToken].some(v => typeof v !== 'string' || !v.length || v.length > 8192)) {
      throw new Error('Temporary KMS credentials required');
    }
    this.client = new KMSClient({ region: REGION, endpoint: `https://${HOST}`, maxAttempts: 1,
      credentials: { ...credentials, expiration: new Date(this.expires) },
      requestHandler: new BoundedHandler({ httpsAgent: this.agent, connectionTimeout: 5000, requestTimeout: 15000 }) });
  }
  async decrypt(request: RecipientDecryptRequest): Promise<Buffer> {
    if (this.closed || this.busy || this.expires <= Date.now()) throw new Error('KMS bootstrap unavailable');
    if (!KEY_ARN.test(request.keyArn) || !(request.ciphertext instanceof Uint8Array) || !request.ciphertext.length || request.ciphertext.length > 6144 ||
        !(request.attestation instanceof Uint8Array) || !request.attestation.length || request.attestation.length > 16384) throw new Error('Invalid KMS bootstrap request');
    const keyArn = request.keyArn;
    const context = encryptionContext(request.context);
    this.busy = true;
    try {
      const result = await this.client.send(new DecryptCommand({ KeyId: keyArn, CiphertextBlob: Buffer.from(request.ciphertext), EncryptionContext: context,
        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', Recipient: { AttestationDocument: Buffer.from(request.attestation), KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256' } }),
      { abortSignal: AbortSignal.any([this.shutdown.signal, AbortSignal.timeout(15000)]) });
      if (this.closed || this.expires <= Date.now() || (result.Plaintext?.length ?? 0) > 0 || result.KeyId !== keyArn || result.EncryptionAlgorithm !== 'SYMMETRIC_DEFAULT' ||
          !result.CiphertextForRecipient?.length || result.CiphertextForRecipient.length > 16384) throw new Error('Invalid attested KMS response');
      return Buffer.from(result.CiphertextForRecipient);
    } catch { throw new Error('Attested KMS bootstrap failed'); }
    finally { this.busy = false; }
  }
  async generate(request: Omit<RecipientDecryptRequest, 'ciphertext'>): Promise<{ wrappedKey: Buffer; envelope: Buffer }> {
    if (this.closed || this.busy || this.expires <= Date.now()) throw new Error('KMS bootstrap unavailable');
    if (!KEY_ARN.test(request.keyArn) || !(request.attestation instanceof Uint8Array) ||
        !request.attestation.length || request.attestation.length > 16384) throw new Error('Invalid KMS bootstrap request');
    const keyArn = request.keyArn;
    const context = encryptionContext(request.context);
    this.busy = true;
    try {
      const result = await this.client.send(new GenerateDataKeyCommand({ KeyId: keyArn, KeySpec: 'AES_256', EncryptionContext: context,
        Recipient: { AttestationDocument: Buffer.from(request.attestation), KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256' } }),
      { abortSignal: AbortSignal.any([this.shutdown.signal, AbortSignal.timeout(15000)]) });
      if (this.closed || this.expires <= Date.now() || (result.Plaintext?.length ?? 0) > 0 || result.KeyId !== keyArn ||
          !result.CiphertextBlob?.length || result.CiphertextBlob.length > 6144 ||
          !result.CiphertextForRecipient?.length || result.CiphertextForRecipient.length > 16384) throw new Error('Invalid attested KMS response');
      return { wrappedKey: Buffer.from(result.CiphertextBlob), envelope: Buffer.from(result.CiphertextForRecipient) };
    } catch { throw new Error('Attested KMS bootstrap failed'); }
    finally { this.busy = false; }
  }
  close(): void { this.closed = true; this.shutdown.abort(); this.client.destroy(); this.agent.destroy(); }
}
