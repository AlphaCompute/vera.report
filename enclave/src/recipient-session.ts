import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { KmsRecipientClient, type TemporaryKmsCredentials } from './kms-recipient-client.js';

import { encodeRecipientEnvelope, decodeRecipientEnvelope, decodeHistoricalEnvelope } from './recipient-envelope.js';

const MAX_FRAME = 12 * 1024 * 1024;
const MAX_READ = 256 * 1024 * 1024;
const READ_CHUNK = 1024 * 1024;
let largeReadOwner: RecipientSession | undefined;
const FAILURE = 'Recipient session unavailable';
type Purpose = 'evidence' | 'narrative';
type Scope = { purpose: Purpose; record: string };
type Result = Record<string, unknown>;

function binary(value: unknown, max: number, exact = false): Buffer {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3)) throw new Error(FAILURE);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length > max || exact && bytes.length !== max) throw new Error(FAILURE);
  return bytes;
}
function fields(result: Result, kind: string, names: string[]): void {
  if (result.kind !== kind || Object.keys(result).sort().join(',') !== ['kind', ...names].sort().join(',')) throw new Error(FAILURE);
}

/** Internal to the measured TLS service. No raw native commands or install operation are exported. */
export class RecipientSession {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly kms: KmsRecipientClient;
  private readonly lifetime: NodeJS.Timeout;
  private buffer: Buffer = Buffer.alloc(0);
  private closed = false;
  private read?: { scope: Scope; stream: number; size: number; received: number; emitted: number; authenticated: boolean };
  private busy = false;
  private nextId = 0;
  private pending?: { id: number; resolve: (value: Result) => void; reject: (error: Error) => void; timer: NodeJS.Timeout };

  constructor(certificateDigest: Buffer, credentials: TemporaryKmsCredentials) {
    if (!Buffer.isBuffer(certificateDigest) || certificateDigest.length !== 32) throw new Error(FAILURE);
    this.kms = new KmsRecipientClient(credentials);
    try { this.child = spawn('/app/bin/vera-recipient-broker', [], { env: {}, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch { this.kms.close(); throw new Error(FAILURE); }
    this.lifetime = setTimeout(() => this.close(), 300_000);
    this.lifetime.unref();
    this.child.on('error', () => this.close());
    this.child.on('exit', () => { this.close(); this.releaseRead(); });
    this.child.stdout.on('end', () => this.close());
    this.child.stdout.on('error', () => this.close());
    this.child.stdin.on('error', () => this.close());
    this.child.stderr.on('error', () => this.close());
    // The helper never emits diagnostics during successful operation. Do not
    // retain, log, or forward even unexpected native diagnostics.
    this.child.stderr.on('data', () => this.close());
    this.child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    this.write({ session: randomBytes(32).toString('base64'), certificate: certificateDigest.toString('base64') });
  }

  private write(value: unknown): void {
    const body = Buffer.from(JSON.stringify(value));
    if (!body.length || body.length > MAX_FRAME) { body.fill(0); this.close(); throw new Error(FAILURE); }
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length);
    this.child.stdin.write(header);
    this.child.stdin.write(body, () => body.fill(0));
  }
  private receive(chunk: Buffer): void {
    if (this.closed) return;
    try {
      if (!this.pending || this.buffer.length + chunk.length > MAX_FRAME + 4) throw new Error(FAILURE);
      const previous = this.buffer;
      this.buffer = Buffer.concat([previous, chunk]);
      previous.fill(0);
      if (this.buffer.length < 4) return;
      const length = this.buffer.readUInt32BE();
      if (!length || length > MAX_FRAME || this.buffer.length > length + 4) throw new Error(FAILURE);
      if (this.buffer.length < length + 4) return;
      const frame = JSON.parse(this.buffer.subarray(4).toString('utf8')) as Record<string, unknown>;
      this.buffer.fill(0);
      this.buffer = Buffer.alloc(0);
      if (!frame || Object.keys(frame).sort().join(',') !== 'id,result' || frame.id !== this.pending.id ||
          !frame.result || typeof frame.result !== 'object' || Array.isArray(frame.result)) throw new Error(FAILURE);
      const pending = this.pending;
      this.pending = undefined;
      clearTimeout(pending.timer);
      pending.resolve(frame.result as Result);
    } catch { this.close(); }
  }
  private request(command: Result): Promise<Result> {
    if (this.closed || this.pending || this.nextId >= 10000) return Promise.reject(new Error(FAILURE));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close(), 15_000);
      timer.unref();
      this.pending = { id, resolve, reject, timer };
      try { this.write({ id, command }); } catch { this.close(); }
    });
  }
  private async operation<T>(scope: Scope, run: () => Promise<T>): Promise<T> {
    if (this.closed || this.busy) throw new Error(FAILURE);
    if (!['evidence', 'narrative'].includes(scope.purpose) || typeof scope.record !== 'string' ||
        !scope.record.length || Buffer.byteLength(scope.record) > 256) throw new Error(FAILURE);
    this.busy = true;
    try { const result = await run(); if (this.closed) throw new Error(FAILURE); return result; }
    catch { this.close(); throw new Error(FAILURE); }
    finally { this.busy = false; }
  }
  async bootstrap(request: Scope & { keyArn: string; wrappedKey: string; context: Record<string, string> }): Promise<string> {
    // Snapshot caller-owned input before awaiting NSM/KMS. The external service
    // must authorize this exact scope before invoking the internal session.
    const scope = { purpose: request.purpose, record: request.record };
    const context = { ...request.context };
    const keyArn = request.keyArn;
    const ciphertext = decodeRecipientEnvelope(request.wrappedKey);
    return this.operation(scope, async () => {
      if (context.purpose !== scope.purpose || !['record', 'trackingId', 'fileKey'].some(k => context[k] === scope.record)) throw new Error(FAILURE);
      const prepared = await this.request({ method: 'prepare', nonce: randomBytes(32).toString('base64'), ...scope });
      fields(prepared, 'attestation', ['document']);
      const attestation = binary(prepared.document, 16384);
      // Only bytes from this enclave-authenticated AWS TLS exchange reach install.
      const envelope = await this.kms.decrypt({ keyArn, ciphertext, context, attestation });
      const installed = await this.request({ method: 'install', envelope: envelope.toString('base64') });
      fields(installed, 'handle', ['handle']);
      return binary(installed.handle, 32, true).toString('base64');
    });
  }
  async bootstrapLegacyEvidence(request: Scope & { keyArn: string; wrappedKey: string; salt: Buffer; context: Record<string, string> }): Promise<string> {
    const scope = { purpose: request.purpose, record: request.record };
    const context = { ...request.context };
    const keyArn = request.keyArn;
    const ciphertext = decodeHistoricalEnvelope(request.wrappedKey);
    if (!Buffer.isBuffer(request.salt) || request.salt.length !== 32) throw new Error(FAILURE);
    const salt = request.salt.toString('base64');
    return this.operation(scope, async () => {
      const binding = scope.purpose === 'evidence' ? 'fileKey' : 'trackingId';
      if (context.purpose !== scope.purpose || context[binding] !== scope.record ||
          Object.keys(context).sort().join(',') !== [binding, 'purpose'].sort().join(',')) throw new Error(FAILURE);
      const prepared = await this.request({ method: 'prepareLegacyEvidence', nonce: randomBytes(32).toString('base64'), ...scope, salt });
      fields(prepared, 'attestation', ['document']);
      const envelope = await this.kms.decrypt({ keyArn, ciphertext, context, attestation: binary(prepared.document, 16384) });
      const installed = await this.request({ method: 'install', envelope: envelope.toString('base64') });
      fields(installed, 'handle', ['handle']);
      return binary(installed.handle, 32, true).toString('base64');
    });
  }
  async decryptLegacyEvidence(scope: Scope, handle: string, sealed: { iv: Buffer; tag: Buffer; ciphertext: Buffer }): Promise<Buffer> {
    const binding = { purpose: scope.purpose, record: scope.record };
    return this.operation(binding, async () => {
      binary(handle, 32, true);
      if (!Buffer.isBuffer(sealed.iv) || sealed.iv.length !== 16 || !Buffer.isBuffer(sealed.tag) || sealed.tag.length !== 16 ||
          !Buffer.isBuffer(sealed.ciphertext) || sealed.ciphertext.length > 8 * 1024 * 1024) throw new Error(FAILURE);
      const result = await this.request({ method: 'decryptLegacyEvidence', ...binding, handle, iv: sealed.iv.toString('base64'),
        tag: sealed.tag.toString('base64'), ciphertext: sealed.ciphertext.toString('base64') });
      fields(result, 'decrypted', ['plaintext']);
      return binary(result.plaintext, 8 * 1024 * 1024);
    });
  }
  async bootstrapLegacyPrivate(request: { record: string; field: string; keyArn: string; wrappedKey: string }): Promise<string> {
    const record = request.record, field = request.field, keyArn = request.keyArn;
    const ciphertext = decodeHistoricalEnvelope(request.wrappedKey);
    return this.operation({ purpose: 'narrative', record }, async () => {
      if (typeof field !== 'string' || !field.length || Buffer.byteLength(field) > 256) throw new Error(FAILURE);
      const prepared = await this.request({ method: 'prepareLegacyPrivate', nonce: randomBytes(32).toString('base64'), record, field });
      fields(prepared, 'attestation', ['document']);
      const envelope = await this.kms.decrypt({ keyArn, ciphertext, context: { purpose: 'narrative', record, field }, attestation: binary(prepared.document, 16384) });
      const installed = await this.request({ method: 'install', envelope: envelope.toString('base64') });
      fields(installed, 'handle', ['handle']);
      return binary(installed.handle, 32, true).toString('base64');
    });
  }
  async decryptLegacyPrivate(record: string, field: string, handle: string, sealed: { iv: Buffer; tag: Buffer; ciphertext: Buffer }): Promise<Buffer> {
    return this.operation({ purpose: 'narrative', record }, async () => {
      binary(handle, 32, true);
      if (typeof field !== 'string' || !field.length || Buffer.byteLength(field) > 256 ||
          !Buffer.isBuffer(sealed.iv) || sealed.iv.length !== 12 || !Buffer.isBuffer(sealed.tag) || sealed.tag.length !== 16 ||
          !Buffer.isBuffer(sealed.ciphertext) || sealed.ciphertext.length > 8 * 1024 * 1024) throw new Error(FAILURE);
      const result = await this.request({ method: 'decryptLegacyPrivate', record, field, handle, iv: sealed.iv.toString('base64'),
        tag: sealed.tag.toString('base64'), ciphertext: sealed.ciphertext.toString('base64') });
      fields(result, 'decrypted', ['plaintext']);
      return binary(result.plaintext, 8 * 1024 * 1024);
    });
  }
  async generate(request: Scope & { keyArn: string; context: Record<string, string> }): Promise<{ handle: string; wrappedKey: string }> {
    const scope = { purpose: request.purpose, record: request.record };
    const context = { ...request.context };
    const keyArn = request.keyArn;
    return this.operation(scope, async () => {
      if (context.purpose !== scope.purpose || !['record', 'trackingId', 'fileKey'].some(k => context[k] === scope.record)) throw new Error(FAILURE);
      const prepared = await this.request({ method: 'prepare', nonce: randomBytes(32).toString('base64'), ...scope });
      fields(prepared, 'attestation', ['document']);
      const generated = await this.kms.generate({ keyArn, context, attestation: binary(prepared.document, 16384) });
      const installed = await this.request({ method: 'install', envelope: generated.envelope.toString('base64') });
      fields(installed, 'handle', ['handle']);
      return { handle: binary(installed.handle, 32, true).toString('base64'), wrappedKey: encodeRecipientEnvelope(generated.wrappedKey) };
    });
  }
  async encrypt(scope: Scope, handle: string, plaintext: Buffer): Promise<{ iv: Buffer; tag: Buffer; ciphertext: Buffer }> {
    const binding = { purpose: scope.purpose, record: scope.record };
    return this.operation(binding, async () => {
      binary(handle, 32, true);
      if (!Buffer.isBuffer(plaintext) || plaintext.length > 8 * 1024 * 1024) throw new Error(FAILURE);
      const result = await this.request({ method: 'encrypt', ...binding, handle, plaintext: plaintext.toString('base64') });
      fields(result, 'encrypted', ['iv', 'tag', 'ciphertext']);
      return { iv: binary(result.iv, 12, true), tag: binary(result.tag, 16, true), ciphertext: binary(result.ciphertext, 8 * 1024 * 1024) };
    });
  }
  async decrypt(scope: Scope, handle: string, sealed: { iv: Buffer; tag: Buffer; ciphertext: Buffer }): Promise<Buffer> {
    const binding = { purpose: scope.purpose, record: scope.record };
    return this.operation(binding, async () => {
      binary(handle, 32, true);
      if (!Buffer.isBuffer(sealed.iv) || sealed.iv.length !== 12 || !Buffer.isBuffer(sealed.tag) || sealed.tag.length !== 16 ||
          !Buffer.isBuffer(sealed.ciphertext) || sealed.ciphertext.length > 8 * 1024 * 1024) throw new Error(FAILURE);
      const result = await this.request({ method: 'decrypt', ...binding, handle, iv: sealed.iv.toString('base64'),
        tag: sealed.tag.toString('base64'), ciphertext: sealed.ciphertext.toString('base64') });
      fields(result, 'decrypted', ['plaintext']);
      return binary(result.plaintext, 8 * 1024 * 1024);
    });
  }
  private releaseRead(): void {
    this.read = undefined;
    if (largeReadOwner === this) largeReadOwner = undefined;
  }
  async beginRead(scope: Scope, handle: string, input: { iv: Buffer; size: number; field?: string }): Promise<void> {
    const binding = { purpose: scope.purpose, record: scope.record };
    if (largeReadOwner) throw new Error(FAILURE);
    return this.operation(binding, async () => {
      binary(handle, 32, true);
      if (!Buffer.isBuffer(input.iv) || ![12, 16].includes(input.iv.length) || !Number.isSafeInteger(input.size) ||
          input.size < 0 || input.size > MAX_READ || input.field !== undefined &&
          (typeof input.field !== 'string' || !input.field.length || Buffer.byteLength(input.field) > 256)) throw new Error(FAILURE);
      const size = input.size;
      const stream = this.nextId;
      largeReadOwner = this;
      const result = await this.request({ method: 'beginRead', ...binding, handle, iv: input.iv.toString('base64'), size, field: input.field ?? null });
      fields(result, 'readStarted', ['stream']);
      if (result.stream !== stream) throw new Error(FAILURE);
      this.read = { scope: binding, stream, size, received: 0, emitted: 0, authenticated: false };
    });
  }
  async appendRead(ciphertext: Buffer): Promise<void> {
    const read = this.read;
    if (!read) throw new Error(FAILURE);
    return this.operation(read.scope, async () => {
      if (read.authenticated || !Buffer.isBuffer(ciphertext) || !ciphertext.length || ciphertext.length > READ_CHUNK ||
          ciphertext.length > read.size - read.received) throw new Error(FAILURE);
      const size = ciphertext.length;
      const result = await this.request({ method: 'appendRead', stream: read.stream, ciphertext: ciphertext.toString('base64') });
      fields(result, 'readAccepted', []);
      read.received += size;
    });
  }
  async authenticateRead(tag: Buffer): Promise<void> {
    const read = this.read;
    if (!read) throw new Error(FAILURE);
    return this.operation(read.scope, async () => {
      if (read.authenticated || read.received !== read.size || !Buffer.isBuffer(tag) || tag.length !== 16) throw new Error(FAILURE);
      const result = await this.request({ method: 'authenticateRead', stream: read.stream, tag: tag.toString('base64') });
      fields(result, 'readAuthenticated', []);
      read.authenticated = true;
    });
  }
  async readChunk(): Promise<{ plaintext: Buffer; done: boolean }> {
    const read = this.read;
    if (!read) throw new Error(FAILURE);
    return this.operation(read.scope, async () => {
      if (!read.authenticated) throw new Error(FAILURE);
      const result = await this.request({ method: 'readChunk', stream: read.stream });
      fields(result, 'readOutput', ['plaintext', 'done']);
      const plaintext = binary(result.plaintext, READ_CHUNK);
      const expected = Math.min(READ_CHUNK, read.size - read.emitted);
      if (plaintext.length !== expected || result.done !== (read.emitted + expected === read.size)) {
        plaintext.fill(0); throw new Error(FAILURE);
      }
      read.emitted += plaintext.length;
      if (result.done) this.releaseRead();
      return { plaintext, done: result.done as boolean };
    });
  }
  async cancelRead(): Promise<void> {
    const read = this.read;
    if (!read) throw new Error(FAILURE);
    return this.operation(read.scope, async () => {
      const result = await this.request({ method: 'cancel' });
      fields(result, 'cancelled', []);
      this.releaseRead();
    });
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.lifetime);
    this.kms.close();
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(new Error(FAILURE));
      this.pending = undefined;
    }
    this.child.stdin.destroy();
    this.child.stdout.destroy();
    this.child.stderr.destroy();
    this.child.kill('SIGKILL');
  }
}
