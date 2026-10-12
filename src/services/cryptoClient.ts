import { logger } from '../utils/logger';
/**
 * CryptoClient Abstraction
 *
 * Provides a unified interface for cryptographic operations with two implementations:
 *   - LocalCryptoClient:   Direct Node.js crypto (staging / Fargate)
 *   - EnclaveCryptoClient: Fail-closed guard until the attested key-handle protocol is available
 *
 * Runtime selection via ENCLAVE_ENABLED env var.
 */

import crypto from 'node:crypto';
import net from 'node:net';
import type { Duplex } from 'node:stream';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EncryptResult {
  ciphertext: string;   // base64
  iv: string;           // hex
  authTag: string;      // hex
  salt: string;         // hex
}

export interface DecryptParams {
  ciphertext: string;   // base64
  iv: string;           // hex
  authTag: string;      // hex
  salt: string;         // hex
}

export interface KeyDerivationParams {
  algorithm: 'pbkdf2' | 'scrypt';
  iterations?: number;  // pbkdf2
  cost?: number;        // scrypt N
  keyLength: number;
}

export interface CryptoClient {
  encrypt(plaintext: Buffer, secret: string, salt?: Buffer): Promise<EncryptResult>;
  decrypt(params: DecryptParams, secret: string): Promise<Buffer>;
  deriveKey(secret: string, salt: Buffer, params: KeyDerivationParams): Promise<Buffer>;
  hash(data: Buffer): string;
  sign(data: Buffer, key: Buffer): Buffer;
  randomBytes(length: number): Buffer;
}

// ─── Local Implementation ────────────────────────────────────────────────────

export class LocalCryptoClient implements CryptoClient {
  async encrypt(plaintext: Buffer, secret: string, salt?: Buffer): Promise<EncryptResult> {
    const s = salt ?? crypto.randomBytes(32);
    const key = crypto.scryptSync(secret, s, 32);
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return {
        ciphertext: encrypted.toString('base64'),
        iv: iv.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex'),
        salt: s.toString('hex'),
      };
    } finally { key.fill(0); }
  }

  async decrypt(params: DecryptParams, secret: string): Promise<Buffer> {
    const salt = Buffer.from(params.salt, 'hex');
    const key = crypto.scryptSync(secret, salt, 32);
    let pending: Buffer | undefined;
    let final: Buffer | undefined;
    try {
      const iv = Buffer.from(params.iv, 'hex');
      const authTag = Buffer.from(params.authTag, 'hex');
      const ciphertext = Buffer.from(params.ciphertext, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
      decipher.setAuthTag(authTag);
      pending = decipher.update(ciphertext);
      final = decipher.final();
      // The returned copy belongs to the caller; only temporary buffers are cleared.
      return Buffer.concat([pending, final]);
    } finally {
      key.fill(0);
      pending?.fill(0);
      final?.fill(0);
    }
  }

  async deriveKey(secret: string, salt: Buffer, params: KeyDerivationParams): Promise<Buffer> {
    if (params.algorithm === 'pbkdf2') {
      return new Promise((resolve, reject) => {
        crypto.pbkdf2(secret, salt, params.iterations ?? 100000, params.keyLength, 'sha256', (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
    }

    // scrypt
    return crypto.scryptSync(secret, salt, params.keyLength);
  }

  hash(data: Buffer): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  sign(data: Buffer, key: Buffer): Buffer {
    return Buffer.from(
      crypto.createHmac('sha256', key).update(data).digest()
    );
  }

  randomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  }
}

// ─── Enclave transport (attested vsock RPC) ──────────────────────────────────

const VSOCK_CID = 16;
const VSOCK_PORT = 5000;
const RPC_TIMEOUT_MS = 15_000;
const MAX_FRAME_BYTES = 16 * 1024 * 1024; // reject a hostile length prefix

/** 4-byte big-endian length prefix + JSON. Matches enclave/src/server.ts `frameMessage`. */
export function frameMessage(data: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(data), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/**
 * Reassembles length-prefixed frames from a byte stream. A single stream chunk
 * may carry a partial frame, one frame, or several — `push` returns every
 * complete JSON message it can now decode and buffers the remainder.
 */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);
  push(chunk: Buffer): unknown[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: unknown[] = [];
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0);
      if (len > MAX_FRAME_BYTES) throw new Error('Enclave frame exceeds the maximum size');
      if (this.buf.length < 4 + len) break; // wait for the rest of this frame
      out.push(JSON.parse(this.buf.subarray(4, 4 + len).toString('utf-8')));
      this.buf = this.buf.subarray(4 + len);
    }
    return out;
  }
}

interface RpcResponse {
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface EnclaveTransportOptions {
  /** Connect factory returning a duplex stream to the enclave RPC endpoint. Injectable for tests. */
  connect?: () => Duplex;
  timeoutMs?: number;
}

/** The enclave could not be reached: connect failure, timeout, or a close before any reply. */
export class EnclaveUnreachableError extends Error {
  override name = 'EnclaveUnreachableError';
}

/** The enclave answered with a JSON-RPC error object. */
export class EnclaveRpcError extends Error {
  override name = 'EnclaveRpcError';
  constructor(method: string, readonly code: number, rpcMessage: string) {
    super(`Enclave RPC '${method}' failed (${code}): ${rpcMessage}`);
  }
}

/** JSON-RPC "method not found": the running enclave build does not implement the verb. */
export const RPC_METHOD_NOT_FOUND = -32601;

export function defaultEnclaveConnect(port: number): () => Duplex {
  return () => {
    // Prod mounts a unix→vsock socat bridge; local tests use TCP host/port.
    const path = process.env.ENCLAVE_VSOCK_PATH;
    if (path) return net.connect(path);
    return net.connect(port, process.env.ENCLAVE_HOST || '127.0.0.1');
  };
}

export class EnclaveCryptoClient implements CryptoClient {
  private readonly connect: () => Duplex;
  private readonly timeoutMs: number;

  constructor(
    private readonly cid = VSOCK_CID,
    private readonly port = VSOCK_PORT,
    opts: EnclaveTransportOptions = {},
  ) {
    // Node has no AF_VSOCK, so the host reaches the enclave through a local
    // socat bridge (unix socket or TCP→vsock). The transport is injectable for tests.
    this.connect = opts.connect ?? defaultEnclaveConnect(this.port);
    this.timeoutMs = opts.timeoutMs ?? RPC_TIMEOUT_MS;
  }

  /**
   * One request/response over a fresh connection. Fails closed on transport
   * error, timeout, a premature close, or an enclave `error` reply — never
   * resolves on ambiguity.
   */
  private rpc(method: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = crypto.randomUUID();
      const sock = this.connect();
      const decoder = new FrameDecoder();
      let settled = false;
      const done = (err: Error | null, value?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        sock.destroy();
        if (err) reject(err);
        else resolve(value);
      };
      const timer = setTimeout(
        () => done(new EnclaveUnreachableError(`Enclave RPC '${method}' timed out after ${this.timeoutMs}ms`)),
        this.timeoutMs,
      );
      sock.on('error', (e: unknown) => done(new EnclaveUnreachableError(
        `Enclave RPC '${method}' transport error: ${e instanceof Error ? e.message : String(e)}`,
      )));
      sock.on('close', () => done(new EnclaveUnreachableError(`Enclave RPC '${method}' connection closed before a reply`)));
      sock.on('data', (chunk: Buffer) => {
        let messages: unknown[];
        try {
          messages = decoder.push(chunk);
        } catch (e) {
          return done(e as Error);
        }
        for (const msg of messages) {
          if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
            return done(new Error('Enclave RPC returned an invalid response'));
          }
          const res = msg as RpcResponse;
          if (res.id !== id) continue; // ignore replies that do not correlate to this request
          if (res.error) {
            if (typeof res.error !== 'object' || typeof res.error.code !== 'number' || typeof res.error.message !== 'string') {
              return done(new Error('Enclave RPC returned an invalid error response'));
            }
            return done(new EnclaveRpcError(method, res.error.code, res.error.message));
          }
          if (!Object.prototype.hasOwnProperty.call(res, 'result')) {
            return done(new Error('Enclave RPC response is missing its result'));
          }
          return done(null, res.result);
        }
      });
      sock.write(frameMessage({ id, method, params }));
    });
  }

  /**
   * Health / attestation-status probe over the RPC transport. Benign — it
   * carries no key material and is the one verb the enclave answers even on
   * real hardware — so it doubles as the connectivity check that the attested
   * decrypt verb (ALPHA-096 Phase 2) will build on. The at-rest crypto methods
   * below stay fail-closed until that attested, no-host-secret verb exists;
   * this transport is the plumbing, not a revived host-key path.
   */
  async health(): Promise<unknown> {
    return this.rpc('health', {});
  }

  /**
   * Request an NSM identity attestation document (VERA-ENCLAVE-IDENTITY-v1).
   * Returns the base64 document for independent verification; does not prove
   * subsequent RPC traffic or that application crypto runs inside the enclave.
   */
  async attestIdentity(nonce: string): Promise<{ document: string }> {
    if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) {
      throw new Error('A 32-byte lowercase hexadecimal nonce is required');
    }
    const result = await this.rpc('attestIdentity', { nonce });
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      throw new Error('Enclave attestIdentity returned an invalid response');
    }
    const document = (result as { document?: unknown }).document;
    if (typeof document !== 'string' || !document.length || document.length > 21848 ||
        Buffer.from(document, 'base64').toString('base64') !== document ||
        Buffer.from(document, 'base64').length > 16384) {
      throw new Error('Enclave attestIdentity returned an invalid document');
    }
    return { document };
  }

  async encrypt(_plaintext: Buffer, _secret: string, _salt?: Buffer): Promise<EncryptResult> {
    throw new Error('Enclave isolation requires an attested key-handle protocol; host-secret encryption is disabled');
  }

  async decrypt(_params: DecryptParams, _secret: string): Promise<Buffer> {
    throw new Error('Enclave isolation requires an attested key-handle protocol; host-secret decryption is disabled');
  }

  async deriveKey(_secret: string, _salt: Buffer, _params: KeyDerivationParams): Promise<Buffer> {
    throw new Error('Enclave keys cannot be exported to the host');
  }

  hash(data: Buffer): string {
    // Hashing is non-sensitive — can run locally for performance.
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  sign(_data: Buffer, _key: Buffer): Buffer {
    throw new Error('Enclave signing requires a confined key handle; host signing is disabled');
  }

  randomBytes(length: number): Buffer {
    // Local randomBytes is fine for non-secret uses (IVs, salts).
    return crypto.randomBytes(length);
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

let _instance: CryptoClient | null = null;

export function getCryptoClient(): CryptoClient {
  if (_instance) return _instance;

  if (process.env.ENCLAVE_ENABLED === 'true') {
    const cid = parseInt(process.env.ENCLAVE_CID || String(VSOCK_CID), 10);
    const port = parseInt(process.env.ENCLAVE_PORT || String(VSOCK_PORT), 10);
    logger.info(`[CRYPTO] Using EnclaveCryptoClient (CID=${cid}, port=${port})`);
    _instance = new EnclaveCryptoClient(cid, port);
  } else {
    logger.info('[CRYPTO] Using LocalCryptoClient');
    _instance = new LocalCryptoClient();
  }

  return _instance;
}

/** Reset singleton — for testing only */
export function _resetCryptoClient(): void {
  _instance = null;
}
