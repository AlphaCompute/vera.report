import * as net from 'node:net';
import * as crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { getSecret, clearSecrets } from './kms-proxy.js';
import { attestIdentity } from './attestation.js';

// Presence of this device is how the process tells "inside a real enclave" from
// "a laptop", which gates the development-only secret fallback below.
const NSM_DEVICE_PATH = '/dev/nsm';

// ─── Types ───────────────────────────────────────────────────────────────────

interface RpcRequest {
  id: string | number;
  method: string;
  params: Record<string, unknown>;
}

interface RpcResponse {
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string };
}

interface EncryptParams {
  plaintext: string;
  salt?: string;
  keyDerivationSecret?: string;
  iterations?: number;
}

interface DecryptParams {
  ciphertext: string;
  iv: string;
  authTag: string;
  salt: string;
  keyDerivationSecret?: string;
  iterations?: number;
}

interface DeriveKeyParams {
  secret: string;
  salt?: string;
  iterations?: number;
  keyLength?: number;
  algorithm?: 'pbkdf2' | 'scrypt';
}

interface HashParams {
  data: string;
  algorithm?: string;
}

interface SignParams {
  data: string;
  keyId: string;
}

interface GenerateRandomParams {
  length: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const VSOCK_PORT = 5000;
const ENCLAVE_CID = 16;
const DEFAULT_PBKDF2_ITERATIONS = 600000;
const DEFAULT_KEY_LENGTH = 32;
// Both derivation costs arrive from the host, which sits outside the enclave's
// trust boundary, and scryptSync/pbkdf2Sync block the event loop — so an
// unbounded value stalls every other request, not just the caller's. These
// ceilings reject rather than clamp: silently lowering a cost would derive a
// different key and orphan anything already sealed with the original value.
// 2,000,000 leaves better than 3x headroom over the default; 256 bytes is
// eight times the longest key any caller needs.
const MAX_PBKDF2_ITERATIONS = 2_000_000;
const MAX_KEY_LENGTH = 256;
const ALGORITHM = 'aes-256-gcm';
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16 MB

// In-memory key store — keys never leave the enclave
const keyStore = new Map<string, Buffer>();

// ─── Crypto Operations ──────────────────────────────────────────────────────

function deriveKeyInternal(
  secret: string,
  salt: Buffer,
  iterations: number,
  keyLength: number,
  algorithm: 'pbkdf2' | 'scrypt'
): Buffer {
  // The algorithm arrives as untyped RPC JSON; anything unrecognized would
  // otherwise fall through to PBKDF2 without the iteration bound below.
  if (algorithm !== 'pbkdf2' && algorithm !== 'scrypt') {
    throw new Error('Unsupported key derivation algorithm');
  }
  if (algorithm === 'pbkdf2' && (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS)) {
    throw new Error('Key derivation iteration limit exceeded');
  }
  if (!Number.isSafeInteger(keyLength) || keyLength < 1 || keyLength > MAX_KEY_LENGTH) {
    throw new Error('Key derivation length limit exceeded');
  }
  if (algorithm === 'scrypt') {
    return crypto.scryptSync(secret, salt, keyLength, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
  }

  return crypto.pbkdf2Sync(secret, salt, iterations, keyLength, 'sha512');
}

async function handleEncrypt(params: EncryptParams): Promise<Record<string, string>> {
  const salt = params.salt
    ? Buffer.from(params.salt, 'hex')
    : crypto.randomBytes(32);

  const secret = params.keyDerivationSecret || (await getSecretOrFallback('encryption'));
  const iterations = params.iterations || DEFAULT_PBKDF2_ITERATIONS;

  const key = deriveKeyInternal(secret, salt, iterations, DEFAULT_KEY_LENGTH, 'pbkdf2');
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const plainBuffer = Buffer.from(params.plaintext, 'utf-8');
    const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      salt: salt.toString('hex'),
    };
  } finally {
    key.fill(0);
  }
}

async function handleDecrypt(params: DecryptParams): Promise<string> {
  const salt = Buffer.from(params.salt, 'hex');
  const iv = Buffer.from(params.iv, 'hex');
  const authTag = Buffer.from(params.authTag, 'hex');
  const ciphertext = Buffer.from(params.ciphertext, 'base64');

  const secret = params.keyDerivationSecret || (await getSecretOrFallback('encryption'));
  const iterations = params.iterations || DEFAULT_PBKDF2_ITERATIONS;

  const key = deriveKeyInternal(secret, salt, iterations, DEFAULT_KEY_LENGTH, 'pbkdf2');

  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf-8');
  } finally {
    // Authentication failures must also erase the derived key buffer.
    key.fill(0);
  }
}

function handleDeriveKey(params: DeriveKeyParams): Record<string, string> {
  const salt = params.salt
    ? Buffer.from(params.salt, 'hex')
    : crypto.randomBytes(32);

  const keyLength = params.keyLength || DEFAULT_KEY_LENGTH;
  const iterations = params.iterations || DEFAULT_PBKDF2_ITERATIONS;
  const algorithm = params.algorithm || 'pbkdf2';

  const derivedKey = deriveKeyInternal(params.secret, salt, iterations, keyLength, algorithm);

  // Store the key in enclave memory under a generated ID
  const keyId = crypto.randomUUID();
  keyStore.set(keyId, Buffer.from(derivedKey));

  // Zero out the temporary buffer
  derivedKey.fill(0);

  return {
    keyId,
    salt: salt.toString('hex'),
    algorithm,
    iterations: iterations.toString(),
    keyLength: keyLength.toString(),
  };
}

function handleHash(params: HashParams): string {
  const algorithm = params.algorithm || 'sha256';
  return crypto.createHash(algorithm).update(params.data, 'utf-8').digest('hex');
}

async function handleSign(params: SignParams): Promise<string> {
  // Look up key from internal store or fetch from KMS
  let keyBuffer = keyStore.get(params.keyId);

  if (!keyBuffer) {
    try {
      keyBuffer = await getSecret(params.keyId);
    } catch {
      throw new Error(`Key not found: ${params.keyId}`);
    }
  }

  const hmac = crypto.createHmac('sha256', keyBuffer);
  hmac.update(params.data, 'utf-8');
  return hmac.digest('hex');
}

function handleGenerateRandom(params: GenerateRandomParams): string {
  const length = Math.min(Math.max(1, params.length), 1024);
  return crypto.randomBytes(length).toString('hex');
}

function handleHealth(): Record<string, unknown> {
  // Liveness is not attestation. Never report a fabricated enclave identity.
  return {
    status: 'unavailable',
    attested: false,
    reason: 'Attested key handling and recipient decryption are not implemented',
    uptime: process.uptime(),
  };
}

// ─── Request Router ──────────────────────────────────────────────────────────

function isRpcRequest(value: unknown): value is RpcRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const req = value as Record<string, unknown>;
  const validId = (typeof req.id === 'string' && req.id.length > 0 && req.id.length <= 128) ||
    (typeof req.id === 'number' && Number.isSafeInteger(req.id));
  return validId && typeof req.method === 'string' && req.method.length > 0 && req.method.length <= 64 &&
    !!req.params && typeof req.params === 'object' && !Array.isArray(req.params);
}

async function handleRequest(req: RpcRequest): Promise<RpcResponse> {
  // Validate again for callers that do not use the wire decoder.
  if (!isRpcRequest(req)) return { id: '', error: { code: -32600, message: 'Invalid RPC request' } };

  try {
    // Legacy RPC carries caller-controlled keys and exposes a decryption oracle.
    // Keep it inaccessible on hardware and outside explicitly local development.
    if (!['health', 'attestIdentity'].includes(req.method) &&
        (existsSync(NSM_DEVICE_PATH) || !['development', 'test'].includes(process.env.NODE_ENV || ''))) {
      throw new Error('Attested purpose-bound protocol unavailable');
    }
    let result: unknown;

    switch (req.method) {
      case 'attestIdentity':
        result = await attestIdentity(req.params);
        break;
      case 'encrypt':
        result = await handleEncrypt(req.params as unknown as EncryptParams);
        break;
      case 'decrypt':
        result = await handleDecrypt(req.params as unknown as DecryptParams);
        break;
      case 'deriveKey':
        result = handleDeriveKey(req.params as unknown as DeriveKeyParams);
        break;
      case 'hash':
        result = handleHash(req.params as unknown as HashParams);
        break;
      case 'sign':
        result = await handleSign(req.params as unknown as SignParams);
        break;
      case 'generateRandom':
        result = handleGenerateRandom(req.params as unknown as GenerateRandomParams);
        break;
      case 'health':
        result = handleHealth();
        break;
      default:
        return {
          id: req.id,
          error: { code: -32601, message: 'Unknown method' },
        };
    }

    return { id: req.id, result };
  } catch {
    // Never echo caller identifiers, arbitrary method names, or parser errors.
    return { id: req.id, error: { code: -32000, message: 'Enclave operation unavailable' } };
  }
}

// ─── Framing Protocol ────────────────────────────────────────────────────────
// 4-byte big-endian uint32 length prefix + JSON payload

function frameMessage(data: unknown): Buffer {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

class MessageFramer {
  private buffer: Buffer = Buffer.alloc(0);

  feed(data: Buffer): RpcRequest[] {
    if (this.buffer.length + data.length > MAX_MESSAGE_SIZE + 4) {
      this.reset();
      throw new Error('RPC buffer limit exceeded');
    }
    this.buffer = Buffer.concat([this.buffer, data]);
    const messages: RpcRequest[] = [];

    let frames = 0;
    while (this.buffer.length >= 4) {
      if (++frames > 32) {
        this.reset();
        throw new Error('RPC batch limit exceeded');
      }
      const messageLength = this.buffer.readUInt32BE(0);

      if (messageLength > MAX_MESSAGE_SIZE) {
        this.reset();
        throw new Error('RPC frame limit exceeded');
      }

      if (this.buffer.length < 4 + messageLength) {
        break; // Wait for more data
      }

      const payload = this.buffer.subarray(4, 4 + messageLength);
      this.buffer = this.buffer.subarray(4 + messageLength);

      try {
        const parsed = JSON.parse(payload.toString('utf-8')) as RpcRequest;

        if (!isRpcRequest(parsed)) {
          log('warn', 'Invalid RPC request: missing id or method');
          continue;
        }

        messages.push(parsed);
      } catch {
        log('error', 'Failed to parse message');
      }
    }

    return messages;
  }

  reset(): void {
    this.buffer = Buffer.alloc(0);
  }
}

// ─── Secret Fallback ─────────────────────────────────────────────────────────

/**
 * Resolve a key-derivation secret from KMS.
 *
 * This used to swallow any KMS failure and substitute
 * sha256(`enclave-fallback-${secretId}`), a constant derivable by anyone with
 * the source. Because handleEncrypt and handleDecrypt call this whenever the
 * caller omits keyDerivationSecret, an unreachable or misconfigured KMS meant
 * the enclave silently encrypted evidence under a publicly known key and
 * reported success, indistinguishably from real protection.
 *
 * A component whose only job is protecting key material has to fail closed, so
 * the default is now to throw. The fallback survives only behind an explicit
 * opt-in for local development, where there is no KMS to talk to and the
 * alternative is being unable to run the server at all.
 *
 * The flag is read per call rather than captured at module load so tests can
 * exercise both paths, and it is deliberately not honoured when the NSM device
 * is present: on real enclave hardware there is no legitimate reason to want a
 * derivable key.
 */
async function getSecretOrFallback(secretId: string): Promise<string> {
  try {
    const secret = await getSecret(secretId);
    return secret.toString('utf-8');
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    const optedIn = process.env.ENCLAVE_ALLOW_INSECURE_FALLBACK === 'true';
    const onEnclaveHardware = existsSync(NSM_DEVICE_PATH);

    if (!optedIn || onEnclaveHardware || !['development', 'test'].includes(process.env.NODE_ENV || '')) {
      log('error', 'Refusing to derive a fallback secret; failing closed', {
        secretId,
        reason,
        optedIn,
        onEnclaveHardware,
      });
      throw new Error(
        `Secret "${secretId}" is unavailable from KMS (${reason}). Refusing to fall ` +
          `back to a derivable key. Set ENCLAVE_ALLOW_INSECURE_FALLBACK=true for local ` +
          `development only; it is ignored when ${NSM_DEVICE_PATH} is present.`
      );
    }

    log('warn', 'INSECURE: deriving a publicly computable fallback secret. Development only.', {
      secretId,
      reason,
    });

    return crypto
      .createHash('sha256')
      .update(`enclave-fallback-${secretId}`)
      .digest('hex');
  }
}

// ─── Logging ─────────────────────────────────────────────────────────────────

function log(level: string, message: string, data?: Record<string, unknown>): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    component: 'enclave-server',
    message,
    ...data,
  };
  process.stderr.write(JSON.stringify(entry) + '\n');
}

// ─── Server ──────────────────────────────────────────────────────────────────

function startServer(port = VSOCK_PORT): void {
  const server = net.createServer((socket) => {
    const framer = new MessageFramer();
    // An absolute deadline also bounds peers that trickle bytes to defeat an
    // idle timeout. Sequential reads and awaited writes propagate backpressure.
    const deadline = setTimeout(() => socket.destroy(), 30000);
    deadline.unref();
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => { /* No peer data or diagnostics in logs. */ });
    void (async () => {
      let requests = 0;
      try {
        for await (const chunk of socket) {
          const messages = framer.feed(chunk as Buffer);
          for (const msg of messages) {
            if (++requests > 32) throw new Error('RPC request limit exceeded');
            const response = await handleRequest(msg);
            await new Promise<void>((resolve, reject) => {
              socket.write(frameMessage(response), (error) => error ? reject(error) : resolve());
            });
          }
        }
      } catch {
        // Malformed or resource-exhausting peers get no diagnostic reflection.
      } finally {
        clearTimeout(deadline);
        framer.reset();
        socket.destroy();
      }
    })();
  });
  server.maxConnections = 16;

  server.on('error', (err) => {
    log('error', 'Server error', { error: err.message });
  });

  // Listen on vsock port 5000
  // In a real Nitro Enclave, this would use AF_VSOCK instead of TCP.
  // The vsock address family is used for communication between the
  // enclave and the parent EC2 instance.
  //
  // For production, use a vsock binding library or the enclave's
  // built-in vsock support. The TCP listener here works for
  // development and testing outside of an enclave.
  server.listen(port, '127.0.0.1', () => {
    log('info', 'Enclave vsock server started', {
      port,
      cid: ENCLAVE_CID,
      pid: process.pid,
      nodeVersion: process.version,
    });
  });

  // Graceful shutdown
  const shutdown = (signal: string): void => {
    log('info', `Received ${signal}, shutting down`);

    // Clear all secrets from memory
    clearSecrets();
    for (const [id, key] of keyStore.entries()) {
      key.fill(0);
      keyStore.delete(id);
    }

    server.close(() => {
      log('info', 'Server closed');
      process.exit(0);
    });

    // Force exit after 5 seconds
    setTimeout(() => {
      log('warn', 'Forced shutdown after timeout');
      process.exit(1);
    }, 5000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Continuing after an unexpected exception can leave security state partial.
  // Never serialize exception text: it can contain request or secret material.
  const fatal = (): never => {
    clearSecrets();
    for (const key of keyStore.values()) key.fill(0);
    keyStore.clear();
    log('error', 'Fatal enclave runtime failure');
    process.exit(1);
  };
  process.on('uncaughtException', fatal);
  process.on('unhandledRejection', fatal);
}

// ─── Exports ─────────────────────────────────────────────────────────────────
// Exported for testing. Nothing here opens a socket or touches /dev/nsm on
// import, so these can be exercised off enclave hardware.

export {
  frameMessage,
  MessageFramer,
  handleRequest,
  handleEncrypt,
  handleDecrypt,
  handleDeriveKey,
  handleHash,
  handleSign,
  handleGenerateRandom,
  deriveKeyInternal,
  getSecretOrFallback,
  startServer,
  keyStore,
  MAX_MESSAGE_SIZE,
  DEFAULT_PBKDF2_ITERATIONS,
};

export type { RpcRequest, RpcResponse, EncryptParams, DecryptParams, DeriveKeyParams };

// Only bind the listener when executed directly (node dist/server.js), not when
// imported by a test. Checking argv rather than import.meta keeps this working
// under both the NodeNext build and the CommonJS transform ts-jest applies.
const invokedDirectly =
  typeof process.argv[1] === 'string' && /(^|[\\/])server\.(js|ts)$/.test(process.argv[1]);

if (invokedDirectly) {
  startServer();
}
