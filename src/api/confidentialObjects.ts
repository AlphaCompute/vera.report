import { CHUNK_LIMITS, createUploadAdmission } from '../utils/confidentialAdmission';
import { createHash } from 'node:crypto';
import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { confidentialBodyErrors, confidentialRequestGuard } from '../middleware/confidentialRequestGuard';
import { requestTimeout } from '../middleware/security';
import { uploadReceiveDeadlineMs } from '../utils/evidenceLimits';
import { MAX_CHUNK_BYTES, isChunkSize } from '../utils/confidentialChunks';

/** Staging for participant-encrypted case objects that exceed the attested
 * channel's body limit. The host only ever receives OpenPGP ciphertext encrypted
 * on the participant's device; it stores it by SHA-256 of the exact armored text.
 * Nothing here decrypts, parses case metadata, or links an upload to a case; the
 * enclave service re-hashes and re-validates staged bytes when an owner-signed
 * manifest references them. Unreferenced uploads expire.
 */
export const MAX_STAGED_CIPHERTEXT = 12 * 1024 * 1024;
const ARMOR_BEGIN = '-----BEGIN PGP MESSAGE-----';
const ARMOR_END = '-----END PGP MESSAGE-----';

/** Staging is anonymous by design, so the per-address count limit alone cannot
 * bound total storage: many addresses could fill the database with 12 MB
 * uploads that live for a day. This process-wide hourly byte budget sheds the
 * excess with a retryable 503 before anything is stored. */
export const STAGING_HOURLY_BYTES_DEFAULT = 2 * 1024 * 1024 * 1024;
const HOUR_MS = 60 * 60_000;

export function stagingHourlyBytes(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.CONFIDENTIAL_STAGING_HOURLY_BYTES;
  if (raw === undefined || raw === '') return STAGING_HOURLY_BYTES_DEFAULT;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MAX_STAGED_CIPHERTEXT) {
    throw new Error('CONFIDENTIAL_STAGING_HOURLY_BYTES must be an integer of at least one maximum object');
  }
  return value;
}

/** Uploads buffered at once per process (each up to 12 MB in memory). A slow or
 * stalled sender holds a slot only until its size-based receive deadline. */
export const STAGING_MAX_CONCURRENT = 16;

/** Evidence chunks (chunked object format) travel as base64 text: WAF body
 * inspection sees only the base64 alphabet, and nothing but canonical base64 of
 * an allowed chunk size is accepted. */
export const CHUNK_CONTENT_TYPE = 'application/vnd.vera.case-chunk+base64';
/** Chunk count per client per hour: 15 GiB of 512 KiB chunks, i.e. about 10 GiB
 * of evidence after worst-case (under 25%) chunk-count padding, plus retries;
 * equal to the CHUNK_LIMITS byte budget in full chunks. */
export const CHUNKS_PER_HOUR = 30_720;
const MAX_CHUNK_WIRE = 4 * Math.ceil(MAX_CHUNK_BYTES / 3);

export type StagedObjectStore = {
  stageObject(digest: string, ciphertext: string, now: number): Promise<void>;
  stageChunk(digest: string, data: Uint8Array, now: number): Promise<void>;
};

export function createConfidentialObjectRouter(store: StagedObjectStore, clock: () => number = Date.now, options: {
  hourlyByteBudget?: number; allowedOrigins?: readonly string[]; maxConcurrent?: number;
} = {}) {
  const router = Router();
  /** Declared size, per-process concurrency, per-client admission and a receive
   * deadline before any byte is buffered. The 30 s API default would cut off a
   * 12 MB upload on a slow (e.g. Tor) link; the deadline instead scales with the
   * declared size at 32 KiB/s (1-5 min). Reservations are held until the store
   * operation settles, even if the client disappears or the deadline answers. */
  const admitted = (admitUpload: ReturnType<typeof createUploadAdmission>, maxBytes: number, maxConcurrent: number): express.RequestHandler => {
    let active = 0;
    return (req, res, next) => {
      // Browser fetch sends a known-length string. Reject compressed or
      // streaming bodies before buffering rather than undercharging their bytes.
      if (req.headers['content-encoding'] || Object.keys(req.query).length) {
        res.status(400).json({ error: 'Encrypted object with a known size required' }); return;
      }
      const raw = req.headers['content-length'];
      const length = typeof raw === 'string' && /^[0-9]{1,9}$/.test(raw) ? Number(raw) : NaN;
      if (!Number.isSafeInteger(length)) { res.status(411).json({ error: 'Content-Length required' }); return; }
      if (length < 1) { res.status(400).json({ error: 'Encrypted object with a known size required' }); return; }
      if (length > maxBytes) { res.status(413).json({ error: 'Request too large' }); return; }
      if (active >= maxConcurrent) {
        res.setHeader('Retry-After', '5');
        res.status(503).json({ error: 'Temporarily unavailable' });
        return;
      }
      const releaseClient = admitUpload(requestRateLimitKey(req), length);
      if (!releaseClient) { res.setHeader('Retry-After', '60'); res.status(429).json({ error: 'Upload capacity unavailable, please try again later.' }); return; }
      active++;
      let released = false;
      const release = () => { if (!released) { released = true; active--; releaseClient(); } };
      let processing = false;
      res.locals.confidentialUpload = { release, start: () => { processing = true; } };
      const deadlineMs = uploadReceiveDeadlineMs(length) + 30_000;
      // Backstop: never keep a stalled socket beyond the receive deadline.
      const deadline = setTimeout(() => req.destroy(), deadlineMs + 5_000);
      deadline.unref();
      const finished = () => {
        clearTimeout(deadline);
        if (!processing) {
          if (!req.complete) req.destroy();
          release();
        }
      };
      res.once('close', finished);
      res.once('finish', finished);
      requestTimeout(deadlineMs)(req, res, next);
    };
  };
  const budget = options.hourlyByteBudget ?? stagingHourlyBytes();
  let window = { start: -Infinity, used: 0 };
  /** Reserve bytes in the current hour; returns seconds to wait when exhausted. */
  const reserve = (bytes: number): number => {
    const now = clock();
    if (now - window.start >= HOUR_MS || now < window.start) window = { start: now, used: 0 };
    if (window.used + bytes > budget) return Math.max(1, Math.ceil((window.start + HOUR_MS - now) / 1000));
    window.used += bytes;
    return 0;
  };
  const limiter = rateLimit({ keyGenerator: requestRateLimitKey, store: sharedRateLimitStore('confidentialObjects.staging'), windowMs: 60 * 60_000, max: 60,
    standardHeaders: true, legacyHeaders: false, message: { error: 'Too many uploads, please try again later.' } });
  router.post('/objects', confidentialRequestGuard('application/pgp-encrypted', options.allowedOrigins), limiter,
    admitted(createUploadAdmission(), MAX_STAGED_CIPHERTEXT, options.maxConcurrent ?? STAGING_MAX_CONCURRENT),
    express.text({ type: 'application/pgp-encrypted', limit: MAX_STAGED_CIPHERTEXT, inflate: false }),
    async (req, res) => {
      // Receive deadline already answered 408, or the client went away.
      if (res.headersSent || res.writableEnded || res.destroyed) { res.locals.confidentialUpload?.release(); return; }
      const ciphertext = req.body;
      if (typeof ciphertext !== 'string' || !ciphertext.startsWith(ARMOR_BEGIN) ||
          !ciphertext.trimEnd().endsWith(ARMOR_END) || Object.keys(req.query).length) {
        res.status(400).json({ error: 'Encrypted object required' });
        return;
      }
      const admission = res.locals.confidentialUpload as { release(): void; start(): void };
      admission.start();
      try {
        const bytes = Buffer.byteLength(ciphertext, 'utf8');
        const wait = reserve(bytes);
        if (wait) {
          if (!res.headersSent && !res.writableEnded && !res.destroyed) {
            res.setHeader('Retry-After', String(wait));
            res.status(503).json({ error: 'Temporarily unavailable' });
          }
          return;
        }
        const digest = createHash('sha256').update(ciphertext, 'utf8').digest('hex');
        try {
          await store.stageObject(digest, ciphertext, clock());
          if (!res.headersSent && !res.writableEnded && !res.destroyed) res.status(201).json({ digest });
        } catch {
          // A failed reply may follow a committed write. Keep the reservation;
          // refunding it could also subtract from a newer hourly window.
          if (!res.headersSent && !res.writableEnded && !res.destroyed) res.status(503).json({ error: 'Temporarily unavailable' });
        }
      } finally { admission.release(); }
    });
  router.use('/objects', confidentialBodyErrors);
  const chunkLimiter = rateLimit({ keyGenerator: requestRateLimitKey, store: sharedRateLimitStore('confidentialObjects.chunks'), windowMs: 60 * 60_000, max: CHUNKS_PER_HOUR,
    standardHeaders: true, legacyHeaders: false, message: { error: 'Too many uploads, please try again later.' } });
  // Same properties as /objects: ciphertext only, content-addressed, no read route,
  // no case linkage and expiry unless a committed owner-signed index promotes it.
  // Chunks have their own budget: one evidence upload is up to 512 of them.
  router.post('/chunks', confidentialRequestGuard(CHUNK_CONTENT_TYPE, options.allowedOrigins), chunkLimiter,
    admitted(createUploadAdmission(undefined, CHUNK_LIMITS), MAX_CHUNK_WIRE, CHUNK_LIMITS.processActive),
    express.text({ type: CHUNK_CONTENT_TYPE, limit: MAX_CHUNK_WIRE, inflate: false }),
    async (req, res) => {
      const admission = res.locals.confidentialUpload as { release(): void; start(): void };
      // Receive deadline already answered 408, or the client went away.
      if (res.headersSent || res.writableEnded || res.destroyed) { admission?.release(); return; }
      const body = req.body;
      let bytes: Buffer | null = null;
      if (typeof body === 'string' && body.length <= MAX_CHUNK_WIRE && body.length % 4 === 0 &&
          /^[A-Za-z0-9+/]*={0,2}$/.test(body)) {
        bytes = Buffer.from(body, 'base64');
        if (bytes.toString('base64') !== body || !isChunkSize(bytes.length)) bytes = null;
      }
      if (!bytes) { res.status(400).json({ error: 'Encrypted chunk required' }); return; }
      admission.start();
      const digest = createHash('sha256').update(bytes).digest('hex');
      try {
        await store.stageChunk(digest, new Uint8Array(bytes), clock());
        if (!res.headersSent && !res.writableEnded && !res.destroyed) res.status(201).json({ digest });
      } catch {
        if (!res.headersSent && !res.writableEnded && !res.destroyed) res.status(503).json({ error: 'Temporarily unavailable' });
      } finally { admission.release(); }
    });
  router.use('/chunks', confidentialBodyErrors);
  return router;
}
