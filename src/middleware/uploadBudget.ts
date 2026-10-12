import {
  EVIDENCE_TRANSFER_TIMEOUT_MS,
  MAX_CLIENT_SMALL_REQUESTS,
  MAX_CLIENT_UPLOADS,
  MAX_PROCESS_SMALL_REQUESTS,
  MAX_PROCESS_UPLOADS,
  SMALL_REQUEST_MAX_BYTES,
  UPLOAD_IDLE_MS,
  UPLOAD_MIN_BYTES_PER_SEC,
  UPLOAD_PROGRESS_GRACE_MS,
  uploadBehindReceivePace,
  uploadReceiveDeadlineMs,
} from '../utils/evidenceLimits';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import type { Request, Response, NextFunction } from 'express';

const progress = new WeakMap<Request, (chunk: Buffer) => void>();
export function recordUploadProgress(req: Request, chunk: Buffer): void { progress.get(req)?.(chunk); }
/** Evidence transfers and small intake bodies are admitted from separate pools: a
 * client holding the scarce evidence slots with slow uploads cannot refuse text-only
 * reports. Node ends a body at its declared Content-Length, so a small declaration
 * stays small. Only intake routes (reserveIntake) use the small pool: elsewhere a
 * small request can still produce a large response (downloads, packet reveals). */
interface Pool { active: number; byClient: Map<string, number>; max: number; perClient: number; gated: boolean }
const evidencePool: Pool = { active: 0, byClient: new Map(), max: MAX_PROCESS_UPLOADS, perClient: MAX_CLIENT_UPLOADS, gated: true };
const smallPool: Pool = { active: 0, byClient: new Map(), max: MAX_PROCESS_SMALL_REQUESTS, perClient: MAX_CLIENT_SMALL_REQUESTS, gated: false };
const isSmallBody = (contentLength: number) =>
  Number.isInteger(contentLength) && contentLength >= 0 && contentLength <= SMALL_REQUEST_MAX_BYTES;
const leases = new WeakMap<Request, { processing: boolean; release: () => void }>();
let secondTransferReady: (() => Promise<boolean>) | null = null;
/** Server-owned live relay observation. Until configured, retain the one-transfer startup cap. */
export function configureUploadReadiness(read: (() => Promise<boolean>) | null): void { secondTransferReady = read; }

function busy(res: Response): void {
  res.setHeader('Retry-After', '30');
  res.status(503).json({ error: 'upload_capacity_busy', message: 'Evidence transfer capacity is busy; retry shortly.' });
}

/** Per-process memory admission before multer allocates buffers. No queue. */
export function reserveUpload(req: Request, res: Response, next: NextFunction): Promise<void> {
  return admit(evidencePool, req, res, next);
}

/** Intake admission: a body declared at most SMALL_REQUEST_MAX_BYTES (a text-only
 * report) takes a small-pool slot; anything larger or undeclared is an evidence transfer. */
export function reserveIntake(req: Request, res: Response, next: NextFunction): Promise<void> {
  return admit(isSmallBody(Number(req.headers['content-length'])) ? smallPool : evidencePool, req, res, next);
}

async function admit(pool: Pool, req: Request, res: Response, next: NextFunction): Promise<void> {
  const clientKey = requestRateLimitKey(req);
  const contentLength = Number(req.headers['content-length']);
  const full = () => pool.active >= pool.max || (pool.byClient.get(clientKey) || 0) >= pool.perClient;
  if (full()) {
    busy(res);
    return;
  }
  if (pool.gated && pool.active >= 1) {
    let ready = false;
    try { ready = await secondTransferReady?.() === true; } catch { /* Unknown sync state retains one slot. */ }
    if (req.aborted || res.destroyed || res.writableEnded) return;
    // The live observation can yield; another request may have taken the slot.
    if (!ready || full()) {
      busy(res);
      return;
    }
  }
  pool.active++;
  pool.byClient.set(clientKey, (pool.byClient.get(clientKey) || 0) + 1);
  let released = false;
  let received = 0;
  let lastProgress = Date.now();
  const started = Date.now();
  const receiveDeadlineMs = uploadReceiveDeadlineMs(contentLength);
  const observe = (chunk: Buffer) => { received += chunk.length; lastProgress = Date.now(); };
  // Adding a data listener here would consume bytes before multer attaches.
  // Observe the parser through explicit accounting instead (recordUploadProgress).
  progress.set(req, observe);
  const progressTimer = setInterval(() => {
    if (lease.processing || req.complete) return;
    const elapsed = Date.now() - started;
    if (
      Date.now() - lastProgress >= UPLOAD_IDLE_MS
      || elapsed >= receiveDeadlineMs
      || (elapsed >= UPLOAD_PROGRESS_GRACE_MS && received < (elapsed / 1000) * UPLOAD_MIN_BYTES_PER_SEC)
      || uploadBehindReceivePace(received, contentLength, elapsed, receiveDeadlineMs)
    ) {
      req.destroy(); lease.release();
    }
  }, 1000);
  progressTimer.unref();
  // Absolute deadline only while still receiving; processing uses route requestTimeout.
  const timer = setTimeout(() => {
    if (!lease.processing) { req.destroy(); lease.release(); }
  }, EVIDENCE_TRANSFER_TIMEOUT_MS);
  timer.unref();
  const lease = { processing: false, release: () => {
    if (!released) {
      released = true;
      pool.active--;
      const remaining = (pool.byClient.get(clientKey) || 1) - 1;
      if (remaining <= 0) pool.byClient.delete(clientKey);
      else pool.byClient.set(clientKey, remaining);
      clearTimeout(timer);
      clearInterval(progressTimer);
      progress.delete(req);
      leases.delete(req);
      if (!req.complete) req.destroy();
    }
  } };
  leases.set(req, lease);
  // A timeout response must not release the slot while expensive work is running.
  res.once('finish', () => { if (!lease.processing) lease.release(); });
  res.once('close', () => { if (!lease.processing) lease.release(); });
  req.once('aborted', () => { if (!lease.processing) lease.release(); });
  next();
}
export function withUploadBudget(handler: (req: Request, res: Response) => Promise<unknown>) {
  return async (req: Request, res: Response): Promise<void> => {
    const lease = leases.get(req);
    if (lease) lease.processing = true;
    try { await handler(req, res); } finally {
      if (lease) {
        lease.processing = false;
        if (res.writableFinished || res.destroyed) lease.release();
      }
    }
  };
}
